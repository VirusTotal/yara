/* Copyright (c) 2024 Stormshield

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifdef USE_WINCRYPT_AUTHENTICODE

#include <authenticode-parser/windows/tools.h>
#include <authenticode-parser/windows/certificate.h>
#include <authenticode-parser/windows/extractors.h>
#include <authenticode-parser/windows/oid.h>

#include <yara/error.h>
#include <yara/mem.h>
#include <yara/modules.h>

#include <crypto.h>

/// @brief Computes the cert data digest using the requested algorithm
/// @param[in]      certificate_context     Certificate context to compute the digest for
/// @param[in]      algorithm               Microsoft digest algorithm identifier
/// @param[in]      expected_digest_length  Expected length of the digest for the given digest algorithm
/// @param[in,out]  digest                  Computed digest, to be freed using yr_free
static VOID compute_cert_data_digest(
    _In_    CONST   PCCERT_CONTEXT          certificate_context,
    _In_    CONST   ALG_ID                  algorithm,
    _In_    CONST   DWORD                   expected_digest_length,
    _Inout_         ByteArray       *CONST  digest
)
{
    PSTR buffer = NULL;
    DWORD buffer_size = 0;
    INT result = -1;

    if (certificate_context == NULL || expected_digest_length == 0 || digest == NULL)
        return;

    GOTO_EXIT_ON_FAIL(CryptHashCertificate(
        0,
        algorithm,
        0,
        certificate_context->pbCertEncoded,
        certificate_context->cbCertEncoded,
        NULL,
        &buffer_size));

    GOTO_EXIT_ON_FAIL(buffer_size == expected_digest_length);

    buffer = (PSTR)yr_malloc(buffer_size);
    GOTO_EXIT_ON_NULL(buffer, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_FAIL(CryptHashCertificate(
        0,
        algorithm,
        0,
        certificate_context->pbCertEncoded,
        certificate_context->cbCertEncoded,
        (BYTE*)buffer,
        &buffer_size));

    digest->len = buffer_size;
    digest->data = (uint8_t*)yr_calloc(buffer_size, sizeof(char));
    GOTO_EXIT_ON_NULL(digest->data, ERROR_INSUFFICIENT_MEMORY);

    memcpy(digest->data, buffer, buffer_size * sizeof(char));

_exit:

    if (buffer != NULL)
    {
        yr_free(buffer);
        buffer = NULL;
    }
}

VOID retrieve_sha1_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
)
{
    compute_cert_data_digest(certificate_context, CALG_SHA1, YR_SHA1_LEN, &certificate->sha1);
}

VOID retrieve_sha256_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
)
{
    compute_cert_data_digest(certificate_context, CALG_SHA_256, YR_SHA256_LEN, &certificate->sha256);
}

VOID retrieve_subject_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
)
{
    INT result = -1;

    PSTR formatted_subject = NULL;

    if (certificate == NULL || certificate_context == NULL || certificate_context->pCertInfo == NULL)
        return;

    GOTO_EXIT_ON_ERROR(format_cert_name_blob_using_known_oid(&certificate_context->pCertInfo->Subject, &formatted_subject));
    GOTO_EXIT_ON_ERROR(fill_attributes_using_cert_name_blob(&certificate_context->pCertInfo->Subject, &certificate->subject_attrs));

    certificate->subject = formatted_subject;
    formatted_subject = NULL;

_exit:

    if (formatted_subject != NULL)
    {
        yr_free(formatted_subject);
        formatted_subject = NULL;
    }
}

VOID retrieve_issuer_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
)
{
    INT result = -1;

    PSTR formatted_issuer = NULL;

    if (certificate == NULL || certificate_context == NULL || certificate_context->pCertInfo == NULL)
        return;

    GOTO_EXIT_ON_ERROR(format_cert_name_blob_using_known_oid(&certificate_context->pCertInfo->Issuer, &formatted_issuer));
    GOTO_EXIT_ON_ERROR(fill_attributes_using_cert_name_blob(&certificate_context->pCertInfo->Issuer, &certificate->issuer_attrs));

    certificate->issuer = formatted_issuer;
    formatted_issuer = NULL;

_exit:

    if (formatted_issuer != NULL)
    {
        yr_free(formatted_issuer);
        formatted_issuer = NULL;
    }
}

VOID retrieve_version_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
)
{
    if (certificate == NULL || certificate_context == NULL || certificate_context->pCertInfo == NULL)
        return;

    // version are 0 based, but one increment is done by yara in write_certificate maccro
    certificate->version = certificate_context->pCertInfo->dwVersion;
}

VOID retrieve_signature_algorithm_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
)
{
    PCSTR algo_display_name = NULL;

    if (certificate == NULL || certificate_context == NULL || certificate_context->pCertInfo == NULL)
    {
        return;
    }

    certificate->sig_alg = get_algorithmname_from_oid(certificate_context->pCertInfo->SignatureAlgorithm.pszObjId);
    certificate->sig_alg_oid = duplicate_string(certificate_context->pCertInfo->SignatureAlgorithm.pszObjId);
}

VOID retrieve_serial_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
)
{
    char* buffer = NULL;
    PCRYPT_INTEGER_BLOB serial_number = NULL;
    int result = -1;

    if (certificate == NULL || certificate_context == NULL || certificate_context->pCertInfo == NULL)
        return;

    serial_number = (PCRYPT_INTEGER_BLOB) &certificate_context->pCertInfo->SerialNumber;

    // About the SerialNumber member:
    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa377200(v=vs.85).aspx
    // A BLOB that contains the serial number of a certificate.
    // The least significant byte is the zero byte of the pbData member of
    // SerialNumber. The index for the last byte of pbData, is one less than the
    // value of the cbData member of SerialNumber. The most significant byte is
    // the last byte of pbData. Leading 0x00 or 0xFF bytes are removed.

    GOTO_EXIT_ON_ERROR(buffer_to_hex(serial_number->cbData, serial_number->pbData, NULL, &buffer, ':', true));

    certificate->serial = duplicate_string(buffer);
    GOTO_EXIT_ON_NULL(certificate->serial, ERROR_INSUFFICIENT_MEMORY);

_exit:

    if (buffer != NULL)
    {
        yr_free(buffer);
        buffer = NULL;
    }
}

VOID retrieve_not_before_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
)
{
    if (certificate == NULL || certificate_context == NULL || certificate_context->pCertInfo == NULL)
        return;

    certificate->not_before = filetime_to_epoch(&certificate_context->pCertInfo->NotBefore);
}

VOID retrieve_not_after_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
)
{
    if (certificate == NULL || certificate_context == NULL || certificate_context->pCertInfo == NULL)
        return;

    certificate->not_after = filetime_to_epoch(&certificate_context->pCertInfo->NotAfter);
}

#endif // USE_WINCRYPT_AUTHENTICODE
