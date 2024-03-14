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

#include <authenticode-parser/authenticode.h>

#include <yara/mem.h>

#ifdef USE_WINCRYPT_AUTHENTICODE

#include <authenticode-parser/windows/cleanup.h>

#define CUSTOM_FREE(data)   \
    if (data != NULL)       \
    {                       \
        yr_free(data);      \
        data = NULL;        \
    }

VOID cleanup_byte_array(
    _Inout_ ByteArray   *CONST  byte_array
)
{
    if (byte_array == NULL)
    {
        return;
    }

    CUSTOM_FREE(byte_array->data);

    byte_array->len = 0;
}

VOID cleanup_attributes(
    _Inout_ Attributes  *CONST attributes
)
{
    if (attributes == NULL)
    {
        return;
    }

    cleanup_byte_array(&attributes->country);
    cleanup_byte_array(&attributes->organization);
    cleanup_byte_array(&attributes->organizationalUnit);
    cleanup_byte_array(&attributes->nameQualifier);
    cleanup_byte_array(&attributes->state);
    cleanup_byte_array(&attributes->commonName);
    cleanup_byte_array(&attributes->serialNumber);
    cleanup_byte_array(&attributes->locality);
    cleanup_byte_array(&attributes->title);
    cleanup_byte_array(&attributes->surname);
    cleanup_byte_array(&attributes->givenName);
    cleanup_byte_array(&attributes->initials);
    cleanup_byte_array(&attributes->pseudonym);
    cleanup_byte_array(&attributes->generationQualifier);
    cleanup_byte_array(&attributes->emailAddress);
}

VOID destroy_certificate(
    _In_ _Post_ptr_invalid_ Certificate *CONST  certificate
)
{
    if (certificate == NULL)
    {
        return;
    }

    CUSTOM_FREE(certificate->issuer);
    CUSTOM_FREE(certificate->subject);
    CUSTOM_FREE(certificate->serial);
    cleanup_byte_array(&certificate->sha1);
    cleanup_byte_array(&certificate->sha256);
    CUSTOM_FREE(certificate->key_alg);
    CUSTOM_FREE(certificate->sig_alg);
    CUSTOM_FREE(certificate->sig_alg_oid);
    CUSTOM_FREE(certificate->key);
    cleanup_attributes(&certificate->issuer_attrs);
    cleanup_attributes(&certificate->subject_attrs);

    yr_free(certificate);
}

VOID destroy_certificate_array(
    _In_ _Post_ptr_invalid_ CertificateArray    *CONST  certificate_array
)
{
    if (certificate_array == NULL)
    {
        return;
    }

    if (certificate_array->certs != NULL)
    {
        for (int index = 0; index < certificate_array->count; index++)
        {
            destroy_certificate(certificate_array->certs[index]);
            certificate_array->certs[index] = NULL;
        }

        yr_free(certificate_array->certs);
        certificate_array->certs = NULL;
    }

    certificate_array->count = 0;

    yr_free(certificate_array);
}

VOID destroy_signer(
    _In_ _Post_ptr_invalid_ Signer  *CONST signer
)
{
    if (signer == NULL)
    {
        return;
    }

    destroy_certificate_array(signer->chain);
    signer->chain = NULL;

    cleanup_byte_array(&signer->digest);

    CUSTOM_FREE(signer->digest_alg);
    CUSTOM_FREE(signer->program_name);

    yr_free(signer);
}

VOID destroy_countersignature(
    _In_ _Post_ptr_invalid_ Countersignature    *CONST  countersignature
)
{
    if (countersignature == NULL)
    {
        return;
    }

    destroy_certificate_array(countersignature->certs);
    countersignature->certs = NULL;

    destroy_certificate_array(countersignature->chain);
    countersignature->chain = NULL;

    cleanup_byte_array(&countersignature->digest);
    CUSTOM_FREE(countersignature->digest_alg);

    yr_free(countersignature);
}

VOID destroy_countersignature_array(
    _In_ _Post_ptr_invalid_ CountersignatureArray   *CONST  array
)
{
    if (array == NULL)
    {
        return; 
    }

    for (DWORD index = 0; index < array->count; index++)
    {
        destroy_countersignature(array->counters[index]);
        array->counters[index] = NULL;
    }

    CUSTOM_FREE(array->counters);
    yr_free(array);
}

VOID destroy_authenticode(
    _In_ _Post_ptr_invalid_ Authenticode    *CONST  authenticode
)
{
    if (authenticode == NULL)
    {
        return;
    }

    cleanup_byte_array(&authenticode->digest);
    cleanup_byte_array(&authenticode->file_digest);
    CUSTOM_FREE(authenticode->digest_alg);
    destroy_signer(authenticode->signer);
    authenticode->signer = NULL;
    destroy_certificate_array(authenticode->certs);
    authenticode->certs = NULL;
    destroy_countersignature_array(authenticode->countersigs);
    authenticode->countersigs = NULL;
    yr_free(authenticode);
}

VOID destroy_authenticode_array(
    _In_ _Post_ptr_invalid_ AuthenticodeArray   *CONST  array
)
{
    if (array == NULL)
    {
        return;
    }

    for (size_t i = 0; i < array->count; ++i)
    {
        destroy_authenticode(array->signatures[i]);
        array->signatures[i] = NULL;
    }

    CUSTOM_FREE(array->signatures);
    yr_free(array);
}

#endif // USE_WINCRYPT_AUTHENTICODE
