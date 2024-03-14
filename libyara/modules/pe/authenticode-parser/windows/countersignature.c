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
#include <authenticode-parser/windows/cleanup.h>
#include <authenticode-parser/windows/countersignature.h>
#include <authenticode-parser/windows/oid.h>
#include <authenticode-parser/windows/signer.h>

#include <authenticode-parser/authenticode.h>
#include "../countersignature.h"

#include <yara/error.h>
#include <yara/mem.h>

/// @brief Parse RSA countersignature from the given RSA countersignature data blob (which is a signer info blob)
/// @param[in]      cert_store                  Signature certificates store
/// @param[in]      data                        RSA countersignature data blob (which is a signer info blob)
/// @param[in]      length                      RSA countersignature data blob length
/// @param[in]      signature_encrypted_digest  Encrypted digest from signature signature info, which is the signature blob
/// @param[in, out] countersignature_array  Countersignatures array, where this countersignature will be appended
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
static INT parse_rsa_countersignature(
    _In_    CONST   HCERTSTORE                      cert_store,
    _In_    CONST   PBYTE                           data,
    _In_    CONST   DWORD                           length,
    _In_    CONST   PCRYPT_DATA_BLOB                signature_encrypted_digest,
    _Inout_         CountersignatureArray   *CONST  countersignature_array
)
{
    INT result = -1;

    Countersignature* local_countersignature = NULL;

    PCMSG_SIGNER_INFO signer_info = NULL;
    DWORD counter_signature_signer_info_size = 0;

    PCWSTR countersigned_digest_bcrypt_algorithm = NULL;
    PBYTE countersigned_data_digest = NULL;
    DWORD countersigned_data_digest_length = 0;

    PCWSTR countersignature_signed_attributes_bcrypt_algorithm = NULL;
    PBYTE encoded_signed_attributes_digest = NULL;
    DWORD encoded_signed_attributes_digest_length = 0;

    PBYTE encoded_signed_attributes = NULL;
    DWORD encoded_signed_attributes_length = 0;

    BOOL is_valid = FALSE;

    if (cert_store == NULL || data == NULL || length == 0 || signature_encrypted_digest == NULL || countersignature_array == NULL)
        return ERROR_INVALID_ARGUMENT;

    // Decode content of the signed message which is signer info
    GOTO_EXIT_ON_FAIL(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        PKCS7_SIGNER_INFO,
        data, length,
        0,
        NULL,
        NULL,
        &counter_signature_signer_info_size));

    signer_info = yr_calloc(1, counter_signature_signer_info_size);
    GOTO_EXIT_ON_NULL(signer_info, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_FAIL(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        PKCS7_SIGNER_INFO,
        data, length,
        0,
        NULL,
        signer_info,
        &counter_signature_signer_info_size));

    local_countersignature = yr_calloc(1, sizeof(Countersignature));
    GOTO_EXIT_ON_NULL(local_countersignature, ERROR_INSUFFICIENT_MEMORY);

    // Get digest algorithm
    local_countersignature->digest_alg = get_algorithmname_from_oid(signer_info->HashAlgorithm.pszObjId);
    GOTO_EXIT_ON_NULL(local_countersignature->digest_alg, ERROR_INSUFFICIENT_MEMORY);

    // Get digest
    GOTO_EXIT_ON_ERROR(get_digest_attribute_from_crypt_attributes(&signer_info->AuthAttrs, szOID_PKCS_9_MESSAGE_DIGEST, &local_countersignature->digest, NULL));

    // Get signing time
    GOTO_EXIT_ON_ERROR(get_rsa_signing_time_attribute_from_crypt_attributes(&signer_info->AuthAttrs, &local_countersignature->sign_time, NULL));

    // Build certificate chain
    GOTO_EXIT_ON_ERROR(build_certificate_chain_from_signer_info(cert_store, signer_info, &local_countersignature->chain));

    // ----------------------------------------
    // Check if countersigned data are matching
    // ----------------------------------------

    countersigned_digest_bcrypt_algorithm = find_algorithm_from_algorithm_name(local_countersignature->digest_alg);
    GOTO_EXIT_ON_NULL(countersigned_digest_bcrypt_algorithm, ERROR_INVALID_VALUE);

    // Compute countersigned data digest
    GOTO_EXIT_ON_ERROR(compute_blob_digest(countersigned_digest_bcrypt_algorithm,
        signature_encrypted_digest->pbData,
        signature_encrypted_digest->cbData,
        &countersigned_data_digest,
        &countersigned_data_digest_length));

    // Check if the digests match
    GOTO_EXIT_ON_FAIL(local_countersignature->digest.len == countersigned_data_digest_length);
    if (memcmp(countersigned_data_digest, local_countersignature->digest.data, countersigned_data_digest_length) != 0)
    {
        // Do not loose the initial error, if any
        if (local_countersignature->verify_flags == COUNTERSIGNATURE_VFY_VALID)
            local_countersignature->verify_flags = COUNTERSIGNATURE_VFY_DOESNT_MATCH_SIGNATURE;
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------
    // Check if countersignature is valid, doing what's specified at https://datatracker.ietf.org/doc/html/rfc5652#section-5.4
    // If signed attributes exist, get its DER representation and change it from CONTEXT SPECIFIC (A0) to EXPLICIT SET (31), compute its digest
    // based on message digest algorithm
    // Here we use CryptEncodeObject to encode the signed attributes so we do not need to change A0 to 31, it is done by encoding
    // ----------------------------------------------------------------------------------------------------------------------------------------

    // Encode signed attributes
    GOTO_EXIT_ON_FAIL(CryptEncodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        PKCS_ATTRIBUTES,
        &signer_info->AuthAttrs,
        NULL,
        &encoded_signed_attributes_length));
    encoded_signed_attributes = yr_calloc(encoded_signed_attributes_length, sizeof(BYTE));
    GOTO_EXIT_ON_NULL(encoded_signed_attributes, ERROR_INSUFFICIENT_MEMORY);
    GOTO_EXIT_ON_FAIL(CryptEncodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        PKCS_ATTRIBUTES,
        &signer_info->AuthAttrs,
        encoded_signed_attributes,
        &encoded_signed_attributes_length));

    // Get BCrypt algorithm
    GOTO_EXIT_ON_ERROR(find_bcrypt_algorithm_from_oid(signer_info->HashAlgorithm.pszObjId,
        &countersignature_signed_attributes_bcrypt_algorithm));
    GOTO_EXIT_ON_NULL(countersignature_signed_attributes_bcrypt_algorithm, ERROR_INVALID_VALUE);

    // Compute the signed attributes DER encoding digest, based on countersignature signer info's digest algorithm
    GOTO_EXIT_ON_ERROR(compute_blob_digest(countersignature_signed_attributes_bcrypt_algorithm, encoded_signed_attributes, encoded_signed_attributes_length, &encoded_signed_attributes_digest, &encoded_signed_attributes_digest_length));

    // Ensure countersignature is correctly signed
    GOTO_EXIT_ON_ERROR(verify_signature_from_signer_info(cert_store, signer_info, encoded_signed_attributes_digest, encoded_signed_attributes_digest_length, &is_valid));
    if (is_valid == FALSE)
    {
        // Do not loose the initial error, if any
        if (local_countersignature->verify_flags == COUNTERSIGNATURE_VFY_VALID)
            local_countersignature->verify_flags = COUNTERSIGNATURE_VFY_INVALID;
    }

    GOTO_EXIT_ON_ERROR(countersignature_array_insert(countersignature_array, local_countersignature));
    local_countersignature = NULL;

    result = ERROR_SUCCESS;

_exit:

    if (encoded_signed_attributes != NULL)
    {
        yr_free(encoded_signed_attributes);
        encoded_signed_attributes = NULL;
    }

    if (encoded_signed_attributes_digest != NULL)
    {
        yr_free(encoded_signed_attributes_digest);
        encoded_signed_attributes_digest = NULL;
    }

    if (countersigned_data_digest != NULL)
    {
        yr_free(countersigned_data_digest);
        countersigned_data_digest = NULL;
    }

    if (local_countersignature != NULL)
    {
        destroy_countersignature(local_countersignature);
        local_countersignature = NULL;
    }

    if (signer_info != NULL)
    {
        yr_free(signer_info);
        signer_info = NULL;
    }

    return result;
}

/// @brief Appends countersignature certificates to all certificates array
/// @param[in]      cert_store          Countersignature certificates store to extract all certificates from
/// @param[in, out] certificate_array   Certificates array to insert countersignatures certificates into
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
/// @note This is only used for microsoft RFC3161 countersignatures which carry certificates in it, whereas RSA countersignatures expect countersignature certificates to be in parent signer info
static INT append_counter_signature_certificates_to_all_certificates(
  _In_      CONST   HCERTSTORE                  cert_store,
  _Inout_           CertificateArray    *CONST  certificate_array
)
{
    INT result = -1;

    CertificateArray* local_certificate_array = NULL;
    Certificate** local_certificates = NULL;

    DWORD certificate_total_count = 0;

    if (cert_store == NULL || certificate_array == NULL)
        return ERROR_INVALID_ARGUMENT;

    GOTO_EXIT_ON_ERROR(get_all_certificates_authenticode(cert_store, &local_certificate_array));

    // There should be at least one certificate
    GOTO_EXIT_ON_FAIL(local_certificate_array->count > 0);

    certificate_total_count = local_certificate_array->count + certificate_array->count;

    local_certificates = yr_calloc(certificate_total_count, sizeof(Certificate*));
    GOTO_EXIT_ON_NULL(local_certificates, ERROR_INSUFFICIENT_MEMORY);

    memcpy(local_certificates, certificate_array->certs, certificate_array->count * sizeof(Certificate*));
    memcpy(local_certificates + certificate_array->count, local_certificate_array->certs, local_certificate_array->count * sizeof(Certificate*));

    if (certificate_array->certs != NULL)
        // Free container but not elements
        yr_free(certificate_array->certs);

    certificate_array->certs = local_certificates;
    certificate_array->count = certificate_total_count;

    // We need to keep elements intacts so we only free the containers
    yr_free(local_certificate_array->certs);
    yr_free(local_certificate_array);
    local_certificate_array = NULL;

    result = ERROR_SUCCESS;

_exit:

    if (local_certificate_array != NULL)
    {
        destroy_certificate_array(local_certificate_array);
        local_certificate_array = NULL;
    }

    return result;
}

/// @brief Parse MS countersignature (RFC3161) from the given MS countersignature data blob (which is a PKCS7 data blob)
/// @param[in]      signature_cert_store    Certificates store of the signature
/// @param[in]      signature_signer_info   Signer info of the signature
/// @param[in]      data                    Countersignature data blob (which is a PKCS7 data blob)
/// @param[in]      length                  Countersignature data blob length
/// @param[in, out] countersignature_array  Countersignatures array where to insert parsed countersignature
/// @param[in, out] certificate_array       Certificate array where countersignature certificates are to be inserted
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
static INT parse_ms_countersignature(
    _In_    CONST   HCERTSTORE                      signature_cert_store,
    _In_    CONST   PCMSG_SIGNER_INFO               signature_signer_info,
    _In_    CONST   PBYTE                           data,
    _In_    CONST   DWORD                           length,
    _Inout_         CountersignatureArray   *CONST  countersignature_array,
    _Inout_         CertificateArray        *CONST  certificate_array
)
{
    INT result = -1;

    HCERTSTORE countersignature_cert_store = NULL;
    HCRYPTMSG countersignature_crypt_msg = NULL;

    PCRYPT_TIMESTAMP_CONTEXT timestamp_context = NULL;
    PCRYPT_TIMESTAMP_INFO timestamp_info = NULL;
    PCMSG_SIGNER_INFO signer_info = NULL;

    // Point to the timestamp info to be used, as it can come from either CryptVerifyTimeStampSignature result or countersignature content parsing. Not to be freed
    PCRYPT_TIMESTAMP_INFO timestamp_info_to_use = NULL;

    PBYTE countersign_content_blob_data = NULL;
    DWORD countersign_content_blob_size = 0;

    DWORD timestamp_buffer_size = 0;

    Countersignature* local_countersignature = NULL;

    CERT_BLOB cert_blob = {
        .pbData = data,
        .cbData = length
    };

    if (signature_cert_store == NULL || signature_signer_info == NULL || data == NULL || length == 0 || countersignature_array == NULL || certificate_array == NULL)
        return ERROR_INVALID_ARGUMENT;

    GOTO_EXIT_ON_FAIL(CryptQueryObject(
        CERT_QUERY_OBJECT_BLOB,
        &cert_blob,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        NULL,
        NULL,
        NULL,
        &countersignature_cert_store,
        &countersignature_crypt_msg,
        NULL));

    // Add ms countersignature certificates to signature all certificates
    GOTO_EXIT_ON_ERROR(append_counter_signature_certificates_to_all_certificates(countersignature_cert_store, certificate_array));

    local_countersignature = yr_calloc(1, sizeof(Countersignature));
    GOTO_EXIT_ON_NULL(local_countersignature, ERROR_INSUFFICIENT_MEMORY);

    // Get all certificates from countersignature certificates store
    GOTO_EXIT_ON_ERROR(get_all_certificates_authenticode(countersignature_cert_store, &local_countersignature->certs));

    if (CryptVerifyTimeStampSignature(data, length,
        signature_signer_info->EncryptedHash.pbData, signature_signer_info->EncryptedHash.cbData,
        signature_cert_store,
        &timestamp_context, NULL,
        NULL))
    {
        // Countersignature is valid, we can get data from timestamp context's timestamp info
        local_countersignature->verify_flags = COUNTERSIGNATURE_VFY_VALID;

        timestamp_info_to_use = timestamp_context->pTimeStamp;
    }
    else
    {
        // Countersignature is invalid, we have to decode message content to get timestamp info
        local_countersignature->verify_flags = COUNTERSIGNATURE_VFY_DOESNT_MATCH_SIGNATURE;

        // Read content of the signed message
        GOTO_EXIT_ON_FAIL(CryptMsgGetParam(countersignature_crypt_msg, CMSG_CONTENT_PARAM, 0, NULL, &countersign_content_blob_size));

        countersign_content_blob_data = yr_calloc(countersign_content_blob_size, sizeof(BYTE));
        GOTO_EXIT_ON_NULL(countersign_content_blob_data, ERROR_INSUFFICIENT_MEMORY);

        GOTO_EXIT_ON_FAIL(CryptMsgGetParam(countersignature_crypt_msg, CMSG_CONTENT_PARAM, 0, countersign_content_blob_data, &countersign_content_blob_size));

        // Decode content of the signed message which is CRYPT_TIMESTAMP_INFO
        GOTO_EXIT_ON_FAIL(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            TIMESTAMP_INFO,
            countersign_content_blob_data, countersign_content_blob_size,
            0,
            NULL,
            NULL,
            &timestamp_buffer_size));

        timestamp_info = yr_calloc(1, timestamp_buffer_size);
        GOTO_EXIT_ON_NULL(timestamp_info, ERROR_INSUFFICIENT_MEMORY);

        GOTO_EXIT_ON_FAIL(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            TIMESTAMP_INFO,
            countersign_content_blob_data, countersign_content_blob_size,
            0,
            NULL,
            timestamp_info,
            &timestamp_buffer_size));

        timestamp_info_to_use = timestamp_info;
    }

    // Get digest algorithm
    local_countersignature->digest_alg = get_algorithmname_from_oid(timestamp_info_to_use->HashAlgorithm.pszObjId);
    GOTO_EXIT_ON_NULL(local_countersignature->digest_alg, ERROR_INSUFFICIENT_MEMORY);

    // Get digest
    GOTO_EXIT_ON_ERROR(copy_data_to_byte_array(timestamp_info_to_use->HashedMessage.pbData, timestamp_info_to_use->HashedMessage.cbData, &local_countersignature->digest));

    // Get signing time
    local_countersignature->sign_time = filetime_to_epoch(&timestamp_info_to_use->ftTime);

    GOTO_EXIT_ON_ERROR(get_signer_info_from_crypt_message(countersignature_crypt_msg, 0, &signer_info));

    // Build certificate chain
    GOTO_EXIT_ON_ERROR(build_certificate_chain_from_signer_info(countersignature_cert_store, signer_info, &local_countersignature->chain));

    GOTO_EXIT_ON_ERROR(countersignature_array_insert(countersignature_array, local_countersignature));
    local_countersignature = NULL;

    result = ERROR_SUCCESS;

_exit:

    if (timestamp_context != NULL)
    {
        CryptMemFree(timestamp_context);
        timestamp_context = NULL;
    }

    if (signer_info != NULL)
    {
        yr_free(signer_info);
        signer_info = NULL;
    }

    if (local_countersignature != NULL)
    {
        destroy_countersignature(local_countersignature);
        local_countersignature = NULL;
    }

    if (timestamp_info != NULL)
    {
        yr_free(timestamp_info);
        timestamp_info = NULL;
    }

    if (countersign_content_blob_data != NULL)
    {
        yr_free(countersign_content_blob_data);
        countersign_content_blob_data = NULL;
    }

    if (countersignature_cert_store != NULL)
    {
        CertCloseStore(countersignature_cert_store, CERT_CLOSE_STORE_FORCE_FLAG);
        countersignature_cert_store = NULL;
    }

    if (countersignature_crypt_msg != NULL)
    {
        CryptMsgClose(countersignature_crypt_msg);
        countersignature_crypt_msg = NULL;
    }

    return result;
}

INT look_for_counter_signature_authenticode(
    _In_        CONST   HCRYPTMSG                       crypt_msg,
    _In_        CONST   HCERTSTORE                      cert_store,
    _In_        CONST   DWORD                           signature_index,
    _Outptr_            CountersignatureArray*  *CONST  countersignature_array,
    _Inout_             CertificateArray        *CONST  certificate_array
)
{
    INT result = -1;

    PCRYPT_ATTRIBUTES crypt_attributes = NULL;

    ByteArray rsa_countersignature_byte_array = {0};
    ByteArray ms_countersignature_byte_array = {0};

    CountersignatureArray* local_countersignature_array = NULL;

    PCMSG_SIGNER_INFO signer_info = NULL;

    if (crypt_msg == NULL || cert_store == NULL || countersignature_array == NULL || certificate_array == NULL)
        return ERROR_INVALID_ARGUMENT;

    local_countersignature_array = yr_calloc(1, sizeof(CountersignatureArray));
    GOTO_EXIT_ON_NULL(local_countersignature_array, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_ERROR(get_unauthenticated_attributes_from_crypt_message(crypt_msg, signature_index, &crypt_attributes));
    // If there is no unauthenticated attributes, the previous function doesn't end up in error. We therefore need to check crypt_attributes
    if (crypt_attributes != NULL)
    {
        BOOL has_countersignature = FALSE;

        GOTO_EXIT_ON_ERROR(get_signer_info_from_crypt_message(crypt_msg, signature_index, &signer_info));

        // check for RFC3161 countersignature
        GOTO_EXIT_ON_ERROR(get_attribute_from_crypt_attributes(crypt_attributes, szOID_RFC3161_counterSign, &ms_countersignature_byte_array, &has_countersignature));
        if (has_countersignature)
        {
            // ms counter signature has countersignature data into its content
            GOTO_EXIT_ON_ERROR(
                parse_ms_countersignature(
                    cert_store,
                    signer_info,
                    ms_countersignature_byte_array.data, ms_countersignature_byte_array.len,
                    local_countersignature_array,
                    certificate_array
                )
            );
        }

        // check for RSA countersignature
        GOTO_EXIT_ON_ERROR(get_attribute_from_crypt_attributes(crypt_attributes, szOID_RSA_counterSign, &rsa_countersignature_byte_array, &has_countersignature));
        if (has_countersignature)
        {
            // counter signature blob is another PKCS7 data blob to be parsed, where we should find authenticated attributes digest/timestamp, and digest algorithm in signer infos
            GOTO_EXIT_ON_ERROR(
                parse_rsa_countersignature(
                    cert_store,
                    rsa_countersignature_byte_array.data, rsa_countersignature_byte_array.len,
                    &signer_info->EncryptedHash,
                    local_countersignature_array
                )
            );
        }
    }

    *countersignature_array = local_countersignature_array;
    local_countersignature_array = NULL;

    result = ERROR_SUCCESS;

_exit:

    if (signer_info != NULL)
    {
        yr_free(signer_info);
        signer_info = NULL;
    }

    if (local_countersignature_array != NULL)
    {
        destroy_countersignature_array(local_countersignature_array);
        local_countersignature_array = NULL;
    }

    cleanup_byte_array(&rsa_countersignature_byte_array);
    cleanup_byte_array(&ms_countersignature_byte_array);

    if (crypt_attributes != NULL)
    {
        yr_free(crypt_attributes);
        crypt_attributes = NULL;
    }

    return result;
}

#endif // USE_WINCRYPT_AUTHENTICODE
