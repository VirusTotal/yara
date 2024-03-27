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

#include <crypto.h>

#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/pe.h>

#ifdef USE_WINCRYPT_AUTHENTICODE
#include <authenticode-parser/windows/tools.h>
#include <authenticode-parser/windows/authenticode.h>
#include <authenticode-parser/windows/certificate.h>
#include <authenticode-parser/windows/cleanup.h>
#include <authenticode-parser/windows/countersignature.h>
#include <authenticode-parser/windows/extractors.h>
#include <authenticode-parser/windows/oid.h>
#include <authenticode-parser/windows/signer.h>

#include <authenticode-parser/authenticode.h>

/// @brief Check for nested signature attribute and parse it
/// @param[in]      crypt_msg           Crypt message from which to look for nested signature
/// @param[in, out] authenticode_array  Parsed authenticode array
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
static INT check_for_nested_signature_authenticode(
    _In_  CONST   HCRYPTMSG                   crypt_msg,
    _Inout_       AuthenticodeArray   *CONST  authenticode_array
)
{
    INT result = -1;

    PCRYPT_ATTRIBUTES crypt_attributes = NULL;

    if (authenticode_array == NULL || crypt_msg == NULL)
        return ERROR_INVALID_ARGUMENT;

    GOTO_EXIT_ON_ERROR(get_unauthenticated_attributes_from_crypt_message(crypt_msg, 0, &crypt_attributes));
    // If there is no unauthenticated attributes, the previous function doesn't end up in error. We therefore need to check crypt_attributes
    if (crypt_attributes != NULL)
    {
        for (DWORD attribute_index = 0; attribute_index < crypt_attributes->cAttr;
            attribute_index++)
        {
            if (strcmp(crypt_attributes->rgAttr[attribute_index].pszObjId, szOID_NESTED_SIGNATURE) == 0)
            {
                GOTO_EXIT_ON_ERROR(parse_authenticode_wincrypt(crypt_attributes->rgAttr[attribute_index].rgValue[0].pbData,
                    crypt_attributes->rgAttr[attribute_index].rgValue[0].cbData,
                    authenticode_array));

                break;
            }
        }
    }

    result = ERROR_SUCCESS;

_exit:

    if (crypt_attributes != NULL)
    {
        yr_free(crypt_attributes);
        crypt_attributes = NULL;
    }

    return result;
}

/// @brief Extract signature digest/digest algorithm from crypt message content
/// @param[in]      crypt_msg       Crypt message from which to retrieve digest/digest algorithm
/// @param[in, out] authenticode    Authenticode signature to write digest/digest algorithm to
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
static INT extract_signature_data_from_crypt_message_content(
    _In_      CONST   HCRYPTMSG               crypt_msg,
    _Inout_           Authenticode    *CONST  authenticode
)
{
    INT result = -1;

    DWORD content_blob_size = 0;
    PBYTE content_blob_data = NULL;

    DWORD spc_indirect_data_size = 0;
    PSPC_INDIRECT_DATA_CONTENT spc_indirect_data_content = NULL;

    if (crypt_msg == NULL || authenticode == NULL)
        return ERROR_INVALID_ARGUMENT;

    // Read content of the signed message
    GOTO_EXIT_ON_FAIL(CryptMsgGetParam(crypt_msg, CMSG_CONTENT_PARAM, 0, NULL, &content_blob_size));

    content_blob_data = yr_calloc(content_blob_size, sizeof(BYTE));
    GOTO_EXIT_ON_NULL(content_blob_data, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_FAIL(CryptMsgGetParam(crypt_msg, CMSG_CONTENT_PARAM, 0, content_blob_data, &content_blob_size));

    // Decode content of the signed message which is CRYPT_TIMESTAMP_INFO
    GOTO_EXIT_ON_FAIL(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        SPC_INDIRECT_DATA_OBJID,
        content_blob_data, content_blob_size,
        0,
        NULL,
        NULL,
        &spc_indirect_data_size));

    spc_indirect_data_content = yr_calloc(1, spc_indirect_data_size);
    GOTO_EXIT_ON_NULL(spc_indirect_data_content, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_FAIL(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        SPC_INDIRECT_DATA_OBJID,
        content_blob_data, content_blob_size,
        0,
        NULL,
        spc_indirect_data_content,
        &spc_indirect_data_size));

    GOTO_EXIT_ON_ERROR(copy_data_to_byte_array(spc_indirect_data_content->Digest.pbData, spc_indirect_data_content->Digest.cbData, &authenticode->digest));

    authenticode->digest_alg = get_algorithmname_from_oid(spc_indirect_data_content->DigestAlgorithm.pszObjId);
    GOTO_EXIT_ON_NULL(authenticode->digest_alg, ERROR_INSUFFICIENT_MEMORY);

    result = ERROR_SUCCESS;

_exit:

    if (spc_indirect_data_content != NULL)
    {
        yr_free(spc_indirect_data_content);
        spc_indirect_data_content = NULL;
    }

    if (content_blob_data != NULL)
    {
        yr_free(content_blob_data);
        content_blob_data = NULL;
    }

    return result;
}

/// @brief Verifies if signature message digest attribute values matches with computed one
/// @param[in]  crypt_msg   Cryptographic message handle
/// @param[in]  signer      Parsed signer information, to get digest/digest algorithm to be checked from
/// @param[in]  is_verified Set to TRUE if digest matches
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
/// @note See https://datatracker.ietf.org/doc/html/rfc5652#section-11.2
/// @note See https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/#length
static INT verify_signature_message_digest(
    _In_  CONST   HCRYPTMSG           crypt_msg,
    _In_  CONST   Signer      *CONST  signer,
    _Out_         PBOOL               is_verified
)
{
    INT result = -1;

    PCWSTR digest_algorithm = NULL;

    DWORD econtent_size = 0;
    PBYTE econtent_data = NULL;

    DWORD payload_to_digest_length = 0;
    DWORD total_length_occupied_bytes = 0;

    PBYTE digest = NULL;
    DWORD digest_length = 0;

    if (crypt_msg == NULL || signer == NULL || is_verified == NULL)
        return ERROR_INVALID_ARGUMENT;

    // To compute signer info message digest attribute value, and as not clearly specified at
    // https://datatracker.ietf.org/doc/html/rfc5652#section-11.2, we have to get content, and
    // compute its digest without the DER type and length tags bytes. To know how many bytes there
    // is to exclude, check latter comments

    GOTO_EXIT_ON_FAIL(CryptMsgGetParam(crypt_msg, CMSG_CONTENT_PARAM, 0, NULL, &econtent_size));
    // Content has to have at least one byte for type, one byte for length
    GOTO_EXIT_ON_FAIL(econtent_size > 2);
    econtent_data = yr_calloc(econtent_size, sizeof(BYTE));
    GOTO_EXIT_ON_NULL(econtent_data, ERROR_INSUFFICIENT_MEMORY);
    GOTO_EXIT_ON_FAIL(CryptMsgGetParam(crypt_msg, CMSG_CONTENT_PARAM, 0, econtent_data, &econtent_size));

    // We have to know of much bytes the length occupies. To do this, as specified at
    // https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/#length
    // We check if the 8th bit of 2nd byte (length) is set to 1.
    // If this is the case, the other 7 bits specify the number of bytes being used afterward to store the size
    if ((econtent_data[1] & 0x80) != 0)
    {
        // 0XXX XXXX. bytes marked with X are used to store the bytes count to be used for the size (see previous comment)
        CONST DWORD bytes_count_used_for_length = (econtent_data[1] & 0x7F);

        // Make sure what we have to read afterward makes sense, as we would underflow later on if this value is 0
        GOTO_EXIT_ON_FAIL(bytes_count_used_for_length > 0);

        // Length occupied bytes is the first byte which tells how many bytes are used + the used bytes
        total_length_occupied_bytes = 1 + bytes_count_used_for_length;

        // We do not handle payload larger than the size of DWORD
        GOTO_EXIT_ON_FAIL(total_length_occupied_bytes <= sizeof(DWORD));

        // Make sure the size to read doesn't make us overflow buffer, tag + (size + its extension) should fit in buffer
        GOTO_EXIT_ON_FAIL(econtent_size > 1 + total_length_occupied_bytes);

        // Length to compute digest for is specified inside bytes_count_used_for_length bytes
        // As we do not know how many bytes are used to store the length in advance, and the one with the lower index is in fact the one with most weight
        // (big endian), we need to manually reverse bytes order
        for (DWORD index = 0; index < bytes_count_used_for_length; index++)
        {
          // We start here at 2 as the first two bytes store the type tag and the size that we do skip
          payload_to_digest_length += econtent_data[2 + index]
              // The lowest byte in buffer is in fact the byte with the most weight (big endian), we reverse the order
              << (bytes_count_used_for_length - index - 1) * 8;
        }
    }
    // Otherwise, the length is only occupying one byte
    else
    {
        total_length_occupied_bytes = 1;
        payload_to_digest_length = (DWORD)econtent_data[1];
    }

    // Make sure the computed data doesn't make us overflow the buffer
    // Payload should contain enough bytes for tag + length + payload we want to digest
    GOTO_EXIT_ON_FAIL(econtent_size >= 1 + total_length_occupied_bytes + payload_to_digest_length);

    // To compute digest, we use signer's digest algorithm
    digest_algorithm = find_algorithm_from_algorithm_name(signer->digest_alg);
    GOTO_EXIT_ON_NULL(digest_algorithm, ERROR_INVALID_VALUE);

    // Compute digest, excluding tag and length
    GOTO_EXIT_ON_ERROR(compute_blob_digest(digest_algorithm,
        econtent_data + 1 + total_length_occupied_bytes,
        payload_to_digest_length,
        &digest, &digest_length));

    // Check if the digest matches
    GOTO_EXIT_ON_FAIL(signer->digest.len == digest_length);
    *is_verified = memcmp(digest, signer->digest.data, digest_length) == 0;

    result = ERROR_SUCCESS;

_exit:

    if (digest != NULL)
    {
        yr_free(digest);
        digest = NULL;
    }

    if (econtent_data != NULL)
    {
        yr_free(econtent_data);
        econtent_data = NULL;
    }

    return result;
}

/// @brief Parse signatures from the given crypt message
/// @param[in]  cert_store          Certificates store associated to these signatures
/// @param[in]  crypt_msg           Crypt message from which to parse signatures
/// @param[out] authenticode_array  Yara authenticodes array
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
static INT parse_signature_authenticode(
    _In_  CONST   HCERTSTORE                  cert_store,
    _In_  CONST   HCRYPTMSG                   crypt_msg,
    _Out_         AuthenticodeArray   *CONST  authenticode_array
)
{
    INT result = -1;

    DWORD signature_count = 0;

    DWORD local_signature_counter = 0;
    AuthenticodeArray *local_authenticode_array = NULL;

    PBYTE computed_hash = NULL;
    DWORD computed_hash_length = 0;

    Authenticode* local_signature = NULL;

    PCMSG_SIGNER_INFO signer_info = NULL;

    DWORD signature_count_param_size = sizeof(DWORD);

    if (cert_store == NULL || crypt_msg == NULL || authenticode_array == NULL)
        return ERROR_INVALID_ARGUMENT;

    local_authenticode_array = yr_calloc(1, sizeof(AuthenticodeArray));
    GOTO_EXIT_ON_NULL(local_authenticode_array, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_FAIL(CryptMsgGetParam(
        crypt_msg,
        CMSG_SIGNER_COUNT_PARAM,
        0,
        &signature_count,
        &signature_count_param_size));

    local_authenticode_array->count = signature_count;
    local_authenticode_array->signatures = yr_calloc(signature_count, sizeof(Authenticode*));
    GOTO_EXIT_ON_NULL(local_authenticode_array->signatures, ERROR_INSUFFICIENT_MEMORY);

    // Compute message digest (hash)
    // CMSG_COMPUTED_HASH_PARAM is doing what's specified at https://datatracker.ietf.org/doc/html/rfc5652#section-5.4
    // If signed attributes exist, get its DER representation and change it from CONTEXT SPECIFIC (A0) to EXPLICIT SET (31), compute its digest
    // based on message digest algorithm
    // Else compute digest for encapContentInfo eContent OCTET STRING
    GOTO_EXIT_ON_FAIL(CryptMsgGetParam(crypt_msg, CMSG_COMPUTED_HASH_PARAM, 0, NULL, &computed_hash_length));
    computed_hash = yr_calloc(computed_hash_length, sizeof(BYTE));
    GOTO_EXIT_ON_FAIL(CryptMsgGetParam(crypt_msg, CMSG_COMPUTED_HASH_PARAM, 0, computed_hash, &computed_hash_length));
 
    for (DWORD signature_index = 0; signature_index < signature_count; signature_index++)
    {
        BOOL is_verified = FALSE;

        DWORD version = 0;
        DWORD version_size = sizeof(DWORD);

        local_signature = yr_calloc(1, sizeof(Authenticode));
        GOTO_EXIT_ON_NULL(local_signature, ERROR_INSUFFICIENT_MEMORY);

        GOTO_EXIT_ON_FAIL(CryptMsgGetParam(
            crypt_msg,
            CMSG_VERSION_PARAM,
            0,
            &version,
            &version_size));

        local_signature->version = version;

        GOTO_EXIT_ON_ERROR(get_signer_info_from_crypt_message(crypt_msg, signature_index, &signer_info));
        GOTO_EXIT_ON_ERROR(parse_signer_authenticode(signer_info, cert_store, &local_signature->signer));
        GOTO_EXIT_ON_ERROR(get_all_certificates_authenticode(cert_store, &local_signature->certs));
        GOTO_EXIT_ON_ERROR(look_for_counter_signature_authenticode(crypt_msg, cert_store, signature_index, &local_signature->countersigs, local_signature->certs));
        GOTO_EXIT_ON_ERROR(extract_signature_data_from_crypt_message_content(crypt_msg, local_signature));
        GOTO_EXIT_ON_ERROR(verify_signature_message_digest(crypt_msg, local_signature->signer, &is_verified));
        if (is_verified == FALSE)
        {
            // Do not loose the initial error, if any
            if (local_signature->verify_flags == AUTHENTICODE_VFY_VALID)
              local_signature->verify_flags = AUTHENTICODE_VFY_INVALID;
        }
        GOTO_EXIT_ON_ERROR(verify_signature_from_signer_info(cert_store, signer_info, computed_hash, computed_hash_length, &is_verified));
        if (is_verified == FALSE)
        {
            // Do not loose the initial error, if any
            if (local_signature->verify_flags == AUTHENTICODE_VFY_VALID)
              local_signature->verify_flags = AUTHENTICODE_VFY_INVALID;
        }

        local_authenticode_array->signatures[signature_index] = local_signature;
        local_signature = NULL;

        yr_free(signer_info);
        signer_info = NULL;
    }

    GOTO_EXIT_ON_ERROR(authenticode_array_move(authenticode_array, local_authenticode_array));

    yr_free(local_authenticode_array);
    local_authenticode_array = NULL;

    GOTO_EXIT_ON_ERROR(check_for_nested_signature_authenticode(crypt_msg, authenticode_array));

    result = ERROR_SUCCESS;

_exit:

    if (signer_info != NULL)
    {
        yr_free(signer_info);
        signer_info = NULL;
    }

    if (computed_hash != NULL)
    {
        yr_free(computed_hash);
        computed_hash = NULL;
    }

    if (local_authenticode_array != NULL)
    {
        destroy_authenticode_array(local_authenticode_array);
        local_authenticode_array = NULL;
    }

    return result;
}

INT authenticode_wincrypt_compute_file_digest(
    _Inout_         Authenticode    *CONST  authenticode,
    _In_    CONST   PBYTE                   pe_data,
    _In_    CONST   ULONGLONG               pe_length,
    _In_    CONST   uint32_t                pe_header_offset,
    _In_    CONST   BOOL                    is_64bit,
    _In_    CONST   uint64_t                cert_addr
)
{
    INT result = -1;

    DWORD bytes_copied = 0;

    PCWSTR algorithm_id = 0;
    BCRYPT_ALG_HANDLE  algorithm_handle = NULL;

    DWORD digest_object_size = 0;
    PUCHAR digest_object = NULL;

    PBYTE digest = NULL;
    DWORD local_digest_length = 0;

    BCRYPT_HASH_HANDLE hash_handle = NULL;

    PBYTE cursor = pe_data;

#define CHECK_CURSOR(cursor, length_to_read)            \
    if (cursor + length_to_read >= pe_data + pe_length) \
    {                                                   \
        result = ERROR_INTEGER_OVERFLOW;                  \
        goto _exit;                                       \
    }

    // If PE is 64bit, header is 16 bytes larger
    CONST DWORD pe64_extra = is_64bit ? 16 : 0;

    // Offset to pointer in DOS header, that points to PE header, at 0x3c th byte
    CONST DWORD cert_table_offset = 0x3c + pe64_extra;

    // Checksum starts at 0x58th byte of the header
    CONST DWORD pe_checksum_offset = pe_header_offset + 0x58;

    if (authenticode == NULL || cursor == NULL)
      return ERROR_INVALID_ARGUMENT;

    algorithm_id = find_algorithm_from_algorithm_name(authenticode->digest_alg);
    GOTO_EXIT_ON_NULL(algorithm_id, ERROR_INVALID_VALUE);

    GOTO_EXIT_ON_FAIL(
        BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm_handle, algorithm_id, NULL, 0))
    );
    GOTO_EXIT_ON_FAIL(
        BCRYPT_SUCCESS(BCryptGetProperty(algorithm_handle, BCRYPT_OBJECT_LENGTH, (PBYTE)&digest_object_size, sizeof(DWORD), &bytes_copied, 0))
    );
    GOTO_EXIT_ON_FAIL(bytes_copied == sizeof(DWORD));

    digest_object = yr_calloc(digest_object_size, sizeof(UCHAR));
    GOTO_EXIT_ON_NULL(digest_object, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_FAIL(
        BCRYPT_SUCCESS(BCryptCreateHash(algorithm_handle, &hash_handle, digest_object, digest_object_size, NULL, 0, 0))
    );

    /* Calculate size of the space between file start and PE header */
    CHECK_CURSOR(cursor, pe_checksum_offset);
    GOTO_EXIT_ON_FAIL(
        BCRYPT_SUCCESS(BCryptHashData(hash_handle, cursor, pe_checksum_offset, 0))
    );
    // Checksum starts at 0x58th byte of the header
    cursor += pe_header_offset + 0x58;

    /* Skip the checksum which is 4 bytes
       see https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-windows-specific-fields-image-only */
    cursor += 4;

    /* Read up to certificate table*/
    CHECK_CURSOR(cursor, cert_table_offset);
    GOTO_EXIT_ON_FAIL(
        BCRYPT_SUCCESS(BCryptHashData(hash_handle, cursor, cert_table_offset, 0))
    );
    cursor += cert_table_offset;

    /* Skip the certificate table, which is 8 bytes
       see https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only */
    cursor += 8;

    /* PE header with check sum + checksum + cert table offset + cert table len */
    /* Hash everything up to the signature (assuming signature is stored in the
     * end of the file) */
    ULONGLONG cursor_offset = cursor - pe_data;
    CHECK_CURSOR(cursor, (cert_addr - (cursor_offset)));
    GOTO_EXIT_ON_FAIL(
        BCRYPT_SUCCESS(BCryptHashData(hash_handle, cursor, (ULONG)(cert_addr - (cursor_offset)), 0))
    );

    // Finalize digest
    GOTO_EXIT_ON_FAIL(
        BCRYPT_SUCCESS(BCryptGetProperty(algorithm_handle, BCRYPT_HASH_LENGTH, (PBYTE)&local_digest_length, sizeof(DWORD), &bytes_copied, 0))
    );
    GOTO_EXIT_ON_FAIL(bytes_copied == sizeof(DWORD));

    digest = (PUCHAR)yr_calloc(local_digest_length, sizeof(BYTE));
    GOTO_EXIT_ON_NULL(digest, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_FAIL(
        BCRYPT_SUCCESS(BCryptFinishHash(hash_handle, digest, local_digest_length, 0))
    );

    authenticode->file_digest.data = digest;
    digest = NULL;
    authenticode->file_digest.len = local_digest_length;

    result = ERROR_SUCCESS;

#undef CHECK_CURSOR

_exit:

    if (digest != NULL)
    {
        yr_free(digest);
        digest = NULL;
    }

    if (hash_handle != NULL)
    {
        BCryptDestroyHash(hash_handle);
        hash_handle = NULL;
    }

    if (digest_object != NULL)
    {
        yr_free(digest_object);
        digest_object = NULL;
    }

    if (algorithm_handle != NULL)
    {
        BCryptCloseAlgorithmProvider(algorithm_handle, 0);
        algorithm_handle = NULL;
    }

    return result;
}

INT parse_authenticode_wincrypt(
    _In_    CONST   PBYTE                       data,
    _In_    CONST   DWORD                       length,
    _Inout_         AuthenticodeArray   *CONST  authenticode_array
)
{
    HCERTSTORE cert_store = NULL;
    HCRYPTMSG crypt_msg = NULL; 
    INT result = -1;

    CERT_BLOB cert_blob = {
        .pbData = data,
        .cbData = length
    };

    if (data == NULL || length == 0 || authenticode_array == NULL)
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
        &cert_store,
        &crypt_msg,
        NULL));
    GOTO_EXIT_ON_ERROR(parse_signature_authenticode(cert_store, crypt_msg, authenticode_array));

    result = ERROR_SUCCESS;

_exit:

    if (cert_store != NULL)
    {
        CertCloseStore(cert_store, CERT_CLOSE_STORE_FORCE_FLAG);
        cert_store = NULL;
    }

    if (crypt_msg != NULL)
    {
        CryptMsgClose(crypt_msg);
        crypt_msg = NULL;
    }

    return result;
}

#endif  // USE_WINCRYPT_AUTHENTICODE
