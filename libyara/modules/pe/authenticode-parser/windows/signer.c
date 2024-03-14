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

#include <authenticode-parser/authenticode.h>

#include <yara/error.h>
#include <yara/mem.h>

#include <crypto.h>

#include <authenticode-parser/windows/tools.h>
#include <authenticode-parser/windows/certificate.h>
#include <authenticode-parser/windows/cleanup.h>
#include <authenticode-parser/windows/oid.h>
#include <authenticode-parser/windows/signer.h>

INT get_signer_info_from_crypt_message(
    _In_        CONST   HCRYPTMSG           crypt_msg,
    _In_        CONST   DWORD               signature_index,
    _Outptr_            PCMSG_SIGNER_INFO*  signer_info
)
{
    INT result = -1;

    PCMSG_SIGNER_INFO local_signer_info = NULL;
    DWORD signer_info_buffer_size = 0;

    if (crypt_msg == NULL || signer_info == NULL)
        return ERROR_INVALID_ARGUMENT;

    GOTO_EXIT_ON_FAIL(CryptMsgGetParam(crypt_msg, CMSG_SIGNER_INFO_PARAM, signature_index, NULL, &signer_info_buffer_size));

    local_signer_info = (PCMSG_SIGNER_INFO)yr_malloc(signer_info_buffer_size);
    GOTO_EXIT_ON_NULL(local_signer_info, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_FAIL(CryptMsgGetParam(crypt_msg, CMSG_SIGNER_INFO_PARAM, signature_index, local_signer_info, &signer_info_buffer_size));

    *signer_info = local_signer_info;
    local_signer_info = NULL;

    result = ERROR_SUCCESS;

_exit:

    if (local_signer_info != NULL)
    {
        yr_free(local_signer_info);
        local_signer_info = NULL;
    }

    return result;
}

INT get_unauthenticated_attributes_from_crypt_message(
    _In_      CONST   HCRYPTMSG           crypt_msg,
    _In_      CONST   DWORD               signature_index,
    _Outptr_          PCRYPT_ATTRIBUTES*  crypt_attributes
)
{
    INT result = -1;

    PCRYPT_ATTRIBUTES local_crypt_attributes = NULL;
    DWORD crypt_attributes_buf_size = 0;

    if (crypt_msg == NULL || crypt_attributes == NULL)
        return ERROR_INVALID_ARGUMENT;

    if (CryptMsgGetParam(
        crypt_msg,
        CMSG_SIGNER_UNAUTH_ATTR_PARAM,
        signature_index,
        NULL,
        &crypt_attributes_buf_size) == FALSE)
    {
        DWORD last_error = GetLastError();

        if (last_error == CRYPT_E_ATTRIBUTES_MISSING)
        {
            // This means there is no unauthenticated attribute (no nested signature for example), do not exit with error
            result = ERROR_SUCCESS;
        }

        goto _exit;
    }

    local_crypt_attributes = (PCRYPT_ATTRIBUTES)yr_calloc(1, crypt_attributes_buf_size);
    GOTO_EXIT_ON_NULL(local_crypt_attributes, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_FAIL(CryptMsgGetParam(crypt_msg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, signature_index, local_crypt_attributes, &crypt_attributes_buf_size));

    *crypt_attributes = local_crypt_attributes;
    local_crypt_attributes = NULL;

    result = ERROR_SUCCESS;

_exit:

    if (local_crypt_attributes != NULL)
    {
        yr_free(local_crypt_attributes);
        local_crypt_attributes = NULL;
    }

    return result;
}

/// @brief Look for SPC_SP_OPUS_INFO_OBJID authenticated attribute into signer info, and parse it to get the program name
/// @param[in]  signer_info Signer info from which to extract the program name
/// @param[out] signer      Signer Yara data structure into which to store the found program name, if found
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
/// @note To get program name, we have to decode SPC_SP_OPUS_INFO_OBJID attribute into SPC_SP_OPUS_INFO has not documented at https://learn.microsoft.com/en-us/windows/win32/seccrypto/constants-for-cryptencodeobject-and-cryptdecodeobject
static INT extract_program_name_from_signer_info(
    _In_      CONST   PCMSG_SIGNER_INFO           signer_info,
    _Inout_           Signer              *CONST  signer
)
{
    INT result = -1;

    ByteArray opus_info_byte_array = {0};
    BOOL has_opus_info = FALSE;

    PSPC_SP_OPUS_INFO opus_info = NULL;

    PSTR local_program_name = NULL;

    if (signer_info == NULL || signer == NULL)
        return ERROR_INVALID_ARGUMENT;

    GOTO_EXIT_ON_ERROR(get_attribute_from_crypt_attributes(&signer_info->AuthAttrs, SPC_SP_OPUS_INFO_OBJID, &opus_info_byte_array, &has_opus_info));

    // Should always be present as it is mandatory. But we won't complain if it not present
    if (has_opus_info)
    {
        DWORD opus_info_size = 0;

        // Decode content of the signed message which is CRYPT_TIMESTAMP_INFO
        GOTO_EXIT_ON_FAIL(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            SPC_SP_OPUS_INFO_OBJID,
            opus_info_byte_array.data, opus_info_byte_array.len,
            0,
            NULL,
            NULL,
            &opus_info_size));

        opus_info = yr_calloc(1, opus_info_size);
        GOTO_EXIT_ON_NULL(opus_info, ERROR_INSUFFICIENT_MEMORY);
        
        GOTO_EXIT_ON_FAIL(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            SPC_SP_OPUS_INFO_OBJID,
            opus_info_byte_array.data, opus_info_byte_array.len,
            0,
            NULL,
            opus_info,
            &opus_info_size));

        // Opus info attribute is mandatory, but program name is not
        if (opus_info->pwszProgramName != NULL)
        {
            GOTO_EXIT_ON_ERROR(widechar_utf8_to_multibytes(opus_info->pwszProgramName,
                wcslen(opus_info->pwszProgramName),
                &signer->program_name));
        }
    }

    result = ERROR_SUCCESS;

_exit:

    if (opus_info != NULL)
    {
        yr_free(opus_info);
        opus_info = NULL;
    }

    cleanup_byte_array(&opus_info_byte_array);

    return result;
}

INT parse_signer_authenticode(
  _In_      CONST   PCMSG_SIGNER_INFO           signer_info,
  _In_      CONST   HCERTSTORE                  cert_store,
  _Outptr_          Signer*             *CONST  signer
)
{
    INT result = -1;

    Signer* local_signer = NULL;

    if (signer == NULL || signer_info == NULL || cert_store == NULL)
        return ERROR_INVALID_ARGUMENT;

    local_signer = yr_calloc(1, sizeof(Signer));
    GOTO_EXIT_ON_NULL(local_signer, ERROR_INSUFFICIENT_MEMORY);

    // Get digest algorithm
    {
        PCSTR hash_algorithm = get_algorithmname_from_oid(signer_info->HashAlgorithm.pszObjId);
        if (hash_algorithm != NULL)
        {
            local_signer->digest_alg = duplicate_string(hash_algorithm);
            GOTO_EXIT_ON_NULL(local_signer->digest_alg, ERROR_INSUFFICIENT_MEMORY);
        }
    }

    // Get program name
    GOTO_EXIT_ON_ERROR(extract_program_name_from_signer_info(signer_info, local_signer));

    // Get digest
    GOTO_EXIT_ON_ERROR(get_digest_attribute_from_crypt_attributes(&signer_info->AuthAttrs, szOID_PKCS_9_MESSAGE_DIGEST, &local_signer->digest, NULL));

    // Build certificate chain
    GOTO_EXIT_ON_ERROR(build_certificate_chain_from_signer_info(cert_store, signer_info, &local_signer->chain));

    *signer = local_signer;
    local_signer = NULL;

    result = ERROR_SUCCESS;

_exit:

    if (local_signer != NULL)
    {
        destroy_signer(local_signer);
        local_signer = NULL;
    }

    return result;
}

INT verify_signature_from_signer_info(
    _In_    CONST   HCERTSTORE          cert_store,
    _In_    CONST   PCMSG_SIGNER_INFO   signer_info,
    _In_    CONST   PBYTE               digest,
    _In_    CONST   DWORD               digest_length,
    _Out_           PBOOL               is_verified
)
{
    INT result = -1;
    NTSTATUS status = 0;

    PCERT_CONTEXT cert_context = NULL;
    BCRYPT_KEY_HANDLE key_handle = NULL;

    BCRYPT_PKCS1_PADDING_INFO padding_info = {0};

    if (cert_store == NULL || signer_info == NULL || is_verified == NULL)
        return ERROR_INVALID_ARGUMENT;

    // Extract public key from signer info
    result = find_signer_certificate_from_signer_info(cert_store, signer_info, &cert_context);
    GOTO_EXIT_ON_ERROR(result);
    GOTO_EXIT_ON_FAIL(CryptImportPublicKeyInfoEx2(
        X509_ASN_ENCODING,
        &cert_context->pCertInfo->SubjectPublicKeyInfo,
        0,
        NULL,
        &key_handle
    ));

    // ---------------------------------------------------------------------------------------------------------------------------------------
    // How to verify signature, quoting https://stackoverflow.com/a/12945098
    //
    // Person with private key generating message and signature
    // originalHash = GenerateHashOfMessage(message);
    // signature = RsaDecrypt(originalHash, privateKey);
    //
    // Receiver validating signed message
    // hash = GenerateHashOfMessage(message);
    // originalHash = RsaEncrypt(signature, publicKey);
    // messageValid = (hash == originalHash);
    //
    // If you ever need to check what's inside the "encrypted digest", you can do it like so:
    //
    // BYTE buffer[2048] = {0};
    // DWORD size = 0;
    // BCryptEncrypt(key_handle, signer_info->EncryptedHash.pbData, signer_info->EncryptedHash.cbData, NULL, NULL, 0, buffer, 2048, &size, 0);
    //
    // You'll have to ignore the padding, and decode what's after [0xff][0x00], starting with 0x30
    // ---------------------------------------------------------------------------------------------------------------------------------------

    // Get BCrypt algorithm constant from hash algorithm object id
    GOTO_EXIT_ON_ERROR(find_bcrypt_algorithm_from_oid(signer_info->HashAlgorithm.pszObjId, &padding_info.pszAlgId));

    // Verify signature (RSAEncrypt with PKCS1 padding/memcmp)
    status = BCryptVerifySignature(key_handle,
        &padding_info,
        digest, digest_length,
        signer_info->EncryptedHash.pbData, signer_info->EncryptedHash.cbData,
        BCRYPT_PAD_PKCS1);
    *is_verified = (status == 0);

    result = ERROR_SUCCESS;

_exit:

    if (key_handle != NULL)
    {
        BCryptDestroyKey(key_handle);
        key_handle = NULL;
    }

    if (cert_context != NULL)
    {
        CertFreeCertificateContext(cert_context);
        cert_context = NULL;
    }

    return result;
}

#endif // USE_WINCRYPT_AUTHENTICODE
