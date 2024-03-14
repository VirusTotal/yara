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

#ifndef YR_AUTHENTICODE_WINDOWS_SIGNER_H
#define YR_AUTHENTICODE_WINDOWS_SIGNER_H

#include <authenticode-parser/windows/tools.h>

#if USE_WINCRYPT_AUTHENTICODE

#include <authenticode-parser/authenticode.h>

/// @brief Parses a signer info into a Yara Signer data structure
/// @param[in]  signer_info     Signature signer info
/// @param[in]  cert_store      Cert store for the given signature
/// @param[out] signer          Resulting allocated signer data structure, to be freed using Yara's signer_free
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT parse_signer_authenticode(
    _In_        CONST   PCMSG_SIGNER_INFO           signer_info,
    _In_        CONST   HCERTSTORE                  cert_store,
    _Outptr_            Signer*             *CONST  signer
);

/// @brief Retrieves signer info from the given crypt message
/// @param[in]  crypt_msg       Crypt message from which to retrieve the signer info
/// @param[in]  signature_index Signature for which to retrieve the signer info
/// @param[out] signer_info     Signer info obtained from crypt message. To be freed using yr_free
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT get_signer_info_from_crypt_message(
    _In_        CONST   HCRYPTMSG           crypt_msg,
    _In_        CONST   DWORD               signature_index,
    _Outptr_            PCMSG_SIGNER_INFO*  signer_info
);

/// @brief Retrieves unauthenticated attributes of signer from the given crypt message
/// @param[in]  crypt_msg           Crypt message from which to retrieve the signer unauthenticated attributes
/// @param[in]  signature_index     Signature for which to retrieve the signer unauthenticated attributes
/// @param[out] crypt_attributes    Unauthenticated attributes obtained from crypt message for signer. To be freed using yr_free
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT get_unauthenticated_attributes_from_crypt_message(
    _In_        CONST   HCRYPTMSG           crypt_msg,
    _In_        CONST   DWORD               signature_index,
    _Outptr_            PCRYPT_ATTRIBUTES*  crypt_attributes
);

/// @brief Verifies signature's signer info using WinVerifyTrust
/// @param[in]  cert_store      Certificate store to use to verify signer info
/// @param[in]  signer_info     Signer info to verify
/// @param[in]  digest          Digest of the data being signed
/// @param[in]  digest_length   Length of the digest of the data being signed
/// @param[out] is_verified     Stores the verification result
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
/// @note Digest is digest of the signed attributes DER representation or encapContentInfo eContent as specified at https://datatracker.ietf.org/doc/html/rfc5652#section-5.4
INT verify_signature_from_signer_info(
  _In_  CONST   HCERTSTORE          cert_store,
  _In_  CONST   PCMSG_SIGNER_INFO   signer_info,
  _In_  CONST   PBYTE               digest,
  _In_  CONST   DWORD               digest_length,
  _Out_         PBOOL               is_verified
);

#endif // USE_WINCRYPT_AUTHENTICODE

#endif // !YR_AUTHENTICODE_WINDOWS_SIGNER_H
