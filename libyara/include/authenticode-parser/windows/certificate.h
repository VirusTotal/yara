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

#ifndef YR_AUTHENTICODE_WINDOWS_CERTIFICATE_H
#define YR_AUTHENTICODE_WINDOWS_CERTIFICATE_H

#include <authenticode-parser/authenticode.h>

#include <authenticode-parser/windows/tools.h>

#if USE_WINCRYPT_AUTHENTICODE

/// @brief Builds a Yara certificates array from the given Microsoft certificates store
/// @param[in]  cert_store          Certificate from which to extract all certificates
/// @param[out] certificate_array   Yara certificates array data structure built from the given Microsoft certificates store. To be freed using certificate_array_free
INT get_all_certificates_authenticode(
    _In_        CONST   HCERTSTORE                  cert_store,
    _Outptr_            CertificateArray*   *CONST  certificate_array
);

/// @brief Take a certificate name blob, which can be an issuer or a subject, and format
/// it using known OID to match the output given by OpenSSL
/// @param[in]  cert_name_blob  Certificate name blob which ie. an issuer or a subject
/// @param[out] Formatted name as PSTR string
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
/// @note The straightforward way to obtain the issuer/subject dn would have been to call
/// @note CertNameToStrA. But some minors differences would appear relatively to the use
/// @note of OpenSSL. However the objective of this module is always have the  same output
/// @note regardless of the API used. That is why, despite the heaviness, it is prefered to
/// @note build our proper string by enumerating all RDN and using a matching strings table.
INT format_cert_name_blob_using_known_oid(
    _In_        CONST   CERT_NAME_BLOB*         cert_name_blob,
    _Outptr_            PSTR            *CONST  formatted_name
);

/// @brief Parses the cert name blob to extract attributes it finds in it
/// @param[in]  cert_name_blob  Data blob to parse to extract attributes
/// @param[out] attributes      Parsed attributes that could be found
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT fill_attributes_using_cert_name_blob(
    _In_    CONST PCERT_NAME_BLOB           cert_name_blob,
    _Out_         Attributes        *CONST  attributes
);

/// @brief Builds certificates chain from a given signer info
/// @param[in]  cert_store              Certificates store to use to build signer certificates chain
/// @param[in]  signer_info             Signer info to build certificates chain for
/// @param[out] certificate_chain_array Resulting built certificates chain
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT build_certificate_chain_from_signer_info(
    _In_    CONST   HCERTSTORE                  cert_store,
    _In_    CONST   PCMSG_SIGNER_INFO           signer_info,
    _Out_           CertificateArray*   *CONST  certificate_chain_array
);

/// @brief Find the signer certificate from certificates store using signer info issuer and serial number
/// @param[in]  cert_store      Certificates store from where to look for the signer certificate
/// @param[in]  signer_info     Signer info to use to look for certificate
/// @param[out] cert_context    Found certificate, to be freed using CertFreeCertificateContext
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT find_signer_certificate_from_signer_info(
    _In_      CONST   HCERTSTORE                  cert_store,
    _In_      CONST   PCMSG_SIGNER_INFO           signer_info,
    _Outptr_          PCERT_CONTEXT       *CONST  cert_context
);

#endif // USE_WINCRYPT_AUTHENTICODE

#endif // !YR_AUTHENTICODE_WINDOWS_CERTIFICATE_H
