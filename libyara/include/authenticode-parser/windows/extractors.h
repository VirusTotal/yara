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

#ifndef YR_AUTHENTICODE_WINDOWS_EXTRACTORS_H
#define YR_AUTHENTICODE_WINDOWS_EXTRACTORS_H

#include <authenticode-parser/authenticode.h>

#include <authenticode-parser/windows/tools.h>

#if USE_WINCRYPT_AUTHENTICODE
/// @brief A function pointer prototype for the extraction and formatting of specific elements
/// from a CERT_CONTEXT to a yara Certificate data structure
/// @param[in] certificate_context  A pointer to the CERT_CONTEXT containing the property to extract
/// @param[in] certificate          The certificate to fill with extracted data
typedef VOID (*CERTIFICATE_PROPERTY_EXTRACTOR_CALLBACK_FUNC)(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
);

/// @brief Retrieves SHA256 digest from certificate context
/// @param[in]      certificate_context Certificate context to extract SHA256 digest from
/// @param[in,out]  certificate         Yara certificate data structure to store computed SHA256 digest into
/// @see CERTIFICATE_PROPERTY_EXTRACTOR_CALLBACK_FUNC
VOID retrieve_sha256_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
);

/// @brief Retrieves SHA1 digest from certificate context
/// @param[in]      certificate_context Certificate context to extract SHA1 digest from
/// @param[in,out]  certificate         Yara certificate data structure to store computed SHA1 digest into
/// @see CERTIFICATE_PROPERTY_EXTRACTOR_CALLBACK_FUNC
VOID retrieve_sha1_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
);

/// @brief Retrieves issuer from certificate context, and format it according to OpenSSL format
/// @param[in]      certificate_context Certificate context to extract issuer from
/// @param[in,out]  certificate         Yara certificate data structure to store issuer into
/// @see CERTIFICATE_PROPERTY_EXTRACTOR_CALLBACK_FUNC
VOID retrieve_issuer_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
);

/// @brief Retrieves subject from certificate context, and format it according to OpenSSL format
/// @param[in]      certificate_context Certificate context to extract subject from
/// @param[in,out]  certificate         Yara certificate data structure to store subject into
/// @see CERTIFICATE_PROPERTY_EXTRACTOR_CALLBACK_FUNC
VOID retrieve_subject_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
);

/// @brief Retrieves version from certificate context
/// @param[in]      certificate_context Certificate context to extract version from
/// @param[in,out]  certificate         Yara certificate data structure to store version into
/// @note Versions are 0 based, but we do not do the one increment in this extractor as it is done later on by Yara write_certificate maccro
/// @see CERTIFICATE_PROPERTY_EXTRACTOR_CALLBACK_FUNC
VOID retrieve_version_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
);

/// @brief Retrieves signature algorithm from certificate context
/// @param[in]      certificate_context Certificate context to extract signature algorithm from
/// @param[in,out]  certificate         Yara certificate data structure to store signature algorithm into
/// @see CERTIFICATE_PROPERTY_EXTRACTOR_CALLBACK_FUNC
VOID retrieve_signature_algorithm_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
);

/// @brief Retrieves serial from certificate context
/// @param[in]      certificate_context Certificate context to extract serial from
/// @param[in,out]  certificate         Yara certificate data structure to store serial into
/// @see CERTIFICATE_PROPERTY_EXTRACTOR_CALLBACK_FUNC
VOID retrieve_serial_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
);

/// @brief Retrieves "not before" time from certificate context
/// @param[in]      certificate_context Certificate context to extract "not before" time from
/// @param[in,out]  certificate         Yara certificate data structure to store "not before" time into
/// @see CERTIFICATE_PROPERTY_EXTRACTOR_CALLBACK_FUNC
VOID retrieve_not_before_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
);

/// @brief Retrieves "not after" time from certificate context
/// @param[in]      certificate_context Certificate context to extract "not after" time from
/// @param[in,out]  certificate         Yara certificate data structure to store "not after" time into
/// @see CERTIFICATE_PROPERTY_EXTRACTOR_CALLBACK_FUNC
VOID retrieve_not_after_from_cert_authenticode(
    _In_    PCCERT_CONTEXT          certificate_context,
    _Inout_ Certificate     *CONST  certificate
);

#endif // USE_WINCRYPT_AUTHENTICODE

#endif  // !YR_AUTHENTICODE_WINDOWS_EXTRACTORS_H
