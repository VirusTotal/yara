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

#ifndef YR_AUTHENTICODE_WINDOWS_COUNTERSIGNATURE_H
#define YR_AUTHENTICODE_WINDOWS_COUNTERSIGNATURE_H

#include <authenticode-parser/windows/tools.h>

#if USE_WINCRYPT_AUTHENTICODE

/// @brief Looks into crypt message for countersignature in unauthenticated attributes. Can either be RFC3161 or RSA countersignature
/// @param[in]      crypt_msg               Crypt message from which to look for countersignatures
/// @param[in]      cert_store              Signature certificates store
/// @param[in]      signature_index         Signature identified by its index to use to retrieve unauthenticated attributes
/// @param[out]     countersignature_array  Countersignatures array into which to insert found countersignatures
/// @param[in, out] certificate_array       Array of certificates into which to insert newly found certificates in the case of a MS RFC3161 countersignature
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT look_for_counter_signature_authenticode(
    _In_        CONST   HCRYPTMSG                       crypt_msg,
    _In_        CONST   HCERTSTORE                      cert_store,
    _In_        CONST   DWORD                           signature_index,
    _Outptr_            CountersignatureArray*  *CONST  countersignature_array,
    _Inout_             CertificateArray        *CONST  certificate_array
);

#endif // USE_WINCRYPT_AUTHENTICODE

#endif // !YR_AUTHENTICODE_WINDOWS_COUNTERSIGNATURE_H
