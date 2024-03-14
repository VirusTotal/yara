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

#ifndef YR_AUTHENTICODE_WINDOWS_CLEANUP_H
#define YR_AUTHENTICODE_WINDOWS_CLEANUP_H

#include <authenticode-parser/windows/tools.h>

#ifdef USE_WINCRYPT_AUTHENTICODE

/// @brief Cleanups a given byte array by freeing its inner data, but not the container itself
/// @param[in]  byte_array  Byte array to be cleaned up
VOID cleanup_byte_array(
    _Inout_ ByteArray   *CONST  byte_array
);

/// @brief Cleanups a given attributes container by freeing its inner ByteArray data, but not the container itself
/// @param[in]  attributes  Attributes to be cleaned up
VOID cleanup_attributes(
    _Inout_ Attributes  *CONST  attributes
);

/// @brief Destroys certificate and free container
/// @parma[in]  certificate Certificate to be destroyed
VOID destroy_certificate(
    _In_ _Post_ptr_invalid_ Certificate *CONST  certificate
);

/// @brief Destroys certificate array and free container
/// @param[in]  certificate_array   Certificates array to be destroyed
VOID destroy_certificate_array(
    _In_ _Post_ptr_invalid_ CertificateArray    *CONST  certificate_array
);

/// @brief Destroys signer and free container
/// @param[in]  signer  Signer to be destroyed
VOID destroy_signer(
    _In_ _Post_ptr_invalid_ Signer  *CONST signer
);

/// @brief Destroy countersignature and free container
/// @param[in]  countersignature    Countersignature to be destroyed
VOID destroy_countersignature(
    _In_ _Post_ptr_invalid_ Countersignature    *CONST  countersignature
);

/// @brief Destroy countersignature array and free container
/// @param[in]  array   Countersignatures array to be destroyed
VOID destroy_countersignature_array(
    _In_ _Post_ptr_invalid_ CountersignatureArray   *CONST  array
);

/// @brief Destroy authenticode signature and free container
/// @param[in]  authenticode    Authenticode signature to be destroyed
VOID destroy_authenticode(
    _In_ _Post_ptr_invalid_ Authenticode    *CONST  authenticode
);

/// @brief Destroy authenticode signatures array and free container
/// @param[in]  array   Array of authenticode signatures to be destroyed
VOID destroy_authenticode_array(
    _In_ _Post_ptr_invalid_ AuthenticodeArray   *CONST  array
);

#endif // USE_WINCRYPT_AUTHENTICODE

#endif // !YR_AUTHENTICODE_WINDOWS_CLEANUP_H
