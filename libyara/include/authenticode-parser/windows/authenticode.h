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

#ifndef YR_AUTHENTICODE_WINDOWS_H
#define YR_AUTHENTICODE_WINDOWS_H

#include <authenticode-parser/authenticode.h>

#include <authenticode-parser/windows/tools.h>

#if USE_WINCRYPT_AUTHENTICODE

/// @brief Parses PE certificate directory data to extract signatures from it
/// @param[in]      data                Certificate directory raw data PKCS7 blob to read signatures from
/// @param[in]      length              Length of the data in bytes
/// @param[in, out] authenticode_array  Signatures array read from data. To be freed using authenticode_array_free
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT parse_authenticode_wincrypt(
  _In_      CONST   PBYTE               data,
  _In_      CONST   DWORD               length,
  _Inout_           AuthenticodeArray*  authenticode_array
);

/// @brief Computes file digest from the given pe data blob, using the digest algorithm specified in the given signature
/// @param[in, out] authenticode        Authenticode signature to read digest algorithm from, and to write the computed file digest to
/// @param[in]      pe_data             PE data blob
/// @param[in]      pe_length           PE data blob length in bytes
/// @param[in]      pe_header_offset    Offset to the pe header
/// @param[in]      is_64bit            Is the PE 64 bits ?
/// @param[in]      cert_addr           Certificates directory address
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT authenticode_wincrypt_compute_file_digest(
  _Inout_           Authenticode    *CONST  authenticode,
  _In_      CONST   PBYTE                   pe_data,
  _In_      CONST   ULONGLONG               pe_length,
  _In_      CONST   uint32_t                pe_header_offset,
  _In_      CONST   BOOL                    is_64bit,
  _In_      CONST   uint64_t                cert_addr
);

#endif  // USE_WINCRYPT_AUTHENTICODE

#endif  // !YR_AUTHENTICODE_WINDOWS_H
