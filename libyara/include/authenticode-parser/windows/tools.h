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

#ifndef YR_AUTHENTICODE_WINDOWS_TOOLS_H
#define YR_AUTHENTICODE_WINDOWS_TOOLS_H

#include <authenticode-parser/authenticode.h>

#if USE_WINCRYPT_AUTHENTICODE

#include <windows.h>
// Needed for LPWIN_CERTIFICATE/WIN_CERT_TYPE_PKCS_SIGNED_DATA/WIN_CERT_REVISION_2_0
#include <WinTrust.h>
#include <stdbool.h>
#include <stdint.h>
#include <winnt.h>

#define PE_WINCRYPT_TOOLS_NO_SEPARATOR_CHAR             0

/// @brief Evaluates the Unix timestamp value for the given Windows FILETIME.
/// @param[in] filetime A pointer to the FILETIME to convert.
/// @return The timestamp in UNIX representation
/// @return 0 if an invalid filetime is provided
uint64_t filetime_to_epoch(
    _In_ CONST PFILETIME filetime
);

/// @brief Formats a human-readable string of the binary content of a buffer.
/// @brief Each byte will be formatted with its hexadecimal representation on 2 characters, 0-padded.
/// @brief It is possible to select the order of the bytes as well as the separators
/// @brief between the bytes.
/// @param[in] in_buffer_size The size in bytes for in_buffer.
/// @param[in] in_buffer A pointer to the buffer to convert.
/// @param[out] out_buffer_size Optional, a pointer that receives the size of the
///                        returned out_buffer
/// @param[out] out_buffer A pointer that receives a newly allocated buffer fo the formatted string.
/// @param[in] separator The separator character to insert between bytes.
///                      PE_WINCRYPT_TOOLS_NO_SEPARATOR_CHAR if no separator is required.
/// @param[in] reverse in_buffer will be enumerated backwards if true, forward if false.
/// @return ERROR_SUCCESS on success
/// @return A Yara error code otherwise
/// @note the caller is responsible for the clean up of out_buffer using yr_free
INT buffer_to_hex(
    _In_    CONST   size_t          in_buffer_size,
    _In_    CONST   PBYTE           in_buffer,
    _Out_           size_t  *const  out_buffer_size,
    _Outptr_        PCSTR   *const  out_buffer,
    _In_    CONST   CHAR            separator,
    _In_    CONST   BOOL            reverse
);

/// @brief Duplicates the given string
/// @param[in]  source  Source string to be duplicated
/// @return Duplicated string address. To be freed using yr_free
PSTR duplicate_string(
    _In_ PCSTR source
);

/// @brief Converts an UTF-8 widechar string into a multibytes string
/// @param[in]  data                Input data blob to be converted
/// @param[in]  data_length         Length of the data blob to be converted
/// @param[out] multibyte_string    Resulting converted string. To be freed using yr_free
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT widechar_utf8_to_multibytes(
    _In_        CONST   PVOID           data,
    _In_        CONST   DWORD           data_length,
    _Outptr_            PSTR    *CONST  multibyte_string
);

/// @brief Duplicates a given cert rdn attribute into a multibytes string. Converts it if necessary
/// @param[in]  cert_rdn_attr   Attribute to get
/// @param[out] value           Extracted value. To be freed using yr_free
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT get_string_value_from_cert_rdn_value_blob(
    _In_        CONST   PCERT_RDN_ATTR          cert_rdn_attr,
    _Outptr_            PSTR            *CONST  value
);

/// @brief Looks for digest attribute identified by the specified attribute oid, and check if this is an octet string before copying it to byte array
/// @param[in]  crypt_attributes    Crypt attributes from where to look for digest attribute
/// @param[in]  attribute_oid       OID of the digest attribute we're looking for
/// @param[out] byte_array          Byte array to which copy digest if found
/// @param[out] is_found            Set to TRUE if the attribute has been found
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT get_digest_attribute_from_crypt_attributes(
    _In_    CONST   PCRYPT_ATTRIBUTES           crypt_attributes,
    _In_            PCSTR                       attribute_oid,
    _Out_           ByteArray           *CONST  byte_array,
    _Out_opt_       PBOOL                       is_found
);

/// @brief Looks for the signing time attribute into an RSA countersignature
/// @param[in]  crypt_attributes    Crypt attributes from where to look for signing time attribute
/// @param[out] epoch               Signing time, expressed as unix timestamp
/// @param[out] is_found            Set to TRUE if signing time attrubute has been found
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT get_rsa_signing_time_attribute_from_crypt_attributes(
    _In_    CONST   PCRYPT_ATTRIBUTES   crypt_attributes,
    _Out_           PULONGLONG          epoch,
    _Out_opt_       PBOOL               is_found
);

/// @brief Look for any kind a attribute identified by its OID to be retrieved raw into a byte array
/// @param[in]  crypt_attributes    Crypt attributes from where to look for attribute
/// @param[in]  attribute_oid       OID of the attribute to get raw data for
/// @param[out] byte_array          Byte array into which copy attribute raw data if found
/// @param[out] is_found            Set to TRUE if the attribute we were looking for has been found
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT get_attribute_from_crypt_attributes(
    _In_    CONST   PCRYPT_ATTRIBUTES           crypt_attributes,
    _In_            PCSTR                       attribute_oid,
    _Out_           ByteArray           *CONST  byte_array,
    _Out_opt_       PBOOL                       is_found
);

/// @brief Copies data to byte array, by allocating byte array internal buffer
/// @param[in]  data        Data to be copied
/// @param[in]  length      Length of the data to be copied
/// @param[out] byte_array  Byte array into which copy the data
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT copy_data_to_byte_array(
    _In_    CONST   PBYTE               data,
    _In_    CONST   DWORD               length,
    _Out_           ByteArray   *CONST  byte_array
);

/// @brief Compute digest for the given blob using the given algorithm oid
/// @param[in]  bcrypt_digest_algorithm BCrypt constant for the digest algorithm to use
/// @param[in]  data_to_digest          Data to digest
/// @param[in]  data_to_digest_length   Length of data to digest
/// @param[out] digest                  Computed digest
/// @param[out] digest_length           Length of the computed digest
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT compute_blob_digest(
  _In_      CONST   PCWSTR          bcrypt_digest_algorithm,
  _In_      CONST   PBYTE           data_to_digest,
  _In_      CONST   DWORD           data_to_digest_length,
  _Outptr_          PBYTE   *CONST  digest,
  _Out_             PDWORD          digest_length
);

/// @brief A structure representing a string with buffer reallocation capabilities
typedef struct _DYNAMIC_STRING
{
  /// @brief The buffer containing an ANSI-string
  LPSTR buffer;

  /// @brief The size in bytes of buffer
  DWORD buffer_size;
} DYNAMIC_STRING, *PDYNAMIC_STRING;

/// @brief Concatenates a regular string to a DYNAMIC_STRING.
/// @param[in,out] dynamic_string A pointer to a valid DYNAMIC_STRING (i.e. already initiated).
/// @param[in] str_append A pointer to the string to concatenate
/// @return ERROR_SUCCESS on success, a Yara error code otherwise
INT dynamic_string_append(
  _Inout_   CONST   PDYNAMIC_STRING dynamic_string,
  _In_              PCSTR           str_append
);

/// @brief Allocates a DYNAMIC_STRING buffer for the first time. Default size is 50 bytes large.
/// @param[out] dynamic_string  A pointer to the DYNAMIC_STRING to initialize.
/// @return ERROR_SUCCESS on success, a Yara error code otherwise
INT dynamic_string_init(
  _Out_ CONST   PDYNAMIC_STRING dynamic_string
);

/// @brief Cleans up resources allocated for a DYNAMIC_STRING.
/// @param[in, out] dynamic_string  A pointer to the DYNAMIC_STRING to clean up.
VOID dynamic_string_free(
  _Inout_   PDYNAMIC_STRING dynamic_string
);

#endif // USE_WINCRYPT_AUTHENTICODE

#endif  // !YR_AUTHENTICODE_WINDOWS_TOOLS_H
