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

#include <yara/error.h>
#include <yara/mem.h>

#ifdef USE_WINCRYPT_AUTHENTICODE

#include <authenticode-parser/windows/oid.h>
#include <authenticode-parser/windows/tools.h>

// DER blob types
// https://luca.ntop.org/Teaching/Appunti/asn1.html
#define OCTET_STRING_TYPE       0x04

uint64_t filetime_to_epoch(
    _In_ CONST PFILETIME filetime
)
{
    // FILETIME unit is 100-nanosecond while Unix time base time is the second
    // 1 / 100e-9 = 10e7
    CONST uint64_t BASE_TIME_RATIO = 10000000LL;

    // Time offset, in seconds, between FILETIME time reference which is
    // January 1, 1601 (UTC) and Unix time reference which is January 1, 1970 (UTC)
    CONST uint64_t SEC_TO_UNIX_EPOCH = 11644473600LL;

    if (filetime == NULL)
        return 0;

    return ((filetime->dwLowDateTime | (uint64_t)filetime->dwHighDateTime << 32) /
        BASE_TIME_RATIO -
        SEC_TO_UNIX_EPOCH);
}

INT buffer_to_hex(
    _In_        CONST   size_t          in_buffer_size,
    _In_        CONST   PBYTE           in_buffer,
    _Out_               size_t  *CONST  out_buffer_size,
    _Outptr_            PCSTR   *CONST  out_buffer,
    _In_        CONST   CHAR            separator,
    _In_        CONST   BOOL            reverse
)
{
    PSTR out_buffer_local = NULL;
    size_t out_buffer_size_local = 0;
    INT result = -1;

    INT input_index = 0;
    PSTR output_writer = NULL;
    INT increment = 0;

    if (in_buffer == NULL || out_buffer == NULL)
        return ERROR_INVALID_ARGUMENT;

    // Compute required size (BufferSize * TwoChar + EndString)
    out_buffer_size_local = in_buffer_size * 2 + 1;

    // Add a place for separator for each element, except the last one
    if (separator != PE_WINCRYPT_TOOLS_NO_SEPARATOR_CHAR)
        out_buffer_size_local += (in_buffer_size - 1);

    out_buffer_local = yr_calloc(out_buffer_size_local, sizeof(BYTE));
    GOTO_EXIT_ON_NULL(out_buffer_local, ERROR_INSUFFICIENT_MEMORY);

    output_writer = out_buffer_local;

    if (reverse == FALSE)
    {
        input_index = 0;
        increment = 1;
    }
    else
    {
        input_index = in_buffer_size - 1;
        increment = -1;
    }

    for (size_t processed_counter = 0; processed_counter < in_buffer_size; processed_counter++)
    {
        CONST BOOL is_last = processed_counter == (in_buffer_size - 1);

        CONST size_t consumed_size = output_writer - out_buffer_local;
        CONST size_t available_size = out_buffer_size_local - consumed_size;

        output_writer += sprintf_s(
            output_writer, available_size, "%02x", in_buffer[input_index]);

        if (separator != PE_WINCRYPT_TOOLS_NO_SEPARATOR_CHAR && is_last == false)
        {
            *output_writer = separator;
            output_writer++;
        }

        input_index += increment;
    }

    out_buffer_local[out_buffer_size_local - 1] = '\0';

    if (out_buffer_size != NULL)
        *out_buffer_size = out_buffer_size_local;

    *out_buffer = out_buffer_local;
    out_buffer_local = NULL;

    result = ERROR_SUCCESS;

_exit:

    if (out_buffer_local != NULL)
    {
        yr_free(out_buffer_local);
        out_buffer_local = NULL;
    }

    return result;
}

PSTR duplicate_string(
    _In_  PCSTR source
)
{
    size_t length = 0;

    if (source == NULL)
    {
        return NULL;
    }

    length = strlen(source);
    if (length <= 0)
        return NULL;

    PSTR output = (PSTR)yr_calloc(length + 1, sizeof(CHAR));
    if (output == NULL)
        return NULL;

    return strcpy(output, source);
}

INT widechar_utf8_to_multibytes(
  _In_      CONST   PVOID           data,
  _In_      CONST   DWORD           data_length,
  _Outptr_          PSTR    *CONST  multibyte_string
)
{
    INT result = -1;

    PSTR buffer = NULL;

    INT needed_length = 0;

    if (data == NULL || multibyte_string == NULL)
    {
        return ERROR_INVALID_ARGUMENT;
    }

    needed_length = WideCharToMultiByte(CP_UTF8, 0,
        (PWCH)data, data_length,
        NULL, 0,
        NULL, NULL);
    GOTO_EXIT_ON_FAIL(needed_length > 0);

    needed_length++;

    buffer = (PSTR)yr_calloc(needed_length, sizeof(char));
    GOTO_EXIT_ON_NULL(buffer, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_FAIL(WideCharToMultiByte(CP_UTF8, 0,
        (PWCH)data, data_length,
        buffer, needed_length,
        NULL, NULL) < needed_length);

    *multibyte_string = buffer;
    buffer = NULL;

    result = ERROR_SUCCESS;

_exit:

    if (buffer != NULL)
    {
        yr_free(buffer);
        buffer = NULL;
    }

    return result;
}

/// @brief Converts the given widechar UTF8 string to a multibyte one, and converts non ASCII character into \xXX to match OpenSSL behavior
/// @param[in]  data            Widechar UTF8 data blob
/// @param[in]  data_length     Length of the widechar UTF8 data blob
/// @param[out] final_string    Resulting string, to be freed using yr_free
static INT convert_to_multibyte_formatting_unknown_character_to_hexa(
    _In_      CONST   PVOID           data,
    _In_      CONST   DWORD           data_length,
    _Outptr_          PSTR    *CONST  final_string
)
{
    INT result = -1;

    PSTR buffer = NULL;
    size_t buffer_length = 0;

    DYNAMIC_STRING dynstring = {0};

    GOTO_EXIT_ON_ERROR(widechar_utf8_to_multibytes(data, (DWORD)wcsnlen_s(data, data_length), &buffer));

    GOTO_EXIT_ON_ERROR(dynamic_string_init(&dynstring));

    buffer_length = strlen(buffer);
    for (size_t index = 0; index < buffer_length; index++)
    {
        if ((unsigned char)buffer[index] >= 128)
        {
            BYTE character[5] = {0};
            sprintf_s(character, 5, "\\x%02X", (BYTE)buffer[index]);
            GOTO_EXIT_ON_ERROR(dynamic_string_append(&dynstring, character));
        }
        else
        {
            BYTE character[2] = {buffer[index], 0};
            GOTO_EXIT_ON_ERROR(dynamic_string_append(&dynstring, character));
        }
    }

    *final_string = duplicate_string(dynstring.buffer);
    if (*final_string == NULL)
    {
        result = ERROR_INSUFFICIENT_MEMORY;
        goto _exit;
    }

    result = ERROR_SUCCESS;

_exit:

    dynamic_string_free(&dynstring);

    if (buffer != NULL)
    {
        yr_free(buffer);
        buffer = NULL;
    }

  return result;
}

INT get_string_value_from_cert_rdn_value_blob(
    _In_        CONST   PCERT_RDN_ATTR          cert_rdn_attr,
    _Outptr_            PSTR            *CONST  value
)
{
    INT result = -1;

    PSTR local_value = NULL;

    switch (cert_rdn_attr->dwValueType)
    {
    case CERT_RDN_UTF8_STRING:
        GOTO_EXIT_ON_ERROR(convert_to_multibyte_formatting_unknown_character_to_hexa(cert_rdn_attr->Value.pbData, cert_rdn_attr->Value.cbData, &local_value));
        break;

    default:
        local_value = duplicate_string(cert_rdn_attr->Value.pbData);
        GOTO_EXIT_ON_NULL(local_value, ERROR_INSUFFICIENT_MEMORY);
        break;
    }

    *value = local_value;
    local_value = NULL;

    result = ERROR_SUCCESS;

_exit:

    if (local_value != NULL)
    {
        yr_free(local_value);
        local_value = NULL;
    }

    return result;
}

INT get_digest_attribute_from_crypt_attributes(
    _In_    CONST   PCRYPT_ATTRIBUTES           crypt_attributes,
    _In_            PCSTR                       attribute_oid,
    _Out_           ByteArray           *CONST  byte_array,
    _Out_opt_       PBOOL                       is_found
)
{
    BOOL local_is_found = FALSE;

    if (crypt_attributes == NULL || attribute_oid == NULL || byte_array == NULL)
        return ERROR_INVALID_ARGUMENT;

    for (DWORD index = 0; index < crypt_attributes->cAttr; index++)
    {
        PCRYPT_ATTRIBUTE crypt_attribute = &crypt_attributes->rgAttr[index];

        if (strcmp(crypt_attribute->pszObjId, attribute_oid) == 0 &&
            // as we want to check header, we need to make sure the length is correct (1 byte for type/1 byte for length)
            crypt_attribute->rgValue[0].cbData > 2 &&
            // check if this is indeed an OCTET STRING
            crypt_attribute->rgValue[0].pbData[0] == OCTET_STRING_TYPE)
        {
            copy_data_to_byte_array(
                crypt_attribute->rgValue[0].pbData + 2 /* exclude DER header */,
                crypt_attribute->rgValue[0].cbData - 2 /* exclude DER header */,
                byte_array
            );

            local_is_found = TRUE;

            break;
        }
    }

    if (is_found != NULL)
        *is_found = local_is_found;
    
    return ERROR_SUCCESS;
}

INT get_rsa_signing_time_attribute_from_crypt_attributes(
    _In_    CONST   PCRYPT_ATTRIBUTES   crypt_attributes,
    _Out_           PULONGLONG          epoch,
    _Out_opt_       PBOOL               is_found
)
{
    BOOL local_is_found = FALSE;

    if (crypt_attributes == NULL || time == NULL)
        return ERROR_INVALID_ARGUMENT;

    for (DWORD index = 0; index < crypt_attributes->cAttr; index++)
    {
        PCRYPT_ATTRIBUTE crypt_attribute = &crypt_attributes->rgAttr[index];

        if (strcmp(crypt_attribute->pszObjId, szOID_RSA_signingTime) == 0)
        {
            FILETIME file_time = {0};
            DWORD size = sizeof(FILETIME);

            if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, szOID_RSA_signingTime, crypt_attribute->rgValue[0].pbData, crypt_attribute->rgValue[0].cbData, 0, &file_time, &size) == FALSE)
            {
                return ERROR_INVALID_VALUE;
            }

            *epoch = filetime_to_epoch(&file_time);

            local_is_found = TRUE;

            break;
        }
    }

    if (is_found != NULL)
        *is_found = local_is_found;

    return ERROR_SUCCESS;
}

INT copy_data_to_byte_array(
    _In_    CONST   PBYTE               data,
    _In_    CONST   DWORD               length,
    _Out_           ByteArray   *CONST  byte_array
)
{
    INT result = -1;

    if (data == NULL || length == 0 || byte_array == NULL)
        return ERROR_INVALID_ARGUMENT;

    byte_array->data = yr_calloc(length, sizeof(uint8_t));
    GOTO_EXIT_ON_NULL(byte_array->data, ERROR_INSUFFICIENT_MEMORY);

    byte_array->len = length;
    memcpy(byte_array->data, data, byte_array->len);

    result = ERROR_SUCCESS;

_exit:

    return result;
}

INT get_attribute_from_crypt_attributes(
    _In_        CONST   PCRYPT_ATTRIBUTES           crypt_attributes,
    _In_                PCSTR                       attribute_oid,
    _Out_               ByteArray           *CONST  byte_array,
    _Out_opt_           PBOOL                       is_found
)
{
    INT result = -1;

    BOOL local_is_found = FALSE;

    if (crypt_attributes == NULL || attribute_oid == NULL || byte_array == NULL)
        return ERROR_INVALID_ARGUMENT;

    for (DWORD index = 0; index < crypt_attributes->cAttr; index++)
    {
        PCRYPT_ATTRIBUTE crypt_attribute = &crypt_attributes->rgAttr[index];

        if (strcmp(crypt_attribute->pszObjId, attribute_oid) == 0)
        {
            GOTO_EXIT_ON_ERROR(copy_data_to_byte_array(crypt_attribute->rgValue[0].pbData, crypt_attribute->rgValue[0].cbData, byte_array));
            local_is_found = TRUE;
            break;
        }
    }

    if (is_found != NULL)
        *is_found = local_is_found;
  
    result = ERROR_SUCCESS;

_exit:

    return result;
}

INT compute_blob_digest(
    _In_        CONST   PCWSTR          bcrypt_digest_algorithm,
    _In_        CONST   PBYTE           data_to_digest,
    _In_        CONST   DWORD           data_to_digest_length,
    _Outptr_            PBYTE   *CONST  digest,
    _Out_               PDWORD          digest_length
)
{
    INT result = -1;

    BCRYPT_ALG_HANDLE algorithm_handle = NULL;
    BCRYPT_HASH_HANDLE hash_handle = NULL;

    DWORD bytes_copied = 0;

    PBYTE digest_object = NULL;
    DWORD digest_object_size = 0;

    PBYTE local_digest = NULL;
    DWORD local_digest_length = 0;

    if (bcrypt_digest_algorithm == NULL || data_to_digest == NULL || digest == NULL || digest_length == NULL)
        return ERROR_INVALID_ARGUMENT;

    GOTO_EXIT_ON_FAIL(
        BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm_handle, bcrypt_digest_algorithm, NULL, 0))
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
    GOTO_EXIT_ON_FAIL(
        BCRYPT_SUCCESS(BCryptHashData(hash_handle, data_to_digest, data_to_digest_length, 0))
    );

    // Finalize digest
    GOTO_EXIT_ON_FAIL(
        BCRYPT_SUCCESS(BCryptGetProperty(algorithm_handle, BCRYPT_HASH_LENGTH, (PBYTE)&local_digest_length, sizeof(DWORD), &bytes_copied, 0))
    );
    GOTO_EXIT_ON_FAIL(bytes_copied == sizeof(DWORD));

    local_digest = (PUCHAR)yr_calloc(local_digest_length, sizeof(BYTE));
    GOTO_EXIT_ON_NULL(local_digest, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_FAIL(
        BCRYPT_SUCCESS(BCryptFinishHash(hash_handle, local_digest, local_digest_length, 0))
    );

    *digest = local_digest;
    local_digest = NULL;
    *digest_length = local_digest_length;

    result = ERROR_SUCCESS;

_exit:

    if (local_digest != NULL)
    {
        yr_free(local_digest);
        local_digest = NULL;
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

/// @brief Evaluates the immediate superior value that is a powers of 2 for the
///        given parameter
/// @param[in] requested_size The value to be rounded to the closest higher
///                           power of 2 value.
/// @return The computed power of 2.
static __inline size_t dynamic_string_compute_power_of_2(
  _In_  CONST   size_t  requested_size
)
{
    DWORD leading_zeroes = 0;

    // Here we just detect which is the bit index of the msb in requested_size,
    // then we add one to this index and we use it as a bit shift to compute the
    // final result The values zero and and one are special values: in these
    // cases, we return 1.
    if (requested_size != 1 &&
        _BitScanReverse(&leading_zeroes, requested_size - 1))
    {
        return 1 << (1 + leading_zeroes);
    }

    return 1;
}

/// @brief Performs a buffer allocation for a DYNAMIC_STRING, following a "power of 2" rule
///        for the requested size, meaning that the size asked by the caller will be rounded 
///        to the closest higher value that is a 2^n. This can limit the impact of fast reallocation
///        due to small size requests.
/// @param[in] requested_size The number of bytes to allocate. This value will be rounded to the 
///                           closest higher power of 2 value. For instance, if the caller asks
///                           for a 37 bytes, 2^6 = 64 bytes will be effectively allocated.
/// @param[out] dynamic_string A pointer to the DYNAMIC_STRING for which we perform the allocation
/// @return ERROR_SUCCESS on success
/// @return A Yara error code otherwise
/// @note A potential already existing buffer of a DYNAMIC_STRING is not tested or managed
/// @note by this function. The memory asociated can therefore be lost. It is of the responsibilty 
/// @note of the caller to ensure that the passed DYNAMIC_STRING is clear.
/// @note The maximum allocation 
static INT dynamic_string_allocate_power_of_2(
    _In_  CONST   size_t          requested_size,
    _Out_ CONST   PDYNAMIC_STRING dynamic_string
)
{
    INT result = -1;

    CONST size_t max_allocation_size = 0x1000;

    LPSTR tmp_buffer = NULL;
    size_t allocation_size = 0;

    if (dynamic_string == NULL || requested_size == 0 || requested_size > max_allocation_size)
        return ERROR_INVALID_ARGUMENT;

    // Find the closest 2^n value
    allocation_size = dynamic_string_compute_power_of_2(requested_size);

    tmp_buffer = yr_malloc(allocation_size);
    GOTO_EXIT_ON_NULL(tmp_buffer, ERROR_INSUFFICIENT_MEMORY);

    dynamic_string->buffer = tmp_buffer;
    tmp_buffer = NULL;

    dynamic_string->buffer_size = allocation_size;

    result = ERROR_SUCCESS;

_exit:

    return result;
}

/// @brief Reallocates the buffer of a DYNAMIC_STRING if the new requested size is higher than the current capacity.
///        If so, the previous buffer is released. The content is preserved and copied to the new buffer.
/// @param[in] requested_size The size in bytes for the new buffer.
/// @param[in,out] dynamic_string A pointer to the DYNAMIC_STRING to update.
/// @return ERROR_SUCCESS on success
/// @return A Yara error code otherwise
static INT dynamic_string_extend_buffer(
    _In_    CONST   size_t          requested_size,
    _Inout_ CONST   PDYNAMIC_STRING dynamic_string
)
{
    DYNAMIC_STRING tmp_dynamic_string = {0};

    if (dynamic_string == NULL || requested_size == 0)
        return ERROR_INVALID_ARGUMENT;

    if (requested_size <= dynamic_string->buffer_size)
        return ERROR_SUCCESS;  // nothing to do

    FAIL_ON_ERROR(dynamic_string_allocate_power_of_2(requested_size, &tmp_dynamic_string));

    memcpy(tmp_dynamic_string.buffer, dynamic_string->buffer, dynamic_string->buffer_size);

    yr_free(dynamic_string->buffer);

    *dynamic_string = tmp_dynamic_string;

    return ERROR_SUCCESS;
}

INT dynamic_string_append(
  _Inout_   CONST   PDYNAMIC_STRING dynamic_string,
  _In_              PCSTR           str_append
)
{
    size_t current_size = 0;
    size_t required_size = 0;

    INT result = -1;

    if (dynamic_string == NULL || str_append == NULL)
        return ERROR_INVALID_ARGUMENT;

    current_size = strnlen_s(dynamic_string->buffer, dynamic_string->buffer_size);
    required_size = current_size + strlen(str_append) + 1;

    if (dynamic_string->buffer_size < required_size)
    {
        FAIL_ON_ERROR(dynamic_string_extend_buffer(required_size, dynamic_string));
    }

    memcpy(dynamic_string->buffer + current_size, str_append, strlen(str_append));

    return ERROR_SUCCESS;
}

INT dynamic_string_init(
    _Out_   CONST   PDYNAMIC_STRING dynamic_string
)
{
    CONST size_t default_size = 64;

    if (dynamic_string == NULL ||
        dynamic_string->buffer != NULL ||
        dynamic_string->buffer_size > 0)
        return ERROR_INVALID_ARGUMENT;

    return dynamic_string_allocate_power_of_2(default_size, dynamic_string);
}

VOID dynamic_string_free(
  _Inout_   PDYNAMIC_STRING dynamic_string
)
{
    if (dynamic_string == NULL)
        return;

    if (dynamic_string->buffer != NULL)
        yr_free(dynamic_string->buffer);

    dynamic_string->buffer = NULL;
    dynamic_string->buffer_size = 0;
}

#endif // USE_WINCRYPT_AUTHENTICODE
