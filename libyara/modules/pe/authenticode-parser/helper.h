/* Copyright (c) 2021 Avast Software

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

#ifndef AUTHENTICODE_PARSER_HELPER_H
#define AUTHENTICODE_PARSER_HELPER_H

#include <authenticode-parser/authenticode.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <openssl/x509.h>

#ifdef _WIN32
#define timegm _mkgmtime
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Endianity related functions for PE reading */
uint16_t bswap16(uint16_t d);
uint32_t bswap32(uint32_t d);

#if defined(WORDS_BIGENDIAN)
#define letoh16(x) bswap16(x)
#define letoh32(x) bswap32(x)
#define betoh16(x) (x)
#define betoh32(x) (x)
#else
#define letoh16(x) (x)
#define letoh32(x) (x)
#define betoh16(x) bswap16(x)
#define betoh32(x) bswap32(x)
#endif

/* Calculates digest md of data, return bytes written to digest or 0 on error
 * Maximum of EVP_MAX_MD_SIZE will be written to digest */
int calculate_digest(const EVP_MD* md, const uint8_t* data, size_t len, uint8_t* digest);
/* Copies data of length len into already existing arr */
int byte_array_init(ByteArray* arr, const uint8_t* data, int len);
/* Converts ASN1_TIME string time into a unix timestamp */
int64_t ASN1_TIME_to_int64_t(const ASN1_TIME* time);

#ifdef __cplusplus
}
#endif

#endif
