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

#include "helper.h"

#include <openssl/bio.h>
#include <openssl/x509_vfy.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint16_t bswap16(uint16_t d)
{
    return (d << 8) | (d >> 8);
}

uint32_t bswap32(uint32_t d)
{
    return (((d)&0xff000000) >> 24) | (((d)&0x00ff0000) >> 8) | (((d)&0x0000ff00) << 8) |
           (((d)&0x000000ff) << 24);
}

int calculate_digest(const EVP_MD* md, const uint8_t* data, size_t len, uint8_t* digest)
{
    unsigned int outLen = 0;

    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (!mdCtx)
        goto end;

    if (!EVP_DigestInit_ex(mdCtx, md, NULL) || !EVP_DigestUpdate(mdCtx, data, len) ||
        !EVP_DigestFinal_ex(mdCtx, digest, &outLen))
        goto end;

end:
    EVP_MD_CTX_free(mdCtx);
    return (int)outLen;
}

int byte_array_init(ByteArray* arr, const uint8_t* data, int len)
{
    if (len == 0) {
        arr->data = NULL;
        arr->len = 0;
        return 0;
    }

    arr->data = (uint8_t*)malloc(len);
    if (!arr->data)
        return -1;

    arr->len = len;
    memcpy(arr->data, data, len);
    return 0;
}

int64_t ASN1_TIME_to_int64_t(const ASN1_TIME* time)
{
    struct tm t = {0};
    if (!time)
        return timegm(&t);

    ASN1_TIME_to_tm(time, &t);
    return timegm(&t);
}
