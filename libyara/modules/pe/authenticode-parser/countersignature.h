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

#ifndef AUTHENTICODE_PARSER_COUNTERSIGNATURE_H
#define AUTHENTICODE_PARSER_COUNTERSIGNATURE_H

#include "certificate.h"
#include "helper.h"
#include <authenticode-parser/authenticode.h>
#include <stdbool.h>
#include <stdint.h>

#include <openssl/safestack.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

Countersignature* pkcs9_countersig_new(
    const uint8_t* data, long size, STACK_OF(X509) * certs, ASN1_STRING* enc_digest);
Countersignature* ms_countersig_new(const uint8_t* data, long size, ASN1_STRING* enc_digest);

int countersignature_array_insert(CountersignatureArray* arr, Countersignature* sig);
/* Moves all countersignatures of src and inserts them into dst */
int countersignature_array_move(CountersignatureArray* dst, CountersignatureArray* src);

void countersignature_free(Countersignature* sig);
void countersignature_array_free(CountersignatureArray* arr);

#ifdef __cplusplus
}
#endif

#endif
