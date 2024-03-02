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

#ifndef AUTHENTICODE_PARSER_CERTIFICATE_H
#define AUTHENTICODE_PARSER_CERTIFICATE_H

#include <authenticode-parser/authenticode.h>

#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

Certificate* certificate_new(X509* x509);
Certificate* certificate_copy(Certificate* cert);
void certificate_free(Certificate* cert);

void parse_x509_certificates(const STACK_OF(X509) * certs, CertificateArray* result);

CertificateArray* parse_signer_chain(X509* signer_cert, STACK_OF(X509) * certs);
int certificate_array_move(CertificateArray* dst, CertificateArray* src);
int certificate_array_append(CertificateArray* dst, CertificateArray* src);
CertificateArray* certificate_array_new(int certCount);
void certificate_array_free(CertificateArray* arr);

#ifdef __cplusplus
}
#endif

#endif
