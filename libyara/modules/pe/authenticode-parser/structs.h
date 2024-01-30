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

#ifndef AUTHENTICODE_PARSER_STRUCTS_H
#define AUTHENTICODE_PARSER_STRUCTS_H

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509v3.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NID_spc_info                "1.3.6.1.4.1.311.2.1.12"
#define NID_spc_ms_countersignature "1.3.6.1.4.1.311.3.3.1"
#define NID_spc_nested_signature    "1.3.6.1.4.1.311.2.4.1"
#define NID_spc_indirect_data       "1.3.6.1.4.1.311.2.1.4"

typedef struct {
    int type;
    union {
        ASN1_BMPSTRING *unicode;
        ASN1_IA5STRING *ascii;
    } value;
} SpcString;

typedef struct {
    ASN1_OCTET_STRING *classId;
    ASN1_OCTET_STRING *serializedData;
} SpcSerializedObject;

typedef struct {
    int type;
    union {
        ASN1_IA5STRING *url;
        SpcSerializedObject *moniker;
        SpcString *file;
    } value;
} SpcLink;

typedef struct {
    ASN1_OBJECT *type;
    ASN1_TYPE *value;
} SpcAttributeTypeAndOptionalValue;

typedef struct {
    ASN1_BIT_STRING *flags;
    SpcLink *file;
} SpcPeImageData;

typedef struct {
    ASN1_OBJECT *algorithm;
    ASN1_TYPE *parameters;
} AlgorithmIdentifier;

typedef struct {
    AlgorithmIdentifier *digestAlgorithm;
    ASN1_OCTET_STRING *digest;
} DigestInfo;

typedef struct {
    SpcAttributeTypeAndOptionalValue *data;
    DigestInfo *messageDigest;
} SpcIndirectDataContent;

typedef struct {
    ASN1_OBJECT *contentType;
    SpcIndirectDataContent *content;
} SpcContentInfo;

typedef struct {
    SpcString *programName;
    SpcLink *moreInfo;
} SpcSpOpusInfo;

DECLARE_ASN1_FUNCTIONS(SpcString)
DECLARE_ASN1_FUNCTIONS(SpcSerializedObject)
DECLARE_ASN1_FUNCTIONS(SpcLink)
DECLARE_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)
DECLARE_ASN1_FUNCTIONS(SpcPeImageData)
DECLARE_ASN1_FUNCTIONS(AlgorithmIdentifier)
DECLARE_ASN1_FUNCTIONS(DigestInfo)
DECLARE_ASN1_FUNCTIONS(SpcIndirectDataContent)
DECLARE_ASN1_FUNCTIONS(SpcSpOpusInfo)
DECLARE_ASN1_FUNCTIONS(SpcContentInfo)

#ifdef __cplusplus
}
#endif

#endif
