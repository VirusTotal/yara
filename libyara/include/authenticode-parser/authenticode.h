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

#ifndef AUTHENTICODE_PARSER_AUTHENTICODE_H
#define AUTHENTICODE_PARSER_AUTHENTICODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <time.h>

/* Signature is valid */
#define AUTHENTICODE_VFY_VALID             0
/* Parsing error (from OpenSSL functions) */
#define AUTHENTICODE_VFY_CANT_PARSE        1
/* Signers certificate is missing */
#define AUTHENTICODE_VFY_NO_SIGNER_CERT    2
/* No digest saved inside the signature */
#define AUTHENTICODE_VFY_DIGEST_MISSING    3
/* Non verification errors - allocations etc. */
#define AUTHENTICODE_VFY_INTERNAL_ERROR    4
/* SignerInfo part of PKCS7 is missing */
#define AUTHENTICODE_VFY_NO_SIGNER_INFO    5
/* PKCS7 doesn't have type of SignedData, can't proceed */
#define AUTHENTICODE_VFY_WRONG_PKCS7_TYPE  6
/* PKCS7 doesn't have corrent content, can't proceed */
#define AUTHENTICODE_VFY_BAD_CONTENT       7
/* Contained and calculated digest don't match */
#define AUTHENTICODE_VFY_INVALID           8
/* Signature hash and file hash doesn't match */
#define AUTHENTICODE_VFY_WRONG_FILE_DIGEST 9
/* Unknown algorithm, can't proceed with verification */
#define AUTHENTICODE_VFY_UNKNOWN_ALGORITHM 10

/* Countersignature is valid */
#define COUNTERSIGNATURE_VFY_VALID                  0
/* Parsing error (from OpenSSL functions) */
#define COUNTERSIGNATURE_VFY_CANT_PARSE             1
/* Signers certificate is missing */
#define COUNTERSIGNATURE_VFY_NO_SIGNER_CERT         2
/* Unknown algorithm, can't proceed with verification */
#define COUNTERSIGNATURE_VFY_UNKNOWN_ALGORITHM      3
/* Verification failed, digest mismatch */
#define COUNTERSIGNATURE_VFY_INVALID                4
/* Failed to decrypt countersignature enc_digest for verification */
#define COUNTERSIGNATURE_VFY_CANT_DECRYPT_DIGEST    5
/* No digest saved inside the countersignature */
#define COUNTERSIGNATURE_VFY_DIGEST_MISSING         6
/* Message digest inside countersignature doesn't match signature it countersigns */
#define COUNTERSIGNATURE_VFY_DOESNT_MATCH_SIGNATURE 7
/* Non verification errors - allocations etc. */
#define COUNTERSIGNATURE_VFY_INTERNAL_ERROR         8
/* Time is missing in the timestamp signature */
#define COUNTERSIGNATURE_VFY_TIME_MISSING           9

typedef struct {
    uint8_t* data;
    int len;
} ByteArray;

typedef struct { /* Various X509 attributes parsed out in raw bytes*/
    ByteArray country;
    ByteArray organization;
    ByteArray organizationalUnit;
    ByteArray nameQualifier;
    ByteArray state;
    ByteArray commonName;
    ByteArray serialNumber;
    ByteArray locality;
    ByteArray title;
    ByteArray surname;
    ByteArray givenName;
    ByteArray initials;
    ByteArray pseudonym;
    ByteArray generationQualifier;
    ByteArray emailAddress;
} Attributes;

typedef struct {
    long version;             /* Raw version of X509 */
    char* issuer;             /* Oneline name of Issuer */
    char* subject;            /* Oneline name of Subject */
    char* serial;             /* Serial number in format 00:01:02:03:04... */
    ByteArray sha1;           /* SHA1 of the DER representation of the cert */
    ByteArray sha256;         /* SHA256 of the DER representation of the cert */
    char* key_alg;            /* Name of the key algorithm */
    char* sig_alg;            /* Name of the signature algorithm */
    char* sig_alg_oid;        /* OID of the signature algorithm */
    int64_t not_before;       /* NotBefore validity */
    int64_t not_after;        /* NotAfter validity */
    char* key;                /* PEM encoded public key */
    Attributes issuer_attrs;  /* Parsed X509 Attributes of Issuer */
    Attributes subject_attrs; /* Parsed X509 Attributes of Subject */
} Certificate;

typedef struct {
    Certificate** certs;
    size_t count;
} CertificateArray;

typedef struct {
    int verify_flags;        /* COUNTERISGNATURE_VFY_ flag */
    int64_t sign_time;       /* Signing time of the timestamp countersignature */
    char* digest_alg;        /* Name of the digest algorithm used */
    ByteArray digest;        /* Stored message digest */
    CertificateArray* chain; /* Certificate chain of the signer */
    CertificateArray* certs; /* All certs stored inside Countersignature, this can be superset
                                of chain in case of non PKCS9 countersignature*/
} Countersignature;

typedef struct {
    Countersignature** counters;
    size_t count;
} CountersignatureArray;

typedef struct {             /* Represents SignerInfo structure */
    ByteArray digest;        /* Message Digest of the SignerInfo */
    char* digest_alg;        /* name of the digest algorithm */
    char* program_name;      /* Program name stored in SpcOpusInfo structure of Authenticode */
    CertificateArray* chain; /* Certificate chain of the signer */
} Signer;

typedef struct {
    int verify_flags;        /* AUTHENTICODE_VFY_ flag */
    int version;             /* Raw PKCS7 version */
    char* digest_alg;        /* name of the digest algorithm */
    ByteArray digest;        /* File Digest stored in the Signature */
    ByteArray file_digest;   /* Actual calculated file digest */
    Signer* signer;          /* SignerInfo information of the Authenticode */
    CertificateArray* certs; /* All certificates in the Signature including the ones in timestamp
                                countersignatures */
    CountersignatureArray* countersigs; /* Array of timestamp countersignatures */
} Authenticode;

typedef struct {
    Authenticode** signatures;
    size_t count;
} AuthenticodeArray;

/**
 * @brief Initializes all globals OpenSSl objects we need for parsing, this is not thread-safe and
 *        needs to be called only once, before any multithreading environment
 *        https://github.com/openssl/openssl/issues/13524
 */
void initialize_authenticode_parser();

/**
 * @brief Constructs AuthenticodeArray from PE file data. Authenticode can
 *        contains nested Authenticode signatures as its unsigned attribute,
 *        which can also contain nested signatures. For this reason the function returns
 *        an Array of parsed Authenticode signatures. Any field of the parsed out
 *        structures can be NULL, depending on the input data.
 *        Verification result is stored in verify_flags with the first verification error.
 *
 * @param pe_data PE binary data
 * @param pe_len
 * @return AuthenticodeArray*
 */
AuthenticodeArray* parse_authenticode(const uint8_t* pe_data, uint64_t pe_len);

/**
 * @brief Constructs AuthenticodeArray from binary data containing Authenticode
 *        signature. Authenticode can contains nested Authenticode signatures
 *        as its unsigned attribute, which can also contain nested signatures.
 *        For this reason the function return an Array of parsed Authenticode signatures.
 *        Any field of the parsed out structures can be NULL, depending on the input data.
 *        WARNING: in case of this interface, the file and signature digest comparison is
 *        up to the library user, as there is no pe data to calculate file digest from.
 *        Verification result is stored in verify_flags with the first verification error
 *
 * @param data Binary data containing Authenticode signature
 * @param len
 * @return AuthenticodeArray*
 */
AuthenticodeArray* authenticode_new(const uint8_t* data, int32_t len);

/**
 * @brief Deallocates AuthenticodeArray and all it's allocated members
 *
 * @param auth
 */
void authenticode_array_free(AuthenticodeArray* auth);

#ifdef __cplusplus
}
#endif

#endif
