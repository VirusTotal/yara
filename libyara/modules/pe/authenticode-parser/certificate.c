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

#include "certificate.h"

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <string.h>

#include "helper.h"

#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
/* Removes any escaping \/ -> / that is happening with oneline() functions
    from OpenSSL 3.0 */
static void parse_oneline_string(char* string)
{
    size_t len = strlen(string);
    char* tmp = string;
    while (true) {
        char* ptr = strstr(tmp, "\\/");
        if (!ptr)
            break;

        memmove(ptr, ptr + 1, strlen(ptr + 1));
        tmp = ptr + 1;
        len--;
    }

    string[len] = 0;
}
#endif

static void parse_name_attributes(X509_NAME* raw, Attributes* attr)
{
    if (!raw || !attr)
        return;

    int entryCount = X509_NAME_entry_count(raw);
    for (int i = entryCount - 1; i >= 0; --i) {
        X509_NAME_ENTRY* entryName = X509_NAME_get_entry(raw, i);
        ASN1_STRING* asn1String = X509_NAME_ENTRY_get_data(entryName);

        const char* key = OBJ_nid2sn(OBJ_obj2nid(X509_NAME_ENTRY_get_object(entryName)));

        ByteArray array = {0};
        if (byte_array_init(&array, asn1String->data, asn1String->length) == -1)
            break;

        if (strcmp(key, "C") == 0 && !attr->country.data)
            attr->country = array;
        else if (strcmp(key, "O") == 0 && !attr->organization.data)
            attr->organization = array;
        else if (strcmp(key, "OU") == 0 && !attr->organizationalUnit.data)
            attr->organizationalUnit = array;
        else if (strcmp(key, "dnQualifier") == 0 && !attr->nameQualifier.data)
            attr->nameQualifier = array;
        else if (strcmp(key, "ST") == 0 && !attr->state.data)
            attr->state = array;
        else if (strcmp(key, "CN") == 0 && !attr->commonName.data)
            attr->commonName = array;
        else if (strcmp(key, "serialNumber") == 0 && !attr->serialNumber.data)
            attr->serialNumber = array;
        else if (strcmp(key, "L") == 0 && !attr->locality.data)
            attr->locality = array;
        else if (strcmp(key, "title") == 0 && !attr->title.data)
            attr->title = array;
        else if (strcmp(key, "SN") == 0 && !attr->surname.data)
            attr->surname = array;
        else if (strcmp(key, "GN") == 0 && !attr->givenName.data)
            attr->givenName = array;
        else if (strcmp(key, "initials") == 0 && !attr->initials.data)
            attr->initials = array;
        else if (strcmp(key, "pseudonym") == 0 && !attr->pseudonym.data)
            attr->pseudonym = array;
        else if (strcmp(key, "generationQualifier") == 0 && !attr->generationQualifier.data)
            attr->generationQualifier = array;
        else if (strcmp(key, "emailAddress") == 0 && !attr->emailAddress.data)
            attr->emailAddress = array;
        else
            free(array.data);
    }
}

/* Reconstructs signers certificate chain */
CertificateArray* parse_signer_chain(X509* signCert, STACK_OF(X509) * certs)
{
    if (!signCert || !certs)
        return NULL;

    X509_STORE* store = X509_STORE_new();
    if (!store)
        return NULL;

    X509_STORE_CTX* storeCtx = X509_STORE_CTX_new();
    if (!storeCtx) {
        X509_STORE_CTX_free(storeCtx);
        return NULL;
    }

    X509_STORE_CTX_init(storeCtx, store, signCert, certs);

    /* I can't find ability to use this function for static verification with missing trust anchors,
     * because roots are generally not part of the PKCS7 signatures, so the return value is
     * currently ignored and the function is only used to build the certificate chain */
    X509_verify_cert(storeCtx);

    STACK_OF(X509)* chain = X509_STORE_CTX_get_chain(storeCtx);

    int certCount = sk_X509_num(chain);

    CertificateArray* result = (CertificateArray*)calloc(1, sizeof(*result));
    if (!result)
        goto error;

    result->certs = (Certificate**)calloc(certCount, sizeof(Certificate*));
    if (!result->certs)
        goto error;

    /* Convert each certificate to internal representation */
    for (int i = 0; i < certCount; ++i) {
        Certificate* cert = certificate_new(sk_X509_value(chain, i));
        if (!cert)
            goto error;

        result->certs[i] = cert;
        result->count++;
    }

    X509_STORE_free(store);
    X509_STORE_CTX_free(storeCtx);
    return result;

error: /* In case of error, return nothing */
    if (result) {
        for (size_t i = 0; i < result->count; ++i) {
            certificate_free(result->certs[i]);
        }
        free(result->certs);
        free(result);
    }
    X509_STORE_free(store);
    X509_STORE_CTX_free(storeCtx);

    return NULL;
}

/* Taken from YARA for compatibility */
static char* integer_to_serial(ASN1_INTEGER* serial)
{
    int bytes = i2d_ASN1_INTEGER(serial, NULL);

    char* res = NULL;
    /* According to X.509 specification the maximum length for the
     * serial number is 20 octets. Add two bytes to account for
     * DER type and length information. */
    if (bytes < 2 || bytes > 22)
        return NULL;

    /* Now that we know the size of the serial number allocate enough
     * space to hold it, and use i2d_ASN1_INTEGER() one last time to
     * hold it in the allocated buffer. */
    uint8_t* serial_der = (uint8_t*)malloc(bytes);
    if (!serial_der)
        return NULL;

    uint8_t* serial_bytes;

    bytes = i2d_ASN1_INTEGER(serial, &serial_der);

    /* i2d_ASN1_INTEGER() moves the pointer as it writes into
       serial_bytes. Move it back. */
    serial_der -= bytes;

    /* Skip over DER type, length information */
    serial_bytes = serial_der + 2;
    bytes -= 2;

    /* Also allocate space to hold the "common" string format:
     * 00:01:02:03:04...
     *
     * For each byte in the serial to convert to hexlified format we
     * need three bytes, two for the byte itself and one for colon.
     * The last one doesn't have the colon, but the extra byte is used
     * for the NULL terminator. */
    res = (char*)malloc(bytes * 3);
    if (res) {
        for (int i = 0; i < bytes; i++) {
            /* Don't put the colon on the last one. */
            if (i < bytes - 1)
                snprintf(res + 3 * i, 4, "%02x:", serial_bytes[i]);
            else
                snprintf(res + 3 * i, 3, "%02x", serial_bytes[i]);
        }
    }
    free(serial_der);

    return (char*)res;
}

/* Converts the pubkey to pem, which is just
 * Base64 encoding of the DER representation */
static char* pubkey_to_pem(EVP_PKEY* pubkey)
{
    uint8_t* der = NULL;
    int len = i2d_PUBKEY(pubkey, &der); /* Convert to DER */
    if (len <= 0)
        return NULL;

    /* Approximate the result length (padding, newlines, 4 out bytes for every 3 in) */
    uint8_t* result = (uint8_t*)malloc(len * 3 / 2);
    if (!result) {
        OPENSSL_free(der);
        return NULL;
    }

    /* Base64 encode the DER data */
    EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();
    if (!ctx) {
        OPENSSL_free(der);
        free(result);
        return NULL;
    }

    int resultLen = 0;
    int tmp = 0;
    EVP_EncodeInit(ctx);
    EVP_EncodeUpdate(ctx, result, &tmp, der, len);
    resultLen += tmp;
    EVP_EncodeFinal(ctx, result + resultLen, &tmp);
    resultLen += tmp;

    EVP_ENCODE_CTX_free(ctx);
    OPENSSL_free(der);

    /* Remove all newlines from the encoded base64
     * resultLen is excluding NULL terminator */
    for (int i = 0; result[i] != 0; i++) {
        if (result[i] == '\n')
            memmove(result + i, result + i + 1, resultLen - i);
    }

    return (char*)result;
}

Certificate* certificate_new(X509* x509)
{
    Certificate* result = (Certificate*)calloc(1, sizeof(*result));
    if (!result)
        return NULL;

    /* Calculate SHA1 and SHA256 digests of the X509 structure */
    result->sha1.data = (uint8_t*)malloc(SHA_DIGEST_LENGTH);
    if (result->sha1.data) {
        X509_digest(x509, EVP_sha1(), result->sha1.data, NULL);
        result->sha1.len = SHA_DIGEST_LENGTH;
    }

    result->sha256.data = (uint8_t*)malloc(SHA256_DIGEST_LENGTH);
    if (result->sha256.data) {
        X509_digest(x509, EVP_sha256(), result->sha256.data, NULL);
        result->sha256.len = SHA256_DIGEST_LENGTH;
    }

    /* 256 bytes should be enough for any name */
    char buffer[256];

    /* X509_NAME_online is deprecated and shouldn't be used per OpenSSL docs
     * but we want to comply with existing YARA code */
    X509_NAME* issuerName = X509_get_issuer_name(x509);
    X509_NAME_oneline(issuerName, buffer, sizeof(buffer));

    result->issuer = strdup(buffer);
    /* This is a little ugly hack for 3.0 compatibility */
#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
    parse_oneline_string(result->issuer);
#endif

    X509_NAME* subjectName = X509_get_subject_name(x509);
    X509_NAME_oneline(subjectName, buffer, sizeof(buffer));
    result->subject = strdup(buffer);
#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
    parse_oneline_string(result->subject);
#endif

    parse_name_attributes(issuerName, &result->issuer_attrs);
    parse_name_attributes(subjectName, &result->subject_attrs);

    result->version = X509_get_version(x509);
    result->serial = integer_to_serial(X509_get_serialNumber(x509));
    result->not_after = ASN1_TIME_to_int64_t(X509_get0_notAfter(x509));
    result->not_before = ASN1_TIME_to_int64_t(X509_get0_notBefore(x509));
    int sig_nid = X509_get_signature_nid(x509);
    result->sig_alg = strdup(OBJ_nid2ln(sig_nid));

    OBJ_obj2txt(buffer, sizeof(buffer), OBJ_nid2obj(sig_nid), 1);
    result->sig_alg_oid = strdup(buffer);

    EVP_PKEY* pkey = X509_get0_pubkey(x509);
    if (pkey) {
        result->key = pubkey_to_pem(pkey);
#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
        result->key_alg = strdup(OBJ_nid2sn(EVP_PKEY_get_base_id(pkey)));
#else
        result->key_alg = strdup(OBJ_nid2sn(EVP_PKEY_base_id(pkey)));
#endif
    }

    return result;
}

void attributes_copy(Attributes* dst, Attributes* src)
{
    byte_array_init(&dst->country, src->country.data, src->country.len);
    byte_array_init(&dst->organization, src->organization.data, src->organization.len);
    byte_array_init(
        &dst->organizationalUnit, src->organizationalUnit.data, src->organizationalUnit.len);
    byte_array_init(&dst->nameQualifier, src->nameQualifier.data, src->nameQualifier.len);
    byte_array_init(&dst->state, src->state.data, src->state.len);
    byte_array_init(&dst->commonName, src->commonName.data, src->commonName.len);
    byte_array_init(&dst->serialNumber, src->serialNumber.data, src->serialNumber.len);
    byte_array_init(&dst->locality, src->locality.data, src->locality.len);
    byte_array_init(&dst->title, src->title.data, src->title.len);
    byte_array_init(&dst->surname, src->surname.data, src->surname.len);
    byte_array_init(&dst->givenName, src->givenName.data, src->givenName.len);
    byte_array_init(&dst->initials, src->initials.data, src->initials.len);
    byte_array_init(&dst->pseudonym, src->pseudonym.data, src->pseudonym.len);
    byte_array_init(
        &dst->generationQualifier, src->generationQualifier.data, src->generationQualifier.len);
    byte_array_init(&dst->emailAddress, src->emailAddress.data, src->emailAddress.len);
}

/* Parses X509* certs into internal representation and inserts into CertificateArray
 * Array is assumed to have enough space to hold all certificates storted in the STACK */
void parse_x509_certificates(const STACK_OF(X509) * certs, CertificateArray* result)
{
    int certCount = sk_X509_num(certs);
    int i = 0;
    for (; i < certCount; ++i) {
        Certificate* cert = certificate_new(sk_X509_value(certs, i));
        if (!cert)
            break;

        /* Write to the result */
        result->certs[i] = cert;
    }
    result->count = i;
}

/* Creates deep copy of a certificate */
Certificate* certificate_copy(Certificate* cert)
{
    if (!cert)
        return NULL;

    Certificate* result = (Certificate*)calloc(1, sizeof(*result));
    if (!result)
        return NULL;

    result->version = cert->version;
    result->issuer = cert->issuer ? strdup(cert->issuer) : NULL;
    result->subject = cert->subject ? strdup(cert->subject) : NULL;
    result->serial = cert->serial ? strdup(cert->serial) : NULL;
    result->not_after = cert->not_after;
    result->not_before = cert->not_before;
    result->sig_alg = cert->sig_alg ? strdup(cert->sig_alg) : NULL;
    result->sig_alg_oid = cert->sig_alg_oid ? strdup(cert->sig_alg_oid) : NULL;
    result->key_alg = cert->key_alg ? strdup(cert->key_alg) : NULL;
    result->key = cert->key ? strdup(cert->key) : NULL;
    byte_array_init(&result->sha1, cert->sha1.data, cert->sha1.len);
    byte_array_init(&result->sha256, cert->sha256.data, cert->sha256.len);
    attributes_copy(&result->issuer_attrs, &cert->issuer_attrs);
    attributes_copy(&result->subject_attrs, &cert->subject_attrs);

    return result;
}

/* Moves certificates from src to dst, returns 0 on success,
 * else 1. If error occurs, arguments are unchanged */
int certificate_array_move(CertificateArray* dst, CertificateArray* src)
{
    if (!dst || !src)
        return 1;

    if (!src->certs || !src->count)
        return 0;

    size_t newCount = dst->count + src->count;

    Certificate** tmp = (Certificate**)realloc(dst->certs, newCount * sizeof(Certificate*));
    if (!tmp)
        return 1;

    dst->certs = tmp;

    for (size_t i = 0; i < src->count; ++i)
        dst->certs[i + dst->count] = src->certs[i];

    dst->count = newCount;

    free(src->certs);
    src->certs = NULL;
    src->count = 0;

    return 0;
}

/* Copies certificates from src and appends to dst, returns 0 on success,
 * else 1. If error occurs, arguments are unchanged */
int certificate_array_append(CertificateArray* dst, CertificateArray* src)
{
    if (!dst || !src)
        return 1;

    if (!src->certs || !src->count)
        return 0;

    size_t newCount = dst->count + src->count;

    Certificate** tmp = (Certificate**)realloc(dst->certs, newCount * sizeof(Certificate*));
    if (!tmp)
        return 1;

    dst->certs = tmp;

    for (size_t i = 0; i < src->count; ++i)
        dst->certs[i + dst->count] = certificate_copy(src->certs[i]);

    dst->count = newCount;

    return 0;
}

/* Allocates empty certificate array with reserved space for certCount certs */
CertificateArray* certificate_array_new(int certCount)
{
    CertificateArray* arr = (CertificateArray*)malloc(sizeof(*arr));
    if (!arr)
        return NULL;

    arr->certs = (Certificate**)malloc(sizeof(Certificate*) * certCount);
    if (!arr->certs) {
        free(arr);
        return NULL;
    }

    arr->count = certCount;

    return arr;
}

static void certificate_attributes_free(Attributes attrs)
{
    free(attrs.country.data);
    free(attrs.organization.data);
    free(attrs.organizationalUnit.data);
    free(attrs.nameQualifier.data);
    free(attrs.state.data);
    free(attrs.commonName.data);
    free(attrs.serialNumber.data);
    free(attrs.locality.data);
    free(attrs.title.data);
    free(attrs.surname.data);
    free(attrs.givenName.data);
    free(attrs.initials.data);
    free(attrs.pseudonym.data);
    free(attrs.generationQualifier.data);
    free(attrs.emailAddress.data);
}

void certificate_free(Certificate* cert)
{
    if (cert) {
        free(cert->issuer);
        free(cert->subject);
        free(cert->sig_alg);
        free(cert->sig_alg_oid);
        free(cert->key_alg);
        free(cert->key);
        free(cert->sha1.data);
        free(cert->sha256.data);
        free(cert->serial);
        certificate_attributes_free(cert->issuer_attrs);
        certificate_attributes_free(cert->subject_attrs);
        free(cert);
    }
}

void certificate_array_free(CertificateArray* arr)
{
    if (arr) {
        for (size_t i = 0; i < arr->count; ++i) {
            certificate_free(arr->certs[i]);
        }
        free(arr->certs);
        free(arr);
    }
}
