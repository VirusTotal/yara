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

#include "countersignature.h"

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/pkcs7.h>
#include <openssl/safestack.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "certificate.h"
#include "helper.h"
#include "structs.h"

Countersignature* pkcs9_countersig_new(
    const uint8_t* data, long size, STACK_OF(X509) * certs, ASN1_STRING* enc_digest)
{
    Countersignature* result = (Countersignature*)calloc(1, sizeof(*result));
    if (!result)
        return NULL;

    PKCS7_SIGNER_INFO* si = d2i_PKCS7_SIGNER_INFO(NULL, &data, size);
    if (!si) {
        result->verify_flags = COUNTERSIGNATURE_VFY_CANT_PARSE;
        return result;
    }

    int digestnid = OBJ_obj2nid(si->digest_alg->algorithm);
    result->digest_alg = strdup(OBJ_nid2ln(digestnid));

    const ASN1_TYPE* sign_time = PKCS7_get_signed_attribute(si, NID_pkcs9_signingTime);
    if (!sign_time) {
        result->verify_flags = COUNTERSIGNATURE_VFY_TIME_MISSING;
        goto end;
    }

    result->sign_time = ASN1_TIME_to_time_t(sign_time->value.utctime);

    X509* signCert = X509_find_by_issuer_and_serial(
        certs, si->issuer_and_serial->issuer, si->issuer_and_serial->serial);
    if (!signCert) {
        result->verify_flags = COUNTERSIGNATURE_VFY_NO_SIGNER_CERT;
        goto end;
    }

    /* PKCS9 stores certificates in the corresponding PKCS7 it countersigns */
    result->chain = parse_signer_chain(signCert, certs);

    /* Get digest that corresponds to decrypted encrypted digest in signature */
    ASN1_TYPE* messageDigest = PKCS7_get_signed_attribute(si, NID_pkcs9_messageDigest);
    if (!messageDigest) {
        result->verify_flags = COUNTERSIGNATURE_VFY_DIGEST_MISSING;
        goto end;
    }

    size_t digestLen = messageDigest->value.octet_string->length;

    if (!digestLen) {
        result->verify_flags = COUNTERSIGNATURE_VFY_DIGEST_MISSING;
        goto end;
    }

    const EVP_MD* md = EVP_get_digestbynid(digestnid);
    if (!md) {
        result->verify_flags = COUNTERSIGNATURE_VFY_UNKNOWN_ALGORITHM;
        goto end;
    }

    const uint8_t* digestData = messageDigest->value.octet_string->data;
    byte_array_init(&result->digest, digestData, digestLen);

    /* By this point we all necessary things for verification
     * Get DER representation of the authenticated attributes to calculate its
     * digest that should correspond with the one encrypted in SignerInfo */
    uint8_t* authAttrsData = NULL;
    int authAttrsLen = ASN1_item_i2d(
        (ASN1_VALUE*)si->auth_attr, &authAttrsData, ASN1_ITEM_rptr(PKCS7_ATTR_VERIFY));

    uint8_t calc_digest[EVP_MAX_MD_SIZE];
    calculate_digest(md, authAttrsData, authAttrsLen, calc_digest);
    OPENSSL_free(authAttrsData);

    /* Get public key to decrypt encrypted digest of auth attrs */
    EVP_PKEY* pkey = X509_get0_pubkey(signCert);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);

    /* TODO try to get rid of hardcoded length bound */
    size_t decLen = 65536;
    uint8_t* decData = (uint8_t*)malloc(decLen);
    if (!decData) {
        EVP_PKEY_CTX_free(ctx);
        result->verify_flags = COUNTERSIGNATURE_VFY_INTERNAL_ERROR;
        goto end;
    }

    uint8_t* encData = si->enc_digest->data;
    size_t encLen = si->enc_digest->length;

    /* Decrypt the encrypted digest */
    EVP_PKEY_verify_recover_init(ctx);
    bool isDecrypted = EVP_PKEY_verify_recover(ctx, decData, &decLen, encData, encLen) == 1;
    EVP_PKEY_CTX_free(ctx);

    if (!isDecrypted) {
        free(decData);
        result->verify_flags = COUNTERSIGNATURE_VFY_CANT_DECRYPT_DIGEST;
        goto end;
    }

    /* compare the encrypted digest and calculated digest */
    bool isValid = false;
     
#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
    size_t mdLen = EVP_MD_get_size(md);
#else
    size_t mdLen = EVP_MD_size(md);
#endif
    /* Sometimes signed data contains DER encoded DigestInfo structure which contains hash of
     * authenticated attributes (39c9d136f026a9ad18fb9f41a64f76dd8418e8de625dce5d3a372bd242fc5edd)
     * but other times it is just purely and I didn't find another way to  distinguish it but only
     * based on the length of data we get. Found mention of this in openssl mailing list:
     * https://mta.openssl.org/pipermail/openssl-users/2015-September/002054.html */
    if (mdLen == decLen) {
        isValid = !memcmp(calc_digest, decData, mdLen);
    } else {
        const uint8_t* data_ptr = decData;
        DigestInfo* digest_info = d2i_DigestInfo(NULL, &data_ptr, decLen);
        if (digest_info) {
            isValid = !memcmp(digest_info->digest->data, calc_digest, mdLen);
            DigestInfo_free(digest_info);
        } else {
            isValid = false;
        }
    }
    free(decData);

    if (!isValid) {
        result->verify_flags = COUNTERSIGNATURE_VFY_INVALID;
        goto end;
    }

    /* Now check the countersignature message-digest that should correspond
     * to Signatures encrypted digest it countersigns */
    calculate_digest(md, enc_digest->data, enc_digest->length, calc_digest);

    /* Check if calculated one matches the stored one */
    if (digestLen != mdLen || memcmp(calc_digest, digestData, mdLen) != 0) {
        result->verify_flags = COUNTERSIGNATURE_VFY_DOESNT_MATCH_SIGNATURE;
        goto end;
    }

end:
    PKCS7_SIGNER_INFO_free(si);
    return result;
}

Countersignature* ms_countersig_new(const uint8_t* data, long size, ASN1_STRING* enc_digest)
{
    Countersignature* result = (Countersignature*)calloc(1, sizeof(*result));
    if (!result)
        return NULL;

    PKCS7* p7 = d2i_PKCS7(NULL, &data, size);
    if (!p7) {
        result->verify_flags = COUNTERSIGNATURE_VFY_CANT_PARSE;
        return result;
    }

    TS_TST_INFO* ts = PKCS7_to_TS_TST_INFO(p7);
    if (!ts) {
        result->verify_flags = COUNTERSIGNATURE_VFY_CANT_PARSE;
        PKCS7_free(p7);
        return result;
    }

    const ASN1_TIME* rawTime = TS_TST_INFO_get_time(ts);
    if (!rawTime) {
        result->verify_flags = COUNTERSIGNATURE_VFY_TIME_MISSING;
        TS_TST_INFO_free(ts);
        PKCS7_free(p7);
        return result;
    }

    result->sign_time = ASN1_TIME_to_time_t(rawTime);

    STACK_OF(X509)* sigs = PKCS7_get0_signers(p7, p7->d.sign->cert, 0);
    X509* signCert = sk_X509_value(sigs, 0);
    if (!signCert) {
        result->verify_flags = COUNTERSIGNATURE_VFY_NO_SIGNER_CERT;
        goto end;
    }

    result->chain = parse_signer_chain(signCert, p7->d.sign->cert);

    /* Imprint == digest */
    TS_MSG_IMPRINT* imprint = TS_TST_INFO_get_msg_imprint(ts);
    if (!imprint) {
        result->verify_flags = COUNTERSIGNATURE_VFY_DIGEST_MISSING;
        goto end;
    }

    X509_ALGOR* digestAlg = TS_MSG_IMPRINT_get_algo(imprint);
    int digestnid = OBJ_obj2nid(digestAlg->algorithm);
    result->digest_alg = strdup(OBJ_nid2ln(digestnid));

    ASN1_STRING* rawDigest = TS_MSG_IMPRINT_get_msg(imprint);

    int digestLen = rawDigest->length;
    uint8_t* digestData = rawDigest->data;

    byte_array_init(&result->digest, digestData, digestLen);

    if (!digestLen) {
        result->verify_flags = COUNTERSIGNATURE_VFY_DIGEST_MISSING;
        goto end;
    }

    const EVP_MD* md = EVP_get_digestbynid(digestnid);
    if (!md) {
        result->verify_flags = COUNTERSIGNATURE_VFY_UNKNOWN_ALGORITHM;
        goto end;
    }

    uint8_t calc_digest[EVP_MAX_MD_SIZE];
    calculate_digest(md, enc_digest->data, enc_digest->length, calc_digest);

#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
    int mdLen = EVP_MD_get_size(md);
#else
    int mdLen = EVP_MD_size(md);
#endif

    if (digestLen != mdLen || memcmp(calc_digest, digestData, mdLen) != 0) {
        result->verify_flags = COUNTERSIGNATURE_VFY_DOESNT_MATCH_SIGNATURE;
        goto end;
    }

    TS_VERIFY_CTX* ctx = TS_VERIFY_CTX_new();
    X509_STORE* store = X509_STORE_new();
    TS_VERIFY_CTX_init(ctx);

    TS_VERIFY_CTX_set_flags(ctx, TS_VFY_VERSION | TS_VFY_IMPRINT);
    TS_VERIFY_CTX_set_store(ctx, store);
#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
    TS_VERIFY_CTX_set_certs(ctx, p7->d.sign->cert);
#else
    TS_VERIFY_CTS_set_certs(ctx, p7->d.sign->cert);
#endif
    TS_VERIFY_CTX_set_imprint(ctx, calc_digest, mdLen);

    bool isValid = TS_RESP_verify_token(ctx, p7) == 1;

    X509_STORE_free(store);
    OPENSSL_free(ctx);

    if (!isValid) {
        result->verify_flags = COUNTERSIGNATURE_VFY_INVALID;
        goto end;
    }

    /* Verify signature with PKCS7_signatureVerify
     because TS_RESP_verify_token would try to verify
     chain and without trust anchors it always fails */
    BIO* p7bio = PKCS7_dataInit(p7, NULL);

    char buf[4096];
    /* We now have to 'read' from p7bio to calculate digests etc. */
    while (BIO_read(p7bio, buf, sizeof(buf)) > 0)
        continue;

    PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(p7), 0);

    isValid = PKCS7_signatureVerify(p7bio, p7, si, signCert) == 1;

    BIO_free_all(p7bio);

    if (!isValid)
        result->verify_flags = COUNTERSIGNATURE_VFY_INVALID;

end:
    sk_X509_free(sigs);
    PKCS7_free(p7);
    TS_TST_INFO_free(ts);
    return result;
}

int countersignature_array_insert(CountersignatureArray* arr, Countersignature* sig)
{
    Countersignature** tmp =
        (Countersignature**)realloc(arr->counters, (arr->count + 1) * sizeof(Countersignature*));
    if (!tmp)
        return 1;

    arr->counters = tmp;
    arr->counters[arr->count] = sig;
    arr->count++;

    return 0;
}

int countersignature_array_move(CountersignatureArray* dst, CountersignatureArray* src)
{
    size_t newCount = dst->count + src->count;

    Countersignature** tmp =
        (Countersignature**)realloc(dst->counters, newCount * sizeof(Countersignature*));
    if (!tmp)
        return 1;

    dst->counters = tmp;

    for (size_t i = 0; i < src->count; ++i)
        dst->counters[i + dst->count] = src->counters[i];

    dst->count = newCount;

    free(src->counters);
    src->counters = NULL;
    src->count = 0;

    return 0;
}

void countersignature_free(Countersignature* sig)
{
    if (sig) {
        free(sig->digest_alg);
        free(sig->digest.data);
        certificate_array_free(sig->chain);
        free(sig);
    }
}

void countersignature_array_free(CountersignatureArray* arr)
{
    if (arr) {
        for (size_t i = 0; i < arr->count; ++i) {
            countersignature_free(arr->counters[i]);
        }
        free(arr->counters);
        free(arr);
    }
}
