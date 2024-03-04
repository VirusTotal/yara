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

#include <assert.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
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

struct CountersignatureImplStruct;

typedef TS_TST_INFO* get_ts_tst_info_func(struct CountersignatureImplStruct*);
typedef STACK_OF(X509) * get_signers_func(struct CountersignatureImplStruct*);
typedef STACK_OF(X509) * get_certs_func(struct CountersignatureImplStruct*);
typedef int
verify_digest_func(struct CountersignatureImplStruct*, uint8_t* digest, size_t digest_size);
typedef BIO* verify_signature_init_func(struct CountersignatureImplStruct*);
typedef int
verify_signature_finish_func(struct CountersignatureImplStruct*, BIO* bio, X509* signer);

#define IMPL_FUNC_NAME(func, type) ms_countersig_impl_##func##_##type##_

#define DECLARE_FUNCS(type)                                                                        \
    get_ts_tst_info_func IMPL_FUNC_NAME(get_ts_tst_info, type);                                    \
    get_signers_func IMPL_FUNC_NAME(get_signers, type);                                            \
    get_certs_func IMPL_FUNC_NAME(get_certs, type);                                                \
    verify_digest_func IMPL_FUNC_NAME(verify_digest, type);                                        \
    verify_signature_init_func IMPL_FUNC_NAME(verify_signature_init, type);                        \
    verify_signature_finish_func IMPL_FUNC_NAME(verify_signature_finish, type);

DECLARE_FUNCS(pkcs7)
DECLARE_FUNCS(cms)

typedef struct {
    get_ts_tst_info_func* get_ts_tst_info;
    get_signers_func* get_signers;
    get_certs_func* get_certs;
    verify_digest_func* verify_digest;
    verify_signature_init_func* verify_signature_init;
    verify_signature_finish_func* verify_signature_finish;
} CountersignatureImplFuncs;

#define FUNC_ARRAY_NAME_FOR_IMPL(type) countersig_impl_funcs_##type##_
#define FUNC_ARRAY_FOR_IMPL(type)                                                                  \
    static const CountersignatureImplFuncs FUNC_ARRAY_NAME_FOR_IMPL(type) = {                      \
        &IMPL_FUNC_NAME(get_ts_tst_info, type),                                                    \
        &IMPL_FUNC_NAME(get_signers, type),                                                        \
        &IMPL_FUNC_NAME(get_certs, type),                                                          \
        &IMPL_FUNC_NAME(verify_digest, type),                                                      \
        &IMPL_FUNC_NAME(verify_signature_init, type),                                              \
        &IMPL_FUNC_NAME(verify_signature_finish, type),                                            \
    };

FUNC_ARRAY_FOR_IMPL(pkcs7)
FUNC_ARRAY_FOR_IMPL(cms)

typedef enum {
    CS_IMPL_PKCS7,
    CS_IMPL_CMS,
} CountersignatureImplType;

typedef struct CountersignatureImplStruct {
    CountersignatureImplType type;
    const CountersignatureImplFuncs* funcs;
    union {
        PKCS7* pkcs7;
        CMS_ContentInfo* cms;
    };
    // this is here to serve as a cache for CMS because the only way to obtain
    // certs from CMS is to use CMS_get1_certs which leaves the deallocation
    // to the caller but it just complicates things if you need to remember to
    // deallocate also certs. This makes it easier if CountersignatureImpl itself
    // is an owner of this thing.
    STACK_OF(X509) * _certs;
} CountersignatureImpl;

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

    result->sign_time = ASN1_TIME_to_int64_t(sign_time->value.utctime);

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

TS_TST_INFO* IMPL_FUNC_NAME(get_ts_tst_info, pkcs7)(CountersignatureImpl* impl)
{
    assert(impl->type == CS_IMPL_PKCS7);

    return PKCS7_to_TS_TST_INFO(impl->pkcs7);
}

TS_TST_INFO* IMPL_FUNC_NAME(get_ts_tst_info, cms)(CountersignatureImpl* impl)
{
    assert(impl->type == CS_IMPL_CMS);

    const ASN1_OBJECT* content_type = CMS_get0_eContentType(impl->cms);
    if (!content_type || OBJ_obj2nid(content_type) != NID_id_smime_ct_TSTInfo) {
        return NULL;
    }

    ASN1_OCTET_STRING** content = CMS_get0_content(impl->cms);
    if (!content || !*content) {
        return NULL;
    }

    const uint8_t* data = (*content)->data;
    TS_TST_INFO* ts_tst_info = d2i_TS_TST_INFO(NULL, &data, (*content)->length);
    if (!ts_tst_info) {
        return NULL;
    }

    return ts_tst_info;
}

STACK_OF(X509) * IMPL_FUNC_NAME(get_signers, pkcs7)(CountersignatureImpl* impl)
{
    assert(impl->type == CS_IMPL_PKCS7);

    return PKCS7_get0_signers(impl->pkcs7, impl->pkcs7->d.sign->cert, 0);
}

STACK_OF(X509) * IMPL_FUNC_NAME(get_signers, cms)(CountersignatureImpl* impl)
{
    assert(impl->type == CS_IMPL_CMS);

    STACK_OF(CMS_SignerInfo)* signer_infos = CMS_get0_SignerInfos(impl->cms);
    if (!signer_infos) {
        return NULL;
    }

    // Use our func points to cache the certs and don't create another copy
    STACK_OF(X509)* certs = impl->funcs->get_certs(impl);

    int si_count = sk_CMS_SignerInfo_num(signer_infos);
    int cert_count = certs ? sk_X509_num(certs) : 0;
    STACK_OF(X509)* result = sk_X509_new_null();

    // PKCS7_get0_signers() lets us specify the certificate array and looks up signer certificate
    // there With CMS_ContentInfo, we don't have direct access to signer certificate, just all the
    // certificates The only thing we can do is to go through all signer infos and find those which
    // match some certificate in all certificates. It essentially simulates what
    // PKCS7_get0_signers() does.
    for (int i = 0; i < si_count; ++i) {
        CMS_SignerInfo* si = sk_CMS_SignerInfo_value(signer_infos, i);
        if (!si) {
            continue;
        }

        if (certs) {
            for (int j = 0; j < cert_count; ++j) {
                X509* cert = sk_X509_value(certs, j);
                if (!cert) {
                    continue;
                }

                if (CMS_SignerInfo_cert_cmp(si, cert) == 0) {
                    if (!sk_X509_push(result, cert)) {
                        return NULL;
                    }
                }
            }
        }
    }

    return result;
}

STACK_OF(X509) * IMPL_FUNC_NAME(get_certs, pkcs7)(CountersignatureImpl* impl)
{
    assert(impl->type == CS_IMPL_PKCS7);

    return impl->pkcs7->d.sign->cert;
}

STACK_OF(X509) * IMPL_FUNC_NAME(get_certs, cms)(CountersignatureImpl* impl)
{
    assert(impl->type == CS_IMPL_CMS);

    if (impl->_certs) {
        return impl->_certs;
    }

    impl->_certs = CMS_get1_certs(impl->cms);
    return impl->_certs;
}

int IMPL_FUNC_NAME(verify_digest, pkcs7)(
    CountersignatureImpl* impl, uint8_t* digest, size_t digest_size)
{
    assert(impl->type == CS_IMPL_PKCS7);

    X509_STORE* store = X509_STORE_new();
    TS_VERIFY_CTX* ctx = TS_VERIFY_CTX_new();

    TS_VERIFY_CTX_set_flags(ctx, TS_VFY_VERSION | TS_VFY_IMPRINT);
    TS_VERIFY_CTX_set_store(ctx, store);
#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
    TS_VERIFY_CTX_set_certs(ctx, impl->funcs->get_certs(impl));
#else
    TS_VERIFY_CTS_set_certs(ctx, impl->funcs->get_certs(impl));
#endif
    TS_VERIFY_CTX_set_imprint(ctx, digest, digest_size);

    int result = TS_RESP_verify_token(ctx, impl->pkcs7);

    X509_STORE_free(store);
    OPENSSL_free(ctx);

    return result;
}

int IMPL_FUNC_NAME(verify_digest, cms)(
    CountersignatureImpl* impl, uint8_t* digest, size_t digest_size)
{
    assert(impl->type == CS_IMPL_CMS);

    // This is essentially just reimplementation of TS_RESP_verify_token() from OpenSSL
    TS_TST_INFO* ts_tst_info = impl->funcs->get_ts_tst_info(impl);
    if (!ts_tst_info || TS_TST_INFO_get_version(ts_tst_info) != 1) {
        if (ts_tst_info)
            TS_TST_INFO_free(ts_tst_info);
        return 0;
    }

    TS_MSG_IMPRINT* ts_imprint = TS_TST_INFO_get_msg_imprint(ts_tst_info);
    if (!ts_imprint) {
        TS_TST_INFO_free(ts_tst_info);
        return 0;
    }

    ASN1_OCTET_STRING* ts_imprint_digest = TS_MSG_IMPRINT_get_msg(ts_imprint);
    if (!ts_imprint_digest) {
        TS_TST_INFO_free(ts_tst_info);
        return 0;
    }

    if (ts_imprint_digest->length != (int)digest_size ||
        memcmp(ts_imprint_digest->data, digest, digest_size) != 0) {
        TS_TST_INFO_free(ts_tst_info);
        return 0;
    }

    TS_TST_INFO_free(ts_tst_info);
    return 1;
}

BIO* IMPL_FUNC_NAME(verify_signature_init, pkcs7)(CountersignatureImpl* impl)
{
    assert(impl->type == CS_IMPL_PKCS7);

    return PKCS7_dataInit(impl->pkcs7, NULL);
}

BIO* IMPL_FUNC_NAME(verify_signature_init, cms)(CountersignatureImpl* impl)
{
    assert(impl->type == CS_IMPL_CMS);

    return CMS_dataInit(impl->cms, NULL);
}

int IMPL_FUNC_NAME(verify_signature_finish, pkcs7)(
    CountersignatureImpl* impl, BIO* bio, X509* signer)
{
    assert(impl->type == CS_IMPL_PKCS7);

    /* Verify signature with PKCS7_signatureVerify
     because TS_RESP_verify_token would try to verify
     chain and without trust anchors it always fails */
    PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(impl->pkcs7), 0);
    return PKCS7_signatureVerify(bio, impl->pkcs7, si, signer);
}

int IMPL_FUNC_NAME(verify_signature_finish, cms)(CountersignatureImpl* impl, BIO* bio, X509* signer)
{
    assert(impl->type == CS_IMPL_CMS);

    (void)signer;
    CMS_SignerInfo* si = sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(impl->cms), 0);
    return CMS_SignerInfo_verify_content(si, bio);
}

CountersignatureImpl* ms_countersig_impl_new(const uint8_t* data, long size)
{
    const uint8_t* d = data;
    PKCS7* p7 = d2i_PKCS7(NULL, &d, size);
    if (p7 && PKCS7_type_is_signed(p7) && p7->d.sign) {
        CountersignatureImpl* result =
            (CountersignatureImpl*)calloc(1, sizeof(CountersignatureImpl));
        result->type = CS_IMPL_PKCS7;
        result->funcs = &FUNC_ARRAY_NAME_FOR_IMPL(pkcs7);
        result->pkcs7 = p7;
        return result;
    } else if (p7) {
        PKCS7_free(p7);
        return NULL;
    }

    d = data;
    CMS_ContentInfo* cms = d2i_CMS_ContentInfo(NULL, &d, size);
    if (cms) {
        CountersignatureImpl* result =
            (CountersignatureImpl*)calloc(1, sizeof(CountersignatureImpl));
        result->type = CS_IMPL_CMS;
        result->funcs = &FUNC_ARRAY_NAME_FOR_IMPL(cms);
        result->cms = cms;
        return result;
    }

    return NULL;
}

void ms_countersig_impl_free(CountersignatureImpl* impl)
{
    switch (impl->type) {
    case CS_IMPL_PKCS7:
        PKCS7_free(impl->pkcs7);
        break;
    case CS_IMPL_CMS:
        if (impl->_certs) {
            sk_X509_pop_free(impl->_certs, X509_free);
        }
        CMS_ContentInfo_free(impl->cms);
        break;
    }

    free(impl);
}

Countersignature* ms_countersig_new(const uint8_t* data, long size, ASN1_STRING* enc_digest)
{
    Countersignature* result = (Countersignature*)calloc(1, sizeof(*result));
    if (!result)
        return NULL;

    CountersignatureImpl* impl = ms_countersig_impl_new(data, size);
    if (!impl) {
        result->verify_flags = COUNTERSIGNATURE_VFY_CANT_PARSE;
        return result;
    }

    TS_TST_INFO* ts = impl->funcs->get_ts_tst_info(impl);
    if (!ts) {
        result->verify_flags = COUNTERSIGNATURE_VFY_CANT_PARSE;
        ms_countersig_impl_free(impl);
        return result;
    }

    const ASN1_TIME* rawTime = TS_TST_INFO_get_time(ts);
    if (!rawTime) {
        result->verify_flags = COUNTERSIGNATURE_VFY_TIME_MISSING;
        TS_TST_INFO_free(ts);
        ms_countersig_impl_free(impl);
        return result;
    }

    result->sign_time = ASN1_TIME_to_int64_t(rawTime);

    STACK_OF(X509)* sigs = impl->funcs->get_signers(impl);
    X509* signCert = sk_X509_value(sigs, 0);
    if (!signCert) {
        result->verify_flags = COUNTERSIGNATURE_VFY_NO_SIGNER_CERT;
        goto end;
    }

    STACK_OF(X509)* certs = impl->funcs->get_certs(impl);

    /* MS Counter signatures (PKCS7/CMS) can have extra certificates that are not part of a chain */
    result->certs = certificate_array_new(sk_X509_num(certs));
    if (!result->certs) {
        result->verify_flags = AUTHENTICODE_VFY_INTERNAL_ERROR;
        goto end;
    }

    parse_x509_certificates(certs, result->certs);

    result->chain = parse_signer_chain(signCert, certs);

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

    bool isValid = impl->funcs->verify_digest(impl, calc_digest, mdLen) == 1;
    if (!isValid) {
        result->verify_flags = COUNTERSIGNATURE_VFY_INVALID;
        goto end;
    }

    BIO* bio = impl->funcs->verify_signature_init(impl);

    char buf[4096];
    /* We now have to 'read' from bio to calculate digests etc. */
    while (BIO_read(bio, buf, sizeof(buf)) > 0)
        continue;

    isValid = impl->funcs->verify_signature_finish(impl, bio, signCert) == 1;

    BIO_free_all(bio);

    if (!isValid)
        result->verify_flags = COUNTERSIGNATURE_VFY_INVALID;

end:
    sk_X509_free(sigs);
    TS_TST_INFO_free(ts);
    ms_countersig_impl_free(impl);
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
        certificate_array_free(sig->certs);
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
