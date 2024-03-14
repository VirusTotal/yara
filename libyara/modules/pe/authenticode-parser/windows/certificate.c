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

#include <Windows.h>

#include <yara/error.h>
#include <yara/mem.h>

#include <authenticode-parser/authenticode.h>

#ifdef USE_WINCRYPT_AUTHENTICODE

#include <authenticode-parser/windows/certificate.h>
#include <authenticode-parser/windows/cleanup.h>
#include <authenticode-parser/windows/extractors.h>
#include <authenticode-parser/windows/oid.h>

/// @brief Counts the certificates count in the given cert store
/// @param[in]  cert_store  Certificates store to count from
/// @param[out] count       Resulting count
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
static INT count_certificates_in_cert_store(
    _In_    CONST   HCERTSTORE  cert_store,
    _Out_           PDWORD      count
)
{
    DWORD local_count = 0;

    PCERT_CONTEXT cert_context = NULL;

    if (cert_store == NULL || count == NULL)
        return ERROR_INVALID_ARGUMENT;

    do
    {
        cert_context = CertEnumCertificatesInStore(cert_store, cert_context);
        if (cert_context == NULL)
            break;
        else
            local_count++;
    } while (cert_context != NULL);

    *count = local_count;

    return ERROR_SUCCESS;
}

/// Build Yara certificate data structure from a given microsoft certificate context
/// @param[in]  certificate_context Certificate context to use to build the Yara certificate data structure
/// @param[out] parsed_certificate  Allocated and filled Yara data structure certificate. To be freed with Yara's certificate_free
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
/// @note As key and key_alg is used nowhere in Yara codebase, it is not recovered as it would add complexity for no reason
static INT parse_certificate_authenticode(
    _In_        PCCERT_CONTEXT          certificate_context,
    _Outptr_    Certificate*    *CONST  parsed_certificate
)
{
    INT result = -1;

    Certificate* local_certificate = NULL;

    if (certificate_context == NULL || parsed_certificate == NULL)
        return ERROR_INVALID_ARGUMENT;

    local_certificate = yr_calloc(1, sizeof(Certificate));
    GOTO_EXIT_ON_NULL(local_certificate, ERROR_INSUFFICIENT_MEMORY);

    // Certificate::key is not used
    // Certificate::key_alg is not used

    static CONST CERTIFICATE_PROPERTY_EXTRACTOR_CALLBACK_FUNC property_extractor_callbacks[] =
    {
        retrieve_sha1_from_cert_authenticode,
        retrieve_sha256_from_cert_authenticode,
        retrieve_subject_from_cert_authenticode,
        retrieve_issuer_from_cert_authenticode,
        retrieve_version_from_cert_authenticode,
        retrieve_signature_algorithm_from_cert_authenticode,
        retrieve_serial_from_cert_authenticode,
        retrieve_not_before_from_cert_authenticode,
        retrieve_not_after_from_cert_authenticode,
    };

    for (DWORD property_extractor_callback_ind = 0;
        property_extractor_callback_ind < _countof(property_extractor_callbacks);
        property_extractor_callback_ind++)
    {
        GOTO_EXIT_ON_NULL(property_extractor_callbacks[property_extractor_callback_ind], ERROR_CALLBACK_ERROR);
        property_extractor_callbacks[property_extractor_callback_ind](certificate_context, local_certificate);
    }

    *parsed_certificate = local_certificate;
    local_certificate = NULL;

    result = ERROR_SUCCESS;

_exit:

    if (local_certificate != NULL)
    {
        destroy_certificate(local_certificate);
        local_certificate = NULL;
    }

    return result;
}

/// @brief Reverse the given certificates array order
/// @param[in,out]  certificate_array   Certificates array to be reversed
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
static INT reverse_certificates_array(
    _Inout_ CertificateArray    *CONST  certificate_array
)
{
    if (certificate_array == NULL)
        return ERROR_INVALID_ARGUMENT;

    for (DWORD index = 0; index < certificate_array->count / 2; index++)
    {
        CONST Certificate *temporary_certificate = certificate_array->certs[index];
        certificate_array->certs[index] = certificate_array->certs[certificate_array->count - index - 1];
        certificate_array->certs[certificate_array->count - index - 1] = temporary_certificate;
    }

    return ERROR_SUCCESS;
}

INT get_all_certificates_authenticode(
    _In_        CONST   HCERTSTORE                  cert_store,
    _Outptr_            CertificateArray*   *CONST  certificate_array
)
{
    INT result = -1;

    PCERT_CONTEXT cert_context = NULL;

    CertificateArray* local_certificate_array = NULL;

    DWORD certificate_count = 0;

    if (cert_store == NULL || certificate_array == NULL)
        return ERROR_INVALID_ARGUMENT;

    GOTO_EXIT_ON_ERROR(count_certificates_in_cert_store(cert_store, &certificate_count));

    local_certificate_array = yr_calloc(1, sizeof(CertificateArray));
    GOTO_EXIT_ON_NULL(local_certificate_array, ERROR_INSUFFICIENT_MEMORY);

    local_certificate_array->certs = yr_calloc(certificate_count, sizeof(Certificate*));
    GOTO_EXIT_ON_NULL(local_certificate_array->certs, ERROR_INSUFFICIENT_MEMORY);
    local_certificate_array->count = certificate_count;

    DWORD index = 0;
    do
    {
        // Previous cert_context is freed by CertEnumCertificatesInStore on each call (see https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certenumcertificatesinstore)
        cert_context = CertEnumCertificatesInStore(cert_store, cert_context);
        if (cert_context != NULL)
        {
          GOTO_EXIT_ON_ERROR(parse_certificate_authenticode(cert_context, &local_certificate_array->certs[index++]));
        }
    } while (cert_context != NULL);

    // To match OpenSSL Yara version, we have to reverse the certificates array order
    GOTO_EXIT_ON_ERROR(reverse_certificates_array(local_certificate_array));

    *certificate_array = local_certificate_array;
    local_certificate_array = NULL;

    result = ERROR_SUCCESS;

_exit:

    // In case of an error in the loop, we need to free the cert context
    if (cert_context != NULL)
    {
        CertFreeCertificateContext(cert_context);
        cert_context = NULL;
    }

    if (local_certificate_array != NULL)
    {
        destroy_certificate_array(local_certificate_array);
        local_certificate_array = NULL;
    }

    return result;
}

/// @brief Builds a Yara certificates array which represent the certificate chain for the given Microsoft certificate context
/// @param[in]  cert_store                  Certificates store from where to build chain
/// @param[in]  cert_context                Certificate from which to build the chain
/// @param[in]  certificate_chain_engine    Certificates chain engine to use (HCCE_CURRENT_USER or HCCE_LOCAL_MACHINE)
/// @param[out] certificate_array           Yara certificates array data structure holding the build chain. To be freed using certificate_array_free
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
/// @note Certificate at index 0 is the certificate itself. Next ones are the one composing the chain, to root CA
static INT build_certificate_chain_authenticode(
    _In_        CONST   HCERTSTORE                  cert_store,
    _In_                PCCERT_CONTEXT              cert_context,
    _In_opt_    CONST   HCERTCHAINENGINE            certificate_chain_engine,
    _Outptr_            CertificateArray*   *CONST  certificate_array
)
{
    INT result = -1;

    PCERT_CHAIN_CONTEXT cert_chain_context = NULL;
    PCCERT_SIMPLE_CHAIN cert_simple_chain = NULL;

    CertificateArray* local_certificate_array = NULL;
    Certificate* local_certificate = NULL;

    if (cert_store == NULL || cert_context == NULL || certificate_array == NULL)
        return ERROR_INVALID_ARGUMENT;

    {
        CERT_CHAIN_PARA cert_chain_para = {0};

        cert_chain_para.cbSize = sizeof(CERT_CHAIN_PARA);

        GOTO_EXIT_ON_FAIL(CertGetCertificateChain(certificate_chain_engine,
            cert_context,
            NULL,
            cert_store,
            &cert_chain_para,
            // When using flag CERT_CHAIN_CACHE_END_CERT, multiple calls using the same certificate can crash here, as cert_context is freed between calls
            CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY | CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
            NULL,
            &cert_chain_context));

        // We should have at least one element in chain
        if (cert_chain_context->cChain < 1 || cert_chain_context->rgpChain == NULL || cert_chain_context->rgpChain[0] == NULL)
        {
            result = ERROR_INVALID_DATA;
            goto _exit;
        }
    }

    for (DWORD ChainIndex = 0; ChainIndex < cert_chain_context->cChain; ChainIndex++)
    {
        cert_simple_chain = cert_chain_context->rgpChain[ChainIndex];
        // Looking for non-empty certificate chain
        if (cert_simple_chain->cElement > 0)
          break;
    }

    // We did not manage to find a non-empty chain
    GOTO_EXIT_ON_NULL(cert_simple_chain, ERROR_INVALID_VALUE);

    local_certificate_array = yr_calloc(1, sizeof(CertificateArray));
    GOTO_EXIT_ON_NULL(local_certificate_array, ERROR_INSUFFICIENT_MEMORY);

    local_certificate_array->count = cert_simple_chain->cElement;

    local_certificate_array->certs = yr_calloc(local_certificate_array->count, sizeof(Certificate*));

    for (DWORD element_index = 0; element_index < cert_simple_chain->cElement; element_index++)
    {
        GOTO_EXIT_ON_ERROR(parse_certificate_authenticode(cert_simple_chain->rgpElement[element_index]->pCertContext, &local_certificate));
        local_certificate_array->certs[element_index] = local_certificate;
        local_certificate = NULL;
    }

    *certificate_array = local_certificate_array;
    local_certificate_array = NULL;

    result = ERROR_SUCCESS;

_exit:

    if (local_certificate != NULL)
    {
        destroy_certificate(local_certificate);
        local_certificate = NULL;
    }

    if (local_certificate_array != NULL)
    {
        destroy_certificate_array(local_certificate_array);
        local_certificate_array = NULL;
    }

    if (cert_chain_context != NULL)
    {
        CertFreeCertificateChain(cert_chain_context);
        cert_chain_context = NULL;
    }

    return result;
}

INT format_cert_name_blob_using_known_oid(
    _In_        CONST   CERT_NAME_BLOB*         cert_name_blob,
    _Outptr_            PSTR            *CONST  formatted_name
)
{
    DYNAMIC_STRING dynstring_name = {0};
    PCERT_NAME_INFO cert_name_info = NULL;
    DWORD cert_name_info_size = 0;

    INT result = -1;

    PSTR local_result = NULL;

    PSTR local_attribute_value = NULL;
    PSTR buffer = NULL;

    if (cert_name_blob == NULL || formatted_name == NULL)
        return ERROR_INVALID_ARGUMENT;

    GOTO_EXIT_ON_FAIL(CryptDecodeObject(X509_ASN_ENCODING, X509_NAME, cert_name_blob->pbData, cert_name_blob->cbData, 0, NULL, &cert_name_info_size));

    cert_name_info = (PCERT_NAME_INFO)yr_calloc(1, cert_name_info_size);
    GOTO_EXIT_ON_NULL(cert_name_info, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_FAIL(CryptDecodeObject(X509_ASN_ENCODING, X509_NAME, cert_name_blob->pbData, cert_name_blob->cbData, 0, cert_name_info, &cert_name_info_size));

    GOTO_EXIT_ON_ERROR(dynamic_string_init(&dynstring_name));

    for (DWORD rdn_index = 0; rdn_index < cert_name_info->cRDN; rdn_index++)
    {
        for (DWORD rdn_attr_index = 0;
             rdn_attr_index < cert_name_info->rgRDN[rdn_index].cRDNAttr;
             rdn_attr_index++)
        {
            PCOID_DATA oid_data = NULL;
            PCERT_RDN_ATTR rdnAttribute = &cert_name_info->rgRDN[rdn_index].rgRDNAttr[rdn_attr_index];

            oid_data = find_oid_attribute_data(rdnAttribute->pszObjId);

            // if oid is not found, build the name string without it
            if (oid_data == NULL)
                continue;

            GOTO_EXIT_ON_ERROR(get_string_value_from_cert_rdn_value_blob(rdnAttribute, &local_attribute_value));
            GOTO_EXIT_ON_ERROR(dynamic_string_append(&dynstring_name, "/"));
            GOTO_EXIT_ON_ERROR(dynamic_string_append(&dynstring_name, oid_data->display_name));
            GOTO_EXIT_ON_ERROR(dynamic_string_append(&dynstring_name, "="));
            GOTO_EXIT_ON_ERROR(dynamic_string_append(&dynstring_name, local_attribute_value));

            yr_free(local_attribute_value);
            local_attribute_value = NULL;
        }
    }

    *formatted_name = duplicate_string(dynstring_name.buffer);
    GOTO_EXIT_ON_NULL(*formatted_name, ERROR_INSUFFICIENT_MEMORY);

    result = ERROR_SUCCESS;

_exit:

    if (local_attribute_value != NULL)
    {
        yr_free(local_attribute_value);
        local_attribute_value = NULL;
    }

    if (buffer != NULL)
    {
        yr_free(buffer);
        buffer = NULL;
    }

    dynamic_string_free(&dynstring_name);

    if (cert_name_info != NULL)
    {
        yr_free(cert_name_info);
        cert_name_info = NULL;
    }

    return result;
}

INT fill_attributes_using_cert_name_blob(
    _In_    CONST PCERT_NAME_BLOB           cert_name_blob,
    _Out_         Attributes        *CONST  attributes
)
{
    PCERT_NAME_INFO cert_name_info = NULL;
    DWORD cert_name_info_size = 0;

    INT result = -1;

    PSTR attribute_value = NULL;

    ByteArray *attribute_ptr = NULL;

    if (cert_name_blob == NULL || attributes == NULL)
      return ERROR_INVALID_ARGUMENT;

    GOTO_EXIT_ON_FAIL(CryptDecodeObject(X509_ASN_ENCODING, X509_NAME, cert_name_blob->pbData, cert_name_blob->cbData, 0, NULL, &cert_name_info_size));

    cert_name_info = (PCERT_NAME_INFO)yr_malloc(cert_name_info_size);
    GOTO_EXIT_ON_NULL(cert_name_info, ERROR_INSUFFICIENT_MEMORY);

    GOTO_EXIT_ON_FAIL(CryptDecodeObject(X509_ASN_ENCODING, X509_NAME, cert_name_blob->pbData, cert_name_blob->cbData, 0, cert_name_info, &cert_name_info_size));

    for (DWORD rdn_index = 0; rdn_index < cert_name_info->cRDN; rdn_index++)
    {
        for (DWORD rdn_attr_index = 0;
            rdn_attr_index < cert_name_info->rgRDN[rdn_index].cRDNAttr;
            rdn_attr_index++)
        {
            PCOID_DATA oid_data = NULL;
            PCERT_RDN_ATTR rdnAttribute = &cert_name_info->rgRDN[rdn_index].rgRDNAttr[rdn_attr_index];

            oid_data = find_oid_attribute_data(rdnAttribute->pszObjId);
            if (oid_data == NULL)
                continue;

            switch (oid_data->attribute_type)
            {
            case ATTRIBUTE_COMMON_NAME:
                attribute_ptr = &attributes->commonName;
                break;
            case ATTRIBUTE_SURNAME:
                attribute_ptr = &attributes->surname;
                break;
            case ATTRIBUTE_SERIAL_NUMBER:
                attribute_ptr = &attributes->serialNumber;
                break;
            case ATTRIBUTE_COUNTRY_NAME:
                attribute_ptr = &attributes->country;
                break;
            case ATTRIBUTE_ORGANIZATION_NAME:
                attribute_ptr = &attributes->organization;
                break;
            case ATTRIBUTE_ORGANIZATION_UNIT_NAME:
                attribute_ptr = &attributes->organizationalUnit;
                break;
            case ATTRIBUTE_GENERATION_QUALIFIER:
                attribute_ptr = &attributes->generationQualifier;
                break;
            case ATTRIBUTE_PSEUDONYM:
                attribute_ptr = &attributes->pseudonym;
                break;
            case ATTRIBUTE_INITIALS:
                attribute_ptr = &attributes->initials;
                break;
            case ATTRIBUTE_GIVEN_NAME:
                attribute_ptr = &attributes->givenName;
                break;
            case ATTRIBUTE_TITLE:
                attribute_ptr = &attributes->title;
                break;
            case ATTRIBUTE_LOCALITY_NAME:
                attribute_ptr = &attributes->locality;
                break;
            case ATTRIBUTE_STATE_OR_PROVINCE_NAME:
                attribute_ptr = &attributes->state;
                break;
            case ATTRIBUTE_DN_QUALIFIER:
                attribute_ptr = &attributes->nameQualifier;
                break;
            case ATTRIBUTE_EMAIL_ADDRESS:
                attribute_ptr = &attributes->emailAddress;
                break;

            default:
                // not a mapped attribute, we continue
                continue;
            }

            // should not happen
            if (attribute_ptr == NULL)
                continue;

            GOTO_EXIT_ON_ERROR(get_string_value_from_cert_rdn_value_blob(rdnAttribute, &attribute_value));

            // fill the attribute
            attribute_ptr->len = strlen(attribute_value);
            attribute_ptr->data = (uint8_t*)attribute_value;
            attribute_value = NULL;
        }
    }

    result = ERROR_SUCCESS;

_exit:

    if (attribute_value != NULL)
    {
        yr_free(attribute_value);
        attribute_value = NULL;
    }

    if (cert_name_info != NULL)
    {
        yr_free(cert_name_info);
        cert_name_info = NULL;
    }

    return result;
}

INT find_signer_certificate_from_signer_info(
  _In_      CONST   HCERTSTORE                  cert_store,
  _In_      CONST   PCMSG_SIGNER_INFO           signer_info,
  _Outptr_          PCERT_CONTEXT       *CONST  cert_context
)
{
    INT result = -1;

    CERT_INFO lookup_cert_info = {0};

    if (cert_store == NULL || signer_info == NULL || cert_context == NULL)
        return ERROR_INVALID_ARGUMENT;

    // Use (issuer, serialnumber) from signerinfo to look up certificate from store
    lookup_cert_info.Issuer = signer_info->Issuer;
    lookup_cert_info.SerialNumber = signer_info->SerialNumber;

    *cert_context = CertFindCertificateInStore(cert_store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_CERT,
        &lookup_cert_info,
        NULL);
    GOTO_EXIT_ON_NULL(*cert_context, ERROR_INVALID_VALUE);

    result = ERROR_SUCCESS;

_exit:

    return result;
}

INT build_certificate_chain_from_signer_info(
    _In_    CONST   HCERTSTORE                  cert_store,
    _In_    CONST   PCMSG_SIGNER_INFO           signer_info,
    _Out_           CertificateArray*   *CONST  certificate_chain_array
)
{
    INT result = -1;

    PCERT_CONTEXT cert_context = NULL;

    if (cert_store == NULL || signer_info == NULL || certificate_chain_array == NULL)
        return ERROR_INVALID_ARGUMENT;

    GOTO_EXIT_ON_ERROR(find_signer_certificate_from_signer_info(cert_store, signer_info, &cert_context));
    // Current user certificates store inherit from local machine certificates store (https://learn.microsoft.com/en-us/windows-hardware/drivers/install/local-machine-and-current-user-certificate-stores)
    GOTO_EXIT_ON_ERROR(build_certificate_chain_authenticode(cert_store, cert_context, HCCE_CURRENT_USER, certificate_chain_array));

    result = ERROR_SUCCESS;

_exit:

    if (cert_context != NULL)
    {
        CertFreeCertificateContext(cert_context);
        cert_context = NULL;
    }

    return result;
}

#endif // USE_WINCRYPT_AUTHENTICODE
