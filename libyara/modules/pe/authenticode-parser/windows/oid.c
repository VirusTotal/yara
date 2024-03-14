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

#ifdef USE_WINCRYPT_AUTHENTICODE

#include <yara/error.h>
#include <yara/mem.h>

#include <authenticode-parser/windows/tools.h>
#include <authenticode-parser/windows/oid.h>

/// @brief Algorithm name to wincrypt algorithm data structure
typedef struct _ALGORITHM_NAME_TO_WINCRYPT_ALGORITHM
{
    // Algorithm name, as expressed by OpenSSL (see algorithm_oid_name_matching)
    PCSTR algorithm_name;

    // Cryptographic algorithm equivalent
    PCWSTR cryptographic_algorithm;
} ALGORITHM_NAME_TO_WINCRYPT_ALGORITHM;

/// @brief Mappings between digest algorithm name and BCrypt constant
static CONST ALGORITHM_NAME_TO_WINCRYPT_ALGORITHM digest_algorithm_name_to_algorithm[] =
{
    {"md2",     BCRYPT_MD2_ALGORITHM    },
    {"md4",     BCRYPT_MD4_ALGORITHM    },
    {"md5",     BCRYPT_MD5_ALGORITHM    },
    {"sha",     BCRYPT_SHA1_ALGORITHM   },
    {"sha1",    BCRYPT_SHA1_ALGORITHM   },
    {"sha256",  BCRYPT_SHA256_ALGORITHM },
    {"sha384",  BCRYPT_SHA384_ALGORITHM },
    {"sha512",  BCRYPT_SHA512_ALGORITHM },
};

// This list is put together with the algorithm short names definitions from the
// OpenSSL sources. This avoids discrepancies between using OpenSSL and Wincrypt
// uses which would cause different results for the same Yara rule evaluation.
static CONST OID_DATA algorithm_oid_name_matching[] =
{
    {"1.2.840.10040.4.1", "dsaEncryption"},
    {"1.2.840.10040.4.3", "dsaWithSHA1"},

    {"1.2.840.113533.7.66.10", "CAST5-CBC"},
    {"1.2.840.113533.7.66.12", "pbeWithMD5AndCast5CBC"},
    {"1.2.840.113533.7.66.13", "id-PasswordBasedMAC"},
    {"1.2.840.113533.7.66.30", "Diffie-Hellman based MAC"},

    {"1.2.840.113549.1", "pkcs"},
    {"1.2.840.113549.1.1", "pkcs1"},
    {"1.2.840.113549.1.1.1", "rsaEncryption"},
    {"1.2.840.113549.1.1.2", "md2WithRSAEncryption"},
    {"1.2.840.113549.1.1.3", "md4WithRSAEncryption"},
    {"1.2.840.113549.1.1.4", "md5WithRSAEncryption"},
    {"1.2.840.113549.1.1.5", "sha1WithRSAEncryption"},
    {"1.2.840.113549.1.1.7", "rsaesOaep"},
    {"1.2.840.113549.1.1.8", "mgf1"},
    {"1.2.840.113549.1.1.9", "pSpecified"},
    {"1.2.840.113549.1.1.10", "rsassaPss"},
    {"1.2.840.113549.1.1.11", "sha256WithRSAEncryption"},
    {"1.2.840.113549.1.1.12", "sha384WithRSAEncryption"},
    {"1.2.840.113549.1.1.13", "sha512WithRSAEncryption"},
    {"1.2.840.113549.1.1.14", "sha224WithRSAEncryption"},
    {"1.2.840.113549.1.1.15", "sha512-224WithRSAEncryption"},
    {"1.2.840.113549.1.1.16", "sha512-256WithRSAEncryption"},

    {"1.2.840.113549.2.2", "md2"},
    {"1.2.840.113549.2.4", "md4"},
    {"1.2.840.113549.2.5", "md5"},
    {"1.2.840.113549.2.6", "hmacWithMD5"},
    {"1.2.840.113549.2.7", "hmacWithSHA1"},
    {"1.2.840.113549.2.8", "hmacWithSHA224"},
    {"1.2.840.113549.2.9", "hmacWithSHA256"},
    {"1.2.840.113549.2.10", "hmacWithSHA384"},
    {"1.2.840.113549.2.11", "hmacWithSHA512"},
    {"1.2.840.113549.2.12", "hmacWithSHA512-224"},
    {"1.2.840.113549.2.13", "hmacWithSHA512-256"},

    {"1.2.840.113549.3.2", "rc2-cbc"},
    {"1.2.840.113549.3.4", "rc4"},
    {"1.2.840.113549.3.7", "des-ede3-cbc"},
    {"1.2.840.113549.3.8", "rc5-cbc"},
    {"1.2.840.113549.3.10", "des-cdmf"},

    {"1.2.840.10040", "X9.57"},
    {"1.2.840.10040.4.1", "dsaEncryption"},
    {"1.2.840.10040.4.3", "dsaWithSHA1"},

    {"1.2.840.10046.2.1", "X9.42 DH"},

    {"1.3.14.3.2.18", "sha"},
    {"1.3.14.3.2.26", "sha1"},

    {"2.16.840.1.101.3.4.2.1", "sha256"},
    {"2.16.840.1.101.3.4.2.2", "sha384"},
    {"2.16.840.1.101.3.4.2.3", "sha512"},
    {"2.16.840.1.101.3.4.2.4", "sha224"},
    {"2.16.840.1.101.3.4.2.5", "sha512-224"},
    {"2.16.840.1.101.3.4.2.6", "sha512-256"},
};

// This list is put together with the DN attribute short names definitions from
// the OpenSSL sources. This avoids discrepancies between using OpenSSL and
// Wincrypt uses which would cause different results for the same Yara rule
// evaluation. When OpenSSL does not define a short name for an entry, regular
// name is used.
static CONST OID_DATA attribute_name_oid_short_name_matching[] =
{
    {"2.5.4.3", "CN", ATTRIBUTE_COMMON_NAME},
    {"2.5.4.4", "SN", ATTRIBUTE_SURNAME},
    {"2.5.4.5", "serialNumber", ATTRIBUTE_SERIAL_NUMBER},
    {"2.5.4.6", "C", ATTRIBUTE_COUNTRY_NAME},
    {"2.5.4.7", "L", ATTRIBUTE_LOCALITY_NAME},
    {"2.5.4.8", "ST", ATTRIBUTE_STATE_OR_PROVINCE_NAME},
    {"2.5.4.9", "street", ATTRIBUTE_STREET},
    {"2.5.4.10", "O", ATTRIBUTE_ORGANIZATION_NAME},
    {"2.5.4.11", "OU", ATTRIBUTE_ORGANIZATION_UNIT_NAME},
    {"2.5.4.12", "title", ATTRIBUTE_TITLE},
    {"2.5.4.13", "description", ATTRIBUTE_DESCRIPTION},
    {"2.5.4.14", "searchGuide", ATTRIBUTE_SEARCH_GUIDE},
    {"2.5.4.15", "businessCategory", ATTRIBUTE_BUSINESS_CATEGORY},
    {"2.5.4.16", "postalAddress", ATTRIBUTE_POSTAL_ADDRESS},
    {"2.5.4.17", "postalCode", ATTRIBUTE_POSTAL_CODE},
    {"2.5.4.18", "postOfficeBox", ATTRIBUTE_POSTAL_OFFICE_BOX},
    {"2.5.4.19", "physicalDeliveryOfficeName", ATTRIBUTE_PHYSICAL_DELIVERY_OFFICE_NAME},
    {"2.5.4.20", "telephoneNumber", ATTRIBUTE_TELEPHONE_NUMBER},
    {"2.5.4.21", "telexNumber", ATTRIBUTE_TELEX_NUMBER},
    {"2.5.4.22", "teletexTerminalIdentifier", ATTRIBUTE_TELETEX_TERMINAL_IDENTIFIER},
    {"2.5.4.23", "facsimileTelephoneNumber", ATTRIBUTE_FACSIMILE_TELEPHONE_NUMBER},
    {"2.5.4.24", "x121Address", ATTRIBUTE_X121_ADDRESS},
    {"2.5.4.25", "internationalISDNNumber", ATTRIBUTE_INTERNATIONAL_ISDN_NUMBER},
    {"2.5.4.26", "registeredAddress", ATTRIBUTE_REGISTERED_ADDRESS},
    {"2.5.4.27", "destinationIndicator", ATTRIBUTE_DESTINATION_INDICATOR},
    {"2.5.4.28", "preferredDeliveryMethod", ATTRIBUTE_PREFERRED_DELIVERY_METHOD},
    {"2.5.4.29", "presentationAddress", ATTRIBUTE_PRESENTATION_ADDRESS},
    {"2.5.4.30", "supportedApplicationContext", ATTRIBUTE_SUPPORTED_APPLICATION_CONTEXT},
    {"2.5.4.31", "member", ATTRIBUTE_MEMBER},
    {"2.5.4.32", "owner", ATTRIBUTE_OWNER},
    {"2.5.4.33", "roleOccupant", ATTRIBUTE_ROLE_OCCUPANT},
    {"2.5.4.34", "seeAlso", ATTRIBUTE_SEE_ALSO},
    {"2.5.4.35", "userPassword", ATTRIBUTE_USER_PASSWORD},
    {"2.5.4.36", "userCertificate", ATTRIBUTE_USER_CERTIFICATE},
    {"2.5.4.37", "cACertificate", ATTRIBUTE_CA_CERTIFICATE},
    {"2.5.4.38", "authorityRevocationList", ATTRIBUTE_AUTHORITY_REVOCATION_LIST},
    {"2.5.4.39", "certificateRevocationList", ATTRIBUTE_CERTIFICATE_REVOCATION_LIST},
    {"2.5.4.40", "crossCertificatePair", ATTRIBUTE_CROSS_CERTIFICATE_PAIR},
    {"2.5.4.41", "name", ATTRIBUTE_NAME},
    {"2.5.4.42", "GN", ATTRIBUTE_GIVEN_NAME},
    {"2.5.4.43", "initials", ATTRIBUTE_INITIALS},
    {"2.5.4.44", "generationQualifier", ATTRIBUTE_GENERATION_QUALIFIER},
    {"2.5.4.45", "x500UniqueIdentifier", ATTRIBUTE_X500_UNIQUE_IDENTIFIER},
    {"2.5.4.46", "dnQualifier", ATTRIBUTE_DN_QUALIFIER},
    {"2.5.4.47", "enhancedSearchGuide", ATTRIBUTE_ENHANCED_SEARCH_GUIDE},
    {"2.5.4.48", "protocolInformation", ATTRIBUTE_PROTOCOL_INFORMATION},
    {"2.5.4.49", "distinguishedName", ATTRIBUTE_DISTINGUISHED_NAME},
    {"2.5.4.50", "uniqueMember", ATTRIBUTE_UNIQUE_MEMBER},
    {"2.5.4.51", "houseIdentifier", ATTRIBUTE_HOUSE_IDENTIFIER},
    {"2.5.4.52", "supportedAlgorithms", ATTRIBUTE_SUPPORTED_ALGORITHMS},
    {"2.5.4.53", "deltaRevocationList", ATTRIBUTE_DELTA_REVOCATION_LIST},
    {"2.5.4.54", "dmdName", ATTRIBUTE_DMD_NAME},
    {"2.5.4.65", "pseudonym", ATTRIBUTE_PSEUDONYM},
    {"2.5.4.72", "role", ATTRIBUTE_ROLE},
    {"2.5.4.97", "organizationIdentifier", ATTRIBUTE_ORGANIZATION_IDENTIFIER},
    {"2.5.4.98", "c3", ATTRIBUTE_C3},
    {"2.5.4.99", "n3", ATTRIBUTE_N3},
    {"2.5.4.100", "dnsName", ATTRIBUTE_DNS_NAME},
    {"1.3.6.1.4.1.311.60.2.1.1", "jurisdictionL", ATTRIBUTE_JURISDICTION_OF_INCORPORATION_LOCALITY_NAME},
    {"1.3.6.1.4.1.311.60.2.1.2", "jurisdictionST", ATTRIBUTE_JURISDICTION_OF_INCORPORATION_STATE_OR_PROVINCE_NAME},
    {"1.3.6.1.4.1.311.60.2.1.3", "jurisdictionC", ATTRIBUTE_JURISDICTION_OF_INCORPORATION_COUNTRY_NAME},
    {"1.2.840.113549.1.9.1", "emailAddress", ATTRIBUTE_EMAIL_ADDRESS}, // deprecated but used by Yara to fill attributes
};

/// @brief Looks through an array of OID_TO_NAME for the given entry and returns
/// @brief the matching oid. The matching is case sensistive.
/// @brief This function is a private helper function and is not meant to be
/// used directly.
/// @param[in] oid The OID for which we want the display name
/// @param[in] oid_table An array of OID_TO_NAME matching structures
/// @param[in] oid_table_size The number of elements in oid_table
/// @return A pointer to an oid structure on success, not to be freed
/// @return NULL otherwise.
static PCOID_DATA lookup_oid_data(
    _In_ PCSTR oid,
    _In_ PCOID_DATA oid_table,
    _In_ size_t oid_table_size)
{
    // we do not test parameters since we are in a private function. Caller is
    // responsible for what is passed to it.

    for (size_t algo_index = 0; algo_index < oid_table_size; algo_index++)
    {
        if (strcmp(oid_table[algo_index].oid, oid) == 0)
            return &oid_table[algo_index];
    }

    return NULL;
}

/// @brief Looks through an array of OID_TO_NAME for the given entry and returns
/// @brief the matching display name. The matching is case sensistive.
/// @brief This function is a private helper function and is not meant to be
/// used directly.
/// @param[in] oid The OID for which we want the display name
/// @param[in] oid_table An array of OID_TO_NAME matching structures
/// @param[in] oid_table_size The number of elements in oid_table
/// @return A pointer to a string containing the display name on success, not to be freed
/// @return NULL otherwise.
static PCSTR lookup_oid_display_name(
    _In_ PCSTR oid,
    _In_ PCOID_DATA oid_table,
    _In_ size_t oid_table_size)
{
    // we do not test parameters since we are in a private function. Caller is
    // responsible for what is passed to it.

    PCOID_DATA data = lookup_oid_data(oid, oid_table, oid_table_size);
    if (data == NULL)
    {
        return NULL;
    }
    else
    {
        return data->display_name;
    }
}

PCSTR get_algorithmname_from_oid(
    _In_ PCSTR algorithm_oid
)
{
    PCSTR algorithm_display_name = NULL;

    if (algorithm_oid == NULL)
        return NULL;

    algorithm_display_name = lookup_oid_display_name(
        algorithm_oid,
        algorithm_oid_name_matching,
        _countof(algorithm_oid_name_matching));
    if (algorithm_display_name == NULL)
        return NULL;

    return duplicate_string(algorithm_display_name);
}

PCOID_DATA find_oid_attribute_data(
    _In_ PCSTR attr_name_oid
)
{
    if (attr_name_oid == NULL)
        return NULL;

    return lookup_oid_data(
        attr_name_oid,
        attribute_name_oid_short_name_matching,
        _countof(attribute_name_oid_short_name_matching));
}

PCWSTR find_algorithm_from_algorithm_name(
    _In_    CONST   PCSTR   algorithm_name
)
{
    if (algorithm_name == NULL)
      return NULL;

    for (DWORD algorithm_index = 0; algorithm_index < _countof(digest_algorithm_name_to_algorithm); algorithm_index++)
    {
        if (strcmp(algorithm_name, digest_algorithm_name_to_algorithm[algorithm_index].algorithm_name) == 0)
        {
            return digest_algorithm_name_to_algorithm[algorithm_index].cryptographic_algorithm;
        }
    }

    return NULL;
}


INT find_bcrypt_algorithm_from_oid(
    _In_    PCSTR           algorithm_oid,
    _Out_   PCWSTR  *CONST  bcrypt_algorithm
)
{
    INT result = -1;

    PCSTR algorithm_name = NULL;

    if (algorithm_oid == NULL || bcrypt_algorithm == NULL)
        return ERROR_INVALID_ARGUMENT;

    algorithm_name = get_algorithmname_from_oid(algorithm_oid);
    if (algorithm_name == NULL)
        return ERROR_INVALID_VALUE;

    *bcrypt_algorithm = find_algorithm_from_algorithm_name(algorithm_name);
    GOTO_EXIT_ON_NULL((*bcrypt_algorithm), ERROR_INVALID_VALUE);

    result = ERROR_SUCCESS;

_exit:

    if (algorithm_name != NULL)
    {
        yr_free(algorithm_name);
        algorithm_name = NULL;
    }

    return result;
}

#endif // USE_WINCRYPT_AUTHENTICODE
