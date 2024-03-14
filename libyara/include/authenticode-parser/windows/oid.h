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

#ifndef YR_AUTHENTICODE_WINDOWS_OID_H
#define YR_AUTHENTICODE_WINDOWS_OID_H

#ifdef USE_WINCRYPT_AUTHENTICODE

/// @brief Attributes types to be used when looking for a particular attribute
typedef enum ATTRIBUTE_TYPE
{
    ATTRIBUTE_COMMON_NAME,
    ATTRIBUTE_SURNAME,
    ATTRIBUTE_SERIAL_NUMBER,
    ATTRIBUTE_COUNTRY_NAME,
    ATTRIBUTE_LOCALITY_NAME,
    ATTRIBUTE_STATE_OR_PROVINCE_NAME,
    ATTRIBUTE_STREET,
    ATTRIBUTE_ORGANIZATION_NAME,
    ATTRIBUTE_ORGANIZATION_UNIT_NAME,
    ATTRIBUTE_TITLE,
    ATTRIBUTE_DESCRIPTION,
    ATTRIBUTE_SEARCH_GUIDE,
    ATTRIBUTE_BUSINESS_CATEGORY,
    ATTRIBUTE_POSTAL_ADDRESS,
    ATTRIBUTE_POSTAL_CODE,
    ATTRIBUTE_POSTAL_OFFICE_BOX,
    ATTRIBUTE_PHYSICAL_DELIVERY_OFFICE_NAME,
    ATTRIBUTE_TELEPHONE_NUMBER,
    ATTRIBUTE_TELEX_NUMBER,
    ATTRIBUTE_TELETEX_TERMINAL_IDENTIFIER,
    ATTRIBUTE_FACSIMILE_TELEPHONE_NUMBER,
    ATTRIBUTE_X121_ADDRESS,
    ATTRIBUTE_INTERNATIONAL_ISDN_NUMBER,
    ATTRIBUTE_REGISTERED_ADDRESS,
    ATTRIBUTE_DESTINATION_INDICATOR,
    ATTRIBUTE_PREFERRED_DELIVERY_METHOD,
    ATTRIBUTE_PRESENTATION_ADDRESS,
    ATTRIBUTE_SUPPORTED_APPLICATION_CONTEXT,
    ATTRIBUTE_MEMBER,
    ATTRIBUTE_OWNER,
    ATTRIBUTE_ROLE_OCCUPANT,
    ATTRIBUTE_SEE_ALSO,
    ATTRIBUTE_USER_PASSWORD,
    ATTRIBUTE_USER_CERTIFICATE,
    ATTRIBUTE_CA_CERTIFICATE,
    ATTRIBUTE_AUTHORITY_REVOCATION_LIST,
    ATTRIBUTE_CERTIFICATE_REVOCATION_LIST,
    ATTRIBUTE_CROSS_CERTIFICATE_PAIR,
    ATTRIBUTE_NAME,
    ATTRIBUTE_GIVEN_NAME,
    ATTRIBUTE_INITIALS,
    ATTRIBUTE_GENERATION_QUALIFIER,
    ATTRIBUTE_X500_UNIQUE_IDENTIFIER,
    ATTRIBUTE_DN_QUALIFIER,
    ATTRIBUTE_ENHANCED_SEARCH_GUIDE,
    ATTRIBUTE_PROTOCOL_INFORMATION,
    ATTRIBUTE_DISTINGUISHED_NAME,
    ATTRIBUTE_UNIQUE_MEMBER,
    ATTRIBUTE_HOUSE_IDENTIFIER,
    ATTRIBUTE_SUPPORTED_ALGORITHMS,
    ATTRIBUTE_DELTA_REVOCATION_LIST,
    ATTRIBUTE_DMD_NAME,
    ATTRIBUTE_PSEUDONYM,
    ATTRIBUTE_ROLE,
    ATTRIBUTE_ORGANIZATION_IDENTIFIER,
    ATTRIBUTE_C3,
    ATTRIBUTE_N3,
    ATTRIBUTE_DNS_NAME,
    ATTRIBUTE_JURISDICTION_OF_INCORPORATION_LOCALITY_NAME,
    ATTRIBUTE_JURISDICTION_OF_INCORPORATION_STATE_OR_PROVINCE_NAME,
    ATTRIBUTE_JURISDICTION_OF_INCORPORATION_COUNTRY_NAME,
    ATTRIBUTE_EMAIL_ADDRESS
} ATTRIBUTE_TYPE;

/// @brief A structure that matches an object ID (numerical reference) to a
/// human readable name or description, plus some info.
typedef struct _OID_DATA
{
  /// A string representing the OID
  PCSTR oid;

  /// A string containing the display name
  PCSTR display_name;

  // Attribute type associated to this OID
  ATTRIBUTE_TYPE attribute_type;
} OID_DATA, *POID_DATA;
typedef CONST OID_DATA* PCOID_DATA;

/// @brief Gets the display name for an algorithm designated by its OID, according to the ISO classification.
/// @param[in] algo_oid A pointer to a ANSI string representing the algorithm OID
/// @return A pointer to a string containing the display name on success. It must be freed using yr_free
/// @return NULL otherwise.
PCSTR get_algorithmname_from_oid(
  _In_  PCSTR algo_oid
);

/// @brief Gets data for an oid designated by its OID, according to the ISO
/// classification.
/// @param[in] attr_name_oid A pointer to a ANSI string representing the
/// attribute OID
/// @return A pointer to an OID_DATA element
/// @return NULL otherwise.
/// @note The caller MUST NOT release the returned data as it is a pointer to
/// a static element.
PCOID_DATA find_oid_attribute_data(
  _In_  PCSTR attr_name_oid
);

/// @brief Finds the wincrypt digest algorithm constant for a given OpenSSL digest algorithm name
/// @param[in]  algorithm_name  Name of the algorithm to look constant for
/// @param[out] algorithm_id    Set to the constant of the algorithm if is_found is set to TRUE by this function
/// @param[out] is_found        TRUE if the digest algorithm is found, FALSE otherwise
/// @return Algorithm name if found, NULL otherwise
PCWSTR find_algorithm_from_algorithm_name(
    _In_    CONST   PCSTR   algorithm_name
);

/// @brief Finds the bcrypt algorithm constant from the given algorithm oid
/// @param[in]  algorithm_oid       Algorithm oid to look algorithm bcrypt constant for
/// @param[out] bcrypt_algorithm    BCrypt algorithm matching the algorithm oid
/// @return ERROR_SUCCESS if everything went well, a Yara error code otherwise
INT find_bcrypt_algorithm_from_oid(
    _In_    PCSTR           algorithm_oid,
    _Out_   PCWSTR  *CONST  bcrypt_algorithm
);

#endif // USE_WINCRYPT_AUTHENTICODE

#endif // !YR_AUTHENTICODE_WINDOWS_OID_H
