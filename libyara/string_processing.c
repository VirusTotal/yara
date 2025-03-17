// string_processing.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "include/yara/string_processing.h"

// Function to replace non-letter and non-number characters with whitespace
char *replace_non_letters_non_numbers_with_whitespace(const char *input) {
    if (!input) return NULL;

    size_t length = strlen(input);
    char *result = malloc(length + 1);
    if (!result) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < length; i++) {
        if (isalnum((unsigned char)input[i])) {
            result[j++] = input[i];
        } else {
            // Only add a single whitespace for sequences of non-alphanumeric characters
            if (j > 0 && result[j - 1] != ' ') {
                result[j++] = ' ';
            }
        }
    }
    
    // Null-terminate the string
    if (j > 0 && result[j - 1] == ' ') {
        j--;  // Remove trailing whitespace
    }
    result[j] = '\0';

    return result;
}

// Function to strip whitespace from both ends of the string
char *string_strip(const char *input) {
    if (!input) return NULL;

    const char *end;
    // Trim leading space
    while (isspace((unsigned char)*input)) input++;

    if (*input == 0)  // All spaces?
        return strdup(""); // Return an empty string

    // Trim trailing space
    end = input + strlen(input) - 1;
    while (end > input && isspace((unsigned char)*end)) end--;

    // Null-terminate the string
    size_t length = end - input + 1;
    char *result = malloc(length + 1);
    if (!result) return NULL;

    strncpy(result, input, length);
    result[length] = '\0';  // Null-terminate the result

    return result;
}

// Function to convert a string to lower case
char *string_to_lower_case(const char *input) {
    if (!input) return NULL;

    size_t length = strlen(input);
    char *result = malloc(length + 1);
    if (!result) return NULL;

    for (size_t i = 0; i < length; i++) {
        result[i] = tolower((unsigned char)input[i]);
    }
    result[length] = '\0';  // Null-terminate the result

    return result;
}

// Function to convert a string to upper case
char *string_to_upper_case(const char *input) {
    if (!input) return NULL;

    size_t length = strlen(input);
    char *result = malloc(length + 1);
    if (!result) return NULL;

    for (size_t i = 0; i < length; i++) {
        result[i] = toupper((unsigned char)input[i]);
    }
    result[length] = '\0';  // Null-terminate the result

    return result;
}
