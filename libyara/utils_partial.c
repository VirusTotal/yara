#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "include/yara/utils_partial.h"
#include "include/yara/string_processing.h" // Including the updated StringProcessor equivalent header

#define PY3 1 // Python 3 behavior is assumed in this implementation

// Function to validate if a string has length > 0
int validate_string(const char *s) {
    return s != NULL && strlen(s) > 0;
}

// Function pointer types for decorators
typedef int (*StringFunc)(const char *, const char *);

// Decorator equivalent for checking equivalence
int check_for_equivalence(const char *s1, const char *s2, StringFunc func) {
    if (strcmp(s1, s2) == 0) {
        return 100;
    }
    return func(s1, s2);
}

// Decorator equivalent for checking None (NULL in C)
int check_for_none(const char *s1, const char *s2, StringFunc func) {
    if (s1 == NULL || s2 == NULL) {
        return 0;
    }
    return func(s1, s2);
}

// Decorator equivalent for checking empty strings
int check_empty_string(const char *s1, const char *s2, StringFunc func) {
    if (strlen(s1) == 0 || strlen(s2) == 0) {
        return 0;
    }
    return func(s1, s2);
}

// Function to remove non-ASCII characters from a string
void remove_non_ascii(char *s) {
    char *ptr = s;
    while (*s) {
        if ((unsigned char)*s < 128) {
            *ptr++ = *s;
        }
        s++;
    }
    *ptr = '\0';
}

// Function equivalent to `asciidammit`
void asciidammit(char *s) {
    remove_non_ascii(s);
}

// Function to ensure both strings are of the same type
void make_type_consistent(char **s1, char **s2) {
    if (*s1 == NULL || *s2 == NULL) {
        printf("Error: Strings must not be NULL\n");
        exit(1);
    }
}

// Function to process a string equivalent to `full_process`
char* full_process(char *s, int force_ascii) {
    if (force_ascii) {
        asciidammit(s);
    }

    // Replace non-letters/non-numbers with whitespace
    s = replace_non_letters_non_numbers_with_whitespace(s);

    // Convert to lowercase
    s = string_to_lower_case(s);

    // Trim whitespace
    s = string_strip(s);

    return s;
}

// Function to round a float value and return an integer
int intr(double n) {
    return (int)(n + 0.5);
}
