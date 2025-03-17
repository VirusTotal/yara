// string_processing.h
#ifndef STRING_PROCESSING_H
#define STRING_PROCESSING_H

#include <stddef.h>

char *replace_non_letters_non_numbers_with_whitespace(const char *input);
char *string_strip(const char *input);
char *string_to_lower_case(const char *input);
char *string_to_upper_case(const char *input);

#endif // STRING_PROCESSING_H
