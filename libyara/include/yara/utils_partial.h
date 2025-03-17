#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

// Function declarations

// Validates if the string is non-NULL and its length is greater than zero
int validate_string(const char *s);

// Decorator equivalents using function pointers
typedef int (*StringFunc)(const char *, const char *);

// Checks if the two strings are equivalent; returns 100 if true, otherwise calls the provided function
int check_for_equivalence(const char *s1, const char *s2, StringFunc func);

// Checks if either of the strings is NULL; returns 0 if true, otherwise calls the provided function
int check_for_none(const char *s1, const char *s2, StringFunc func);

// Checks if either of the strings is empty; returns 0 if true, otherwise calls the provided function
int check_empty_string(const char *s1, const char *s2, StringFunc func);

// Removes non-ASCII characters from the string
void remove_non_ascii(char *s);

// Converts the string to ASCII only, removing non-ASCII characters
void asciidammit(char *s);

// Ensures that both strings are non-NULL and are of the same type (in C, ensures they are not NULL)
void make_type_consistent(char **s1, char **s2);

// Processes the string: removes non-letters/numbers, trims whitespace, and converts to lowercase
char* full_process(char *s, int force_ascii);

// Rounds a floating-point number to the nearest integer
int intr(double n);

#endif // UTILS_H
