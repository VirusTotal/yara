#ifndef FUZZ_H
#define FUZZ_H

#include <stddef.h>  // For size_t

// Basic Scoring Function Declarations
int ratio(const char *s1, const char *s2);
int partial_ratio(const char *s1, const char *s2);

// Advanced Scoring Function Declarations
char* process_and_sort(const char *s, int force_ascii, int use_full_process);
int token_sort_ratio(const char *s1, const char *s2, int force_ascii, int use_full_process);
int partial_token_sort_ratio(const char *s1, const char *s2, int force_ascii, int use_full_process);

// Combination API Function Declarations
int QRatio(const char *s1, const char *s2, int force_ascii, int use_full_process);
int UQRatio(const char *s1, const char *s2, int use_full_process);
int WRatio(const char *s1, const char *s2, int force_ascii, int use_full_process);
int UWRatio(const char *s1, const char *s2, int use_full_process);

#endif // FUZZ_H
