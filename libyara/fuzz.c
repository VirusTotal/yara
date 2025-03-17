#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/yara/utils_partial.h"
#include "include/yara/StringMatcher.h"
#include "include/yara/fuzz.h"
#include "include/yara/string_processing.h"

// Basic Scoring Functions
#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

int ratio(const char *s1, const char *s2) {
    if (!validate_string(s1) || !validate_string(s2)) return 0;

    StringMatcher matcher;
    init_string_matcher(&matcher, s1, s2);
    double match_ratio = calculate_ratio(&matcher);
    destroy_string_matcher(&matcher);

    return intr(100 * match_ratio);
}

// The below code works as always str1 is checked against str2 regardless of their lengths 
// checks wheather str1 is substring of str2
int lcs_length(const char *s1, const char *s2) {
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);

    // Create a 2D array to store LCS lengths
    int **lcs_table = (int **)malloc((len1 + 1) * sizeof(int *));
    for (size_t i = 0; i <= len1; i++) {
        lcs_table[i] = (int *)malloc((len2 + 1) * sizeof(int));
    }

    // Initialize the table
    for (size_t i = 0; i <= len1; i++) {
        for (size_t j = 0; j <= len2; j++) {
            if (i == 0 || j == 0) {
                lcs_table[i][j] = 0;
            } else if (s1[i - 1] == s2[j - 1]) {
                lcs_table[i][j] = lcs_table[i - 1][j - 1] + 1;
            } else {
                lcs_table[i][j] = (lcs_table[i - 1][j] > lcs_table[i][j - 1]) ? lcs_table[i - 1][j] : lcs_table[i][j - 1];
            }
        }
    }

    int lcs_len = lcs_table[len1][len2];

    // Free memory
    for (size_t i = 0; i <= len1; i++) {
        free(lcs_table[i]);
    }
    free(lcs_table);

    return lcs_len;
}

// Helper function to check if a cyclic rotation of str1 is a substring of str2
int is_cyclic_rotation(const char *str1, const char *str2) {
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);

    // If lengths are not equal, it cannot be a cyclic rotation
    if (len1 != len2) return 0;

    // Create a concatenated version of str1 (str1 + str1)
    char *concatenated = (char *)malloc(2 * len1 + 1);
    strcpy(concatenated, str1);
    strcat(concatenated, str1);

    // Check if str2 is a substring of the concatenated version
    int result = (strstr(concatenated, str2) != NULL);

    free(concatenated);
    return result;
}

// Helper function to count matching words (case-sensitive, reordered)
int count_reordered_matching_words(const char *s1, const char *s2) {
    char *s1_copy = strdup(s1);
    char *s2_copy = strdup(s2);
    int match_count = 0;

    char *token = strtok(s1_copy, " ");
    while (token != NULL) {
        // Check if the word exists in the second string (case-sensitive)
        if (strstr(s2_copy, token) != NULL) {
            match_count++;
        }
        token = strtok(NULL, " ");
    }

    free(s1_copy);
    free(s2_copy);
    return match_count;
}

// Revised partial_ratio function to always check string1 against string2
int partial_ratio(const char *s1, const char *s2) {
    // Validate strings
    if (!validate_string(s1) || !validate_string(s2)) return 0;

    // Check if string1 is a direct substring of string2 (case-sensitive)
    if (strstr(s2, s1)) {
        return 100;
    }

    // Determine if the strings contain spaces (treat as sentences) or not (treat as sequences)
    int s1_contains_space = (strchr(s1, ' ') != NULL);
    int s2_contains_space = (strchr(s2, ' ') != NULL);

    // If neither string contains spaces, check for cyclic rotation (character-level)
    if (!s1_contains_space && !s2_contains_space) {
        if (is_cyclic_rotation(s1, s2)) {
            return 100;
        } else {
            // If not a cyclic rotation, fall back to LCS for character sequences
            int lcs_len = lcs_length(s1, s2);
            return (int)((100.0 * lcs_len) / strlen(s1));
        }
    } else {
        // If both contain spaces, use word-level matching (case-sensitive)
        int matching_words = count_reordered_matching_words(s1, s2);
        int total_words = count_reordered_matching_words(s1, s1); // Total words in string1

        // Calculate the ratio based on word count
        if (total_words > 0 && matching_words > 0) {
            // Calculate score based on the proportion of matching words
            int word_score = (int)((100.0 * matching_words) / total_words);
            // If all words match but are reordered, calculate a higher partial ratio
            if (matching_words == total_words) {
                int lcs_len = lcs_length(s1, s2);
                int adjusted_score = (int)((100.0 * lcs_len) / strlen(s1));
                return (word_score > adjusted_score) ? word_score : adjusted_score;
            } else {
                return word_score;
            }
        }
    }

    // Fallback to character-level LCS if no direct match criteria met
    int lcs_len = lcs_length(s1, s2);
    return (int)((100.0 * lcs_len) / strlen(s1));
}


// below commented checks dynamics if str1 is shorter it is checked against str2 or vice verse
/*
//helper function for partial_ratio
int lcs_length(const char *s1, const char *s2) {
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);

    // Create a 2D array to store LCS lengths
    int **lcs_table = (int **)malloc((len1 + 1) * sizeof(int *));
    for (size_t i = 0; i <= len1; i++) {
        lcs_table[i] = (int *)malloc((len2 + 1) * sizeof(int));
    }

    // Initialize the table
    for (size_t i = 0; i <= len1; i++) {
        for (size_t j = 0; j <= len2; j++) {
            if (i == 0 || j == 0) {
                lcs_table[i][j] = 0;
            } else if (s1[i - 1] == s2[j - 1]) {
                lcs_table[i][j] = lcs_table[i - 1][j - 1] + 1;
            } else {
                lcs_table[i][j] = (lcs_table[i - 1][j] > lcs_table[i][j - 1]) ? lcs_table[i - 1][j] : lcs_table[i][j - 1];
            }
        }
    }

    int lcs_len = lcs_table[len1][len2];

    // Free memory
    for (size_t i = 0; i <= len1; i++) {
        free(lcs_table[i]);
    }
    free(lcs_table);

    return lcs_len;
}

int is_cyclic_rotation(const char *str1, const char *str2) {
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);

    // If lengths are not equal, it cannot be a cyclic rotation
    if (len1 != len2) return 0;

    // Create a concatenated version of str1 (str1 + str1)
    char *concatenated = (char *)malloc(2 * len1 + 1);
    strcpy(concatenated, str1);
    strcat(concatenated, str1);

    // Check if str2 is a substring of the concatenated version
    int result = (strstr(concatenated, str2) != NULL);

    free(concatenated);
    return result;
}

// Helper function to count matching words (case-sensitive, reordered)
int count_reordered_matching_words(const char *s1, const char *s2) {
    char *s1_copy = strdup(s1);
    char *s2_copy = strdup(s2);
    int match_count = 0;

    char *token = strtok(s1_copy, " ");
    while (token != NULL) {
        // Check if the word exists in the second string (case-sensitive)
        if (strstr(s2_copy, token) != NULL) {
            match_count++;
        }
        token = strtok(NULL, " ");
    }

    free(s1_copy);
    free(s2_copy);
    return match_count;
}

// Revised partial_ratio function (maintaining original functionality)
int partial_ratio(const char *s1, const char *s2) {
    // Validate strings
    if (!validate_string(s1) || !validate_string(s2)) return 0;

    // Check if one string is a direct substring of the other (case-sensitive)
    if (strstr(s1, s2) || strstr(s2, s1)) {
        return 100;
    }

    // Maintain the original functionality: determine if the strings contain spaces
    int s1_contains_space = (strchr(s1, ' ') != NULL);
    int s2_contains_space = (strchr(s2, ' ') != NULL);

    // If neither string contains spaces, check for cyclic rotation (character-level)
    if (!s1_contains_space && !s2_contains_space) {
        if (is_cyclic_rotation(s1, s2)) {
            return 100;
        } else {
            // If not a cyclic rotation, fall back to LCS for character sequences
            int lcs_len = lcs_length(s1, s2);
            return (int)((100.0 * lcs_len) / strlen(s1));
        }
    } else {
        // If both contain spaces, use word-level matching (case-sensitive)
        const char *shorter = strlen(s1) <= strlen(s2) ? s1 : s2;
        const char *longer = strlen(s1) > strlen(s2) ? s1 : s2;

        int matching_words = count_reordered_matching_words(shorter, longer);
        int total_words = count_reordered_matching_words(shorter, shorter); // Total words in the shorter string

        // Calculate the ratio based on word count
        if (total_words > 0 && matching_words > 0) {
            // Calculate score based on the proportion of matching words
            int word_score = (int)((100.0 * matching_words) / total_words);
            // If all words match but are reordered, calculate a higher partial ratio
            if (matching_words == total_words) {
                int lcs_len = lcs_length(s1, s2);
                int adjusted_score = (int)((100.0 * lcs_len) / strlen(s1));
                return (word_score > adjusted_score) ? word_score : adjusted_score;
            } else {
                return word_score;
            }
        }
    }

    // Fallback to character-level LCS if no direct match criteria met
    int lcs_len = lcs_length(s1, s2);
    return (int)((100.0 * lcs_len) / strlen(s1));
}*/


// Advanced Scoring Functions

char* process_and_sort(const char *s, int force_ascii, int use_full_process) {
    // Make a copy of the input string to avoid modifying the original
    char *s_copy = strdup(s);
    char *processed_str = use_full_process ? full_process(s_copy, force_ascii) : strdup(s_copy);
    free(s_copy);

    char *tokens = strtok(processed_str, " ");
    char **sorted_tokens = NULL;
    size_t num_tokens = 0;

    // Collect tokens
    while (tokens) {
        sorted_tokens = realloc(sorted_tokens, sizeof(char*) * (num_tokens + 1));
        sorted_tokens[num_tokens] = strdup(tokens);
        num_tokens++;
        tokens = strtok(NULL, " ");
    }

    // Sort tokens
    qsort(sorted_tokens, num_tokens, sizeof(char*), (int (*)(const void *, const void *)) strcmp);

    // Reconstruct sorted string
    char *sorted_string = malloc(strlen(processed_str) + 1);
    sorted_string[0] = '\0';
    for (size_t i = 0; i < num_tokens; i++) {
        strcat(sorted_string, sorted_tokens[i]);
        if (i < num_tokens - 1) strcat(sorted_string, " ");
        free(sorted_tokens[i]);
    }

    free(sorted_tokens);
    free(processed_str);
    return sorted_string;
}

int token_sort_ratio(const char *s1, const char *s2, int force_ascii, int use_full_process) {
    char *sorted1 = process_and_sort(s1, force_ascii, use_full_process);
    char *sorted2 = process_and_sort(s2, force_ascii, use_full_process);

    int score = ratio(sorted1, sorted2);

    free(sorted1);
    free(sorted2);
    return score;
}

int partial_token_sort_ratio(const char *s1, const char *s2, int force_ascii, int use_full_process) {
    char *sorted1 = process_and_sort(s1, force_ascii, use_full_process);
    char *sorted2 = process_and_sort(s2, force_ascii, use_full_process);

    int score = partial_ratio(sorted1, sorted2);

    free(sorted1);
    free(sorted2);
    return score;
}

// Combination API

int QRatio(const char *s1, const char *s2, int force_ascii, int use_full_process) {
    char *s1_copy = strdup(s1);
    char *s2_copy = strdup(s2);
    
    char *p1 = use_full_process ? full_process(s1_copy, force_ascii) : strdup(s1_copy);
    char *p2 = use_full_process ? full_process(s2_copy, force_ascii) : strdup(s2_copy);
    
    free(s1_copy);
    free(s2_copy);

    if (!validate_string(p1) || !validate_string(p2)) {
        free(p1);
        free(p2);
        return 0;
    }

    int result = ratio(p1, p2);
    free(p1);
    free(p2);
    return result;
}

int UQRatio(const char *s1, const char *s2, int use_full_process) {
    return QRatio(s1, s2, 0, use_full_process);
}

int WRatio(const char *s1, const char *s2, int force_ascii, int use_full_process) {
    char *s1_copy = strdup(s1);
    char *s2_copy = strdup(s2);

    char *p1 = use_full_process ? full_process(s1_copy, force_ascii) : strdup(s1_copy);
    char *p2 = use_full_process ? full_process(s2_copy, force_ascii) : strdup(s2_copy);

    free(s1_copy);
    free(s2_copy);

    if (!validate_string(p1) || !validate_string(p2)) {
        free(p1);
        free(p2);
        return 0;
    }

    int base = ratio(p1, p2);
    double len_ratio = (double)max(strlen(p1), strlen(p2)) / min(strlen(p1), strlen(p2));

    int partial = 0;
    double partial_scale = 0.9;
    if (len_ratio > 1.5) {
        partial = partial_ratio(p1, p2) * partial_scale;
    }

    int result = intr(max(base, partial));
    free(p1);
    free(p2);
    return result;
}

int UWRatio(const char *s1, const char *s2, int use_full_process) {
    return WRatio(s1, s2, 0, use_full_process);
}
