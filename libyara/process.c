#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/yara/fuzz.h"
#include "include/yara/utils_partial.h"
#include "include/yara/process.h"

// Helper function for the processing step when no processing is needed
char* no_process(const char *s) {
    return strdup(s);
}

// Comparison function for qsort to sort by score in descending order
int compare_match_results(const void *a, const void *b) {
    MatchResult *resultA = (MatchResult *)a;
    MatchResult *resultB = (MatchResult *)b;
    return resultB->score - resultA->score;
}

// Comparison function for qsort to sort matches by length and alphabetically
int compare_matches(const void *a, const void *b) {
    MatchResult *resultA = (MatchResult *)a;
    MatchResult *resultB = (MatchResult *)b;
    int len_diff = strlen(resultB->match) - strlen(resultA->match);
    return len_diff ? len_diff : strcmp(resultA->match, resultB->match);
}

// Function to extract matches without order
MatchResult* extractWithoutOrder(const char *query, const char **choices, size_t choice_count, int *result_count,
                                 char* (*processor)(const char*),
                                 int (*scorer)(const char*, const char*),
                                 int score_cutoff) {

    MatchResult *results = (MatchResult*) malloc(sizeof(MatchResult) * choice_count);
    *result_count = 0;

    // Run the processor on the input query
    char *processed_query = processor(query);
    if (strlen(processed_query) == 0) {
        fprintf(stderr, "Warning: Processed query is empty. All comparisons will have score 0.\n");
        free(processed_query);
        return NULL;
    }

    // Iterate over choices
    for (size_t i = 0; i < choice_count; i++) {
        char *processed_choice = processor(choices[i]);
        int score = scorer(processed_query, processed_choice);

        if (score >= score_cutoff) {
            results[*result_count].match = strdup(choices[i]);
            results[*result_count].score = score;
            results[*result_count].key = NULL; // If using a key-value pair, set this accordingly
            (*result_count)++;
        }

        free(processed_choice);
    }

    free(processed_query);
    return results;
}

// Function to extract the best matches
MatchResult* extract(const char *query, const char **choices, size_t choice_count, int limit,
                     char* (*processor)(const char*),
                     int (*scorer)(const char*, const char*)) {

    int result_count = 0;
    MatchResult *all_results = extractWithoutOrder(query, choices, choice_count, &result_count, processor, scorer, 0);

    if (result_count == 0) {
        return NULL;
    }

    // Sort results by score (descending order) and return top `limit` results
    qsort(all_results, result_count, sizeof(MatchResult), compare_match_results);

    if (limit < result_count) {
        result_count = limit;
    }

    return all_results;
}

// Function to find the best match (extract one)
MatchResult extractOne(const char *query, const char **choices, size_t choice_count,
                       char* (*processor)(const char*),
                       int (*scorer)(const char*, const char*),
                       int score_cutoff) {

    int result_count = 0;
    MatchResult *results = extractWithoutOrder(query, choices, choice_count, &result_count, processor, scorer, score_cutoff);

    if (result_count == 0) {
        MatchResult empty_result = {NULL, 0, NULL};
        return empty_result;
    }

    MatchResult best_match = results[0];
    for (int i = 1; i < result_count; i++) {
        if (results[i].score > best_match.score) {
            best_match = results[i];
        }
    }

    free(results);
    return best_match;
}

// Function to deduplicate based on fuzzy matching
char** dedupe(char **contains_dupes, size_t count, int threshold, int (*scorer)(const char*, const char*)) {
    char **extractor = (char**)malloc(sizeof(char*) * count);
    size_t extractor_count = 0;

    for (size_t i = 0; i < count; i++) {
        MatchResult *matches = extract(contains_dupes[i], (const char**)contains_dupes, count, count, no_process, scorer);

        if (matches == NULL) {
            extractor[extractor_count++] = strdup(contains_dupes[i]);
        } else {
            int match_count = 0;
            for (size_t j = 0; j < count; j++) {
                if (matches[j].score > threshold) {
                    match_count++;
                }
            }

            if (match_count == 1) {
                extractor[extractor_count++] = strdup(matches[0].match);
            } else {
                // Sort matches alphabetically and by length
                qsort(matches, match_count, sizeof(MatchResult), compare_matches);

                extractor[extractor_count++] = strdup(matches[0].match);
            }

            free(matches);
        }
    }

    // Remove duplicates
    char **unique_extractor = (char**)malloc(sizeof(char*) * extractor_count);
    size_t unique_count = 0;
    for (size_t i = 0; i < extractor_count; i++) {
        int found = 0;
        for (size_t j = 0; j < unique_count; j++) {
            if (strcmp(unique_extractor[j], extractor[i]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            unique_extractor[unique_count++] = strdup(extractor[i]);
        }
    }

    free(extractor);
    return unique_extractor;
}
