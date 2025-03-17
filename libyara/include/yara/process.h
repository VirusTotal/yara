#ifndef PROCESS_H
#define PROCESS_H

#include <stddef.h>

// Default scorer and processor
#define DEFAULT_SCORER WRatio
#define DEFAULT_PROCESSOR full_process

// Structure for storing match results
typedef struct {
    char *match;
    int score;
    char *key; // Optional, used if choices is a dictionary-like structure
} MatchResult;

// Function declarations
char* no_process(const char *s);

MatchResult* extractWithoutOrder(const char *query, const char **choices, size_t choice_count, int *result_count,
                                 char* (*processor)(const char*),
                                 int (*scorer)(const char*, const char*),
                                 int score_cutoff);

MatchResult* extract(const char *query, const char **choices, size_t choice_count, int limit,
                     char* (*processor)(const char*),
                     int (*scorer)(const char*, const char*));

MatchResult extractOne(const char *query, const char **choices, size_t choice_count,
                       char* (*processor)(const char*),
                       int (*scorer)(const char*, const char*),
                       int score_cutoff);

char** dedupe(char **contains_dupes, size_t count, int threshold, int (*scorer)(const char*, const char*));

#endif // PROCESS_H
