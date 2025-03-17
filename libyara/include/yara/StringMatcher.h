#ifndef STRINGMATCHER_H
#define STRINGMATCHER_H

#include <stddef.h>  // For size_t
#include "levenshtein.h"  // Include the header where LevOpCode, LevEditOp, and LevMatchingBlock are defined

// Define the StringMatcher structure
typedef struct {
    char *str1;
    char *str2;
    double ratio;
    size_t distance;
    LevOpCode *opcodes;
    LevEditOp *editops;
    LevMatchingBlock *matching_blocks;
} StringMatcher;

// Function declarations
void init_string_matcher(StringMatcher *matcher, const char *seq1, const char *seq2);
void set_seqs(StringMatcher *matcher, const char *seq1, const char *seq2);
void set_seq1(StringMatcher *matcher, const char *seq1);
void set_seq2(StringMatcher *matcher, const char *seq2);
LevOpCode* get_opcodes(StringMatcher *matcher, size_t *nblocks);
LevEditOp* get_editops(StringMatcher *matcher, size_t *nops);
LevMatchingBlock* get_matching_blocks(StringMatcher *matcher, size_t *nblocks);
double calculate_ratio(StringMatcher *matcher);
double quick_ratio(StringMatcher *matcher);
double real_quick_ratio(StringMatcher *matcher);
size_t calculate_distance(StringMatcher *matcher);
void destroy_string_matcher(StringMatcher *matcher);

#endif // STRINGMATCHER_H
