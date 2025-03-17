#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/yara/StringMatcher.h"
#include "include/yara/levenshtein.h"

// Function to reset the cache
void reset_cache(StringMatcher *matcher) {
    matcher->ratio = 0;
    matcher->distance = 0;
    matcher->opcodes = NULL;
    matcher->editops = NULL;
    matcher->matching_blocks = NULL;
}

// Function to initialize the StringMatcher object
void init_string_matcher(StringMatcher *matcher, const char *seq1, const char *seq2) {
    matcher->str1 = strdup(seq1);
    matcher->str2 = strdup(seq2);
    reset_cache(matcher);
}

// Function to set the sequences
void set_seqs(StringMatcher *matcher, const char *seq1, const char *seq2) {
    free(matcher->str1);
    free(matcher->str2);
    matcher->str1 = strdup(seq1);
    matcher->str2 = strdup(seq2);
    reset_cache(matcher);
}

// Function to set sequence 1
void set_seq1(StringMatcher *matcher, const char *seq1) {
    free(matcher->str1);
    matcher->str1 = strdup(seq1);
    reset_cache(matcher);
}

// Function to set sequence 2
void set_seq2(StringMatcher *matcher, const char *seq2) {
    free(matcher->str2);
    matcher->str2 = strdup(seq2);
    reset_cache(matcher);
}

// Function to get the opcodes
LevOpCode* get_opcodes(StringMatcher *matcher, size_t *nblocks) {
    if (!matcher->opcodes) {
        if (matcher->editops) {
            size_t n = *nblocks; // The number of edit operations should be passed as the first argument
            matcher->opcodes = lev_editops_to_opcodes(n, matcher->editops, nblocks, strlen(matcher->str1), strlen(matcher->str2));
        } else {
            matcher->editops = lev_editops_find(strlen(matcher->str1), (const lev_byte *)matcher->str1,
                                                strlen(matcher->str2), (const lev_byte *)matcher->str2, nblocks);
            size_t n = *nblocks; // Update nblocks after finding edit operations
            matcher->opcodes = lev_editops_to_opcodes(n, matcher->editops, nblocks, strlen(matcher->str1), strlen(matcher->str2));
        }
    }
    return matcher->opcodes;
}

// Function to get edit operations
LevEditOp* get_editops(StringMatcher *matcher, size_t *nops) {
    if (!matcher->editops) {
        matcher->editops = lev_editops_find(strlen(matcher->str1), (const lev_byte *)matcher->str1,
                                            strlen(matcher->str2), (const lev_byte *)matcher->str2, nops);
    }
    return matcher->editops;
}

/*
// Function to get matching blocks
LevMatchingBlock* get_matching_blocks(StringMatcher *matcher, size_t *nblocks) {
    if (!matcher->matching_blocks) {
        size_t nb = *nblocks; // Number of block operations
        matcher->matching_blocks = lev_opcodes_matching_blocks(strlen(matcher->str1), strlen(matcher->str2), nb, matcher->opcodes, nblocks);
    }
    return matcher->matching_blocks;
} */

/*
LevMatchingBlock* get_matching_blocks(StringMatcher *matcher, size_t *nblocks) {
    if (!matcher->matching_blocks) {
        // Ensure opcodes are calculated before using them to get matching blocks
        if (!matcher->opcodes) {
            size_t n = 0;  // Temporary variable for number of edit operations
            get_opcodes(matcher, &n);
        }
        
        // Now use the opcodes to find matching blocks
        size_t nb = *nblocks; // Initialize nb properly if necessary
        matcher->matching_blocks = lev_opcodes_matching_blocks(strlen(matcher->str1), strlen(matcher->str2), nb, matcher->opcodes, nblocks);
    }
    return matcher->matching_blocks;
} */

LevMatchingBlock* get_matching_blocks(StringMatcher *matcher, size_t *nblocks) {
    if (!matcher->matching_blocks) {
        // Ensure opcodes are calculated before using them to get matching blocks
        if (!matcher->opcodes) {
            size_t n = 0;  // Temporary variable for number of edit operations
            LevEditOp* ops = get_editops(matcher, &n);

            if (ops == NULL || n == 0) {
                return NULL;
            }

            matcher->opcodes = lev_editops_to_opcodes(n, matcher->editops, &n, strlen(matcher->str1), strlen(matcher->str2));
            if (matcher->opcodes == NULL) {
                return NULL;
            }
        }

        // Now use the opcodes to find matching blocks
        size_t nb = 0;
        matcher->matching_blocks = lev_opcodes_matching_blocks(strlen(matcher->str1), strlen(matcher->str2), nb, matcher->opcodes, nblocks);
        
        if (matcher->matching_blocks == NULL) {
            return NULL;
        }

    }
    return matcher->matching_blocks;
}



// Function to calculate the ratio
double calculate_ratio(StringMatcher *matcher) {
    if (!matcher->ratio) {
        matcher->distance = lev_edit_distance(strlen(matcher->str1), (const lev_byte *)matcher->str1, strlen(matcher->str2), (const lev_byte *)matcher->str2, 0);
        matcher->ratio = 1.0 - ((double)matcher->distance / (double)(strlen(matcher->str1) + strlen(matcher->str2)));
    }
    return matcher->ratio;
}

// Function to calculate quick ratio (identical to ratio in this context)
double quick_ratio(StringMatcher *matcher) {
    return calculate_ratio(matcher);
}

// Function to calculate the real quick ratio
double real_quick_ratio(StringMatcher *matcher) {
    size_t len1 = strlen(matcher->str1);
    size_t len2 = strlen(matcher->str2);
    return 2.0 * ((double)(len1 < len2 ? len1 : len2) / (len1 + len2));
}

// Function to calculate the distance
size_t calculate_distance(StringMatcher *matcher) {
    if (!matcher->distance) {
        matcher->distance = lev_edit_distance(strlen(matcher->str1), (const lev_byte *)matcher->str1,
                                              strlen(matcher->str2), (const lev_byte *)matcher->str2, 0);
    }
    return matcher->distance;
}

// Function to clean up memory used by the StringMatcher object
void destroy_string_matcher(StringMatcher *matcher) {
    free(matcher->str1);
    free(matcher->str2);
    if (matcher->opcodes) free(matcher->opcodes);
    if (matcher->editops) free(matcher->editops);
    if (matcher->matching_blocks) free(matcher->matching_blocks);
}
