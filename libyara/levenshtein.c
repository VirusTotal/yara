/*
 * This file has been altered to better fit fuzzywuzzy.
 * To se all changes done, please diff this file with
 * <https://github.com/Tmplt/python-Levenshtein/blob/master/Levenshtein.c>
 *
 * Summary:
 *   - stripped all python-related code and data types;
 *   - fixed some spelling errors.
 */

/*
 * Levenshtein.c
 * @(#) $Id: Levenshtein.c,v 1.41 2005/01/13 20:05:36 yeti Exp $
 * Python extension computing Levenshtein distances, string similarities,
 * median strings and other goodies.
 *
 * Copyright (C) 2002-2003 David Necas (Yeti) <yeti@physics.muni.cz>.
 *
 * The Taus113 random generator:
 * Copyright (C) 2002 Atakan Gurkan
 * Copyright (C) 1996, 1997, 1998, 1999, 2000 James Theiler, Brian Gough
 * (see below for more)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 **/

/**
 * TODO:
 *
 * - Implement weighted string averaging, see:
 *   H. Bunke et. al.: On the Weighted Mean of a Pair of Strings,
 *         Pattern Analysis and Applications 2002, 5(1): 23-30.
 *   X. Jiang et. al.: Dynamic Computations of Generalized Median Strings,
 *         Pattern Analysis and Applications 2002, ???.
 *   The latter also contains an interesting median-search algorithm.
 *
 * - Deal with stray symbols in greedy median() and median_improve().
 *   There are two possibilities:
 *    (i) Remember which strings contain which symbols.  This allows certain
 *        small optimizations when processing them.
 *   (ii) Use some overall heuristics to find symbols which don't worth
 *        trying.  This is very appealing, but hard to do properly
 *        (requires some inequality strong enough to allow practical exclusion
 *        of certain symbols -- at certain positions)
 *
 * - Editops should be an object that only *looks* like a list (which means
 *   it is a list in duck typing) to avoid never-ending conversions from
 *   Python lists to LevEditOp arrays and back
 *
 * - Optimize munkers_blackman(), it's pretty dumb (no memory of visited
 *   columns/rows)
 *
 * - Make it really usable as a C library (needs some wrappers, headers, ...,
 *   and maybe even documentation ;-)
 *
 * - Add interface to various interesting auxiliary results, namely
 *   set and sequence distance (only ratio is exported), the map from
 *   munkers_blackman() itself, ...
 *
 * - Generalizations:
 *   - character weight matrix/function
 *   - arbitrary edit operation costs, decomposable edit operations
 *
 * - Create a test suite
 *
 * - Add more interesting algorithms ;-)
 *
 * Postponed TODO (investigated, and a big `but' was found):
 *
 * - A linear approximate set median algorithm:
 *   P. Indyk: Sublinear time algorithms for metric space problems,
 *         STOC 1999, http://citeseer.nj.nec.com/indyk00sublinear.html.
 *   BUT: The algorithm seems to be advantageous only in the case of very
 *   large sets -- if my estimates are correct (the article itself is quite
 *   `asymptotic'), say 10^5 at least.  On smaller sets either one would get
 *   only an extermely rough median estimate, or the number of distance
 *   computations would be in fact higher than in the dumb O(n^2) algorithm.
 *
 * - Improve setmedian() speed with triangular inequality, see:
 *   Juan, A., E. Vidal: An Algorithm for Fast Median Search,
 *         1997, http://citeseer.nj.nec.com/article/juan97algorithm.html
 *   BUT: It doesn't seem to help much in spaces of high dimension (see the
 *   discussion and graphs in the article itself), a few percents at most,
 *   and strings behave like a space with a very high dimension (locally), so
 *   who knows, it probably wouldn't help much.
 *
 **/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <math.h>
/* for debugging */
#include <stdio.h>

#include <assert.h>
#include "include/yara/levenshtein.h"

/**
 * lev_edit_distance:
 * @len1: The length of @string1.
 * @string1: A sequence of bytes of length @len1, may contain NUL characters.
 * @len2: The length of @string2.
 * @string2: A sequence of bytes of length @len2, may contain NUL characters.
 * @xcost: If nonzero, the replace operation has weight 2, otherwise all
 *         edit operations have equal weights of 1.
 *
 * Computes Levenshtein edit distance of two strings.
 *
 * Returns: The edit distance.
 **/
size_t
lev_edit_distance(size_t len1, const lev_byte *string1,
                  size_t len2, const lev_byte *string2,
                  int xcost)
{
    size_t i;
    size_t *row; /* we only need to keep one row of costs */
    size_t *end;
    size_t half;

    /* strip common prefix */
    while (len1 > 0 && len2 > 0 && *string1 == *string2)
    {
        len1--;
        len2--;
        string1++;
        string2++;
    }

    /* strip common suffix */
    while (len1 > 0 && len2 > 0 && string1[len1 - 1] == string2[len2 - 1])
    {
        len1--;
        len2--;
    }

    /* catch trivial cases */
    if (len1 == 0)
        return len2;
    if (len2 == 0)
        return len1;

    /* make the inner cycle (i.e. string2) the longer one */
    if (len1 > len2)
    {
        size_t nx = len1;
        const lev_byte *sx = string1;
        len1 = len2;
        len2 = nx;
        string1 = string2;
        string2 = sx;
    }
    /* check len1 == 1 separately */
    if (len1 == 1)
    {
        if (xcost)
            return len2 + 1 - 2 * (memchr(string2, *string1, len2) != NULL);
        else
            return len2 - (memchr(string2, *string1, len2) != NULL);
    }
    len1++;
    len2++;
    half = len1 >> 1;

    /* initialize first row */
    row = (size_t *)malloc(len2 * sizeof(size_t));
    if (!row)
        return (size_t)(-1);
    end = row + len2 - 1;
    for (i = 0; i < len2 - (xcost ? 0 : half); i++)
        row[i] = i;

    /* go through the matrix and compute the costs.  yes, this is an extremely
     * obfuscated version, but also extremely memory-conservative and relatively
     * fast.  */
    if (xcost)
    {
        for (i = 1; i < len1; i++)
        {
            size_t *p = row + 1;
            const lev_byte char1 = string1[i - 1];
            const lev_byte *char2p = string2;
            size_t D = i;
            size_t x = i;
            while (p <= end)
            {
                if (char1 == *(char2p++))
                    x = --D;
                else
                    x++;
                D = *p;
                D++;
                if (x > D)
                    x = D;
                *(p++) = x;
            }
        }
    }
    else
    {
        /* in this case we don't have to scan two corner triangles (of size len1/2)
         * in the matrix because no best path can go thought them. note this
         * breaks when len1 == len2 == 2 so the memchr() special case above is
         * necessary */
        row[0] = len1 - half - 1;
        for (i = 1; i < len1; i++)
        {
            size_t *p;
            const lev_byte char1 = string1[i - 1];
            const lev_byte *char2p;
            size_t D, x;
            /* skip the upper triangle */
            if (i >= len1 - half)
            {
                size_t offset = i - (len1 - half);
                size_t c3;

                char2p = string2 + offset;
                p = row + offset;
                c3 = *(p++) + (char1 != *(char2p++));
                x = *p;
                x++;
                D = x;
                if (x > c3)
                    x = c3;
                *(p++) = x;
            }
            else
            {
                p = row + 1;
                char2p = string2;
                D = x = i;
            }
            /* skip the lower triangle */
            if (i <= half + 1)
                end = row + len2 + i - half - 2;
            /* main */
            while (p <= end)
            {
                size_t c3 = --D + (char1 != *(char2p++));
                x++;
                if (x > c3)
                    x = c3;
                D = *p;
                D++;
                if (x > D)
                    x = D;
                *(p++) = x;
            }
            /* lower triangle sentinel */
            if (i <= half)
            {
                size_t c3 = --D + (char1 != *char2p);
                x++;
                if (x > c3)
                    x = c3;
                *p = x;
            }
        }
    }

    i = *end;
    free(row);
    return i;
}

/**
 * editops_from_cost_matrix:
 * @len1: The length of @string1.
 * @string1: A string of length @len1, may contain NUL characters.
 * @o1: The offset where the matrix starts from the start of @string1.
 * @len2: The length of @string2.
 * @string2: A string of length @len2, may contain NUL characters.
 * @o2: The offset where the matrix starts from the start of @string2.
 * @matrix: The cost matrix.
 * @n: Where the number of edit operations should be stored.
 *
 * Reconstructs the optimal edit sequence from the cost matrix @matrix.
 *
 * The matrix is freed.
 *
 * Returns: The optimal edit sequence, as a newly allocated array of
 *          elementary edit operations, it length is stored in @n.
 **/
static LevEditOp *
editops_from_cost_matrix(size_t len1, const lev_byte *string1, size_t off1,
                         size_t len2, const lev_byte *string2, size_t off2,
                         size_t *matrix, size_t *n)
{
    size_t *p;
    size_t i, j, pos;
    LevEditOp *ops;
    int dir = 0;

    pos = *n = matrix[len1 * len2 - 1];
    if (!*n)
    {
        free(matrix);
        return NULL;
    }
    ops = (LevEditOp *)malloc((*n) * sizeof(LevEditOp));
    if (!ops)
    {
        free(matrix);
        *n = (size_t)(-1);
        return NULL;
    }
    i = len1 - 1;
    j = len2 - 1;
    p = matrix + len1 * len2 - 1;
    while (i || j)
    {
        /* prefer contiuning in the same direction */
        if (dir < 0 && j && *p == *(p - 1) + 1)
        {
            pos--;
            ops[pos].type = LEV_EDIT_INSERT;
            ops[pos].spos = i + off1;
            ops[pos].dpos = --j + off2;
            p--;
            continue;
        }
        if (dir > 0 && i && *p == *(p - len2) + 1)
        {
            pos--;
            ops[pos].type = LEV_EDIT_DELETE;
            ops[pos].spos = --i + off1;
            ops[pos].dpos = j + off2;
            p -= len2;
            continue;
        }
        if (i && j && *p == *(p - len2 - 1) && string1[i - 1] == string2[j - 1])
        {
            /* don't be stupid like difflib, don't store LEV_EDIT_KEEP */
            i--;
            j--;
            p -= len2 + 1;
            dir = 0;
            continue;
        }
        if (i && j && *p == *(p - len2 - 1) + 1)
        {
            pos--;
            ops[pos].type = LEV_EDIT_REPLACE;
            ops[pos].spos = --i + off1;
            ops[pos].dpos = --j + off2;
            p -= len2 + 1;
            dir = 0;
            continue;
        }
        /* we cant't turn directly from -1 to 1, in this case it would be better
         * to go diagonally, but check it (dir == 0) */
        if (dir == 0 && j && *p == *(p - 1) + 1)
        {
            pos--;
            ops[pos].type = LEV_EDIT_INSERT;
            ops[pos].spos = i + off1;
            ops[pos].dpos = --j + off2;
            p--;
            dir = -1;
            continue;
        }
        if (dir == 0 && i && *p == *(p - len2) + 1)
        {
            pos--;
            ops[pos].type = LEV_EDIT_DELETE;
            ops[pos].spos = --i + off1;
            ops[pos].dpos = j + off2;
            p -= len2;
            dir = 1;
            continue;
        }
        /* coredump right now, later might be too late ;-) */
        assert("lost in the cost matrix" == NULL);
    }
    free(matrix);

    return ops;
}

/**
 * lev_editops_find:
 * @len1: The length of @string1.
 * @string1: A string of length @len1, may contain NUL characters.
 * @len2: The length of @string2.
 * @string2: A string of length @len2, may contain NUL characters.
 * @n: Where the number of edit operations should be stored.
 *
 * Find an optimal edit sequence from @string1 to @string2.
 *
 * When there's more than one optimal sequence, a one is arbitrarily (though
 * deterministically) chosen.
 *
 * Returns: The optimal edit sequence, as a newly allocated array of
 *          elementary edit operations, it length is stored in @n.
 *          It is normalized, i.e., keep operations are not included.
 **/

LevEditOp *lev_editops_find(size_t len1, const lev_byte *string1, size_t len2, const lev_byte *string2, size_t *n) {
    size_t len1o, len2o;
    size_t i;
    size_t *matrix; /* cost matrix */

    // Strip common prefix
    len1o = 0;
    while (len1 > 0 && len2 > 0 && *string1 == *string2) {
        len1--;
        len2--;
        string1++;
        string2++;
        len1o++;
    }
    len2o = len1o;

    // Strip common suffix
    while (len1 > 0 && len2 > 0 && string1[len1 - 1] == string2[len2 - 1]) {
        len1--;
        len2--;
    }

    len1++;
    len2++;

    // Initialize the cost matrix
    matrix = (size_t *)malloc(len1 * len2 * sizeof(size_t));
    if (!matrix) {
        *n = (size_t)(-1);
        return NULL;
    }

    // Initialize first row and column
    for (i = 0; i < len2; i++) matrix[i] = i;
    for (i = 1; i < len1; i++) matrix[len2 * i] = i;

    // Fill the matrix
    for (i = 1; i < len1; i++) {
        size_t *prev = matrix + (i - 1) * len2;
        size_t *p = matrix + i * len2;
        size_t *end = p + len2 - 1;
        const lev_byte char1 = string1[i - 1];
        const lev_byte *char2p = string2;
        size_t x = i;
        p++;
        while (p <= end) {
            size_t c3 = *(prev++) + (char1 != *(char2p++));
            x++;
            if (x > c3) x = c3;
            c3 = *prev + 1;
            if (x > c3) x = c3;
            *(p++) = x;
        }
    }

    // Find the way back
    LevEditOp *edit_ops = editops_from_cost_matrix(len1, string1, len1o, len2, string2, len2o, matrix, n);
    return edit_ops;
}


/**
 * lev_u_edit_distance:
 * @len1: The length of @string1.
 * @string1: A sequence of Unicode characters of length @len1, may contain NUL
 *           characters.
 * @len2: The length of @string2.
 * @string2: A sequence of Unicode characters of length @len2, may contain NUL
 *           characters.
 * @xcost: If nonzero, the replace operation has weight 2, otherwise all
 *         edit operations have equal weights of 1.
 *
 * Computes Levenshtein edit distance of two Unicode strings.
 *
 * Returns: The edit distance.
 **/
size_t
lev_u_edit_distance(size_t len1, const lev_wchar *string1,
                    size_t len2, const lev_wchar *string2,
                    int xcost)
{
    size_t i;
    size_t *row; /* we only need to keep one row of costs */
    size_t *end;
    size_t half;

    /* strip common prefix */
    while (len1 > 0 && len2 > 0 && *string1 == *string2)
    {
        len1--;
        len2--;
        string1++;
        string2++;
    }

    /* strip common suffix */
    while (len1 > 0 && len2 > 0 && string1[len1 - 1] == string2[len2 - 1])
    {
        len1--;
        len2--;
    }

    /* catch trivial cases */
    if (len1 == 0)
        return len2;
    if (len2 == 0)
        return len1;

    /* make the inner cycle (i.e. string2) the longer one */
    if (len1 > len2)
    {
        size_t nx = len1;
        const lev_wchar *sx = string1;
        len1 = len2;
        len2 = nx;
        string1 = string2;
        string2 = sx;
    }
    /* check len1 == 1 separately */
    if (len1 == 1)
    {
        lev_wchar z = *string1;
        const lev_wchar *p = string2;
        for (i = len2; i; i--)
        {
            if (*(p++) == z)
                return len2 - 1;
        }
        return len2 + (xcost != 0);
    }
    len1++;
    len2++;
    half = len1 >> 1;

    /* initalize first row */
    row = (size_t *)malloc(len2 * sizeof(size_t));
    if (!row)
        return (size_t)(-1);
    end = row + len2 - 1;
    for (i = 0; i < len2 - (xcost ? 0 : half); i++)
        row[i] = i;

    /* go through the matrix and compute the costs.  yes, this is an extremely
     * obfuscated version, but also extremely memory-conservative and relatively
     * fast.  */
    if (xcost)
    {
        for (i = 1; i < len1; i++)
        {
            size_t *p = row + 1;
            const lev_wchar char1 = string1[i - 1];
            const lev_wchar *char2p = string2;
            size_t D = i - 1;
            size_t x = i;
            while (p <= end)
            {
                if (char1 == *(char2p++))
                    x = D;
                else
                    x++;
                D = *p;
                if (x > D + 1)
                    x = D + 1;
                *(p++) = x;
            }
        }
    }
    else
    {
        /* in this case we don't have to scan two corner triangles (of size len1/2)
         * in the matrix because no best path can go throught them. note this
         * breaks when len1 == len2 == 2 so the memchr() special case above is
         * necessary */
        row[0] = len1 - half - 1;
        for (i = 1; i < len1; i++)
        {
            size_t *p;
            const lev_wchar char1 = string1[i - 1];
            const lev_wchar *char2p;
            size_t D, x;
            /* skip the upper triangle */
            if (i >= len1 - half)
            {
                size_t offset = i - (len1 - half);
                size_t c3;

                char2p = string2 + offset;
                p = row + offset;
                c3 = *(p++) + (char1 != *(char2p++));
                x = *p;
                x++;
                D = x;
                if (x > c3)
                    x = c3;
                *(p++) = x;
            }
            else
            {
                p = row + 1;
                char2p = string2;
                D = x = i;
            }
            /* skip the lower triangle */
            if (i <= half + 1)
                end = row + len2 + i - half - 2;
            /* main */
            while (p <= end)
            {
                size_t c3 = --D + (char1 != *(char2p++));
                x++;
                if (x > c3)
                    x = c3;
                D = *p;
                D++;
                if (x > D)
                    x = D;
                *(p++) = x;
            }
            /* lower triangle sentinel */
            if (i <= half)
            {
                size_t c3 = --D + (char1 != *char2p);
                x++;
                if (x > c3)
                    x = c3;
                *p = x;
            }
        }
    }

    i = *end;
    free(row);
    return i;
}

/**
 * lev_editops_to_opcodes:
 * @n: The size of @ops.
 * @ops: An array of elementary edit operations.
 * @nb: Where the number of difflib block operation codes should be stored.
 * @len1: The length of the source string.
 * @len2: The length of the destination string.
 *
 * Converts elementary edit operations to difflib block operation codes.
 *
 * Note the string lengths are necessary since difflib doesn't allow omitting
 * keep operations.
 *
 * Returns: The converted block operation codes, as a newly allocated array;
 *          its length is stored in @nb.
 **/

LevOpCode *lev_editops_to_opcodes(size_t n, const LevEditOp *ops, size_t *nb, size_t len1, size_t len2) {
    size_t nbl = 0;
    const LevEditOp *o = ops;
    size_t spos = 0, dpos = 0;
    LevOpCode *bops = NULL;
    LevOpCode *b = NULL;

    // Calculate the number of blocks needed
    for (size_t i = 0; i < n; i++, o++) {
        if (spos < o->spos || dpos < o->dpos) {
            nbl++;
        }
        nbl++;
        spos = o->spos + 1;
        dpos = o->dpos + 1;
    }

    // Allocate memory for opcodes
    bops = (LevOpCode *)malloc(nbl * sizeof(LevOpCode));
    if (!bops) {
        *nb = 0; // Set nb to 0 if allocation fails
        return NULL;
    }

    b = bops;
    o = ops;
    spos = dpos = 0;

    // Convert edit operations to opcodes
    for (size_t i = 0; i < n; i++, o++) {
        // Handle "keep" operations if there's a gap between edit operations
        if (spos < o->spos || dpos < o->dpos) {
            b->type = LEV_EDIT_KEEP;
            b->sbeg = spos;
            b->send = o->spos;
            b->dbeg = dpos;
            b->dend = o->dpos;
            b++;
        }

        // Handle the actual edit operation
        b->type = o->type;
        b->sbeg = o->spos;
        b->send = o->spos + 1;
        b->dbeg = o->dpos;
        b->dend = o->dpos + 1;
        b++;

        spos = o->spos + 1;
        dpos = o->dpos + 1;
    }

    // Handle any remaining "keep" operations if there are characters left
    if (spos < len1 || dpos < len2) {
        b->type = LEV_EDIT_KEEP;
        b->sbeg = spos;
        b->send = len1;
        b->dbeg = dpos;
        b->dend = len2;
        b++;
    }

    *nb = b - bops;  // Update nb to reflect the number of opcodes generated
    return bops;
}




/**
 * lev_opcodes_matching_blocks:
 * @len1: The length of the source string.
 * @len2: The length of the destination string.
 * @nb: The size of @bops.
 * @bops: An array of difflib block edit operation codes.
 * @nmblocks: Where the number of matching block should be stored.
 *
 * Computes the matching block corresponding to an optimal edit @bops.
 *
 * Returns: The matching blocks as a newly allocated array, it length is
 *          stored in @nmblocks.
 **/

LevMatchingBlock *lev_opcodes_matching_blocks(size_t len1, size_t len2, size_t nb, const LevOpCode *bops, size_t *nmblocks) {

    if (bops == NULL || nb == 0) {
        printf("No opcodes available to process.\n");
        *nmblocks = 0;
        return NULL;
    }

    size_t nmb = 0;
    const LevOpCode *b = bops;

    // First, count the number of matching blocks
    for (size_t i = 0; i < nb; i++, b++) {
        if (b->type == LEV_EDIT_KEEP) {
            nmb++;
        }
    }

    if (nmb == 0) {
        *nmblocks = 0;
        return NULL;
    }

    // Allocate memory for matching blocks
    LevMatchingBlock *mblocks = (LevMatchingBlock *)malloc(nmb * sizeof(LevMatchingBlock));
    if (!mblocks) {
        *nmblocks = (size_t)(-1);
        return NULL;
    }

    // Populate the matching blocks
    LevMatchingBlock *mb = mblocks;
    b = bops;
    for (size_t i = 0; i < nb; i++, b++) {
        if (b->type == LEV_EDIT_KEEP) {
            mb->spos = b->sbeg;
            mb->dpos = b->dbeg;
            mb->len = b->send - b->sbeg;
            mb++;
        }
    }

    *nmblocks = nmb;
    return mblocks;
}

/**
 * lev_editops_matching_blocks:
 * @len1: The length of the source string.
 * @len2: The length of the destination string.
 * @n: The size of @ops.
 * @ops: An array of elementary edit operations.
 * @nmblocks: Where the number of matching block should be stored.
 *
 * Computes the matching block corresponding to an optimal edit @ops.
 *
 * Returns: The matching blocks as a newly allocated array, it length is
 *          stored in @nmblocks.
 **/
LevMatchingBlock *
lev_editops_matching_blocks(size_t len1,
                            size_t len2,
                            size_t n,
                            const LevEditOp *ops,
                            size_t *nmblocks)
{
    size_t nmb, i, spos, dpos;
    LevEditType type;
    const LevEditOp *o;
    LevMatchingBlock *mblocks, *mb;

    /* compute the number of matching blocks */
    nmb = 0;
    o = ops;
    spos = dpos = 0;
    type = LEV_EDIT_KEEP;
    for (i = n; i;)
    {
        /* simply pretend there are no keep blocks */
        while (o->type == LEV_EDIT_KEEP && --i)
            o++;
        if (!i)
            break;
        if (spos < o->spos || dpos < o->dpos)
        {
            nmb++;
            spos = o->spos;
            dpos = o->dpos;
        }
        type = o->type;
        switch (type)
        {
        case LEV_EDIT_REPLACE:
            do
            {
                spos++;
                dpos++;
                i--;
                o++;
            } while (i && o->type == type && spos == o->spos && dpos == o->dpos);
            break;

        case LEV_EDIT_DELETE:
            do
            {
                spos++;
                i--;
                o++;
            } while (i && o->type == type && spos == o->spos && dpos == o->dpos);
            break;

        case LEV_EDIT_INSERT:
            do
            {
                dpos++;
                i--;
                o++;
            } while (i && o->type == type && spos == o->spos && dpos == o->dpos);
            break;

        default:
            break;
        }
    }
    if (spos < len1 || dpos < len2)
        nmb++;

    /* fill the info */
    mb = mblocks = (LevMatchingBlock *)malloc(nmb * sizeof(LevOpCode));
    if (!mblocks)
    {
        *nmblocks = (size_t)(-1);
        return NULL;
    }
    o = ops;
    spos = dpos = 0;
    type = LEV_EDIT_KEEP;
    for (i = n; i;)
    {
        /* simply pretend there are no keep blocks */
        while (o->type == LEV_EDIT_KEEP && --i)
            o++;
        if (!i)
            break;
        if (spos < o->spos || dpos < o->dpos)
        {
            mb->spos = spos;
            mb->dpos = dpos;
            mb->len = o->spos - spos;
            spos = o->spos;
            dpos = o->dpos;
            mb++;
        }
        type = o->type;
        switch (type)
        {
        case LEV_EDIT_REPLACE:
            do
            {
                spos++;
                dpos++;
                i--;
                o++;
            } while (i && o->type == type && spos == o->spos && dpos == o->dpos);
            break;

        case LEV_EDIT_DELETE:
            do
            {
                spos++;
                i--;
                o++;
            } while (i && o->type == type && spos == o->spos && dpos == o->dpos);
            break;

        case LEV_EDIT_INSERT:
            do
            {
                dpos++;
                i--;
                o++;
            } while (i && o->type == type && spos == o->spos && dpos == o->dpos);
            break;

        default:
            break;
        }
    }
    if (spos < len1 || dpos < len2)
    {
        assert(len1 - spos == len2 - dpos);
        mb->spos = spos;
        mb->dpos = dpos;
        mb->len = len1 - spos;
        mb++;
    }
    assert((size_t)(mb - mblocks) == nmb);

    *nmblocks = nmb;
    return mblocks;
}
