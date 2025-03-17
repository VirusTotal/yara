/*
 * This file has been altered to better fit fuzzywuzzy.
 * To se all changes done, please diff this file with
 * <https://github.com/Tmplt/python-Levenshtein/blob/master/Levenshtein.c>
 *
 * Summary:
 *   - stripped all python-related code and data types;
 */

/* @(#) $Id: Levenshtein.h,v 1.22 2005/01/13 20:02:56 yeti Exp $ */
#ifndef LEVENSHTEIN_H
#define LEVENSHTEIN_H

#ifndef size_t
#include <stdlib.h>
#endif

/* A bit dirty. */
#ifndef _LEV_STATIC_PY
#define _LEV_STATIC_PY /* */
#endif

/* In C, this is just wchar_t and unsigned char, in Python, lev_wchar can
 * be anything.  If you really want to cheat, define wchar_t to any integer
 * type you like before including Levenshtein.h and recompile it. */
#ifndef lev_wchar
#ifndef wchar_t
#include <wchar.h>
#endif
#define lev_wchar wchar_t
#endif
typedef char lev_byte;

/* Edit opration type
 * DON'T CHANGE! used ad arrays indices and the bits are occasionally used
 * as flags */
typedef enum
{
    LEV_EDIT_KEEP = 0,
    LEV_EDIT_REPLACE = 1,
    LEV_EDIT_INSERT = 2,
    LEV_EDIT_DELETE = 3,
    LEV_EDIT_LAST /* sometimes returned when an error occurs */
} LevEditType;

/* Error codes returned by editop check functions */
typedef enum
{
    LEV_EDIT_ERR_OK = 0,
    LEV_EDIT_ERR_TYPE,  /* nonexistent edit type */
    LEV_EDIT_ERR_OUT,   /* edit out of string bounds */
    LEV_EDIT_ERR_ORDER, /* ops are not ordered */
    LEV_EDIT_ERR_BLOCK, /* inconsistent block boundaries (block ops) */
    LEV_EDIT_ERR_SPAN,  /* sequence is not a full transformation (block ops) */
    LEV_EDIT_ERR_LAST
} LevEditOpError;

/* string averaging method (UNUSED yet) */
typedef enum
{
    LEV_AVG_HEAD = 0, /* take operations from the head */
    LEV_AVG_TAIL,     /* take operations from the tail */
    LEV_AVG_SPREAD,   /* take a equidistantly distributed subset */
    LEV_AVG_BLOCK,    /* take a random continuous block */
    LEV_AVG_RANDOM,   /* take a random subset */
    LEV_AVG_LAST
} LevAveragingType;

/* Edit operation (atomic).
 * This is the `native' atomic edit operation.  It differs from the difflib
 * one's because it represents a change of one character, not a block.  And
 * we usually don't care about LEV_EDIT_KEEP, though the functions can handle
 * them.  The positions are interpreted as at the left edge of a character.
 */
typedef struct
{
    LevEditType type; /* editing operation type */
    size_t spos;      /* source block position */
    size_t dpos;      /* destination position */
} LevEditOp;

/* Edit operation (difflib-compatible).
 * This is not `native', but conversion functions exist.  These fields exactly
 * correspond to the codeops() tuples fields (and this method is also the
 * source of the silly OpCode name).  Sequences must span over complete
 * strings, subsequences are simply edit sequences with more (or larger)
 * LEV_EDIT_KEEP blocks.
 */
typedef struct
{
    LevEditType type;  /* editing operation type */
    size_t sbeg, send; /* source block begin, end */
    size_t dbeg, dend; /* destination block begin, end */
} LevOpCode;

/* Matching block (difflib-compatible). */
typedef struct
{
    size_t spos;
    size_t dpos;
    size_t len;
} LevMatchingBlock;

size_t
lev_edit_distance(size_t len1,
                  const lev_byte *string1,
                  size_t len2,
                  const lev_byte *string2,
                  int xcost);

size_t
lev_u_edit_distance(size_t len1,
                    const lev_wchar *string1,
                    size_t len2,
                    const lev_wchar *string2,
                    int xcost);

LevEditOp *
lev_editops_find(size_t len1,
                 const lev_byte *string1,
                 size_t len2,
                 const lev_byte *string2,
                 size_t *n);

LevOpCode *
lev_editops_to_opcodes(size_t n,
                       const LevEditOp *ops,
                       size_t *nb,
                       size_t len1,
                       size_t len2);

LevMatchingBlock *
lev_opcodes_matching_blocks(size_t len1,
                            __attribute__((unused)) size_t len2,
                            size_t nb,
                            const LevOpCode *bops,
                            size_t *nmblocks);

LevMatchingBlock *
lev_editops_matching_blocks(size_t len1,
                            size_t len2,
                            size_t n,
                            const LevEditOp *ops,
                            size_t *nmblocks);

#endif