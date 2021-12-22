#include "tlsh_util.h"
#include "tlsh_impl.h"
#include <tlshc/tlsh.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RANGE_LVALUE 256
#define RANGE_QRATIO 16

static void
find_quartile(unsigned int *q1, unsigned int *q2, unsigned int *q3, const unsigned int *a_bucket);
static unsigned int partition(unsigned int *buf, unsigned int left, unsigned int right);
static void tlsh_impl_fast_update5(
    TlshImpl *impl, const unsigned char *data, unsigned int len, int tlsh_option);

// Pearson's sample random table
static unsigned char v_table[256] = {
    1,   87,  49,  12,  176, 178, 102, 166, 121, 193, 6,   84,  249, 230, 44,  163, 14,  197, 213,
    181, 161, 85,  218, 80,  64,  239, 24,  226, 236, 142, 38,  200, 110, 177, 104, 103, 141, 253,
    255, 50,  77,  101, 81,  18,  45,  96,  31,  222, 25,  107, 190, 70,  86,  237, 240, 34,  72,
    242, 20,  214, 244, 227, 149, 235, 97,  234, 57,  22,  60,  250, 82,  175, 208, 5,   127, 199,
    111, 62,  135, 248, 174, 169, 211, 58,  66,  154, 106, 195, 245, 171, 17,  187, 182, 179, 0,
    243, 132, 56,  148, 75,  128, 133, 158, 100, 130, 126, 91,  13,  153, 246, 216, 219, 119, 68,
    223, 78,  83,  88,  201, 99,  122, 11,  92,  32,  136, 114, 52,  10,  138, 30,  48,  183, 156,
    35,  61,  26,  143, 74,  251, 94,  129, 162, 63,  152, 170, 7,   115, 167, 241, 206, 3,   150,
    55,  59,  151, 220, 90,  53,  23,  131, 125, 173, 15,  238, 79,  95,  89,  16,  105, 137, 225,
    224, 217, 160, 37,  123, 118, 73,  2,   157, 46,  116, 9,   145, 134, 228, 207, 212, 202, 215,
    69,  229, 27,  188, 67,  124, 168, 252, 42,  4,   29,  108, 21,  247, 19,  205, 39,  203, 233,
    40,  186, 147, 198, 192, 155, 33,  164, 191, 98,  204, 165, 180, 117, 76,  140, 36,  210, 172,
    41,  54,  159, 8,   185, 232, 113, 196, 231, 47,  146, 120, 51,  65,  28,  144, 254, 221, 93,
    189, 194, 139, 112, 43,  71,  109, 184, 209};

static unsigned char v_table48[256] = {
    1,  39, 1,  12, 32, 34, 6,  22, 25, 1,  6,  36, 48, 38, 44, 19, 14, 5,  21, 37, 17, 37, 26, 32,
    16, 47, 24, 34, 44, 46, 38, 8,  14, 33, 8,  7,  45, 48, 48, 2,  29, 5,  33, 18, 45, 0,  31, 30,
    25, 11, 46, 22, 38, 45, 48, 34, 24, 48, 20, 22, 48, 35, 5,  43, 1,  42, 9,  22, 12, 48, 34, 31,
    16, 5,  31, 7,  15, 14, 39, 48, 30, 25, 19, 10, 18, 10, 10, 3,  48, 27, 17, 43, 38, 35, 0,  48,
    36, 8,  4,  27, 32, 37, 14, 4,  34, 30, 43, 13, 9,  48, 24, 27, 23, 20, 31, 30, 35, 40, 9,  3,
    26, 11, 44, 32, 40, 18, 4,  10, 42, 30, 0,  39, 12, 35, 13, 26, 47, 26, 48, 46, 33, 18, 15, 8,
    26, 7,  19, 23, 48, 14, 3,  6,  7,  11, 7,  28, 42, 5,  23, 35, 29, 29, 15, 46, 31, 47, 41, 16,
    9,  41, 33, 32, 25, 16, 37, 27, 22, 25, 2,  13, 46, 20, 9,  1,  38, 36, 15, 20, 10, 23, 21, 37,
    27, 44, 19, 28, 24, 48, 42, 4,  29, 12, 21, 48, 19, 13, 39, 11, 41, 40, 42, 3,  6,  0,  11, 33,
    20, 47, 2,  12, 21, 36, 21, 28, 44, 36, 18, 28, 41, 6,  15, 8,  41, 40, 17, 4,  39, 47, 2,  24,
    3,  17, 28, 0,  48, 29, 45, 45, 2,  43, 16, 43, 23, 13, 40, 17,
};

// Pearson's algorithm
static unsigned char
b_mapping(unsigned char salt, unsigned char i, unsigned char j, unsigned char k)
{
    unsigned char h = 0;

    h = v_table[h ^ salt];
    h = v_table[h ^ i];
    h = v_table[h ^ j];
    h = v_table[h ^ k];
    return h;
}

#if defined BUCKETS_48
    #define fast_b_mapping(ms, i, j, k) (v_table48[v_table[v_table[ms ^ i] ^ j] ^ k])
#else
    #define fast_b_mapping(ms, i, j, k) (v_table[v_table[v_table[ms ^ i] ^ j] ^ k])
#endif

////////////////////////////////////////////////////////////////////////////////////////////

#if SLIDING_WND_SIZE == 5
    #define SLIDING_WND_SIZE_M1 4
#elif SLIDING_WND_SIZE == 4
    #define SLIDING_WND_SIZE_M1 3
#elif SLIDING_WND_SIZE == 6
    #define SLIDING_WND_SIZE_M1 5
#elif SLIDING_WND_SIZE == 7
    #define SLIDING_WND_SIZE_M1 6
#elif SLIDING_WND_SIZE == 8
    #define SLIDING_WND_SIZE_M1 7
#endif

#define RNG_SIZE   SLIDING_WND_SIZE
#define RNG_IDX(i) ((i + RNG_SIZE) % RNG_SIZE)

TlshImpl *tlsh_impl_new()
{
    TlshImpl *impl = calloc(1, sizeof(TlshImpl));
    if (!impl)
        return NULL;

    return impl;
}
void tlsh_impl_free(TlshImpl *impl)
{
    if (impl) {
        free(impl->a_bucket);
        free(impl->lsh_code);
        free(impl);
    }
}

void tlsh_impl_reset(TlshImpl *impl)
{
    free(impl->a_bucket);
    impl->a_bucket = NULL;
    memset(impl->slide_window, 0, sizeof impl->slide_window);
    free(impl->lsh_code);
    impl->lsh_code = NULL;
    memset(&impl->lsh_bin, 0, sizeof impl->lsh_bin);
    impl->data_len = 0;
    impl->lsh_code_valid = false;
}

int tlsh_impl_update(TlshImpl *impl, const unsigned char *data, unsigned int len, int tlsh_option)
{
    if (impl->lsh_code_valid) {
        fprintf(stderr, "call to update() on a tlsh that is already valid\n");
        return 1;
    }

    unsigned int fed_len = impl->data_len;

    if (impl->a_bucket == NULL) {
        impl->a_bucket = malloc(BUCKETS * sizeof(unsigned int)); // TODO error handling
        if (!impl->a_bucket) {
            return 1;
        }

        memset(impl->a_bucket, 0, sizeof(int) * BUCKETS);
    }

#if SLIDING_WND_SIZE == 5
    if (TLSH_CHECKSUM_LEN == 1) {
        tlsh_impl_fast_update5(impl, data, len, tlsh_option);
    #ifndef CHECKSUM_0B
        if ((tlsh_option & TLSH_OPTION_THREADED) || (tlsh_option & TLSH_OPTION_PRIVATE)) {
            impl->lsh_bin.checksum[0] = 0;
        }
    #endif
        return 0;
    }
#endif
    int j = (int)(impl->data_len % RNG_SIZE);

    for (unsigned int i = 0; i < len; i++, fed_len++, j = RNG_IDX(j + 1)) {
        impl->slide_window[j] = data[i];

        if (fed_len >= SLIDING_WND_SIZE_M1) {
            // only calculate when input >= 5 bytes
            int j_1 = RNG_IDX(j - 1);
            int j_2 = RNG_IDX(j - 2);
            int j_3 = RNG_IDX(j - 3);
#if SLIDING_WND_SIZE >= 5
            int j_4 = RNG_IDX(j - 4);
#endif
#if SLIDING_WND_SIZE >= 6
            int j_5 = RNG_IDX(j - 5);
#endif
#if SLIDING_WND_SIZE >= 7
            int j_6 = RNG_IDX(j - 6);
#endif
#if SLIDING_WND_SIZE >= 8
            int j_7 = RNG_IDX(j - 7);
#endif

#ifndef CHECKSUM_0B
            for (int k = 0; k < TLSH_CHECKSUM_LEN; k++) {
                if (k == 0) {
                    //				 b_mapping(0, ... )
                    impl->lsh_bin.checksum[k] = fast_b_mapping(
                        1,
                        impl->slide_window[j],
                        impl->slide_window[j_1],
                        impl->lsh_bin.checksum[k]);
                } else {
                    // use calculated 1 byte checksums to expand the total checksum to 3
                    // bytes
                    impl->lsh_bin.checksum[k] = b_mapping(
                        impl->lsh_bin.checksum[k - 1],
                        impl->slide_window[j],
                        impl->slide_window[j_1],
                        impl->lsh_bin.checksum[k]);
                }
            }
#endif

            unsigned char r;
            //	     b_mapping(2, ... )
            r = fast_b_mapping(
                49, impl->slide_window[j], impl->slide_window[j_1], impl->slide_window[j_2]);
            impl->a_bucket[r]++;
            //	     b_mapping(3, ... )
            r = fast_b_mapping(
                12, impl->slide_window[j], impl->slide_window[j_1], impl->slide_window[j_3]);
            impl->a_bucket[r]++;
            //	     b_mapping(5, ... )
            r = fast_b_mapping(
                178, impl->slide_window[j], impl->slide_window[j_2], impl->slide_window[j_3]);
            impl->a_bucket[r]++;
#if SLIDING_WND_SIZE >= 5
            //	     b_mapping(7, ... )
            r = fast_b_mapping(
                166, impl->slide_window[j], impl->slide_window[j_2], impl->slide_window[j_4]);
            impl->a_bucket[r]++;
            //	     b_mapping(11, ... )
            r = fast_b_mapping(
                84, impl->slide_window[j], impl->slide_window[j_1], impl->slide_window[j_4]);
            impl->a_bucket[r]++;
            //	     b_mapping(13, ... )
            r = fast_b_mapping(
                230, impl->slide_window[j], impl->slide_window[j_3], impl->slide_window[j_4]);
            impl->a_bucket[r]++;
#endif
#if SLIDING_WND_SIZE >= 6
            //	     b_mapping(17, ... )
            r = fast_b_mapping(
                197, this->slide_window[j], this->slide_window[j_1], this->slide_window[j_5]);
            this->a_bucket[r]++;
            //	     b_mapping(19, ... )
            r = fast_b_mapping(
                181, this->slide_window[j], this->slide_window[j_2], this->slide_window[j_5]);
            this->a_bucket[r]++;
            //	     b_mapping(23, ... )
            r = fast_b_mapping(
                80, this->slide_window[j], this->slide_window[j_3], this->slide_window[j_5]);
            this->a_bucket[r]++;
            //	     b_mapping(29, ... )
            r = fast_b_mapping(
                142, this->slide_window[j], this->slide_window[j_4], this->slide_window[j_5]);
            this->a_bucket[r]++;
#endif
#if SLIDING_WND_SIZE >= 7
            //	     b_mapping(31, ... )
            r = fast_b_mapping(
                200, this->slide_window[j], this->slide_window[j_1], this->slide_window[j_6]);
            this->a_bucket[r]++;
            //	     b_mapping(37, ... )
            r = fast_b_mapping(
                253, this->slide_window[j], this->slide_window[j_2], this->slide_window[j_6]);
            this->a_bucket[r]++;
            //	     b_mapping(41, ... )
            r = fast_b_mapping(
                101, this->slide_window[j], this->slide_window[j_3], this->slide_window[j_6]);
            this->a_bucket[r]++;
            //	     b_mapping(43, ... )
            r = fast_b_mapping(
                18, this->slide_window[j], this->slide_window[j_4], this->slide_window[j_6]);
            this->a_bucket[r]++;
            //	     b_mapping(47, ... )
            r = fast_b_mapping(
                222, this->slide_window[j], this->slide_window[j_5], this->slide_window[j_6]);
            this->a_bucket[r]++;
#endif
#if SLIDING_WND_SIZE >= 8
            //	     b_mapping(53, ... )
            r = fast_b_mapping(
                237, this->slide_window[j], this->slide_window[j_1], this->slide_window[j_7]);
            this->a_bucket[r]++;
            //	     b_mapping(59, ... )
            r = fast_b_mapping(
                214, this->slide_window[j], this->slide_window[j_2], this->slide_window[j_7]);
            this->a_bucket[r]++;
            //	     b_mapping(61, ... )
            r = fast_b_mapping(
                227, this->slide_window[j], this->slide_window[j_3], this->slide_window[j_7]);
            this->a_bucket[r]++;
            //	     b_mapping(67, ... )
            r = fast_b_mapping(
                22, this->slide_window[j], this->slide_window[j_4], this->slide_window[j_7]);
            this->a_bucket[r]++;
            //	     b_mapping(71, ... )
            r = fast_b_mapping(
                175, this->slide_window[j], this->slide_window[j_5], this->slide_window[j_7]);
            this->a_bucket[r]++;
            //	     b_mapping(73, ... )
            r = fast_b_mapping(
                5, this->slide_window[j], this->slide_window[j_6], this->slide_window[j_7]);
            this->a_bucket[r]++;
#endif
        }
    }
    impl->data_len += len;
#ifndef CHECKSUM_0B
    if ((tlsh_option & TLSH_OPTION_THREADED) || (tlsh_option & TLSH_OPTION_PRIVATE)) {
        for (int k = 0; k < TLSH_CHECKSUM_LEN; k++) {
            impl->lsh_bin.checksum[k] = 0;
        }
    }
#endif

    return 0;
}

/////////////////////////////////////////////////////////////////////////////
// update for the case when SLIDING_WND_SIZE==5
// have different optimized functions for
//	default TLSH
//	threaded TLSH
//	private TLSH
/////////////////////////////////////////////////////////////////////////////
static void raw_fast_update5(
    // inputs
    const unsigned char *data,
    unsigned int len,
    unsigned int fed_len,
    // outputs
    unsigned int *a_bucket,
    unsigned char *ret_checksum,
    unsigned char *slide_window);

static void raw_fast_update5_private(
    // inputs
    const unsigned char *data,
    unsigned int len,
    unsigned int fed_len,
    // outputs
    unsigned int *a_bucket,
    unsigned char *slide_window);

static void
tlsh_impl_fast_update5(TlshImpl *impl, const unsigned char *data, unsigned int len, int tlsh_option)
{
    if (tlsh_option & TLSH_OPTION_PRIVATE) {
        raw_fast_update5_private(data, len, impl->data_len, impl->a_bucket, impl->slide_window);
        impl->data_len += len;
        impl->lsh_bin.checksum[0] = 0;
    } else {
        raw_fast_update5(
            data,
            len,
            impl->data_len,
            impl->a_bucket,
            &(impl->lsh_bin.checksum[0]),
            impl->slide_window);
        impl->data_len += len;
    }
}

static void raw_fast_update5(
    // inputs
    const unsigned char *data,
    unsigned int len,
    unsigned int fed_len,
    // outputs
    unsigned int *a_bucket,
    unsigned char *ret_checksum,
    unsigned char *slide_window)
{
    int j = (int)(fed_len % RNG_SIZE);
    unsigned char checksum = *ret_checksum;

    unsigned int start_i = 0;
    if (fed_len < SLIDING_WND_SIZE_M1) {
        int extra = SLIDING_WND_SIZE_M1 - fed_len;
        start_i = extra;
        j = (j + extra) % RNG_SIZE;
    }
    for (unsigned int i = start_i; i < len;) {
        // only calculate when input >= 5 bytes
        if ((i >= 4) && (i + 5 < len)) {
            unsigned char a0 = data[i - 4];
            unsigned char a1 = data[i - 3];
            unsigned char a2 = data[i - 2];
            unsigned char a3 = data[i - 1];
            unsigned char a4 = data[i];
            unsigned char a5 = data[i + 1];
            unsigned char a6 = data[i + 2];
            unsigned char a7 = data[i + 3];
            unsigned char a8 = data[i + 4];

            checksum = fast_b_mapping(1, a4, a3, checksum);
            a_bucket[fast_b_mapping(49, a4, a3, a2)]++;
            a_bucket[fast_b_mapping(12, a4, a3, a1)]++;
            a_bucket[fast_b_mapping(178, a4, a2, a1)]++;
            a_bucket[fast_b_mapping(166, a4, a2, a0)]++;
            a_bucket[fast_b_mapping(84, a4, a3, a0)]++;
            a_bucket[fast_b_mapping(230, a4, a1, a0)]++;

            checksum = fast_b_mapping(1, a5, a4, checksum);
            a_bucket[fast_b_mapping(49, a5, a4, a3)]++;
            a_bucket[fast_b_mapping(12, a5, a4, a2)]++;
            a_bucket[fast_b_mapping(178, a5, a3, a2)]++;
            a_bucket[fast_b_mapping(166, a5, a3, a1)]++;
            a_bucket[fast_b_mapping(84, a5, a4, a1)]++;
            a_bucket[fast_b_mapping(230, a5, a2, a1)]++;

            checksum = fast_b_mapping(1, a6, a5, checksum);
            a_bucket[fast_b_mapping(49, a6, a5, a4)]++;
            a_bucket[fast_b_mapping(12, a6, a5, a3)]++;
            a_bucket[fast_b_mapping(178, a6, a4, a3)]++;
            a_bucket[fast_b_mapping(166, a6, a4, a2)]++;
            a_bucket[fast_b_mapping(84, a6, a5, a2)]++;
            a_bucket[fast_b_mapping(230, a6, a3, a2)]++;

            checksum = fast_b_mapping(1, a7, a6, checksum);
            a_bucket[fast_b_mapping(49, a7, a6, a5)]++;
            a_bucket[fast_b_mapping(12, a7, a6, a4)]++;
            a_bucket[fast_b_mapping(178, a7, a5, a4)]++;
            a_bucket[fast_b_mapping(166, a7, a5, a3)]++;
            a_bucket[fast_b_mapping(84, a7, a6, a3)]++;
            a_bucket[fast_b_mapping(230, a7, a4, a3)]++;

            checksum = fast_b_mapping(1, a8, a7, checksum);
            a_bucket[fast_b_mapping(49, a8, a7, a6)]++;
            a_bucket[fast_b_mapping(12, a8, a7, a5)]++;
            a_bucket[fast_b_mapping(178, a8, a6, a5)]++;
            a_bucket[fast_b_mapping(166, a8, a6, a4)]++;
            a_bucket[fast_b_mapping(84, a8, a7, a4)]++;
            a_bucket[fast_b_mapping(230, a8, a5, a4)]++;

            i = i + 5;
            j = RNG_IDX(j + 5);
        } else {
            slide_window[j] = data[i];
            int j_1 = RNG_IDX(j - 1);
            if (i >= 1) {
                slide_window[j_1] = data[i - 1];
            }
            int j_2 = RNG_IDX(j - 2);
            if (i >= 2) {
                slide_window[j_2] = data[i - 2];
            }
            int j_3 = RNG_IDX(j - 3);
            if (i >= 3) {
                slide_window[j_3] = data[i - 3];
            }
            int j_4 = RNG_IDX(j - 4);
            if (i >= 4) {
                slide_window[j_4] = data[i - 4];
            }

            checksum = fast_b_mapping(1, slide_window[j], slide_window[j_1], checksum);
            a_bucket[fast_b_mapping(49, slide_window[j], slide_window[j_1], slide_window[j_2])]++;
            a_bucket[fast_b_mapping(12, slide_window[j], slide_window[j_1], slide_window[j_3])]++;
            a_bucket[fast_b_mapping(178, slide_window[j], slide_window[j_2], slide_window[j_3])]++;
            a_bucket[fast_b_mapping(166, slide_window[j], slide_window[j_2], slide_window[j_4])]++;
            a_bucket[fast_b_mapping(84, slide_window[j], slide_window[j_1], slide_window[j_4])]++;
            a_bucket[fast_b_mapping(230, slide_window[j], slide_window[j_3], slide_window[j_4])]++;
            i++;
            j = RNG_IDX(j + 1);
        }
    }
    *ret_checksum = checksum;
}

static void raw_fast_update5_private(
    // inputs
    const unsigned char *data,
    unsigned int len,
    unsigned int fed_len,
    // outputs
    unsigned int *a_bucket,
    unsigned char *slide_window)
{
    int j = (int)(fed_len % RNG_SIZE);

    unsigned int start_i = 0;
    if (fed_len < SLIDING_WND_SIZE_M1) {
        int extra = SLIDING_WND_SIZE_M1 - fed_len;
        start_i = extra;
        j = (j + extra) % RNG_SIZE;
    }
    for (unsigned int i = start_i; i < len;) {
        // only calculate when input >= 5 bytes
        if ((i >= 4) && (i + 5 < len)) {
            unsigned char a0 = data[i - 4];
            unsigned char a1 = data[i - 3];
            unsigned char a2 = data[i - 2];
            unsigned char a3 = data[i - 1];
            unsigned char a4 = data[i];
            unsigned char a5 = data[i + 1];
            unsigned char a6 = data[i + 2];
            unsigned char a7 = data[i + 3];
            unsigned char a8 = data[i + 4];

            a_bucket[fast_b_mapping(49, a4, a3, a2)]++;
            a_bucket[fast_b_mapping(12, a4, a3, a1)]++;
            a_bucket[fast_b_mapping(178, a4, a2, a1)]++;
            a_bucket[fast_b_mapping(166, a4, a2, a0)]++;
            a_bucket[fast_b_mapping(84, a4, a3, a0)]++;
            a_bucket[fast_b_mapping(230, a4, a1, a0)]++;

            a_bucket[fast_b_mapping(49, a5, a4, a3)]++;
            a_bucket[fast_b_mapping(12, a5, a4, a2)]++;
            a_bucket[fast_b_mapping(178, a5, a3, a2)]++;
            a_bucket[fast_b_mapping(166, a5, a3, a1)]++;
            a_bucket[fast_b_mapping(84, a5, a4, a1)]++;
            a_bucket[fast_b_mapping(230, a5, a2, a1)]++;

            a_bucket[fast_b_mapping(49, a6, a5, a4)]++;
            a_bucket[fast_b_mapping(12, a6, a5, a3)]++;
            a_bucket[fast_b_mapping(178, a6, a4, a3)]++;
            a_bucket[fast_b_mapping(166, a6, a4, a2)]++;
            a_bucket[fast_b_mapping(84, a6, a5, a2)]++;
            a_bucket[fast_b_mapping(230, a6, a3, a2)]++;

            a_bucket[fast_b_mapping(49, a7, a6, a5)]++;
            a_bucket[fast_b_mapping(12, a7, a6, a4)]++;
            a_bucket[fast_b_mapping(178, a7, a5, a4)]++;
            a_bucket[fast_b_mapping(166, a7, a5, a3)]++;
            a_bucket[fast_b_mapping(84, a7, a6, a3)]++;
            a_bucket[fast_b_mapping(230, a7, a4, a3)]++;

            a_bucket[fast_b_mapping(49, a8, a7, a6)]++;
            a_bucket[fast_b_mapping(12, a8, a7, a5)]++;
            a_bucket[fast_b_mapping(178, a8, a6, a5)]++;
            a_bucket[fast_b_mapping(166, a8, a6, a4)]++;
            a_bucket[fast_b_mapping(84, a8, a7, a4)]++;
            a_bucket[fast_b_mapping(230, a8, a5, a4)]++;

            i = i + 5;
            j = RNG_IDX(j + 5);
        } else {
            slide_window[j] = data[i];
            int j_1 = RNG_IDX(j - 1);
            if (i >= 1) {
                slide_window[j_1] = data[i - 1];
            }
            int j_2 = RNG_IDX(j - 2);
            if (i >= 2) {
                slide_window[j_2] = data[i - 2];
            }
            int j_3 = RNG_IDX(j - 3);
            if (i >= 3) {
                slide_window[j_3] = data[i - 3];
            }
            int j_4 = RNG_IDX(j - 4);
            if (i >= 4) {
                slide_window[j_4] = data[i - 4];
            }

            a_bucket[fast_b_mapping(49, slide_window[j], slide_window[j_1], slide_window[j_2])]++;
            a_bucket[fast_b_mapping(12, slide_window[j], slide_window[j_1], slide_window[j_3])]++;
            a_bucket[fast_b_mapping(178, slide_window[j], slide_window[j_2], slide_window[j_3])]++;
            a_bucket[fast_b_mapping(166, slide_window[j], slide_window[j_2], slide_window[j_4])]++;
            a_bucket[fast_b_mapping(84, slide_window[j], slide_window[j_1], slide_window[j_4])]++;
            a_bucket[fast_b_mapping(230, slide_window[j], slide_window[j_3], slide_window[j_4])]++;
            i++;
            j = RNG_IDX(j + 1);
        }
    }
}

/////////////////////////////////////////////////////////////////////////////
// fc_cons_option - a bitfield
//	0	default
//	1	force (now the default)
//	2	conservative
//	4	do not delete a_bucket
/////////////////////////////////////////////////////////////////////////////

/* to signal the class there is no more data to be added */
void tlsh_impl_final(TlshImpl *this, int fc_cons_option)
{
    if (this->lsh_code_valid) {
        fprintf(stderr, "call to final() on a tlsh that is already valid\n");
        return;
    }
    // incoming data must more than or equal to MIN_DATA_LENGTH bytes
    if (((fc_cons_option & TLSH_OPTION_CONSERVATIVE) == 0) && (this->data_len < MIN_DATA_LENGTH)) {
        // this->lsh_code be empty
        free(this->a_bucket);
        this->a_bucket = NULL;
        return;
    }
    if ((fc_cons_option & TLSH_OPTION_CONSERVATIVE) &&
        (this->data_len < MIN_CONSERVATIVE_DATA_LENGTH)) {
        // this->lsh_code be empty
        free(this->a_bucket);
        this->a_bucket = NULL;
        return;
    }

    unsigned int q1, q2, q3;
    find_quartile(&q1, &q2, &q3, this->a_bucket);

    // issue #79 - divide by 0 if q3 == 0
    if (q3 == 0) {
        free(this->a_bucket);
        this->a_bucket = NULL;
        return;
    }

    // buckets must be more than 50% non-zero
    int nonzero = 0;
    for (unsigned int i = 0; i < CODE_SIZE; i++) {
        for (unsigned int j = 0; j < 4; j++) {
            if (this->a_bucket[4 * i + j] > 0) {
                nonzero++;
            }
        }
    }
#if defined BUCKETS_48
    if (nonzero < 18) {
        // printf("nonzero=%d\n", nonzero);
        delete[] this->a_bucket;
        this->a_bucket = NULL;
        return;
    }
#else
    if (nonzero <= 4 * CODE_SIZE / 2) {
        free(this->a_bucket);
        this->a_bucket = NULL;
        return;
    }
#endif

    for (unsigned int i = 0; i < CODE_SIZE; i++) {
        unsigned char h = 0;
        for (unsigned int j = 0; j < 4; j++) {
            unsigned int k = this->a_bucket[4 * i + j];
            if (q3 < k) {
                h += 3 << (j * 2); // leave the optimization j*2 = j<<1 or j*2 = j+j for
                                   // compiler
            } else if (q2 < k) {
                h += 2 << (j * 2);
            } else if (q1 < k) {
                h += 1 << (j * 2);
            }
        }
        this->lsh_bin.tmp_code[i] = h;
    }

    if ((fc_cons_option & TLSH_OPTION_KEEP_BUCKET) == 0) {
        // Done with a_bucket so deallocate
        free(this->a_bucket);
        this->a_bucket = NULL;
    }

    this->lsh_bin.lvalue = l_capturing(this->data_len);
    this->lsh_bin.Q.QR.q1ratio = (unsigned int)((float)(q1 * 100) / (float)q3) % 16;
    this->lsh_bin.Q.QR.q2ratio = (unsigned int)((float)(q2 * 100) / (float)q3) % 16;
    this->lsh_code_valid = true;
}

int tlsh_impl_from_tlsh_str(TlshImpl *impl, const char *str)
{
    // Assume that we have 128 Buckets
    int start = 0;
    if (strncmp(str, "T1", 2) == 0) {
        start = 2;
    } else {
        start = 0;
    }
    // Validate input string
    for (int ii = 0; ii < INTERNAL_TLSH_STRING_LEN; ii++) {
        int i = ii + start;
        if (!((str[i] >= '0' && str[i] <= '9') || (str[i] >= 'A' && str[i] <= 'F') ||
              (str[i] >= 'a' && str[i] <= 'f'))) {
            // printf("warning ii=%d str[%d]='%c'\n", ii, i, str[i]);
            return 1;
        }
    }
    int xi = INTERNAL_TLSH_STRING_LEN + start;
    if (((str[xi] >= '0' && str[xi] <= '9') || (str[xi] >= 'A' && str[xi] <= 'F') ||
         (str[xi] >= 'a' && str[xi] <= 'f'))) {
        // printf("warning xi=%d\n", xi);
        return 1;
    }

    tlsh_impl_reset(impl);

    LshBinStruct tmp;
    from_hex(&str[start], INTERNAL_TLSH_STRING_LEN, (unsigned char *)&tmp);

    // Reconstruct checksum, Qrations & lvalue
    for (int k = 0; k < TLSH_CHECKSUM_LEN; k++) {
        impl->lsh_bin.checksum[k] = swap_byte(tmp.checksum[k]);
    }
    impl->lsh_bin.lvalue = swap_byte(tmp.lvalue);
    impl->lsh_bin.Q.qb = swap_byte(tmp.Q.qb);
    for (int i = 0; i < CODE_SIZE; i++) {
        impl->lsh_bin.tmp_code[i] = (tmp.tmp_code[CODE_SIZE - 1 - i]);
    }
    impl->lsh_code_valid = true;

    return 0;
}

const char *hash2(TlshImpl *impl, char *buffer, unsigned int bufSize, bool showvers)
{
    if (bufSize < TLSH_STRING_LEN_REQ + 1) {
        strncpy(buffer, "", bufSize);
        return buffer;
    }
    if (impl->lsh_code_valid == false) {
        strncpy(buffer, "", bufSize);
        return buffer;
    }

    LshBinStruct tmp;
    for (int k = 0; k < TLSH_CHECKSUM_LEN; k++) {
        tmp.checksum[k] = swap_byte(impl->lsh_bin.checksum[k]);
    }
    tmp.lvalue = swap_byte(impl->lsh_bin.lvalue);
    tmp.Q.qb = swap_byte(impl->lsh_bin.Q.qb);
    for (int i = 0; i < CODE_SIZE; i++) {
        tmp.tmp_code[i] = (impl->lsh_bin.tmp_code[CODE_SIZE - 1 - i]);
    }

    if (showvers) {
        buffer[0] = 'T';
        buffer[1] = '0' + showvers;
        to_hex((unsigned char *)&tmp, sizeof(tmp), &buffer[2]);
    } else {
        to_hex((unsigned char *)&tmp, sizeof(tmp), buffer);
    }
    return buffer;
}

/* to get the hex-encoded hash code */
const char *tlsh_impl_hash(TlshImpl *impl, bool showvers)
{
    if (impl->lsh_code != NULL) {
        // lsh_code has been previously calculated, so just return it
        return impl->lsh_code;
    }

    impl->lsh_code = (char *)malloc(TLSH_STRING_LEN_REQ + 1);
    if (!impl->lsh_code) {
        return NULL;
    }

    memset(impl->lsh_code, 0, TLSH_STRING_LEN_REQ + 1);

    return hash2(impl, impl->lsh_code, TLSH_STRING_LEN_REQ + 1, showvers);
}

int tlsh_impl_compare(TlshImpl *this, TlshImpl *other)
{
    return (memcmp(&(this->lsh_bin), &(other->lsh_bin), sizeof(this->lsh_bin)));
}

////////////////////////////////////////////
// the default for these parameters is 12
////////////////////////////////////////////

static int length_mult = 12;
static int qratio_mult = 12;

#ifdef TLSH_DISTANCE_PARAMETERS

int hist_diff1_add = 1;
int hist_diff2_add = 2;
int hist_diff3_add = 6;

void set_tlsh_distance_parameters(
    int length_mult_value,
    int qratio_mult_value,
    int hist_diff1_add_value,
    int hist_diff2_add_value,
    int hist_diff3_add_value)
{
    if (length_mult_value != -1) {
        length_mult = length_mult_value;
    }
    if (qratio_mult_value != -1) {
        qratio_mult = qratio_mult_value;
    }
    if (hist_diff1_add_value != -1) {
        hist_diff1_add = hist_diff1_add_value;
    }
    if (hist_diff2_add_value != -1) {
        hist_diff2_add = hist_diff2_add_value;
    }
    if (hist_diff3_add_value != -1) {
        hist_diff3_add = hist_diff3_add_value;
    }
}
#endif

int tlsh_impl_lvalue(TlshImpl *impl)
{
    return (impl->lsh_bin.lvalue);
}

int tlsh_impl_q1ratio(TlshImpl *impl)
{
    return (impl->lsh_bin.Q.QR.q1ratio);
}

int tlsh_impl_q2ratio(TlshImpl *impl)
{
    return (impl->lsh_bin.Q.QR.q2ratio);
}

int tlsh_impl_is_valid(TlshImpl *impl)
{
    return (impl->lsh_code_valid);
}

int tlsh_impl_checksum(TlshImpl *impl, int k)
{
    if ((k >= TLSH_CHECKSUM_LEN) || (k < 0)) {
        return 0;
    }
    return impl->lsh_bin.checksum[k];
}

int tlsh_impl_bucket_value(TlshImpl *impl, int bucket)
{
    int idx;
    int elem;
    unsigned char bv;

    idx = (CODE_SIZE - (bucket / 4)) - 1;
    elem = bucket % 4;
    bv = impl->lsh_bin.tmp_code[idx];
    int h1 = bv / 16;
    int h2 = bv % 16;
    int p1 = h1 / 4;
    int p2 = h1 % 4;
    int p3 = h2 / 4;
    int p4 = h2 % 4;
    if (elem == 0) {
        return (p1);
    }
    if (elem == 1) {
        return (p2);
    }
    if (elem == 2) {
        return (p3);
    }
    return (p4);
}

int tlsh_impl_histogram_count(TlshImpl *impl, int bucket)
{
    if (impl->a_bucket == NULL)
        return (-1);
    return (impl->a_bucket[EFF_BUCKETS - 1 - bucket]);
}

int tlsh_impl_total_diff(TlshImpl *impl, TlshImpl *other, bool len_diff)
{
    int diff = 0;

    if (len_diff) {
        int ldiff = mod_diff(impl->lsh_bin.lvalue, other->lsh_bin.lvalue, RANGE_LVALUE);
        if (ldiff == 0)
            diff = 0;
        else if (ldiff == 1)
            diff = 1;
        else
            diff += ldiff * length_mult;
    }

    int q1diff = mod_diff(impl->lsh_bin.Q.QR.q1ratio, other->lsh_bin.Q.QR.q1ratio, RANGE_QRATIO);
    if (q1diff <= 1)
        diff += q1diff;
    else
        diff += (q1diff - 1) * qratio_mult;

    int q2diff = mod_diff(impl->lsh_bin.Q.QR.q2ratio, other->lsh_bin.Q.QR.q2ratio, RANGE_QRATIO);
    if (q2diff <= 1)
        diff += q2diff;
    else
        diff += (q2diff - 1) * qratio_mult;

    for (int k = 0; k < TLSH_CHECKSUM_LEN; k++) {
        if (impl->lsh_bin.checksum[k] != other->lsh_bin.checksum[k]) {
            diff++;
            break;
        }
    }

    diff += h_distance(CODE_SIZE, impl->lsh_bin.tmp_code, other->lsh_bin.tmp_code);

    return (diff);
}

#define SWAP_UINT(x, y)                                                                            \
    do {                                                                                           \
        unsigned int int_tmp = (x);                                                                \
        (x) = (y);                                                                                 \
        (y) = int_tmp;                                                                             \
    } while (0)

void find_quartile(
    unsigned int *q1, unsigned int *q2, unsigned int *q3, const unsigned int *a_bucket)
{
    unsigned int bucket_copy[EFF_BUCKETS], short_cut_left[EFF_BUCKETS],
        short_cut_right[EFF_BUCKETS], spl = 0, spr = 0;
    unsigned int p1 = EFF_BUCKETS / 4 - 1;
    unsigned int p2 = EFF_BUCKETS / 2 - 1;
    unsigned int p3 = EFF_BUCKETS - EFF_BUCKETS / 4 - 1;
    unsigned int end = EFF_BUCKETS - 1;

    for (unsigned int i = 0; i <= end; i++) {
        bucket_copy[i] = a_bucket[i];
    }

    for (unsigned int l = 0, r = end;;) {
        unsigned int ret = partition(bucket_copy, l, r);
        if (ret > p2) {
            r = ret - 1;
            short_cut_right[spr] = ret;
            spr++;
        } else if (ret < p2) {
            l = ret + 1;
            short_cut_left[spl] = ret;
            spl++;
        } else {
            *q2 = bucket_copy[p2];
            break;
        }
    }

    short_cut_left[spl] = p2 - 1;
    short_cut_right[spr] = p2 + 1;

    for (unsigned int i = 0, l = 0; i <= spl; i++) {
        unsigned int r = short_cut_left[i];
        if (r > p1) {
            for (;;) {
                unsigned int ret = partition(bucket_copy, l, r);
                if (ret > p1) {
                    r = ret - 1;
                } else if (ret < p1) {
                    l = ret + 1;
                } else {
                    *q1 = bucket_copy[p1];
                    break;
                }
            }
            break;
        } else if (r < p1) {
            l = r;
        } else {
            *q1 = bucket_copy[p1];
            break;
        }
    }

    for (unsigned int i = 0, r = end; i <= spr; i++) {
        unsigned int l = short_cut_right[i];
        if (l < p3) {
            for (;;) {
                unsigned int ret = partition(bucket_copy, l, r);
                if (ret > p3) {
                    r = ret - 1;
                } else if (ret < p3) {
                    l = ret + 1;
                } else {
                    *q3 = bucket_copy[p3];
                    break;
                }
            }
            break;
        } else if (l > p3) {
            r = l;
        } else {
            *q3 = bucket_copy[p3];
            break;
        }
    }
}

unsigned int partition(unsigned int *buf, unsigned int left, unsigned int right)
{
    if (left == right) {
        return left;
    }
    if (left + 1 == right) {
        if (buf[left] > buf[right]) {
            SWAP_UINT(buf[left], buf[right]);
        }
        return left;
    }

    unsigned int ret = left, pivot = (left + right) >> 1;

    unsigned int val = buf[pivot];

    buf[pivot] = buf[right];
    buf[right] = val;

    for (unsigned int i = left; i < right; i++) {
        if (buf[i] < val) {
            SWAP_UINT(buf[ret], buf[i]);
            ret++;
        }
    }
    buf[right] = buf[ret];
    buf[ret] = val;

    return ret;
}
