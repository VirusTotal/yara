#ifndef __TLSH_TLSH_IMPL_H__
#define __TLSH_TLSH_IMPL_H__

#include <stdbool.h>

#define SLIDING_WND_SIZE 5

#define BUCKETS 256
#define Q_BITS  2  // 2 bits; quartile value 0, 1, 2, 3

// BUCKETS_256 & CHECKSUM_3B are compiler switches defined in CMakeLists.txt

#if defined BUCKETS_256
#define EFF_BUCKETS 256
#define CODE_SIZE   64  // 256 * 2 bits = 64 bytes
#if defined CHECKSUM_3B
#define INTERNAL_TLSH_STRING_LEN 138
#define TLSH_CHECKSUM_LEN        3
// defined in tlsh.h   #define TLSH_STRING_LEN   138  // 2 + 3 + 64 bytes = 138
// hexidecimal chars
#else
#define INTERNAL_TLSH_STRING_LEN 134
#define TLSH_CHECKSUM_LEN        1
// defined in tlsh.h   #define TLSH_STRING_LEN   134  // 2 + 1 + 64 bytes = 134
// hexidecimal chars
#endif
#endif

#if defined BUCKETS_128
#define EFF_BUCKETS 128
#define CODE_SIZE   32  // 128 * 2 bits = 32 bytes
#if defined CHECKSUM_3B
#define INTERNAL_TLSH_STRING_LEN 74
#define TLSH_CHECKSUM_LEN        3
// defined in tlsh.h   #define TLSH_STRING_LEN   74   // 2 + 3 + 32 bytes = 74
// hexidecimal chars
#else
#define INTERNAL_TLSH_STRING_LEN 70
#define TLSH_CHECKSUM_LEN        1
// defined in tlsh.h   #define TLSH_STRING_LEN   70   // 2 + 1 + 32 bytes = 70
// hexidecimal chars
#endif
#endif

#if defined BUCKETS_48
#define INTERNAL_TLSH_STRING_LEN 33
#define EFF_BUCKETS              48
#define CODE_SIZE                12  // 48 * 2 bits = 12 bytes
#define TLSH_CHECKSUM_LEN        1
// defined in tlsh.h   #define TLSH_STRING_LEN   30   // 2 + 1 + 12 bytes = 30
// hexidecimal chars
#endif

#ifdef __cplusplus
extern "C"
{
#endif

  typedef struct
  {
    unsigned char checksum[TLSH_CHECKSUM_LEN];
    unsigned char lvalue;
    union
    {
      unsigned char qb;
      struct
      {
        unsigned char q1ratio : 4;
        unsigned char q2ratio : 4;
      } QR;
    } Q;
    unsigned char tmp_code[CODE_SIZE];
  } LshBinStruct;

  typedef struct TlshImpl
  {
    unsigned int *a_bucket;
    unsigned char slide_window[SLIDING_WND_SIZE];
    unsigned int data_len;
    LshBinStruct lsh_bin;
    char *lsh_code;
    bool lsh_code_valid;
  } TlshImpl;

  TlshImpl *tlsh_impl_new();
  void tlsh_impl_free(TlshImpl *impl);

  int tlsh_impl_update(
      TlshImpl *impl,
      const unsigned char *data,
      unsigned int len,
      int tlsh_option);
  void tlsh_impl_final(TlshImpl *impl, int fc_cons_option);
  void tlsh_impl_reset(TlshImpl *impl);
  int tlsh_impl_is_valid(TlshImpl *impl);
  int tlsh_impl_compare(TlshImpl *impl, TlshImpl *other);
  int tlsh_impl_total_diff(TlshImpl *impl, TlshImpl *other, bool len_diff);
  int tlsh_impl_lvalue(TlshImpl *impl);
  int tlsh_impl_q1ratio(TlshImpl *impl);
  int tlsh_impl_q2ratio(TlshImpl *impl);
  int tlsh_impl_checksum(TlshImpl *impl, int k);
  int tlsh_impl_bucket_value(TlshImpl *impl, int bucket);
  int tlsh_impl_histogram_count(TlshImpl *impl, int bucket);
  int tlsh_impl_from_tlsh_str(TlshImpl *impl, const char *str);
  const char *tlsh_impl_hash(TlshImpl *impl, bool showvers);

#ifdef __cplusplus
}
#endif

#endif  // __TLSH_TLSH_IMPL_H__