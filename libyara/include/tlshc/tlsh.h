#ifndef __TLSH_TLSH_H__
#define __TLSH_TLSH_H__

#include <stdbool.h>

#define TLSH_OPTION_CONSERVATIVE 2
#define TLSH_OPTION_KEEP_BUCKET  4
#define TLSH_OPTION_PRIVATE      8
#define TLSH_OPTION_THREADED     16

// Define TLSH_STRING_LEN_REQ, which is the string length of "T1" + the hex
// value of the Tlsh hash. BUCKETS_256 & CHECKSUM_3B are compiler switches
// defined in CMakeLists.txt
#if defined BUCKETS_256
    #define TLSH_STRING_LEN_REQ          136
    // changed the minimum data length to 256 for version 3.3
    #define MIN_DATA_LENGTH              50
    // added the -force option for version 3.5
    // added the -conservatibe option for version 3.17
    #define MIN_CONSERVATIVE_DATA_LENGTH 256
#endif

#if defined BUCKETS_128
    #define TLSH_STRING_LEN_REQ          72
    // changed the minimum data length to 256 for version 3.3
    #define MIN_DATA_LENGTH              50
    // added the -force option for version 3.5
    // added the -conservatibe option for version 3.17
    #define MIN_CONSERVATIVE_DATA_LENGTH 256
#endif

#if defined BUCKETS_48
    // No 3 Byte checksum option for 48 Bucket min hash
    #define TLSH_STRING_LEN              30
    // changed the minimum data length to 256 for version 3.3
    #define MIN_DATA_LENGTH              10
    // added the -force option for version 3.5
    #define MIN_CONSERVATIVE_DATA_LENGTH 10
#endif

#define TLSH_STRING_BUFFER_LEN (TLSH_STRING_LEN_REQ + 1)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TlshImpl TlshImpl;

typedef struct {
    TlshImpl* impl;
} Tlsh;

Tlsh* tlsh_new();
void tlsh_free(Tlsh* tlsh);
void tlsh_reset(Tlsh* tlsh);
int tlsh_update(Tlsh* tlsh, const unsigned char* data, unsigned int len);
int tlsh_final(Tlsh* tlsh, const unsigned char* data, unsigned int len, int tlsh_option);
const char* tlsh_get_hash(Tlsh* tlsh, bool showvers);

#ifdef __cplusplus
}
#endif

#endif // __TLSH_TLSH_H__