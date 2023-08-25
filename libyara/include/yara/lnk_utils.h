#ifndef YR_LNK_UTILS_H
#define YR_LNK_UTILS_H

#include <yara/lnk.h>

uint64_t convertWindowsTimeToUnixTime(uint64_t input);
char* get_hotkey_char(uint8_t key);

#endif