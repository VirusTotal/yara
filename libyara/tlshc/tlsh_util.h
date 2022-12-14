#ifndef __TLSH_TLSH_UTIL_H__
#define __TLSH_TLSH_UTIL_H__

#ifdef __cplusplus
extern "C"
{
#endif

  // unsigned char b_mapping(unsigned char salt, unsigned char i, unsigned char
  // j, unsigned char k);
  unsigned char l_capturing(unsigned int len);
  int mod_diff(unsigned int x, unsigned int y, unsigned int R);
  int h_distance(int len, const unsigned char x[], const unsigned char y[]);
  void to_hex(unsigned char* psrc, int len, char* pdest);
  void from_hex(const char* psrc, int len, unsigned char* pdest);
  unsigned char swap_byte(const unsigned char in);

#ifdef __cplusplus
}
#endif

#endif  // __TLSH_TLSH_UTIL_H__