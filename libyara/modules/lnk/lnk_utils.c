#include <stdio.h>
#include <string.h>
#include <yara/endian.h>
#include <yara/integers.h>
#include <yara/mem.h>
#include <yara/strutils.h>
#include <yara/utils.h>
#include <yara/lnk.h>
#include <yara/lnk_utils.h>

uint64_t convertWindowsTimeToUnixTime(uint64_t input)
{
  // https://stackoverflow.com/questions/6161776/convert-windows-filetime-to-second-in-unix-linux
  long long int temp;
  temp = input / TICKS_PER_SECOND;  // convert from 100ns intervals to seconds;
  temp = temp - EPOCH_DIFFERENCE;   // subtract number of seconds between epochs
  return temp;
}

char* get_hotkey_char(uint8_t key) {

  char key_str[64];
  key_str[0] = '\0';

  switch(key) {
    case 0x30:
      sprintf(key_str, "0");
      break;
      
    case 0x31:
      sprintf(key_str, "1");
      break;
      
    case 0x32:
      sprintf(key_str, "2");
      break;
      
    case 0x33:
      sprintf(key_str, "3");
      break;
      
    case 0x34:
      sprintf(key_str, "4");
      break;
      
    case 0x35:
      sprintf(key_str, "5");
      break;
      
    case 0x36:
      sprintf(key_str, "6");
      break;
      
    case 0x37:
      sprintf(key_str, "7");
      break;
      
    case 0x38:
      sprintf(key_str, "8");
      break;
      
    case 0x39:
      sprintf(key_str, "9");
      break;
      
    case 0x41:
      sprintf(key_str, "A");
      break;
      
    case 0x42:
      sprintf(key_str, "B");
      break;
      
    case 0x43:
      sprintf(key_str, "C");
      break;
      
    case 0x44:
      sprintf(key_str, "D");
      break;
      
    case 0x45:
      sprintf(key_str, "E");
      break;
      
    case 0x46:
      sprintf(key_str, "F");
      break;
      
    case 0x47:
      sprintf(key_str, "G");
      break;
      
    case 0x48:
      sprintf(key_str, "H");
      break;
      
    case 0x49:
      sprintf(key_str, "I");
      break;
      
    case 0x4A:
      sprintf(key_str, "J");
      break;
      
    case 0x4B:
      sprintf(key_str, "K");
      break;
      
    case 0x4C:
      sprintf(key_str, "L");
      break;
      
    case 0x4D:
      sprintf(key_str, "M");
      break;
      
    case 0x4E:
      sprintf(key_str, "N");
      break;
      
    case 0x4F:
      sprintf(key_str, "O");
      break;
      
    case 0x50:
      sprintf(key_str, "P");
      break;
      
    case 0x51:
      sprintf(key_str, "Q");
      break;
      
    case 0x52:
      sprintf(key_str, "R");
      break;
      
    case 0x53:
      sprintf(key_str, "S");
      break;
      
    case 0x54:
      sprintf(key_str, "T");
      break;
      
    case 0x55:
      sprintf(key_str, "U");
      break;
      
    case 0x56:
      sprintf(key_str, "V");
      break;
      
    case 0x57:
      sprintf(key_str, "W");
      break;
      
    case 0x58:
      sprintf(key_str, "X");
      break;
      
    case 0x59:
      sprintf(key_str, "Y");
      break;
      
    case 0x5A:
      sprintf(key_str, "Z");
      break;
      
    case 0x70:
      sprintf(key_str, "F1");
      break;
      
    case 0x71:
      sprintf(key_str, "F2");
      break;
      
    case 0x72:
      sprintf(key_str, "F3");
      break;
      
    case 0x73:
      sprintf(key_str, "F4");
      break;
      
    case 0x74:
      sprintf(key_str, "F5");
      break;
      
    case 0x75:
      sprintf(key_str, "F6");
      break;
      
    case 0x76:
      sprintf(key_str, "F7");
      break;
      
    case 0x77:
      sprintf(key_str, "F8");
      break;
      
    case 0x78:
      sprintf(key_str, "F9");
      break;
      
    case 0x79:
      sprintf(key_str, "F10");
      break;
      
    case 0x7A:
      sprintf(key_str, "F11");
      break;
      
    case 0x7B:
      sprintf(key_str, "F12");
      break;
      
    case 0x7C:
      sprintf(key_str, "F13");
      break;
      
    case 0x7D:
      sprintf(key_str, "F14");
      break;
      
    case 0x7E:
      sprintf(key_str, "F15");
      break;
      
    case 0x7F:
      sprintf(key_str, "F16");
      break;
      
    case 0x80:
      sprintf(key_str, "F17");
      break;
      
    case 0x81:
      sprintf(key_str, "F18");
      break;
      
    case 0x82:
      sprintf(key_str, "F19");
      break;
      
    case 0x83:
      sprintf(key_str, "F20");
      break;
      
    case 0x84:
      sprintf(key_str, "F21");
      break;
      
    case 0x85:
      sprintf(key_str, "F22");
      break;
      
    case 0x86:
      sprintf(key_str, "F23");
      break;
      
    case 0x87:
      sprintf(key_str, "F24");
      break;
      
    case 0x90:
      sprintf(key_str, "NUM LOCK");
      break;
      
    case 0x91:
      sprintf(key_str, "SCROLL LOCK");
      break;
  }

  return yr_strdup(key_str);
}