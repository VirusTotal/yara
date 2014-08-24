/*
Copyright (c) 2007. The YARA Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <string.h>

size_t xtoi(const char* hexstr)
{
  size_t r = 0;
  int i;
  int l = strlen(hexstr);

  for (i = 0; i < l; i++)
  {
    switch(hexstr[i])
    {
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        r |= ((size_t)(hexstr[i] - '0')) << ((l - i - 1) * 4);
        break;
      case 'a':
      case 'b':
      case 'c':
      case 'd':
      case 'e':
      case 'f':
        r |= ((size_t)(hexstr[i] - 'a' + 10)) << ((l - i - 1) * 4);
        break;
      case 'A':
      case 'B':
      case 'C':
      case 'D':
      case 'E':
      case 'F':
        r |= ((size_t)(hexstr[i] - 'A' + 10)) << ((l - i - 1) * 4);
        break;
      default:
        i = l;  // force loop exit
    }
  }

  return r;
}
