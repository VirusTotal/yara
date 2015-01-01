/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

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

#include <yara/sizedstr.h>


int sized_string_cmp(
  SIZED_STRING* s1,
  SIZED_STRING* s2)
{
  int i = 0;

  while (s1->length > i &&
         s2->length > i &&
         s1->c_string[i] == s2->c_string[i])
  {
    i++;
  }

  if (i == s1->length && i == s2->length)
    return 0;
  else if (i == s1->length)
    return -1;
  else if (i == s2->length)
    return 1;
  else if (s1->c_string[i] < s2->c_string[i])
    return -1;
  else
    return 1;
}
