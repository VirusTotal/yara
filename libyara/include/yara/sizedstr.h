/*
Copyright (c) 2007-2014. The YARA Authors. All Rights Reserved.

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

#ifndef _SIZEDSTR_H
#define _SIZEDSTR_H

#include <stddef.h>

//
// This struct is used to support strings containing null chars. The length of
// the string is stored along the string data. However the string data is also
// terminated with a null char.
//

#define SIZED_STRING_FLAGS_NO_CASE  1
#define SIZED_STRING_FLAGS_DOT_ALL  2

typedef struct _SIZED_STRING
{
  size_t length;
  int flags;
  char c_string[1];

} SIZED_STRING;


int sized_string_cmp(
  SIZED_STRING* s1,
  SIZED_STRING* s2);

#endif
