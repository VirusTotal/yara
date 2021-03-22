/*
Copyright (c) 2007-2014. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _SIZEDSTR_H
#define _SIZEDSTR_H

#include <yara/integers.h>
#include <yara/utils.h>

// SIZED_STRING_FLAGS_NO_CASE indicates that the has been decorated with
// the "nocase" modifier or with the /i modifier in the case of regular
// expressions.
#define SIZED_STRING_FLAGS_NO_CASE 1

// SIZED_STRING_FLAGS_DOT_ALL is used for strings that contain a regular
// expression that had the /s modifier.
#define SIZED_STRING_FLAGS_DOT_ALL 2


#pragma pack(push)
#pragma pack(1)

//
// This struct is used to support strings containing null chars. The length of
// the string is stored along the string data. However the string data is also
// terminated with a null char.
//
typedef struct _SIZED_STRING
{
  uint32_t length;
  uint32_t flags;

  char c_string[1];

} SIZED_STRING;

#pragma pack(pop)

int ss_compare(SIZED_STRING* s1, SIZED_STRING* s2);

int ss_icompare(SIZED_STRING* s1, SIZED_STRING* s2);

bool ss_contains(SIZED_STRING* s1, SIZED_STRING* s2);

bool ss_icontains(SIZED_STRING* s1, SIZED_STRING* s2);

bool ss_startswith(SIZED_STRING* s1, SIZED_STRING* s2);

bool ss_istartswith(SIZED_STRING* s1, SIZED_STRING* s2);

bool ss_endswith(SIZED_STRING* s1, SIZED_STRING* s2);

bool ss_iendswith(SIZED_STRING* s1, SIZED_STRING* s2);

SIZED_STRING* ss_dup(SIZED_STRING* s);

SIZED_STRING* ss_new(const char* s);

SIZED_STRING* ss_convert_to_wide(SIZED_STRING* s);

#endif
