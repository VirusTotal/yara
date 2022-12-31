/*
Copyright (c) 2014-2022. The YARA Authors. All Rights Reserved.

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

#include <stdlib.h>
#include <errno.h>
#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/strutils.h>
#include <yara/utils.h>

#define MODULE_NAME string

bool string_to_int(char* s, int base, int64_t* result)
{
  char* endp = s;

  errno = 0;
  *result = strtoll(s, &endp, base);

  if (errno != 0) {
    // Error while parsing the string.
    return false;
  }
  if (endp == s) {
    // No digits were found.
    return false;
  }
  if (*endp != '\0') {
    // Parsing did not reach the end of the string.
    return false;
  }

  return true;
}

define_function(to_int)
{
  char* s = string_argument(1);
  int64_t result = 0;

  if (string_to_int(s, 0, &result)) {
      return_integer(result);
  } else {
      return_integer(YR_UNDEFINED);
  }
}

define_function(to_int_base)
{
  char* s = string_argument(1);
  int64_t base = integer_argument(2);
  int64_t result = 0;

  if (!(base == 0 || (base >= 2 && base <= 36))) {
      return_integer(YR_UNDEFINED);
  }
  if (string_to_int(s, base, &result)) {
      return_integer(result);
  } else {
      return_integer(YR_UNDEFINED);
  }
}

define_function(string_length)
{
  SIZED_STRING* s = sized_string_argument(1);
  return_integer(s->length);
}

begin_declarations
  declare_function("to_int", "s", "i", to_int);
  declare_function("to_int", "si", "i", to_int_base);
  declare_function("length", "s", "i", string_length);
end_declarations

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
