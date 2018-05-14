/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

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

#include <yara/modules.h>

#define MODULE_NAME tests


define_function(fsum_2)
{
  double a = float_argument(1);
  double b = float_argument(2);

  return_float(a + b);
}

define_function(fsum_3)
{
  double a = float_argument(1);
  double b = float_argument(2);
  double c = float_argument(3);

  return_float(a + b + c);
}

define_function(isum_2)
{
  int64_t a = integer_argument(1);
  int64_t b = integer_argument(2);

  return_integer(a + b);
}


define_function(isum_3)
{
  int64_t a = integer_argument(1);
  int64_t b = integer_argument(2);
  int64_t c = integer_argument(3);

  return_integer(a + b + c);
}


define_function(length)
{
  char* s = string_argument(1);

  return_integer(strlen(s));
}


define_function(empty)
{
  return_string("");
}


define_function(match)
{
  return_integer(
      yr_re_match(
          scan_context(),
          regexp_argument(1),
          string_argument(2)));
}


define_function(foobar)
{
  int64_t arg = integer_argument(1);

  switch (arg)
  {
    case 1:
      return_string("foo");
      break;
    case 2:
      return_string("bar");
      break;
  }

  return_string("oops")
}

begin_declarations;

  begin_struct("constants");
    declare_integer("one");
    declare_integer("two");
    declare_string("foo");
    declare_string("empty");
  end_struct("constants");

  begin_struct("undefined");
    declare_integer("i");
    declare_float("f");
  end_struct("undefined");

  declare_string("module_data")

  declare_integer_array("integer_array");
  declare_string_array("string_array");

  declare_integer_dictionary("integer_dict");
  declare_string_dictionary("string_dict");

  begin_struct_array("struct_array");
    declare_integer("i");
    declare_string("s");
  end_struct_array("struct_array");

  begin_struct_dictionary("struct_dict");
    declare_integer("i");
    declare_string("s");
  end_struct_dictionary("struct_dict");

  declare_function("match", "rs", "i", match);
  declare_function("isum", "ii", "i", isum_2);
  declare_function("isum", "iii", "i", isum_3);
  declare_function("fsum", "ff", "f", fsum_2);
  declare_function("fsum", "fff", "f", fsum_3);
  declare_function("length", "s", "i", length);
  declare_function("empty", "", "s", empty);
  declare_function("foobar", "i", "s", foobar);

end_declarations;


int module_initialize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


int module_finalize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  set_integer(1, module_object, "constants.one");
  set_integer(2, module_object, "constants.two");
  set_string("foo", module_object, "constants.foo");
  set_string("", module_object, "constants.empty");

  set_integer(1, module_object, "struct_array[1].i");

  set_integer(0, module_object, "integer_array[%i]", 0);
  set_integer(1, module_object, "integer_array[%i]", 1);
  set_integer(2, module_object, "integer_array[%i]", 2);
  set_integer(256, module_object, "integer_array[%i]", 256);

  set_string("foo", module_object, "string_array[%i]", 0);
  set_string("bar", module_object, "string_array[%i]", 1);
  set_string("baz", module_object, "string_array[%i]", 2);

  set_sized_string("foo\0bar", 7, module_object, "string_array[%i]", 3);

  set_string("foo", module_object, "string_dict[%s]", "foo");
  set_string("bar", module_object, "string_dict[\"bar\"]");

  set_string("foo", module_object, "struct_dict[%s].s", "foo");
  set_integer(1, module_object, "struct_dict[%s].i", "foo");

  if (module_data_size > 0 && module_data != NULL) {
    set_sized_string(
        (const char*) module_data,
        module_data_size,
        module_object,
        "module_data");
  }

  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module_object)
{
  // Fail if module_unload is called twice with the same module_object
  if (module_object->data == (void*) 0xFABADA)
    assert(false);

  module_object->data = (void*) 0xFABADA;
  return ERROR_SUCCESS;
}
