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

#include <yara/modules.h>

#define MODULE_NAME tests


define_function(double_sum)
{
  double a = double_argument(1);
  double b = double_argument(2);

  return_double(a + b);
}

define_function(sum_2)
{
  int64_t a = integer_argument(1);
  int64_t b = integer_argument(2);

  return_integer(a + b);
}


define_function(sum_3)
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

begin_declarations;

  begin_struct("constants");
    declare_integer("one");
    declare_integer("two");
    declare_string("foo");
  end_struct("constants");

  begin_struct("undefined");
    declare_integer("i");
    declare_double("d");
  end_struct("undefined");

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

  declare_function("sum", "ii", "i", sum_2);
  declare_function("sum", "iii", "i", sum_3);
  declare_function("length", "s", "i", length);
  declare_function("double_sum", "dd", "d", double_sum);

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

  set_integer(1, module_object, "struct_array[1].i");

  set_integer(0, module_object, "integer_array[%i]", 0);
  set_integer(1, module_object, "integer_array[%i]", 1);
  set_integer(2, module_object, "integer_array[%i]", 2);

  set_string("foo", module_object, "string_array[%i]", 0);
  set_string("bar", module_object, "string_array[%i]", 1);
  set_string("baz", module_object, "string_array[%i]", 2);

  set_sized_string("foo\0bar", 7, module_object, "string_array[%i]", 3);

  set_string("foo", module_object, "string_dict[%s]", "foo");
  set_string("bar", module_object, "string_dict[\"bar\"]");

  set_string("foo", module_object, "struct_dict[%s].s", "foo");
  set_integer(1, module_object, "struct_dict[%s].i", "foo");

  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
