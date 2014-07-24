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


define_function(sum)
{
  int64_t a = integer_argument(1);
  int64_t b = integer_argument(1);

  if (a == UNDEFINED || b == UNDEFINED)
    return_integer(UNDEFINED);

  return_integer(a + b);
}

begin_declarations;

  begin_struct("constants");
    integer("one");
    integer("two");
    string("foo");
  end_struct("constants");

  integer_array("integer_array");
  string_array("string_array");

  begin_struct_array("struct_array");
    integer("i");
    string("s");
  end_struct_array("struct_array");

  function("sum", "ii", "i", sum);

end_declarations;


int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module, void* module_data, size_t module_data_size)
{
  set_integer(1, module, "constants.one");
  set_integer(2, module, "constants.two");
  set_string("foo", module, "constants.foo");

  set_integer(1, module, "struct_array[1].i");

  set_integer(0, module, "integer_array[%i]", 0);
  set_integer(1, module, "integer_array[%i]", 1);
  set_integer(2, module, "integer_array[%i]", 2);

  set_string("foo", module, "string_array[%i]", 0);
  set_string("bar", module, "string_array[%i]", 1);
  set_string("baz", module, "string_array[%i]", 2);

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module)
{
  return ERROR_SUCCESS;
}
