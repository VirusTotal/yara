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

begin_declarations;

  begin_struct("constants");
    integer("one");
    integer("two");
    string("foo");
  end_struct("constants");

  begin_struct_array("struct_array");
    integer("i");
    string("s");
  end_struct_array("struct_array");

end_declarations;


int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module, void* module_data, size_t module_data_size)
{
  set_integer(1, module, "constants.one");
  set_integer(2, module, "constants.two");
  set_string("foo", module, "constants.foo");

  set_integer(1, module, "struct_array[1].i");

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module)
{
  return ERROR_SUCCESS;
}



#undef MODULE_NAME