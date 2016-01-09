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

#define MODULE_NAME demo

begin_declarations;

  declare_string("greeting");

  begin_struct_dictionary("d1");
    declare_integer("i1");
  end_struct_dictionary("d1");

  begin_struct_dictionary("d2");
    declare_integer("i2");
    begin_struct_dictionary("d2_2");
      declare_integer("i3");
    end_struct_dictionary("d2_2");
  end_struct_dictionary("d2");

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
  set_string("Hello World!", module_object, "greeting");

  set_integer(5, module_object, "d1[\"abc\"].i1");
  set_integer(5, module_object, "d2[\"def\"].i2");
  set_integer(5, module_object, "d2[\"def\"].d2_2[\"ghi\"].i3");

  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
