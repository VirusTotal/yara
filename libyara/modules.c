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


#include <config.h>

#include <yara/exec.h>
#include <yara/modules.h>
#include <yara/libyara.h>


#define MODULE(name) \
    int name ## __declarations(YR_OBJECT* module); \
    int name ## __load(YR_SCAN_CONTEXT* context, \
                       YR_OBJECT* module, \
                       void* module_data, \
                       size_t module_data_size); \
    int name ## __unload(YR_OBJECT* main_structure); \
    int name ## __initialize(YR_MODULE* module); \
    int name ## __finalize(YR_MODULE* module);


#include <modules/module_list>

#undef MODULE


#define MODULE(name) \
    { \
      #name, \
      name##__declarations, \
      name##__load, \
      name##__unload, \
      name##__initialize, \
      name##__finalize \
    },

YR_MODULE yr_modules_table[] =
{
  #include <modules/module_list>
};

#undef MODULE


int yr_modules_initialize()
{
  for (int i = 0; i < sizeof(yr_modules_table) / sizeof(YR_MODULE); i++)
  {
    int result = yr_modules_table[i].initialize(&yr_modules_table[i]);

    if (result != ERROR_SUCCESS)
      return result;
  }

  return ERROR_SUCCESS;
}


int yr_modules_finalize()
{
  for (int i = 0; i < sizeof(yr_modules_table) / sizeof(YR_MODULE); i++)
  {
    int result = yr_modules_table[i].finalize(&yr_modules_table[i]);

    if (result != ERROR_SUCCESS)
      return result;
  }

  return ERROR_SUCCESS;
}


int yr_modules_do_declarations(
    const char* module_name,
    YR_OBJECT* main_structure)
{
  for (int i = 0; i < sizeof(yr_modules_table) / sizeof(YR_MODULE); i++)
  {
    if (strcmp(yr_modules_table[i].name, module_name) == 0)
      return yr_modules_table[i].declarations(main_structure);
  }

  return ERROR_UNKNOWN_MODULE;
}


int yr_modules_load(
    const char* module_name,
    YR_SCAN_CONTEXT* context)
{
  YR_OBJECT* module_structure = (YR_OBJECT*) yr_hash_table_lookup(
      context->objects_table,
      module_name,
      NULL);

  // if module_structure != NULL, the module was already
  // loaded, return successfully without doing nothing.

  if (module_structure != NULL)
    return ERROR_SUCCESS;

  // not loaded yet

  FAIL_ON_ERROR(yr_object_create(
      OBJECT_TYPE_STRUCTURE,
      module_name,
      NULL,
      &module_structure));

  YR_MODULE_IMPORT mi;

  mi.module_name = module_name;
  mi.module_data = NULL;
  mi.module_data_size = 0;

  int result = context->callback(
      CALLBACK_MSG_IMPORT_MODULE,
      &mi,
      context->user_data);

  if (result == CALLBACK_ERROR)
    return ERROR_CALLBACK_ERROR;

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_modules_do_declarations(module_name, module_structure),
      yr_object_destroy(module_structure));

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_hash_table_add(
          context->objects_table,
          module_name,
          NULL,
          module_structure),
      yr_object_destroy(module_structure));

  for (int i = 0; i < sizeof(yr_modules_table) / sizeof(YR_MODULE); i++)
  {
    if (strcmp(yr_modules_table[i].name, module_name) == 0)
    {
      result = yr_modules_table[i].load(
          context,
          module_structure,
          mi.module_data,
          mi.module_data_size);

      if (result != ERROR_SUCCESS)
        return result;
    }
  }

  return ERROR_SUCCESS;
}


int yr_modules_unload_all(
    YR_SCAN_CONTEXT* context)
{
  for (int i = 0; i < sizeof(yr_modules_table) / sizeof(YR_MODULE); i++)
  {
    YR_OBJECT* module_structure = (YR_OBJECT*) yr_hash_table_lookup(
        context->objects_table,
        yr_modules_table[i].name,
        NULL);

    if (module_structure != NULL)
      yr_modules_table[i].unload(module_structure);
  }

  return ERROR_SUCCESS;
}


void yr_modules_print_data(
    YR_SCAN_CONTEXT* context)
{
  for (int i = 0; i < sizeof(yr_modules_table) / sizeof(YR_MODULE); i++)
  {
    YR_OBJECT* module_structure = (YR_OBJECT*) yr_hash_table_lookup(
        context->objects_table,
        yr_modules_table[i].name,
        NULL);

    if (module_structure != NULL)
      yr_object_print_data(module_structure, 0);
  }
}
