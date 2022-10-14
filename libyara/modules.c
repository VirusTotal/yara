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

#include <yara/exec.h>
#include <yara/libyara.h>
#include <yara/modules.h>

#define MODULE(name)                             \
  int name##__declarations(YR_OBJECT* module);   \
  int name##__load(                              \
      YR_SCAN_CONTEXT* context,                  \
      YR_OBJECT* module,                         \
      void* module_data,                         \
      size_t module_data_size);                  \
  int name##__unload(YR_OBJECT* main_structure); \
  int name##__initialize(YR_MODULE* module);     \
  int name##__finalize(YR_MODULE* module);

#include <modules/module_list>

#undef MODULE

#define MODULE(name)     \
  {#name,                \
   name##__declarations, \
   name##__load,         \
   name##__unload,       \
   name##__initialize,   \
   name##__finalize},

YR_MODULE yr_modules_table[] = {
#include <modules/module_list>
    {NULL, NULL, NULL, NULL, NULL, NULL}};

#undef MODULE

int yr_modules_initialize()
{
  for (YR_MODULE* module = yr_modules_table; module->initialize != NULL;
       module++)
  {
    int result = module->initialize(module);

    if (result != ERROR_SUCCESS)
      return result;
  }

  return ERROR_SUCCESS;
}

int yr_modules_finalize()
{
  for (YR_MODULE* module = yr_modules_table; module->finalize != NULL; module++)
  {
    int result = module->finalize(module);

    if (result != ERROR_SUCCESS)
      return result;
  }

  return ERROR_SUCCESS;
}

int yr_modules_do_declarations(
    const char* module_name,
    YR_OBJECT* main_structure)
{
  for (YR_MODULE* module = yr_modules_table;
       module->name != NULL && module->declarations != NULL;
       module++)
  {
    if (strcmp(module->name, module_name) == 0)
      return module->declarations(main_structure);
  }

  return ERROR_UNKNOWN_MODULE;
}

int yr_modules_load(const char* module_name, YR_SCAN_CONTEXT* context)
{
  int result;

  YR_MODULE_IMPORT mi;

  YR_OBJECT* module_structure = (YR_OBJECT*) yr_hash_table_lookup(
      context->objects_table, module_name, NULL);

  // if module_structure != NULL, the module was already
  // loaded, return successfully without doing nothing.

  if (module_structure != NULL)
    return ERROR_SUCCESS;

  // not loaded yet

  FAIL_ON_ERROR(yr_object_create(
      OBJECT_TYPE_STRUCTURE, module_name, NULL, &module_structure));

  // initialize canary for module's top-level structure, every other object
  // within the module inherits the same canary.
  yr_object_set_canary(module_structure, context->canary);

  mi.module_name = module_name;
  mi.module_data = NULL;
  mi.module_data_size = 0;

  result = context->callback(
      context, CALLBACK_MSG_IMPORT_MODULE, &mi, context->user_data);

  if (result == CALLBACK_ERROR)
  {
    yr_object_destroy(module_structure);
    return ERROR_CALLBACK_ERROR;
  }

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_modules_do_declarations(module_name, module_structure),
      yr_object_destroy(module_structure));

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_hash_table_add(
          context->objects_table, module_name, NULL, module_structure),
      yr_object_destroy(module_structure));

  for (YR_MODULE* module = yr_modules_table;
       module->name != NULL && module->load != NULL;
       module++)
  {
    if (strcmp(module->name, module_name) == 0)
    {
      result = module->load(
          context, module_structure, mi.module_data, mi.module_data_size);

      if (result != ERROR_SUCCESS)
        return result;
    }
  }

  result = context->callback(
      context,
      CALLBACK_MSG_MODULE_IMPORTED,
      module_structure,
      context->user_data);

  if (result == CALLBACK_ERROR)
    return ERROR_CALLBACK_ERROR;

  return ERROR_SUCCESS;
}

int yr_modules_unload_all(YR_SCAN_CONTEXT* context)
{
  for (YR_MODULE* module = yr_modules_table;
       module->name != NULL && module->unload != NULL;
       module++)
  {
    YR_OBJECT* module_structure = (YR_OBJECT*) yr_hash_table_remove(
        context->objects_table, module->name, NULL);

    if (module_structure != NULL)
    {
      module->unload(module_structure);
      yr_object_destroy(module_structure);
    }
  }

  return ERROR_SUCCESS;
}

YR_MODULE* yr_modules_get_table(void)
{
  return yr_modules_table;
}