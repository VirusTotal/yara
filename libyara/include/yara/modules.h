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

#ifndef YR_MODULES_H
#define YR_MODULES_H

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <yara/utils.h>
#include <yara/limits.h>
#include <yara/error.h>
#include <yara/exec.h>
#include <yara/types.h>
#include <yara/object.h>

// Concatenation that macro-expands its arguments.

#define CONCAT(arg1, arg2) _CONCAT(arg1, arg2) // expands the arguments.
#define _CONCAT(arg1, arg2) arg1 ## arg2       // do the actual concatenation.


#define module_declarations CONCAT(MODULE_NAME, _declarations)
#define module_load CONCAT(MODULE_NAME, _load)
#define module_unload CONCAT(MODULE_NAME, _unload)


#define begin_declarations \
    int module_declarations(YR_OBJECT* module) { \
      YR_OBJECT* stack[64]; \
      int stack_top = 0; \
      stack[stack_top] = module;


#define end_declarations \
    return ERROR_SUCCESS; }


#define begin_struct(name) { \
    YR_OBJECT* structure; \
    FAIL_ON_ERROR(yr_object_create( \
        OBJECT_TYPE_STRUCTURE, \
        name, \
        stack[stack_top], \
        &structure)); \
    assertf( \
        stack_top < sizeof(stack)/sizeof(stack[0]) - 1, \
        "too many nested structures"); \
    stack[++stack_top] = structure; \
  }


#define begin_struct_array(name) { \
    YR_OBJECT* structure; \
    YR_OBJECT* array; \
    FAIL_ON_ERROR(yr_object_create( \
        OBJECT_TYPE_ARRAY, \
        name, \
        stack[stack_top], \
        &array)); \
    FAIL_ON_ERROR(yr_object_create( \
        OBJECT_TYPE_STRUCTURE, \
        name, \
        array, \
        &structure)); \
    assertf( \
        stack_top < sizeof(stack)/sizeof(stack[0]) - 1, \
        "too many nested structures"); \
    stack[++stack_top] = structure; \
  }


#define end_struct(name) { \
    assert(stack[stack_top]->type == OBJECT_TYPE_STRUCTURE); \
    assertf( \
        strcmp(stack[stack_top]->identifier, name) == 0, \
        "unbalanced begin_struct/end_struct"); \
    stack_top--; \
  }


#define end_struct_array(name) end_struct(name)


#define declare_integer(name) { \
    FAIL_ON_ERROR(yr_object_create( \
        OBJECT_TYPE_INTEGER, \
        name, \
        stack[stack_top], \
        NULL)); \
  }


#define declare_integer_array(name) { \
    YR_OBJECT* array; \
    FAIL_ON_ERROR(yr_object_create( \
        OBJECT_TYPE_ARRAY, \
        name, \
        stack[stack_top], \
        &array)); \
    FAIL_ON_ERROR(yr_object_create( \
        OBJECT_TYPE_INTEGER, \
        name, \
        array, \
        NULL)); \
  }


#define declare_string(name) { \
    FAIL_ON_ERROR(yr_object_create( \
        OBJECT_TYPE_STRING, \
        name, \
        stack[stack_top], \
        NULL)); \
  }


#define declare_string_array(name) { \
    YR_OBJECT* array; \
    FAIL_ON_ERROR(yr_object_create( \
        OBJECT_TYPE_ARRAY, \
        name, \
        stack[stack_top], \
        &array)); \
    FAIL_ON_ERROR(yr_object_create( \
        OBJECT_TYPE_STRING, \
        name, \
        array, \
        NULL)); \
  }


#define declare_function(name, args_fmt, ret_fmt, func) { \
    YR_OBJECT* function; \
    FAIL_ON_ERROR(yr_object_function_create( \
        name, \
        args_fmt, \
        ret_fmt, \
        func, \
        stack[stack_top], \
        &function)); \
    }


#define define_function(func) \
    int func ( \
        void* __args, \
        YR_SCAN_CONTEXT* __context, \
        YR_OBJECT_FUNCTION* __function_obj)


#define integer_argument(n)  (((int64_t*) __args)[n-1])
#define string_argument(n)   ((char*)((int64_t*) __args)[n-1])
#define regexp_argument(n)   ((RE_CODE)((int64_t*) __args)[n-1])


#define module()        yr_object_get_root((YR_OBJECT*) __function_obj)
#define parent()        (__function_obj->parent)
#define scan_context()  (__context)


#define foreach_memory_block(context, block) \
  for (block = (context)->mem_block; \
       block != NULL; \
       block = block->next) \


#define first_memory_block(context) \
      (context)->mem_block


#define get_object(object, ...) \
    yr_object_lookup(object, 0, __VA_ARGS__)


#define get_integer(object, ...) \
    yr_object_get_integer(object, __VA_ARGS__)


#define get_string(object, ...) \
    yr_object_get_string(object, __VA_ARGS__)


#define set_integer(value, object, ...) \
    yr_object_set_integer(value, object, __VA_ARGS__)


#define set_string(value, object, ...) \
    yr_object_set_string(value, object, __VA_ARGS__)


#define return_integer(integer) { \
      assertf( \
          __function_obj->return_obj->type == OBJECT_TYPE_INTEGER, \
          "return type differs from function declaration"); \
      yr_object_set_integer( \
          (integer), \
          __function_obj->return_obj, \
          NULL); \
      return ERROR_SUCCESS; \
    }


#define return_string(string) { \
      assertf( \
          __function_obj->return_obj->type == OBJECT_TYPE_STRING, \
          "return type differs from function declaration"); \
      yr_object_set_string( \
          ((string) != UNDEFINED) ? (string) : NULL, \
          __function_obj->return_obj, \
          NULL); \
      return ERROR_SUCCESS; \
    }


typedef int (*YR_EXT_DECLARATIONS_FUNC)( \
    YR_OBJECT* module);


typedef int (*YR_EXT_LOAD_FUNC)( \
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module,
    void* module_data,
    size_t module_data_size);



typedef int (*YR_EXT_UNLOAD_FUNC)( \
    YR_OBJECT* module);


typedef struct _YR_MODULE
{
  tidx_mask_t is_loaded;

  char* name;

  YR_EXT_DECLARATIONS_FUNC declarations;
  YR_EXT_LOAD_FUNC load;
  YR_EXT_UNLOAD_FUNC unload;

} YR_MODULE;


typedef struct _YR_MODULE_IMPORT
{
  const char* module_name;
  void* module_data;
  size_t module_data_size;

} YR_MODULE_IMPORT;



int yr_modules_do_declarations(
    const char* module_name,
    YR_OBJECT* main_structure);


int yr_modules_load(
    const char* module_name,
    YR_SCAN_CONTEXT* context);


int yr_modules_unload_all(
    YR_SCAN_CONTEXT* context);


#endif
