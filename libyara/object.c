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


#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include <yara/mem.h>
#include <yara/error.h>
#include <yara/object.h>
#include <yara/exec.h>
#include <yara/utils.h>


int yr_object_create(
    int8_t type,
    const char* identifier,
    YR_OBJECT* parent,
    YR_OBJECT** object)
{
  YR_OBJECT* obj;
  size_t object_size;

  switch (type)
  {
    case OBJECT_TYPE_STRUCTURE:
      object_size = sizeof(YR_OBJECT_STRUCTURE);
      break;
    case OBJECT_TYPE_ARRAY:
      object_size = sizeof(YR_OBJECT_ARRAY);
      break;
    case OBJECT_TYPE_INTEGER:
      object_size = sizeof(YR_OBJECT_INTEGER);
      break;
    case OBJECT_TYPE_STRING:
      object_size = sizeof(YR_OBJECT_STRING);
      break;
    case OBJECT_TYPE_FUNCTION:
      object_size = sizeof(YR_OBJECT_FUNCTION);
      break;
    case OBJECT_TYPE_REGEXP:
      object_size = sizeof(YR_OBJECT_REGEXP);
      break;
    default:
      assert(FALSE);
  }

  obj = (YR_OBJECT*) yr_malloc(object_size);

  if (obj == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  obj->type = type;
  obj->identifier = yr_strdup(identifier);
  obj->parent = parent;
  obj->data = NULL;

  if (obj->identifier == NULL)
  {
    yr_free(obj);
    return ERROR_INSUFICIENT_MEMORY;
  }

  switch(type)
  {
    case OBJECT_TYPE_STRUCTURE:
      ((YR_OBJECT_STRUCTURE*) obj)->members = NULL;
      break;
    case OBJECT_TYPE_ARRAY:
      ((YR_OBJECT_ARRAY*) obj)->items = NULL;
      break;
    case OBJECT_TYPE_INTEGER:
      ((YR_OBJECT_INTEGER*) obj)->value = UNDEFINED;
      break;
    case OBJECT_TYPE_STRING:
      ((YR_OBJECT_STRING*) obj)->value = NULL;
      break;
    case OBJECT_TYPE_REGEXP:
      ((YR_OBJECT_REGEXP*) obj)->value = NULL;
      break;
    case OBJECT_TYPE_FUNCTION:
      ((YR_OBJECT_FUNCTION*) obj)->arguments_fmt = NULL;
      ((YR_OBJECT_FUNCTION*) obj)->return_obj = NULL;
      break;
  }

  if (parent != NULL)
  {
    assert( parent->type == OBJECT_TYPE_STRUCTURE ||
            parent->type == OBJECT_TYPE_ARRAY ||
            parent->type == OBJECT_TYPE_FUNCTION);

    switch(parent->type)
    {
      case OBJECT_TYPE_STRUCTURE:
        FAIL_ON_ERROR_WITH_CLEANUP(
            yr_object_structure_set_member(parent, obj),
            yr_free(obj));
        break;

      case OBJECT_TYPE_ARRAY:
        FAIL_ON_ERROR_WITH_CLEANUP(
            yr_object_array_set_item(parent, obj, 0),
            yr_free(obj));
        break;
    }
  }

  if (object != NULL)
    *object = obj;

  return ERROR_SUCCESS;
}


int yr_object_function_create(
    const char* identifier,
    const char* arguments_fmt,
    const char* return_fmt,
    YR_MODULE_FUNC code,
    YR_OBJECT* parent,
    YR_OBJECT** function)
{
  YR_OBJECT* return_obj;
  YR_OBJECT* f;

  int8_t return_type;

  switch (*return_fmt)
  {
    case 'i':
      return_type = OBJECT_TYPE_INTEGER;
      break;
    case 's':
      return_type = OBJECT_TYPE_STRING;
      break;
    default:
      return ERROR_INVALID_FORMAT;
  }

  FAIL_ON_ERROR(yr_object_create(
      OBJECT_TYPE_FUNCTION,
      identifier,
      parent,
      &f));

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_object_create(return_type, "result", f, &return_obj),
      yr_object_destroy(f));

  ((YR_OBJECT_FUNCTION* )f)->arguments_fmt = arguments_fmt;
  ((YR_OBJECT_FUNCTION* )f)->return_obj = return_obj;
  ((YR_OBJECT_FUNCTION* )f)->code = code;

  if (function != NULL)
    *function = f;

  return ERROR_SUCCESS;
}


int yr_object_from_external_variable(
    YR_EXTERNAL_VARIABLE* external,
    YR_OBJECT** object)
{
  YR_OBJECT* obj;
  int result;
  uint8_t obj_type = 0;

  switch(external->type)
  {
    case EXTERNAL_VARIABLE_TYPE_INTEGER:
    case EXTERNAL_VARIABLE_TYPE_BOOLEAN:
      obj_type = OBJECT_TYPE_INTEGER;
      break;

    case EXTERNAL_VARIABLE_TYPE_STRING:
    case EXTERNAL_VARIABLE_TYPE_MALLOC_STRING:
      obj_type = OBJECT_TYPE_STRING;
      break;

    default:
      assert(FALSE);
  }

  result = yr_object_create(
      obj_type,
      external->identifier,
      NULL,
      &obj);

  if (result == ERROR_SUCCESS)
  {
    switch(external->type)
    {
      case EXTERNAL_VARIABLE_TYPE_INTEGER:
      case EXTERNAL_VARIABLE_TYPE_BOOLEAN:
        yr_object_set_integer(external->integer, obj, NULL);
        break;

      case EXTERNAL_VARIABLE_TYPE_STRING:
      case EXTERNAL_VARIABLE_TYPE_MALLOC_STRING:
        yr_object_set_string(external->string, obj, NULL);
        break;
    }

    *object = obj;
  }

  return result;
}


void yr_object_destroy(
    YR_OBJECT* object)
{
  YR_STRUCTURE_MEMBER* member;
  YR_STRUCTURE_MEMBER* next_member;
  YR_ARRAY_ITEMS* array_items;

  RE* re;
  int i;
  char* str;

  switch(object->type)
  {
    case OBJECT_TYPE_STRUCTURE:
      member = ((YR_OBJECT_STRUCTURE*) object)->members;

      while (member != NULL)
      {
        next_member = member->next;
        yr_object_destroy(member->object);
        yr_free(member);
        member = next_member;
      }
      break;

    case OBJECT_TYPE_STRING:
      str = ((YR_OBJECT_STRING*) object)->value;
      if (str != NULL)
        yr_free(str);
      break;

    case OBJECT_TYPE_REGEXP:
      re = ((YR_OBJECT_REGEXP*) object)->value;
      if (re != NULL)
        yr_re_destroy(re);
      break;

    case OBJECT_TYPE_ARRAY:
      array_items = ((YR_OBJECT_ARRAY*) object)->items;

      for (i = 0; i < array_items->count; i++)
        if (array_items->objects[i] != NULL)
          yr_object_destroy(array_items->objects[i]);

      yr_free(array_items);
      break;

    case OBJECT_TYPE_FUNCTION:
      yr_object_destroy(((YR_OBJECT_FUNCTION*) object)->return_obj);
      break;
  }

  yr_free((void*) object->identifier);
  yr_free(object);
}


YR_OBJECT* yr_object_lookup_field(
    YR_OBJECT* object,
    const char* field_name)
{
  YR_STRUCTURE_MEMBER* member;

  assert(object != NULL);
  assert(object->type == OBJECT_TYPE_STRUCTURE);

  member = ((YR_OBJECT_STRUCTURE*) object)->members;

  while (member != NULL)
  {
    if (strcmp(member->object->identifier, field_name) == 0)
      return member->object;

    member = member->next;
  }

  return NULL;
}


YR_OBJECT* _yr_object_lookup(
    YR_OBJECT* object,
    int flags,
    const char* pattern,
    va_list args)
{
  YR_OBJECT* obj = object;

  const char* p = pattern;
  char field_name[256];

  int i;
  int index;

  while (obj != NULL)
  {
    i = 0;

    while(*p != '\0' && *p != '.' && *p != '[')
    {
      field_name[i++] = *p++;
    }

    field_name[i] = '\0';

    if (obj->type != OBJECT_TYPE_STRUCTURE)
      return NULL;

    obj = yr_object_lookup_field(obj, field_name);

    if (obj == NULL)
      return NULL;

    if (*p == '[')
    {
      p++;

      if (*p == '%')
      {
        if (*++p == 'i')
        {
          index = va_arg(args, int);
          p++;
        }
        else
        {
          return NULL;
        }
      }
      else if (*p >= '0' && *p <= '9')
      {
        index = strtol(p, (char**) &p, 10);
      }
      else
      {
        return NULL;
      }

      assert(*p++ == ']');
      assert(*p == '.' || *p == '\0');

      obj = yr_object_array_get_item(obj, flags, index);
    }

    if (*p == '\0')
      break;

    p++;
  }

  return obj;
}


YR_OBJECT* yr_object_lookup(
    YR_OBJECT* object,
    int flags,
    const char* pattern,
    ...)
{
  YR_OBJECT* result;

  va_list args;
  va_start(args, pattern);

  result = _yr_object_lookup(object, flags, pattern, args);

  va_end(args);

  return result;

}


int yr_object_copy(
    YR_OBJECT* object,
    YR_OBJECT** object_copy)
{
  YR_OBJECT* copy;
  YR_OBJECT* o;

  YR_ARRAY_ITEMS* array_items;
  YR_STRUCTURE_MEMBER* structure_member;

  int i;

  *object_copy = NULL;

  FAIL_ON_ERROR(yr_object_create(
      object->type,
      object->identifier,
      NULL,
      &copy));

  switch(object->type)
  {
    case OBJECT_TYPE_INTEGER:
      ((YR_OBJECT_INTEGER*) copy)->value = UNDEFINED;
      break;

    case OBJECT_TYPE_STRING:
      ((YR_OBJECT_STRING*) copy)->value = NULL;
      break;

    case OBJECT_TYPE_REGEXP:
      ((YR_OBJECT_REGEXP*) copy)->value = NULL;
      break;

    case OBJECT_TYPE_STRUCTURE:

      structure_member = ((YR_OBJECT_STRUCTURE*) object)->members;

      while (structure_member != NULL)
      {
        FAIL_ON_ERROR_WITH_CLEANUP(
            yr_object_copy(structure_member->object, &o),
            yr_object_destroy(copy));

        FAIL_ON_ERROR_WITH_CLEANUP(
            yr_object_structure_set_member(copy, o),
            yr_free(o);
            yr_object_destroy(copy));

        structure_member = structure_member->next;
      }

      break;

    case OBJECT_TYPE_ARRAY:

      array_items = ((YR_OBJECT_ARRAY*) object)->items;

      for (i = 0; i < array_items->count; i++)
      {
        if (array_items->objects[i] != NULL)
        {
          FAIL_ON_ERROR_WITH_CLEANUP(
              yr_object_copy(array_items->objects[i], &o),
              yr_object_destroy(copy));

          FAIL_ON_ERROR_WITH_CLEANUP(
                yr_object_array_set_item(copy, o, i),
                yr_free(o);
                yr_object_destroy(copy));
        }
      }

      break;
  }

  *object_copy = copy;

  return ERROR_SUCCESS;
}


int yr_object_structure_set_member(
    YR_OBJECT* object,
    YR_OBJECT* member)
{
  YR_STRUCTURE_MEMBER* sm;

  assert(object->type == OBJECT_TYPE_STRUCTURE);

  // Check if the object already have a member with the same identifier

  if (yr_object_lookup_field(object,  member->identifier) != NULL)
    return ERROR_DUPLICATED_STRUCTURE_MEMBER;

  sm = yr_malloc(sizeof(YR_STRUCTURE_MEMBER));

  if (sm == NULL)
    return ERROR_INSUFICIENT_MEMORY;

  member->parent = object;
  sm->object = member;
  sm->next = ((YR_OBJECT_STRUCTURE*) object)->members;

  ((YR_OBJECT_STRUCTURE*) object)->members = sm;

  return ERROR_SUCCESS;
}


YR_OBJECT* yr_object_array_get_item(
    YR_OBJECT* object,
    int flags,
    int index)
{
  YR_OBJECT* result = NULL;
  YR_ARRAY_ITEMS* array_items;

  assert(object->type == OBJECT_TYPE_ARRAY);

  array_items = ((YR_OBJECT_ARRAY*) object)->items;

  assert(array_items != NULL);

  if (array_items->count > index)
    result = array_items->objects[index];

  if (result == NULL && flags & OBJECT_CREATE)
  {
    yr_object_copy(array_items->objects[0], &result);

    if (result != NULL)
      yr_object_array_set_item(object, result, index);
  }

  return result;
}


int yr_object_array_set_item(
    YR_OBJECT* object,
    YR_OBJECT* item,
    int index)
{
  YR_OBJECT_ARRAY* array;

  int i;
  int count;

  assert(object->type == OBJECT_TYPE_ARRAY);

  array = ((YR_OBJECT_ARRAY*) object);

  if (array->items == NULL)
  {
    count = max(64, (index + 1) * 2);

    array->items = yr_malloc(
        sizeof(YR_ARRAY_ITEMS) + count * sizeof(YR_OBJECT*));

    if (array->items == NULL)
      return ERROR_INSUFICIENT_MEMORY;

    memset(array->items->objects, 0, count * sizeof(YR_OBJECT*));

    array->items->count = count;
  }
  else if (index >= array->items->count)
  {
    count = array->items->count * 2;
    array->items = yr_realloc(
        array->items,
        sizeof(YR_ARRAY_ITEMS) + count * sizeof(YR_OBJECT*));

    if (array->items == NULL)
      return ERROR_INSUFICIENT_MEMORY;

    for (i = array->items->count; i < count; i++)
      array->items->objects[i] = NULL;

    array->items->count = count;
  }

  item->parent = object;
  array->items->objects[index] = item;

  return ERROR_SUCCESS;
}


int64_t yr_object_get_integer(
    YR_OBJECT* object,
    char* field,
    ...)
{
  YR_OBJECT* integer_obj;

  va_list args;
  va_start(args, field);

  if (field != NULL)
    integer_obj = _yr_object_lookup(object, 0, field, args);
  else
    integer_obj = object;

  va_end(args);

  if (integer_obj == NULL)
    return UNDEFINED;

  assertf(integer_obj->type == OBJECT_TYPE_INTEGER,
          "type of \"%s\" is not integer\n", field);

  return ((YR_OBJECT_INTEGER*) integer_obj)->value;
}


char* yr_object_get_string(
    YR_OBJECT* object,
    char* field,
    ...)
{
  YR_OBJECT* string_obj;

  va_list args;
  va_start(args, field);

  if (field != NULL)
    string_obj = _yr_object_lookup(object, 0, field, args);
  else
    string_obj = object;

  va_end(args);

  if (string_obj == NULL)
    return NULL;

  assertf(string_obj->type == OBJECT_TYPE_STRING,
          "type of \"%s\" is not string\n", field);

  return ((YR_OBJECT_STRING*) string_obj)->value;
}


void yr_object_set_integer(
    int64_t value,
    YR_OBJECT* object,
    char* field,
    ...)
{
  YR_OBJECT* integer_obj;

  va_list args;
  va_start(args, field);

  if (field != NULL)
    integer_obj = _yr_object_lookup(
        object, OBJECT_CREATE, field, args);
  else
    integer_obj = object;

  va_end(args);

  assert(integer_obj != NULL);
  assert(integer_obj->type == OBJECT_TYPE_INTEGER);

  ((YR_OBJECT_INTEGER*) integer_obj)->value = value;
}


void yr_object_set_string(
    char* value,
    YR_OBJECT* object,
    char* field,
    ...)
{
  YR_OBJECT_STRING* string_obj;

  va_list args;
  va_start(args, field);

  if (field != NULL)
    string_obj = (YR_OBJECT_STRING*) _yr_object_lookup(
        object, OBJECT_CREATE, field, args);
  else
    string_obj = (YR_OBJECT_STRING*) object;

  va_end(args);

  assert(string_obj != NULL);
  assert(string_obj->type == OBJECT_TYPE_STRING);

  if (string_obj->value != NULL)
    yr_free(string_obj->value);

  string_obj->value = yr_strdup(value);
}


YR_OBJECT* yr_object_get_root(
    YR_OBJECT* object)
{
  YR_OBJECT* o = object;

  while (o->parent != NULL)
    o = o->parent;

  return o;
}
