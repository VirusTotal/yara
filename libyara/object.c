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


#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <yara/globals.h>
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
  int i;
  size_t object_size = 0;

  assert(parent != NULL || object != NULL);

  switch (type)
  {
    case OBJECT_TYPE_STRUCTURE:
      object_size = sizeof(YR_OBJECT_STRUCTURE);
      break;
    case OBJECT_TYPE_ARRAY:
      object_size = sizeof(YR_OBJECT_ARRAY);
      break;
    case OBJECT_TYPE_DICTIONARY:
      object_size = sizeof(YR_OBJECT_DICTIONARY);
      break;
    case OBJECT_TYPE_INTEGER:
      object_size = sizeof(YR_OBJECT);
      break;
    case OBJECT_TYPE_FLOAT:
      object_size = sizeof(YR_OBJECT);
      break;
    case OBJECT_TYPE_STRING:
      object_size = sizeof(YR_OBJECT);
      break;
    case OBJECT_TYPE_FUNCTION:
      object_size = sizeof(YR_OBJECT_FUNCTION);
      break;
    default:
      assert(false);
  }

  obj = (YR_OBJECT*) yr_malloc(object_size);

  if (obj == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  obj->canary = yr_canary;
  obj->type = type;
  obj->identifier = yr_strdup(identifier);
  obj->parent = parent;
  obj->data = NULL;

  switch(type)
  {
    case OBJECT_TYPE_INTEGER:
      obj->value.i = UNDEFINED;
      break;
    case OBJECT_TYPE_FLOAT:
      obj->value.d = NAN;
      break;
    case OBJECT_TYPE_STRING:
      obj->value.ss = NULL;
      break;
    case OBJECT_TYPE_STRUCTURE:
      object_as_structure(obj)->members = NULL;
      break;
    case OBJECT_TYPE_ARRAY:
      object_as_array(obj)->items = NULL;
      object_as_array(obj)->prototype_item = NULL;
      break;
    case OBJECT_TYPE_DICTIONARY:
      object_as_dictionary(obj)->items = NULL;
      object_as_dictionary(obj)->prototype_item = NULL;
      break;
    case OBJECT_TYPE_FUNCTION:
      object_as_function(obj)->return_obj = NULL;
      for (i = 0; i < YR_MAX_OVERLOADED_FUNCTIONS; i++)
      {
        object_as_function(obj)->prototypes[i].arguments_fmt = NULL;
        object_as_function(obj)->prototypes[i].code = NULL;
      }
      break;
  }

  if (obj->identifier == NULL)
  {
    yr_free(obj);
    return ERROR_INSUFFICIENT_MEMORY;
  }

  if (parent != NULL)
  {
    assert(parent->type == OBJECT_TYPE_STRUCTURE ||
           parent->type == OBJECT_TYPE_ARRAY ||
           parent->type == OBJECT_TYPE_DICTIONARY ||
           parent->type == OBJECT_TYPE_FUNCTION);

    switch(parent->type)
    {
      case OBJECT_TYPE_STRUCTURE:
        FAIL_ON_ERROR_WITH_CLEANUP(
            yr_object_structure_set_member(parent, obj),
            {
              yr_free((void*) obj->identifier);
              yr_free(obj);
            });
        break;

      case OBJECT_TYPE_ARRAY:
        object_as_array(parent)->prototype_item = obj;
        break;

      case OBJECT_TYPE_DICTIONARY:
        object_as_dictionary(parent)->prototype_item = obj;
        break;

      case OBJECT_TYPE_FUNCTION:
        object_as_function(parent)->return_obj = obj;
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
  YR_OBJECT* o = NULL;
  YR_OBJECT_FUNCTION* f = NULL;

  int8_t return_type;
  int i;

  switch (*return_fmt)
  {
    case 'i':
      return_type = OBJECT_TYPE_INTEGER;
      break;
    case 's':
      return_type = OBJECT_TYPE_STRING;
      break;
    case 'f':
      return_type = OBJECT_TYPE_FLOAT;
      break;
    default:
      return ERROR_INVALID_FORMAT;
  }

  if (parent != NULL)
  {
    // The parent of a function must be a structure.

    assert(parent->type == OBJECT_TYPE_STRUCTURE);

    // Try to find if the structure already has a function
    // with that name. In that case this is a function overload.

    f = object_as_function(yr_object_lookup_field(parent, identifier));

    // Overloaded functions must have the same return type.

    if (f != NULL && return_type != f->return_obj->type)
      return ERROR_WRONG_RETURN_TYPE;
  }

  if (f == NULL) // Function doesn't exist yet
  {
    FAIL_ON_ERROR(
        yr_object_create(
            OBJECT_TYPE_FUNCTION,
            identifier,
            parent,
            &o));

    FAIL_ON_ERROR_WITH_CLEANUP(
        yr_object_create(
            return_type,
            "result",
            o,
            &return_obj),
        yr_object_destroy(o));

    f = object_as_function(o);
  }

  for (i = 0; i < YR_MAX_OVERLOADED_FUNCTIONS; i++)
  {
    if (f->prototypes[i].arguments_fmt == NULL)
    {
      f->prototypes[i].arguments_fmt = arguments_fmt;
      f->prototypes[i].code = code;

      break;
    }
  }

  if (function != NULL)
    *function = (YR_OBJECT*) f;

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

    case EXTERNAL_VARIABLE_TYPE_FLOAT:
      obj_type = OBJECT_TYPE_FLOAT;
      break;

    case EXTERNAL_VARIABLE_TYPE_STRING:
    case EXTERNAL_VARIABLE_TYPE_MALLOC_STRING:
      obj_type = OBJECT_TYPE_STRING;
      break;

    default:
      assert(false);
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
        result = yr_object_set_integer(external->value.i, obj, NULL);
        break;

      case EXTERNAL_VARIABLE_TYPE_FLOAT:
        result = yr_object_set_float(external->value.f, obj, NULL);
        break;

      case EXTERNAL_VARIABLE_TYPE_STRING:
      case EXTERNAL_VARIABLE_TYPE_MALLOC_STRING:
        result = yr_object_set_string(
            external->value.s, strlen(external->value.s), obj, NULL);
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
  YR_DICTIONARY_ITEMS* dict_items;

  int i;

  if (object == NULL)
    return;

  switch(object->type)
  {
    case OBJECT_TYPE_STRUCTURE:
      member = object_as_structure(object)->members;

      while (member != NULL)
      {
        next_member = member->next;
        yr_object_destroy(member->object);
        yr_free(member);
        member = next_member;
      }
      break;

    case OBJECT_TYPE_STRING:
      if (object->value.ss != NULL)
        yr_free(object->value.ss);
      break;

    case OBJECT_TYPE_ARRAY:
      if (object_as_array(object)->prototype_item != NULL)
        yr_object_destroy(object_as_array(object)->prototype_item);

      array_items = object_as_array(object)->items;

      if (array_items != NULL)
      {
        for (i = 0; i < array_items->count; i++)
          if (array_items->objects[i] != NULL)
            yr_object_destroy(array_items->objects[i]);
      }

      yr_free(array_items);
      break;

    case OBJECT_TYPE_DICTIONARY:
      if (object_as_dictionary(object)->prototype_item != NULL)
        yr_object_destroy(object_as_dictionary(object)->prototype_item);

      dict_items = object_as_dictionary(object)->items;

      if (dict_items != NULL)
      {
        for (i = 0; i < dict_items->used; i++)
        {
          if (dict_items->objects[i].key != NULL)
            yr_free(dict_items->objects[i].key);

          if (dict_items->objects[i].obj != NULL)
            yr_object_destroy(dict_items->objects[i].obj);
        }
      }

      yr_free(dict_items);
      break;

    case OBJECT_TYPE_FUNCTION:
      yr_object_destroy(object_as_function(object)->return_obj);
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

  member = object_as_structure(object)->members;

  while (member != NULL)
  {
    if (strcmp(member->object->identifier, field_name) == 0)
      return member->object;

    member = member->next;
  }

  return NULL;
}


static YR_OBJECT* _yr_object_lookup(
    YR_OBJECT* object,
    int flags,
    const char* pattern,
    va_list args)
{
  YR_OBJECT* obj = object;

  const char* p = pattern;
  const char* key = NULL;

  char str[256];

  int i;
  int index = -1;

  while (obj != NULL)
  {
    i = 0;

    while (*p != '\0' && *p != '.' && *p != '[' && i < sizeof(str) - 1)
    {
      str[i++] = *p++;
    }

    str[i] = '\0';

    if (obj->type != OBJECT_TYPE_STRUCTURE)
      return NULL;

    obj = yr_object_lookup_field(obj, str);

    if (obj == NULL)
      return NULL;

    if (*p == '[')
    {
      p++;

      if (*p == '%')
      {
        p++;

        switch(*p++)
        {
          case 'i':
            index = va_arg(args, int);
            break;
          case 's':
            key = va_arg(args, const char*);
            break;

          default:
            return NULL;
        }
      }
      else if (*p >= '0' && *p <= '9')
      {
        index = (int) strtol(p, (char**) &p, 10);
      }
      else if (*p == '"')
      {
        i = 0;
        p++;              // skip the opening quotation mark

        while (*p != '"' && *p != '\0' && i < sizeof(str) - 1)
          str[i++] = *p++;

        str[i] = '\0';
        p++;              // skip the closing quotation mark
        key = str;
      }
      else
      {
        return NULL;
      }

      assert(*p == ']');
      p++;
      assert(*p == '.' || *p == '\0');

      switch(obj->type)
      {
        case OBJECT_TYPE_ARRAY:
          assert(index != -1);
          obj = yr_object_array_get_item(obj, flags, index);
          break;

        case OBJECT_TYPE_DICTIONARY:
          assert(key != NULL);
          obj = yr_object_dict_get_item(obj, flags, key);
          break;
      }
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
      copy->value.i = object->value.i;
      break;

    case OBJECT_TYPE_FLOAT:
      copy->value.d = object->value.d;
      break;

    case OBJECT_TYPE_STRING:

      if (object->value.ss != NULL)
        copy->value.ss = sized_string_dup(object->value.ss);
      else
        copy->value.ss = NULL;

      break;

    case OBJECT_TYPE_FUNCTION:

      FAIL_ON_ERROR_WITH_CLEANUP(
          yr_object_copy(
              object_as_function(object)->return_obj,
              &object_as_function(copy)->return_obj),
          yr_object_destroy(copy));

      for (i = 0; i < YR_MAX_OVERLOADED_FUNCTIONS; i++)
        object_as_function(copy)->prototypes[i] = \
            object_as_function(object)->prototypes[i];

      break;

    case OBJECT_TYPE_STRUCTURE:

      structure_member = object_as_structure(object)->members;

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

      FAIL_ON_ERROR_WITH_CLEANUP(
          yr_object_copy(object_as_array(object)->prototype_item, &o),
          yr_object_destroy(copy));

      object_as_array(copy)->prototype_item = o;

      break;

    case OBJECT_TYPE_DICTIONARY:

      FAIL_ON_ERROR_WITH_CLEANUP(
          yr_object_copy(object_as_dictionary(object)->prototype_item, &o),
          yr_object_destroy(copy));

      object_as_dictionary(copy)->prototype_item = o;

      break;

    default:
      assert(false);

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

  sm = (YR_STRUCTURE_MEMBER*) yr_malloc(sizeof(YR_STRUCTURE_MEMBER));

  if (sm == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  member->parent = object;
  sm->object = member;
  sm->next = object_as_structure(object)->members;

  object_as_structure(object)->members = sm;

  return ERROR_SUCCESS;
}


YR_OBJECT* yr_object_array_get_item(
    YR_OBJECT* object,
    int flags,
    int index)
{
  YR_OBJECT* result = NULL;
  YR_OBJECT_ARRAY* array;

  assert(object->type == OBJECT_TYPE_ARRAY);

  if (index < 0)
    return NULL;

  array = object_as_array(object);

  if (array->items != NULL && array->items->count > index)
      result = array->items->objects[index];

  if (result == NULL && flags & OBJECT_CREATE)
  {
    yr_object_copy(array->prototype_item, &result);

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

  assert(index >= 0);
  assert(object->type == OBJECT_TYPE_ARRAY);

  array = object_as_array(object);

  if (array->items == NULL)
  {
    count = 64;

    while (count <= index)
      count *= 2;

    array->items = (YR_ARRAY_ITEMS*) yr_malloc(
        sizeof(YR_ARRAY_ITEMS) + count * sizeof(YR_OBJECT*));

    if (array->items == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    memset(array->items->objects, 0, count * sizeof(YR_OBJECT*));

    array->items->count = count;
  }
  else if (index >= array->items->count)
  {
    count = array->items->count * 2;

    while (count <= index)
      count *= 2;

    array->items = (YR_ARRAY_ITEMS*) yr_realloc(
        array->items,
        sizeof(YR_ARRAY_ITEMS) + count * sizeof(YR_OBJECT*));

    if (array->items == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    for (i = array->items->count; i < count; i++)
      array->items->objects[i] = NULL;

    array->items->count = count;
  }

  item->parent = object;
  array->items->objects[index] = item;

  return ERROR_SUCCESS;
}


YR_OBJECT* yr_object_dict_get_item(
    YR_OBJECT* object,
    int flags,
    const char* key)
{
  int i;

  YR_OBJECT* result = NULL;
  YR_OBJECT_DICTIONARY* dict;

  assert(object->type == OBJECT_TYPE_DICTIONARY);

  dict = object_as_dictionary(object);

  if (dict->items != NULL)
  {
    for (i = 0; i < dict->items->used; i++)
    {
      if (strcmp(dict->items->objects[i].key, key) == 0)
        result = dict->items->objects[i].obj;
    }
  }

  if (result == NULL && flags & OBJECT_CREATE)
  {
    yr_object_copy(dict->prototype_item, &result);

    if (result != NULL)
      yr_object_dict_set_item(object, result, key);
  }

  return result;
}


int yr_object_dict_set_item(
    YR_OBJECT* object,
    YR_OBJECT* item,
    const char* key)
{
  YR_OBJECT_DICTIONARY* dict;

  int i;
  int count;

  assert(object->type == OBJECT_TYPE_DICTIONARY);

  dict = object_as_dictionary(object);

  if (dict->items == NULL)
  {
    count = 64;

    dict->items = (YR_DICTIONARY_ITEMS*) yr_malloc(
        sizeof(YR_DICTIONARY_ITEMS) + count * sizeof(dict->items->objects[0]));

    if (dict->items == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    memset(dict->items->objects, 0, count * sizeof(dict->items->objects[0]));

    dict->items->free = count;
    dict->items->used = 0;
  }
  else if (dict->items->free == 0)
  {
    count = dict->items->used * 2;
    dict->items = (YR_DICTIONARY_ITEMS*) yr_realloc(
        dict->items,
        sizeof(YR_DICTIONARY_ITEMS) + count * sizeof(dict->items->objects[0]));

    if (dict->items == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    for (i = dict->items->used; i < count; i++)
    {
      dict->items->objects[i].key = NULL;
      dict->items->objects[i].obj = NULL;
    }

    dict->items->free = dict->items->used;
  }

  item->parent = object;

  dict->items->objects[dict->items->used].key = yr_strdup(key);
  dict->items->objects[dict->items->used].obj = item;

  dict->items->used++;
  dict->items->free--;

  return ERROR_SUCCESS;
}


bool yr_object_has_undefined_value(
    YR_OBJECT* object,
    const char* field,
    ...)
{
  YR_OBJECT* field_obj;

  va_list args;
  va_start(args, field);

  if (field != NULL)
    field_obj = _yr_object_lookup(object, 0, field, args);
  else
    field_obj = object;

  va_end(args);

  if (field_obj == NULL)
    return true;

  switch(field_obj->type)
  {
    case OBJECT_TYPE_FLOAT:
      return isnan(field_obj->value.d);
    case OBJECT_TYPE_STRING:
      return field_obj->value.ss == NULL;
    case OBJECT_TYPE_INTEGER:
      return field_obj->value.i == UNDEFINED;
  }

  return false;
}


int64_t yr_object_get_integer(
    YR_OBJECT* object,
    const char* field,
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

  return integer_obj->value.i;
}


double yr_object_get_float(
    YR_OBJECT* object,
    const char* field,
    ...)
{
  YR_OBJECT* double_obj;

  va_list args;
  va_start(args, field);

  if (field != NULL)
    double_obj = _yr_object_lookup(object, 0, field, args);
  else
    double_obj = object;

  va_end(args);

  if (double_obj == NULL)
    return NAN;

  assertf(double_obj->type == OBJECT_TYPE_FLOAT,
          "type of \"%s\" is not double\n", field);

  return double_obj->value.d;
}


SIZED_STRING* yr_object_get_string(
    YR_OBJECT* object,
    const char* field,
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

  return string_obj->value.ss;
}


int yr_object_set_integer(
    int64_t value,
    YR_OBJECT* object,
    const char* field,
    ...)
{
  YR_OBJECT* integer_obj;

  va_list args;
  va_start(args, field);

  if (field != NULL)
    integer_obj = _yr_object_lookup(object, OBJECT_CREATE, field, args);
  else
    integer_obj = object;

  va_end(args);

  if (integer_obj == NULL)
  {
    if (field != NULL)
      return ERROR_INSUFFICIENT_MEMORY;
    else
      return ERROR_INVALID_ARGUMENT;
  }

  assert(integer_obj->type == OBJECT_TYPE_INTEGER);

  integer_obj->value.i = value;

  return ERROR_SUCCESS;
}


int yr_object_set_float(
    double value,
    YR_OBJECT* object,
    const char* field,
    ...)
{
  YR_OBJECT* double_obj;

  va_list args;
  va_start(args, field);

  if (field != NULL)
    double_obj = _yr_object_lookup(object, OBJECT_CREATE, field, args);
  else
    double_obj = object;

  va_end(args);

  if (double_obj == NULL)
  {
    if (field != NULL)
      return ERROR_INSUFFICIENT_MEMORY;
    else
      return ERROR_INVALID_ARGUMENT;
  }

  assert(double_obj->type == OBJECT_TYPE_FLOAT);

  double_obj->value.d = value;

  return ERROR_SUCCESS;
}


int yr_object_set_string(
    const char* value,
    size_t len,
    YR_OBJECT* object,
    const char* field,
    ...)
{
  YR_OBJECT* string_obj;

  va_list args;
  va_start(args, field);

  if (field != NULL)
    string_obj = _yr_object_lookup(object, OBJECT_CREATE, field, args);
  else
    string_obj = object;

  va_end(args);

  if (string_obj == NULL)
  {
    if (field != NULL)
      return ERROR_INSUFFICIENT_MEMORY;
    else
      return ERROR_INVALID_ARGUMENT;
  }

  assert(string_obj->type == OBJECT_TYPE_STRING);

  if (string_obj->value.ss != NULL)
    yr_free(string_obj->value.ss);

  if (value != NULL)
  {
    string_obj->value.ss = (SIZED_STRING*) yr_malloc(
        len + sizeof(SIZED_STRING));

    if (string_obj->value.ss == NULL)
      return ERROR_INSUFFICIENT_MEMORY;

    string_obj->value.ss->length = (uint32_t) len;
    string_obj->value.ss->flags = 0;

    memcpy(string_obj->value.ss->c_string, value, len);
    string_obj->value.ss->c_string[len] = '\0';
  }
  else
  {
    string_obj->value.ss = NULL;
  }

  return ERROR_SUCCESS;
}


YR_OBJECT* yr_object_get_root(
    YR_OBJECT* object)
{
  YR_OBJECT* o = object;

  while (o->parent != NULL)
    o = o->parent;

  return o;
}

YR_API void yr_object_print_data(
    YR_OBJECT* object,
    int indent,
    int print_identifier)
{
  YR_DICTIONARY_ITEMS* dict_items;
  YR_ARRAY_ITEMS* array_items;
  YR_STRUCTURE_MEMBER* member;

  char indent_spaces[32];
  int i;

  indent = yr_min(indent, sizeof(indent_spaces) - 1);

  memset(indent_spaces, '\t', indent);
  indent_spaces[indent] = '\0';

  if (print_identifier && object->type != OBJECT_TYPE_FUNCTION)
    printf("%s%s", indent_spaces, object->identifier);

  switch(object->type)
  {
    case OBJECT_TYPE_INTEGER:

      if (object->value.i != UNDEFINED)
        printf(" = %" PRIu64, object->value.i);
      else
        printf(" = UNDEFINED");

      break;

    case OBJECT_TYPE_STRING:

      if (object->value.ss != NULL)
      {
        size_t l;
        printf(" = \"");

        for (l = 0; l < object->value.ss->length; l++)
        {
          char c = object->value.ss->c_string[l];

          if (isprint((unsigned char) c))
            printf("%c", c);
          else
            printf("\\x%02x", (unsigned char) c);
        }

        printf("\"");
      }
      else
      {
        printf(" = UNDEFINED");
      }

      break;

    case OBJECT_TYPE_STRUCTURE:

      member = object_as_structure(object)->members;

      while (member != NULL)
      {
        if (member->object->type != OBJECT_TYPE_FUNCTION)
        {
          printf("\n");
          yr_object_print_data(member->object, indent + 1, 1);
        }
        member = member->next;
      }

      break;

    case OBJECT_TYPE_ARRAY:

      array_items = object_as_array(object)->items;

      if (array_items != NULL)
      {
        for (i = 0; i < array_items->count; i++)
        {
          if (array_items->objects[i] != NULL)
          {
            printf("\n%s\t[%d]", indent_spaces, i);
            yr_object_print_data(array_items->objects[i], indent + 1, 0);
          }
        }
      }

      break;

    case OBJECT_TYPE_DICTIONARY:

      dict_items = object_as_dictionary(object)->items;

      if (dict_items != NULL)
      {
        for (i = 0; i < dict_items->used; i++)
        {
          printf("\n%s\t%s", indent_spaces, dict_items->objects[i].key);
          yr_object_print_data(dict_items->objects[i].obj, indent + 1, 0);
        }
      }

      break;
  }
}
