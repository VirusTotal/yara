/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

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
/* headers */

#include <Python.h>
#include "structmember.h"

#if PY_VERSION_HEX >= 0x02060000
#include "bytesobject.h"
#elif PY_VERSION_HEX < 0x02060000
#define PyBytes_AsString PyString_AsString
#define PyBytes_Check PyString_Check
#define PyBytes_FromStringAndSize PyString_FromStringAndSize
#endif

#include <time.h>
#include <yara.h>

#if PY_VERSION_HEX < 0x02050000 && !defined(PY_SSIZE_T_MIN)
typedef int Py_ssize_t;
#define PY_SSIZE_T_MAX INT_MAX
#define PY_SSIZE_T_MIN INT_MIN
#endif

#ifndef PyVarObject_HEAD_INIT
#define PyVarObject_HEAD_INIT(type, size) PyObject_HEAD_INIT(type) size,
#endif

#if PY_MAJOR_VERSION >= 3
#define PY_STRING(x) PyUnicode_FromString(x)
#define PY_STRING_TO_C(x) PyBytes_AsString(\
                            PyUnicode_AsEncodedString(x, "utf-8", "strict"))
#define PY_STRING_CHECK(x) PyUnicode_Check(x)
#else
#define PY_STRING(x) PyString_FromString(x)
#define PY_STRING_TO_C(x) PyString_AsString(x)
#define PY_STRING_CHECK(x) (PyString_Check(x) || PyUnicode_Check(x))
#endif

/* Module globals */

static PyObject *YaraError = NULL;
static PyObject *YaraSyntaxError = NULL;
static PyObject *YaraTimeoutError = NULL;
static PyObject *YaraWarningError = NULL;


#define YARA_DOC "\
This module allows you to apply YARA rules to files or strings.\n\
\n\
For complete documentation please visit:\n\
https://plusvic.github.io/yara\n"


// Match object

typedef struct
{
  PyObject_HEAD
  PyObject* rule;
  PyObject* ns;
  PyObject* tags;
  PyObject* meta;
  PyObject* strings;

} Match;

static PyMemberDef Match_members[] = {
  {
    "rule",
    T_OBJECT_EX,
    offsetof(Match, rule),
    READONLY,
    "Name of the matching rule"
  },
  {
    "namespace",
    T_OBJECT_EX,
    offsetof(Match, ns),
    READONLY,
    "Namespace of the matching rule"
  },
  {
    "tags",
    T_OBJECT_EX,
    offsetof(Match, tags),
    READONLY,
    "List of tags associated to the rule"
  },
  {
    "meta",
    T_OBJECT_EX,
    offsetof(Match, meta),
    READONLY,
    "Dictionary with metadata associated to the rule"
  },
  {
    "strings",
    T_OBJECT_EX,
    offsetof(Match, strings),
    READONLY,
    "Dictionary with offsets and strings that matched the file"
  },
  { NULL } // End marker
};

static PyObject * Match_NEW(
    const char* rule,
    const char* ns,
    PyObject* tags,
    PyObject* meta,
    PyObject* strings);

static void Match_dealloc(
  PyObject *self);

static PyObject * Match_repr(
    PyObject *self);

static PyObject * Match_getattro(
    PyObject *self,
    PyObject *name);

static PyObject * Match_richcompare(
    PyObject *self,
    PyObject *other,
    int op);

static long Match_hash(
    PyObject *self);


static PyMethodDef Match_methods[] =
{
  { NULL },
};

static PyTypeObject Match_Type = {
  PyVarObject_HEAD_INIT(NULL, 0)
  "yara.Match",               /*tp_name*/
  sizeof(Match),              /*tp_basicsize*/
  0,                          /*tp_itemsize*/
  (destructor)Match_dealloc,  /*tp_dealloc*/
  0,                          /*tp_print*/
  0,                          /*tp_getattr*/
  0,                          /*tp_setattr*/
  0,                          /*tp_compare*/
  Match_repr,                 /*tp_repr*/
  0,                          /*tp_as_number*/
  0,                          /*tp_as_sequence*/
  0,                          /*tp_as_mapping*/
  Match_hash,                 /*tp_hash */
  0,                          /*tp_call*/
  0,                          /*tp_str*/
  Match_getattro,             /*tp_getattro*/
  0,                          /*tp_setattro*/
  0,                          /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
  "Match class",              /* tp_doc */
  0,                          /* tp_traverse */
  0,                          /* tp_clear */
  Match_richcompare,          /* tp_richcompare */
  0,                          /* tp_weaklistoffset */
  0,                          /* tp_iter */
  0,                          /* tp_iternext */
  Match_methods,              /* tp_methods */
  Match_members,              /* tp_members */
  0,                          /* tp_getset */
  0,                          /* tp_base */
  0,                          /* tp_dict */
  0,                          /* tp_descr_get */
  0,                          /* tp_descr_set */
  0,                          /* tp_dictoffset */
  0,                          /* tp_init */
  0,                          /* tp_alloc */
  0,                          /* tp_new */
};

// Rule object

typedef struct
{
  PyObject_HEAD
  PyObject* identifier;
  PyObject* tags;
  PyObject* meta;
} Rule;

static void Rule_dealloc(
    PyObject *self);

static PyObject * Rule_getattro(
    PyObject *self,
    PyObject *name);

static PyMemberDef Rule_members[] = {
  {
    "identifier",
    T_OBJECT_EX,
    offsetof(Rule, identifier),
    READONLY,
    "Name of the rule"
  },
  {
    "tags",
    T_OBJECT_EX,
    offsetof(Rule, tags),
    READONLY,
    "Tags for the rule"
  },
  {
    "meta",
    T_OBJECT_EX,
    offsetof(Rule, meta),
    READONLY,
    "Meta for the rule"
  },
  { NULL } // End marker
};

static PyMethodDef Rule_methods[] =
{
  { NULL, NULL }
};

static PyTypeObject Rule_Type = {
  PyVarObject_HEAD_INIT(NULL, 0)
  "yara.Rule",                /*tp_name*/
  sizeof(Rule),               /*tp_basicsize*/
  0,                          /*tp_itemsize*/
  (destructor)Rule_dealloc,   /*tp_dealloc*/
  0,                          /*tp_print*/
  0,                          /*tp_getattr*/
  0,                          /*tp_setattr*/
  0,                          /*tp_compare*/
  0,                          /*tp_repr*/
  0,                          /*tp_as_number*/
  0,                          /*tp_as_sequence*/
  0,                          /*tp_as_mapping*/
  0,                          /*tp_hash */
  0,                          /*tp_call*/
  0,                          /*tp_str*/
  Rule_getattro,              /*tp_getattro*/
  0,                          /*tp_setattro*/
  0,                          /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
  "Rule class",               /* tp_doc */
  0,                          /* tp_traverse */
  0,                          /* tp_clear */
  0,                          /* tp_richcompare */
  0,                          /* tp_weaklistoffset */
  0,                          /* tp_iter */
  0,                          /* tp_iternext */
  Rule_methods,               /* tp_methods */
  Rule_members,               /* tp_members */
  0,                          /* tp_getset */
  0,                          /* tp_base */
  0,                          /* tp_dict */
  0,                          /* tp_descr_get */
  0,                          /* tp_descr_set */
  0,                          /* tp_dictoffset */
  0,                          /* tp_init */
  0,                          /* tp_alloc */
  0,                          /* tp_new */
};


// Rules object

typedef struct
{
  PyObject_HEAD
  PyObject* externals;
  YR_RULES* rules;
  YR_RULE* iter_current_rule;
} Rules;

static void Rules_dealloc(
    PyObject *self);

static PyObject * Rules_match(
    PyObject *self,
    PyObject *args,
    PyObject *keywords);

static PyObject * Rules_save(
    PyObject *self,
    PyObject *args);

static PyObject * Rules_profiling_info(
    PyObject *self,
    PyObject *args);

static PyObject * Rules_getattro(
    PyObject *self,
    PyObject *name);

static PyObject * Rules_next(
    PyObject *self);

static PyMethodDef Rules_methods[] =
{
  {
    "match",
    (PyCFunction) Rules_match,
    METH_VARARGS | METH_KEYWORDS
  },
  {
    "save",
    (PyCFunction) Rules_save,
    METH_VARARGS
  },
  {
    "profiling_info",
    (PyCFunction) Rules_profiling_info,
    METH_NOARGS
  },
  {
    NULL,
    NULL
  }
};

static PyTypeObject Rules_Type = {
  PyVarObject_HEAD_INIT(NULL, 0)
  "yara.Rules",               /*tp_name*/
  sizeof(Rules),              /*tp_basicsize*/
  0,                          /*tp_itemsize*/
  (destructor)Rules_dealloc,  /*tp_dealloc*/
  0,                          /*tp_print*/
  0,                          /*tp_getattr*/
  0,                          /*tp_setattr*/
  0,                          /*tp_compare*/
  0,                          /*tp_repr*/
  0,                          /*tp_as_number*/
  0,                          /*tp_as_sequence*/
  0,                          /*tp_as_mapping*/
  0,                          /*tp_hash */
  0,                          /*tp_call*/
  0,                          /*tp_str*/
  Rules_getattro,             /*tp_getattro*/
  0,                          /*tp_setattro*/
  0,                          /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
  "Rules class",              /* tp_doc */
  0,                          /* tp_traverse */
  0,                          /* tp_clear */
  0,                          /* tp_richcompare */
  0,                          /* tp_weaklistoffset */
  PyObject_SelfIter,          /* tp_iter */
  (iternextfunc) Rules_next,  /* tp_iternext */
  Rules_methods,              /* tp_methods */
  0,                          /* tp_members */
  0,                          /* tp_getset */
  0,                          /* tp_base */
  0,                          /* tp_dict */
  0,                          /* tp_descr_get */
  0,                          /* tp_descr_set */
  0,                          /* tp_dictoffset */
  0,                          /* tp_init */
  0,                          /* tp_alloc */
  0,                          /* tp_new */
};

typedef struct _CALLBACK_DATA
{
  PyObject *matches;
  PyObject *callback;
  PyObject *modules_data;

} CALLBACK_DATA;


int yara_callback(
    int message,
    void* message_data,
    void* user_data)
{
  YR_STRING* string;
  YR_MATCH* m;
  YR_META* meta;
  YR_RULE* rule;
  YR_MODULE_IMPORT* module_import;

  const char* tag;

  PyObject* tag_list = NULL;
  PyObject* string_list = NULL;
  PyObject* meta_list = NULL;
  PyObject* match;
  PyObject* callback_dict;
  PyObject* object;
  PyObject* tuple;
  PyObject* matches = ((CALLBACK_DATA*) user_data)->matches;
  PyObject* callback = ((CALLBACK_DATA*) user_data)->callback;
  PyObject* modules_data = ((CALLBACK_DATA*) user_data)->modules_data;
  PyObject* module_data;
  PyObject* callback_result;

  Py_ssize_t data_size;
  PyGILState_STATE gil_state;

  int result = CALLBACK_CONTINUE;

  if (message == CALLBACK_MSG_SCAN_FINISHED)
    return CALLBACK_CONTINUE;

  if (message == CALLBACK_MSG_RULE_NOT_MATCHING && callback == NULL)
    return CALLBACK_CONTINUE;

  if (message == CALLBACK_MSG_IMPORT_MODULE)
  {
    if (modules_data == NULL)
      return CALLBACK_CONTINUE;

    module_import = (YR_MODULE_IMPORT*) message_data;

    module_data = PyDict_GetItemString(
        modules_data,
        module_import->module_name);

    #if PY_MAJOR_VERSION >= 3
    if (module_data != NULL && PyBytes_Check(module_data))
    #else
    if (module_data != NULL && PyString_Check(module_data))
    #endif
    {
      #if PY_MAJOR_VERSION >= 3
      PyBytes_AsStringAndSize(
          module_data,
          (char**) &module_import->module_data,
          &data_size);
      #else
      PyString_AsStringAndSize(
          module_data,
          (char**) &module_import->module_data,
          &data_size);
      #endif

      module_import->module_data_size = data_size;
    }

    return CALLBACK_CONTINUE;
  }

  rule = (YR_RULE*) message_data;

  gil_state = PyGILState_Ensure();

  tag_list = PyList_New(0);
  string_list = PyList_New(0);
  meta_list = PyDict_New();

  if (tag_list == NULL || string_list == NULL || meta_list == NULL)
  {
    Py_XDECREF(tag_list);
    Py_XDECREF(string_list);
    Py_XDECREF(meta_list);
    PyGILState_Release(gil_state);

    return CALLBACK_ERROR;
  }

  yr_rule_tags_foreach(rule, tag)
  {
    object = PY_STRING(tag);
    PyList_Append(tag_list, object);
    Py_DECREF(object);
  }

  yr_rule_metas_foreach(rule, meta)
  {
    if (meta->type == META_TYPE_INTEGER)
      object = Py_BuildValue("i", meta->integer);
    else if (meta->type == META_TYPE_BOOLEAN)
      object = PyBool_FromLong(meta->integer);
    else
      object = PY_STRING(meta->string);

    PyDict_SetItemString(meta_list, meta->identifier, object);
    Py_DECREF(object);
  }

  yr_rule_strings_foreach(rule, string)
  {
    yr_string_matches_foreach(string, m)
    {
      object = PyBytes_FromStringAndSize((char*) m->data, m->length);

      tuple = Py_BuildValue(
          "(L,s,O)",
          m->offset,
          string->identifier,
          object);

      PyList_Append(string_list, tuple);

      Py_DECREF(object);
      Py_DECREF(tuple);
    }
  }

  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    match = Match_NEW(
        rule->identifier,
        rule->ns->name,
        tag_list,
        meta_list,
        string_list);

    if (match != NULL)
    {
      PyList_Append(matches, match);
      Py_DECREF(match);
    }
    else
    {
      Py_DECREF(tag_list);
      Py_DECREF(string_list);
      Py_DECREF(meta_list);
      PyGILState_Release(gil_state);

      return CALLBACK_ERROR;
    }
  }

  if (callback != NULL)
  {
    Py_INCREF(callback);

    callback_dict = PyDict_New();

    object = PyBool_FromLong(message == CALLBACK_MSG_RULE_MATCHING);
    PyDict_SetItemString(callback_dict, "matches", object);
    Py_DECREF(object);

    object = PY_STRING(rule->identifier);
    PyDict_SetItemString(callback_dict, "rule", object);
    Py_DECREF(object);

    object = PY_STRING(rule->ns->name);
    PyDict_SetItemString(callback_dict, "namespace", object);
    Py_DECREF(object);

    PyDict_SetItemString(callback_dict, "tags", tag_list);
    PyDict_SetItemString(callback_dict, "meta", meta_list);
    PyDict_SetItemString(callback_dict, "strings", string_list);

    callback_result = PyObject_CallFunctionObjArgs(
        callback,
        callback_dict,
        NULL);

    if (callback_result != NULL)
    {
      #if PY_MAJOR_VERSION >= 3
      if (PyLong_Check(callback_result))
      #else
      if (PyLong_Check(callback_result) || PyInt_Check(callback_result))
      #endif
      {
        result = (int) PyLong_AsLong(callback_result);
      }

      Py_DECREF(callback_result);
    }
    else
    {
      result = CALLBACK_ERROR;
    }

    Py_DECREF(callback_dict);
    Py_DECREF(callback);
  }

  Py_DECREF(tag_list);
  Py_DECREF(string_list);
  Py_DECREF(meta_list);
  PyGILState_Release(gil_state);

  return result;
}


/* YR_STREAM read method for "file-like objects" */

static size_t flo_read(
    void* ptr,
    size_t size,
    size_t count,
    void* user_data)
{
  for (int i = 0; i < count; i++)
  {
    PyGILState_STATE gil_state = PyGILState_Ensure();

    PyObject* bytes = PyObject_CallMethod(
        (PyObject*) user_data, "read", "n", (Py_ssize_t) size);

    PyGILState_Release(gil_state);

    if (bytes != NULL)
    {
      Py_ssize_t len;
      char* buffer;

      int result = PyBytes_AsStringAndSize(bytes, &buffer, &len);

      Py_DECREF(bytes);

      if (result == -1 || len < size)
        return i;

      memcpy(ptr + i * size, buffer, size);
    }
    else
    {
      return i;
    }
  }

  return count;
}


/* YR_STREAM write method for "file-like objects" */

static size_t flo_write(
    const void* ptr,
    size_t size,
    size_t count,
    void* user_data)
{
  for (int i = 0; i < count; i++)
  {
    PyGILState_STATE gil_state = PyGILState_Ensure();

    PyObject* result = PyObject_CallMethod(
        (PyObject*) user_data, "write", "s#", ptr + i * size, size);

    PyGILState_Release(gil_state);

    if (result == NULL)
      return i;

    Py_DECREF(result);
  }

  return count;
}


int process_compile_externals(
    PyObject* externals,
    YR_COMPILER* compiler)
{
  PyObject *key, *value;
  Py_ssize_t pos = 0;

  char* identifier = NULL;

  while (PyDict_Next(externals, &pos, &key, &value))
  {
    identifier = PY_STRING_TO_C(key);

    if (PyBool_Check(value))
    {
      yr_compiler_define_boolean_variable(
          compiler,
          identifier,
          PyObject_IsTrue(value));
    }
#if PY_MAJOR_VERSION >= 3
    else if (PyLong_Check(value))
#else
    else if (PyLong_Check(value) || PyInt_Check(value))
#endif
    {
      yr_compiler_define_integer_variable(
          compiler,
          identifier,
          PyLong_AsLong(value));
    }
    else if (PyFloat_Check(value))
    {
      yr_compiler_define_float_variable(
          compiler,
          identifier,
          PyFloat_AsDouble(value));
    }
    else if (PY_STRING_CHECK(value))
    {
      yr_compiler_define_string_variable(
          compiler,
          identifier,
          PY_STRING_TO_C(value));
    }
    else
    {
      return FALSE;
    }
  }

  return TRUE;
}


int process_match_externals(
    PyObject* externals,
    YR_RULES* rules)
{
  PyObject *key, *value;
  Py_ssize_t pos = 0;

  char* identifier = NULL;

  while (PyDict_Next(externals, &pos, &key, &value))
  {
    identifier = PY_STRING_TO_C(key);

    if (PyBool_Check(value))
    {
      yr_rules_define_boolean_variable(
          rules,
          identifier,
          PyObject_IsTrue(value));
    }
#if PY_MAJOR_VERSION >= 3
    else if (PyLong_Check(value))
#else
    else if (PyLong_Check(value) || PyInt_Check(value))
#endif
    {
      yr_rules_define_integer_variable(
          rules,
          identifier,
          PyLong_AsLong(value));
    }
    else if (PyFloat_Check(value))
    {
      yr_rules_define_float_variable(
          rules,
          identifier,
          PyFloat_AsDouble(value));
    }
    else if (PY_STRING_CHECK(value))
    {
      yr_rules_define_string_variable(
          rules,
          identifier,
          PY_STRING_TO_C(value));
    }
    else
    {
      return FALSE;
    }
  }

  return TRUE;
}


PyObject* handle_error(
    int error,
    char* extra)
{
  switch(error)
  {
    case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
      return PyErr_Format(
        YaraError,
        "access denied");
    case ERROR_INSUFICIENT_MEMORY:
      return PyErr_NoMemory();
    case ERROR_COULD_NOT_OPEN_FILE:
      return PyErr_Format(
          YaraError,
          "could not open file \"%s\"",
          extra);
    case ERROR_COULD_NOT_MAP_FILE:
      return PyErr_Format(
          YaraError,
          "could not map file \"%s\" into memory",
          extra);
    case ERROR_INVALID_FILE:
      return PyErr_Format(
          YaraError,
          "invalid rules file \"%s\"",
          extra);
    case ERROR_CORRUPT_FILE:
      return PyErr_Format(
          YaraError,
          "corrupt rules file \"%s\"",
          extra);
    case ERROR_SCAN_TIMEOUT:
      return PyErr_Format(
          YaraTimeoutError,
          "scanning timed out");
    default:
      return PyErr_Format(
          YaraError,
          "internal error: %d",
          error);
  }
}


static PyObject * Match_NEW(
    const char* rule,
    const char* ns,
    PyObject* tags,
    PyObject* meta,
    PyObject* strings)
{
  Match* object;

  object = PyObject_NEW(Match, &Match_Type);

  if (object != NULL)
  {
    object->rule = PY_STRING(rule);
    object->ns = PY_STRING(ns);
    object->tags = tags;
    object->meta = meta;
    object->strings = strings;

    Py_INCREF(tags);
    Py_INCREF(meta);
    Py_INCREF(strings);
  }

  return (PyObject *)object;
}


static void Match_dealloc(
    PyObject *self)
{
  Match *object = (Match *) self;

  Py_DECREF(object->rule);
  Py_DECREF(object->ns);
  Py_DECREF(object->tags);
  Py_DECREF(object->meta);
  Py_DECREF(object->strings);

  PyObject_Del(self);
}


static PyObject * Match_repr(
    PyObject *self)
{
  Match *object = (Match *) self;
  Py_INCREF(object->rule);
  return object->rule;
}


static PyObject * Match_getattro(
    PyObject *self,
    PyObject *name)
{
  return PyObject_GenericGetAttr(self, name);
}


static PyObject * Match_richcompare(
    PyObject *self,
    PyObject *other,
    int op)
{
  PyObject* result = NULL;

  Match *a = (Match *) self;
  Match *b = (Match *) other;

  if(PyObject_TypeCheck(other, &Match_Type))
  {
    switch(op)
    {
    case Py_EQ:
      if (PyObject_RichCompareBool(a->rule, b->rule, Py_EQ) &&
          PyObject_RichCompareBool(a->ns, b->ns, Py_EQ))
        result = Py_True;
      else
        result = Py_False;

      Py_INCREF(result);
      break;

    case Py_NE:
      if (PyObject_RichCompareBool(a->rule, b->rule, Py_NE) ||
          PyObject_RichCompareBool(a->ns, b->ns, Py_NE))
          result = Py_True;
      else
          result = Py_False;

      Py_INCREF(result);
      break;

    case Py_LT:
    case Py_LE:
    case Py_GT:
    case Py_GE:
      if (PyObject_RichCompareBool(a->rule, b->rule, Py_EQ))
        result = PyObject_RichCompare(a->ns, b->ns, op);
      else
        result = PyObject_RichCompare(a->rule, b->rule, op);

      break;
    }
  }
  else
  {
    result = PyErr_Format(
        PyExc_TypeError,
        "'Match' objects must be compared with objects of the same class");
  }

  return result;
}


static long Match_hash(
    PyObject *self)
{
  Match *match = (Match *) self;
  return PyObject_Hash(match->rule) + PyObject_Hash(match->ns);
}

////////////////////////////////////////////////////////////////////////////////


static void Rule_dealloc(PyObject *self)
{
  Rule *object = (Rule *) self;
  Py_XDECREF(object->identifier);
  Py_XDECREF(object->tags);
  Py_XDECREF(object->meta);
  PyObject_Del(self);
}

static PyObject * Rule_getattro(
    PyObject *self,
    PyObject *name)
{
  return PyObject_GenericGetAttr(self, name);
}

static void Rules_dealloc(PyObject *self)
{
  Rules *object = (Rules *) self;

  Py_XDECREF(object->externals);
  yr_rules_destroy(object->rules);

  PyObject_Del(self);
}

static PyObject * Rules_next(PyObject *self)
{
  Rule *rule;
  PyObject *tag_list;
  PyObject *object;
  PyObject *meta_list;
  YR_META *meta;
  Rules *rules;
  const char *tag;

  rules = (Rules *) self;

  // Generate new Rule object based upon iter_current_rule and increment
  // iter_current_rule.

  if (RULE_IS_NULL(rules->iter_current_rule))
  {
    PyErr_SetNone(PyExc_StopIteration);
    return NULL;
  }

  rule = PyObject_NEW(Rule, &Rule_Type);
  tag_list = PyList_New(0);
  meta_list = PyDict_New();

  if (rule != NULL && tag_list != NULL && meta_list != NULL)
  {
    yr_rule_tags_foreach(rules->iter_current_rule, tag)
    {
      object = PY_STRING(tag);
      PyList_Append(tag_list, object);
      Py_DECREF(object);
    }

    yr_rule_metas_foreach(rules->iter_current_rule, meta)
    {
      if (meta->type == META_TYPE_INTEGER)
        object = Py_BuildValue("i", meta->integer);
      else if (meta->type == META_TYPE_BOOLEAN)
        object = PyBool_FromLong(meta->integer);
      else
        object = PY_STRING(meta->string);

      PyDict_SetItemString(meta_list, meta->identifier, object);
      Py_DECREF(object);
    }

    rule->identifier = PY_STRING(rules->iter_current_rule->identifier);
    rule->tags = tag_list;
    rule->meta = meta_list;
    rules->iter_current_rule++;
    return (PyObject *) rule;
  }
  else
  {
    Py_XDECREF(tag_list);
    Py_XDECREF(meta_list);
    return PyErr_Format(PyExc_TypeError, "Out of memory");
  }
}

static PyObject * Rules_match(
    PyObject *self,
    PyObject *args,
    PyObject *keywords)
{
  static char *kwlist[] = {
      "filepath", "pid", "data", "externals",
      "callback", "fast", "timeout", "modules_data", NULL
      };

  char* filepath = NULL;
  char* data = NULL;

  int pid = 0;
  int timeout = 0;
  int length;
  int error = ERROR_SUCCESS;
  int fast_mode = FALSE;

  PyObject *externals = NULL;
  PyObject *fast = NULL;

  Rules* object = (Rules*) self;

  CALLBACK_DATA callback_data;

  callback_data.matches = NULL;
  callback_data.callback = NULL;
  callback_data.modules_data = NULL;

  if (PyArg_ParseTupleAndKeywords(
        args,
        keywords,
        "|sis#OOOiO",
        kwlist,
        &filepath,
        &pid,
        &data,
        &length,
        &externals,
        &callback_data.callback,
        &fast,
        &timeout,
        &callback_data.modules_data))
  {
    if (filepath == NULL && data == NULL && pid == 0)
    {
      return PyErr_Format(
          PyExc_TypeError,
          "match() takes at least one argument");
    }

    if (callback_data.callback != NULL)
    {
      if (!PyCallable_Check(callback_data.callback))
      {
        return PyErr_Format(
            PyExc_TypeError,
            "'callback' must be callable");
      }
    }

    if (callback_data.modules_data != NULL)
    {
      if (!PyDict_Check(callback_data.modules_data))
      {
        return PyErr_Format(
            PyExc_TypeError,
            "'modules_data' must be a dictionary");
      }
    }

    if (externals != NULL && externals != Py_None)
    {
      if (PyDict_Check(externals))
      {
        if (!process_match_externals(externals, object->rules))
        {
          // Restore original externals provided during compiling.
          process_match_externals(object->externals, object->rules);

          return PyErr_Format(
              PyExc_TypeError,
              "external values must be of type integer, float, boolean or string");
        }
      }
      else
      {
        return PyErr_Format(
            PyExc_TypeError,
            "'externals' must be a dictionary");
      }
    }

    if (fast != NULL)
    {
      fast_mode = (PyObject_IsTrue(fast) == 1);
    }

    if (filepath != NULL)
    {
      callback_data.matches = PyList_New(0);

      Py_BEGIN_ALLOW_THREADS

      error = yr_rules_scan_file(
          object->rules,
          filepath,
          fast_mode ? SCAN_FLAGS_FAST_MODE : 0,
          yara_callback,
          &callback_data,
          timeout);

      Py_END_ALLOW_THREADS
    }
    else if (data != NULL)
    {
      callback_data.matches = PyList_New(0);

      Py_BEGIN_ALLOW_THREADS

      error = yr_rules_scan_mem(
          object->rules,
          (unsigned char*) data,
          (unsigned int) length,
          fast_mode ? SCAN_FLAGS_FAST_MODE : 0,
          yara_callback,
          &callback_data,
          timeout);

      Py_END_ALLOW_THREADS
    }
    else if (pid != 0)
    {
      callback_data.matches = PyList_New(0);

      Py_BEGIN_ALLOW_THREADS

      error = yr_rules_scan_proc(
          object->rules,
          pid,
          fast_mode ? SCAN_FLAGS_FAST_MODE : 0,
          yara_callback,
          &callback_data,
          timeout);

      Py_END_ALLOW_THREADS
    }

    // Restore original externals provided during compiling.
    if (object->externals != NULL)
      process_match_externals(object->externals, object->rules);

    if (error != ERROR_SUCCESS)
    {
      Py_DECREF(callback_data.matches);

      if (error == ERROR_CALLBACK_ERROR)
      {
        return NULL;
      }
      else
      {
        handle_error(error, filepath);

#ifdef PROFILING_ENABLED
        PyObject* exception = PyErr_Occurred();

        if (exception != NULL && error == ERROR_SCAN_TIMEOUT)
        {
          PyObject_SetAttrString(
              exception,
              "profiling_info",
              Rules_profiling_info(self, NULL));
        }
#endif

        return NULL;
      }
    }
  }

  return callback_data.matches;
}


static PyObject * Rules_save(
    PyObject *self,
    PyObject *args)
{
  int error;

  PyObject* param;
  Rules* rules = (Rules*) self;

  if (!PyArg_UnpackTuple(args, "save", 1, 1, &param))
  {
    return PyErr_Format(
        PyExc_TypeError,
          "save() takes 1 argument");
  }

  if (PY_STRING_CHECK(param))
  {
    char* filepath = PY_STRING_TO_C(param);

    Py_BEGIN_ALLOW_THREADS
    error = yr_rules_save(rules->rules, filepath);
    Py_END_ALLOW_THREADS

    if (error != ERROR_SUCCESS)
      return handle_error(error, filepath);
  }
  else if (PyObject_HasAttrString(param, "write"))
  {
    YR_STREAM stream;

    stream.user_data = param;
    stream.write = flo_write;

    Py_BEGIN_ALLOW_THREADS;
    error = yr_rules_save_stream(rules->rules, &stream);
    Py_END_ALLOW_THREADS;

    if (error != ERROR_SUCCESS)
      return handle_error(error, "<file-like-object>");
  }
  else
  {
    return PyErr_Format(
      PyExc_TypeError,
      "load() expects either a file path or a file-like object");
  }

  Py_RETURN_NONE;
}


static PyObject * Rules_profiling_info(
    PyObject *self,
    PyObject *args)
{

#ifdef PROFILING_ENABLED
  PyObject* object;
  PyObject* result;

  YR_RULES* rules = ((Rules*) self)->rules;
  YR_RULE* rule;
  YR_STRING* string;

  char key[512];
  uint64_t clock_ticks;

  result = PyDict_New();

  yr_rules_foreach(rules, rule)
  {
    clock_ticks = rule->clock_ticks;

    yr_rule_strings_foreach(rule, string)
    {
      clock_ticks += string->clock_ticks;
    }

    snprintf(key, sizeof(key), "%s:%s", rule->ns->name, rule->identifier);

    object = PyLong_FromLongLong(clock_ticks);
    PyDict_SetItemString(result, key, object);
    Py_DECREF(object);
  }

  return result;
#else
  return PyErr_Format(YaraError, "libyara compiled without profiling support");
#endif
}


static PyObject * Rules_getattro(
    PyObject *self,
    PyObject *name)
{
  return PyObject_GenericGetAttr(self, name);
}


void raise_exception_on_error(
    int error_level,
    const char* file_name,
    int line_number,
    const char* message,
    void* user_data)
{
  if (error_level == YARA_ERROR_LEVEL_ERROR)
  {
    if (file_name != NULL)
      PyErr_Format(
          YaraSyntaxError,
          "%s(%d): %s",
          file_name,
          line_number,
          message);
    else
      PyErr_Format(
          YaraSyntaxError,
          "%s",
          message);
  }
}


void raise_exception_on_error_or_warning(
    int error_level,
    const char* file_name,
    int line_number,
    const char* message,
    void* user_data)
{
  if (error_level == YARA_ERROR_LEVEL_ERROR)
  {
    if (file_name != NULL)
      PyErr_Format(
          YaraSyntaxError,
          "%s(%d): %s",
          file_name,
          line_number,
          message);
    else
      PyErr_Format(
          YaraSyntaxError,
          "%s",
          message);
  }
  else
  {
    if (file_name != NULL)
      PyErr_Format(
          YaraWarningError,
          "%s(%d): %s",
          file_name,
          line_number,
          message);
    else
      PyErr_Format(
          YaraWarningError,
          "%s",
          message);
  }
}

////////////////////////////////////////////////////////////////////////////////

static PyObject * yara_compile(
    PyObject *self,
    PyObject *args,
    PyObject *keywords)
{
  static char *kwlist[] = {
    "filepath", "source", "file", "filepaths", "sources",
    "includes", "externals", "error_on_warning", NULL};

  YR_COMPILER* compiler;
  YR_RULES* yara_rules;
  FILE* fh;

  int fd;
  int error = 0;

  Rules* rules;
  PyObject *result = NULL;
  PyObject *file = NULL;

  PyObject *sources_dict = NULL;
  PyObject *filepaths_dict = NULL;
  PyObject *includes = NULL;
  PyObject *externals = NULL;
  PyObject *error_on_warning = NULL;

  PyObject *key, *value;

  Py_ssize_t pos = 0;

  char* filepath = NULL;
  char* source = NULL;
  char* ns = NULL;

  if (PyArg_ParseTupleAndKeywords(
        args,
        keywords,
        "|ssOOOOOO",
        kwlist,
        &filepath,
        &source,
        &file,
        &filepaths_dict,
        &sources_dict,
        &includes,
        &externals,
        &error_on_warning))
  {
    error = yr_compiler_create(&compiler);

    if (error != ERROR_SUCCESS)
      return handle_error(error, NULL);

    yr_compiler_set_callback(compiler, raise_exception_on_error, NULL);

    if (error_on_warning != NULL)
    {
      if (PyBool_Check(error_on_warning))
      {
        if (PyObject_IsTrue(error_on_warning) == 1)
        {
          yr_compiler_set_callback(
              compiler,
              raise_exception_on_error_or_warning,
              NULL);
        }
      }
      else
      {
        yr_compiler_destroy(compiler);
        return PyErr_Format(
            PyExc_TypeError,
            "'error_on_warning' param must be of boolean type");
      }
    }

    if (includes != NULL)
    {
      if (PyBool_Check(includes))
      {
        // PyObject_IsTrue can return -1 in case of error
        compiler->allow_includes = (PyObject_IsTrue(includes) == 1);
      }
      else
      {
        yr_compiler_destroy(compiler);
        return PyErr_Format(
            PyExc_TypeError,
            "'includes' param must be of boolean type");
      }
    }

    if (externals != NULL && externals != Py_None)
    {
      if (PyDict_Check(externals))
      {
        if (!process_compile_externals(externals, compiler))
        {
          yr_compiler_destroy(compiler);
          return PyErr_Format(
              PyExc_TypeError,
              "external values must be of type integer, float, boolean or string");
        }
      }
      else
      {
        yr_compiler_destroy(compiler);
        return PyErr_Format(
            PyExc_TypeError,
            "'externals' must be a dictionary");
      }
    }

    if (filepath != NULL)
    {
      fh = fopen(filepath, "r");

      if (fh != NULL)
      {
        error = yr_compiler_add_file(compiler, fh, NULL, filepath);
        fclose(fh);
      }
      else
      {
        result = PyErr_SetFromErrno(YaraError);
      }
    }
    else if (source != NULL)
    {
      error = yr_compiler_add_string(compiler, source, NULL);
    }
    else if (file != NULL)
    {
      fd = dup(PyObject_AsFileDescriptor(file));
      fh = fdopen(fd, "r");
      error = yr_compiler_add_file(compiler, fh, NULL, NULL);
      fclose(fh);
    }
    else if (sources_dict != NULL)
    {
      if (PyDict_Check(sources_dict))
      {
        while (PyDict_Next(sources_dict, &pos, &key, &value))
        {
          source = PY_STRING_TO_C(value);
          ns = PY_STRING_TO_C(key);

          if (source != NULL && ns != NULL)
          {
            error = yr_compiler_add_string(compiler, source, ns);

            if (error > 0)
              break;
          }
          else
          {
            result = PyErr_Format(
                PyExc_TypeError,
                "keys and values of the 'sources' dictionary must be "
                "of string type");
            break;
          }
        }
      }
      else
      {
        result = PyErr_Format(
            PyExc_TypeError,
            "'sources' must be a dictionary");
      }
    }
    else if (filepaths_dict != NULL)
    {
      if (PyDict_Check(filepaths_dict))
      {
        while (PyDict_Next(filepaths_dict, &pos, &key, &value))
        {
          filepath = PY_STRING_TO_C(value);
          ns = PY_STRING_TO_C(key);

          if (filepath != NULL && ns != NULL)
          {
            fh = fopen(filepath, "r");

            if (fh != NULL)
            {
              error = yr_compiler_add_file(compiler, fh, ns, filepath);
              fclose(fh);

              if (error > 0)
                break;
            }
            else
            {
              result = PyErr_SetFromErrno(YaraError);
              break;
            }
          }
          else
          {
            result = PyErr_Format(
                PyExc_TypeError,
                "keys and values of the filepaths dictionary must be of "
                "string type");
            break;
          }
        }
      }
      else
      {
        result = PyErr_Format(
            PyExc_TypeError,
            "filepaths must be a dictionary");
      }
    }
    else
    {
      result = PyErr_Format(
          PyExc_TypeError,
          "compile() takes 1 argument");
    }

    if (PyErr_Occurred() == NULL)
    {
      rules = PyObject_NEW(Rules, &Rules_Type);

      if (rules != NULL)
      {
        Py_BEGIN_ALLOW_THREADS
        error = yr_compiler_get_rules(compiler, &yara_rules);
        Py_END_ALLOW_THREADS

        if (error == ERROR_SUCCESS)
        {
          rules->rules = yara_rules;
          rules->iter_current_rule = rules->rules->rules_list_head;

          if (externals != NULL && externals != Py_None)
            rules->externals = PyDict_Copy(externals);
          else
            rules->externals = NULL;

          result = (PyObject*) rules;
        }
        else
        {
          printf("yr_compiler_get_rules: %d\n", error);
          result = handle_error(error, NULL);
        }
      }
      else
      {
        printf("PyObject_NEW: ERROR_INSUFICIENT_MEMORY\n");
        result = handle_error(ERROR_INSUFICIENT_MEMORY, NULL);
      }
    }

    yr_compiler_destroy(compiler);
  }

  return result;
}


static PyObject * yara_load(
    PyObject *self,
    PyObject *args)
{
  Rules* rules = PyObject_NEW(Rules, &Rules_Type);
  PyObject* param;

  if (rules == NULL)
    return PyErr_NoMemory();

  if (!PyArg_UnpackTuple(args, "load", 1, 1, &param))
  {
    return PyErr_Format(
        PyExc_TypeError,
          "load() takes 1 argument");
  }

  int error;

  if (PY_STRING_CHECK(param))
  {
    char* filepath = PY_STRING_TO_C(param);

    Py_BEGIN_ALLOW_THREADS;
    error = yr_rules_load(filepath, &rules->rules);
    Py_END_ALLOW_THREADS;

    if (error != ERROR_SUCCESS)
      return handle_error(error, filepath);
  }
  else if (PyObject_HasAttrString(param, "read"))
  {
    YR_STREAM stream;

    stream.user_data = param;
    stream.read = flo_read;

    Py_BEGIN_ALLOW_THREADS;
    error = yr_rules_load_stream(&stream, &rules->rules);
    Py_END_ALLOW_THREADS;

    if (error != ERROR_SUCCESS)
      return handle_error(error, "<file-like-object>");
  }
  else
  {
    return PyErr_Format(
      PyExc_TypeError,
      "load() expects either a file path or a file-like object");
  }

  YR_EXTERNAL_VARIABLE* external = rules->rules->externals_list_head;
  rules->iter_current_rule = rules->rules->rules_list_head;

  if (!EXTERNAL_VARIABLE_IS_NULL(external))
    rules->externals = PyDict_New();
  else
    rules->externals = NULL;

  while (!EXTERNAL_VARIABLE_IS_NULL(external))
  {
    switch(external->type)
    {
      case EXTERNAL_VARIABLE_TYPE_BOOLEAN:
        PyDict_SetItemString(
            rules->externals,
            external->identifier,
            PyBool_FromLong((long) external->value.i));
        break;
      case EXTERNAL_VARIABLE_TYPE_INTEGER:
        PyDict_SetItemString(
            rules->externals,
            external->identifier,
            PyLong_FromLong((long) external->value.i));
        break;
      case EXTERNAL_VARIABLE_TYPE_FLOAT:
        PyDict_SetItemString(
            rules->externals,
            external->identifier,
            PyFloat_FromDouble(external->value.f));
        break;
      case EXTERNAL_VARIABLE_TYPE_STRING:
        PyDict_SetItemString(
            rules->externals,
            external->identifier,
            PY_STRING(external->value.s));
        break;
    }

    external++;
  }

  return (PyObject*) rules;
}


void finalize(void)
{
  yr_finalize();
}


static PyMethodDef yara_methods[] = {
  {
    "compile",
    (PyCFunction) yara_compile,
    METH_VARARGS | METH_KEYWORDS,
    "Compiles a YARA rules file and returns an instance of class Rules"
  },
  {
    "load",
    (PyCFunction) yara_load,
    METH_VARARGS,
    "Loads a previously saved YARA rules file and returns an instance of class Rules"
  },
  { NULL, NULL }
};

#if PY_MAJOR_VERSION >= 3
#define MOD_ERROR_VAL NULL
#define MOD_SUCCESS_VAL(val) val
#define MOD_INIT(name) PyMODINIT_FUNC PyInit_##name(void)
#define MOD_DEF(ob, name, doc, methods) \
      static struct PyModuleDef moduledef = { \
        PyModuleDef_HEAD_INIT, name, doc, -1, methods, }; \
      ob = PyModule_Create(&moduledef);
#else
#define MOD_ERROR_VAL
#define MOD_SUCCESS_VAL(val)
#define MOD_INIT(name) void init##name(void)
#define MOD_DEF(ob, name, doc, methods) \
      ob = Py_InitModule3(name, methods, doc);
#endif


MOD_INIT(yara)
{
  PyObject *m;

  MOD_DEF(m, "yara", YARA_DOC, yara_methods)

  if (m == NULL)
    return MOD_ERROR_VAL;

  /* initialize module variables/constants */

  PyModule_AddIntConstant(m, "CALLBACK_CONTINUE", 0);
  PyModule_AddIntConstant(m, "CALLBACK_ABORT", 1);

#if PYTHON_API_VERSION >= 1007
  YaraError = PyErr_NewException("yara.Error", PyExc_Exception, NULL);
  YaraSyntaxError = PyErr_NewException("yara.SyntaxError", YaraError, NULL);
  YaraTimeoutError = PyErr_NewException("yara.TimeoutError", YaraError, NULL);
  YaraWarningError = PyErr_NewException("yara.WarningError", YaraError, NULL);
#else
  YaraError = Py_BuildValue("s", "yara.Error");
  YaraSyntaxError = Py_BuildValue("s", "yara.SyntaxError");
  YaraTimeoutError = Py_BuildValue("s", "yara.TimeoutError");
  YaraWarningError = Py_BuildValue("s", "yara.WarningError");
#endif

  if (PyType_Ready(&Rule_Type) < 0)
    return MOD_ERROR_VAL;

  if (PyType_Ready(&Rules_Type) < 0)
    return MOD_ERROR_VAL;

  if (PyType_Ready(&Match_Type) < 0)
    return MOD_ERROR_VAL;

  PyModule_AddObject(m, "Error", YaraError);
  PyModule_AddObject(m, "SyntaxError", YaraSyntaxError);
  PyModule_AddObject(m, "TimeoutError", YaraTimeoutError);
  PyModule_AddObject(m, "WarningError", YaraWarningError);

  if (yr_initialize() != ERROR_SUCCESS)
  {
    PyErr_SetString(YaraError, "initialization error");
    return MOD_ERROR_VAL;
  }

  Py_AtExit(finalize);

  return MOD_SUCCESS_VAL(m);
}
