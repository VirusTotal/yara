/*

Copyright(c) 2008. Victor M. Alvarez [plusvic@gmail.com].

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

*/

/* headers */

#include <Python.h>
#include "structmember.h"

#include "yara.h"

/* Module globals */

static PyObject *yara_error = NULL;

static char* module_doc = "\
This module allows you to apply YARA rules to files or strings. You will need to        \n\
compile the YARA rules before applying them to your data:                               \n\
                                                                                        \n\
rules = yara.compile('/foo/bar/myrules')                                                \n\
The method \"compile\" of this module returns an instance of the class \"Rules\", which \n\
in turn has two methods: \"matchfile\" and \"match\". The first one applies the rules   \n\
to a file given its path:                                                               \n\
                                                                                        \n\
matches = rules.matchfile('/foo/bar/myfile')                                            \n\
                                                                                        \n\
The second one applies the rules to a string:                                           \n\
                                                                                        \n\
f = fopen('/foo/bar/myfile', 'rb')                                                      \n\
data = f.read()                                                                         \n\
f.close()                                                                               \n\
                                                                                        \n\
matches = rules.match(data)                                                             \n\
                                                                                        \n\
Both methods return a list of instances of the class \"Match\". The instances of this   \n\
class can be treated as text string containing the name of the matching YARA rule.      \n\
For example you can print them:                                                         \n\
                                                                                        \n\
foreach m in matches:                                                                   \n\
    print \"%s\" % m                                                                    \n\
                                                                                        \n\
In some circumstances you may need to explicitly convert the instance of \"Match\" to   \n\
string, for example when comparing it with another string:                              \n\
                                                                                        \n\
if str(matches[0]) == 'SomeRuleName':                                                   \n\
    ...                                                                                 \n\
                                                                                        \n\
The \"Match\" class have another two attributes: \"tags\" and \"strings\". The \"tags\" \n\
attribute is a list of strings containing the tags associated to the rule. The          \n\
\"strings\" attribute is a dictionary whose values are those strings within the data    \n\
that made the YARA rule match, and the keys are the offset where the associated         \n\
string was found.                                                                       \n";






//////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    
    PyObject_HEAD
    char* rule;
    PyObject* tags;
    PyObject* strings;

} Match;

static PyObject * Match_Repr(PyObject *self);
static PyObject * Match_getattro(PyObject *self, PyObject *name);
static void Match_dealloc(PyObject *self);

static PyMemberDef Match_members[] = {
    {"tags", T_OBJECT_EX, offsetof(Match, tags), READONLY, "List of tags associated to the rule"},
    {"strings", T_OBJECT_EX, offsetof(Match, strings), READONLY, "Dictionary with offsets and strings that matched the file"},
    {NULL}  /* Sentinel */
};

static PyMethodDef Match_methods[] = 
{
    {NULL},
};

static PyTypeObject Match_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
    "yara.Match",               /*tp_name*/
    sizeof(Match),              /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    (destructor)Match_dealloc,  /*tp_dealloc*/
    0,                          /*tp_print*/
    0,                          /*tp_getattr*/
    0,                          /*tp_setattr*/
    0,                          /*tp_compare*/
    Match_Repr,                 /*tp_repr*/
    0,                          /*tp_as_number*/
    0,                          /*tp_as_sequence*/
    0,                          /*tp_as_mapping*/
    0,                          /*tp_hash */
    0,                          /*tp_call*/
    0,                          /*tp_str*/
    Match_getattro,     /*tp_getattro*/
    0,                          /*tp_setattro*/
    0,                          /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "Match class",              /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
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


static PyObject * Match_NEW(char* rule, PyObject* tags, PyObject* strings)
{ 
    Match* object;
    
    object = PyObject_NEW(Match, &Match_Type);
    
    if (object != NULL)
    {
        object->rule = rule;   
        object->tags = tags;
        object->strings = strings;
    } 
      
    return (PyObject *)object;
}

static void Match_dealloc(PyObject *self)
{    
    Match *object = (Match *) self;
     
    Py_DECREF(object->tags); 
    Py_DECREF(object->strings);
    PyObject_FREE(self);
}

static PyObject * Match_Repr(PyObject *self)
{ 
    Match *object = (Match *) self;
    
    return PyString_FromString(object->rule);
}

static PyObject * Match_getattro(PyObject *self, PyObject *name)
{
    return PyObject_GenericGetAttr(self, name); 
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    
    PyObject_HEAD
    char* filepath;
    RULE_LIST* rules;

} Rules;


static PyObject * Rules_matchstring(PyObject *self, PyObject *args);
static PyObject * Rules_matchfile(PyObject *self, PyObject *args);
static PyObject * Rules_getattro(PyObject *self, PyObject *name);
static void Rules_dealloc(PyObject *self);

static PyMethodDef Rules_methods[] = 
{
  {"match", Rules_matchstring, METH_VARARGS},
  {"matchfile", Rules_matchfile, METH_VARARGS},
  {NULL, NULL},
};

static PyTypeObject Rules_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                          /*ob_size*/
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
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
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


//////////////////////////////////////////////////////////////////////////////////////////////////////////

static PyObject * Rules_NEW(char* filepath)
{ 
    FILE*  file;
    RULE_LIST* rules;
    Rules* object;
    int errors;
    
    rules = alloc_rule_list();
    
    if (rules == NULL)
    {
        return PyErr_NoMemory();
    }
    
    file = fopen(filepath, "r");
    
    if (file == NULL)
    {
        free_rule_list(rules);
        return PyErr_SetFromErrno(PyExc_IOError);
    }
        
    errors = compile_rules(file, rules);
    
    fclose(file);
        
    if (errors > 0)   /* errors during compilation */
    {
        free_rule_list(rules);              
        return PyErr_Format(PyExc_Exception, "error compiling rules"); 
    }
    
    object = PyObject_NEW(Rules, &Rules_Type);
    
    if (object != NULL)
    {
        init_hash_table(rules);
        object->filepath = filepath;    
        object->rules = rules;
    } 
      
    return (PyObject *)object;
}

static void Rules_dealloc(PyObject *self)
{      
    free_hash_table(((Rules*) self)->rules);
    free_rule_list(((Rules*) self)->rules);
    PyObject_FREE(self);
}

int callback(RULE* rule, unsigned char* buffer, unsigned int buffer_size, void* data)
{
    TAG* tag;
    STRING* string;
    MATCH* m;
    PyObject* taglist = NULL;
    PyObject* stringlist = NULL;
    PyObject* match;
    PyObject* list = (PyObject*) data;
    
    if (!(rule->flags & RULE_FLAGS_MATCH))
        return 0;
       
    taglist = PyList_New(0);
    stringlist = PyDict_New();
    
    if (taglist == NULL || stringlist == NULL)
        return 1; // error!
        
    tag = rule->tag_list_head;
    
    while(tag != NULL)
    {
        PyList_Append(taglist, PyString_FromString(tag->identifier));               
        tag = tag->next;
    }       
    
    string = rule->string_list_head;

    while (string != NULL)
    {
        if (string->flags & STRING_FLAGS_FOUND)
        {
            m = string->matches;

            while (m != NULL)
            {
                PyDict_SetItem( stringlist,
                                PyInt_FromLong(m->offset),
                                PyString_FromStringAndSize((char*) buffer + m->offset, m->length));
                m = m->next;
            }
        }

        string = string->next;
    }
    
    
    match = Match_NEW(rule->identifier, taglist, stringlist);
    
    if (match != NULL)
    {       
        PyList_Append(list, match);
    }
    else
    {
        PyObject_FREE(taglist);
        PyObject_FREE(stringlist);
        return 1;
    }
    
    return 0;

}

PyObject * Rules_matchstring(PyObject *self, PyObject *args)
{
    char* data;
    int length;
    int result;
    
    PyObject *matches = NULL;
    Rules *object = (Rules *)self;
    
    if (PyArg_ParseTuple(args, "t#", &data, &length)) 
    {  
        matches = PyList_New(0);
        
        result = scan_mem((unsigned char*) data, (unsigned int) length, object->rules, callback, matches);
       
       if (result != ERROR_SUCCESS)
       {
           PyObject_FREE(matches);
           return PyErr_Format(PyExc_Exception, "internal error"); 
       }
    }
    
    return matches;
}

PyObject * Rules_matchfile(PyObject *self, PyObject *args)
{
    char* filepath;
    int result;
    PyObject *matches = NULL;
    Rules *object = (Rules *)self;
     
    if (PyArg_ParseTuple(args, "s", &filepath)) 
    {  
        matches = PyList_New(0);
        
        result = scan_file(filepath, object->rules, callback, matches);
       
        if (result == ERROR_COULD_NOT_OPEN_FILE)
        {
            PyObject_FREE(matches);
            return PyErr_SetFromErrno(PyExc_IOError);
        }
        else if (result != ERROR_SUCCESS)
        {
            PyObject_FREE(matches);
            return PyErr_Format(PyExc_Exception, "internal error");
        }
    }
    
    return matches;
}

static PyObject * Rules_getattro(PyObject *self, PyObject *name)
{
    return PyObject_GenericGetAttr(self, name); 
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////

static PyObject * yara_compile(PyObject *self, PyObject *args)
{ 
    PyObject *result = NULL;
    
    char* filepath = NULL;

    if (PyArg_ParseTuple(args, "s", &filepath))
      result = Rules_NEW(filepath);
      
    return result;
}

/* Module functions */

static PyMethodDef methods[] = {
  {"compile", yara_compile, METH_VARARGS, "Compiles a YARA rules file and returns an instance of class Rules"},
  {NULL, NULL},
};

/* Module init function */

void inityara(void)
{ 
    PyObject *m, *d;
 
    m = Py_InitModule3("yara", methods, module_doc);
    d = PyModule_GetDict(m);

    /* initialize module variables/constants */

#if PYTHON_API_VERSION >= 1007
    yara_error = PyErr_NewException("yara.error", NULL, NULL);
#else
    yara_error = Py_BuildValue("s", "yara.error");
#endif
    PyDict_SetItemString(d, "error", yara_error);
}
