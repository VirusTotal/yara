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

#include <yara.h>

#if PY_VERSION_HEX < 0x02050000 && !defined(PY_SSIZE_T_MIN)
typedef int Py_ssize_t;
#define PY_SSIZE_T_MAX INT_MAX
#define PY_SSIZE_T_MIN INT_MIN
#endif

/* Module globals */

static PyObject *YaraError = NULL;
static PyObject *YaraSyntaxError = NULL;


static char* module_doc = "\
This module allows you to apply YARA rules to files or strings.               \n\
                                                                              \n\
First of all your need to compile your YARA rules. The method \"compile\" can \n\
receive a file path, a file object, or a string containing the rules.         \n\
                                                                              \n\
rules = yara.compile(filepath='/foo/bar/myrules')                             \n\
rules = yara.compile('/foo/bar/myrules')                                      \n\
                                                                              \n\
f = open('/foo/bar/myrules')                                                  \n\
rules = yara.compile(file=f)                                                  \n\
f.close()                                                                     \n\
                                                                              \n\
rules = yara.compile(source='rule dummy { condition: true }')                 \n\
                                                                              \n\
This method returns an instance of the \"Rules\" class if the rules were      \n\
compiled sucessfully, or raises an exception in other case.                   \n\
                                                                              \n\
The returned \"Rules\" object has a method \"match\" that allows you to apply \n\
the rules to your data. This method can receive a file path or a string       \n\
containing the data.                                                          \n\
                                                                              \n\
matches = rules.match(filepath='/foo/bar/myfile')                             \n\
matches = rules.match('/foo/bar/myfile')                                      \n\
                                                                              \n\
f = fopen('/foo/bar/myfile', 'rb')                                            \n\
matches = rules.match(data=f.read())                                          \n\
                                                                              \n\
The \"match\" method returns a list of instances of the class \"Match\". The  \n\
instances of this class can be treated as text string containing the name of  \n\
the matching YARA rule.                                                       \n\
                                                                              \n\
For example you can print them:                                               \n\
                                                                              \n\
foreach m in matches:                                                         \n\
    print \"%s\" % m                                                          \n\
                                                                              \n\
In some circumstances you may need to explicitly convert the instance of      \n\
\"Match\" to string, for example when comparing it with another string:       \n\
                                                                              \n\
if str(matches[0]) == 'SomeRuleName':                                         \n\
    ...                                                                       \n\
                                                                              \n\
The \"Match\" class have the following attributes:                            \n\
	                                                                          \n\
- rule	                                                                      \n\
- namespace	                                                                  \n\
- meta	                                                                      \n\
- tags	                                                                      \n\
- strings	                                                                  \n\
	                                                                          \n\
The \"rule\" and \"namespace\" attributes are the names of the matching rule and\n\
its namespace respectively.                                                   \n\
	                                                                          \n\
The \"meta\" attribute is a dictionary containing the metadata associated to the\n\
rule, where the metadata identifiers are the dictionary keys.                 \n\
	                                                                          \n\
The \"tags\" attribute is a list of strings containing the tags associated to \n\
the rule.                                                                     \n\
	                                                                          \n\
The \"strings\" attribute is a list of tuples containig the offset, identifier,\n\
and content of the matching strings.                                          \n";



//////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    
    PyObject_HEAD
	PyObject* rule;
	PyObject* ns;
    PyObject* tags;
    PyObject* meta;
    PyObject* strings;

} Match;

static PyObject * Match_repr(PyObject *self);
static PyObject * Match_getattro(PyObject *self, PyObject *name);
static int Match_compare(PyObject *self, PyObject *other);
static long Match_hash(PyObject *self);
static void Match_dealloc(PyObject *self);


//TODO: Change strings member to be a dictionary of offsets and objects of my own String class. This class should hold information about the matching string.

static PyMemberDef Match_members[] = {
	{"rule", T_OBJECT_EX, offsetof(Match, rule), READONLY, "Name of the matching rule"},
	{"namespace", T_OBJECT_EX, offsetof(Match, ns), READONLY, "Namespace of the matching rule"},
    {"tags", T_OBJECT_EX, offsetof(Match, tags), READONLY, "List of tags associated to the rule"},
    {"meta", T_OBJECT_EX, offsetof(Match, meta), READONLY, "Dictionary with metadata associated to the rule"},
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
	Match_compare,              /*tp_compare*/
    Match_repr,                 /*tp_repr*/
    0,                          /*tp_as_number*/
    0,                          /*tp_as_sequence*/
    0,                          /*tp_as_mapping*/
    Match_hash,                 /*tp_hash */
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


static PyObject * Match_NEW(const char* rule, const char* ns, PyObject* tags, PyObject* meta, PyObject* strings)
{ 
    Match* object;
    
    object = PyObject_NEW(Match, &Match_Type);
    
    if (object != NULL)
    {
		object->rule = PyString_FromString(rule);
		object->ns = PyString_FromString(ns);
        object->tags = tags;
        object->meta = meta;
        object->strings = strings;
    } 
      
    return (PyObject *)object;
}

static void Match_dealloc(PyObject *self)
{    
    Match *object = (Match *) self;
     
	Py_DECREF(object->rule); 
	Py_DECREF(object->ns);
    Py_DECREF(object->tags);
    Py_DECREF(object->meta);  
    Py_DECREF(object->strings);

    PyObject_Del(self);
}

static PyObject * Match_repr(PyObject *self)
{ 
    Match *object = (Match *) self;
	Py_INCREF(object->rule);
    return object->rule;
}

static PyObject * Match_getattro(PyObject *self, PyObject *name)
{
    return PyObject_GenericGetAttr(self, name); 
}

static int Match_compare(PyObject *self, PyObject *other)
{
	int result;
	
	Match *a = (Match *) self;
	Match *b = (Match *) other;
	
	if(PyObject_TypeCheck(other, &Match_Type))
	{
		result = PyObject_Compare(a->rule, b->rule);
		
		if (result == 0)
		{
			result = PyObject_Compare(a->ns, b->ns);
		}
	}
	else
	{
		result = -1;
		PyErr_BadArgument();
	}
	
	return result;
	
}

static long Match_hash(PyObject *self)
{
	Match *match = (Match *) self;
	
	return PyObject_Hash(match->rule) + PyObject_Hash(match->ns);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    
    PyObject_HEAD
    YARA_CONTEXT* context;

} Rules;


static PyObject * Rules_match(PyObject *self, PyObject *args, PyObject *keywords);
static PyObject * Rules_weight(PyObject *self);
static PyObject * Rules_getattro(PyObject *self, PyObject *name);
static void Rules_dealloc(PyObject *self);


static PyMethodDef Rules_methods[] = 
{
  {"match", (PyCFunction) Rules_match, METH_VARARGS | METH_KEYWORDS},
  {"weight", (PyCFunction) Rules_weight, METH_NOARGS},
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
    0,          				/*tp_as_number*/
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

int process_externals(PyObject* externals, YARA_CONTEXT* context)
{
    PyObject *key, *value;
	Py_ssize_t pos = 0;
	
	char* identifier = NULL;

    while (PyDict_Next(externals, &pos, &key, &value)) 
    {
        identifier = PyString_AsString(key);
        
        if (PyInt_Check(value))
        {
            yr_set_external_integer(context, identifier, PyInt_AsLong(value));
        } 
        else if (PyBool_Check(value))
        {
            yr_set_external_boolean(context, identifier, PyObject_IsTrue(value));
        }
        else if (PyString_Check(value))
        {
            yr_set_external_string(context, identifier, PyString_AsString(value));
        }
        else
        {
            return FALSE;
        }				
    }

    return TRUE;
}


static PyObject * Rules_new_from_file(FILE* file, const char* filepath, PyObject* rules, YARA_CONTEXT* context)
{ 
    Rules* result;
    
    int  errors;
    int  error_line;
    char error_message[256];

    if (file == NULL)
    {
        return PyErr_SetFromErrno(PyExc_IOError);
    }
	
	if (filepath != NULL)
	{
        yr_push_file_name(context, filepath);
	}
		         
    errors = yr_compile_file(file, context);
       
    if (errors)   /* errors during compilation */
    {
        error_line = context->last_error_line;
        yr_get_error_message(context, error_message, sizeof(error_message));
        
        return PyErr_Format(YaraSyntaxError, "line %d: %s", error_line, error_message);
    }

	if (rules == NULL)
	{
		result = PyObject_NEW(Rules, &Rules_Type);

		if (result != NULL)
	        result->context = context;
	}
	else
	{
		result = (Rules*) rules;
	}
          
    return (PyObject *) result;
}


static PyObject * Rules_new_from_string(const char* string, PyObject* rules, YARA_CONTEXT* context)
{ 
	Rules* result;

    int  errors;
    int  error_line;
    char error_message[256];
    	
    errors = yr_compile_string(string, context);
       
    if (errors)   /* errors during compilation */
    {
        error_line = context->last_error_line;
        yr_get_error_message(context, error_message, sizeof(error_message));
              
        return PyErr_Format(YaraSyntaxError, "line %d: %s", error_line, error_message);	
    }

	if (rules == NULL)
	{
		result = PyObject_NEW(Rules, &Rules_Type);

		if (result != NULL)
	        result->context = context;
	}
	else
	{
		result = (Rules*) rules;
	}
          
    return (PyObject*) result;
}

static void Rules_dealloc(PyObject *self)
{     
    yr_destroy_context(((Rules*) self)->context);
    PyObject_Del(self);
}


typedef struct _CALLBACK_DATA {

    PyObject *matches;
    PyObject *callback;
    
} CALLBACK_DATA;


int yara_callback(RULE* rule, void* data)
{
    TAG* tag;
    STRING* string;
    MATCH* m;
    META* meta;
    
    PyObject* tag_list = NULL;
    PyObject* string_list = NULL;
    PyObject* meta_list = NULL;
    PyObject* match;
    PyObject* callback_dict;
    PyObject* object;
    PyObject* matches = ((CALLBACK_DATA*) data)->matches;
    PyObject* callback = ((CALLBACK_DATA*) data)->callback;
    PyObject* callback_result;
    
    long result = CALLBACK_CONTINUE;
    
    if (!(rule->flags & RULE_FLAGS_MATCH) && callback == NULL)
        return CALLBACK_CONTINUE;
    
    tag_list = PyList_New(0);
    string_list = PyList_New(0);
    meta_list = PyDict_New();
    
    if (tag_list == NULL || string_list == NULL || meta_list == NULL)
    {
        Py_XDECREF(tag_list);
        Py_XDECREF(string_list);
        Py_XDECREF(meta_list);
        
        return CALLBACK_ERROR;
    }           
    
    tag = rule->tag_list_head;
    
    while(tag != NULL)
    {
        object = PyString_FromString(tag->identifier);
        PyList_Append(tag_list, object);
        Py_DECREF(object);    
                   
        tag = tag->next;
    }      
    
    meta = rule->meta_list_head;
    
    while(meta != NULL)
    {
        if (meta->type == META_TYPE_INTEGER)
        {
            object = Py_BuildValue("I", meta->integer);
        }
        else if (meta->type == META_TYPE_BOOLEAN)
        {
            object = PyBool_FromLong(meta->boolean);
        }
        else
        {
            object = PyString_FromString(meta->string);
        }
        
        PyDict_SetItemString( meta_list, meta->identifier, object);  
        Py_DECREF(object);
        
        meta = meta->next;
    } 
    
    string = rule->string_list_head;

    while (string != NULL)
    {
        if (string->flags & STRING_FLAGS_FOUND)
        {
            m = string->matches;

            while (m != NULL)
            {
                object = Py_BuildValue("(i,s,s#)", m->offset, string->identifier, (char*) m->data, m->length);
                PyList_Append(string_list, object);
                Py_DECREF(object);
                
                m = m->next;
            }
        }

        string = string->next;
    }
    
    PyList_Sort(string_list);
    
    if (rule->flags & RULE_FLAGS_MATCH)
    {
        match = Match_NEW(rule->identifier, rule->ns->name, tag_list, meta_list, string_list);

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
    
            return CALLBACK_ERROR;
        }
    }
    
    if (callback != NULL)
	{
	    Py_INCREF(callback); 
	    
	    callback_dict = PyDict_New();
	    
	    object = PyBool_FromLong(rule->flags & RULE_FLAGS_MATCH);
        PyDict_SetItemString(callback_dict, "matches", object);
        Py_DECREF(object);
	    
        object = PyString_FromString(rule->identifier);        
        PyDict_SetItemString(callback_dict, "rule", object);
        Py_DECREF(object);
        
        object = PyString_FromString(rule->ns->name);
        PyDict_SetItemString(callback_dict, "namespace", object);
        Py_DECREF(object);
        
	    PyDict_SetItemString(callback_dict, "tags", tag_list);
	    PyDict_SetItemString(callback_dict, "meta", meta_list);
	    PyDict_SetItemString(callback_dict, "strings", string_list);

		callback_result = PyObject_CallFunction(callback, "O", callback_dict);
		
		if (PyInt_Check(callback_result))
		{
		    result = PyInt_AsLong(callback_result);
		}
    
        Py_DECREF(callback_dict);
		Py_DECREF(callback_result);
		Py_DECREF(callback); 
	}
    
    return result;

}

PyObject * Rules_match(PyObject *self, PyObject *args, PyObject *keywords)
{
    static char *kwlist[] = {"filepath", "pid", "data", "externals", "callback", NULL};
    
    char* filepath = NULL;
    char* data = NULL;

    int pid = 0;
    int length;
    int result;
    
    PyObject *externals = NULL;
    
    CALLBACK_DATA callback_data;
    
    callback_data.matches = NULL;
    callback_data.callback = NULL;
    
    Rules* object = (Rules*) self;
    
    if (PyArg_ParseTupleAndKeywords(args, keywords, "|sis#OO", kwlist, &filepath, &pid, &data, &length, &externals, &callback_data.callback))
    {
        if (externals != NULL)
        {
            if (PyDict_Check(externals))
			{
				if (!process_externals(externals, object->context))
			    {
			        return PyErr_Format(PyExc_TypeError, "external values must be of type integer, boolean or string");
				}				
			}
			else
			{
				return PyErr_Format(PyExc_TypeError, "'externals' must be a dictionary");
			}
        }
             
        if (callback_data.callback != NULL)
        {
            if (!PyCallable_Check(callback_data.callback)) 
            {
                return PyErr_Format(YaraError, "callback must be callable");
            }
        }
             
        if (filepath != NULL)
        {    
            callback_data.matches = PyList_New(0);
        
            result = yr_scan_file(filepath, object->context, yara_callback, &callback_data);

            if (result != ERROR_SUCCESS)
            {
                Py_DECREF(callback_data.matches);

                switch(result)
                {
                    case ERROR_COULD_NOT_OPEN_FILE:
                        return PyErr_Format(YaraError, "could not open file \"%s\"", filepath);
                    case ERROR_COULD_NOT_MAP_FILE:
                        return PyErr_Format(YaraError, "could not map file \"%s\" into memory", filepath);
                    case ERROR_ZERO_LENGTH_FILE:
                        return PyErr_Format(YaraError, "zero length file \"%s\"", filepath);
                    default:
                        return PyErr_Format(YaraError, "unknown error while scanning file \"%s\"", filepath);
                }
            }
        }
        else if (data != NULL)
        {
            callback_data.matches = PyList_New(0);
        
			result = yr_scan_mem((unsigned char*) data, (unsigned int) length, object->context, yara_callback, &callback_data);

            if (result != ERROR_SUCCESS)
            {
               Py_DECREF(callback_data.matches);
               return PyErr_Format(PyExc_Exception, "internal error"); 
            }
        }
        else if (pid != 0)
        {
            callback_data.matches = PyList_New(0);
            
            result = yr_scan_proc(pid, object->context, yara_callback, &callback_data);
            
            if (result != ERROR_SUCCESS)
            {
               Py_DECREF(callback_data.matches);
               
               switch(result)
               {
                   case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
                       return PyErr_Format(YaraError, "access denied");
                   case ERROR_INSUFICIENT_MEMORY:
                       return PyErr_Format(YaraError, "not enough memory"); 
                   default:
                       return PyErr_Format(YaraError, "unknown error while scanning file \"%s\"", filepath);
               }
            }
        }
        else
        {
            return PyErr_Format(PyExc_TypeError, "match() takes 1 argument");
        }
    }
    
    return callback_data.matches;
}

static PyObject * Rules_getattro(PyObject *self, PyObject *name)
{
    return PyObject_GenericGetAttr(self, name); 
}

static PyObject * Rules_weight(PyObject *self)
{
    Rules* object = (Rules*) self;
    
    return PyInt_FromLong(yr_calculate_rules_weight(object->context));
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////

static PyObject * yara_compile(PyObject *self, PyObject *args, PyObject *keywords)
{ 
    static char *kwlist[] = {"filepath", "source", "file", "filepaths", "sources", "includes", "externals", NULL};
    
    YARA_CONTEXT* context;
    FILE* fh;
    
    PyObject *result = NULL;
	PyObject *file = NULL;
	
	PyObject *sources_dict = NULL;
	PyObject *filepaths_dict = NULL;
	PyObject *includes = NULL;
	PyObject *externals = NULL;
	
	PyObject *key, *value;
	
	Py_ssize_t pos = 0;

    char* filepath = NULL;
    char* source = NULL;
	char* ns = NULL;
	    
    if (PyArg_ParseTupleAndKeywords(args, keywords, "|ssOOOOO", kwlist, &filepath, &source, &file, &filepaths_dict, &sources_dict, &includes, &externals))
    {      
        context = yr_create_context();
   
   		if (context == NULL)
       		return PyErr_NoMemory();
       		      		
       	if (includes != NULL)
        {
            if (PyBool_Check(includes))
            {
                context->allow_includes = (PyObject_IsTrue(includes) == 1);  // PyObject_IsTrue can return -1 in case of error
            }
            else
            {
                yr_destroy_context(context); 
                return PyErr_Format(PyExc_TypeError, "'includes' param must be of boolean type");
            }
        }
          	
        if (externals != NULL)
        {
            if (PyDict_Check(externals))
            {
                if (!process_externals(externals, context))
                {
                    yr_destroy_context(context); 
                    return PyErr_Format(PyExc_TypeError, "external values must be of type integer, boolean or string");
                }				
            }
            else
            {
                yr_destroy_context(context); 
                return PyErr_Format(PyExc_TypeError, "'externals' must be a dictionary");
            }
        }
     
        if (filepath != NULL)
        {            
            fh = fopen(filepath, "r");
            
            if (fh != NULL)
            {
                result = Rules_new_from_file(fh, filepath, NULL, context);
                fclose(fh);
            }
            else
            {
                result = PyErr_SetFromErrno(YaraError);
            }
        }
        else if (source != NULL)
        {
            result = Rules_new_from_string(source, NULL, context);
        }
        else if (file != NULL)
        {
            fh = PyFile_AsFile(file);   
            result = Rules_new_from_file(fh, NULL, NULL, context);
        }
        else if (sources_dict != NULL)
        {
            if (PyDict_Check(sources_dict))
			{
				while (PyDict_Next(sources_dict, &pos, &key, &value)) 
				{
					source = PyString_AsString(value);
					ns = PyString_AsString(key);
					
					if (source != NULL && ns != NULL)
					{
		                context->current_namespace = yr_create_namespace(context, ns);

						result = Rules_new_from_string(source, result, context);
					}
					else
					{
						result = PyErr_Format(PyExc_TypeError, "keys and values of the 'sources' dictionary must be of string type");
						break;
					}
				}
			}
			else
			{
				result = PyErr_Format(PyExc_TypeError, "'sources' must be a dictionary");
			}
        }
        else if (filepaths_dict != NULL)
        {
            if (PyDict_Check(filepaths_dict))
			{
				while (PyDict_Next(filepaths_dict, &pos, &key, &value)) 
				{
					filepath = PyString_AsString(value);
					ns = PyString_AsString(key);
					
					if (filepath != NULL && ns != NULL)
					{
						fh = fopen(filepath, "r");
            
            			if (fh != NULL)
            			{
            			    context->current_namespace = yr_create_namespace(context, ns);
            			
                			result = Rules_new_from_file(fh, filepath, result, context);
                			fclose(fh);
            			}
            			else
            			{
                			result = PyErr_SetFromErrno(YaraError);
            			}
					}
					else
					{
						result = PyErr_Format(PyExc_TypeError, "keys and values of the filepaths dictionary must be of string type");
						break;
					}
				}
			}
			else
			{
				result = PyErr_Format(PyExc_TypeError, "filepaths must be a dictionary");
			}
        }
        else
        {
            result = PyErr_Format(PyExc_TypeError, "compile() takes 1 argument");
        }
    } 
      
    return result;
}

/* Module functions */

static PyMethodDef methods[] = {
  {"compile", (PyCFunction) yara_compile, METH_VARARGS | METH_KEYWORDS, "Compiles a YARA rules file and returns an instance of class Rules"},
  {NULL, NULL},
};

/* Module init function */

void inityara(void)
{ 
    PyObject *m;
    
    yr_init();
 
    m = Py_InitModule3("yara", methods, module_doc);
    
    /* initialize module variables/constants */
    
    PyModule_AddIntConstant(m, "CALLBACK_CONTINUE", 0);
    PyModule_AddIntConstant(m, "CALLBACK_ABORT", 1);

#if PYTHON_API_VERSION >= 1007
    YaraError = PyErr_NewException("yara.Error", PyExc_StandardError, NULL);
    YaraSyntaxError = PyErr_NewException("yara.SyntaxError", YaraError, NULL);
#else
    YaraError = Py_BuildValue("s", "yara.Error");
    YaraSyntaxError = Py_BuildValue("s", "yara.SyntaxError");
#endif

    PyModule_AddObject(m, "Error", YaraError);
    PyModule_AddObject(m, "SyntaxError", YaraSyntaxError);
}
