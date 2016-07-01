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

#include <string.h>
#include <jansson.h>


#include <yara/re.h>
#include <yara/modules.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#define strcasecmp _stricmp
#endif

#define MODULE_NAME cuckoo


define_function(network_dns_lookup)
{
  YR_OBJECT* network_obj = parent();

  json_t* network_json = (json_t*) network_obj->data;
  json_t* dns_json = json_object_get(network_json, "dns");
  json_t* value;

  uint64_t result = 0;
  size_t index;

  char* ip;
  char* hostname;

  json_array_foreach(dns_json, index, value)
  {
    json_unpack(value, "{s:s, s:s}", "ip", &ip, "hostname", &hostname);

    if (yr_re_match(regexp_argument(1), hostname) > 0)
    {
      result = 1;
      break;
    }
  }

  return_integer(result);
}


#define METHOD_GET    0x01
#define METHOD_POST   0x02


uint64_t http_request(
    YR_OBJECT* network_obj,
    RE_CODE uri_regexp,
    int methods)
{
  json_t* network_json = (json_t*) network_obj->data;
  json_t* http_json = json_object_get(network_json, "http");
  json_t* value;

  uint64_t result = 0;
  size_t index;

  char* method;
  char* uri;

  json_array_foreach(http_json, index, value)
  {
    json_unpack(value, "{s:s, s:s}", "uri", &uri, "method", &method);

    if (((methods & METHOD_GET && strcasecmp(method, "get") == 0) ||
         (methods & METHOD_POST && strcasecmp(method, "post") == 0)) &&
         yr_re_match(uri_regexp, uri) > 0)
    {
      result = 1;
      break;
    }
  }

  return result;
}


define_function(network_http_request)
{
  return_integer(
      http_request(
          parent(),
          regexp_argument(1),
          METHOD_GET | METHOD_POST));
}


define_function(network_http_get)
{
  return_integer(
      http_request(
          parent(),
          regexp_argument(1),
          METHOD_GET));
}


define_function(network_http_post)
{
  return_integer(
      http_request(
          parent(),
          regexp_argument(1),
          METHOD_POST));
}


#define REGISTRY_KEY_ACCESS         0x00
#define REGISTRY_KEY_READ           0x01
#define REGISTRY_KEY_WRITE          0x02
#define REGISTRY_KEY_DELETE         0x03
#define REGISTRY_KEY_VALUE_ACCESS   0x04


uint64_t registry_match(
  YR_OBJECT* registry_obj,
  RE_CODE name_regexp,
  int registry_operation_type)
{
  static const char* const registry_names[] = {
    "keys",
    "read_keys",
    "write_keys",
    "delete_keys"
  };

  json_t* summary_json = json_object_get((json_t*) registry_obj->data, "summary");
  json_t* registry_json = json_object_get(summary_json, registry_names[registry_operation_type]);
  json_t* value;

  uint64_t result = 0;
  size_t index;

  json_array_foreach(registry_json, index, value)
  {
    if (yr_re_match(name_regexp, json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }

  return result;
}


define_function(registry_key_access)
{
  return_integer(
    registry_match(
      parent(),
      regexp_argument(1),
      REGISTRY_KEY_ACCESS));
}


define_function(registry_key_read)
{
  return_integer(
    registry_match(
      parent(),
      regexp_argument(1),
      REGISTRY_KEY_READ));
}


define_function(registry_key_write)
{
  return_integer(
    registry_match(
      parent(),
      regexp_argument(1),
      REGISTRY_KEY_WRITE));
}


define_function(registry_key_delete)
{
  return_integer(
    registry_match(
      parent(),
      regexp_argument(1),
      REGISTRY_KEY_DELETE));
}


define_function(registry_key_value_access)
{
  YR_OBJECT* registry_obj = parent();

  json_t* enhanced_json = json_object_get((json_t*) registry_obj->data, "enhanced");
  json_t* value;

  uint64_t result = 0;
  size_t index;

  json_array_foreach(enhanced_json, index, value)
  {
    json_t* enhanced_json_object = json_object_get(value, "object");

    if (strcasecmp(json_string_value(enhanced_json_object), "registry") == 0)
    {
      json_t* registry_data = json_object_get(value, "data");

      json_t* regkey  = json_object_get(registry_data, "regkey");
      json_t* content = json_object_get(registry_data, "content");

      const char* regkey_str = json_string_value(regkey);
      const char* content_str = json_string_value(content);

      if (regkey_str  != NULL &&
          content_str != NULL &&
          yr_re_match(regexp_argument(1), regkey_str)  > 0 &&
          yr_re_match(regexp_argument(2), content_str) > 0)
      {
        result = 1;
        break;
      }
    }
  }

  return_integer(result);
}


#define FILESYSTEM_FILE_ACCESS  0x00
#define FILESYSTEM_FILE_READ    0x01
#define FILESYSTEM_FILE_WRITE   0x02
#define FILESYSTEM_FILE_DELETE  0x03


uint64_t filesystem_match(
  YR_OBJECT* filesystem_obj,
  RE_CODE name_regexp,
  int file_operation_type)
{
  static const char* const filesystem_names[] = {
    "files",
    "read_files",
    "write_files",
    "delete_files",
  };

  json_t* summary_json = (json_t*) filesystem_obj->data;
  json_t* filesystem_json = json_object_get(summary_json, filesystem_names[file_operation_type]);
  json_t* value;

  uint64_t result = 0;
  size_t index;

  json_array_foreach(filesystem_json, index, value)
  {
    if (yr_re_match(name_regexp, json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }

  return result;
}


define_function(filesystem_file_access)
{
  return_integer(
    filesystem_match(
      parent(),
      regexp_argument(1),
      FILESYSTEM_FILE_ACCESS));
}


define_function(filesystem_file_read)
{
  return_integer(
    filesystem_match(
      parent(),
      regexp_argument(1),
      FILESYSTEM_FILE_READ));
}


define_function(filesystem_file_write)
{
  return_integer(
    filesystem_match(
      parent(),
      regexp_argument(1),
      FILESYSTEM_FILE_WRITE));
}


define_function(filesystem_file_delete)
{
  return_integer(
    filesystem_match(
      parent(),
      regexp_argument(1),
      FILESYSTEM_FILE_DELETE));
}


define_function(sync_mutex)
{
  YR_OBJECT* sync_obj = parent();

  json_t* mutexes_json = (json_t*) sync_obj->data;
  json_t* value;

  uint64_t result = 0;
  size_t index;

  json_array_foreach(mutexes_json, index, value)
  {
    if (yr_re_match(regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }

  return_integer(result);
}


define_function(process_executed_command)
{
  YR_OBJECT* process_obj = parent();

  json_t* executed_commands_json = (json_t*) process_obj->data;
  json_t* value;

  uint64_t result = 0;
  size_t index;

  json_array_foreach(executed_commands_json, index, value)
  {
    if (yr_re_match(regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }

  return_integer(result);
}


begin_declarations;

  begin_struct("network");
    declare_function("dns_lookup", "r", "i", network_dns_lookup);
    declare_function("http_get", "r", "i", network_http_get);
    declare_function("http_post", "r", "i", network_http_post);
    declare_function("http_request", "r", "i", network_http_request);
  end_struct("network");

  begin_struct("registry");
    declare_function("key_access", "r", "i", registry_key_access);
    declare_function("key_read", "r", "i", registry_key_read);
    declare_function("key_write", "r", "i", registry_key_write);
    declare_function("key_delete", "r", "i", registry_key_delete);
    declare_function("key_value_access", "rr", "i", registry_key_value_access);
  end_struct("registry");

  begin_struct("filesystem");
    declare_function("file_access", "r", "i", filesystem_file_access);
    declare_function("file_read", "r", "i", filesystem_file_read);
    declare_function("file_write", "r", "i", filesystem_file_write);
    declare_function("file_delete", "r", "i", filesystem_file_delete);
  end_struct("filesystem");

  begin_struct("sync");
    declare_function("mutex", "r", "i", sync_mutex);
  end_struct("sync");

  begin_struct("process");
    declare_function("executed_command", "r", "i", process_executed_command);
  end_struct("process");

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
  YR_OBJECT* network_obj;
  YR_OBJECT* registry_obj;
  YR_OBJECT* filesystem_obj;
  YR_OBJECT* sync_obj;
  YR_OBJECT* process_obj;

  json_error_t json_error;

  json_t* summary_json;
  json_t* json;

  if (module_data == NULL)
    return ERROR_SUCCESS;

  json = json_loadb(
      (const char*) module_data,
      module_data_size,
      0,
      &json_error);

  if (json == NULL)
    return ERROR_INVALID_FILE;

  module_object->data = (void*) json;

  network_obj = get_object(module_object, "network");
  registry_obj = get_object(module_object, "registry");
  filesystem_obj = get_object(module_object, "filesystem");
  sync_obj = get_object(module_object, "sync");
  process_obj = get_object(module_object, "process");

  network_obj->data = (void*) json_object_get(json, "network");

  json = json_object_get(json, "behavior");
  summary_json = json_object_get(json, "summary");

  registry_obj->data = (void*) json;
  filesystem_obj->data = (void*) summary_json;
  sync_obj->data = (void*) json_object_get(summary_json, "mutexes");
  process_obj->data = (void*) json_object_get(summary_json, "executed_commands");

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module)
{
  if (module->data != NULL)
    json_decref((json_t*) module->data);

  return ERROR_SUCCESS;
}
