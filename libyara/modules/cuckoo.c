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

#include <string.h>
#include <jansson.h>


#include <yara/re.h>
#include <yara/modules.h>


#define MODULE_NAME cuckoo


define_function(network_dns_lookup)
{
  YR_OBJECT* network_obj = self();

  json_t* network_json = (json_t*) network_obj->data;
  json_t* dns_json = json_object_get(network_json, "dns");;
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
    uint8_t* uri_regexp,
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
          self(),
          regexp_argument(1),
          METHOD_GET | METHOD_POST));
}


define_function(network_http_get)
{
  return_integer(
      http_request(
          self(),
          regexp_argument(1),
          METHOD_GET));
}


define_function(network_http_post)
{
  return_integer(
      http_request(
          self(),
          regexp_argument(1),
          METHOD_POST));
}


define_function(registry_key_access)
{
  YR_OBJECT* registry_obj = self();

  json_t* keys_json = (json_t*) registry_obj->data;
  json_t* value;

  uint64_t result = 0;
  size_t index;

  json_array_foreach(keys_json, index, value)
  {
    if (yr_re_match(regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }

  return_integer(result);
}


define_function(filesystem_file_access)
{
  YR_OBJECT* filesystem_obj = self();

  json_t* files_json = (json_t*) filesystem_obj->data;
  json_t* value;

  uint64_t result = 0;
  size_t index;

  json_array_foreach(files_json, index, value)
  {
    if (yr_re_match(regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }

  return_integer(result);
}



define_function(sync_mutex)
{
  YR_OBJECT* sync_obj = self();

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


int module_load(
    YR_EVALUATION_CONTEXT* context,
    YR_OBJECT* main_struct,
    void* module_data,
    size_t module_data_size)
{
  YR_OBJECT* network_obj;
  YR_OBJECT* registry_obj;
  YR_OBJECT* filesystem_obj;
  YR_OBJECT* sync_obj;

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

  main_struct->data = (void*) json;

  network_obj = get_object(main_struct, "network");
  registry_obj = get_object(main_struct, "registry");
  filesystem_obj = get_object(main_struct, "filesystem");
  sync_obj = get_object(main_struct, "sync");

  network_obj->data = (void*) json_object_get(json, "network");

  json = json_object_get(json, "behavior");
  summary_json = json_object_get(json, "summary");

  registry_obj->data = (void*) json_object_get(summary_json, "keys");
  filesystem_obj->data = (void*) json_object_get(summary_json, "files");
  sync_obj->data = (void*) json_object_get(summary_json, "mutexes");

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* main_struct)
{
  if (main_struct->data != NULL)
    json_decref((json_t*) main_struct->data);

  return ERROR_SUCCESS;
}


begin_declarations;

  begin_struct("network");
    function("dns_lookup", "s", "i", network_dns_lookup);
    function("http_get", "r", "i", network_http_get);
    function("http_post", "r", "i", network_http_post);
    function("http_request", "r", "i", network_http_request);
  end_struct("network");

  begin_struct("registry");
    function("key_access", "r", "i", registry_key_access);
  end_struct("registry");

  begin_struct("filesystem");
    function("file_access", "r", "i", filesystem_file_access);
  end_struct("filesystem");

  begin_struct("sync");
    function("mutex", "r", "i", sync_mutex);
  end_struct("sync");

end_declarations;



#undef MODULE_NAME