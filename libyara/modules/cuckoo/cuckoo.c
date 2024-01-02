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


#include <jansson.h>
#include <string.h>
#include <yara/modules.h>
#include <yara/re.h>


#if defined(_WIN32) || defined(__CYGWIN__)
#define strcasecmp _stricmp
#endif

#define MODULE_NAME cuckoo


define_function(network_dns_lookup)
{
  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_OBJECT* network_obj = yr_parent();

  json_t* network_json = (json_t*) network_obj->data;
  json_t* value;

  uint64_t result = 0;
  size_t index;

  // Recent versions of Cuckoo generate domain resolution information with
  // this format:
  //
  //       "domains": [
  //           {
  //               "ip": "192.168.0.1",
  //               "domain": "foo.bar.com"
  //           }
  //        ]
  //
  // But older versions with this other format:
  //
  //       "dns": [
  //           {
  //               "ip": "192.168.0.1",
  //               "hostname": "foo.bar.com"
  //           }
  //        ]
  //
  // Additionally, the newer versions also have a "dns" field. So, let's try
  // to locate the "domains" field first, if not found fall back to the older
  // format.

  char* field_name = "domain";
  char* hostname;
  char* ip;

  json_t* dns_info_json = json_object_get(network_json, "domains");

  if (dns_info_json == NULL)
  {
    dns_info_json = json_object_get(network_json, "dns");
    field_name = "hostname";
  }

  json_array_foreach(dns_info_json, index, value)
  {
    if (json_unpack(value, "{s:s, s:s}", "ip", &ip, field_name, &hostname) == 0)
    {
      if (yr_re_match(context, regexp_argument(1), hostname) > 0)
      {
        result = 1;
        break;
      }
    }
  }

  return_integer(result);
}


#define METHOD_GET  0x01
#define METHOD_POST 0x02


uint64_t http_request(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* network_obj,
    RE* uri_regexp,
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
    if (json_unpack(value, "{s:s, s:s}", "uri", &uri, "method", &method) == 0)
    {
      if (((methods & METHOD_GET && strcasecmp(method, "get") == 0) ||
           (methods & METHOD_POST && strcasecmp(method, "post") == 0)) &&
          yr_re_match(context, uri_regexp, uri) > 0)
      {
        result = 1;
        break;
      }
    }
  }

  return result;
}


define_function(network_http_request)
{
  return_integer(http_request(
      yr_scan_context(), yr_parent(), regexp_argument(1), METHOD_GET | METHOD_POST));
}


define_function(network_http_get)
{
  return_integer(
      http_request(yr_scan_context(), yr_parent(), regexp_argument(1), METHOD_GET));
}


define_function(network_http_post)
{
  return_integer(
      http_request(yr_scan_context(), yr_parent(), regexp_argument(1), METHOD_POST));
}


// checks the host array in network JSON
// loops through array and checks value for argument
define_function(network_host)
{
  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_OBJECT* network_obj = yr_parent();

  json_t* network_json = (json_t*) network_obj->data;
  json_t* value;

  uint64_t result = 0;
  size_t index;

  json_t* hosts_info_json = json_object_get(network_json, "hosts");

  json_array_foreach(hosts_info_json, index, value)
  {
    if (yr_re_match(context, regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }

  return_integer(result);
}

// loops through TCP array in network JSON
// checks for dest IP regex and dest port integer match
define_function(network_tcp)
{
  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_OBJECT* network_obj = yr_parent();

  json_t* network_json = (json_t*) network_obj->data;
  json_t* value;

  uint64_t result = 0;
  size_t index;

  int dport;
  char* dst;

  json_t* tcp_info_json = json_object_get(network_json, "tcp");

  json_array_foreach(tcp_info_json, index, value)
  {
    if (json_unpack(value, "{s:i, s:s}", "dport", &dport, "dst", &dst) == 0)
    {
      if (yr_re_match(context, regexp_argument(1), dst) > 0)
      {
        if ((int64_t) dport == integer_argument(2))
        {
          result = 1;
          break;
        }
      }
    }
  }

  return_integer(result);
}


// loops through UDP array in network JSON
// checks for dest IP regex and dest port integer match
define_function(network_udp)
{
  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_OBJECT* network_obj = yr_parent();

  json_t* network_json = (json_t*) network_obj->data;
  json_t* value;

  uint64_t result = 0;
  size_t index;

  int dport;
  char* dst;

  json_t* udp_info_json = json_object_get(network_json, "udp");

  json_array_foreach(udp_info_json, index, value)
  {
    if (json_unpack(value, "{s:i, s:s}", "dport", &dport, "dst", &dst) == 0)
    {
      if (yr_re_match(context, regexp_argument(1), dst) > 0)
      {
        if ((int64_t) dport == integer_argument(2))
        {
          result = 1;
          break;
        }
      }
    }
  }

  return_integer(result);
}


// loops through http array in network JSON
// checks for regex match on user-agent
define_function(network_http_user_agent)
{
  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_OBJECT* network_obj = yr_parent();

  json_t* network_json = (json_t*) network_obj->data;
  json_t* http_json = json_object_get(network_json, "http");
  json_t* value;

  uint64_t result = 0;
  size_t index;

  char* user_agent;

  json_array_foreach(http_json, index, value)
  {
    if (json_unpack(value, "{s:s}", "user-agent", &user_agent) == 0)
    {
      if (yr_re_match(context, regexp_argument(1), user_agent) > 0)
      {
        result = 1;
        break;
      }
    }
  }

  return_integer(result);
}


define_function(registry_key_access)
{
  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_OBJECT* registry_obj = yr_parent();

  json_t* keys_json = (json_t*) registry_obj->data;
  json_t* value;

  uint64_t result = 0;
  size_t index;

  json_array_foreach(keys_json, index, value)
  {
    if (yr_re_match(context, regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }

  return_integer(result);
}


define_function(filesystem_file_access)
{
  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_OBJECT* filesystem_obj = yr_parent();

  json_t* files_json = (json_t*) filesystem_obj->data;
  json_t* value;

  uint64_t result = 0;
  size_t index;

  json_array_foreach(files_json, index, value)
  {
    if (yr_re_match(context, regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }

  return_integer(result);
}


define_function(sync_mutex)
{
  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_OBJECT* sync_obj = yr_parent();

  json_t* mutexes_json = (json_t*) sync_obj->data;
  json_t* value;

  uint64_t result = 0;
  size_t index;

  json_array_foreach(mutexes_json, index, value)
  {
    if (yr_re_match(context, regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }

  return_integer(result);
}


begin_declarations
  begin_struct("network")
    declare_function("dns_lookup", "r", "i", network_dns_lookup);
    declare_function("http_get", "r", "i", network_http_get);
    declare_function("http_post", "r", "i", network_http_post);
    declare_function("http_request", "r", "i", network_http_request);
    declare_function("http_user_agent", "r", "i", network_http_user_agent);
    declare_function("host", "r", "i", network_host);
    declare_function("tcp", "ri", "i", network_tcp);
    declare_function("udp", "ri", "i", network_udp);
  end_struct("network")

  begin_struct("registry")
    declare_function("key_access", "r", "i", registry_key_access);
  end_struct("registry")

  begin_struct("filesystem")
    declare_function("file_access", "r", "i", filesystem_file_access);
  end_struct("filesystem")

  begin_struct("sync")
    declare_function("mutex", "r", "i", sync_mutex)
  end_struct("sync")
end_declarations


int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


int module_finalize(YR_MODULE* module)
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

  json_error_t json_error;

  json_t* summary_json;
  json_t* json;

  if (module_data == NULL)
    return ERROR_SUCCESS;

  json = json_loadb(
      (const char*) module_data,
      module_data_size,
#if JANSSON_VERSION_HEX >= 0x020600
      JSON_ALLOW_NUL,
#else
      0,
#endif
      &json_error);

  if (json == NULL)
    return ERROR_INVALID_MODULE_DATA;

  module_object->data = (void*) json;

  network_obj = yr_get_object(module_object, "network");
  registry_obj = yr_get_object(module_object, "registry");
  filesystem_obj = yr_get_object(module_object, "filesystem");
  sync_obj = yr_get_object(module_object, "sync");

  network_obj->data = (void*) json_object_get(json, "network");

  json = json_object_get(json, "behavior");
  summary_json = json_object_get(json, "summary");

  registry_obj->data = (void*) json_object_get(summary_json, "keys");
  filesystem_obj->data = (void*) json_object_get(summary_json, "files");
  sync_obj->data = (void*) json_object_get(summary_json, "mutexes");

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module)
{
  if (module->data != NULL)
    json_decref((json_t*) module->data);

  return ERROR_SUCCESS;
}
