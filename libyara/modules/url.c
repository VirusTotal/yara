/*
Copyright (c) 2019. The YARA Authors. All Rights Reserved.

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

#include <curl/urlapi.h>
#include <yara/mem.h>
#include <yara/modules.h>

#define MODULE_NAME url


const unsigned int SET_FLAGS = CURLU_NON_SUPPORT_SCHEME | CURLU_URLENCODE | CURLU_DEFAULT_SCHEME;
const unsigned int GET_FLAGS = CURLU_DEFAULT_PORT | CURLU_DEFAULT_SCHEME | CURLU_URLDECODE;

char EMPTY_STR[1] = "\x00";
char *EMPTY_STR_PTR = EMPTY_STR;

typedef struct
{
  char *url;
  char *scheme;
  char *user;
  char *password;
  char *options;
  char *host;
  char *port;
  char *path;
  char *query;
  char *fragment;
  char *zoneid;
} URLParts;

int yr_re_match_curlupart(char *url_part, YR_SCAN_CONTEXT *context, RE *regexp)
{
  int result = 0;

  if (yr_re_match(context, regexp, url_part) > 0)
  {
    result = 1;
  }

  return result;
}

define_function(url) {
  URLParts *url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->url, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(scheme) {
  URLParts *url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->scheme, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(user) {
  URLParts *url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->user, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(password) {
  URLParts *url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->password, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(options) {
  URLParts *url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->options, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(host) {
  URLParts *url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->host, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(port) {
  URLParts *url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->port, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(path) {
  URLParts *url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->path, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(query) {
  URLParts *url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->query, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(fragment) {
  URLParts *url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->fragment, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(zoneid) {
  URLParts *url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->zoneid, scan_context(), regexp_argument(1));
  return_integer(result);
}


begin_declarations;

  declare_string("url");
  declare_string("scheme");
  declare_string("user");
  declare_string("password");
  declare_string("options");
  declare_string("host");
  declare_integer("port");
  declare_string("path");
  declare_string("query");
  declare_string("fragment");
  declare_string("zoneid");

  begin_struct("match");

    declare_function("url", "r", "i", url);
    declare_function("scheme", "r", "i", scheme);
    declare_function("user", "r", "i", user);
    declare_function("password", "r", "i", password);
    declare_function("options", "r", "i", options);
    declare_function("host", "r", "i", host);
    declare_function("port", "r", "i", port);
    declare_function("path", "r", "i", path);
    declare_function("query", "r", "i", query);
    declare_function("fragment", "r", "i", fragment);
    declare_function("zoneid", "r", "i", zoneid);

  end_struct("match");

end_declarations;


void curl_get_yara_set_string(CURLU *url, CURLUPart what, char **out, YR_OBJECT *module_object, char *name)
{
  CURLUcode uc = curl_url_get(url, what, out, GET_FLAGS);
  if (!uc)
    set_string(*out, module_object, name, "");
  else
    set_string(EMPTY_STR_PTR, module_object, name, "");
}

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(YR_SCAN_CONTEXT *context, YR_OBJECT *module_object, void *module_data, size_t module_data_size)
{
  CURLUcode uc;
  CURLU *url;
  URLParts *url_parts_ptr = yr_malloc(sizeof(URLParts));
  memset(url_parts_ptr, 0, sizeof(URLParts));
  module_object->data = url_parts_ptr;

  url = curl_url();
  if (!url)
    return ERROR_INTERNAL_FATAL_ERROR;

  uc = curl_url_set(url, CURLUPART_URL, module_data, SET_FLAGS);
  if (uc) {
    curl_url_cleanup(url);
    return ERROR_INVALID_MODULE_DATA;
  }

  url_parts_ptr->url = module_data;
  set_string(module_data, module_object, "url");

  curl_get_yara_set_string(url, CURLUPART_SCHEME, &url_parts_ptr->scheme, module_object, "scheme");
  curl_get_yara_set_string(url, CURLUPART_USER, &url_parts_ptr->user, module_object, "user");
  curl_get_yara_set_string(url, CURLUPART_PASSWORD, &url_parts_ptr->password, module_object, "password");
  curl_get_yara_set_string(url, CURLUPART_OPTIONS, &url_parts_ptr->options, module_object, "options");
  curl_get_yara_set_string(url, CURLUPART_HOST, &url_parts_ptr->host, module_object, "host");

  uc = curl_url_get(url, CURLUPART_PORT, &url_parts_ptr->port, GET_FLAGS);
  if (!uc)
    set_integer(atoi(url_parts_ptr->port), module_object, "port");

  curl_get_yara_set_string(url, CURLUPART_PATH, &url_parts_ptr->path, module_object, "path");
  curl_get_yara_set_string(url, CURLUPART_QUERY, &url_parts_ptr->query, module_object, "query");
  curl_get_yara_set_string(url, CURLUPART_FRAGMENT, &url_parts_ptr->fragment, module_object, "fragment");
  curl_get_yara_set_string(url, CURLUPART_ZONEID, &url_parts_ptr->zoneid, module_object, "zoneid");

  curl_url_cleanup(url);

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT *module_object)
{
  URLParts *url_parts_ptr = module_object->data;
  curl_free(url_parts_ptr->scheme);
  curl_free(url_parts_ptr->user);
  curl_free(url_parts_ptr->password);
  curl_free(url_parts_ptr->options);
  curl_free(url_parts_ptr->host);
  curl_free(url_parts_ptr->port);
  curl_free(url_parts_ptr->path);
  curl_free(url_parts_ptr->query);
  curl_free(url_parts_ptr->fragment);
  curl_free(url_parts_ptr->zoneid);
  yr_free(url_parts_ptr);
  return ERROR_SUCCESS;
}
