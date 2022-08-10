/*
Copyright (c) 2021. The YARA Authors. All Rights Reserved.

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

#include <stdio.h>

#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/strutils.h>

#define MODULE_NAME console

define_function(log_string)
{
  // We are intentionally using sized strings here as we may be needing to
  // output strings with a null character in the middle.
  SIZED_STRING* s = sized_string_argument(1);
  YR_SCAN_CONTEXT* ctx = yr_scan_context();
  YR_CALLBACK_FUNC callback = ctx->callback;

  // Assume the entire string is non-printable, so allocate 4 times the
  // space so that we can represent each byte as an escaped value. eg: \x00
  // Add an extra byte for the NULL terminator.
  char* msg = (char*) yr_calloc((s->length * 4) + 1, sizeof(char));
  if (msg == NULL)
    return_integer(YR_UNDEFINED);

  char* p = msg;
  for (size_t i = 0; i < s->length; i++)
  {
    if (isprint((unsigned char) s->c_string[i]))
    {
      *p++ = s->c_string[i];
    }
    else
    {
      sprintf(p, "\\x%02x", (unsigned char) s->c_string[i]);
      p += 4;
    }
  }

  // result is ignored, as we have no way to signal to the library that it
  // should abort or continue.
  callback(ctx, CALLBACK_MSG_CONSOLE_LOG, (void*) msg, ctx->user_data);

  yr_free(msg);
  return_integer(1);
}

define_function(log_string_msg)
{
  char* m = string_argument(1);
  // We are intentionally using sized strings here as we may be needing to
  // output strings with a null character in the middle.
  SIZED_STRING* s = sized_string_argument(2);
  YR_SCAN_CONTEXT* ctx = yr_scan_context();
  YR_CALLBACK_FUNC callback = ctx->callback;

  // Assume the entire string is non-printable, so allocate 4 times the
  // space so that we can represent each byte as an escaped value. eg: \x00
  // Add an extra byte for the NULL terminator.
  size_t msg_len = strlen(m) + (s->length * 4) + 1;
  char* msg = (char*) yr_calloc(msg_len, sizeof(char));
  if (msg == NULL)
    return_integer(YR_UNDEFINED);

  char* p = msg;
  strlcpy(msg, m, msg_len);
  p += strlen(m);
  for (size_t i = 0; i < s->length; i++)
  {
    if (isprint((unsigned char) s->c_string[i]))
    {
      *p++ = s->c_string[i];
    }
    else
    {
      sprintf(p, "\\x%02x", (unsigned char) s->c_string[i]);
      p += 4;
    }
  }

  // result is ignored, as we have no way to signal to the library that it
  // should abort or continue.
  callback(ctx, CALLBACK_MSG_CONSOLE_LOG, (void*) msg, ctx->user_data);

  yr_free(msg);
  return_integer(1);
}

define_function(log_integer)
{
  char* msg = NULL;
  int64_t i = integer_argument(1);
  YR_SCAN_CONTEXT* ctx = yr_scan_context();
  YR_CALLBACK_FUNC callback = ctx->callback;

  yr_asprintf(&msg, "%lli", i);

  if (msg == NULL)
    return_integer(YR_UNDEFINED);

  // result is ignored, as we have no way to signal to the library that it
  // should abort or continue.
  callback(ctx, CALLBACK_MSG_CONSOLE_LOG, (void*) msg, ctx->user_data);

  yr_free(msg);
  return_integer(1);
}

define_function(log_integer_msg)
{
  char* msg = NULL;
  char* s = string_argument(1);
  int64_t i = integer_argument(2);
  YR_SCAN_CONTEXT* ctx = yr_scan_context();
  YR_CALLBACK_FUNC callback = ctx->callback;

  yr_asprintf(&msg, "%s%lli", s, i);

  if (msg == NULL)
    return_integer(YR_UNDEFINED);

  // result is ignored, as we have no way to signal to the library that it
  // should abort or continue.
  callback(ctx, CALLBACK_MSG_CONSOLE_LOG, (void*) msg, ctx->user_data);

  yr_free(msg);
  return_integer(1);
}

define_function(log_float)
{
  char* msg = NULL;
  double f = float_argument(1);
  YR_SCAN_CONTEXT* ctx = yr_scan_context();
  YR_CALLBACK_FUNC callback = ctx->callback;

  yr_asprintf(&msg, "%f", f);

  if (msg == NULL)
    return_integer(YR_UNDEFINED);

  // result is ignored, as we have no way to signal to the library that it
  // should abort or continue.
  callback(ctx, CALLBACK_MSG_CONSOLE_LOG, (void*) msg, ctx->user_data);

  yr_free(msg);
  return_integer(1);
}

define_function(log_float_msg)
{
  char* msg = NULL;
  char* s = string_argument(1);
  double f = float_argument(2);
  YR_SCAN_CONTEXT* ctx = yr_scan_context();
  YR_CALLBACK_FUNC callback = ctx->callback;

  yr_asprintf(&msg, "%s%f", s, f);

  if (msg == NULL)
    return_integer(YR_UNDEFINED);

  // result is ignored, as we have no way to signal to the library that it
  // should abort or continue.
  callback(ctx, CALLBACK_MSG_CONSOLE_LOG, (void*) msg, ctx->user_data);

  yr_free(msg);
  return_integer(1);
}

define_function(hex_integer)
{
  char* msg = NULL;
  int64_t i = integer_argument(1);
  YR_SCAN_CONTEXT* ctx = yr_scan_context();
  YR_CALLBACK_FUNC callback = ctx->callback;

  yr_asprintf(&msg, "0x%llx", i);

  if (msg == NULL)
    return_integer(YR_UNDEFINED);

  // result is ignored, as we have no way to signal to the library that it
  // should abort or continue.
  callback(ctx, CALLBACK_MSG_CONSOLE_LOG, (void*) msg, ctx->user_data);

  yr_free(msg);
  return_integer(1);
}

define_function(hex_integer_msg)
{
  char* msg = NULL;
  char* s = string_argument(1);
  int64_t i = integer_argument(2);
  YR_SCAN_CONTEXT* ctx = yr_scan_context();
  YR_CALLBACK_FUNC callback = ctx->callback;

  yr_asprintf(&msg, "%s0x%llx", s, i);

  if (msg == NULL)
    return_integer(YR_UNDEFINED);

  // result is ignored, as we have no way to signal to the library that it
  // should abort or continue.
  callback(ctx, CALLBACK_MSG_CONSOLE_LOG, (void*) msg, ctx->user_data);

  yr_free(msg);
  return_integer(1);
}

begin_declarations
  declare_function("log", "s", "i", log_string);
  declare_function("log", "ss", "i", log_string_msg);
  declare_function("log", "i", "i", log_integer);
  declare_function("log", "si", "i", log_integer_msg);
  declare_function("log", "f", "i", log_float);
  declare_function("log", "sf", "i", log_float_msg);
  declare_function("hex", "i", "i", hex_integer);
  declare_function("hex", "si", "i", hex_integer_msg);
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
  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
