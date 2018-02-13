/*
Copyright (c) 2018. The YARA Authors. All Rights Reserved.

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

#ifndef YR_SCANNER_H
#define YR_SCANNER_H

#include <yara/types.h>
#include <yara/utils.h>


typedef YR_SCAN_CONTEXT YR_SCANNER;


YR_API int yr_scanner_create(
    YR_RULES* rules,
    YR_SCANNER** scanner);


YR_API void yr_scanner_destroy(
    YR_SCANNER* scanner);


YR_API void yr_scanner_set_callback(
    YR_SCANNER* scanner,
    YR_CALLBACK_FUNC callback,
    void* user_data);


YR_API void yr_scanner_set_timeout(
    YR_SCANNER* scanner,
    int timeout);


YR_API void yr_scanner_set_flags(
    YR_SCANNER* scanner,
    int flags);


YR_API int yr_scanner_define_integer_variable(
    YR_SCANNER* scanner,
    const char* identifier,
    int64_t value);


YR_API int yr_scanner_define_boolean_variable(
    YR_SCANNER* scanner,
    const char* identifier,
    int value);


YR_API int yr_scanner_define_float_variable(
    YR_SCANNER* scanner,
    const char* identifier,
    double value);


YR_API int yr_scanner_define_string_variable(
    YR_SCANNER* scanner,
    const char* identifier,
    const char* value);


YR_API int yr_scanner_scan_mem_blocks(
    YR_SCANNER* scanner,
    YR_MEMORY_BLOCK_ITERATOR* iterator);


YR_API int yr_scanner_scan_mem(
    YR_SCANNER* scanner,
    const uint8_t* buffer,
    size_t buffer_size);


YR_API int yr_scanner_scan_file(
    YR_SCANNER* scanner,
    const char* filename);


YR_API int yr_scanner_scan_fd(
    YR_SCANNER* scanner,
    YR_FILE_DESCRIPTOR fd);


YR_API int yr_scanner_scan_proc(
    YR_SCANNER* scanner,
    int pid);


YR_API YR_RULE* yr_scanner_last_error_rule(
    YR_SCANNER* scanner);


YR_API YR_STRING* yr_scanner_last_error_string(
    YR_SCANNER* scanner);

#endif
