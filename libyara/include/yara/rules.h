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


#ifndef YR_RULES_H
#define YR_RULES_H

#include <yara/types.h>


#define CALLBACK_MSG_RULE_MATCHING              1
#define CALLBACK_MSG_RULE_NOT_MATCHING          2
#define CALLBACK_MSG_SCAN_FINISHED              3
#define CALLBACK_MSG_IMPORT_MODULE              4

#define CALLBACK_CONTINUE   0
#define CALLBACK_ABORT      1
#define CALLBACK_ERROR      2


typedef int (*YR_CALLBACK_FUNC)(
    int message,
    void* message_data,
    void* user_data);


int yr_rules_scan_mem(
    YR_RULES* rules,
    uint8_t* buffer,
    size_t buffer_size,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int fast_scan_mode,
    int timeout);


int yr_rules_scan_file(
    YR_RULES* rules,
    const char* filename,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int fast_scan_mode,
    int timeout);


int yr_rules_scan_proc(
    YR_RULES* rules,
    int pid,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int fast_scan_mode,
    int timeout);


int yr_rules_save(
    YR_RULES* rules,
    const char* filename);


int yr_rules_load(
    const char* filename,
    YR_RULES** rules);


int yr_rules_destroy(
    YR_RULES* rules);


int yr_rules_define_integer_variable(
    YR_RULES* rules,
    const char* identifier,
    int64_t value);


int yr_rules_define_boolean_variable(
    YR_RULES* rules,
    const char* identifier,
    int value);


int yr_rules_define_string_variable(
    YR_RULES* rules,
    const char* identifier,
    const char* value);


void yr_rules_print_profiling_info(
    YR_RULES* rules);

#endif