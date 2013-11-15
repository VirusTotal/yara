/*
Copyright (c) 2007. Victor M. Alvarez [plusvic@gmail.com] &
                    Stefan Buehlmann [stefan.buehlmann@joebox.org].

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

#ifndef _PROC_H
#define _PROC_H

#include "yara.h"

int yr_process_get_memory(
		int pid,
		MEMORY_BLOCK** first_block);

#endif
