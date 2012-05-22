/*
Copyright (c) 2007. Victor M. Alvarez [plusvic@gmail.com].

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

#include "weight.h"

int string_weight(STRING* string, int multiplier)
{
    int len;

    if (IS_REGEXP(string))
    {
        return (16 * multiplier);
    }
    else
    {
        len = string->length;
    
        if (len > 8)
        {
            return (1 * multiplier);
        }
        else if (len > 4)
        {
            return (2 * multiplier);
        }
        else
        {
            return (4 * multiplier);
        }                  
    }
}

