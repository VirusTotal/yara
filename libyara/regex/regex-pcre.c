/*
Copyright(c) 2011, Google, Inc. [mjwiacek@google.com].
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. All advertising materials mentioning features or use of this software
   must display the following acknowledgement:
   This product includes software developed by Google, Inc. and its 
   contributors.
4. Neither the name of Google, Inc. nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

#include "regex.h"
#include <pcre.h>
#include <string.h>
#include "../yara.h"


int regex_exec(REGEXP* regex, int anchored, const char *buffer, size_t buffer_size) 
{    
    int ovector[3];
    int result = -1;
    int options = 0;
    char *s;
    
    if (!regex || buffer_size == 0)
        return 0;
        
    if (anchored)
        options = PCRE_ANCHORED;

    result = pcre_exec( (pcre*)regex->regexp,           /* the compiled pattern */
                        (pcre_extra*)regex->extra,      /* extra data */
                        (char*) buffer,                 /* the subject string */
                        buffer_size,                    /* the length of the subject */
                        0,                              /* start at offset 0 in the subject */
                        options,                        /* options */
                        ovector,                        /* output vector for substring information */
                        sizeof(ovector)/sizeof(int));   /* number of elements in the output vector */
    
    if (result >= 0) 
    {
        result = pcre_get_substring((char*) buffer, ovector, 1, 0, (const char**) &s);
    
        if (result != PCRE_ERROR_NOMEMORY && result != PCRE_ERROR_NOSUBSTRING) 
        {
            pcre_free_substring(s);
            return result;
        }
    }
    
    return -1;
}


void regex_free(REGEXP* regex) 
{  
    if (!regex)
        return;

    if (regex->regexp) 
    {
        pcre_free((pcre*)regex->regexp);
        regex->regexp = NULL;
    }

    if (regex->extra) 
    {
        pcre_free((pcre_extra*)regex->extra);
        regex->extra = NULL;
    }
}


int regex_compile(REGEXP* output,
                  const char* pattern,
                  int case_insensitive,
                  char* error_message,
                  size_t error_message_size,
                  int* error_offset) 
{
  
    int pcre_options = 0;
    char *pcre_error = NULL;
                          
    if (!output || !pattern)
        return 0;

    memset(output, '\0', sizeof(REGEXP));

    if (case_insensitive)
        pcre_options |= PCRE_CASELESS;

    output->regexp = (pcre*) pcre_compile(pattern, pcre_options, (const char **)&pcre_error, error_offset, NULL);
  
    if (output->regexp != NULL) 
    {
        output->extra = (pcre_extra *) pcre_study(output->regexp, 0, (const char **)error_message);
    } 
    else 
    {
        if (error_message && error_message_size) 
        {
            strncpy(error_message, pcre_error, error_message_size - 1);
            error_message[error_message_size - 1] = '\0';
        }
        
        // TODO: Handle fatal error here, consistently with how yara would.
        return 0;
    }

    return 1;
}



int regex_get_first_bytes(  REGEXP* regex, 
                            unsigned char* table)
{
    unsigned char* t;
    
    int i;
    int b;
    int result;
    int count = 0;
    
    result = pcre_fullinfo(regex->regexp, regex->extra, PCRE_INFO_FIRSTTABLE, &t);
    
    if (result == 0 && t != NULL)
    {        
        for (i = 0; i < 256; i++)
        {
            if (t[i / 8] & (1 << i % 8))
            {
                table[count] = i; 
                count++;
            }
        }
    }
    
    result = pcre_fullinfo(regex->regexp, regex->extra, PCRE_INFO_FIRSTBYTE, &b);
    
    if (result == 0 && b > 0)
    {   
        table[count] = b;
        count++;
    }
    
    return count;
}
