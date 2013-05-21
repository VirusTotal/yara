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

#ifndef WIN32

#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#else

#include <windows.h>
#include "getopt.h"

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yara.h>

#include "config.h"
#include "REVISION"

#ifndef MAX_PATH
#define MAX_PATH 255
#endif

int recursive_search = FALSE;
int show_tags = FALSE;
int show_specified_tags = FALSE;
int show_specified_rules = FALSE;
int show_strings = FALSE;
int show_meta = FALSE;
int negate = FALSE;
int count = 0;
int limit = 0;


TAG* specified_tags_list = NULL;

typedef struct _IDENTIFIER
{
    char*           name;
    struct _IDENTIFIER* next;

} IDENTIFIER;

IDENTIFIER* specified_rules_list = NULL;


////////////////////////////////////////////////////////////////////////////////////////////////

void show_help()
{
    printf("usage:  yara [OPTION]... [RULEFILE]... FILE | PID\n");
    printf("options:\n");
    printf("  -t <tag>                  print rules tagged as <tag> and ignore the rest. Can be used more than once.\n");
    printf("  -i <identifier>           print rules named <identifier> and ignore the rest. Can be used more than once.\n");
    printf("  -n                        print only not satisfied rules (negate).\n");
    printf("  -g                        print tags.\n");
    printf("  -m                        print metadata.\n");
    printf("  -s                        print matching strings.\n");
    printf("  -l <number>               abort scanning after a <number> of rules matched.\n");
    printf("  -d <identifier>=<value>   define external variable.\n");
    printf("  -r                        recursively search directories.\n");
    printf("  -f                        fast matching mode.\n");
    printf("  -v                        show version information.\n");
    printf("\nReport bugs to: <%s>\n", PACKAGE_BUGREPORT);
}


////////////////////////////////////////////////////////////////////////////////////////////////

int is_numeric(const char *str)
{
  while(*str)
  {
    if(!isdigit(*str++))
      return 0;
  }

  return 1;
}


#ifdef WIN32

int is_directory(const char* path)
{
    if (GetFileAttributes(path) & FILE_ATTRIBUTE_DIRECTORY)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

void scan_dir(const char* dir, int recursive, YARA_CONTEXT* context, YARACALLBACK callback)
{
    WIN32_FIND_DATA FindFileData;
    HANDLE hFind;

    char full_path[MAX_PATH];
    static char path_and_mask[MAX_PATH];

    snprintf(path_and_mask, sizeof(path_and_mask), "%s\\*", dir);

    hFind = FindFirstFile(path_and_mask, &FindFileData);

    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            snprintf(full_path, sizeof(full_path), "%s\\%s", dir, FindFileData.cFileName);

            if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {
                //printf("Processing %s...\n", FindFileData.cFileName);
                yr_scan_file(full_path, context, callback, full_path);
            }
            else if (recursive && FindFileData.cFileName[0] != '.' )
            {
                scan_dir(full_path, recursive, context, callback);
            }

        } while (FindNextFile(hFind, &FindFileData));

        FindClose(hFind);
    }
}

#else

int is_directory(const char* path)
{
    struct stat st;

    if (stat(path,&st) == 0)
    {
        return S_ISDIR(st.st_mode);
    }

    return 0;
}

void scan_dir(const char* dir, int recursive, YARA_CONTEXT* context, YARACALLBACK callback)
{
    DIR *dp;
    struct dirent *de;
    struct stat st;
    char full_path[MAX_PATH];

    dp = opendir(dir);

    if (dp)
    {
        de = readdir(dp);

        while (de)
        {
            snprintf(full_path, sizeof(full_path), "%s/%s", dir, de->d_name);

            int err = stat(full_path,&st);

            if (err == 0)
            {
                if(S_ISREG(st.st_mode))
                {
                    //printf("Processing %s\n", de->d_name);
                    yr_scan_file(full_path, context, callback, full_path);
                }
                else if(recursive && S_ISDIR(st.st_mode) && de->d_name[0] != '.')
                {
                    //printf("Entering %s\n", de->d_name);
                    scan_dir(full_path, recursive, context, callback);
                }
            }

            de = readdir(dp);
        }

        closedir(dp);
    }
}

#endif

void print_string(unsigned char* data, unsigned int length, int unicode)
{
    unsigned int i;
    char* str;

    str = (char*) (data);

    for (i = 0; i < length; i++)
    {
        if (str[i] >= 32 && str[i] <= 126)
        {
            printf("%c",str[i]);
        }
        else
        {
            printf("\\x%02x", str[i]);
        }

        if (unicode) i++;
    }

    printf("\n");
}

void print_hex_string(unsigned char* data, unsigned int length)
{
    unsigned int i;

    for (i = 0; i < length; i++)
    {
        printf("%02X ", data[i]);
    }

    printf("\n");
}

int callback(RULE* rule, void* data)
{
    TAG* tag;
    IDENTIFIER* identifier;
    STRING* string;
    META* meta;
    MATCH* match;

    int rule_match;
    int string_found;
    int show = TRUE;

    if (show_specified_tags)
    {
        show = FALSE;
        tag = specified_tags_list;

        while (tag != NULL)
        {
            if (lookup_tag(rule->tag_list_head, tag->identifier) != NULL)
            {
                show = TRUE;
                break;
            }

            tag = tag->next;
        }
    }

    if (show_specified_rules)
    {
        show = FALSE;
        identifier = specified_rules_list;

        while (identifier != NULL)
        {
            if (strcmp(identifier->name, rule->identifier) == 0)
            {
                show = TRUE;
                break;
            }

            identifier = identifier->next;
        }
    }

    rule_match = (rule->flags & RULE_FLAGS_MATCH);

    show = show && ((!negate && rule_match) || (negate && !rule_match));

    if (show)
    {
        printf("%s ", rule->identifier);

        if (show_tags)
        {
            tag = rule->tag_list_head;

            printf("[");

            while(tag != NULL)
            {
                if (tag->next == NULL)
                {
                    printf("%s", tag->identifier);
                }
                else
                {
                    printf("%s,", tag->identifier);
                }

                tag = tag->next;
            }

            printf("] ");
        }

        if (show_meta)
        {
            meta = rule->meta_list_head;

            printf("[");

            while(meta != NULL)
            {
                if (meta->type == META_TYPE_INTEGER)
                {
                    printf("%s=%lu", meta->identifier, meta->integer);
                }
                else if (meta->type == META_TYPE_BOOLEAN)
                {
                    printf("%s=%s", meta->identifier, (meta->boolean)?("true"):("false"));
                }
                else
                {
                    printf("%s=\"%s\"", meta->identifier, meta->string);
                }

                if (meta->next != NULL)
                    printf(",");

                meta = meta->next;
            }

            printf("] ");
        }

        printf("%s\n", (char*) data);

        /* show matched strings */

        if (show_strings)
        {
            string = rule->string_list_head;

            while (string != NULL)
            {
                string_found = string->flags & STRING_FLAGS_FOUND;

                if (string_found)
                {
                    match = string->matches_head;

                    while (match != NULL)
                    {
                        printf("0x%lx:%s: ", match->offset, string->identifier);

                        if (IS_HEX(string))
                        {
                            print_hex_string(match->data, match->length);
                        }
                        else if (IS_WIDE(string))
                        {
                            print_string(match->data, match->length, TRUE);
                        }
                        else
                        {
                            print_string(match->data, match->length, FALSE);
                        }

                        match = match->next;
                    }
                }

                string = string->next;
            }
        }
    }

    if (rule_match)
        count++;

    if (limit != 0 && count >= limit)
        return CALLBACK_ABORT;

    return CALLBACK_CONTINUE;
}

int process_cmd_line(YARA_CONTEXT* context, int argc, char const* argv[])
{
    char* equal_sign;
    char* value;
    char c;
    TAG* tag;
    IDENTIFIER* identifier;
    opterr = 0;

    while ((c = getopt (argc, (char**) argv, "rnsvgml:t:i:d:f")) != -1)
    {
        switch (c)
        {
            case 'v':
                printf("%s (rev:%s)\n", PACKAGE_STRING, REVISION);
                return 0;

            case 'r':
                recursive_search = TRUE;
                break;

            case 'g':
                show_tags = TRUE;
                break;

            case 'm':
                show_meta = TRUE;
                break;

            case 's':
                show_strings = TRUE;
                break;

            case 'n':
                negate = TRUE;
                break;

            case 'f':
                context->fast_match = TRUE;
                break;

            case 't':

                show_specified_tags = TRUE;

                tag = malloc(sizeof(TAG));

                if (tag != NULL)
                {
                    tag->identifier = optarg;
                    tag->next = specified_tags_list;
                    specified_tags_list = tag;
                }
                else
                {
                    fprintf (stderr, "Not enough memory.\n", optopt);
                    return 0;
                }

                break;

            case 'i':

                show_specified_rules = TRUE;

                identifier = malloc(sizeof(IDENTIFIER));

                if (identifier != NULL)
                {
                    identifier->name = optarg;
                    identifier->next = specified_rules_list;
                    specified_rules_list = identifier;
                }
                else
                {
                    fprintf (stderr, "Not enough memory.\n", optopt);
                    return 0;
                }

                break;

            case 'd':

                equal_sign = strchr(optarg, '=');

                if (equal_sign != NULL)
                {
                    *equal_sign = '\0';

                    value = equal_sign + 1;

                    if (is_numeric(value))
                    {
                        yr_define_integer_variable(context, optarg, atol(value));
                    }
                    else if (strcmp(value, "true") == 0  || strcmp(value, "false") == 0)
                    {
                        yr_define_boolean_variable(context, optarg, strcmp(value, "true") == 0);
                    }
                    else
                    {
                        yr_define_string_variable(context, optarg, value);
                    }
                }

                break;

            case 'l':
                limit = atoi(optarg);
                break;

            case '?':

                if (optopt == 't')
                {
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                }
                else if (isprint (optopt))
                {
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                }
                else
                {
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                }

                return 0;

             default:
                 abort ();
         }
    }

    return 1;

}

void report_error(const char* file_name, int line_number, const char* error_message)
{
    fprintf(stderr, "%s:%d: %s\n", file_name, line_number, error_message);
}

int main(int argc, char const* argv[])
{
    int i, pid, errors;
    YARA_CONTEXT* context;
    FILE* rule_file;
    TAG* tag;
    TAG* next_tag;

    yr_init();

    context = yr_create_context();

    if (context == NULL)
        return 0;

    if (!process_cmd_line(context, argc, argv))
    {
        yr_destroy_context(context);
        return 0;
    }

    if (argc == 1 || optind == argc)
    {
        yr_destroy_context(context);
        show_help();
        return 0;
    }

    context->error_report_function = report_error;

    for (i = optind; i < argc - 1; i++)
    {
        rule_file = fopen(argv[i], "r");

        if (rule_file != NULL)
        {
            yr_push_file_name(context, argv[i]);

            errors = yr_compile_file(rule_file, context);

            fclose(rule_file);

            if (errors) /* errors during compilation */
            {
                yr_destroy_context(context);
                return 0;
            }
        }
        else
        {
            fprintf(stderr, "could not open file: %s\n", argv[i]);
        }
    }

    if (optind == argc - 1)  /* no rule files, read rules from stdin */
    {
        yr_push_file_name(context, "stdin");

        errors = yr_compile_file(stdin, context);

        if (errors > 0) /* errors during compilation */
        {
            yr_destroy_context(context);
            return 0;
        }
    }

    if (is_numeric(argv[argc - 1]))
    {
        pid = atoi(argv[argc - 1]);

        switch (i = yr_scan_proc(pid, context, callback, (void*) argv[argc - 1]))
        {
            case ERROR_SUCCESS:
                break;
            case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
                fprintf(stderr, "can not attach to process (try running as root)\n");
                break;
            case ERROR_INSUFICIENT_MEMORY:
                fprintf(stderr, "not enough memory\n");
                break;
            default:
                fprintf(stderr, "internal error: %d\n", i);
                break;
        }
    }
    else if (is_directory(argv[argc - 1]))
    {
        scan_dir(argv[argc - 1], recursive_search, context, callback);
    }
    else
    {
        yr_scan_file(argv[argc - 1], context, callback, (void*) argv[argc - 1]);
    }

    yr_destroy_context(context);

    /* free tag list allocated by process_cmd_line */

    tag = specified_tags_list;

    while(tag != NULL)
    {
        next_tag = tag->next;
        free(tag);
        tag = next_tag;
    }

    return 1;
}

