


#define exit_with_code(code) { result = code; goto _exit; }

int compile_files(
  YR_COMPILER* compiler,
  int argc,
  const char** argv)
{
  for (int i = 0; i < argc - 1; i++)
  {
    const char* ns;
    const char* file_name;
    char* colon = (char*) strchr(argv[i], ':');
    int errors;

    // Namespace delimiter must be a colon not followed by a slash or backslash
    if (colon && *(colon + 1) != '\\' && *(colon + 1) != '/')
    {
      file_name = colon + 1;
      *colon = '\0';
      ns = argv[i];
    }
    else
    {
      file_name = argv[i];
      ns = NULL;
    }

    FILE* rule_file = fopen(file_name, "r");

    if (rule_file == NULL)
    {
      fprintf(stderr, "error: could not open file: %s\n", file_name);
      return FALSE;
    }

    errors = yr_compiler_add_file(compiler, rule_file, ns, file_name);

    fclose(rule_file);

    if (errors > 0)
      return FALSE;
  }

  return TRUE;
}
