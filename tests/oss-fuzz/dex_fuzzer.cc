#include <stdint.h>
#include <stddef.h>

#include <yara.h>


YR_RULES* rules = NULL;


extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  YR_COMPILER* compiler;

  if (yr_initialize() != ERROR_SUCCESS)
    return 0;

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
    return 0;

  if (yr_compiler_add_string(compiler, "import \"dex\"", NULL) == 0)
    yr_compiler_get_rules(compiler, &rules);

  yr_compiler_destroy(compiler);

  return 0;
}


int callback(int message, void* message_data, void* user_data)
{
  return CALLBACK_CONTINUE;
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (rules == NULL)
    return 0;

  yr_rules_scan_mem(
      rules,
      data,
      size,
      SCAN_FLAGS_NO_TRYCATCH,
      callback,
      NULL,
      0);

  return 0;
}
