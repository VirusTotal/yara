
#include <yara.h>
#include "util.h"

#if defined(_WIN32) || defined(__CYGWIN__)
#include <fileapi.h>
#else
#include <unistd.h>
#endif
#include <fcntl.h>

void test_disabled_rules()
{
  YR_RULES* rules;
  YR_RULE* rule;

  int matches = 0;
  char* buf = "foo bar";
  char* rules_str = " \
    rule disabled_rule {condition: true} \
    rule false_rule {condition: true and disabled_rule} \
    rule true_rule {condition: true or disabled_rule}";


  yr_initialize();

  if (compile_rule(rules_str, &rules) != ERROR_SUCCESS)
  {
    perror("compile_rule");
    exit(EXIT_FAILURE);
  }

  // diable any rule containing disable in its identifier
  yr_rules_foreach(rules, rule)
  {
    if (strstr(rule->identifier, "disabled"))
      yr_rule_disable(rule);
  }

  yr_rules_scan_mem(
      rules, (uint8_t *) buf, strlen(buf), 0, count_matches, &matches, 0);

  yr_rules_destroy(rules);

  // matches should be exactly one.
  if (matches != 1)
  {
    fprintf(stderr, "test_disabled_rules failed\n");
    exit(EXIT_FAILURE);
  }

  yr_finalize();
}


const char* _include_callback(
  const char* include_name,
  const char* calling_rule_filename,
  const char* calling_rule_namespace,
  void* user_data)
{
if (strcmp(include_name, "ok") == 0)
  return "rule test {condition: true}";
else
  return NULL;
}


void test_include_callback()
{
  YR_COMPILER* compiler = NULL;

  yr_initialize();

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
  {
    perror("yr_compiler_create");
    exit(EXIT_FAILURE);
  }

  yr_compiler_set_include_callback(compiler, _include_callback, NULL, NULL);

  // This include produces no error.
  if (yr_compiler_add_string(compiler, "include \"ok\"", NULL) != 0)
  {
    yr_compiler_destroy(compiler);
    exit(EXIT_FAILURE);
  }

  // This include one error.
  if (yr_compiler_add_string(compiler, "include \"fail\"", NULL) != 1)
  {
    yr_compiler_destroy(compiler);
    exit(EXIT_FAILURE);
  }

  yr_compiler_destroy(compiler);
  yr_finalize();
}


void test_file_descriptor()
{
  YR_COMPILER* compiler = NULL;
  YR_RULES* rules = NULL;

#if defined(_WIN32) || defined(__CYGWIN__)
  HANDLE fd = CreateFile("tests/data/true.yar", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (fd == INVALID_HANDLE_VALUE)
  {
    fputs("CreateFile failed", stderr);
    exit(1);
  }
#else
  int fd = open("tests/data/true.yar", O_RDONLY);
  if (fd < 0)
  {
    perror("open");
    exit(EXIT_FAILURE);
  }
#endif

  yr_initialize();

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
  {
    perror("yr_compiler_create");
    exit(EXIT_FAILURE);
  }

  if (yr_compiler_add_fd(compiler, fd, NULL, NULL) != 0) {
    perror("yr_compiler_add_fd");
    exit(EXIT_FAILURE);
  }

#if defined(_WIN32) || defined(__CYGWIN__)
  CloseHandle(fd);
#else
  close(fd);
#endif

  if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
    perror("yr_compiler_add_fd");
    exit(EXIT_FAILURE);
  }

  if (compiler)
    yr_compiler_destroy(compiler);

  if (rules)
    yr_rules_destroy(rules);

  yr_finalize();

  return;
}

void test_max_string_per_rules()
{
  uint32_t new_max_strings_per_rule = 1;
  uint32_t old_max_strings_per_rule;

  yr_initialize();

  yr_get_configuration(
      YR_CONFIG_MAX_STRINGS_PER_RULE,
      (void*) &old_max_strings_per_rule);

  yr_set_configuration(
      YR_CONFIG_MAX_STRINGS_PER_RULE,
      (void*) &new_max_strings_per_rule);

  assert_error(
      "rule test { \
         strings: \
           $ = \"uno\" \
           $ = \"dos\" \
         condition: \
           all of them }",
      ERROR_TOO_MANY_STRINGS);

  new_max_strings_per_rule = 2;

  yr_set_configuration(
      YR_CONFIG_MAX_STRINGS_PER_RULE,
      (void*) &new_max_strings_per_rule);

  assert_error(
      "rule test { \
         strings: \
           $ = \"uno\" \
           $ = \"dos\" \
         condition: \
           all of them }",
      ERROR_SUCCESS);

  yr_set_configuration(
      YR_CONFIG_MAX_STRINGS_PER_RULE,
      (void*) &old_max_strings_per_rule);

  yr_finalize();
}


void test_save_load_rules()
{
  YR_COMPILER* compiler = NULL;
  YR_RULES* rules = NULL;

  yr_initialize();

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
  {
    perror("yr_compiler_create");
    exit(EXIT_FAILURE);
  }

  if (yr_compiler_add_string(compiler, "rule test {condition: true}", NULL) != 0)
  {
    yr_compiler_destroy(compiler);
    perror("yr_compiler_add_string");
    exit(EXIT_FAILURE);
  }

  if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
  {
    yr_compiler_destroy(compiler);
    perror("yr_compiler_add_fd");
    exit(EXIT_FAILURE);
  }

  yr_compiler_destroy(compiler);

  if (yr_rules_save(rules, "test-rules.yarc") != ERROR_SUCCESS)
  {
    yr_rules_destroy(rules);
    perror("yr_rules_save");
    exit(EXIT_FAILURE);
  }

  yr_rules_destroy(rules);

  if (yr_rules_load("test-rules.yarc", &rules) != ERROR_SUCCESS)
  {
    perror("yr_rules_load");
    exit(EXIT_FAILURE);
  }

  yr_rules_destroy(rules);
  yr_finalize();
}


int main(int argc, char** argv)
{
  test_disabled_rules();
  test_file_descriptor();
  test_max_string_per_rules();
  test_include_callback();
  test_save_load_rules();
}