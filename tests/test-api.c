
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
  HANDLE fd = CreateFile("tests/data/baz.yar", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (fd == INVALID_HANDLE_VALUE)
  {
    fputs("CreateFile failed", stderr);
    exit(1);
  }
#else
  int fd = open("tests/data/baz.yar", O_RDONLY);
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


void test_scanner()
{
  int matches = 0;
  const char* buf = "dummy";
  const char* rules_str = "\
    rule test { \
    condition: bool_var and int_var == 1 and str_var == \"foo\" }";

  YR_COMPILER* compiler = NULL;
  YR_RULES* rules = NULL;
  YR_SCANNER* scanner1 = NULL;
  YR_SCANNER* scanner2 = NULL;

  int result;

  yr_initialize();

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
  {
    perror("yr_compiler_create");
    exit(EXIT_FAILURE);
  }

  // Define a few variables
  yr_compiler_define_integer_variable(compiler, "int_var", 0);
  yr_compiler_define_boolean_variable(compiler, "bool_var", 0);
  yr_compiler_define_string_variable(compiler, "str_var", "");

  // Compile a rule that use the variables in the condition.
  if (yr_compiler_add_string(compiler, rules_str, NULL) != 0)
  {
    yr_compiler_destroy(compiler);
    perror("yr_compiler_add_string");
    exit(EXIT_FAILURE);
  }

  if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
  {
    yr_compiler_destroy(compiler);
    perror("yr_compiler_get_rules");
    exit(EXIT_FAILURE);
  }

  yr_compiler_destroy(compiler);

  // Create an scanner
  if (yr_scanner_create(rules, &scanner1)!= ERROR_SUCCESS)
  {
    yr_rules_destroy(rules);
    perror("yr_scanner_create");
    exit(EXIT_FAILURE);
  }

  // Create another scanner
  if (yr_scanner_create(rules, &scanner2)!= ERROR_SUCCESS)
  {
    yr_scanner_destroy(scanner1);
    yr_rules_destroy(rules);
    perror("yr_scanner_create");
    exit(EXIT_FAILURE);
  }

  // Let's check the yr_scanner_scan_mem returns the appropriate error when
  // called without specifying a callback.
  result = yr_scanner_scan_mem(scanner1, (uint8_t *) buf, strlen(buf));

  if (result != ERROR_CALLBACK_REQUIRED)
  {
    yr_scanner_destroy(scanner1);
    yr_scanner_destroy(scanner2);
    yr_rules_destroy(rules);
    printf("expecting ERROR_CALLBACK_REQUIRED (%d), got: %d\n",
           ERROR_CALLBACK_REQUIRED, result);
    exit(EXIT_FAILURE);
  }

  // Set the callback and a some the correct values for the rule to match.
  yr_scanner_set_callback(scanner1, count_matches, &matches);
  yr_scanner_define_integer_variable(scanner1, "int_var", 1);
  yr_scanner_define_boolean_variable(scanner1, "bool_var", 1);
  yr_scanner_define_string_variable(scanner1, "str_var", "foo");

  // Set some other values for the second scanner to make sure it doesn't
  // interfere with the first one.
  yr_scanner_define_integer_variable(scanner2, "int_var", 2);
  yr_scanner_define_boolean_variable(scanner2, "bool_var", 0);
  yr_scanner_define_string_variable(scanner2, "str_var", "bar");

  result = yr_scanner_scan_mem(scanner1, (uint8_t *) buf, strlen(buf));

  if (result != ERROR_SUCCESS)
  {
    yr_scanner_destroy(scanner1);
    yr_scanner_destroy(scanner2);
    yr_rules_destroy(rules);
    printf("expecting ERROR_SUCCESS (%d), got: %d\n",
           ERROR_SUCCESS, result);
    exit(EXIT_FAILURE);
  }

  if (matches != 1)
  {
    yr_scanner_destroy(scanner1);
    yr_scanner_destroy(scanner2);
    yr_rules_destroy(rules);
    exit(EXIT_FAILURE);
  }

  yr_scanner_destroy(scanner1);
  yr_scanner_destroy(scanner2);
  yr_rules_destroy(rules);
  yr_finalize();
}


void ast_callback(
    const YR_RULE* rule,
    const char* string_identifier,
    const RE_AST* re_ast,
    void* user_data)
{
  if (strcmp(rule->identifier, "test") == 0 &&
      strcmp(string_identifier, "$foo") == 0)
  {
    *((int*) user_data) = 1;
  }
}

void test_ast_callback()
{
  const char* rules_str = "\
      rule test { \
      strings: $foo = /a.*b/ \
      condition: $foo }";

  YR_COMPILER* compiler = NULL;

  yr_initialize();

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
  {
    perror("yr_compiler_create");
    exit(EXIT_FAILURE);
  }

  int ok = 0;

  yr_compiler_set_re_ast_callback(
      compiler,
      ast_callback,
      &ok);

  // Compile a rule that use the variables in the condition.
  if (yr_compiler_add_string(compiler, rules_str, NULL) != 0)
  {
    yr_compiler_destroy(compiler);
    perror("yr_compiler_add_string");
    exit(EXIT_FAILURE);
  }

  if (!ok)
  {
    printf("ast callback failed\n");
    exit(EXIT_FAILURE);
  }

  yr_compiler_destroy(compiler);
  yr_finalize();
}

int main(int argc, char** argv)
{
  test_disabled_rules();
  test_file_descriptor();
  test_max_string_per_rules();
  test_include_callback();
  test_save_load_rules();
  test_scanner();
  test_ast_callback();
}
