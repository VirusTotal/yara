#include <yara.h>
#include "util.h"

static int count_matches(
    int message,
    void* message_data,
    void* user_data)
{
  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    (*(int*) user_data)++;
  }

  return CALLBACK_CONTINUE;
}


void scan_incr_string(
    YR_RULES* rules,
    YR_SCAN_CONTEXT* context,
    char* string)
{
  int result = yr_rules_scan_incr_mem(
      rules, context, (uint8_t*) string, strlen(string));

  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "yr_rules_scan_incr_mem: error\n");
    exit(EXIT_FAILURE);
  }
}


int main(int argc, char** argv)
{
  yr_initialize();

  YR_RULES* rules = compile_rule(
      "rule test { \
        strings: \
        $a = { 30 31 32 33 } \
        $b = { 34 35 36 37 } \
        condition: all of them }");
  YR_SCAN_CONTEXT* context;

  int matches = 0;
  int result = yr_rules_scan_incr_init(
      rules, 0, count_matches, &matches, -1, &context);
  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "yr_rules_scan_incr_init: error\n");
    exit(EXIT_FAILURE);
  }

  scan_incr_string(rules, context, "split buffer 0123 split");
  scan_incr_string(rules, context, "continue 4567 buffer end");

  result = yr_rules_scan_incr_finish(rules, context);
  if (result != ERROR_SUCCESS)
  {
    fprintf(stderr, "yr_rules_scan_incr_finish: error\n");
    exit(EXIT_FAILURE);
  }

  yr_rules_destroy(rules);

  yr_finalize();
  return 0;
}
