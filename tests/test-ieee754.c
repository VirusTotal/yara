#include <stdio.h>
#include <yara.h>

#include "util.h"

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  yr_initialize();

  assert_true_rule_blob(
      "import \"ieee754\" \
      rule test { \
        condition: \
          ieee754.binary16le(0) == 1.0 \
      }",
      "\x00\x3C");

  assert_true_rule_blob(
      "import \"ieee754\" \
      rule test { \
        condition: \
          ieee754.binary16be(0) == 1.0 \
      }",
      "\x3C\x00");

  assert_true_rule_blob(
      "import \"ieee754\" \
      rule test { \
        condition: \
          ieee754.binary32le(0) == 1.0 \
      }",
      "\x00\x00\x80\x3F");

  assert_true_rule_blob(
      "import \"ieee754\" \
      rule test { \
        condition: \
          ieee754.binary32be(0) == 1.0 \
      }",
      "\x3F\x80\x00\x00");

  assert_true_rule_blob(
      "import \"ieee754\" \
      rule test { \
        condition: \
          ieee754.binary64le(0) == 1.0 \
      }",
      "\x00\x00\x00\x00\x00\x00\xF0\x3F");

  assert_true_rule_blob(
      "import \"ieee754\" \
      rule test { \
        condition: \
          ieee754.binary64be(0) == 1.0 \
      }",
      "\x3F\xF0\x00\x00\x00\x00\x00\x00");

  assert_true_rule_blob(
      "import \"ieee754\" \
      rule test { \
        condition: \
          ieee754.float32be(0) == 0.75 \
      }",
      "\x3F\x40\x00\x00");

  assert_true_rule_blob(
      "import \"ieee754\" \
      rule test { \
        condition: \
          ieee754.double64be(0) == 0.01171875 \
      }",
      "\x3F\x88\x00\x00\x00\x00\x00\x00");

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
