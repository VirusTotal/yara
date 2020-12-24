#include <yara.h>

#include "blob.h"
#include "util.h"

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  yr_initialize();

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.header.magic == \
        dex.DEX_FILE_MAGIC_035 }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.header.checksum == \
        0x3F9C602F }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.header.data_size == \
        0x18C }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.string_ids[0].value ==\
      \"<clinit>\" }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.string_ids[8].value == \
        \"com.google.helloyara\" }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.type_ids[0].descriptor_idx == \
        0x2 }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.proto_ids[0].shorty_idx == \
        0x6 }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.field_ids[0].class_idx == \
        0x1 }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.method_ids[0].class_idx == \
        0x1 }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.class_defs[0].class_idx == \
        0x1 }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.number_of_fields == 2 }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.field[0].class_name == \
        \"Lcom/android/tools/ir/server/AppInfo;\" }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.field[0].name == \
        \"applicationId\" }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.number_of_methods == 2 }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.method[0].class_name == \
        \"Lcom/android/tools/ir/server/AppInfo;\" }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.method[0].proto == \"V\" }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.method[0].name == \
        \"<clinit>\" }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.method[1].name == \
        \"<init>\" }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: dex.map_list.size == 12 }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: \
          dex.map_list.map_item[0].type == dex.TYPE_HEADER_ITEM \
        }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: \
          dex.has_method(\"<init>\") \
        }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: \
          dex.has_method(\"Lcom/android/tools/ir/server/AppInfo;\", \"<clinit>\") \
        }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: \
          dex.has_method(/init/) \
        }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: \
          dex.has_method(/AppInfo/, /init/) \
        }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: \
          dex.has_class(\"Lcom/android/tools/ir/server/AppInfo;\") \
        }",
      DEX_FILE);

  assert_true_rule_blob(
      "import \"dex\" rule test { condition: \
          dex.has_class(/AppInfo/) \
        }",
      DEX_FILE);

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
