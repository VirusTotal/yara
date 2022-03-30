#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <yara.h>

#include "util.h"

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  init_top_srcdir();

  yr_initialize();

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          not dotnet.is_dotnet \
      }",
      "tests/data/tiny");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.is_dotnet and \
          dotnet.assembly.name == \"hpjsoaputility.Sv.resources\" \
      }",
      "tests/data/"
      "0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.is_dotnet and \
          dotnet.number_of_resources == 1 and \
          dotnet.resources[0].offset == 724 and \
          dotnet.resources[0].length == 180 and \
          dotnet.resources[0].name == \"hpjsoaputility.XmlStreamSoapExtension.pt.resources\" \
      }",
      "tests/data/"
      "0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.is_dotnet and \
          dotnet.number_of_guids == 1 and \
          dotnet.guids[0] == \"3764d539-e21a-4366-bc7c-b56fa67efbb0\" \
      }",
      "tests/data/"
      "0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.is_dotnet and \
          dotnet.number_of_streams == 5 and \
          dotnet.streams[0].name == \"#~\" and \
          dotnet.streams[1].name == \"#Strings\" and \
          dotnet.streams[2].name == \"#US\" and \
          dotnet.streams[3].name == \"#GUID\" and \
          dotnet.streams[4].name == \"#Blob\" \
      }",
      "tests/data/"
      "0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.is_dotnet and \
          dotnet.module_name == \"hpjsoaputility.Sv.resources.dll\" and \
          dotnet.version == \"v2.0.50727\" \
      }",
      "tests/data/"
      "0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.number_of_guids == 2 and \
          dotnet.guids[0] == \"cb9aa69f-4951-49d2-98a1-18984dcfdb91\" and \
          dotnet.guids[1] == \"00000000-0000-0000-0000-000000000000\" \
      }",
      "tests/data/"
      "33fc70f99be6d2833ae48852d611c8048d0c053ed0b2c626db4dbe902832a08b");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.user_strings[0] == \"F\\x00r\\x00e\\x00e\\x00D\\x00i\\x00s\\x00c\\x00B\\x00u\\x00r\\x00n\\x00e\\x00r\\x00.\\x00S\\x00t\\x00r\\x00i\\x00n\\x00g\\x00R\\x00e\\x00s\\x00o\\x00u\\x00r\\x00c\\x00e\\x00s\\x00\" \
      }",
      "tests/data/"
      "33fc70f99be6d2833ae48852d611c8048d0c053ed0b2c626db4dbe902832a08b");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.entry_point == 0x600027A and \
          dotnet.flags & ( \
            dotnet.COMIMAGE_FLAGS_ILONLY & \
            dotnet.COMIMAGE_FLAGS_32BITREQUIRED) == \
            dotnet.COMIMAGE_FLAGS_ILONLY & \
            dotnet.COMIMAGE_FLAGS_32BITREQUIRED \
      }",
      "tests/data/"
      "33fc70f99be6d2833ae48852d611c8048d0c053ed0b2c626db4dbe902832a08b");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          for any method in dotnet.methods : ( \
              method.name == \"DoSetControlValues\" and \
              method.rva == 0x2830 and \
              method.impl_flags & ( \
                  dotnet.METHOD_IMPL_FLAGS_IL & \
                  dotnet.METHOD_IMPL_FLAGS_MANAGED & \
                  dotnet.METHOD_IMPL_FLAGS_NO_INLINING) == \
                  dotnet.METHOD_IMPL_FLAGS_IL & \
                  dotnet.METHOD_IMPL_FLAGS_MANAGED & \
                  dotnet.METHOD_IMPL_FLAGS_NO_INLINING and \
              method.flags & ( \
                  dotnet.METHOD_FLAGS_FAMILY & \
                  dotnet.METHOD_FLAGS_VIRTUAL & \
                  dotnet.METHOD_FLAGS_HIDE_BY_SIG & \
                  dotnet.METHOD_FLAGS_REUSE_SLOT) == \
                  dotnet.METHOD_FLAGS_FAMILY & \
                  dotnet.METHOD_FLAGS_VIRTUAL & \
                  dotnet.METHOD_FLAGS_HIDE_BY_SIG & \
                  dotnet.METHOD_FLAGS_REUSE_SLOT \
          ) \
      }",
      "tests/data/"
      "33fc70f99be6d2833ae48852d611c8048d0c053ed0b2c626db4dbe902832a08b");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          for any typeref in dotnet.typerefs : ( \
            typeref.namespace == \"DVDVideoSoft.Utils\" and \
            typeref.name == \"WindowUtils\") \
      }",
      "tests/data/"
      "33fc70f99be6d2833ae48852d611c8048d0c053ed0b2c626db4dbe902832a08b");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          for any i in (0..dotnet.number_of_memberrefs - 1): ( \
            dotnet.memberrefs[i].name == \"CompareTo\" and \
            dotnet.memberrefs[i+1].name == \"get_IsDirectory\" \
          ) \
      }",
      "tests/data/"
      "33fc70f99be6d2833ae48852d611c8048d0c053ed0b2c626db4dbe902832a08b");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          for any imap in dotnet.impl_maps : ( \
              imap.import_name == \"RtlZeroMemory\" and \
              imap.mapping_flags & \
                  dotnet.PINVOKE_FLAGS_CALL_CONV_PLATFORM_API == \
                  dotnet.PINVOKE_FLAGS_CALL_CONV_PLATFORM_API \
          ) \
      }",
      "tests/data/"
      "33fc70f99be6d2833ae48852d611c8048d0c053ed0b2c626db4dbe902832a08b");
  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
