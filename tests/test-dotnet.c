#include <yara.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "util.h"

int main(int argc, char** argv)
{
  char *top_srcdir = getenv("TOP_SRCDIR");
  if (top_srcdir)
    chdir(top_srcdir);

  yr_initialize();

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.assembly.name == \"hpjsoaputility.Sv.resources\" \
      }",
      "tests/data/0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.number_of_resources == 1 and \
          dotnet.resources[0].offset == 724 and \
          dotnet.resources[0].length == 180 and \
          dotnet.resources[0].name == \"hpjsoaputility.XmlStreamSoapExtension.pt.resources\" \
      }",
      "tests/data/0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.number_of_guids == 1 and \
          dotnet.guids[0] == \"3764d539-e21a-4366-bc7c-b56fa67efbb0\" \
      }",
      "tests/data/0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.number_of_streams == 5 and \
          dotnet.streams[0].name == \"#~\" and \
          dotnet.streams[1].name == \"#Strings\" and \
          dotnet.streams[2].name == \"#US\" and \
          dotnet.streams[3].name == \"#GUID\" and \
          dotnet.streams[4].name == \"#Blob\" \
      }",
      "tests/data/0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.module_name == \"hpjsoaputility.Sv.resources.dll\" and \
          dotnet.version == \"v2.0.50727\" \
      }",
      "tests/data/0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
          dotnet.number_of_guids == 2 and \
          dotnet.guids[0] == \"cb9aa69f-4951-49d2-98a1-18984dcfdb91\" and \
          dotnet.guids[1] == \"00000000-0000-0000-0000-000000000000\" \
      }",
      "tests/data/33fc70f99be6d2833ae48852d611c8048d0c053ed0b2c626db4dbe902832a08b");

  yr_finalize();
  return 0;
}
