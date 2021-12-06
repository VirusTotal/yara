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
          dotnet.assembly.name == \"hpjsoaputility.Sv.resources\" \
      }",
      "tests/data/"
      "0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
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
          dotnet.number_of_guids == 1 and \
          dotnet.guids[0] == \"3764d539-e21a-4366-bc7c-b56fa67efbb0\" \
      }",
      "tests/data/"
      "0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

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
      "tests/data/"
      "0ca09bde7602769120fadc4f7a4147347a7a97271370583586c9e587fd396171");

  assert_true_rule_file(
      "import \"dotnet\" \
      rule test { \
        condition: \
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
          dotnet.classes[0].fullname == \"Autodesk.AutoCAD.Internal.Windows.MenuServices\" and \
          dotnet.classes[0].name == \"MenuServices\" and \
          dotnet.classes[0].namespace == \"Autodesk.AutoCAD.Internal.Windows\" and \
          dotnet.classes[0].visibility == \"public\" and \
          dotnet.classes[0].type == \"class\" and \
          dotnet.classes[0].abstract and \
          dotnet.classes[0].sealed and \
          dotnet.classes[0].number_of_generic_parameters == 0 and \
          dotnet.classes[0].number_of_base_types == 1 and \
          dotnet.classes[0].base_types[0] == \"System.Object\" and \
          dotnet.classes[0].number_of_methods == 20 and \
          dotnet.classes[0].methods[0].name == \"Initialize\" and \
          dotnet.classes[0].methods[0].visibility == \"public\" and \
          dotnet.classes[0].methods[0].static and \
          not dotnet.classes[0].methods[0].virtual and \
          not dotnet.classes[0].methods[0].final and \
          dotnet.classes[0].methods[0].return_type == \"void\" and \
          dotnet.classes[0].methods[0].parameters[0].name == \"productName\" and \
          dotnet.classes[0].methods[0].parameters[0].type == \"string\" and \
          dotnet.classes[0].methods[0].parameters[1].name == \"maxRecentFiles\" and \
          dotnet.classes[0].methods[0].parameters[1].type == \"int\" and \
          dotnet.classes[0].methods[0].number_of_generic_parameters == 0 and \
          dotnet.classes[156].fullname == \"Autodesk.AutoCAD.Ribbon.Point3dDoubleToStringConverter\" and \
          dotnet.classes[156].name == \"Point3dDoubleToStringConverter\" and \
          dotnet.classes[156].namespace == \"Autodesk.AutoCAD.Ribbon\" and \
          dotnet.classes[156].number_of_base_types == 2 and \
          dotnet.classes[156].base_types[0] == \"System.Object\" and \
          dotnet.classes[156].base_types[1] == \"System.Windows.Data.IValueConverter\" and \
          dotnet.classes[156].number_of_methods == 3 and \
          dotnet.classes[156].methods[0].name == \"Convert\" and \
          dotnet.classes[156].methods[0].return_type == \"object\" and \
          dotnet.classes[156].methods[0].number_of_parameters == 4 and \
          dotnet.classes[156].methods[0].parameters[0].name == \"value\" and \
          dotnet.classes[156].methods[0].parameters[0].type == \"object\" and \
          dotnet.classes[156].methods[0].parameters[1].name == \"targetType\" and \
          dotnet.classes[156].methods[0].parameters[1].type == \"System.Type\" and \
          dotnet.classes[156].methods[0].parameters[2].name == \"parameter\" and \
          dotnet.classes[156].methods[0].parameters[2].type == \"object\" and \
          dotnet.classes[156].methods[0].parameters[3].name == \"culture\" and \
          dotnet.classes[156].methods[0].parameters[3].type == \"System.Globalization.CultureInfo\" \
      }",
      "tests/data/"
      "756684f4017ba7e931a26724ae61606b16b5f8cc84ed38a260a34e50c5016f59");

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
