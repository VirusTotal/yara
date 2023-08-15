// testrundll.cpp : This file contains the 'main' function. Program execution
// begins and ends there.
//

#include <windows.h>
#include <cstdlib>
#include <iostream>
using namespace std;
typedef struct detectResult
{
  int size;
  char** result;
} detectResult;
typedef const detectResult*(__cdecl* MYPROC)(const char** argv, int lenparam);

int main()
{
  HINSTANCE hinstLib;
  MYPROC ProcAdd;

  BOOL fFreeResult, fRunTimeLinkSuccess = FALSE;

  // Get a handle to the DLL module.

  hinstLib = LoadLibrary(TEXT("yara64.dll"));

  // If the handle is valid, try to get the function address.

  if (hinstLib != NULL)

  {
    const detectResult* result;
    ProcAdd = (MYPROC) GetProcAddress(hinstLib, "detect");

    // ProcAdd1 = (MYPROC)GetProcAddress(hinstLib, "detect");

    // If the function address is valid, call the function.

    if (NULL != ProcAdd)
    {
      fRunTimeLinkSuccess = TRUE;

      int lenparam = 1;

      const char* argv2[] = {"--help"};
      /*(ProcAdd1)(argv2, lenparam);*/

      result = (ProcAdd) (argv2, lenparam);
      for (size_t i = 0; i < result->size; i++)
      {
        printf("\nresult: %s", result->result[i]);
      }

      /*const char* argv2[] = { "checkpefile.yara","test-alignment.exe" };
      (ProcAdd)(argv2,lenparam);*/
    }
    // Free the DLL module.

    fFreeResult = FreeLibrary(hinstLib);
  }

  // If unable to call the DLL function, use an alternative.
  if (!fRunTimeLinkSuccess)
    printf("Message printed from executable\n");

  return 0;
}
