// testrundll.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h> 
using namespace std;
typedef void (__cdecl* MYPROC)(const char** argv,int lenparam);
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
        ProcAdd = (MYPROC)GetProcAddress(hinstLib, "detect");

        // If the function address is valid, call the function.

        if (NULL != ProcAdd)
        {
            fRunTimeLinkSuccess = TRUE;
            const char* argv[] = { "--help"};
            int lenparam = 1;
            (ProcAdd)(argv, lenparam);
            const char* argv1[] = { "checkpefile.yara","test-alignment.exe" };
            (ProcAdd)(argv1, lenparam);
            const char* argv2[] = { "checkpefile.yara","test-alignment.exe" };
            (ProcAdd)(argv2,lenparam);

        }
        // Free the DLL module.

        fFreeResult = FreeLibrary(hinstLib);
    }

    // If unable to call the DLL function, use an alternative.
    if (!fRunTimeLinkSuccess)
        printf("Message printed from executable\n");

    return 0;
}
