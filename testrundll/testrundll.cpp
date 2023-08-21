// testrundll.cpp : This file contains the 'main' function. Program execution
// begins and ends there.
//
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <cstdlib>
#include <iostream>
using namespace std;
typedef struct detectResult
{
  const wchar_t* file_name;
  int size;
  const wchar_t** rules;
} detectResult;

typedef struct detectResults
{
  int size;
  detectResult** dr;
} detectResults;

typedef const detectResults*(
    __cdecl* MYPROC)(const wchar_t** argv, int lenparam);

int main(int agrc, const char** argv)
{


    wchar_t rule_path[256];
    wchar_t path_scan[256]; 
    wprintf(L"Nhap duong dan file rule: ");
    wscanf(L"%255ls", rule_path);
    wprintf(L"Nhap duong dan file can scan: ");
    wscanf(L"%255ls", path_scan);


  HINSTANCE hinstLib;
  MYPROC ProcAdd;

  BOOL fFreeResult, fRunTimeLinkSuccess = FALSE;

  // Get a handle to the DLL module.

  hinstLib = LoadLibrary(TEXT("yara64.dll"));

  // If the handle is valid, try to get the function address.

  if (hinstLib != NULL)

  {
    const detectResults* drS;
    ProcAdd = (MYPROC) GetProcAddress(hinstLib, "detect");


    // If the function address is valid, call the function.

    if (NULL != ProcAdd)
    {
      fRunTimeLinkSuccess = TRUE;

      /*const wchar_t* command[] = {
          L"checkpefile.yara",
          L"9364"};*/
      /*const wchar_t* command[] = {
          L"C:\\Users\\TRUNG\\Desktop\\scanner\\checkpefile.yara",
          L"C:\\Users\\TRUNG\\Desktop\\scanner\\helo"};*/
      const wchar_t* command[] = { rule_path, path_scan };
      int lenparam = sizeof(command) / sizeof(command[0]);

      drS = (ProcAdd) (command, lenparam);
      for (int i = 0; i < drS->size; i++)
      {
        wprintf(L"File scan: %s \n", drS->dr[i]->file_name);
        wprintf(L"Number of match rule: %d \n", drS->dr[i]->size);
        wprintf(L"Match rule:\n");
        for (int j = 0; j < drS->dr[i]->size; j++)
        {
          wprintf(L"\t[%d]: %s \n", j, drS->dr[i]->rules[j]);
        }
        wprintf(L"-----------------------------------\n");
      }
    }
    // Free the DLL module.

    fFreeResult = FreeLibrary(hinstLib);
  }

  // If unable to call the DLL function, use an alternative.
  if (!fRunTimeLinkSuccess)
    printf("Message printed from executable\n");

  return 0;
}
