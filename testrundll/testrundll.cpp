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
  const char** rules;
} detectResult;


typedef int (
    __cdecl* init_function)(const wchar_t* pathRule);
typedef const detectResult* (
    __cdecl* detect)(const wchar_t* pathFileScan);
typedef void(
    __cdecl* destroy)();

int main(int agrc, const char** argv)
{
      HINSTANCE hinstLib;
      init_function InitFunction;
      detect Detect;
      destroy Destroy;

      BOOL fFreeResult, fRunTimeLinkSuccess = FALSE;
    hinstLib = LoadLibrary(TEXT("yara32.dll"));

    

  if (hinstLib != NULL)

  {
    wchar_t rule_path[256];
    wchar_t path_scan[256];
    wprintf(L"Nhap duong dan file rule: ");
    wscanf(L"%255ls", rule_path);
    wprintf(L"Nhap PID hoac duong dan file can scan: ");
    wscanf(L"%255ls", path_scan);

    int result;
    
    InitFunction = (init_function) GetProcAddress(hinstLib, "init_function");
    Detect = (detect) GetProcAddress(hinstLib, "detect");
    Destroy = (destroy) GetProcAddress(hinstLib, "destroy");

    // If the function address is valid, call the function.
    if (NULL != InitFunction && NULL != Detect && NULL != Destroy) {
        fRunTimeLinkSuccess = TRUE;
        result = InitFunction(rule_path);
        if (result != -1)
        {
          const detectResult* dr1 = Detect(path_scan);
          if (dr1 != NULL)
          {
                wprintf(L"File(PID) scan: %s \n", dr1->file_name);
                wprintf(L"Number of match rule: %d \n", dr1->size);
                wprintf(L"Match rule:\n");
                for (int j = 0; j < dr1->size; j++)
                {
                  printf("\t[%d]: %s \n", j, dr1->rules[j]);
                }
                wprintf(L"-----------------------------------\n");
          }         
        

            printf("Call lan 2");
            printf("***************************");

            const detectResult* dr2 = Detect(path_scan);
            if (dr2 != NULL)
            {
                wprintf(L"File(PID) scan: %s \n", dr2->file_name);
                wprintf(L"Number of match rule: %d \n", dr2->size);
                wprintf(L"Match rule:\n");
                for (int j = 0; j < dr2->size; j++)
                {
                  printf("\t[%d]: %s \n", j, dr2->rules[j]);
                }
                printf("-----------------------------------\n");
            }
        }
       
        //DOn dep
        Destroy();
    }
    
    fFreeResult = FreeLibrary(hinstLib);
  }

  // If unable to call the DLL function, use an alternative.
  if (!fRunTimeLinkSuccess)
    printf("Message printed from executable\n");

  return 0;
}
