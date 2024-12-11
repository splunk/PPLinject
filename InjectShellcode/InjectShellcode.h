#include "ntdll.h"

typedef NTSTATUS (NTAPI * RtlAdjustPrivilege_t)(
    DWORD privilege,
    BOOL bEnablePrivilege,
    BOOL IsThreadPrivilege,
    PBOOLEAN PreviousValue);

typedef HMODULE(WINAPI* LoadLibraryW_t)(
    LPCWSTR lpLibFileName
    );

typedef FARPROC(WINAPI* GetProcAddress_t)(
    HMODULE hModule,
    LPCSTR  lpProcName
    );

typedef HANDLE(WINAPI* OpenProcess_t)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
    );

typedef NTSTATUS (NTAPI * NtOpenProcess_t)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

typedef NTSTATUS (NTAPI *NtOpenThread_t)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
);


typedef HANDLE(WINAPI* CreateFileW_t)(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    );

typedef BOOL (WINAPI *ReadFile_t)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

typedef BOOL(WINAPI* TerminateProcess_t)(
    HANDLE hProcess,
    UINT   uExitCode
    );

typedef NTSTATUS (NTAPI *NtTerminateProcess_t)(
    HANDLE   ProcessHandle,
    NTSTATUS ExitStatus
);

typedef NTSTATUS (NTAPI *NtTerminateThread_t)(
    IN HANDLE               ThreadHandle,
    IN NTSTATUS             ExitStatus);


typedef LPVOID (WINAPI* VirtualAllocEx_t)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

typedef NTSTATUS (NTAPI * NtAllocateVirtualMemory_t)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

typedef BOOL (WINAPI *WriteProcessMemory_t)(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    IN PVOID                Buffer,
    IN ULONG                NumberOfBytesToWrite,
    OUT PULONG              NumberOfBytesWritten);

typedef HANDLE (WINAPI * CreateRemoteThread_t)(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
);

typedef NTSTATUS (NTAPI *RtlCreateUserThread_t)(
    IN HANDLE               ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN              CreateSuspended,
    IN ULONG                StackZeroBits,
    IN OUT PULONG           StackReserved,
    IN OUT PULONG           StackCommit,
    IN PVOID                StartAddress,
    IN PVOID                StartParameter OPTIONAL,
    OUT PHANDLE             ThreadHandle,
    OUT CLIENT_ID          *ClientID);

typedef NTSTATUS (NTAPI * NtWaitForSingleObject_t)(
    HANDLE         Handle,
    BOOLEAN        Alertable,
    PLARGE_INTEGER Timeout
);

typedef NTSTATUS (NTAPI * NtSetInformationProcess_t)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG ProcessInformationLength
);

typedef DWORD (WINAPI * GetLastError_t)(void);

#define MAGIC1 0x1BADC0D3
#define MAGIC2 0xDEADBEEF

// 90                      nop
// 48 87 c9                xchg   rcx, rcx
// 48 87 d2                xchg   rdx, rdx
// 4d 87 c0                xchg   r8, r8
// 4d 87 c9                xchg   r9, r9
// 90                      nop
#define MAGIC_NOPS { 0x90, 0x48, 0x87, 0xC9, 0x48, 0x87, 0xD2, 0x4D, 0x87, 0xC0, 0x4D, 0x87, 0xC9, 0x90 }
#define MAGIC_NOPS_LENGTH 14

//const int ProcessMitigationPolicy = 52;

typedef struct PROCESS_MITIGATION {
    PROCESS_MITIGATION_POLICY Policy;
    DWORD Flags;
} PROCESS_MITIGATION;

typedef HMODULE (*LoadLibraryPtr)(LPCSTR);

typedef struct _LoadLibraryThread
{
	LoadLibraryW_t LoadLibraryW;
	GetLastError_t GetLastError;
	NtSetInformationProcess_t NtSetInformationProcess;
	RtlAdjustPrivilege_t RtlAdjustPrivilege;
	PWCHAR DllPath;
} LoadLibraryThread;

typedef struct _SHELLCODE_PARAMS
{
    DWORD magic1;
    DWORD magic2;

    DWORD mySize;
    UCHAR magicNops[MAGIC_NOPS_LENGTH];

    WCHAR mutexName[60];
    WCHAR reqName[60];
    WCHAR doneName[60];
    WCHAR sectionName[60];
    WCHAR dllName[60];

    // User params
    DWORD dwPid;

    // IAT
    NtOpenProcess_t pNtOpenProcess;
    NtTerminateProcess_t pNtTerminateProcess;
    RtlAdjustPrivilege_t pRtlAdjustPrivilege;
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory;
    NtWriteVirtualMemory_t pNtWriteVirtualMemory;
    RtlCreateUserThread_t pRtlCreateUserThread;
    NtWaitForSingleObject_t pNtWaitForSingleObject;
	NtSetInformationProcess_t pNtSetInformationProcess;

	LoadLibraryW_t pLoadLibraryW;
	GetLastError_t pGetLastError;

} SHELLCODE_PARAMS, * PSHELLCODE_PARAMS;
