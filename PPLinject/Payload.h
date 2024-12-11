#pragma once

#include <string>
#include "ntdll.h"

bool BuildPayload(
    HANDLE hBenignDll, 
    std::string & payloadBuffer,
    DWORD dwTargetProcessId,
	LPWSTR pwszDllPath);
