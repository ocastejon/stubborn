#include "windowsInternals.h"

DWORD CountRelocationEntries(DWORD dwBlockSize) {
    return (dwBlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
}

PPEB FindRemotePEB(HANDLE hProcess) {
    HMODULE hNTDLL = LoadLibraryA("ntdll");
    if (!hNTDLL)
        return nullptr;
    FARPROC fpNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");
    if (!fpNtQueryInformationProcess)
        return nullptr;
    auto ntQueryInformationProcess =(_NtQueryInformationProcess)fpNtQueryInformationProcess;
    auto pBasicInfo = new PROCESS_BASIC_INFORMATION();
    DWORD dwReturnLength = 0;
    ntQueryInformationProcess(hProcess, 0, pBasicInfo ,sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);
    return pBasicInfo->PebBaseAddress;
}

PPEB ReadRemotePEB(HANDLE hProcess) {
    PPEB dwPEBAddress = FindRemotePEB(hProcess);
    PEB* pPEB = new PEB();
    BOOL bSuccess = ReadProcessMemory(hProcess, (LPCVOID)dwPEBAddress, pPEB, sizeof(PEB), nullptr);
    if (!bSuccess)
        return nullptr;
    return pPEB;
}

PPE_HEADERS LoadPEHeaders(VIRTUAL_ADDRESS dwImageBase) {
    auto pPEHeaders = new PE_HEADERS();
    pPEHeaders->DOSHeader = (PIMAGE_DOS_HEADER)dwImageBase;
    pPEHeaders->NTHeaders = (PIMAGE_NT_HEADERS)(dwImageBase + pPEHeaders->DOSHeader->e_lfanew);
    pPEHeaders->SectionHeaders = (PIMAGE_SECTION_HEADER)(dwImageBase + pPEHeaders->DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    return pPEHeaders;
}

DWORD GetMemProtectionFlag(DWORD dwCharacteristic) {
    DWORD dwMemProtectionFlag;
    if (dwCharacteristic & IMAGE_SCN_MEM_EXECUTE) {
        if (dwCharacteristic & IMAGE_SCN_MEM_READ) {
            if (dwCharacteristic & IMAGE_SCN_MEM_WRITE) {
                dwMemProtectionFlag = PAGE_EXECUTE_READWRITE;
            } else {
                dwMemProtectionFlag = PAGE_EXECUTE_READ;
            }
        } else {
            dwMemProtectionFlag = PAGE_EXECUTE;
        }
    } else {
        if (dwCharacteristic & IMAGE_SCN_MEM_WRITE) {
            dwMemProtectionFlag = PAGE_READWRITE;
        } else {
            dwMemProtectionFlag = PAGE_READONLY;
        }
    }
    return dwMemProtectionFlag;
}