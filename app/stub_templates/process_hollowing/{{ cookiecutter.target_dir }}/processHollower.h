#ifndef STUBBORN_PROCESS_HOLLOWER_H
#define STUBBORN_PROCESS_HOLLOWER_H
#include "windowsInternals.h"
#include "windows.h"
#include <winnt.h>
#include <memoryapi.h>

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
