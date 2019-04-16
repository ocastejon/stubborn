#include <windows.h>

#ifndef STUBBORN_WININTERNALS_H
#define STUBBORN_WININTERNALS_H

#define BUFFER_SIZE 1000000 // improve. probably we do not need to be a constant

typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STRING, *PUNICODE_STRING;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
//__declspec( align(8) )
typedef struct _LDR_DATA_TABLE_ENTRY
{
    //LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first entry.
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG                   Length;
    BOOLEAN                 Initialized;
    PVOID                   SsHandle;
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
    struct _PEB_FREE_BLOCK * pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;



// see http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FPEB.html
typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT                  Flags;
    USHORT                  Length;
    ULONG                   TimeStamp;
    UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG                   MaximumLength;
    ULONG                   Length;
    ULONG                   Flags;
    ULONG                   DebugFlags;
    PVOID                   ConsoleHandle;
    ULONG                   ConsoleFlags;
    HANDLE                  StdInputHandle;
    HANDLE                  StdOutputHandle;
    HANDLE                  StdErrorHandle;
    UNICODE_STRING          CurrentDirectoryPath;
    HANDLE                  CurrentDirectoryHandle;
    UNICODE_STRING          DllPath;
    UNICODE_STRING          ImagePathName;
    UNICODE_STRING          CommandLine;
    PVOID                   Environment;
    ULONG                   StartingPositionLeft;
    ULONG                   StartingPositionTop;
    ULONG                   Width;
    ULONG                   Height;
    ULONG                   CharWidth;
    ULONG                   CharHeight;
    ULONG                   ConsoleTextAttributes;
    ULONG                   WindowFlags;
    ULONG                   ShowWindowFlags;
    UNICODE_STRING          WindowTitle;
    UNICODE_STRING          DesktopName;
    UNICODE_STRING          ShellInfo;
    UNICODE_STRING          RuntimeData;
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;


typedef void (*PPEBLOCKROUTINE)(
        PVOID PebLock
);

typedef LPVOID * PPVOID;

typedef struct _PEB {
  BOOLEAN                 InheritedAddressSpace;
  BOOLEAN                 ReadImageFileExecOptions;
  BOOLEAN                 BeingDebugged;
  BOOLEAN                 Spare;
  HANDLE                  Mutant;
  PVOID                   ImageBaseAddress;
  PPEB_LDR_DATA           LoaderData;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID                   SubSystemData;
  PVOID                   ProcessHeap;
  PVOID                   FastPebLock;
  PPEBLOCKROUTINE         FastPebLockRoutine;
  PPEBLOCKROUTINE         FastPebUnlockRoutine;
  ULONG                   EnvironmentUpdateCount;
  PPVOID                  KernelCallbackTable;
  PVOID                   EventLogSection;
  PVOID                   EventLog;
  PPEB_FREE_BLOCK         FreeList;
  ULONG                   TlsExpansionCounter;
  PVOID                   TlsBitmap;
  ULONG                   TlsBitmapBits[0x2];
  PVOID                   ReadOnlySharedMemoryBase;
  PVOID                   ReadOnlySharedMemoryHeap;
  PPVOID                  ReadOnlyStaticServerData;
  PVOID                   AnsiCodePageData;
  PVOID                   OemCodePageData;
  PVOID                   UnicodeCaseTableData;
  ULONG                   NumberOfProcessors;
  ULONG                   NtGlobalFlag;
  BYTE                    Spare2[0x4];
  LARGE_INTEGER           CriticalSectionTimeout;
  ULONG                   HeapSegmentReserve;
  ULONG                   HeapSegmentCommit;
  ULONG                   HeapDeCommitTotalFreeThreshold;
  ULONG                   HeapDeCommitFreeBlockThreshold;
  ULONG                   NumberOfHeaps;
  ULONG                   MaximumNumberOfHeaps;
  PPVOID                  *ProcessHeaps;
  PVOID                   GdiSharedHandleTable;
  PVOID                   ProcessStarterHelper;
  PVOID                   GdiDCAttributeList;
  PVOID                   LoaderLock;
  ULONG                   OSMajorVersion;
  ULONG                   OSMinorVersion;
  ULONG                   OSBuildNumber;
  ULONG                   OSPlatformId;
  ULONG                   ImageSubSystem;
  ULONG                   ImageSubSystemMajorVersion;
  ULONG                   ImageSubSystemMinorVersion;
  ULONG                   GdiHandleBuffer[0x22];
  ULONG                   PostProcessInitRoutine;
  ULONG                   TlsExpansionBitmap;
  BYTE                    TlsExpansionBitmapBits[0x80];
  ULONG                   SessionId;

} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef DWORD (WINAPI* _NtQueryInformationProcess)(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        DWORD ProcessInformationLength,
        PDWORD ReturnLength
);

typedef DWORD (WINAPI *_NtUnmapViewOfSection)(
        HANDLE ProcessHandle,
        PVOID BaseAddress
);


typedef struct _LOADED_IMAGE {
    PIMAGE_NT_HEADERS32 FileHeader;
    WORD NumberOfSections;
    PIMAGE_SECTION_HEADER Sections;
} LOADED_IMAGE, *PLOADED_IMAGE;

// Per relocations
typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

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

PEB* ReadRemotePEB(HANDLE hProcess) {
    PPEB dwPEBAddress = FindRemotePEB(hProcess);
    PEB* pPEB = new PEB();
    BOOL bSuccess = ReadProcessMemory (hProcess, (LPCVOID)dwPEBAddress, pPEB, sizeof(PEB), nullptr);

    if (!bSuccess)
        return nullptr  ;

    return pPEB;
}

// pot estar be fer utilities d'aquest tipus
PIMAGE_NT_HEADERS32 GetNTHeaders(DWORD pBuffer) {
    return (PIMAGE_NT_HEADERS32)(pBuffer +((PIMAGE_DOS_HEADER)pBuffer)->e_lfanew);
}

PLOADED_IMAGE GetLoadedImage(DWORD dwImageBase) {
    auto pDosHeader = (PIMAGE_DOS_HEADER)dwImageBase;
    PIMAGE_NT_HEADERS32 pNTHeaders = GetNTHeaders(dwImageBase);
    auto pImage = new LOADED_IMAGE();
    pImage->FileHeader = (PIMAGE_NT_HEADERS32)(dwImageBase + pDosHeader->e_lfanew);
    pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
    pImage->Sections = (PIMAGE_SECTION_HEADER)(dwImageBase + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
    return pImage;
}

#endif //STUBBORN_WININTERNALS_H
