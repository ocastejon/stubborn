#include "antivirusChecks.h"

BOOL isCodeEmulated() {
    return checkSleep() || checkLoadDLL();
}

BOOL isSandBox() {
    return checkNumberOfProcessors() || checkPhysicalMemory() || checkDriveSize();
}

BOOL checkSleep() {
    DebugInfoMessage("Checking code emulation using the Sleep function");
    DWORD dwCount1 = GetTickCount();
    Sleep(1000);
    DWORD dwCount2 = GetTickCount();
    if(dwCount2 - dwCount1 < 1000) {
        DebugInfoMessage("Code Emulation Detected: Time check did not pass.");
        return TRUE;
    }
    return FALSE;
}

BOOL checkLoadDLL() {
    DebugInfoMessage("Checking code emulation loading rare and fake DLLs");
    char const *realDLL[] = {"Kernel32.DLL", "networkexplorer.DLL", "NlsData0000.DLL"};
    char const *falseDLL[] = {"NetProjW.DLL", "Ghofr.DLL", "fg122.DLL"};
    HMODULE hInstLib;
    for (int i = 0; i < 3; i++) {
        hInstLib = LoadLibraryA(realDLL[i]);
        if(hInstLib == nullptr) {
            DebugData("Code Emulation Detected. Existing DLL not found", (VIRTUAL_ADDRESS)realDLL[i], FORMAT_STRING);
            return TRUE;
        }
        FreeLibrary(hInstLib);
    }

    for(int i = 0; i < 3; i++) {
        hInstLib = LoadLibraryA(falseDLL[i]);
        if(hInstLib != nullptr) {
            DebugData("Code Emulation Detected. Fake DLL was found", (VIRTUAL_ADDRESS)realDLL[i], FORMAT_STRING);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL checkNumberOfProcessors() {
    DebugInfoMessage("Checking number of processors to detect sandbox");
    SYSTEM_INFO siSysInfo;
    GetSystemInfo(&siSysInfo);
    if (siSysInfo.dwNumberOfProcessors < 2) {
        DebugData("Sandbox detected. Number of processors", siSysInfo.dwNumberOfProcessors, FORMAT_INT);
        return TRUE;
    }
    return FALSE;
}

BOOL checkPhysicalMemory() {
    DebugInfoMessage("Checking physical memory to detect sandbox");
    MEMORYSTATUSEX mseMemoryStatus;
    mseMemoryStatus.dwLength = sizeof (mseMemoryStatus);
    GlobalMemoryStatusEx(&mseMemoryStatus);
    if ((mseMemoryStatus.ullTotalPhys/1024) < 1048576) {
        DebugData("Sandbox detected. Physical memory", mseMemoryStatus.ullTotalPhys/1024, FORMAT_INT);
        return TRUE;
    }
    return FALSE;
}

BOOL checkDriveSize() {
    DebugInfoMessage("Checking C drive size to detect sandbox");
    ULARGE_INTEGER total_bytes;
    if (!GetDiskFreeSpaceExA("C:\\", nullptr, &total_bytes, nullptr)) {
        return FALSE;
    }
    if (total_bytes.QuadPart / 1073741824 <= 60) {
        DebugData("Sandbox detected. C drive size", total_bytes.QuadPart / 1073741824, FORMAT_INT);
        return TRUE;
    }
    return FALSE;
}

