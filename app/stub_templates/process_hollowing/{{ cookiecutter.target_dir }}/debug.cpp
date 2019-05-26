#include <windows.h>
#include <stdio.h>
#include "debug.h"

void DebugInfoMessage(char const *message) {
#ifndef NDEBUG
    printf("[-] %s\n", message);
#endif
}

void DebugSuccessMessage(char const *message) {
#ifndef NDEBUG
    printf("[+] %s\n", message);
#endif
}

void DebugData(char const *message, VIRTUAL_ADDRESS data, int dataFormat) {
#ifndef NDEBUG
    if (dataFormat == FORMAT_INT) {
        printf("    %s: %d\n", message, data);
    } else if(dataFormat == FORMAT_ADDRESS)  {
    #ifdef _WIN64
        printf("    %s: 0x%016llx\n", message, data);
    #else
        printf("    %s: 0x%08x\n", message, data);
    #endif
    } else if (dataFormat == FORMAT_SECTION) {
        printf("    %s: %.8s\n", message, data);
    } else if (dataFormat == FORMAT_STRING) {
        printf("    %s: %s\n", message, data);
    }
#endif
}

void DebugErrorMessage(char const *message) {
#ifndef NDEBUG
    LPVOID lpMsgBuf;
    DWORD dwLastError = GetLastError();
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                  dwLastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &lpMsgBuf, 0, NULL );
    printf("[!] %s\nError: %s", message, (char *) lpMsgBuf);
#endif
}