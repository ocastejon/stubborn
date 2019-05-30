#ifndef PROCESS_HOLLOWING_DECRYPT_H
#define PROCESS_HOLLOWING_DECRYPT_H

#include <windows.h>

VOID Xor(char *lpData, DWORD dwDataSize, LPCSTR lpKey, DWORD dwKeyLength);

#endif //PROCESS_HOLLOWING_DECRYPT_H
