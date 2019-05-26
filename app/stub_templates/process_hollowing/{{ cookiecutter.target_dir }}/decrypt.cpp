#include "decrypt.h"

VOID Xor(char *lpData, DWORD dwDataSize, LPCSTR lpKey, DWORD dwKeyLength) {
    for (int i = 0; i < dwDataSize; i++) {
        lpData[i] ^= lpKey[i % dwKeyLength];
    }
}

