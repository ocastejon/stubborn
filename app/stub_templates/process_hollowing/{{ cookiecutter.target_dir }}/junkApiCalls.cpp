#include "junkApiCalls.h"

LPPOINT callGetCursorPos() {
    DebugInfoMessage("Making junk call to GetCursorPos");
    auto lpPoint = new POINT();
    GetCursorPos(lpPoint);
    return lpPoint;
}

VOID callGetMenu() {
    DebugInfoMessage("Making junk call to GetActiveWindow and GetMenu");
    auto hWnd = GetActiveWindow();
    GetMenu(hWnd);
}

VOID callIsTextUnicode() {
    DebugInfoMessage("Making junk call to IsTextUnicode");
    const VOID *lpv = "is this text unicode?";
    int iSize = 21;
    auto lpiResult = new INT();
    IsTextUnicode(lpv, iSize, lpiResult);
}

VOID callHeapFunctions() {
    DebugInfoMessage("Making junk calls to GetProcessHeap, HeapAlloc and HeapFree");
    HANDLE hHeap = GetProcessHeap();
    LPVOID lpMem = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 16);
    if (lpMem != nullptr)
        HeapFree(hHeap, NULL, lpMem);
}

VOID callGetParent() {
    DebugInfoMessage("Making junk calls to GetActiveWindow and GetParent");
    auto hWnd = GetActiveWindow();
    GetParent(hWnd);
}