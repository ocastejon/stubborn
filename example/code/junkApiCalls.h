#ifndef PROCESS_HOLLOWING_JUNKAPICALLS_H
#define PROCESS_HOLLOWING_JUNKAPICALLS_H

#include <heapapi.h>
#include <windows.h>
#include <winuser.h>
#include "debug.h"

LPPOINT callGetCursorPos();
VOID callGetMenu();
VOID callIsTextUnicode();
VOID callHeapFunctions();
VOID callGetParent();

#endif //PROCESS_HOLLOWING_JUNKAPICALLS_H
