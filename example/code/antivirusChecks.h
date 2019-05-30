#include <windows.h>
#include "debug.h"

#ifndef PROCESS_HOLLOWING_ANTIVIRUS_CHECKS_H
#define PROCESS_HOLLOWING_ANTIVIRUS_CHECKS_H

BOOL isCodeEmulated();

BOOL checkSleep();

BOOL checkLoadDLL();

BOOL isSandBox();

BOOL checkNumberOfProcessors();

BOOL checkPhysicalMemory();

BOOL checkDriveSize();

#endif //PROCESS_HOLLOWING_ANTIVIRUS_CHECKS_H
