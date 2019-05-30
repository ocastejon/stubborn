#include "windowsInternals.h"

#ifndef PROCESS_HOLLOWING_DEBUG_H
#define PROCESS_HOLLOWING_DEBUG_H

#define FORMAT_INT 0
#define FORMAT_ADDRESS 1
#define FORMAT_SECTION 2
#define FORMAT_STRING 3

void DebugInfoMessage(char const *message);

void DebugSuccessMessage(char const *message);

void DebugData(char const *message, VIRTUAL_ADDRESS data, int dataFormat);

void DebugErrorMessage(char const *message);
#endif //PROCESS_HOLLOWING_DEBUG_H
