#pragma once
#include <windows.h>
#include "shared.h"

BOOL DeviceOpen();
BOOL DeviceRead(EDR_EVENT* buffer, DWORD count, DWORD* outCount);

// Asks the driver to resolve a PID's process create-time via
// PsLookupProcessByProcessId. Returns TRUE on IOCTL success;
// outCreateTime->QuadPart will be 0 if the PID couldn't be resolved.
BOOL DeviceResolveCreateTime(DWORD pid, LARGE_INTEGER* outCreateTime);