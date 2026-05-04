#include "globals.h"
#include <ntifs.h>
#include <ntddk.h>
#pragma comment(lib, "ntoskrnl.lib")

BOOLEAN GetProcessImageSafe(HANDLE pid, LARGE_INTEGER expectedCreateTime, PWCHAR outBuffer, SIZE_T outSize)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_TableLock, &oldIrql);

    RtlZeroMemory(outBuffer, outSize);

    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (g_ProcessTable[i].InUse &&
            g_ProcessTable[i].ProcessId == pid &&
            g_ProcessTable[i].CreateTime.QuadPart == expectedCreateTime.QuadPart &&
            g_ProcessTable[i].CreateTime.QuadPart != 0) {

            SIZE_T copyLen = wcslen(g_ProcessTable[i].ImagePath) * sizeof(WCHAR);
            copyLen = min(copyLen, outSize - sizeof(WCHAR));

            RtlCopyMemory(outBuffer, g_ProcessTable[i].ImagePath, copyLen);
            outBuffer[copyLen / sizeof(WCHAR)] = L'\0';

            KeReleaseSpinLock(&g_TableLock, oldIrql);
            return TRUE;
        }
    }

    KeReleaseSpinLock(&g_TableLock, oldIrql);

    RtlStringCbCopyW(outBuffer, outSize, L"UNKNOWN");

    return FALSE;
}


BOOLEAN GetProcessCommandLineSafe(HANDLE pid, LARGE_INTEGER expectedCreateTime, PWCHAR outBuffer, SIZE_T outSize)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_TableLock, &oldIrql);

    RtlZeroMemory(outBuffer, outSize);


    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (g_ProcessTable[i].InUse &&
            g_ProcessTable[i].ProcessId == pid &&
            g_ProcessTable[i].CreateTime.QuadPart == expectedCreateTime.QuadPart &&
            g_ProcessTable[i].CreateTime.QuadPart != 0) {

            SIZE_T copyLen = wcslen(g_ProcessTable[i].CommandLine) * sizeof(WCHAR);
            copyLen = min(copyLen, outSize - sizeof(WCHAR));

            RtlCopyMemory(outBuffer, g_ProcessTable[i].CommandLine, copyLen);

            outBuffer[copyLen / sizeof(WCHAR)] = L'\0';

            KeReleaseSpinLock(&g_TableLock, oldIrql);
            return TRUE;
        }
    }

    KeReleaseSpinLock(&g_TableLock, oldIrql);

    RtlStringCbCopyW(outBuffer, outSize, L"UNKNOWN");

    return FALSE;
}
