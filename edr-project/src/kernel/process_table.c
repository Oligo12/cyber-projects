#include "globals.h"
#include <ntifs.h>


VOID AddProcessToTable(
    HANDLE pid,
    HANDLE parentPid,
    PCUNICODE_STRING image,
    PCUNICODE_STRING parentImage,
    PCUNICODE_STRING cmd,
    LARGE_INTEGER createTime,
    LARGE_INTEGER parentCreateTime
)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_TableLock, &oldIrql);

    for (int i = 0; i < MAX_PROCESSES; i++) {

        if (!g_ProcessTable[i].InUse) {

            g_ProcessTable[i].ProcessId = pid;
            g_ProcessTable[i].ParentProcessId = parentPid;
            g_ProcessTable[i].CreateTime = createTime;
            g_ProcessTable[i].ParentCreateTime = parentCreateTime;
            g_ProcessTable[i].InUse = TRUE;
            g_ProcessTable[i].IsNew = TRUE;

            LARGE_INTEGER now;
            KeQuerySystemTimePrecise(&now);
            g_ProcessTable[i].EventTime = now;
            g_ProcessTable[i].EventType = EDR_EVENT_PROCESS_CREATE;

            g_ProcessTable[i].ImageBase = NULL;
            g_ProcessTable[i].ImageCount = 0;
            RtlZeroMemory(g_ProcessTable[i].LoadedImages, sizeof(g_ProcessTable[i].LoadedImages));

            RtlZeroMemory(g_ProcessTable[i].ImagePath, sizeof(g_ProcessTable[i].ImagePath));

            if (image && image->Buffer) {
                SIZE_T copyLen = min(image->Length, sizeof(g_ProcessTable[i].ImagePath) - sizeof(WCHAR));
                RtlCopyMemory(g_ProcessTable[i].ImagePath, image->Buffer, copyLen);

                g_ProcessTable[i].ImagePath[copyLen / sizeof(WCHAR)] = L'\0';
            }

            RtlZeroMemory(g_ProcessTable[i].ParentImage, sizeof(g_ProcessTable[i].ParentImage));

            if (parentImage && parentImage->Buffer) {
                SIZE_T copyLen = min(parentImage->Length, sizeof(g_ProcessTable[i].ParentImage) - sizeof(WCHAR));
                RtlCopyMemory(g_ProcessTable[i].ParentImage, parentImage->Buffer, copyLen);
                g_ProcessTable[i].ParentImage[copyLen / sizeof(WCHAR)] = L'\0';
            }

            RtlZeroMemory(g_ProcessTable[i].CommandLine, sizeof(g_ProcessTable[i].CommandLine));

            if (cmd && cmd->Buffer) {
                SIZE_T copyLen = min(cmd->Length, sizeof(g_ProcessTable[i].CommandLine) - sizeof(WCHAR));
                RtlCopyMemory(g_ProcessTable[i].CommandLine, cmd->Buffer, copyLen);

                g_ProcessTable[i].CommandLine[copyLen / sizeof(WCHAR)] = L'\0';
            }

            break;
        }
    }

    KeReleaseSpinLock(&g_TableLock, oldIrql);
}


// Marks process as terminated.
VOID RemoveProcessFromTable(HANDLE pid, LARGE_INTEGER createTime)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_TableLock, &oldIrql);

    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (g_ProcessTable[i].InUse &&
            g_ProcessTable[i].ProcessId == pid &&
            g_ProcessTable[i].CreateTime.QuadPart == createTime.QuadPart &&
            g_ProcessTable[i].CreateTime.QuadPart != 0) {

            LARGE_INTEGER now;
            KeQuerySystemTimePrecise(&now);

            g_ProcessTable[i].IsNew = TRUE;
            g_ProcessTable[i].EventType = EDR_EVENT_PROCESS_TERMINATE;
            g_ProcessTable[i].EventTime = now;

            // Don't clear InUse, leave the entry in place so the terminate event
            // can still resolve create-time lookups before userland processes it.

            break;
        }
    }

    KeReleaseSpinLock(&g_TableLock, oldIrql);
}