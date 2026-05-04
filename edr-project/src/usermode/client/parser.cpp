#include "edrclient.h"

ULONG FindRecentHandleSourcePid(ULONG dstPid, ULONGLONG now)
{
    ULONG bestSource = 0;
    ULONG fallbackSource = 0;

    for (int i = 0; i < MAX_TRACKED_HANDLES; i++)
    {
        if (!g_HandleTable[i].InUse)
            continue;

        if ((ULONG)(ULONG_PTR)g_HandleTable[i].TargetPid != dstPid)
            continue;

        if ((now - g_HandleTable[i].Timestamp) >= (5ULL * 1000 * 1000 * 10))
            continue;

        if (!(g_HandleTable[i].DesiredAccess &
            (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)))
            continue;

        ULONG srcPid = (ULONG)(ULONG_PTR)g_HandleTable[i].SourcePid;

        // Skip known noisy system PIDs
        PROC_STATE* srcProc = FindProcess(
            g_HandleTable[i].SourcePid,
            g_HandleTable[i].SourceCreateTime
        );

        BOOL isSystemNoise = FALSE;
        if (srcProc && srcProc->ImagePath[0] != L'\0')
        {
            if (wcsstr(srcProc->ImagePath, L"svchost.exe") ||
                wcsstr(srcProc->ImagePath, L"csrss.exe") ||
                wcsstr(srcProc->ImagePath, L"explorer.exe") ||
                wcsstr(srcProc->ImagePath, L"services.exe") ||
                wcsstr(srcProc->ImagePath, L"WerFault.exe") ||
                wcsstr(srcProc->ImagePath, L"MsMpEng.exe"))
            {
                isSystemNoise = TRUE;
            }
        }

        if (!isSystemNoise)
        {
            // Non-system source
            bestSource = srcPid;
            break; // first non-noise match wins
        }
        else if (fallbackSource == 0)
        {
            fallbackSource = srcPid;
        }
    }

    return bestSource ? bestSource : fallbackSource;
}