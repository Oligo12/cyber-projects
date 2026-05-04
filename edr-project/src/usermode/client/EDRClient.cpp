#define _CRT_SECURE_NO_WARNINGS
#include "shared.h"
#include "edrclient.h"
#include "output.h"
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <tlhelp32.h>
#pragma comment(lib, "Advapi32.lib")
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif

SECCTX_WORK_ITEM g_SecCtxQueue[MAX_SECCTX_QUEUE];

BOOL EqualLuid(LUID a, LUID b)
{
    return (a.LowPart == b.LowPart && a.HighPart == b.HighPart);
}

EDR_EVENT g_EventBuffer[512];

void EnqueueSecCtxWork(HANDLE pid, ULONGLONG createTime);
PROC_STATE g_ProcTable[MAX_TRACKED_PROCS] = { 0 };
HANDLE_EVENT_STATE g_HandleTable[MAX_TRACKED_HANDLES] = { 0 };

PROC_STATE* FindProcess(HANDLE pid, ULONGLONG createTime);

BOOL TryPopulateSecCtx(PROC_STATE* p);

DWORD g_SensorPid = 0;
ULONGLONG g_SensorCreateTime = 0;

BOOL IsSensorProcess(HANDLE pid, LARGE_INTEGER createTime)
{
    DWORD checkPid = (DWORD)(ULONG_PTR)pid;
    ULONGLONG checkCreate = (ULONGLONG)createTime.QuadPart;

    return (checkPid == g_SensorPid) &&
        (checkCreate == g_SensorCreateTime);
}

void TrackProcessCreate(EDR_EVENT* evt) {
    for (int i = 0; i < MAX_TRACKED_PROCS; i++) {
        if (!g_ProcTable[i].InUse) {
            g_ProcTable[i].InUse = TRUE;
            g_ProcTable[i].ProcessId = evt->ProcessId;
            g_ProcTable[i].ParentProcessId = evt->ParentProcessId;
            g_ProcTable[i].CreateTime = evt->ProcessCreateTime.QuadPart;

            wcscpy_s(g_ProcTable[i].ImagePath, evt->ImagePath);
            wcscpy_s(g_ProcTable[i].ParentImagePath, evt->ParentImagePath);
            wcscpy_s(g_ProcTable[i].CommandLine, evt->CommandLine);
            g_ProcTable[i].SecCtxReady = FALSE;

            g_ProcTable[i].UserSid[0] = L'\0';
            g_ProcTable[i].Integrity[0] = L'\0';
            g_ProcTable[i].TokenType[0] = L'\0';
            g_ProcTable[i].ElevationType[0] = L'\0';

            g_ProcTable[i].PrivSeDebug = FALSE;
            g_ProcTable[i].PrivSeImpersonate = FALSE;
            g_ProcTable[i].PrivSeAssignPrimaryToken = FALSE;
            g_ProcTable[i].PrivSeTcb = FALSE;
            g_ProcTable[i].PrivSeBackup = FALSE;
            g_ProcTable[i].PrivSeRestore = FALSE;
            g_ProcTable[i].PrivSeLoadDriver = FALSE;
            g_ProcTable[i].PrivSeTakeOwnership = FALSE;

            EnqueueSecCtxWork(evt->ProcessId, evt->ProcessCreateTime.QuadPart);

            return;
        }
    }
}

void TrackProcessExit(EDR_EVENT* evt) {
    for (int i = 0; i < MAX_TRACKED_PROCS; i++) {
        if (g_ProcTable[i].InUse &&
            g_ProcTable[i].ProcessId == evt->ProcessId &&
            g_ProcTable[i].CreateTime == evt->ProcessCreateTime.QuadPart) {

            ZeroMemory(&g_ProcTable[i], sizeof(PROC_STATE));
            return;
        }
    }
}

// capability event (process gained rights, not executed yet)
void TrackHandleEvent(EDR_EVENT* evt) {

    for (int i = 0; i < MAX_TRACKED_HANDLES; i++) {
        if (!g_HandleTable[i].InUse) {

            g_HandleTable[i].InUse = TRUE;
            g_HandleTable[i].SourcePid = evt->SourceProcessId;
            g_HandleTable[i].TargetPid = evt->TargetProcessId;

            g_HandleTable[i].SourceCreateTime = evt->SourceProcessCreateTime.QuadPart;
            g_HandleTable[i].TargetCreateTime = evt->TargetProcessCreateTime.QuadPart;

            g_HandleTable[i].DesiredAccess = evt->DesiredAccess;
            g_HandleTable[i].Timestamp = evt->Timestamp.QuadPart;

            return;
        }
    }
}

void CleanupOldHandles(ULONGLONG now) {

    for (int i = 0; i < MAX_TRACKED_HANDLES; i++) {

        if (!g_HandleTable[i].InUse)
            continue;

        // 5 second expiry
        if ((now - g_HandleTable[i].Timestamp) > (5ULL * 1000 * 1000 * 10)) {
            g_HandleTable[i].InUse = FALSE;
        }
    }
}

BOOL TryPopulateSecCtx(PROC_STATE* p)
{
    if (!p || p->SecCtxReady)
        return FALSE;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        (DWORD)(ULONG_PTR)p->ProcessId
    );


    LUID luidDebug, luidImpersonate, luidAssign, luidTcb;
    LUID luidBackup, luidRestore, luidLoadDriver, luidTakeOwnership;

    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug);
    LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &luidImpersonate);
    LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luidAssign);
    LookupPrivilegeValue(NULL, SE_TCB_NAME, &luidTcb);
    LookupPrivilegeValue(NULL, SE_BACKUP_NAME, &luidBackup);
    LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &luidRestore);
    LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &luidLoadDriver);
    LookupPrivilegeValue(NULL, SE_TAKE_OWNERSHIP_NAME, &luidTakeOwnership);

    if (!hProcess)
        return FALSE;

    HANDLE hToken = NULL;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return FALSE;
    }

    DWORD len = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &len);

    PTOKEN_USER tu = (PTOKEN_USER)malloc(len);
    if (!tu) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenUser, tu, len, &len)) {
        free(tu);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    // - GetTokenInformation (SID)
    LPWSTR sidStr = NULL;

    if (ConvertSidToStringSidW(tu->User.Sid, &sidStr)) {
        wcscpy_s(p->UserSid, sidStr);
        LocalFree(sidStr);
    }

    free(tu);
    // - GetTokenInformation (Integrity)
    len = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &len);

    PTOKEN_MANDATORY_LABEL tml = (PTOKEN_MANDATORY_LABEL)malloc(len);
    if (!tml) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenIntegrityLevel, tml, len, &len)) {
        free(tml);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    DWORD il = *GetSidSubAuthority(
        tml->Label.Sid,
        (DWORD)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1)
    );

    if (il >= SECURITY_MANDATORY_SYSTEM_RID)
        wcscpy_s(p->Integrity, L"System");
    else if (il >= SECURITY_MANDATORY_HIGH_RID)
        wcscpy_s(p->Integrity, L"High");
    else if (il >= SECURITY_MANDATORY_MEDIUM_RID)
        wcscpy_s(p->Integrity, L"Medium");
    else if (il >= SECURITY_MANDATORY_LOW_RID)
        wcscpy_s(p->Integrity, L"Low");
    else
        wcscpy_s(p->Integrity, L"Unknown");

    free(tml);

    // - GetTokenInformation (TokenType)
    TOKEN_TYPE tokenType;
    DWORD tokenTypeLen = 0;

    if (!GetTokenInformation(
        hToken,
        TokenType,
        &tokenType,
        sizeof(tokenType),
        &tokenTypeLen
    )) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (tokenType == TokenPrimary)
        wcscpy_s(p->TokenType, L"Primary");
    else if (tokenType == TokenImpersonation)
        wcscpy_s(p->TokenType, L"Impersonation");
    else
        wcscpy_s(p->TokenType, L"Unknown");

    // - GetTokenInformation (ElevationType)
    TOKEN_ELEVATION_TYPE elevType;
    DWORD elevLen = 0;

    if (!GetTokenInformation(
        hToken,
        TokenElevationType,
        &elevType,
        sizeof(elevType),
        &elevLen
    )) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (elevType == TokenElevationTypeDefault)
        wcscpy_s(p->ElevationType, L"Default");
    else if (elevType == TokenElevationTypeFull)
        wcscpy_s(p->ElevationType, L"Full");
    else if (elevType == TokenElevationTypeLimited)
        wcscpy_s(p->ElevationType, L"Limited");
    else
        wcscpy_s(p->ElevationType, L"Unknown");

    // - GetTokenInformation (Privileges)
    DWORD privLen = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &privLen);

    PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)malloc(privLen);
    if (!tp) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!GetTokenInformation(hToken, TokenPrivileges, tp, privLen, &privLen)) {
        free(tp);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    // reset flags
    p->PrivSeDebug = FALSE;
    p->PrivSeImpersonate = FALSE;
    p->PrivSeAssignPrimaryToken = FALSE;
    p->PrivSeTcb = FALSE;
    p->PrivSeBackup = FALSE;
    p->PrivSeRestore = FALSE;
    p->PrivSeLoadDriver = FALSE;
    p->PrivSeTakeOwnership = FALSE;

    for (DWORD i = 0; i < tp->PrivilegeCount; i++) {

        if (!(tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
            continue;

        LUID luid = tp->Privileges[i].Luid;

        if (EqualLuid(luid, luidDebug))
            p->PrivSeDebug = TRUE;
        else if (EqualLuid(luid, luidImpersonate))
            p->PrivSeImpersonate = TRUE;
        else if (EqualLuid(luid, luidAssign))
            p->PrivSeAssignPrimaryToken = TRUE;
        else if (EqualLuid(luid, luidTcb))
            p->PrivSeTcb = TRUE;
        else if (EqualLuid(luid, luidBackup))
            p->PrivSeBackup = TRUE;
        else if (EqualLuid(luid, luidRestore))
            p->PrivSeRestore = TRUE;
        else if (EqualLuid(luid, luidLoadDriver))
            p->PrivSeLoadDriver = TRUE;
        else if (EqualLuid(luid, luidTakeOwnership))
            p->PrivSeTakeOwnership = TRUE;
    }

    free(tp);

    CloseHandle(hToken);
    CloseHandle(hProcess);

    return TRUE;
}

void ProcessSecCtxQueue()
{
    ULONGLONG now = GetTickCount64();

    for (int i = 0; i < MAX_SECCTX_QUEUE; i++) {

        if (!g_SecCtxQueue[i].InUse)
            continue;

        if (g_SecCtxQueue[i].RetryCount > 5) {
            g_SecCtxQueue[i].InUse = FALSE;
            continue;
        }

        if (now < g_SecCtxQueue[i].NextAttemptTick)
            continue;

        PROC_STATE* p = FindProcess(
            g_SecCtxQueue[i].ProcessId,
            g_SecCtxQueue[i].CreateTime
        );

        if (!p) {
            g_SecCtxQueue[i].InUse = FALSE;
            continue;
        }

        if (p->SecCtxReady) {
            g_SecCtxQueue[i].InUse = FALSE;
            continue;
        }

        if (TryPopulateSecCtx(p)) {

            p->SecCtxReady = TRUE;
            g_SecCtxQueue[i].InUse = FALSE;
        }
        else {
            g_SecCtxQueue[i].RetryCount++;
            g_SecCtxQueue[i].NextAttemptTick = now + 100;
        }
    }
}

PROC_STATE* FindProcess(HANDLE pid, ULONGLONG createTime) {
    for (int i = 0; i < MAX_TRACKED_PROCS; i++) {
        if (g_ProcTable[i].InUse &&
            g_ProcTable[i].ProcessId == pid &&
            g_ProcTable[i].CreateTime == createTime) {
            return &g_ProcTable[i];
        }
    }
    return NULL;
}

void EnqueueSecCtxWork(HANDLE pid, ULONGLONG createTime)
{
    PROC_STATE* p = FindProcess(pid, createTime);
    if (p && p->SecCtxReady)
        return;

    for (int i = 0; i < MAX_SECCTX_QUEUE; i++) {

        if (g_SecCtxQueue[i].InUse &&
            g_SecCtxQueue[i].ProcessId == pid &&
            g_SecCtxQueue[i].CreateTime == createTime) {
            return; // already queued
        }

        if (!g_SecCtxQueue[i].InUse) {
            g_SecCtxQueue[i].InUse = TRUE;
            g_SecCtxQueue[i].ProcessId = pid;
            g_SecCtxQueue[i].CreateTime = createTime;
            g_SecCtxQueue[i].RetryCount = 0;
            g_SecCtxQueue[i].NextAttemptTick = GetTickCount64();
            return;
        }
    }
}


// Deferred injection for suspended processes

DEFERRED_INJECT g_DeferredInject[MAX_DEFERRED_INJECT] = { 0 };

extern BOOL InjectDLL(DWORD pid, const wchar_t* dllPath);

BOOL IsProcessSuspended(DWORD pid)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return FALSE;

    THREADENTRY32 te = { 0 };
    te.dwSize = sizeof(te);
    BOOL suspended = FALSE;

    if (Thread32First(hSnap, &te))
    {
        do {
            if (te.th32OwnerProcessID != pid)
                continue;

            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (hThread)
            {
                DWORD count = SuspendThread(hThread);

                if (count == (DWORD)-1)
                {
                    // SuspendThread failed — can't determine state
                    CloseHandle(hThread);
                    continue;
                }

                // Undo our suspend immediately
                ResumeThread(hThread);
                CloseHandle(hThread);

                // count = previous suspend count BEFORE our suspend.
                // If >= 1, the thread was already suspended.
                if (count >= 1)
                {
                    suspended = TRUE;
                    break;
                }
            }
        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    return suspended;
}

void DeferredInjectAdd(DWORD pid, ULONGLONG createTime)
{
    // Check if already queued
    for (int i = 0; i < MAX_DEFERRED_INJECT; i++)
    {
        if (g_DeferredInject[i].InUse && g_DeferredInject[i].Pid == pid)
            return;
    }

    for (int i = 0; i < MAX_DEFERRED_INJECT; i++)
    {
        if (!g_DeferredInject[i].InUse)
        {
            g_DeferredInject[i].InUse = TRUE;
            g_DeferredInject[i].Pid = pid;
            g_DeferredInject[i].CreateTime = createTime;
            g_DeferredInject[i].QueuedTick = GetTickCount64();

            LogExtra(L"[INJECT DEFERRED] PID=%lu (suspended)\n", pid);
            return;
        }
    }

    LogExtra(L"[INJECT DEFERRED] Queue full, dropping PID=%lu\n", pid);
}

void DeferredInjectRemove(DWORD pid)
{
    for (int i = 0; i < MAX_DEFERRED_INJECT; i++)
    {
        if (g_DeferredInject[i].InUse && g_DeferredInject[i].Pid == pid)
        {
            g_DeferredInject[i].InUse = FALSE;
            g_DeferredInject[i].Pid = 0;
            g_DeferredInject[i].CreateTime = 0;
            g_DeferredInject[i].QueuedTick = 0;
            return;
        }
    }
}

void DeferredInjectTryResume(DWORD targetPid)
{
    for (int i = 0; i < MAX_DEFERRED_INJECT; i++)
    {
        if (!g_DeferredInject[i].InUse)
            continue;

        if (g_DeferredInject[i].Pid != targetPid)
            continue;

        // The process that was suspended is now being resumed.
        // Inject our hook DLL now.
        if (InjectDLL(targetPid, L"C:\\drivers\\EDRHookClean.dll"))
            LogExtra(L"[INJECT OK] PID=%lu (deferred, on resume)\n", targetPid);
        else
            LogExtra(L"[INJECT FAIL] PID=%lu (deferred, on resume)\n", targetPid);

        g_DeferredInject[i].InUse = FALSE;
        g_DeferredInject[i].Pid = 0;
        g_DeferredInject[i].CreateTime = 0;
        g_DeferredInject[i].QueuedTick = 0;
        return;
    }
}

void DeferredInjectCleanup()
{
    ULONGLONG now = GetTickCount64();

    for (int i = 0; i < MAX_DEFERRED_INJECT; i++)
    {
        if (!g_DeferredInject[i].InUse)
            continue;

        // Expire entries older than 60 seconds, process probably died
        // or was never resumed
        if ((now - g_DeferredInject[i].QueuedTick) > 60000)
        {
            LogExtra(L"[INJECT DEFERRED] Expired PID=%lu (60s timeout)\n",
                g_DeferredInject[i].Pid);

            g_DeferredInject[i].InUse = FALSE;
            g_DeferredInject[i].Pid = 0;
            g_DeferredInject[i].CreateTime = 0;
            g_DeferredInject[i].QueuedTick = 0;
        }
    }
}
