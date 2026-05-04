#define _CRT_SECURE_NO_WARNINGS

#include "output.h"
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "shared.h"
#include "device.h"
#include "edrclient.h"
#include "detections.h"
#include "parser.h"
#include <map>
#include <string>

DWORD ResolveHandleToPid(HANDLE h)
{
    if (!h || h == INVALID_HANDLE_VALUE)
        return 0;

    DWORD pid = GetProcessId(h);
    return pid;
}

extern std::map<DWORD, std::wstring> g_PidToName;

BOOL InjectDLL(DWORD pid, const wchar_t* dllPath);

void DecodeProtection(ULONG protect, WCHAR* out, size_t outCount);
void DecodeMemType(ULONG type, WCHAR* out, size_t outCount);

static WCHAR g_TimeBuf[32];
static WCHAR g_LineBuf[1024];
static WCHAR g_AccessBuf[128];
static WCHAR g_ProtBuf[128];

static void ResolvePidName(ULONG pid, WCHAR* out, size_t outCount)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h)
    {
        DWORD size = (DWORD)outCount;
        if (QueryFullProcessImageNameW(h, 0, out, &size))
        {
            CloseHandle(h);
            return;
        }
        CloseHandle(h);
    }

    wcscpy_s(out, outCount, L"unknown");
}

static FILE* g_LogFile = NULL;

void InitLogFile()
{
    if (!g_LogFile)
    {
        g_LogFile = _wfopen(L"C:\\drivers\\edr_log.txt", L"w");
        if (g_LogFile)
            setvbuf(g_LogFile, NULL, _IONBF, 0); // unbuffered,  flush every write
    }
}

void PrintLine(const WCHAR* line)
{
    wprintf(L"%ws\n", line);

    if (g_LogFile)
    {
        fwprintf(g_LogFile, L"%ws\n", line);
    }
}

// Log arbitrary format strings (for wprintf calls outside PrintLine)
void LogExtra(const WCHAR* fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    vwprintf(fmt, args);
    va_end(args);

    if (g_LogFile)
    {
        va_start(args, fmt);
        vfwprintf(g_LogFile, fmt, args);
        va_end(args);
    }
}

static void FormatTimestamp(LARGE_INTEGER ts, WCHAR* out, size_t outCount)
{
    FILETIME ftUtc, ftLocal;
    SYSTEMTIME stLocal;

    ftUtc.dwLowDateTime = ts.LowPart;
    ftUtc.dwHighDateTime = ts.HighPart;

    FileTimeToLocalFileTime(&ftUtc, &ftLocal);
    FileTimeToSystemTime(&ftLocal, &stLocal);

    swprintf_s(
        out,
        outCount,
        L"%02u:%02u:%02u.%03u",
        stLocal.wHour,
        stLocal.wMinute,
        stLocal.wSecond,
        stLocal.wMilliseconds
    );
}

static void DecodeAccessMask(DWORD access, WCHAR* out, size_t outCount)
{
    out[0] = L'\0';

    if (access & PROCESS_VM_WRITE)
        wcscat_s(out, outCount, L"VM_WRITE|");

    if (access & PROCESS_VM_OPERATION)
        wcscat_s(out, outCount, L"VM_OPERATION|");

    if (access & PROCESS_CREATE_THREAD)
        wcscat_s(out, outCount, L"CREATE_THREAD|");

    if (out[0] == L'\0') {
        wcscpy_s(out, outCount, L"0");
        return;
    }

    size_t len = wcslen(out);
    if (len > 0 && out[len - 1] == L'|')
        out[len - 1] = L'\0';
}

static const WCHAR* DecodeMemType(ULONG type)
{
    switch (type) {
    case 0x01000000: return L"MEM_IMAGE";
    case 0x00020000: return L"MEM_PRIVATE";
    case 0x00040000: return L"MEM_MAPPED";
    default: return L"UNKNOWN";
    }
}

static void DecodeProtection(ULONG protect, WCHAR* out, size_t outCount)
{
    out[0] = L'\0';

    switch (protect & 0xFF) {
    case 0x01: wcscpy_s(out, outCount, L"NOACCESS"); break;
    case 0x02: wcscpy_s(out, outCount, L"R"); break;
    case 0x04: wcscpy_s(out, outCount, L"RW"); break;
    case 0x08: wcscpy_s(out, outCount, L"WCOPY"); break;
    case 0x10: wcscpy_s(out, outCount, L"X"); break;
    case 0x20: wcscpy_s(out, outCount, L"RX"); break;
    case 0x40: wcscpy_s(out, outCount, L"RWX"); break;
    case 0x80: wcscpy_s(out, outCount, L"XWCOPY"); break;
    default: wcscpy_s(out, outCount, L"?"); break;
    }

    if (protect & 0x100) wcscat_s(out, outCount, L"|GUARD");
    if (protect & 0x200) wcscat_s(out, outCount, L"|NOCACHE");
    if (protect & 0x400) wcscat_s(out, outCount, L"|WRITECOMBINE");
}

static const WCHAR* SafeStr(const WCHAR* s)
{
    return (s && s[0]) ? s : L"(null)";
}

static const WCHAR* NormalizeNtPathClient(const WCHAR* path)
{
    if (!path || !path[0])
        return L"(null)";

    if (wcsncmp(path, L"\\??\\", 4) == 0)
        return path + 4;

    return path;
}

static const WCHAR* GetFileNameOnly(const WCHAR* path)
{
    const WCHAR* norm = NormalizeNtPathClient(path);
    if (!norm || !norm[0])
        return L"(null)";

    const WCHAR* slash = wcsrchr(norm, L'\\');
    return slash ? (slash + 1) : norm;
}

void HandleEvent(EDR_EVENT* evt)
{
    EnrichThreadMemory(evt);
    FormatTimestamp(evt->Timestamp, g_TimeBuf, _countof(g_TimeBuf));

    switch (evt->EventType)
    {
    case EDR_EVENT_PROCESS_CREATE:
    {
        // If kernel didn't provide an ImagePath, resolve it from userland
        static WCHAR s_ResolvedPath[260];

        if (!evt->ImagePath || !evt->ImagePath[0])
        {
            DWORD rpid = (DWORD)(ULONG_PTR)evt->ProcessId;
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, rpid);
            if (hProc)
            {
                DWORD sz = _countof(s_ResolvedPath);
                if (QueryFullProcessImageNameW(hProc, 0, s_ResolvedPath, &sz))
                {
                    wcscpy_s(evt->ImagePath, _countof(evt->ImagePath), s_ResolvedPath);
                }
                CloseHandle(hProc);
            }

            // If still empty after resolution, skip
            if (!evt->ImagePath[0])
            {
                LogExtra(L"[WARN] PROC_CREATE pid=%lu — ImagePath empty even after resolution, skipping\n",
                    (ULONG)(ULONG_PTR)evt->ProcessId);
                break;
            }
        }

        TrackProcessCreate(evt);

        PROC_STATE* p = FindProcess(
            evt->ProcessId,
            evt->ProcessCreateTime.QuadPart
        );

        const WCHAR* il = (p && p->SecCtxReady) ? p->Integrity : L"?";
        const WCHAR* elev = (p && p->SecCtxReady) ? p->ElevationType : L"?";
        const WCHAR* tok = (p && p->SecCtxReady) ? p->TokenType : L"?";

        int dbg = (p && p->SecCtxReady) ? p->PrivSeDebug : 0;
        int imp = (p && p->SecCtxReady) ? p->PrivSeImpersonate : 0;
        int tcb = (p && p->SecCtxReady) ? p->PrivSeTcb : 0;
        int assign = (p && p->SecCtxReady) ? p->PrivSeAssignPrimaryToken : 0;
        int loaddrv = (p && p->SecCtxReady) ? p->PrivSeLoadDriver : 0;
        int backup = (p && p->SecCtxReady) ? p->PrivSeBackup : 0;
        int restore = (p && p->SecCtxReady) ? p->PrivSeRestore : 0;

        swprintf_s(
            g_LineBuf,
            _countof(g_LineBuf),
            L"[%ws] PROC_CREATE | img=%ws pid=%lu pimg=%ws ppid=%lu il=%ws elev=%ws tok=%ws dbg=%d imp=%d tcb=%d assign=%d loaddrv=%d backup=%d restore=%d cmd=%ws",
            g_TimeBuf,
            GetFileNameOnly(SafeStr(evt->ImagePath)),
            (ULONG)(ULONG_PTR)evt->ProcessId,
            GetFileNameOnly(SafeStr(evt->ParentImagePath)),
            (ULONG)(ULONG_PTR)evt->ParentProcessId,
            il,
            elev,
            tok,
            dbg,
            imp,
            tcb,
            assign,
            loaddrv,
            backup,
            restore,
            SafeStr(NormalizeNtPathClient(evt->CommandLine))
        );

        PrintLine(g_LineBuf);

        DWORD pid = (DWORD)(ULONG_PTR)evt->ProcessId;

        g_PidToName[pid] = evt->ImagePath;

        const wchar_t* img = wcsrchr(evt->ImagePath, L'\\');
        img = img ? img + 1 : evt->ImagePath;

        if (!img)
            break;

        // PID 0 (System Idle) and PID 4 (System) are kernel-only
        if (pid <= 4)
            break;

        if (_wcsicmp(img, L"System") == 0) break;
        if (_wcsicmp(img, L"smss.exe") == 0) break;
        if (_wcsicmp(img, L"csrss.exe") == 0) break;
        if (_wcsicmp(img, L"wininit.exe") == 0) break;
        if (_wcsicmp(img, L"winlogon.exe") == 0) break;
        if (_wcsicmp(img, L"lsass.exe") == 0) break;
        if (_wcsicmp(img, L"services.exe") == 0) break;
        if (_wcsicmp(img, L"explorer.exe") == 0) break;
        if (_wcsicmp(img, L"OSRLOADER.exe") == 0) break;
        if (_wcsicmp(img, L"EDRClient.exe") == 0) break;
        if (_wcsicmp(img, L"Dbgview.exe") == 0) break;

        if (IsProcessSuspended(pid))
        {
            DeferredInjectAdd(pid, evt->ProcessCreateTime.QuadPart);
        }
        else
        {
            if (InjectDLL(pid, L"C:\\drivers\\EDRHookClean.dll"))
                LogExtra(L"[INJECT OK] PID=%lu\n", pid);
            else
                LogExtra(L"[INJECT FAIL] PID=%lu\n", pid);
        }

        break;
    }

    case EDR_EVENT_PROCESS_TERMINATE:
    {
        TrackProcessExit(evt);

        // Remove from deferred inject queue if present
        DeferredInjectRemove((DWORD)(ULONG_PTR)evt->ProcessId);

        swprintf_s(
            g_LineBuf,
            _countof(g_LineBuf),
            L"[%ws] PROC_EXIT | pid=%lu",
            g_TimeBuf,
            (ULONG)(ULONG_PTR)evt->ProcessId
        );

        PrintLine(g_LineBuf);
        break;
    }

    case EDR_EVENT_HANDLE_OPEN:

    {
        DetectionHandleEvent(evt);

        if (IsSensorProcess(evt->SourceProcessId, evt->SourceProcessCreateTime))
            break;

        if (evt->SourceProcessId == evt->TargetProcessId)
            break;

        if (evt->DesiredAccess == 0)
            break;

        if (!evt->SourceProcessId || !evt->TargetProcessId)
            break;

        TrackHandleEvent(evt);

        DecodeAccessMask(evt->DesiredAccess, g_AccessBuf, _countof(g_AccessBuf));

        PROC_STATE* src = FindProcess(
            evt->SourceProcessId,
            evt->SourceProcessCreateTime.QuadPart
        );

        PROC_STATE* tgt = FindProcess(
            evt->TargetProcessId,
            evt->TargetProcessCreateTime.QuadPart
        );

        const WCHAR* srcName = src ? GetFileNameOnly(SafeStr(src->ImagePath)) : L"unknown";
        const WCHAR* tgtName = tgt ? GetFileNameOnly(SafeStr(tgt->ImagePath)) : L"unknown";
        const WCHAR* htype =
            (evt->DesiredAccess & PROCESS_VM_WRITE) ? L"write" :
            (evt->DesiredAccess & PROCESS_CREATE_THREAD) ? L"thread" :
            (evt->DesiredAccess & PROCESS_VM_OPERATION) ? L"vmop" :
            L"other";

        WCHAR srcNameBuf[MAX_PATH];
        WCHAR tgtNameBuf[MAX_PATH];

        wcscpy_s(srcNameBuf, _countof(srcNameBuf), srcName);
        wcscpy_s(tgtNameBuf, _countof(tgtNameBuf), tgtName);

        if (wcscmp(srcNameBuf, L"unknown") == 0)
        {
            ResolvePidName((ULONG)(ULONG_PTR)evt->SourceProcessId, srcNameBuf, _countof(srcNameBuf));
        }

        if (wcscmp(tgtNameBuf, L"unknown") == 0)
        {
            ResolvePidName((ULONG)(ULONG_PTR)evt->TargetProcessId, tgtNameBuf, _countof(tgtNameBuf));
        }
        swprintf_s(
            g_LineBuf,
            _countof(g_LineBuf),
            L"[%ws] HANDLE_OPEN | src=%ws spid=%lu tgt=%ws tpid=%lu access=%ws raw=0x%08X type=%ws",
            g_TimeBuf,
            srcNameBuf,
            (ULONG)(ULONG_PTR)evt->SourceProcessId,
            tgtNameBuf,
            (ULONG)(ULONG_PTR)evt->TargetProcessId,
            g_AccessBuf,
            evt->DesiredAccess,
            htype
        );

        PrintLine(g_LineBuf);
        break;
    }

    case EDR_EVENT_THREAD_CREATE:
    {

        if (!evt->ThreadStartAddress)
            break;

        DecodeProtection(evt->ThreadStartProtection, g_ProtBuf, _countof(g_ProtBuf));

        PROC_STATE* tgt = FindProcess(
            evt->TargetProcessId,
            evt->TargetProcessCreateTime.QuadPart
        );

        const WCHAR* tgtName = tgt ? GetFileNameOnly(SafeStr(tgt->ImagePath)) : L"unknown";

        swprintf_s(
            g_LineBuf,
            _countof(g_LineBuf),
            L"[%ws] THREAD_CREATE | img=%ws pid=%lu tid=%lu start=%p base=%p size=%llu type=%ws prot=%ws",
            g_TimeBuf,
            tgtName,
            (ULONG)(ULONG_PTR)evt->TargetProcessId,
            (ULONG)(ULONG_PTR)evt->ThreadId,
            evt->ThreadStartAddress,
            evt->ThreadStartBaseAddress,
            evt->ThreadStartRegionSize,
            DecodeMemType(evt->ThreadStartType),
            g_ProtBuf
        );

        PrintLine(g_LineBuf);
        break;
    }

    case EDR_EVENT_WRITE_MEMORY:
    {
        if (IsSensorProcess(evt->SourceProcessId, evt->SourceProcessCreateTime))
            break;

        DetectionWriteEvent(evt);
        ULONG src = (ULONG)(ULONG_PTR)evt->SourceProcessId;
        ULONG dst = (ULONG)(ULONG_PTR)evt->TargetProcessId;

        auto srcIt = g_PidToName.find(src);
        auto dstIt = g_PidToName.find(dst);

        const wchar_t* rawSrc = (srcIt != g_PidToName.end()) ? srcIt->second.c_str() : L"unknown";
        const wchar_t* rawDst = (dstIt != g_PidToName.end()) ? dstIt->second.c_str() : L"unknown";

        const wchar_t* srcName = wcsrchr(rawSrc, L'\\');
        srcName = srcName ? srcName + 1 : rawSrc;

        const wchar_t* dstName = wcsrchr(rawDst, L'\\');
        dstName = dstName ? dstName + 1 : rawDst;

        swprintf_s(
            g_LineBuf,
            _countof(g_LineBuf),
            L"[%ws] WRITE | src=%ws spid=%lu dst=%ws dpid=%lu addr=%p size=%llu",
            g_TimeBuf,
            srcName,
            src,
            dstName,
            dst,
            evt->WriteAddress,
            (unsigned long long)evt->WriteSize
        );

        PrintLine(g_LineBuf);
        break;
    }

    case EDR_EVENT_PROTECT_MEMORY:
    {
        if (IsSensorProcess(evt->SourceProcessId, evt->SourceProcessCreateTime))
            break;

        ULONG src = (ULONG)(ULONG_PTR)evt->SourceProcessId;
        ULONG dst = (ULONG)(ULONG_PTR)evt->TargetProcessId;

        if (!src || !dst)
            break;

        DetectionProtectEvent(evt);

        WCHAR oldProt[64];
        WCHAR newProt[64];

        DecodeProtection(evt->OldProtect, oldProt, _countof(oldProt));
        DecodeProtection(evt->NewProtect, newProt, _countof(newProt));

        swprintf_s(
            g_LineBuf,
            _countof(g_LineBuf),
            L"[%ws] PROTECT | src=%lu dst=%lu addr=%p size=%llu %ws -> %ws",
            g_TimeBuf,
            src,
            dst,
            evt->ProtectAddress,
            (unsigned long long)evt->ProtectSize,
            oldProt,
            newProt
        );

        PrintLine(g_LineBuf);
        break;
    }

    case EDR_EVENT_RESUME_THREAD:
    {
        DetectionResumeEvent(evt);

        // If this process was deferred (created suspended), inject now
        DWORD resumedPid = (DWORD)(ULONG_PTR)evt->TargetProcessId;
        DeferredInjectTryResume(resumedPid);

        swprintf_s(
            g_LineBuf,
            _countof(g_LineBuf),
            L"[%ws] RESUME_THREAD | pid=%lu tid=%lu",
            g_TimeBuf,
            (ULONG)(ULONG_PTR)evt->TargetProcessId,
            (ULONG)(ULONG_PTR)evt->ThreadId
        );

        PrintLine(g_LineBuf);
        break;
    }
    }
}

void EnrichThreadMemory(EDR_EVENT* evt)
{

    if (evt->EventType != EDR_EVENT_THREAD_CREATE)
        return;

    // Always try to infer source PID from recent handle events, works even if target process is dead
    ULONG inferredSrc = FindRecentHandleSourcePid(
        (ULONG)(ULONG_PTR)evt->TargetProcessId,
        evt->Timestamp.QuadPart
    );

    // Resolve source create time via kernel IOCTL, same authoritative path
    // (PsLookupProcessByProcessId + PsGetProcessCreateTimeQuadPart) used in
    // callbacks.c.
    if (inferredSrc != 0)
    {
        LARGE_INTEGER ct = { 0 };
        if (DeviceResolveCreateTime(inferredSrc, &ct))
        {
            evt->SourceProcessCreateTime.QuadPart = ct.QuadPart;
        }
    }

    LogExtra(L"[ENRICH_DEBUG] pid=%lu inferredSrc=%lu type=%lu prot=%lu\n",
        (ULONG)(ULONG_PTR)evt->TargetProcessId,
        inferredSrc,
        evt->ThreadStartType,
        evt->ThreadStartProtection
    );

    if ((DWORD)inferredSrc == g_SensorPid)
        return;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        (DWORD)(ULONG_PTR)evt->TargetProcessId
    );

    if (!hProcess)
    {
        // Process is already dead (crashed after hollowing).
        // Use kernel-provided memory info to run detection anyway.
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        mbi.BaseAddress = evt->ThreadStartBaseAddress;
        mbi.RegionSize = evt->ThreadStartRegionSize;
        mbi.Type = evt->ThreadStartType;
        mbi.Protect = evt->ThreadStartProtection;

        DetectionThreadEvent(evt, inferredSrc, &mbi);
        return;
    }

    MEMORY_BASIC_INFORMATION mbi = { 0 };

    if (VirtualQueryEx(
        hProcess,
        evt->ThreadStartAddress,
        &mbi,
        sizeof(mbi)
    ) == sizeof(mbi))
    {
        evt->ThreadStartBaseAddress = mbi.BaseAddress;
        evt->ThreadStartRegionSize = mbi.RegionSize;
        evt->ThreadStartType = mbi.Type;
        evt->ThreadStartProtection = mbi.Protect;

        DetectionThreadEvent(evt, inferredSrc, &mbi);

        WCHAR protect[64] = L"";
        WCHAR type[64] = L"";

        DecodeProtection(mbi.Protect, protect, _countof(protect));
        DecodeMemType(mbi.Type, type, _countof(type));

        BOOL isPrivateExec =
            (mbi.Type == MEM_PRIVATE) &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));

        BOOL isImageExec =
            (mbi.Type == MEM_IMAGE) &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ));

        ULONG dstPid = (ULONG)(ULONG_PTR)evt->TargetProcessId;

        BOOL isRemoteThread =
            (inferredSrc != 0) &&
            (inferredSrc != dstPid);

        if (isPrivateExec)
        {
            LogExtra(L"[MEM][PRIVATE_EXEC] SRC=%lu DST=%lu START=%p BASE=%p SIZE=%llu TYPE=%ws PROTECT=%ws\n",
                inferredSrc,
                dstPid,
                evt->ThreadStartAddress,
                mbi.BaseAddress,
                (unsigned long long)mbi.RegionSize,
                type,
                protect
            );
        }
        else if (isImageExec)
        {
            LogExtra(L"[MEM][IMAGE_EXEC] SRC=%lu DST=%lu START=%p BASE=%p SIZE=%llu TYPE=%ws PROTECT=%ws\n",
                inferredSrc,
                dstPid,
                evt->ThreadStartAddress,
                mbi.BaseAddress,
                (unsigned long long)mbi.RegionSize,
                type,
                protect
            );
        }
        else
        {
            LogExtra(L"[MEM][OTHER] SRC=%lu DST=%lu START=%p BASE=%p SIZE=%llu TYPE=%ws PROTECT=%ws\n",
                inferredSrc,
                dstPid,
                evt->ThreadStartAddress,
                mbi.BaseAddress,
                (unsigned long long)mbi.RegionSize,
                type,
                protect
            );
        }
    }
    CloseHandle(hProcess);
}

void DecodeMemType(ULONG type, WCHAR* out, size_t outCount)
{
    if (type == MEM_IMAGE)
        wcscpy_s(out, outCount, L"MEM_IMAGE");
    else if (type == MEM_MAPPED)
        wcscpy_s(out, outCount, L"MEM_MAPPED");
    else if (type == MEM_PRIVATE)
        wcscpy_s(out, outCount, L"MEM_PRIVATE");
    else
        wcscpy_s(out, outCount, L"UNKNOWN");
}