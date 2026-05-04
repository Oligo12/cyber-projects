#include "detections.h"
#include "edrclient.h"
#include "output.h"
#include <windows.h>
#include <stdio.h>
#include "parser.h"
#include <map>
#include <string>

// For Authenticode signature verification (IsTrustedSystemSource).
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#pragma comment(lib, "wintrust.lib")

extern std::map<DWORD, std::wstring> g_PidToName;

#define TIME_WINDOW_5S  (5ULL * 1000 * 1000 * 10)
#define TIME_WINDOW_30S (30ULL * 1000 * 1000 * 10)

// ============================================================
// Trust subsystem
// ============================================================
// Layered check used to suppress alerts/SUSPICIOUS lines on chains
// where the source process is a signed Microsoft binary in a trusted
// system directory and is not on the LOLBin denylist.
//
// Layers (fail-closed at every step):
//   1. Path normalization to DOS form (handles \??\, \Device\HarddiskVolumeN\)
//   2. Path prefix must be under a trusted system directory
//   3. Filename must NOT be a known shell / script-host / LOLBin
//   4. Authenticode signature must verify (WinVerifyTrust)
//
// Invocation is lazy and behavior-gated: this fires only when a chain
// reaches a SUSPICIOUS or ALERT decision point, never in the per-event
// hot path. Cached per-image (g_TrustCache) and per-chain (sourceTrust
// field on INJECT_STATE) so each unique binary verifies at most once.
// ============================================================

#define TRUST_UNCHECKED 0
#define TRUST_TRUSTED   1
#define TRUST_UNTRUSTED 2

// Path-level cache: full DOS path -> TRUE/FALSE (signature verified)
static std::map<std::wstring, BOOL> g_TrustCache;

// Translate an arbitrary path string (NT or DOS) into a canonical DOS path.
// Returns FALSE if the path can't be normalized (caller treats as untrusted).
static BOOL ToDosPath(const wchar_t* in, wchar_t* out, size_t outCount)
{
    if (!in || !in[0] || outCount < 4)
        return FALSE;

    // Already a DOS path: "X:\..."
    if (in[1] == L':' && in[2] == L'\\')
    {
        return wcscpy_s(out, outCount, in) == 0;
    }

    // \??\ prefix (NT user-mode form): strip it
    if (wcsncmp(in, L"\\??\\", 4) == 0)
    {
        return wcscpy_s(out, outCount, in + 4) == 0;
    }

    // \Device\HarddiskVolumeN\... translate using the DOS device map.
    // Iterate drive letters, ask the OS what device each maps to,
    // then prefix-match the input against any matching device path.
    if (_wcsnicmp(in, L"\\Device\\", 8) == 0)
    {
        for (wchar_t drive = L'A'; drive <= L'Z'; drive++)
        {
            wchar_t letterPath[3] = { drive, L':', L'\0' };
            wchar_t devicePath[MAX_PATH];

            if (QueryDosDeviceW(letterPath, devicePath, _countof(devicePath)) == 0)
                continue;

            size_t devLen = wcslen(devicePath);
            if (devLen == 0 || devLen >= wcslen(in))
                continue;

            if (_wcsnicmp(in, devicePath, devLen) == 0 && in[devLen] == L'\\')
            {
                int written = swprintf_s(out, outCount, L"%c:%ws", drive, in + devLen);
                return (written > 0);
            }
        }
        return FALSE;
    }

    // Unknown format — fail closed.
    return FALSE;
}

// Path prefix must be one of the trusted system directories.
// Prefix match is case-insensitive and requires a trailing backslash so
// "C:\Windows\System32_evil\" wouldn't match "C:\Windows\System32".
static BOOL IsInTrustedSystemDir(const wchar_t* dosPath)
{
    if (!dosPath || !dosPath[0])
        return FALSE;

    static const wchar_t* trustedDirs[] = {
        L"C:\\Windows\\System32\\",
        L"C:\\Windows\\SysWOW64\\",
        L"C:\\Windows\\WinSxS\\",
        L"C:\\Program Files\\",
        L"C:\\Program Files (x86)\\",
    };

    for (const wchar_t* dir : trustedDirs)
    {
        size_t dirLen = wcslen(dir);
        if (_wcsnicmp(dosPath, dir, dirLen) == 0)
            return TRUE;
    }

    return FALSE;
}

// LOLBin / shell / script-host denylist — even signed Microsoft binaries
// in System32 don't get a trust pass if they're on this list, because they
// are commonly abused for living-off-the-land execution.
static BOOL IsLolBin(const wchar_t* fileName)
{
    if (!fileName || !fileName[0])
        return FALSE;

    static const wchar_t* lolbins[] = {
        L"cmd.exe",
        L"powershell.exe",
        L"powershell_ise.exe",
        L"pwsh.exe",
        L"wscript.exe",
        L"cscript.exe",
        L"mshta.exe",
        L"regsvr32.exe",
        L"rundll32.exe",
    };

    for (const wchar_t* bin : lolbins)
    {
        if (_wcsicmp(fileName, bin) == 0)
            return TRUE;
    }

    return FALSE;
}

// Verifies an embedded Authenticode signature. Used as the fast-path
// signature check; covers binaries with signatures embedded in the PE
// certificate table (chrome.exe, taskhostw.exe, third-party signed apps).
static BOOL VerifyEmbeddedSignature(const wchar_t* dosPath)
{
    if (!dosPath || !dosPath[0])
        return FALSE;

    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = dosPath;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wd = { 0 };
    wd.cbStruct = sizeof(WINTRUST_DATA);
    wd.dwUIChoice = WTD_UI_NONE;
    // WTD_REVOKE_NONE: skip CRL/OCSP. Faster, works offline. Tradeoff:
    // Won't catch revoked certs, but for cached/path-stable trust
    // decisions on system binaries that's acceptable.
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fileInfo;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_SAFER_FLAG;

    LONG status = WinVerifyTrust(NULL, &policyGuid, &wd);

    // Always release the trust state.
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGuid, &wd);

    return (status == ERROR_SUCCESS);
}

// Verifies a catalog-based signature against a specific hash algorithm.
// Many Microsoft system binaries (e.g., MusNotification.exe, ntdll.dll)
// have NO embedded Authenticode signature, their signatures live in
// security catalog files under C:\Windows\System32\CatRoot\.
//
// Catalog member entries can be hashed with either SHA-1 (legacy) or
// SHA-256 (modern); a single binary may appear in only one. The caller
// (VerifyCatalogSignature) tries both algos.
//
// Verification flow:
//   1. Hash the file contents with hashAlgo
//   2. Find a catalog containing that hash
//   3. WinVerifyTrust with WTD_CHOICE_CATALOG
static BOOL VerifyCatalogSignatureWithAlgo(const wchar_t* dosPath, const wchar_t* hashAlgo)
{
    if (!dosPath || !dosPath[0] || !hashAlgo)
        return FALSE;

    // ALL variables that have an initializer are declared up-front because
    // C++ forbids `goto` from skipping over a variable's initialization,
    // even if the cleanup label never references the variable.
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HCATADMIN hCatAdmin = NULL;
    HCATINFO hCatInfo = NULL;
    BYTE* hash = NULL;
    DWORD hashLen = 0;
    BOOL result = FALSE;
    CATALOG_INFO ci = { 0 };
    wchar_t memberTag[2 * 64 + 1] = { 0 };  // SHA-512 worst case = 128 hex chars + null
    WINTRUST_CATALOG_INFO wtc = { 0 };
    WINTRUST_DATA wd = { 0 };
    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = ERROR_INVALID_FUNCTION;  // sentinel; overwritten on the success path

    ci.cbStruct = sizeof(CATALOG_INFO);

    // Open the file for hashing. Liberal sharing flags to avoid
    // contention with the loader/AV/etc. that may be reading concurrently.
    hFile = CreateFileW(
        dosPath,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto cleanup;

    if (!CryptCATAdminAcquireContext2(&hCatAdmin, NULL, hashAlgo, NULL, 0))
        goto cleanup;

    // Two-step hash compute: first call returns required size, second
    // call fills the buffer. The size-query call may return FALSE
    // (ERROR_INSUFFICIENT_BUFFER); that's expected — only hashLen
    // being populated matters.
    CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashLen, NULL, 0);
    if (hashLen == 0) goto cleanup;

    hash = (BYTE*)malloc(hashLen);
    if (!hash) goto cleanup;

    // Reset file position before the actual hash compute — the size-query
    // call may have advanced it.
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

    if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashLen, hash, 0))
        goto cleanup;

    // Find a catalog containing this file's hash. NULL return = no catalog
    // has this hash; usually means the wrong hash algorithm.
    hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashLen, 0, NULL);
    if (!hCatInfo) goto cleanup;

    if (!CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0))
        goto cleanup;

    // Build hex member tag from hash bytes (uppercase, contiguous).
    for (DWORD i = 0; i < hashLen && (i * 2 + 2) < _countof(memberTag); i++)
    {
        swprintf_s(&memberTag[i * 2], 3, L"%02X", hash[i]);
    }

    wtc.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
    wtc.pcwszCatalogFilePath = ci.wszCatalogFile;
    wtc.pcwszMemberTag = memberTag;
    wtc.pcwszMemberFilePath = dosPath;
    wtc.pbCalculatedFileHash = hash;
    wtc.cbCalculatedFileHash = hashLen;

    wd.cbStruct = sizeof(WINTRUST_DATA);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_CATALOG;
    wd.pCatalog = &wtc;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_SAFER_FLAG;

    status = WinVerifyTrust(NULL, &policyGuid, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGuid, &wd);

    if (status != ERROR_SUCCESS) goto cleanup;

    result = TRUE;

cleanup:
    if (hCatInfo && hCatAdmin)
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    if (hash)
        free(hash);
    if (hCatAdmin)
        CryptCATAdminReleaseContext(hCatAdmin, 0);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    return result;
}

// Top-level catalog signature verification. Tries SHA-256 first (modern
// catalogs) then falls back to SHA-1 (legacy catalogs). Many Windows
// system binaries — especially ones with long heritage — only appear
// in SHA-1 catalogs, so the fallback is essential for coverage.
static BOOL VerifyCatalogSignature(const wchar_t* dosPath)
{
    if (VerifyCatalogSignatureWithAlgo(dosPath, L"SHA256"))
        return TRUE;
    return VerifyCatalogSignatureWithAlgo(dosPath, L"SHA1");
}

// Signature verification dispatcher. Tries embedded first (fast), then
// falls back to catalog (covers most Windows system binaries).
//
// Return values: SIG_NONE (not signed / verification failed),
// SIG_EMBEDDED (passed via embedded sig), SIG_CATALOG (passed via catalog).
#define SIG_NONE     0
#define SIG_EMBEDDED 1
#define SIG_CATALOG  2

static int VerifyAuthenticodeSignature(const wchar_t* dosPath)
{
    if (VerifyEmbeddedSignature(dosPath))
        return SIG_EMBEDDED;
    if (VerifyCatalogSignature(dosPath))
        return SIG_CATALOG;
    return SIG_NONE;
}

// Main trust check. Returns TRUE if the source process is a signed system
// binary in a trusted directory and not on the LOLBin denylist.
//
// Caches the verification result by full DOS path so WinVerifyTrust runs
// at most once per unique image.
static BOOL IsTrustedSystemSource(HANDLE pid, ULONGLONG createTime)
{
    PROC_STATE* p = FindProcess(pid, createTime);
    if (!p || !p->ImagePath[0])
        return FALSE;

    wchar_t dosPath[280];
    if (!ToDosPath(p->ImagePath, dosPath, _countof(dosPath)))
        return FALSE;

    // Cache hit?
    auto it = g_TrustCache.find(dosPath);
    if (it != g_TrustCache.end())
        return it->second;

    BOOL trusted = FALSE;

    // Layer 1: must be in a trusted directory.
    if (IsInTrustedSystemDir(dosPath))
    {
        // Layer 2: filename must not be a LOLBin.
        const wchar_t* fileName = wcsrchr(dosPath, L'\\');
        fileName = fileName ? fileName + 1 : dosPath;

        if (!IsLolBin(fileName))
        {
            // Layer 3: signature must verify (embedded OR catalog).
            trusted = (VerifyAuthenticodeSignature(dosPath) != SIG_NONE);
        }
    }

    g_TrustCache[std::wstring(dosPath)] = trusted;
    return trusted;
}

// ============================================================
// End trust subsystem
// ============================================================

// Source processes that do legitimate parent-child write+resume patterns.
// These are system orchestrators, not injectors. This is a fast filter
// run at the top of every detection handler, so it intentionally does NOT
// run signature verification — that's the job of IsTrustedSystemSource at
// SUSPICIOUS/ALERT decision points.
//
// Both name AND path-in-trusted-dir must match. Path requirement closes
// the rename-bypass hole where a `C:\Users\Public\svchost.exe` would have
// been substring-matched as legitimate svchost.
static BOOL IsWhitelistedSource(HANDLE pid, ULONGLONG createTime)
{
    PROC_STATE* p = FindProcess(pid, createTime);
    if (!p || !p->ImagePath[0])
        return FALSE;

    wchar_t dosPath[280];
    if (!ToDosPath(p->ImagePath, dosPath, _countof(dosPath)))
        return FALSE;

    if (!IsInTrustedSystemDir(dosPath))
        return FALSE;

    const wchar_t* name = wcsrchr(dosPath, L'\\');
    name = name ? name + 1 : dosPath;

    if (_wcsicmp(name, L"svchost.exe") == 0 ||
        _wcsicmp(name, L"services.exe") == 0 ||
        _wcsicmp(name, L"explorer.exe") == 0 ||
        _wcsicmp(name, L"msedge.exe") == 0 ||
        _wcsicmp(name, L"chrome.exe") == 0 ||
        _wcsicmp(name, L"CompatTelRunner.exe") == 0 ||
        _wcsicmp(name, L"WerFault.exe") == 0 ||
        _wcsicmp(name, L"RuntimeBroker.exe") == 0 ||
        _wcsicmp(name, L"SearchHost.exe") == 0 ||
        _wcsicmp(name, L"smartscreen.exe") == 0)
    {
        return TRUE;
    }

    return FALSE;
}

typedef struct _INJECT_STATE {
    ULONG srcPid;
    ULONG dstPid;

    ULONGLONG srcCreateTime;
    ULONGLONG dstCreateTime;

    BOOL sawHandle;
    BOOL sawWrite;
    BOOL sawThread;
    BOOL sawProtect;
    BOOL sawResume;

    // Set the first time a [SUSPICIOUS] line is emitted for this chain, so the
    // line fires once per (src, dst) lifetime rather than once per primitive
    // event after the score crosses 60. Reset implicitly via ZeroMemory in
    // CleanupStaleInjectStates and the score<=0 branches.
    BOOL loggedSuspicious;

    // Per-chain trust cache. Set lazily on the first SUSPICIOUS or ALERT
    // decision point reached by this chain, then reused for the chain's
    // lifetime. Values: TRUST_UNCHECKED / TRUST_TRUSTED / TRUST_UNTRUSTED.
    // Reset implicitly via ZeroMemory.
    BYTE sourceTrust;

    PVOID writeAddr;
    SIZE_T writeSize;
    ULONGLONG lastWriteTime;

    ULONGLONG lastSeen;

    int score;
    BOOL alerted;
} INJECT_STATE;

static const wchar_t* NormalizePath(const wchar_t* path)
{
    if (!path || !path[0])
        return L"unknown";

    // Strip NT path prefix
    if (wcsncmp(path, L"\\??\\", 4) == 0)
        path += 4;

    // Return filename only
    const wchar_t* slash = wcsrchr(path, L'\\');
    return slash ? (slash + 1) : path;
}

static const wchar_t* GetProcessNameSafe(HANDLE pid, ULONGLONG createTime)
{
    PROC_STATE* p = FindProcess(pid, createTime);
    if (p && p->ImagePath[0] != L'\0')
        return NormalizePath(p->ImagePath);

    // Fallback: check g_PidToName (populated from startup snapshot and PROC_CREATE events)
    DWORD dpid = (DWORD)(ULONG_PTR)pid;
    auto it = g_PidToName.find(dpid);
    if (it != g_PidToName.end() && !it->second.empty())
    {
        // g_PidToName entries from the snapshot are just exe names (no path),
        // so NormalizePath is safe but mostly a no-op here.
        return NormalizePath(it->second.c_str());
    }

    return L"unknown";
}

// Per-chain wrapper around IsTrustedSystemSource. Caches the trust decision
// on the chain itself (s->sourceTrust) so subsequent events in the same
// chain skip the path-level cache lookup. Emits [TRUST_BYPASS] the first
// time a chain is determined to be trusted, so suppressed chains still
// leave a forensic trail.
static BOOL IsChainSourceTrusted(INJECT_STATE* s)
{
    if (!s)
        return FALSE;

    if (s->sourceTrust == TRUST_TRUSTED)
        return TRUE;
    if (s->sourceTrust == TRUST_UNTRUSTED)
        return FALSE;

    // First check for this chain — resolve via path-level cache.
    BOOL trusted = IsTrustedSystemSource((HANDLE)(ULONG_PTR)s->srcPid, s->srcCreateTime);
    s->sourceTrust = trusted ? TRUST_TRUSTED : TRUST_UNTRUSTED;

    if (trusted)
    {
        const wchar_t* srcName = GetProcessNameSafe((HANDLE)(ULONG_PTR)s->srcPid, s->srcCreateTime);
        const wchar_t* dstName = GetProcessNameSafe((HANDLE)(ULONG_PTR)s->dstPid, s->dstCreateTime);

        LogExtra(
            L"[TRUST_BYPASS] suppressed alert | src=%ws(%lu) dst=%ws(%lu) primitives=handle:%d,write:%d,protect:%d,thread:%d,resume:%d score=%d (source verified as signed system binary)\n",
            srcName,
            s->srcPid,
            dstName,
            s->dstPid,
            s->sawHandle ? 1 : 0,
            s->sawWrite ? 1 : 0,
            s->sawProtect ? 1 : 0,
            s->sawThread ? 1 : 0,
            s->sawResume ? 1 : 0,
            s->score
        );
    }

    return trusted;
}

#define MAX_INJECT 256

static INJECT_STATE g_Inject[MAX_INJECT] = { 0 };

static INJECT_STATE* GetState(
    ULONG src,
    ULONG dst,
    ULONGLONG srcCreateTime,
    ULONGLONG dstCreateTime
)
{
    for (int i = 0; i < MAX_INJECT; i++)
    {
        if (g_Inject[i].srcPid == src &&
            g_Inject[i].dstPid == dst &&
            g_Inject[i].srcCreateTime == srcCreateTime &&
            g_Inject[i].dstCreateTime == dstCreateTime)
        {
            return &g_Inject[i];
        }
    }

    for (int i = 0; i < MAX_INJECT; i++)
    {
        if (g_Inject[i].srcPid == 0)
        {
            g_Inject[i].srcPid = src;
            g_Inject[i].dstPid = dst;
            g_Inject[i].srcCreateTime = srcCreateTime;
            g_Inject[i].dstCreateTime = dstCreateTime;
            g_Inject[i].lastSeen = 0;

            g_Inject[i].score = 0;
            g_Inject[i].alerted = FALSE;

            return &g_Inject[i];
        }
    }
    return NULL;
}

void DetectionHandleEvent(EDR_EVENT* evt)
{
    ULONG src = (ULONG)(ULONG_PTR)evt->SourceProcessId;
    ULONG dst = (ULONG)(ULONG_PTR)evt->TargetProcessId;

    if (IsSensorProcess(evt->SourceProcessId, evt->SourceProcessCreateTime))
        return;

    if (!src || !dst)
        return;

    if (src == dst)
        return;

    if (IsWhitelistedSource(evt->SourceProcessId, evt->SourceProcessCreateTime.QuadPart))
        return;

    if (evt->DesiredAccess & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD))
    {
        INJECT_STATE* s = GetState(
            src,
            dst,
            evt->SourceProcessCreateTime.QuadPart,
            evt->TargetProcessCreateTime.QuadPart
        );
        if (s)
        {
            ULONGLONG now = evt->Timestamp.QuadPart;

            if (s->lastSeen != 0 && (now - s->lastSeen) > TIME_WINDOW_30S)
            {
                s->score -= 20;

                if (s->score <= 0)
                {
                    ZeroMemory(s, sizeof(*s));
                    return;
                }

                s->lastSeen = now;
            }

            s->lastSeen = now;

            // Score the "dangerous handle" primitive once per (src, dst) chain.
            // Subsequent handle events for the same pair refresh lastSeen above
            // (keeping the chain alive) but do not re-score. Real EDRs score
            // distinct behavioral primitives, not raw event counts.
            if (!s->sawHandle)
            {
                s->sawHandle = TRUE;
                s->score += 20;

                // Extra boost: parent opening handle to its own recently-created
                // child with dangerous access. Only meaningful at the moment the
                // primitive is first observed.
                PROC_STATE* dstProc = FindProcess(evt->TargetProcessId, evt->TargetProcessCreateTime.QuadPart);
                if (dstProc && dstProc->ParentProcessId == evt->SourceProcessId)
                {
                    ULONGLONG childAge = now - dstProc->CreateTime;
                    if (childAge < TIME_WINDOW_5S)
                    {
                        s->score += 10;
                    }
                }
            }
        }
    }
}

void DetectionWriteEvent(EDR_EVENT* evt)
{
    ULONG src = (ULONG)(ULONG_PTR)evt->SourceProcessId;
    ULONG dst = (ULONG)(ULONG_PTR)evt->TargetProcessId;

    if (IsSensorProcess(evt->SourceProcessId, evt->SourceProcessCreateTime))
        return;

    if (!src || !dst)
        return;

    if (src == dst)
        return;

    if (IsWhitelistedSource(evt->SourceProcessId, evt->SourceProcessCreateTime.QuadPart))
        return;

    INJECT_STATE* s = GetState(
        src,
        dst,
        evt->SourceProcessCreateTime.QuadPart,
        evt->TargetProcessCreateTime.QuadPart
    );
    if (!s)
        return;

    ULONGLONG now = evt->Timestamp.QuadPart;

    if (s->lastSeen != 0 && (now - s->lastSeen) > TIME_WINDOW_30S)
    {
        s->score -= 20;

        if (s->score <= 0)
        {
            ZeroMemory(s, sizeof(*s));
            return;
        }

        s->lastSeen = now;
    }

    s->lastSeen = now;

    // Always refresh the most recent write metadata, DetectionThreadEvent
    // uses this to check whether a remote thread's start address lands inside
    // a recently-written region, and the *latest* write for that is needed.
    s->writeAddr = evt->WriteAddress;
    s->writeSize = evt->WriteSize;
    s->lastWriteTime = evt->Timestamp.QuadPart;

    // Score the "cross-process write" primitive once per (src, dst) chain.
    if (!s->sawWrite)
    {
        s->sawWrite = TRUE;
        s->score += 30;

        // Hollowing heuristic: parent writing into its own recently-created
        // child. Only meaningful at the moment the write primitive is first
        // observed.
        PROC_STATE* dstProc = FindProcess(evt->TargetProcessId, evt->TargetProcessCreateTime.QuadPart);

        if (dstProc &&
            dstProc->ParentProcessId == evt->SourceProcessId &&
            !s->alerted)
        {
            ULONGLONG childAge = now - dstProc->CreateTime;

            if (childAge < TIME_WINDOW_5S)
            {
                s->score += 40;
            }
        }
    }

    // No alert from this handler. Writes are preparation, not execution,
    // the defining event for hollowing is NtResumeThread, and for remote
    // thread injection it's the thread itself. A [SUSPICIOUS] line is
    // logged when this chain has accumulated significant prep score,
    // so even if execution is missed (direct syscalls, hook bypass, timing), 
    // there's a forensic trail showing what was observed.
    // Gated by loggedSuspicious so the line fires once per chain, 
    // not once per write event
    if (!s->alerted && !s->loggedSuspicious && s->score >= 60)
    {
        // Trust gate: signed system binary in trusted dir, not a LOLBin.
        // Suppresses both SUSPICIOUS log and any future ALERT for this chain.
        if (IsChainSourceTrusted(s))
            return;

        s->loggedSuspicious = TRUE;

        const wchar_t* srcName = GetProcessNameSafe((HANDLE)(ULONG_PTR)s->srcPid, s->srcCreateTime);
        const wchar_t* dstName = GetProcessNameSafe((HANDLE)(ULONG_PTR)s->dstPid, s->dstCreateTime);

        LogExtra(
            L"[SUSPICIOUS] Injection prep observed | src=%ws(%lu) dst=%ws(%lu) primitives=handle:%d,write:%d,protect:%d score=%d (no execution observed yet)\n",
            srcName,
            s->srcPid,
            dstName,
            s->dstPid,
            s->sawHandle ? 1 : 0,
            s->sawWrite ? 1 : 0,
            s->sawProtect ? 1 : 0,
            s->score
        );
    }
}

void DetectionThreadEvent(
    EDR_EVENT* evt,
    ULONG inferredSrc,
    MEMORY_BASIC_INFORMATION* mbi
)
{
    ULONG dst = (ULONG)(ULONG_PTR)evt->TargetProcessId;
    ULONG src = inferredSrc;

    if (!src || !dst || src == dst)
        return;

    if (src == g_SensorPid)
        return;

    if (IsWhitelistedSource((HANDLE)(ULONG_PTR)src, evt->SourceProcessCreateTime.QuadPart))
        return;

    INJECT_STATE* s = GetState(
        src,
        dst,
        evt->SourceProcessCreateTime.QuadPart,
        evt->TargetProcessCreateTime.QuadPart
    );

    if (!s)
        return;

    if (s->alerted)
        return;

    ULONGLONG now = evt->Timestamp.QuadPart;

    if (s->lastSeen != 0 && (now - s->lastSeen) > TIME_WINDOW_30S)
    {
        s->score -= 20;

        if (s->score <= 0)
        {
            ZeroMemory(s, sizeof(*s));
            return;
        }

        s->lastSeen = now;
    }

    // refresh activity
    s->lastSeen = now;

    BOOL isPrivateExec =
        (mbi->Type == MEM_PRIVATE) &&
        (mbi->Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));

    BOOL isImageExec =
        (mbi->Type == MEM_IMAGE) &&
        (mbi->Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));

    BOOL isSuspiciousResume =
        (mbi->Type == 0) &&
        (mbi->Protect == PAGE_NOACCESS);

    if (!isPrivateExec && !isImageExec && !isSuspiciousResume)
        return;

    if (s->sawThread)
        return;

    s->sawThread = TRUE;

    BYTE* start = (BYTE*)evt->ThreadStartAddress;
    BYTE* write = (BYTE*)s->writeAddr;

    BOOL startMatchesWrite =
        (start >= write - 0x1000) &&
        (start < write + s->writeSize + 0x1000);

    if (isPrivateExec)
        s->score += 50;
    else if (isSuspiciousResume)
        s->score += 50;
    else if (isImageExec)
        s->score += 30;

    if (startMatchesWrite)
        s->score += 40;

    // Tiny-region bonus: a single-page (<=4KB) MEM_PRIVATE+RX region with a
    // remote thread pointing into it is shellcode-shaped by definition.
    // Catches "drip allocation" evasion — splitting payload across 4KB pages
    // to break the conventional alloc/write/thread event chain. Also covers
    // samples that bypass write hooks (direct syscalls, NtMapViewOfSection)
    // where the WriteProcessMemory event is never seen, but the resulting
    // shellcode region is still visible from the kernel-side thread callback.
    BOOL isTinyRegion = (mbi->RegionSize > 0 && mbi->RegionSize <= 0x1000);
    if (isPrivateExec && isTinyRegion)
    {
        s->score += 10;
        LogExtra(L"[SCORE] tiny private-exec region bonus: src=%lu dst=%lu size=%llu\n",
            s->srcPid, s->dstPid, (ULONGLONG)mbi->RegionSize);
    }

    if (!s->alerted && s->score >= 80)
    {
        // Trust gate: signed system binary in trusted dir, not a LOLBin.
        // If trusted, suppress the alert (and mark chain so subsequent
        // events also skip).
        if (IsChainSourceTrusted(s))
            return;

        const wchar_t* technique =
            isSuspiciousResume ? L"PROCESS_HOLLOWING" :
            isPrivateExec ? L"SHELLCODE_REMOTE_THREAD" :
            isImageExec ? L"IMAGE_BASED_INJECTION" :
            L"UNKNOWN";

        const wchar_t* srcName = GetProcessNameSafe((HANDLE)(ULONG_PTR)s->srcPid, s->srcCreateTime);
        const wchar_t* dstName = GetProcessNameSafe((HANDLE)(ULONG_PTR)s->dstPid, s->dstCreateTime);

        LogExtra(
            L"[ALERT] Remote Injection | src=%ws(%lu) dst=%ws(%lu) technique=%ws confidence=HIGH score=%d\n",
            srcName,
            s->srcPid,
            dstName,
            s->dstPid,
            technique,
            s->score
        );

        s->alerted = TRUE;
    }
}

void DetectionResumeEvent(EDR_EVENT* evt)
{
    ULONG src = (ULONG)(ULONG_PTR)evt->SourceProcessId;
    ULONG dst = (ULONG)(ULONG_PTR)evt->TargetProcessId;

    if (!src || !dst || src == dst)
        return;

    if (src == g_SensorPid)
        return;

    if (IsWhitelistedSource(evt->SourceProcessId, evt->SourceProcessCreateTime.QuadPart))
        return;

    INJECT_STATE* s = NULL;

    // Exact match: all four fields
    for (int i = 0; i < MAX_INJECT; i++)
    {
        if (g_Inject[i].srcPid == src &&
            g_Inject[i].dstPid == dst &&
            g_Inject[i].srcCreateTime == evt->SourceProcessCreateTime.QuadPart &&
            g_Inject[i].dstCreateTime == evt->TargetProcessCreateTime.QuadPart)
        {
            s = &g_Inject[i];
            break;
        }
    }

    if (!s)
        return;

    if (s->alerted)
        return;

    ULONGLONG now = evt->Timestamp.QuadPart;

    if (s->lastSeen != 0 && (now - s->lastSeen) > TIME_WINDOW_30S)
    {
        s->score -= 20;

        if (s->score <= 0)
        {
            ZeroMemory(s, sizeof(*s));
            return;
        }

        s->lastSeen = now;
    }

    s->lastSeen = now;

    // Score the "resume after recent write" primitive once per (src, dst) chain.
    // A hollowed process can have multiple NtResumeThread calls; only the first
    // one within the write→resume window contributes signal.
    if (!s->sawResume && s->lastWriteTime != 0)
    {
        ULONGLONG diff = now - s->lastWriteTime;

        if (diff < TIME_WINDOW_5S)
        {
            s->sawResume = TRUE;
            s->score += 50;
        }
    }

    if (!s->alerted && s->score >= 80)
    {
        // Trust gate: signed system binary in trusted dir, not a LOLBin.
        if (IsChainSourceTrusted(s))
            return;

        const wchar_t* srcName = GetProcessNameSafe((HANDLE)(ULONG_PTR)s->srcPid, s->srcCreateTime);
        const wchar_t* dstName = GetProcessNameSafe((HANDLE)(ULONG_PTR)s->dstPid, s->dstCreateTime);

        LogExtra(
            L"[ALERT] Remote Injection | src=%ws(%lu) dst=%ws(%lu) technique=PROCESS_HOLLOWING confidence=HIGH score=%d\n",
            srcName,
            s->srcPid,
            dstName,
            s->dstPid,
            s->score
        );

        s->alerted = TRUE;
    }
}

void DetectionProtectEvent(EDR_EVENT* evt)
{
    ULONG src = (ULONG)(ULONG_PTR)evt->SourceProcessId;
    ULONG dst = (ULONG)(ULONG_PTR)evt->TargetProcessId;

    if (IsSensorProcess(evt->SourceProcessId, evt->SourceProcessCreateTime))
        return;

    if (!src || !dst)
        return;

    if (src == dst)
        return;

    if (IsWhitelistedSource(evt->SourceProcessId, evt->SourceProcessCreateTime.QuadPart))
        return;

    BOOL isExecFlip =
        (evt->NewProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));

    if (!isExecFlip)
        return;

    INJECT_STATE* s = GetState(
        src,
        dst,
        evt->SourceProcessCreateTime.QuadPart,
        evt->TargetProcessCreateTime.QuadPart
    );

    if (!s)
        return;

    if (s->alerted)
        return;

    ULONGLONG now = evt->Timestamp.QuadPart;

    if (s->lastSeen != 0 && (now - s->lastSeen) > TIME_WINDOW_30S)
    {
        s->score -= 20;

        if (s->score <= 0)
        {
            ZeroMemory(s, sizeof(*s));
            return;
        }

        s->lastSeen = now;
    }

    s->lastSeen = now;

    // Score the "remote exec-flip" primitive once per (src, dst) chain.
    // The +15 write+protect combo also fires once, at the moment the protect
    // primitive is first observed alongside an already-seen write.
    if (!s->sawProtect)
    {
        s->sawProtect = TRUE;
        s->score += 25;

        if (s->sawWrite)
            s->score += 15;
    }

    // No alert from this handler. Protect flips are preparation — making a
    // region executable doesn't mean code has executed. The defining event
    // for remote thread injection is the thread itself; for hollowing it's
    // NtResumeThread. A [SUSPICIOUS] line is logged so prep-only chains leave
    // a forensic trail even when execution is missed. Gated by
    // loggedSuspicious so the line fires once per chain, not once per
    // protect event.
    if (!s->alerted && !s->loggedSuspicious && s->score >= 60)
    {
        // Trust gate: signed system binary in trusted dir, not a LOLBin.
        if (IsChainSourceTrusted(s))
            return;

        s->loggedSuspicious = TRUE;

        const wchar_t* srcName = GetProcessNameSafe((HANDLE)(ULONG_PTR)s->srcPid, s->srcCreateTime);
        const wchar_t* dstName = GetProcessNameSafe((HANDLE)(ULONG_PTR)s->dstPid, s->dstCreateTime);

        LogExtra(
            L"[SUSPICIOUS] Injection prep observed | src=%ws(%lu) dst=%ws(%lu) primitives=handle:%d,write:%d,protect:%d score=%d (no execution observed yet)\n",
            srcName,
            s->srcPid,
            dstName,
            s->dstPid,
            s->sawHandle ? 1 : 0,
            s->sawWrite ? 1 : 0,
            s->sawProtect ? 1 : 0,
            s->score
        );
    }
}

void CleanupStaleInjectStates()
{
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);
    ULONGLONG now = ((ULONGLONG)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;

    for (int i = 0; i < MAX_INJECT; i++)
    {
        if (g_Inject[i].srcPid == 0)
            continue;

        if (g_Inject[i].lastSeen == 0)
            continue;

        ULONGLONG SIXTY_SECONDS = 60ULL * 1000 * 1000 * 10;

        if ((now - g_Inject[i].lastSeen) > SIXTY_SECONDS)
        {
            ZeroMemory(&g_Inject[i], sizeof(INJECT_STATE));
        }
    }
}