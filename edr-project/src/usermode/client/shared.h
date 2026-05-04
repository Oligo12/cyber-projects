#pragma once
#include <windows.h>

#define IOCTL_EDR_RESOLVE_CREATETIME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Mirror of the kernel-side struct in globals.h. Keep both in sync.
typedef struct _EDR_CREATETIME_QUERY {
    ULONG          Pid;          // [in]  process ID to resolve
    ULONG          _Reserved;    // padding
    LARGE_INTEGER  CreateTime;   // [out] 0 if PID not found
} EDR_CREATETIME_QUERY;
#define MAX_PROCESSES 256
#define MAX_SECCTX_QUEUE 256

typedef struct _PROC_STATE {
    BOOL InUse;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    ULONGLONG CreateTime;
    WCHAR ImagePath[260];
    WCHAR ParentImagePath[260];
    WCHAR CommandLine[512];

    // userland SECCTX
    BOOL SecCtxReady;

    WCHAR UserSid[128];
    WCHAR Integrity[32];
    WCHAR TokenType[32];
    WCHAR ElevationType[32];

    BOOL PrivSeDebug;
    BOOL PrivSeImpersonate;
    BOOL PrivSeAssignPrimaryToken;
    BOOL PrivSeTcb;
    BOOL PrivSeBackup;
    BOOL PrivSeRestore;
    BOOL PrivSeLoadDriver;
    BOOL PrivSeTakeOwnership;

} PROC_STATE;

typedef struct _SECCTX_WORK_ITEM {
    BOOL InUse;
    HANDLE ProcessId;
    ULONGLONG CreateTime;
    DWORD RetryCount;
    ULONGLONG NextAttemptTick;
} SECCTX_WORK_ITEM;

#define EDR_EVENT_PROCESS_CREATE    1
#define EDR_EVENT_PROCESS_TERMINATE 2
#define EDR_EVENT_HANDLE_OPEN       3
#define EDR_EVENT_THREAD_CREATE     4
#define EDR_EVENT_WRITE_MEMORY      5
#define EDR_EVENT_PROTECT_MEMORY    6
#define EDR_EVENT_RESUME_THREAD     7

// NOTE: This struct is shared with kernel (globals.h). Keep both in sync!
typedef struct _EDR_EVENT {
    ULONG EventType;
    LARGE_INTEGER Timestamp;

    HANDLE ProcessId;
    HANDLE ParentProcessId;

    HANDLE SourceProcessId;
    HANDLE TargetProcessId;
    HANDLE RawTargetHandle;

    PVOID WriteAddress;
    SIZE_T WriteSize;

    PVOID ProtectAddress;
    SIZE_T ProtectSize;
    ULONG OldProtect;
    ULONG NewProtect;

    HANDLE ThreadId;
    ACCESS_MASK DesiredAccess;

    PVOID ThreadStartAddress;
    PVOID ThreadStartBaseAddress;
    SIZE_T ThreadStartRegionSize;
    ULONG ThreadStartType;
    ULONG ThreadStartProtection;

    LARGE_INTEGER ProcessCreateTime;
    LARGE_INTEGER ParentProcessCreateTime;
    LARGE_INTEGER SourceProcessCreateTime;
    LARGE_INTEGER TargetProcessCreateTime;

    WCHAR ImagePath[260];
    WCHAR ParentImagePath[260];
    WCHAR CommandLine[512];
} EDR_EVENT;

extern EDR_EVENT g_EventBuffer[512];