#pragma once

#define DEBUG_PRINTS 0
#define MAX_PROCESSES 256
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntdef.h>
#include <wdm.h>

#define EDR_EVENT_PROCESS_CREATE        1
#define EDR_EVENT_PROCESS_TERMINATE     2
#define EDR_EVENT_HANDLE_OPEN           3
#define EDR_EVENT_THREAD_CREATE         4
#define EDR_EVENT_WRITE_MEMORY          5
#define EDR_EVENT_PROTECT_MEMORY        6
#define EDR_EVENT_RESUME_THREAD         7
#define IOCTL_EDR_WRITE_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EDR_RESOLVE_CREATETIME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Single buffer used for both directions (METHOD_BUFFERED).
// Userland sets Pid; kernel writes CreateTime back. CreateTime stays 0 on miss.
typedef struct _EDR_CREATETIME_QUERY {
    ULONG          Pid;          // [in]  process ID to resolve
    ULONG          _Reserved;    // padding
    LARGE_INTEGER  CreateTime;   // [out] 0 if PID not found
} EDR_CREATETIME_QUERY;


#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif

// Tagged union for all userland-hook events. Carries WRITE, PROTECT, and
// RESUME events distinguished by EventType. Per-type field validity:
//   EventType=5 (WRITE)   → SrcPid, TargetPid, TargetHandle, Address, Size
//   EventType=6 (PROTECT) → SrcPid, TargetPid, Address, Size, OldProtect, NewProtect
//   EventType=7 (RESUME)  → SrcPid, TargetPid, TargetTid
// Name is historical (originally write-only) — kept for kernel ABI stability.
// MUST match userland layout in shared.h.
typedef struct _EDR_WRITE_EVENT {
    ULONG EventType;      // 5 = WRITE, 6 = PROTECT, 7 = RESUME_THREAD

    ULONG SrcPid;
    ULONG TargetPid;      
    HANDLE TargetHandle;   // RAW handle from hooked process

    PVOID Address;
    SIZE_T Size;

    ULONG OldProtect;     // only used for PROTECT
    ULONG NewProtect;     // only used for PROTECT

    ULONG TargetTid;      // only used for RESUME_THREAD. MUST match userland layout in shared.h
} EDR_WRITE_EVENT;

// NOTE: This struct is shared with userland (shared.h). Keep both in sync
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

#define MAX_EVENTS 16384

typedef struct _EVENT_QUEUE {
    EDR_EVENT Events[MAX_EVENTS];
    ULONG Head;
    ULONG Tail;
    KSPIN_LOCK Lock;
} EVENT_QUEUE;

extern EVENT_QUEUE g_EventQueue;

// NOTE: Kernel-side only. Client has its own PROCESS_ENTRY in shared.h with extra fields.
typedef struct _KERNEL_PROCESS_ENTRY {
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    WCHAR ImagePath[260];
    WCHAR ParentImage[260];
    WCHAR CommandLine[512];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ParentCreateTime;
    BOOLEAN InUse;
    BOOLEAN IsNew;
    LARGE_INTEGER EventTime;
    ULONG EventType;
    PVOID ImageBase;
    SIZE_T ImageSize;
    BOOLEAN IsSystemMode;
    ULONG IntegrityLevel;
    WCHAR LoadedImages[5][260];
    ULONG ImageCount;
} KERNEL_PROCESS_ENTRY;


// GLOBALS (shared across all files)
extern KERNEL_PROCESS_ENTRY g_ProcessTable[MAX_PROCESSES];
extern KSPIN_LOCK g_TableLock;
extern OB_CALLBACK_REGISTRATION g_CallbackRegistration;
extern PVOID g_RegistrationHandle;
extern EVENT_QUEUE g_EventQueue;

VOID PushEvent(EDR_EVENT* evt);


// FUNCTIONS (so files can call each other)
VOID AddProcessToTable(
    HANDLE pid,
    HANDLE parentPid,
    PCUNICODE_STRING image,
    PCUNICODE_STRING parentImage,
    PCUNICODE_STRING cmd,
    LARGE_INTEGER createTime,
    LARGE_INTEGER parentCreateTime
);

VOID RemoveProcessFromTable(HANDLE pid, LARGE_INTEGER createTime);

BOOLEAN GetProcessImageSafe(
    HANDLE pid,
    LARGE_INTEGER expectedCreateTime,
    PWCHAR outBuffer,
    SIZE_T outSize
);

BOOLEAN GetProcessCommandLineSafe(
    HANDLE pid,
    LARGE_INTEGER expectedCreateTime,
    PWCHAR outBuffer,
    SIZE_T outSize
);

VOID ProcessNotifyCallbackEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
);

VOID ImageLoadCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
);

OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

VOID ThreadNotifyCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
);

