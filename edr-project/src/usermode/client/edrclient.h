#pragma once

#include "shared.h"

#define MAX_TRACKED_HANDLES 2048
#define MAX_TRACKED_PROCS 1024

extern DWORD g_SensorPid;
extern ULONGLONG g_SensorCreateTime;
extern PROC_STATE g_ProcTable[MAX_TRACKED_PROCS];

BOOL IsSensorProcess(HANDLE pid, LARGE_INTEGER createTime);

typedef struct _HANDLE_EVENT_STATE {
    BOOL InUse;
    HANDLE SourcePid;
    HANDLE TargetPid;
    ULONGLONG SourceCreateTime;
    ULONGLONG TargetCreateTime;
    DWORD DesiredAccess;
    ULONGLONG Timestamp;
} HANDLE_EVENT_STATE;

extern HANDLE_EVENT_STATE g_HandleTable[MAX_TRACKED_HANDLES];

PROC_STATE* FindProcess(HANDLE pid, ULONGLONG createTime);

void TrackProcessCreate(EDR_EVENT* evt);
void TrackProcessExit(EDR_EVENT* evt);
void TrackHandleEvent(EDR_EVENT* evt);
void CleanupOldHandles(ULONGLONG now);
void ProcessSecCtxQueue();

// --- Deferred injection for suspended processes ---

#define MAX_DEFERRED_INJECT 256

typedef struct _DEFERRED_INJECT {
    BOOL InUse;
    DWORD Pid;
    ULONGLONG CreateTime;
    ULONGLONG QueuedTick;   // GetTickCount64 when queued, for expiry
} DEFERRED_INJECT;

extern DEFERRED_INJECT g_DeferredInject[MAX_DEFERRED_INJECT];

BOOL IsProcessSuspended(DWORD pid);
void DeferredInjectAdd(DWORD pid, ULONGLONG createTime);
void DeferredInjectRemove(DWORD pid);
void DeferredInjectTryResume(DWORD pid);
void DeferredInjectCleanup();