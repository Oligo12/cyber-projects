#include "globals.h"
#include <ntifs.h>
#include <ntddk.h>

EXTERN_C NTSTATUS ZwOpenThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

EXTERN_C NTSTATUS ZwQueryInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE        0x0020
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION    0x0008
#endif

#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD   0x0002
#endif

#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE      0x0040
#endif

#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME  0x0800
#endif

// ==============================

VOID NTAPI ProcessNotifyCallbackEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    if (CreateInfo)
    {
        PEPROCESS parentProcess = NULL;
        LARGE_INTEGER parentTime = { 0 };

        if (NT_SUCCESS(PsLookupProcessByProcessId(CreateInfo->ParentProcessId, &parentProcess))) {
            parentTime.QuadPart = PsGetProcessCreateTimeQuadPart(parentProcess);
            ObDereferenceObject(parentProcess);
        }

        WCHAR parentImage[260] = L"";
        PCUNICODE_STRING finalCmd = CreateInfo->CommandLine;
        PCUNICODE_STRING finalImg = CreateInfo->ImageFileName;
        UNICODE_STRING parentImgUs;
        RtlInitUnicodeString(&parentImgUs, parentImage);

        GetProcessImageSafe(
            CreateInfo->ParentProcessId,
            parentTime,
            parentImage,
            sizeof(parentImage)
        );

        LARGE_INTEGER realCreateTime;
        realCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);

        AddProcessToTable(
            ProcessId,
            CreateInfo->ParentProcessId,
            finalImg ? finalImg : NULL,
            &parentImgUs,
            finalCmd ? finalCmd : NULL,
            realCreateTime,
            parentTime
        );

        EDR_EVENT evt = { 0 };

        evt.EventType = EDR_EVENT_PROCESS_CREATE;
        KeQuerySystemTimePrecise(&evt.Timestamp);

        evt.ProcessId = ProcessId;
        evt.ParentProcessId = CreateInfo->ParentProcessId;

        if (finalImg && finalImg->Buffer)
            RtlStringCbCopyNW(evt.ImagePath, sizeof(evt.ImagePath), finalImg->Buffer, finalImg->Length);
        else
            RtlStringCbCopyW(evt.ImagePath, sizeof(evt.ImagePath), L"(null)");

        RtlStringCbCopyW(
            evt.ParentImagePath,
            sizeof(evt.ParentImagePath),
            parentImage
        );

        if (finalCmd && finalCmd->Buffer)
            RtlStringCbCopyNW(evt.CommandLine, sizeof(evt.CommandLine), finalCmd->Buffer, finalCmd->Length);
        else
            RtlStringCbCopyW(evt.CommandLine, sizeof(evt.CommandLine), L"(null)");

        evt.ProcessCreateTime = realCreateTime;

        evt.ParentProcessCreateTime = parentTime;

        PushEvent(&evt);
    }
    else {
        LARGE_INTEGER createTime;
        createTime.QuadPart = PsGetProcessCreateTimeQuadPart(Process);

        EDR_EVENT evt;
        RtlZeroMemory(&evt, sizeof(EDR_EVENT));

        evt.EventType = EDR_EVENT_PROCESS_TERMINATE;
        KeQuerySystemTimePrecise(&evt.Timestamp);

        evt.ProcessId = ProcessId;
        evt.ParentProcessId = NULL;
        evt.SourceProcessId = NULL;
        evt.TargetProcessId = NULL;
        evt.ThreadId = NULL;
        evt.DesiredAccess = 0;
        evt.ProcessCreateTime = createTime;
        evt.ParentProcessCreateTime.QuadPart = 0;
        evt.SourceProcessCreateTime.QuadPart = 0;
        evt.TargetProcessCreateTime.QuadPart = 0;

        PushEvent(&evt);
        RemoveProcessFromTable(ProcessId, createTime);

#if DEBUG_PRINTS
        DbgPrint("Process terminate: %lu\n",
            (ULONG)(ULONG_PTR)ProcessId);
#endif
    }
}

// ==============================

VOID ImageLoadCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{
    if (!ImageInfo)
        return;

    if (!ProcessId || !FullImageName || !FullImageName->Buffer)
        return;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_TableLock, &oldIrql);

    for (int i = 0; i < MAX_PROCESSES; i++) {

        if (!g_ProcessTable[i].InUse)
            continue;

        if (g_ProcessTable[i].ProcessId != ProcessId)
            continue;

        if (g_ProcessTable[i].ImageCount < 5) {

            SIZE_T idx = g_ProcessTable[i].ImageCount;
            g_ProcessTable[i].ImageBase = ImageInfo->ImageBase;
            g_ProcessTable[i].ImageSize = ImageInfo->ImageSize;
            g_ProcessTable[i].IsSystemMode = (BOOLEAN)ImageInfo->SystemModeImage;
            SIZE_T copyLen = min(
                FullImageName->Length,
                sizeof(g_ProcessTable[i].LoadedImages[idx]) - sizeof(WCHAR)
            );

            RtlCopyMemory(
                g_ProcessTable[i].LoadedImages[idx],
                FullImageName->Buffer,
                copyLen
            );

            g_ProcessTable[i].LoadedImages[idx][copyLen / sizeof(WCHAR)] = L'\0';

            g_ProcessTable[i].ImageCount++;
        }

        break;
    }

    KeReleaseSpinLock(&g_TableLock, oldIrql);
}

//====================================================
OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!OperationInformation)
        return OB_PREOP_SUCCESS;

    if (OperationInformation->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;

    if (OperationInformation->Operation != OB_OPERATION_HANDLE_CREATE &&
        OperationInformation->Operation != OB_OPERATION_HANDLE_DUPLICATE)
        return OB_PREOP_SUCCESS;

    if (!OperationInformation->Parameters)
        return OB_PREOP_SUCCESS;

    HANDLE targetPid = PsGetProcessId((PEPROCESS)OperationInformation->Object);
    HANDLE sourcePid = PsGetCurrentProcessId();
    ACCESS_MASK access = 0;

    // --- Kernel-side filters: drop noise before it hits the event queue ---

    // Self-handle: process opening itself (extremely common, never interesting)
    if (sourcePid == targetPid)
        return OB_PREOP_SUCCESS;

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        access = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    }
    else {
        access = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
    }

    // Only care about handles with dangerous rights.
    // PROCESS_QUERY_INFORMATION / PROCESS_QUERY_LIMITED_INFORMATION alone are benign.

    ACCESS_MASK dangerousMask =
        PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION |
        PROCESS_CREATE_THREAD |
        PROCESS_DUP_HANDLE |
        PROCESS_SUSPEND_RESUME;

    if (!(access & dangerousMask))
        return OB_PREOP_SUCCESS;

    LARGE_INTEGER sourceCreateTime = { 0 };
    LARGE_INTEGER targetCreateTime = { 0 };

    PEPROCESS sourceProcess = PsGetCurrentProcess();
    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;

    sourceCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(sourceProcess);
    targetCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(targetProcess);

    EDR_EVENT evt;
    RtlZeroMemory(&evt, sizeof(EDR_EVENT));

    evt.EventType = EDR_EVENT_HANDLE_OPEN;
    KeQuerySystemTimePrecise(&evt.Timestamp);

    evt.ProcessId = targetPid;
    evt.SourceProcessId = sourcePid;
    evt.TargetProcessId = targetPid;
    evt.DesiredAccess = access;

    evt.SourceProcessCreateTime = sourceCreateTime;
    evt.TargetProcessCreateTime = targetCreateTime;
    evt.ProcessCreateTime.QuadPart = 0;
    evt.ParentProcessCreateTime.QuadPart = 0;

    PushEvent(&evt);

    return OB_PREOP_SUCCESS;
}


// ==============================
VOID ThreadNotifyCallback(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
)
{
    if (!Create)
        return;

    HANDLE hThread = NULL;
    HANDLE hProcess = NULL;

    CLIENT_ID cid = { 0 };
    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = ThreadId;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    if (!NT_SUCCESS(ZwOpenThread(
        &hThread,
        THREAD_QUERY_INFORMATION,
        &oa,
        &cid)))
    {
        return;
    }

    if (!NT_SUCCESS(ZwOpenProcess(
        &hProcess,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        &oa,
        &cid)))
    {
        ZwClose(hThread);
        return;
    }

    PVOID startAddress = NULL;

    ZwQueryInformationThread(
        hThread,
        ThreadQuerySetWin32StartAddress,
        &startAddress,
        sizeof(PVOID),
        NULL
    );

    MEMORY_BASIC_INFORMATION mbi = { 0 };

    ZwQueryVirtualMemory(
        hProcess,
        startAddress,
        MemoryBasicInformation,
        &mbi,
        sizeof(mbi),
        NULL
    );

    ZwClose(hThread);
    ZwClose(hProcess);

    EDR_EVENT evt;
    RtlZeroMemory(&evt, sizeof(EDR_EVENT));

    evt.EventType = EDR_EVENT_THREAD_CREATE;
    KeQuerySystemTimePrecise(&evt.Timestamp);

    evt.ProcessId = ProcessId;
    evt.TargetProcessId = ProcessId;
    evt.ThreadId = ThreadId;

    evt.ThreadStartAddress = startAddress;
    evt.ThreadStartBaseAddress = mbi.BaseAddress;
    evt.ThreadStartRegionSize = mbi.RegionSize;
    evt.ThreadStartType = mbi.Type;
    evt.ThreadStartProtection = mbi.Protect;

    PEPROCESS targetProcess = NULL;

    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &targetProcess))) {
        evt.TargetProcessCreateTime.QuadPart =
            PsGetProcessCreateTimeQuadPart(targetProcess);
        ObDereferenceObject(targetProcess);
    }

    PushEvent(&evt);
}
