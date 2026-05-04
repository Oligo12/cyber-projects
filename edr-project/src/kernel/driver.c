#include "globals.h"
#include <wdm.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

// GLOBAL STATE
// ============================

EVENT_QUEUE g_EventQueue;

NTSTATUS DeviceCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
);

NTSTATUS DeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
);

PVOID g_RegistrationHandle = NULL;

KERNEL_PROCESS_ENTRY g_ProcessTable[MAX_PROCESSES];
KSPIN_LOCK g_TableLock;

NTSTATUS DeviceRead(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
);

DRIVER_UNLOAD DriverUnload;

// ==============================
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
   
    if (g_RegistrationHandle) {
        ObUnRegisterCallbacks(g_RegistrationHandle);
        g_RegistrationHandle = NULL;
        DbgPrint("[OK] Ob callbacks unregistered\n");
    }

    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\MyEDR");

    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrint("MyEDR: Driver unloaded\n");
}

// Driver initialization:
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    g_EventQueue.Head = 0;
    g_EventQueue.Tail = 0;
    KeInitializeSpinLock(&g_EventQueue.Lock);

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("MyEDR: Driver loaded\n");

    KeInitializeSpinLock(&g_TableLock);

    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\MyEDR");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\MyEDR");

    PDEVICE_OBJECT deviceObject = NULL;

    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("MyEDR: Failed to create device\n");
        return status;
    }

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoCreateSymbolicLink(&symLink, &deviceName);

    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        DbgPrint("MyEDR: Failed to create symbolic link\n");
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = DeviceRead;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

    NTSTATUS cbStatus = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);

    if (!NT_SUCCESS(cbStatus)) {
        DbgPrint("MyEDR: CALLBACK REGISTRATION FAILED: 0x%X\n", cbStatus);
    }

    NTSTATUS imgStatus = PsSetLoadImageNotifyRoutine(ImageLoadCallback);

    if (!NT_SUCCESS(imgStatus)) {
        DbgPrint("ImageLoadCallback failed: 0x%X\n", imgStatus);
    }

    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"12345");

    OB_OPERATION_REGISTRATION operationRegistration = { 0 };

    operationRegistration.ObjectType = PsProcessType;
    operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration.PreOperation = PreOperationCallback;
    operationRegistration.PostOperation = NULL;

    OB_CALLBACK_REGISTRATION registration = { 0 };

    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = 1;
    registration.RegistrationContext = NULL;
    registration.Altitude = altitude;
    registration.OperationRegistration = &operationRegistration;

    status = ObRegisterCallbacks(&registration, &g_RegistrationHandle);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[ERROR] ObRegisterCallbacks failed: 0x%X\n", status);
    }
    return STATUS_SUCCESS;
}

// ==============================
NTSTATUS DeviceRead(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG outLen = stack->Parameters.Read.Length;

    if (outLen < sizeof(EDR_EVENT)) {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_BUFFER_TOO_SMALL;
    }

    EDR_EVENT* out = (EDR_EVENT*)Irp->AssociatedIrp.SystemBuffer;

    ULONG maxEntries = outLen / sizeof(EDR_EVENT);
    ULONG count = 0;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EventQueue.Lock, &oldIrql);

    while (g_EventQueue.Tail != g_EventQueue.Head && count < maxEntries)
    {
        out[count++] = g_EventQueue.Events[g_EventQueue.Tail];
        g_EventQueue.Tail = (g_EventQueue.Tail + 1) % MAX_EVENTS;
    }

    KeReleaseSpinLock(&g_EventQueue.Lock, oldIrql);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = count * sizeof(EDR_EVENT);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

// ==============================
NTSTATUS DeviceCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
   
    if (ioControlCode == IOCTL_EDR_WRITE_EVENT)
    {
        if (inputLen < sizeof(EDR_WRITE_EVENT))
        {
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_BUFFER_TOO_SMALL;
        }

        EDR_WRITE_EVENT* in = (EDR_WRITE_EVENT*)Irp->AssociatedIrp.SystemBuffer;

        if (in)
        {
            EDR_EVENT evt;
            RtlZeroMemory(&evt, sizeof(EDR_EVENT));

            evt.EventType = in->EventType;
            KeQuerySystemTimePrecise(&evt.Timestamp);

            evt.SourceProcessId = (HANDLE)(ULONG_PTR)in->SrcPid;
            evt.TargetProcessId = (HANDLE)(ULONG_PTR)in->TargetPid;
            evt.RawTargetHandle = in->TargetHandle;

            BOOLEAN srcFound = FALSE;
            BOOLEAN targetFound = FALSE;

            // Fast path: try the in-driver process table first.
            for (int i = 0; i < MAX_PROCESSES; i++)
            {
                if (g_ProcessTable[i].InUse)
                {
                    if (!srcFound && g_ProcessTable[i].ProcessId == (HANDLE)(ULONG_PTR)in->SrcPid)
                    {
                        evt.SourceProcessCreateTime = g_ProcessTable[i].CreateTime;
                        srcFound = TRUE;
                    }
                    if (!targetFound && g_ProcessTable[i].ProcessId == (HANDLE)(ULONG_PTR)in->TargetPid)
                    {
                        evt.TargetProcessCreateTime = g_ProcessTable[i].CreateTime;
                        targetFound = TRUE;
                    }
                    if (srcFound && targetFound) break;
                }
            }

            // Fallback: if the table missed, ask the kernel directly.
            // IOCTL handler runs at PASSIVE_LEVEL, so PsLookupProcessByProcessId is safe here.
            if (!srcFound && in->SrcPid != 0)
            {
                PEPROCESS srcProc = NULL;
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)in->SrcPid, &srcProc)))
                {
                    evt.SourceProcessCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(srcProc);
                    ObDereferenceObject(srcProc);
                }
            }

            if (!targetFound && in->TargetPid != 0)
            {
                PEPROCESS targetProc = NULL;
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)in->TargetPid, &targetProc)))
                {
                    evt.TargetProcessCreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(targetProc);
                    ObDereferenceObject(targetProc);
                }
            }

            if (in->EventType == EDR_EVENT_WRITE_MEMORY)
            {
                evt.WriteAddress = in->Address;
                evt.WriteSize = in->Size;
            }
            else if (in->EventType == EDR_EVENT_PROTECT_MEMORY)
            {
                evt.ProtectAddress = in->Address;
                evt.ProtectSize = in->Size;
                evt.OldProtect = in->OldProtect;
                evt.NewProtect = in->NewProtect;
            }
            else if (in->EventType == EDR_EVENT_RESUME_THREAD)
            {
                evt.ThreadId = (HANDLE)(ULONG_PTR)in->TargetTid;
                // Resume events carry only src/dst PIDs — no address data.
            }

            PushEvent(&evt);
        }

        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    if (ioControlCode == IOCTL_EDR_RESOLVE_CREATETIME)
    {
        ULONG outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (inputLen < sizeof(EDR_CREATETIME_QUERY) ||
            outputLen < sizeof(EDR_CREATETIME_QUERY))
        {
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_BUFFER_TOO_SMALL;
        }

        EDR_CREATETIME_QUERY* q = (EDR_CREATETIME_QUERY*)Irp->AssociatedIrp.SystemBuffer;
        ULONG pid = q->Pid;

        // Default: not found.
        q->CreateTime.QuadPart = 0;

        if (pid != 0)
        {
            PEPROCESS proc = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc)))
            {
                q->CreateTime.QuadPart = PsGetProcessCreateTimeQuadPart(proc);
                ObDereferenceObject(proc);
            }
        }

        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = sizeof(EDR_CREATETIME_QUERY);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
    
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}