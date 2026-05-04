#include "pch.h"
#include "shared.h"
#include <winioctl.h>
#include <Windows.h>
#include <Zydis/Zydis.h>
#include <cstdio>
#include <winternl.h>
#include <intrin.h>
#define IOCTL_EDR_WRITE_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

ZydisDecoder g_Decoder;
void* g_NtWriteVirtualMemory = nullptr;
volatile LONG g_HookHitCount = 0;


// Tagged union for all userland-hook events. The kernel exposes a single
// IOCTL (IOCTL_EDR_WRITE_EVENT) that carries WRITE, PROTECT, and RESUME
// events distinguished by EventType. Per-type field validity:
//   EventType=5 (WRITE)   → SrcPid, TargetPid, TargetHandle, Address, Size
//   EventType=6 (PROTECT) → SrcPid, TargetPid, Address, Size, OldProtect, NewProtect
//   EventType=7 (RESUME)  → SrcPid, TargetPid, TargetTid
// Name is historical (originally write-only), kept for kernel ABI stability.

typedef struct _EDR_WRITE_EVENT
{
    ULONG EventType; // 5 = WRITE, 6 = PROTECT, 7 = RESUME_THREAD
    ULONG SrcPid;
    ULONG TargetPid;   // resolved in DLL via GetProcessId / GetProcessIdOfThread
    HANDLE TargetHandle; // raw handle (kept for debugging)
    PVOID Address;
    SIZE_T Size;

    ULONG OldProtect;   // only used for PROTECT
    ULONG NewProtect;   // only used for PROTECT

    ULONG TargetTid;    // only used for RESUME_THREAD. MUST match kernel struct layout in globals.h
} EDR_WRITE_EVENT;

void* g_NtProtectVirtualMemory = nullptr;
size_t g_NtProtectVirtualMemoryPatchLen = 0;
unsigned char g_NtProtectVirtualMemoryOriginalBytes[32] = { 0 };
void* g_NtProtectVirtualMemoryTrampoline = nullptr;

void* g_NtResumeThread = nullptr;
size_t g_NtResumeThreadPatchLen = 0;
unsigned char g_NtResumeThreadOriginalBytes[32] = { 0 };
void* g_NtResumeThreadTrampoline = nullptr;

typedef NTSTATUS(NTAPI* NtResumeThread_t)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
    );

NtResumeThread_t g_OriginalNtResumeThread = nullptr;
NtResumeThread_t g_SyscallNtResumeThread = nullptr;

extern NTSTATUS NTAPI MyNtResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

NtProtectVirtualMemory_t g_OriginalNtProtectVirtualMemory = nullptr;
NtProtectVirtualMemory_t g_SyscallNtProtectVirtualMemory = nullptr;

extern NTSTATUS NTAPI MyNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

#define QUEUE_SIZE 256

EDR_WRITE_EVENT g_EventQueue[QUEUE_SIZE];
volatile LONG g_QueueHead = 0;
volatile LONG g_QueueTail = 0;

// CRITICAL: g_InHook MUST NOT be __declspec(thread) (static TLS).
//
// Static TLS for a dynamically-loaded DLL is allocated lazily by the loader.
// When LoadLibrary loads us, the loader walks loaded modules and extends
// each thread's TLS array — but the loader itself calls NtProtectVirtualMemory
// while doing that work. If a thread in the loader hits MyNtProtectVirtualMemory
// before its TLS slot for our DLL is allocated, reading g_InHook returns
// garbage and writing it (g_InHook++) AVs inside the loader — process dies
// during startup with STATUS_ACCESS_VIOLATION. That broke elevation: every
// admin launch creates consent.exe which loads many DLLs and triggers this
// race.
//
// Tradeoff with a plain global: if two threads in the same process call
// MyNtProtect simultaneously, the second sees g_InHook=1 and skips its
// telemetry event. That's acceptable — losing one telemetry event is far
// better than crashing the host process. The hook itself is still correct
// because forward() goes through the trampoline either way.
volatile LONG g_InHook = 0;
size_t g_NtWriteVirtualMemoryPatchLen = 0;
unsigned char g_NtWriteVirtualMemoryOriginalBytes[32] = { 0 };
void* g_NtWriteVirtualMemoryTrampoline = nullptr;
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );
NtWriteVirtualMemory_t g_OriginalNtWriteVirtualMemory = nullptr;
extern NTSTATUS NTAPI MyNtWriteVirtualMemory(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T
);
NtWriteVirtualMemory_t g_SyscallNtWriteVirtualMemory = nullptr;

NTSTATUS NTAPI MyNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

void QueueEvent(const EDR_WRITE_EVENT* evt)
{
    LONG head;
    LONG tail;
    LONG newHead;

    do
    {
        head = g_QueueHead;
        tail = g_QueueTail;

        if ((head - tail) >= QUEUE_SIZE)
            return;

        newHead = head + 1;
    } while (InterlockedCompareExchange(&g_QueueHead, newHead, head) != head);

    LONG index = head % QUEUE_SIZE;

    g_EventQueue[index] = *evt;

    _mm_sfence(); // ensure write is visible before sender reads
}

void InitZydis()
{
    ZydisDecoderInit(
        &g_Decoder,
        ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64
    );
}

void ResolveTargets()
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
    {
        OutputDebugStringA("[HOOK] GetModuleHandleW(ntdll) failed\n");
        return;
    }

    g_NtWriteVirtualMemory = (void*)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    if (!g_NtWriteVirtualMemory)
    {
        OutputDebugStringA("[HOOK] GetProcAddress(NtWriteVirtualMemory) failed\n");
        return;
    }

    g_SyscallNtWriteVirtualMemory = (NtWriteVirtualMemory_t)g_NtWriteVirtualMemory;

    g_NtProtectVirtualMemory = (void*)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    if (!g_NtProtectVirtualMemory)
    {
        OutputDebugStringA("[HOOK] GetProcAddress(NtProtectVirtualMemory) failed\n");
        return;
    }

    g_SyscallNtProtectVirtualMemory = (NtProtectVirtualMemory_t)g_NtProtectVirtualMemory;

    g_NtResumeThread = (void*)GetProcAddress(hNtdll, "NtResumeThread");
    if (!g_NtResumeThread)
    {
        OutputDebugStringA("[HOOK] GetProcAddress(NtResumeThread) failed\n");
        return;
    }

    g_SyscallNtResumeThread = (NtResumeThread_t)g_NtResumeThread;

}

size_t CalculatePatchLength(void* target)
{
    size_t offset = 0;

    while (offset < 14)
    {
        ZydisDecodedInstruction instruction;
        ZydisDecoderContext context;

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
            &g_Decoder,
            &context,
            (unsigned char*)target + offset,
            16,
            &instruction)))
        {
            OutputDebugStringA("[HOOK] decode failed\n");
            return 0;
        }

        offset += instruction.length;
    }
    return offset;
}

void SaveOriginalBytes(void* target, size_t patchLen, unsigned char* outBuffer)
{
    if (!target || patchLen == 0 || patchLen > sizeof(g_NtWriteVirtualMemoryOriginalBytes))
    {
        OutputDebugStringA("[HOOK] SaveOriginalBytes invalid args\n");
        return;
    }

    memcpy(outBuffer, target, patchLen);
}

bool IsRipRelative(const ZydisDecodedInstruction& instr, const ZydisDecoderContext& context)
{
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeOperands(
        &g_Decoder,
        (ZydisDecoderContext*)&context,
        &instr,
        operands,
        instr.operand_count_visible)))
    {
        OutputDebugStringA("[HOOK] DecodeOperands failed\n");
        return false;
    }

    for (uint8_t i = 0; i < instr.operand_count_visible; i++)
    {
        if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[i].mem.base == ZYDIS_REGISTER_RIP)
        {
            return true;
        }
    }

    return false;
}

bool GetRipRelativeDisp(const ZydisDecodedInstruction& instr, const ZydisDecoderContext& context, int32_t& dispOut)
{
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeOperands(
        &g_Decoder,
        (ZydisDecoderContext*)&context,
        &instr,
        operands,
        instr.operand_count_visible)))
    {
        OutputDebugStringA("[HOOK] DecodeOperands failed\n");
        return false;
    }

    for (uint8_t i = 0; i < instr.operand_count_visible; i++)
    {
        if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[i].mem.base == ZYDIS_REGISTER_RIP)
        {
            dispOut = operands[i].mem.disp.value;
            return true;
        }
    }

    return false;
}

bool IsRelativeControlFlow(const ZydisDecodedInstruction& instr)
{
    if (instr.meta.category == ZYDIS_CATEGORY_COND_BR)
        return true;

    if (instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR)
        return true;

    if (instr.meta.category == ZYDIS_CATEGORY_CALL)
        return true;

    return false;
}

void BuildTrampoline(void* target, size_t patchLen, void** outTrampoline)
{
    *outTrampoline = NULL;

    if (!target || patchLen == 0)
    {
        return;
    }

    // allocate RWX memory for the trampoline
    unsigned char* tramp = (unsigned char*)VirtualAlloc(
        NULL,
        256,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!tramp)
    {
        return;
    }

    // copy original bytes
    size_t offset = 0;
    size_t trampOffset = 0;

    while (offset < patchLen)
    {
        ZydisDecodedInstruction instr;
        ZydisDecoderContext context = {};

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
            &g_Decoder,
            &context,
            (unsigned char*)target + offset,
            16,
            &instr)))
        {
            VirtualFree(tramp, 0, MEM_RELEASE);
            return;
        }

        if (IsRelativeControlFlow(instr))
        {
            VirtualFree(tramp, 0, MEM_RELEASE);
            return;
        }

        // RIP-relative fix
        if (IsRipRelative(instr, context))
        {
            int32_t origDisp = 0;

            if (!GetRipRelativeDisp(instr, context, origDisp))
            {
                VirtualFree(tramp, 0, MEM_RELEASE);
                return;
            }

            unsigned char* origInstrAddr = (unsigned char*)target + offset;
            unsigned char* newInstrAddr = tramp + trampOffset;

            uint64_t targetAddr =
                (uint64_t)(origInstrAddr + instr.length + origDisp);

            int64_t newDisp64 =
                (int64_t)targetAddr - (int64_t)(uint64_t)(newInstrAddr + instr.length);

            if (newDisp64 < INT32_MIN || newDisp64 > INT32_MAX)
            {
                VirtualFree(tramp, 0, MEM_RELEASE);
                return;
            }

            int32_t newDisp = (int32_t)newDisp64;

            memcpy(newInstrAddr, origInstrAddr, instr.length);

            if (instr.raw.disp.size != 32)
            {
                OutputDebugStringA("[HOOK] unsupported disp size\n");
                VirtualFree(tramp, 0, MEM_RELEASE);
                return;
            }

            *(int32_t*)(newInstrAddr + instr.raw.disp.offset) = newDisp;

            offset += instr.length;
            trampOffset += instr.length;
            continue;
        }

        memcpy(tramp + trampOffset,
            (unsigned char*)target + offset,
            instr.length);

        offset += instr.length;
        trampOffset += instr.length;
    }

    // append jump back -> target + patchLen
    unsigned char* jmp = tramp + trampOffset;

    // mov r11, <addr>
    jmp[0] = 0x49;
    jmp[1] = 0xBB;
    *(void**)(jmp + 2) = (unsigned char*)target + offset;

    // jmp r11
    jmp[10] = 0x41;
    jmp[11] = 0xFF;
    jmp[12] = 0xE3;

    FlushInstructionCache(GetCurrentProcess(), tramp, 256);
    *outTrampoline = tramp;

   }

HANDLE g_DeviceHandle = INVALID_HANDLE_VALUE;
HANDLE g_ShutdownEvent = NULL;


NTSTATUS NTAPI MyNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
)
{
    // Cheap fast paths first — no syscalls, no locks.

    if (g_InHook)
        return g_OriginalNtWriteVirtualMemory(
            ProcessHandle, BaseAddress, Buffer,
            NumberOfBytesToWrite, NumberOfBytesWritten);

    if (ProcessHandle == (HANDLE)-1)
        return g_OriginalNtWriteVirtualMemory(
            ProcessHandle, BaseAddress, Buffer,
            NumberOfBytesToWrite, NumberOfBytesWritten);

    // Worth investigating — do the actual call first, then build telemetry.
    InterlockedIncrement(&g_InHook);

    NTSTATUS status = g_OriginalNtWriteVirtualMemory(
        ProcessHandle, BaseAddress, Buffer,
        NumberOfBytesToWrite, NumberOfBytesWritten);

    if (NT_SUCCESS(status))
    {
        DWORD srcPid = GetCurrentProcessId();
        DWORD targetPid = GetProcessId(ProcessHandle);

        if (targetPid != 0 && targetPid != srcPid)
        {
            EDR_WRITE_EVENT evt = { 0 };
            evt.EventType = EDR_EVENT_WRITE_MEMORY;
            evt.SrcPid = srcPid;
            evt.TargetPid = targetPid;
            evt.TargetHandle = ProcessHandle;
            evt.Address = BaseAddress;
            evt.Size = NumberOfBytesToWrite;

            QueueEvent(&evt);
        }
    }

    InterlockedDecrement(&g_InHook);
    return status;
}

// NtProtectVirtualMemory hook.
//
// No reentrancy guard needed: the trampoline jumps past our patch into
// the original syscall stub (mov r10,rcx / mov eax,imm / syscall).
// That path never calls back into MyNtProtectVirtualMemory.
//
// We do NOT use __declspec(thread) / TLS because NtProtectVirtualMemory
// is called by the loader during TLS initialization — accessing dynamic
// TLS before it's ready crashes the process.
//
// We also do NOT touch any TEB fields (ArbitraryUserPointer etc.)
// because Windows components actively use them and corrupting them
// breaks the loader / RPC / SenderThread.

NTSTATUS NTAPI MyNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) 
{
    // Pick the forwarding path once. Prefer the trampoline (no re-entry into
    // this function). Fall back to the raw syscall pointer if the trampoline
    // isn't installed yet (only happens during InstallHook's own VirtualProtect).
    //
    // CRITICAL: g_SyscallNtProtectVirtualMemory points at the start of the
    // patched ntdll stub — calling it re-enters MyNtProtectVirtualMemory.
    // The g_InHook guard catches it, but every fast-path return then does
    // TWO passes through this function. The trampoline avoids that.
    NtProtectVirtualMemory_t forward = g_OriginalNtProtectVirtualMemory
        ? g_OriginalNtProtectVirtualMemory
        : g_SyscallNtProtectVirtualMemory;

    // Cheap fast paths first — no syscalls, no locks.

    if (g_InHook)
        return forward(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    if (ProcessHandle == (HANDLE)-1)
        return forward(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    // Only EXECUTE-class transitions are interesting (RX, RWX, EXEC, EXEC_WRITECOPY).
    // PAGE_EXECUTE         = 0x10
    // PAGE_EXECUTE_READ    = 0x20
    // PAGE_EXECUTE_READWRITE = 0x40
    // PAGE_EXECUTE_WRITECOPY = 0x80
    // Mask 0xF0 catches all four. Skips ~95% of protect calls (RW->RO etc.)
    // BEFORE we pay for any extra syscalls.
    if (!(NewProtect & 0xF0))
        return forward(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    // Worth investigating — do the actual call, then build telemetry.
    InterlockedIncrement(&g_InHook);

    NTSTATUS status = forward(
        ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    if (NT_SUCCESS(status))
    {
        ULONG srcPid = GetCurrentProcessId();
        ULONG targetPid = GetProcessId(ProcessHandle);

        if (targetPid != 0 && targetPid != srcPid)
        {
            EDR_WRITE_EVENT evt = { 0 };
            evt.EventType = EDR_EVENT_PROTECT_MEMORY;
            evt.SrcPid = srcPid;
            evt.TargetPid = targetPid;
            evt.TargetHandle = ProcessHandle;
            evt.Address = BaseAddress ? *BaseAddress : NULL;
            evt.Size = RegionSize ? *RegionSize : 0;
            evt.OldProtect = OldProtect ? *OldProtect : 0;
            evt.NewProtect = NewProtect;
            QueueEvent(&evt);
        }
    }

    InterlockedDecrement(&g_InHook);
    return status;
}

NTSTATUS NTAPI MyNtResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
)
{
    if (g_InHook)
    {
        return g_OriginalNtResumeThread(
            ThreadHandle,
            PreviousSuspendCount
        );
    }

    InterlockedIncrement(&g_InHook);

    ULONG srcPid = GetCurrentProcessId();

    // Resolve target PID before resume.
    // Try direct call first — CreateProcess returns THREAD_ALL_ACCESS handles.
    DWORD targetPid = GetProcessIdOfThread(ThreadHandle);

    if (targetPid == 0)
    {
        // Fallback: duplicate with query rights in case the original handle
        // only has THREAD_SUSPEND_RESUME access.
        HANDLE hDup = NULL;
        if (DuplicateHandle(
            GetCurrentProcess(),
            ThreadHandle,
            GetCurrentProcess(),
            &hDup,
            THREAD_QUERY_LIMITED_INFORMATION,
            FALSE,
            0))
        {
            targetPid = GetProcessIdOfThread(hDup);
            CloseHandle(hDup);
        }
    }

    NTSTATUS status = g_OriginalNtResumeThread(
        ThreadHandle,
        PreviousSuspendCount
    );

    if (NT_SUCCESS(status) && targetPid != 0)
    {
        EDR_WRITE_EVENT evt = { 0 };

        evt.EventType = EDR_EVENT_RESUME_THREAD;
        evt.SrcPid = srcPid;
        evt.TargetPid = targetPid;
        evt.TargetHandle = ThreadHandle;
        evt.TargetTid = GetThreadId(ThreadHandle);

        QueueEvent(&evt);
    }

    InterlockedDecrement(&g_InHook);
    return status;
}

void InstallHook(void* target, void* hook, size_t patchLen)
{
    if (!target || !hook || patchLen < 14)
    {
        return;
    }

    DWORD oldProtect;

    if (!VirtualProtect(target, patchLen, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        return;
    }

    unsigned char patch[32] = { 0 };

    // mov rax, hook
    patch[0] = 0x48;
    patch[1] = 0xB8;
    *(void**)(patch + 2) = hook;

    // jmp rax
    patch[10] = 0xFF;
    patch[11] = 0xE0;

    // write patch
   // fill remaining bytes with NOPs
    for (size_t i = 12; i < patchLen; i++)
    {
        patch[i] = 0x90;
    }

    memcpy(target, patch, patchLen);

    // restore protection
    VirtualProtect(target, patchLen, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), target, patchLen);

}

DWORD WINAPI SenderThread(LPVOID)
{
    while (WaitForSingleObject(g_ShutdownEvent, 5) == WAIT_TIMEOUT)
    {
        LONG tail = g_QueueTail;
        LONG head = g_QueueHead;

        if (tail < head)
        {
            LONG index = tail % QUEUE_SIZE;
            EDR_WRITE_EVENT* evt = &g_EventQueue[index];

            if (g_DeviceHandle && g_DeviceHandle != INVALID_HANDLE_VALUE)
            {
                DWORD bytesReturned = 0;

                DeviceIoControl(
                    g_DeviceHandle,
                    IOCTL_EDR_WRITE_EVENT,
                    evt,
                    sizeof(EDR_WRITE_EVENT),
                    NULL,
                    0,
                    &bytesReturned,
                    NULL
                );
            }

            g_QueueTail = tail + 1;
        }
    }

    return 0;
}

void UninstallHook()
{
    if (!g_NtWriteVirtualMemory || g_NtWriteVirtualMemoryPatchLen == 0)
        return;

    DWORD oldProtect = 0;

    if (!VirtualProtect(g_NtWriteVirtualMemory, g_NtWriteVirtualMemoryPatchLen, PAGE_EXECUTE_READWRITE, &oldProtect))
        return;

    memcpy(
        g_NtWriteVirtualMemory,
        g_NtWriteVirtualMemoryOriginalBytes,
        g_NtWriteVirtualMemoryPatchLen
    );

    FlushInstructionCache(
        GetCurrentProcess(),
        g_NtWriteVirtualMemory,
        g_NtWriteVirtualMemoryPatchLen
    );

    VirtualProtect(g_NtWriteVirtualMemory, g_NtWriteVirtualMemoryPatchLen, oldProtect, &oldProtect);

    if (g_NtWriteVirtualMemoryTrampoline)
    {
        VirtualFree(g_NtWriteVirtualMemoryTrampoline, 0, MEM_RELEASE);
        g_NtWriteVirtualMemoryTrampoline = nullptr;
    }

    // ---- Uninstall NtProtectVirtualMemory hook ----
    if (g_NtProtectVirtualMemory && g_NtProtectVirtualMemoryPatchLen != 0)
    {
        DWORD oldProtect2 = 0;

        if (VirtualProtect(g_NtProtectVirtualMemory, g_NtProtectVirtualMemoryPatchLen, PAGE_EXECUTE_READWRITE, &oldProtect2))
        {
            memcpy(
                g_NtProtectVirtualMemory,
                g_NtProtectVirtualMemoryOriginalBytes,
                g_NtProtectVirtualMemoryPatchLen
            );

            FlushInstructionCache(
                GetCurrentProcess(),
                g_NtProtectVirtualMemory,
                g_NtProtectVirtualMemoryPatchLen
            );

            VirtualProtect(g_NtProtectVirtualMemory, g_NtProtectVirtualMemoryPatchLen, oldProtect2, &oldProtect2);
        }
    }
    
    if (g_NtProtectVirtualMemoryTrampoline)
    {
        VirtualFree(g_NtProtectVirtualMemoryTrampoline, 0, MEM_RELEASE);
        g_NtProtectVirtualMemoryTrampoline = nullptr;
    }

    // ---- Uninstall NtResumeThread hook ----
    if (g_NtResumeThread && g_NtResumeThreadPatchLen != 0)
    {
        DWORD oldProtect3 = 0;

        if (VirtualProtect(g_NtResumeThread, g_NtResumeThreadPatchLen, PAGE_EXECUTE_READWRITE, &oldProtect3))
        {
            memcpy(
                g_NtResumeThread,
                g_NtResumeThreadOriginalBytes,
                g_NtResumeThreadPatchLen
            );

            FlushInstructionCache(
                GetCurrentProcess(),
                g_NtResumeThread,
                g_NtResumeThreadPatchLen
            );

            VirtualProtect(g_NtResumeThread, g_NtResumeThreadPatchLen, oldProtect3, &oldProtect3);
        }

        if (g_NtResumeThreadTrampoline)
        {
            VirtualFree(g_NtResumeThreadTrampoline, 0, MEM_RELEASE);
            g_NtResumeThreadTrampoline = nullptr;
        }
    }
}
