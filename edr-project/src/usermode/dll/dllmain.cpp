#include <Zydis/Zydis.h>
#include "pch.h"
#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <TlHelp32.h>

DWORD WINAPI SenderThread(LPVOID);

extern HANDLE g_DeviceHandle;
extern HANDLE g_ShutdownEvent;
extern void InitZydis();
extern void ResolveTargets();
extern size_t CalculatePatchLength(void* target);
extern void* g_NtWriteVirtualMemory;
extern void* g_NtWriteVirtualMemoryTrampoline;
extern size_t g_NtWriteVirtualMemoryPatchLen;
extern void SaveOriginalBytes(void* target, size_t patchLen, unsigned char* outBuffer);
extern void BuildTrampoline(void* target, size_t patchLen, void** outTrampoline);
extern void InstallHook(void* target, void* hook, size_t patchLen);
extern void UninstallHook();
extern unsigned char g_NtWriteVirtualMemoryOriginalBytes[32];
extern unsigned char g_NtProtectVirtualMemoryOriginalBytes[32];
extern NTSTATUS NTAPI MyNtWriteVirtualMemory(
    HANDLE,
    PVOID,
    PVOID,
    SIZE_T,
    PSIZE_T
);
extern void* g_NtProtectVirtualMemory;
extern size_t g_NtProtectVirtualMemoryPatchLen;
extern void* g_NtProtectVirtualMemoryTrampoline;

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE,
    PVOID*,
    PSIZE_T,
    ULONG,
    PULONG
    );

extern NtProtectVirtualMemory_t g_OriginalNtProtectVirtualMemory;

extern NTSTATUS NTAPI MyNtProtectVirtualMemory(
    HANDLE,
    PVOID*,
    PSIZE_T,
    ULONG,
    PULONG
);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
    HANDLE,
    PVOID,
    PVOID,
    SIZE_T,
    PSIZE_T
    );

extern NtWriteVirtualMemory_t g_OriginalNtWriteVirtualMemory;
extern void* g_NtResumeThread;
extern size_t g_NtResumeThreadPatchLen;
extern void* g_NtResumeThreadTrampoline;
extern unsigned char g_NtResumeThreadOriginalBytes[32];

typedef NTSTATUS(NTAPI* NtResumeThread_t)(
    HANDLE,
    PULONG
    );

extern NtResumeThread_t g_OriginalNtResumeThread;

extern NTSTATUS NTAPI MyNtResumeThread(
    HANDLE,
    PULONG
);

DWORD WINAPI InitHooksThread(LPVOID)
{
    InitZydis();
    ResolveTargets();

    g_DeviceHandle = CreateFileA(
        "\\\\.\\MyEDR",
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,  
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (g_DeviceHandle == INVALID_HANDLE_VALUE)
    {
        return 0;
    }


    // ---- NtWriteVirtualMemory hook ----

    g_NtWriteVirtualMemoryPatchLen = CalculatePatchLength(g_NtWriteVirtualMemory);
    SaveOriginalBytes(
        g_NtWriteVirtualMemory,
        g_NtWriteVirtualMemoryPatchLen,
        g_NtWriteVirtualMemoryOriginalBytes
    );
    BuildTrampoline(
        g_NtWriteVirtualMemory,
        g_NtWriteVirtualMemoryPatchLen,
        &g_NtWriteVirtualMemoryTrampoline
    );

    if (!g_NtWriteVirtualMemoryTrampoline)
        return 0;

    g_OriginalNtWriteVirtualMemory =
        (NtWriteVirtualMemory_t)g_NtWriteVirtualMemoryTrampoline;

    InstallHook(
        g_NtWriteVirtualMemory,
        (void*)MyNtWriteVirtualMemory,
        g_NtWriteVirtualMemoryPatchLen
    );  

    // ---- NtProtectVirtualMemory hook ----

    g_NtProtectVirtualMemoryPatchLen = CalculatePatchLength(g_NtProtectVirtualMemory);

    if (g_NtProtectVirtualMemoryPatchLen == 0)
        return 0;

    SaveOriginalBytes(
        g_NtProtectVirtualMemory,
        g_NtProtectVirtualMemoryPatchLen,
        g_NtProtectVirtualMemoryOriginalBytes
    );

    BuildTrampoline(
        g_NtProtectVirtualMemory,
        g_NtProtectVirtualMemoryPatchLen,
        &g_NtProtectVirtualMemoryTrampoline
    );

    if (!g_NtProtectVirtualMemoryTrampoline)
        return 0;

    g_OriginalNtProtectVirtualMemory =
        (NtProtectVirtualMemory_t)g_NtProtectVirtualMemoryTrampoline;

    InstallHook(
        g_NtProtectVirtualMemory,
        (void*)MyNtProtectVirtualMemory,
        g_NtProtectVirtualMemoryPatchLen
    );
   
    // ---- NtResumeThread hook ----  
     
    g_NtResumeThreadPatchLen = CalculatePatchLength(g_NtResumeThread);

    if (g_NtResumeThreadPatchLen == 0)
        return 0;

    SaveOriginalBytes(
        g_NtResumeThread,
        g_NtResumeThreadPatchLen,
        g_NtResumeThreadOriginalBytes
    );

    BuildTrampoline(
        g_NtResumeThread,
        g_NtResumeThreadPatchLen,
        &g_NtResumeThreadTrampoline
    );

    if (!g_NtResumeThreadTrampoline)
        return 0;

    g_OriginalNtResumeThread =
        (NtResumeThread_t)g_NtResumeThreadTrampoline;

    InstallHook(
        g_NtResumeThread,
        (void*)MyNtResumeThread,
        g_NtResumeThreadPatchLen
    );  

    g_ShutdownEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    CreateThread(NULL, 0, SenderThread, NULL, 0, NULL);

    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InitHooksThread, NULL, 0, NULL);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        // Signal sender thread to stop, then wait briefly for it to finish
        if (g_ShutdownEvent)
        {
            SetEvent(g_ShutdownEvent);
            Sleep(50); // give sender thread time to exit
            CloseHandle(g_ShutdownEvent);
            g_ShutdownEvent = NULL;
        }

        UninstallHook();

        if (g_DeviceHandle && g_DeviceHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(g_DeviceHandle);
            g_DeviceHandle = INVALID_HANDLE_VALUE;
        }
        break;
    }
    return TRUE;
}
