#include <windows.h>
#include <stdio.h>
#include "shared.h"
#include "device.h"
#include "output.h"
#include "edrclient.h"
#include "detections.h"
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#include <map>
#include <string>
#include "parser.h"

std::map<DWORD, std::wstring> g_PidToName;

HMODULE GetRemoteKernel32(HANDLE hProcess)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            char modName[MAX_PATH];

            if (GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName)))
            {
                if (_stricmp(modName, "kernel32.dll") == 0)
                {
                    return hMods[i];
                }
            }
        }
    }

    return NULL;
}

BOOL InjectDLL(DWORD pid, const wchar_t* dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return FALSE;

    BOOL    success    = FALSE;
    void*   alloc      = NULL;
    HANDLE  hThread    = NULL;
    SIZE_T  pathBytes  = (wcslen(dllPath) + 1) * sizeof(wchar_t);

   // Resolve kernel32 in the target process before computing loadLibAddr.
   // On freshly-created processes, kernel32 may not be loaded yet, without
   // this check the remote thread would start at NULL + offset and crash the
   // target with STATUS_PRIVILEGED_INSTRUCTION.
    HMODULE hKernel32Remote = GetRemoteKernel32(hProcess);
    if (!hKernel32Remote)
    {
        printf("InjectDLL(%lu): kernel32 not yet loaded in target — skipping\n", pid);
        goto cleanup;
    }

    {
        HMODULE hKernel32Local = GetModuleHandleA("kernel32.dll");
        if (!hKernel32Local)
        {
            printf("GetModuleHandle(local kernel32) failed\n");
            goto cleanup;
        }

        FARPROC loadLibLocal = GetProcAddress(hKernel32Local, "LoadLibraryW");
        if (!loadLibLocal)
        {
            printf("GetProcAddress(LoadLibraryW) failed\n");
            goto cleanup;
        }

        DWORD_PTR offset = (DWORD_PTR)loadLibLocal - (DWORD_PTR)hKernel32Local;
        FARPROC loadLibAddr = (FARPROC)((DWORD_PTR)hKernel32Remote + offset);

        alloc = VirtualAllocEx(hProcess, NULL, pathBytes,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!alloc)
        {
            printf("VirtualAllocEx failed\n");
            goto cleanup;
        }

        SIZE_T written = 0;
        if (!WriteProcessMemory(hProcess, alloc, dllPath, pathBytes, &written) ||
            written != pathBytes)
        {
            printf("WriteProcessMemory failed\n");
            goto cleanup;
        }

        hThread = CreateRemoteThread(
            hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)loadLibAddr,
            alloc, 0, NULL);

        if (!hThread)
        {
            printf("CreateRemoteThread failed\n");
            goto cleanup;
        }

        WaitForSingleObject(hThread, 5000);

        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);

        // LoadLibraryW returns the HMODULE on success, NULL on failure.
        // Low 32 bits of the module base are never zero on success.
        if (exitCode == 0)
        {
            printf("InjectDLL(%lu): LoadLibraryW returned NULL in target\n", pid);
            goto cleanup;
        }

        success = TRUE;
    }

cleanup:
    if (hThread) CloseHandle(hThread);
    if (alloc)   VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
    if (hProcess) CloseHandle(hProcess);
    return success;
}

int main() {

    printf("START\n");

    InitLogFile();

    g_SensorPid = GetCurrentProcessId();

    FILETIME ftCreate = { 0 };
    FILETIME ftExit = { 0 };
    FILETIME ftKernel = { 0 };
    FILETIME ftUser = { 0 };

    if (GetProcessTimes(GetCurrentProcess(), &ftCreate, &ftExit, &ftKernel, &ftUser))
    {
        ULARGE_INTEGER uli;
        uli.LowPart = ftCreate.dwLowDateTime;
        uli.HighPart = ftCreate.dwHighDateTime;
        g_SensorCreateTime = uli.QuadPart;
    }

    if (!DeviceOpen()) {
        printf("Failed to open device\n");
        return 1;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (Process32First(snapshot, &pe))
    {
        do {
            g_PidToName[pe.th32ProcessID] = pe.szExeFile;

            // Seed g_ProcTable so pre-existing processes show names in alerts
            if (pe.th32ProcessID > 4)
            {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProc)
                {
                    WCHAR fullPath[260] = { 0 };
                    DWORD pathSize = _countof(fullPath);
                    QueryFullProcessImageNameW(hProc, 0, fullPath, &pathSize);

                    FILETIME ftSeedCreate = { 0 }, ftSeedExit = { 0 }, ftSeedKernel = { 0 }, ftSeedUser = { 0 };
                    GetProcessTimes(hProc, &ftSeedCreate, &ftSeedExit, &ftSeedKernel, &ftSeedUser);

                    ULARGE_INTEGER uli;
                    uli.LowPart = ftSeedCreate.dwLowDateTime;
                    uli.HighPart = ftSeedCreate.dwHighDateTime;

                    CloseHandle(hProc);

                    // Build a synthetic event to populate g_ProcTable
                    EDR_EVENT seedEvt = { 0 };
                    seedEvt.EventType = EDR_EVENT_PROCESS_CREATE;
                    seedEvt.ProcessId = (HANDLE)(ULONG_PTR)pe.th32ProcessID;
                    seedEvt.ParentProcessId = (HANDLE)(ULONG_PTR)pe.th32ParentProcessID;
                    seedEvt.ProcessCreateTime.QuadPart = uli.QuadPart;
                    wcscpy_s(seedEvt.ImagePath, fullPath);

                    TrackProcessCreate(&seedEvt);
                }
            }

            // PID 0 (System Idle) and PID 4 (System) are kernel-only
            if (pe.th32ProcessID <= 4)
                continue;

            if (_wcsicmp(pe.szExeFile, L"OSRLOADER.exe") == 0)
                continue;

            if (_wcsicmp(pe.szExeFile, L"EDRClient.exe") == 0)
                continue;

            if (_wcsicmp(pe.szExeFile, L"System") == 0)
                continue;

            if (_wcsicmp(pe.szExeFile, L"smss.exe") == 0)
                continue;

            if (_wcsicmp(pe.szExeFile, L"csrss.exe") == 0)
                continue;

            if (_wcsicmp(pe.szExeFile, L"wininit.exe") == 0)
                continue;

            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0)
                continue;

            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0)
                continue;

            if (_wcsicmp(pe.szExeFile, L"services.exe") == 0)
                continue;

            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0)
                continue;

            if (_wcsicmp(pe.szExeFile, L"Dbgview.exe") == 0)
                continue;

            if (IsProcessSuspended(pe.th32ProcessID))
            {
                LogExtra(L"[INJECT DEFERRED] PID=%lu (suspended at startup)\n", (ULONG)pe.th32ProcessID);
            }
            else
            {
                if (InjectDLL(pe.th32ProcessID, L"C:\\drivers\\EDRHookClean.dll"))
                    LogExtra(L"[INJECT OK] PID=%lu\n", (ULONG)pe.th32ProcessID);
                else
                    LogExtra(L"[INJECT FAIL] PID=%lu\n", (ULONG)pe.th32ProcessID);
            }
        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);

    while (1) {
        DWORD count = 0;

        if (DeviceRead(g_EventBuffer, 512, &count)) {

            for (DWORD i = 0; i < count; i++) {
                EDR_EVENT* evt = &g_EventBuffer[i];

                CleanupOldHandles(evt->Timestamp.QuadPart);
                HandleEvent(evt);
            }
        }
        ProcessSecCtxQueue();
        CleanupStaleInjectStates();
        DeferredInjectCleanup();
        Sleep(1);
    }
}