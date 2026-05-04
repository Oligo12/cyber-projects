#include "shared.h"

static HANDLE g_Device = INVALID_HANDLE_VALUE;


BOOL DeviceOpen()
{
    g_Device = CreateFileA(
        "\\\\.\\MyEDR",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    return (g_Device != INVALID_HANDLE_VALUE);
}

BOOL DeviceRead(EDR_EVENT* buffer, DWORD count, DWORD* outCount)
{
    DWORD bytesRead = 0;

    if (!ReadFile(
        g_Device,
        buffer,
        sizeof(EDR_EVENT) * count,
        &bytesRead,
        NULL))
    {
        return FALSE;
    }

    *outCount = bytesRead / sizeof(EDR_EVENT);
    return TRUE;
}

BOOL DeviceResolveCreateTime(DWORD pid, LARGE_INTEGER* outCreateTime)
{
    if (!outCreateTime || g_Device == INVALID_HANDLE_VALUE)
        return FALSE;

    EDR_CREATETIME_QUERY q = { 0 };
    q.Pid = pid;

    DWORD bytesReturned = 0;

    BOOL ok = DeviceIoControl(
        g_Device,
        IOCTL_EDR_RESOLVE_CREATETIME,
        &q, sizeof(q),
        &q, sizeof(q),
        &bytesReturned,
        NULL
    );

    if (!ok || bytesReturned < sizeof(q))
    {
        outCreateTime->QuadPart = 0;
        return FALSE;
    }

    *outCreateTime = q.CreateTime;
    return TRUE;
}