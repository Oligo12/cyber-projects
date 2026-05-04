#include "globals.h"
#include <ntifs.h>

VOID PushEvent(EDR_EVENT* evt)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EventQueue.Lock, &oldIrql);

    ULONG next = (g_EventQueue.Head + 1) % MAX_EVENTS;

    if (next != g_EventQueue.Tail)
    {
        g_EventQueue.Events[g_EventQueue.Head] = *evt;
        g_EventQueue.Head = next;
    }

    KeReleaseSpinLock(&g_EventQueue.Lock, oldIrql);
}
