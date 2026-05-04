#pragma once
#include "shared.h"

void DetectionHandleEvent(EDR_EVENT* evt);
void DetectionWriteEvent(EDR_EVENT* evt);
void DetectionThreadEvent(EDR_EVENT* evt, ULONG inferredSrc, MEMORY_BASIC_INFORMATION* mbi);
void DetectionResumeEvent(EDR_EVENT* evt);
void DetectionProtectEvent(EDR_EVENT* evt);
void CleanupStaleInjectStates();