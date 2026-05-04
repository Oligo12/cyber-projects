#pragma once
#include "shared.h"

void HandleEvent(EDR_EVENT* evt);
void EnrichThreadMemory(EDR_EVENT* evt);
void InitLogFile();
void PrintLine(const WCHAR* line);
void LogExtra(const WCHAR* fmt, ...);