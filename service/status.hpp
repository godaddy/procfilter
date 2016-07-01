
#pragma once

#include <Windows.h>

#include <stdint.h>

//
// Init/shutdown the status init engine
//
void StatusInit();
void StatusShutdown();

#define STAT_TYPE_DOUBLE 0
#define STAT_TYPE_DWORD 1
#define STAT_TYPE_QWORD 2

//
// Query the stats subsystem in another procfilter.exe process.  This call does not
// require a all to StatsInit().
//
void StatusQuery();

//
// This prints out a string to the procfilter.exe requesting a stats query.
//
void StatusPrint(const WCHAR *lpszFmt, ...); // may only be called indirectly by the stats module
void WINAPI Export_StatusPrintFmt(const WCHAR *lpszFmt, ...);
