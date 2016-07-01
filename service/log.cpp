
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <tchar.h>

#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include "ProcFilterEvents.h"

#include "config.hpp"

#include "log.hpp"


static CRITICAL_SECTION g_LogCs;


void
LogInit()
{
	InitializeCriticalSection(&g_LogCs);
}


void
LogShutdown()
{
	DeleteCriticalSection(&g_LogCs);
}


//
// Log the timestamp/level prefix to file
//
static
void
print_prefix(FILE *f, int level)
{
	time_t t = time(NULL);
	struct tm tmp;
	localtime_s(&tmp, &t);

	WCHAR timestamp[64] = { 0 };
	wcsftime(timestamp, sizeof(timestamp)/sizeof(WCHAR), L"%c", &tmp);

	fwprintf(f, L"[%s] [%d] ", timestamp, level);
}


//
// Log the line suffix to file
//
static
void
print_suffix(FILE *f)
{
	fwprintf(f, L"%s", L"\n");
}


void
Log(DWORD level, const char *str)
{
	LogFmt(level, "%s", str);
}


//
// Log a string to log file at a particular level
//
void
LogFmt(DWORD level, const char *fmt, ...)
{
	const CONFIG_DATA *cd = GetConfigData();

	if (level < cd->dwLogLevel) return;

	va_list ap;
	va_start(ap, fmt);
	
	EnterCriticalSection(&g_LogCs);
	FILE *f = _wfopen(cd->szLogFile, L"a+");
	if (f) {
		print_prefix(f, level);

		vfprintf(f, fmt, ap);
		print_suffix(f);

		fclose(f);
	}
	LeaveCriticalSection(&g_LogCs);

	va_end(ap);
}
