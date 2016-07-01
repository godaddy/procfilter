

#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <tchar.h>
#include <stdarg.h>
#include <stdio.h>

#include "die.hpp"
#include "config.hpp"
#include "strlcat.hpp"
#include "shellnotice.hpp"
#include "ProcFilterEvents.h"

#define FATAL_LOG (L"C:\\procfilter_fatal.log")


static CRITICAL_SECTION g_cs;

void
DieInit()
{
	InitializeCriticalSection(&g_cs);
}


void
DieShutdown()
{
	DeleteCriticalSection(&g_cs);
}


void
_Die(const char *file, int line, const char *fmt, ...)
{
	// Lock the mutex to prevent concurrent fatal errors from happening
	EnterCriticalSection(&g_cs);

	va_list ap;
	va_start(ap, fmt);

	// Send the error to windows event log
	char error[1024] = { '\0' };
	vsnprintf(error, sizeof(error)-1, fmt, ap);
	EventWriteFATAL_ERROR(error);

	WCHAR szExePath[MAX_PATH+1] = { '\0' };
	if (GetModuleFileName(NULL, szExePath, sizeof(szExePath)/sizeof(WCHAR) - 1)) {
		// By default use the .exe's directory as the working path, unless the config file specifies otherwise
		WCHAR drive[MAX_PATH+1] = { '\0' };
		WCHAR dir[MAX_PATH+1] = { '\0' };
		WCHAR szBaseDirectory[MAX_PATH+1] = { '\0' };

		_wsplitpath_s(szExePath, drive, sizeof(drive)/sizeof(WCHAR), dir, sizeof(dir)/sizeof(WCHAR), NULL, 0, NULL, 0);
		wstrlprintf(szBaseDirectory, sizeof(szBaseDirectory), L"%ls%ls", drive, dir);

		WCHAR szFatalLog[MAX_PATH+1] = { '\0' };
		wstrlprintf(szFatalLog, sizeof(szFatalLog), L"%ls%hs", szBaseDirectory, "fatal.log");

		// Write the error string to a file on disk
		FILE *f = _wfopen(szFatalLog, L"a+");
		if (!f) f = _wfopen(FATAL_LOG, L"a+");
		if (f) {
			fprintf(f, "%s(%d): %s\r\n", file, line, error);
			fclose(f);
		}
	}

	va_end(ap);

	// Raise a notice to the user
	ShellNoticeFmt(60, false, MB_OK | MB_ICONWARNING, L"ProcFilter Fatal Error", L"%hs", error);

	// Bail
	ExitProcess(-1);

	DeleteCriticalSection(&g_cs);
}
