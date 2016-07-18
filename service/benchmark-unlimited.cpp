
#define _CRT_NON_CONFORMING_SWPRINTFS
#define _CRT_SECURE_NO_WARNINGS

#include "benchmark-unlimited.hpp"

#include <stdio.h>
#include <malloc.h>
#include <ctype.h>

#include "strlcat.hpp"
#include "die.hpp"
#include "winerr.hpp"
#include "config.hpp"
#include "isadmin.hpp"
#include "winmain.hpp"


static WCHAR *g_lpszProgramName = NULL;
static WCHAR *g_lpszCommandLine = NULL;
static DWORD g_dwNumRuns = 0;
static DWORD g_dwCount = 0;
static CRITICAL_SECTION g_csApiMutex;


static
bool
GetNext(size_t *n)
{
	bool rv = false;

	EnterCriticalSection(&g_csApiMutex);
	if (g_dwCount < g_dwNumRuns) {
		*n = g_dwCount++;
		rv = true;
	}
	LeaveCriticalSection(&g_csApiMutex);

	return rv;
}


VOID
CALLBACK
WorkerRoutine(PTP_CALLBACK_INSTANCE Instance, PVOID lpParameter, PTP_WORK Work)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));

	si.cb = sizeof(si);

	size_t n = 0;
	bool rv = GetNext(&n);
	if (!rv) return;

	if (!CreateProcessW(g_lpszProgramName, g_lpszCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		fwprintf(stderr, L"Error creating process: %ls\n", ErrorText(GetLastError()));
		ExitProcess(-1);
	} else {
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
}


static
void
LoadConfigData(CONFIG_DATA *cd, WCHAR lpszTarget[MAX_PATH+1], DWORD *dwNumRuns, DWORD *dwDuration)
{
	GetPrivateProfileStringW(L"UlBenchmarkData", L"LastBenchmarkTarget", L"", lpszTarget, MAX_PATH, cd->szConfigFile);
	lpszTarget[MAX_PATH] = '\0';
	*dwDuration = GetPrivateProfileIntW(L"UlBenchmarkData", L"LastBenchmarkDuration", 0, cd->szConfigFile);
	*dwNumRuns = GetPrivateProfileIntW(L"UlBenchmarkData", L"LastBenchmarkNumberOfRuns", 0, cd->szConfigFile);
}


static
void
SaveConfigData(CONFIG_DATA *cd, WCHAR *lpszTarget, DWORD dwNumRuns, DWORD dwDuration)
{
	WCHAR szValue[256];
	WritePrivateProfileStringW(L"UlBenchmarkData", L"LastBenchmarkTarget", lpszTarget, cd->szConfigFile);
	swprintf(szValue, L"%u", dwDuration);
	WritePrivateProfileStringW(L"UlBenchmarkData", L"LastBenchmarkDuration", szValue, cd->szConfigFile);
	swprintf(szValue, L"%u", dwNumRuns);
	WritePrivateProfileStringW(L"UlBenchmarkData", L"LastBenchmarkNumberOfRuns", szValue, cd->szConfigFile);
}


static inline
double
PercentDelta(double rOld, double rNew)
{
	if (rOld == 0.0) return 0.0;
	return (rNew / rOld) * 100.0 - 100.0;
}


int
BenchmarkUnlimited(int argc, WCHAR *argv[])
{
	CONFIG_DATA *cd = GetConfigData();

	if (!IsAdmin()) {
		fprintf(stderr, "This feature requires administrator privileges.\n");
		ExitProcess(-1);
	}

	bool bBaseline = IsProcFilterServiceRunning();
	if (bBaseline) {
		wprintf(L"ProcFilter not running; running and storing baseline tests...\n");
	} else {
		wprintf(L"ProcFilter running; running comparison against baseline...\n");
	}

	InitializeCriticalSection(&g_csApiMutex);

	if (argc < 4) return -1;

	if (argc > 4) {
		size_t dwCommandLineSize = sizeof(WCHAR)*wcslen(GetCommandLineW()) + 1;
		g_lpszCommandLine = (WCHAR*)malloc(dwCommandLineSize);
		if (!g_lpszCommandLine) Die("No memory for command line");
		g_lpszCommandLine[0] = '\0';
		for (int i = 3; i < argc; ++i) {
			if (i > 3) wstrlcatf(g_lpszCommandLine, dwCommandLineSize, L" ");
			wstrlcatf(g_lpszCommandLine, dwCommandLineSize, L"%s", argv[i]);
		}
	}
	
	g_dwNumRuns = _wtoi(argv[2]);
	g_lpszProgramName = argv[3];
	PTP_WORK pool = CreateThreadpoolWork(WorkerRoutine, NULL, NULL);
	if (!pool) Die("Unable to create threadpool");
	
	DWORD dwStartTick = GetTickCount();

	for (DWORD i = 0; i < g_dwNumRuns; ++i) {
		SubmitThreadpoolWork(pool);
	}

	BOOL rc = FALSE;
	
	WaitForThreadpoolWorkCallbacks(pool, FALSE);
	CloseThreadpoolWork(pool);

	DWORD dwDuration = GetTickCount() - dwStartTick;

	// prior program was the same; show the delta
	if (bBaseline) {
		SaveConfigData(cd, g_lpszProgramName, g_dwNumRuns, dwDuration);
		wprintf(L"Baseline data saved\n");
	} else {
		WCHAR szOldTarget[MAX_PATH+1];
		DWORD dwOldNumRuns;
		DWORD dwOldDuration;
		LoadConfigData(cd, szOldTarget, &dwOldNumRuns, &dwOldDuration);
		if (_wcsicmp(szOldTarget, g_lpszProgramName) == 0 && g_dwNumRuns > 0 && dwOldNumRuns == g_dwNumRuns) {
			double rDuration = (double)dwDuration;
			double rOldDuration = (double)dwOldDuration;
			double rDelta = rDuration - rOldDuration;
			wprintf(L"Baseline:    %u\n", dwOldNumRuns);
			wprintf(L"Delta:      %+.03f seconds\n", rDelta / 1000.0);
			double rPercentDelta = PercentDelta(rOldDuration, rDuration);
			wprintf(L"%% Delta:    %+.03f%% %hs in running time\n", rPercentDelta, rPercentDelta >= 0.0 ? "increase" : "decrease");
		} else {
			wprintf(L"Baseline data for this type of test not found; rerun with ProcFilter off to set it\n");
		}
	}
	
	wprintf(L"Total time:  %u.%.03u seconds\n", dwDuration / 1000, dwDuration % 1000);

	DeleteCriticalSection(&g_csApiMutex);

	free(g_lpszCommandLine);

	return 0;
}

