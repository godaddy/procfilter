//
// The MIT License (MIT)
//
// Copyright (c) 2016 GoDaddy Operating Company, LLC.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//

#include "benchmark-timed.hpp"

#include <stdio.h>

#include "threadpool.hpp"
#include "config.hpp"
#include "strlcat.hpp"
#include "die.hpp"
#include "isadmin.hpp"
#include "winerr.hpp"
#include "winmain.hpp"


static WCHAR *g_lpszCommandLine = NULL;
static WCHAR *g_lpszProgramName = NULL;


static
void
LoadConfigData(CONFIG_DATA *cd, WCHAR lpszTarget[MAX_PATH+1], DWORD64 *dwNumRuns, DWORD64 *dwDuration, int *dwPoolSize)
{
	GetPrivateProfileStringW(L"LBenchmarkData", L"LastBenchmarkTarget", L"", lpszTarget, MAX_PATH, cd->szConfigFile);
	lpszTarget[MAX_PATH] = '\0';

	WCHAR szValue[256] = { '\0' };
	
	GetPrivateProfileStringW(L"LBenchmarkData", L"LastNumRuns", L"", szValue, sizeof(szValue)-1, cd->szConfigFile);
	*dwNumRuns = _wtoi64(szValue);
	GetPrivateProfileStringW(L"LBenchmarkData", L"LastDuration", L"", szValue, sizeof(szValue)-1, cd->szConfigFile);
	*dwDuration = _wtoi64(szValue);
	GetPrivateProfileStringW(L"LBenchmarkData", L"LastPoolSize", L"", szValue, sizeof(szValue)-1, cd->szConfigFile);
	*dwPoolSize = _wtoi(szValue);
}


static
void
SaveConfigData(CONFIG_DATA *cd, WCHAR *lpszTarget, DWORD64 dwNumRuns, DWORD64 dwDuration, int dwPoolSize)
{
	WCHAR szValue[256];
	WritePrivateProfileStringW(L"LBenchmarkData", L"LastBenchmarkTarget", lpszTarget, cd->szConfigFile);
	swprintf(szValue, _countof(szValue), L"%I64u", dwDuration);
	WritePrivateProfileStringW(L"LBenchmarkData", L"LastDuration", szValue, cd->szConfigFile);
	swprintf(szValue, _countof(szValue), L"%I64u", dwNumRuns);
	WritePrivateProfileStringW(L"LBenchmarkData", L"LastNumRuns", szValue, cd->szConfigFile);
	swprintf(szValue, _countof(szValue), L"%d", dwPoolSize);
	WritePrivateProfileStringW(L"LBenchmarkData", L"LastPoolSize", szValue, cd->szConfigFile);
}


void
WorkFunction(void *lpPoolData, void *lpThreadData, void *lpTaskData, bool bCancel)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));

	si.cb = sizeof(si);

	if (!CreateProcessW(g_lpszProgramName, g_lpszCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		fwprintf(stderr, L"Error creating process: %ls\n", ErrorText(GetLastError()));
		ExitProcess(-1);
	} else {
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
}


static inline
double
PercentDelta(double rOld, double rNew)
{
	if (rOld == 0.0) return 0.0;
	return (rNew / rOld) * 100.0 - 100.0;
}


int
BenchmarkTimed(int argc, WCHAR *argv[])
{
	CONFIG_DATA *cd = GetConfigData();

	if (!IsAdmin()) {
		fprintf(stderr, "This feature requires administrator privileges.\n");
		ExitProcess(-1);
	}

	if (argc < 5) return -1;

	if (argc > 5) {
		size_t dwCommandLineSize = sizeof(WCHAR)*wcslen(GetCommandLineW()) + 1;
		g_lpszCommandLine = (WCHAR*)malloc(dwCommandLineSize);
		if (!g_lpszCommandLine) Die("No memory for command line");
		g_lpszCommandLine[0] = '\0';
		for (int i = 4; i < argc; ++i) {
			if (i > 4) wstrlcatf(g_lpszCommandLine, dwCommandLineSize, L" ");
			wstrlcatf(g_lpszCommandLine, dwCommandLineSize, L"%s", argv[i]);
		}
	}

	bool bBaseline = IsProcFilterServiceRunning();
	if (bBaseline) {
		wprintf(L"ProcFilter not running; running and storing baseline tests...\n");
	} else {
		wprintf(L"ProcFilter running; running comparison against baseline...\n");
	}
	
	int dwPoolSize = _wtoi(argv[2]);
	DWORD64 dwDuration = _wtoi64(argv[3]) * 1000 * 60; // convert from minutes to milliseconds
	g_lpszProgramName = argv[4];
	THREADPOOL *tp = ThreadPoolAlloc(dwPoolSize, 0, NULL, WorkFunction, NULL, NULL, 0, 0);
	if (!tp) Die("Unable to create threadpool");
	
	DWORD64 dwNumRuns = 0;
	DWORD64 dwStartTick = GetTickCount64();
	do {
		ThreadPoolPost(tp, 0, true, NULL, NULL);
		++dwNumRuns;
	} while (GetTickCount64() - dwStartTick < dwDuration);
	ThreadPoolFree(tp);
	DWORD64 dwEndTick = GetTickCount64();

	if (bBaseline) {
		SaveConfigData(cd, g_lpszProgramName, dwNumRuns, dwDuration, dwPoolSize);
		wprintf(L"Baseline data saved\n");
	} else {
		WCHAR szOldTarget[MAX_PATH+1];
		DWORD64 dwOldNumRuns = 0;
		DWORD64 dwOldDuration = 0;
		int dwOldPoolSize = 0;

		LoadConfigData(cd, szOldTarget, &dwOldNumRuns, &dwOldDuration, &dwOldPoolSize);
		if (_wcsicmp(szOldTarget, g_lpszProgramName) == 0 && dwOldDuration == dwDuration && dwOldPoolSize == dwPoolSize) {
			wprintf(L"Old Runs:    %I64u\n", dwOldNumRuns);
			wprintf(L"Delta:       %hs%I64d runs\n", dwNumRuns >= dwOldNumRuns ? "+" : "", dwNumRuns - dwOldNumRuns);\
			double fPercentDelta = PercentDelta((double)dwOldNumRuns, (double)dwNumRuns);
			wprintf(L"%% Delta:     %+.03f%% %hs in process throughput\n", fPercentDelta, fPercentDelta >= 0.0 ? "increase" : "decrease");
		} else {
			wprintf(L"Baseline data for this type of test not found; rerun with ProcFilter off to set it\n");
		}
	}
	
	wprintf(L"Total Runs:  %I64u\n", dwNumRuns);

	free(g_lpszCommandLine);

	return 0;
}