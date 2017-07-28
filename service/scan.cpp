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

#include <Windows.h>

#include <malloc.h>

#include "scan.hpp"

#include "config.hpp"
#include "quarantine.hpp"
#include "hash.hpp"
#include "die.hpp"
#include "log.hpp"
#include "status.hpp"
#include "umdriver.hpp"
#include "timing.hpp"
#include "minmaxavg.hpp"
#include "terminate.hpp"
#include "ProcFilterEvents.h"

#pragma comment(lib, "kernel32.lib")


typedef struct stats STATS;
struct stats {
	WCHAR *lpszScanName; // The scan name associated with the stats 
	MMA    mma;          // The moving average
};

static STATS g_Stats[PROCFILTER_NUM_CONTEXTS + 1];

void
ScanInit()
{
	ZeroMemory(g_Stats, sizeof(g_Stats));

	for (int i = 0; i < PROCFILTER_NUM_CONTEXTS + 1; ++i) {
		MmaInit(&g_Stats[i].mma);
	}
	
	g_Stats[PROCFILTER_SCAN_CONTEXT_PROCESS_CREATE].lpszScanName = L"Creation";
	g_Stats[PROCFILTER_SCAN_CONTEXT_PROCESS_TERMINATE].lpszScanName = L"Termination";
	g_Stats[PROCFILTER_SCAN_CONTEXT_PERIODIC_SCAN].lpszScanName = L"Periodic";
	g_Stats[PROCFILTER_SCAN_CONTEXT_IMAGE_LOAD].lpszScanName = L"ImageLoad";
	g_Stats[PROCFILTER_NUM_CONTEXTS].lpszScanName = L"AllTypes";
}


void
ScanShutdown()
{
	for (int i = 0; i < PROCFILTER_NUM_CONTEXTS + 1; ++i) {
		MmaDestroy(&g_Stats[i].mma);
	}
}


void
ScanStatusPrint()
{
	LONG64 llFrequency = GetPerformanceFrequency();
	MMA_DATA mdTotal;
	ZeroMemory(&mdTotal, sizeof(MMA_DATA));
	for (int i = 0; i < PROCFILTER_NUM_CONTEXTS + 1; ++i) {
		WCHAR *lpszName = NULL;
		MMA_DATA md;

		lpszName = g_Stats[i].lpszScanName;
		md = MmaGet(&g_Stats[i].mma);
		
		LONG64 llSma = (LONG64)md.rSma;
		double rWeight = MmaGetWeight(&g_Stats[i].mma);
	
		StatusPrint(L"%11ls->TotalScans        = %I64d\n", lpszName, md.llNum);
		StatusPrint(L"%11ls->MinTimeScanning   = %I64d.%03I64d seconds\n",
			lpszName, GetPerformanceSeconds(md.llMin, llFrequency), GetPerformanceMilliseconds(md.llMin, llFrequency) % 1000);
		StatusPrint(L"%11ls->MaxTimeScanning   = %I64d.%03I64d seconds\n",
			lpszName, GetPerformanceSeconds(md.llMax, llFrequency), GetPerformanceMilliseconds(md.llMax, llFrequency) % 1000);
		StatusPrint(L"%11ls->AvgTimeScanning   = %I64d.%03I64d seconds (SMA Weight=%0.02f)\n",
			lpszName, GetPerformanceSeconds(llSma, llFrequency), GetPerformanceMilliseconds(llSma, llFrequency) % 1000, rWeight);
		StatusPrint(L"%11ls->TotalTimeScanning = %I64d.%03I64d seconds\n",
			lpszName, GetPerformanceSeconds(md.llTotalSum, llFrequency), GetPerformanceMilliseconds(md.llTotalSum, llFrequency) % 1000);
		StatusPrint(L"\n");
	}
	StatusPrint(L" * Time counts include plugins\n");
}


typedef struct callback_user_data CALLBACK_USER_DATA;
struct callback_user_data {
	PROCFILTER_EVENT *e;
	DWORD dwProcessId;
	WCHAR *lpszFileName;
	void *lpvScanDataArray;
	int dScanContext;
	int dMatchLocation;
};


static
void
OnMatchCallback(char *lpszRuleName, void *user_data)
{
	CALLBACK_USER_DATA *cud = (CALLBACK_USER_DATA*)user_data;
	PROCFILTER_EVENT *e = cud->e;

	ApiEventReinit(e, PROCFILTER_EVENT_YARA_RULE_MATCH);
	e->dwProcessId = cud->dwProcessId;
	e->lpszFileName = cud->lpszFileName;
	e->lpvScanData = cud->lpvScanDataArray;
	e->dMatchLocation = cud->dMatchLocation;
	e->dScanContext = cud->dScanContext;
	e->lpszRuleName = lpszRuleName;

	ApiEventExport(e);
}


static
void
OnMetaCallback(char *lpszRuleName, char *lpszMetaTagName, char *lpszStringValue, int64_t dNumericValue, void *user_data)
{
	CALLBACK_USER_DATA *cud = (CALLBACK_USER_DATA*)user_data;
	PROCFILTER_EVENT *e = cud->e;

	ApiEventReinit(e, PROCFILTER_EVENT_YARA_RULE_MATCH_META_TAG);
	e->dwProcessId = cud->dwProcessId;
	e->lpszFileName = cud->lpszFileName;
	e->lpvScanData = cud->lpvScanDataArray;
	e->dMatchLocation = cud->dMatchLocation;
	e->dScanContext = cud->dScanContext;
	e->lpszRuleName = lpszRuleName;
	e->lpszStringValue = lpszStringValue;
	e->dNumericValue = dNumericValue;
	e->lpszMetaTagName = lpszMetaTagName;

	ApiEventExport(e);
}


//
// Perform the scanning as specified in the various input parameters
//
void
Scan(DWORD dwEventType, int dScanContext, PROCFILTER_EVENT *e, YARASCAN_CONTEXT *ctx, HANDLE hDriver, HANDLE hWriteCompletionEvent, DWORD dwProcessId, DWORD dwParentProcessId, WCHAR *lpszFileName, void *lpImageBase, void *lpvScanDataArray)
{
	if (!lpszFileName) return;

	LONG64 llStart = GetPerformanceCount();

	CONFIG_DATA *cd = GetConfigData();

	bool bScanFile = false;
	bool bScanMemory = false;
	
	bool bBlock = false;
	bool bLog = false;
	bool bQuarantine = false;

	// Pull the scan parameters out of config
	if (dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_CREATE) {
		bScanFile = cd->bScanFileOnProcessCreate;
		bScanMemory = cd->bScanMemoryOnProcessCreate;
	} else if (dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_TERMINATE) {
		bScanFile = cd->bScanFileOnProcessTerminate;
		bScanMemory = cd->bScanMemoryOnProcessTerminate;
	} else if (dScanContext == PROCFILTER_SCAN_CONTEXT_PERIODIC_SCAN) {
		bScanFile = cd->bScanFileOnPeriodic;
		bScanMemory = cd->bScanMemoryOnPeriodic;
	} else if (dScanContext == PROCFILTER_SCAN_CONTEXT_IMAGE_LOAD) {
		bScanFile = cd->bScanFileOnImageLoad;
		bScanMemory = cd->bScanMemoryOnImageLoad;
	} else {
		Die("Invalid context passed to Scan(): %d", dScanContext);
	}

	// Initialize the API event with the passed-in parameters
	ApiEventReinit(e, PROCFILTER_EVENT_YARA_SCAN_INIT);
	e->dwProcessId = dwProcessId;
	e->dwParentProcessId = dwParentProcessId;
	e->lpszFileName = lpszFileName;
	e->dScanContext = dScanContext;
	e->bScanFile = bScanFile;
	e->bScanMemory = bScanMemory;
	e->lpvScanData = lpvScanDataArray;

	// Export the event to the API and handle the result flags
	DWORD dwPluginResultFlags = ApiEventExport(e);
	if (dwPluginResultFlags & PROCFILTER_RESULT_BLOCK_PROCESS)     bBlock = true;
	if (dwPluginResultFlags & PROCFILTER_RESULT_DONT_SCAN_MEMORY)  bScanMemory = false;
	if (dwPluginResultFlags & PROCFILTER_RESULT_FORCE_SCAN_MEMORY) bScanMemory = true;
	if (dwPluginResultFlags & PROCFILTER_RESULT_DONT_SCAN_FILE)    bScanFile = false;
	if (dwPluginResultFlags & PROCFILTER_RESULT_FORCE_SCAN_FILE)   bScanFile = true;
	if (dwPluginResultFlags & PROCFILTER_RESULT_QUARANTINE)        bQuarantine = true;
	
	// Scan the file if requested
	SCAN_RESULT srFileResult;
	ZeroMemory(&srFileResult, sizeof(SCAN_RESULT));
	if (bScanFile) {
		CALLBACK_USER_DATA cud = { e, dwProcessId, lpszFileName, lpvScanDataArray, dScanContext, PROCFILTER_MATCH_FILE };
		YarascanScanFile(ctx, lpszFileName, cd->dwScanFileSizeLimit, OnMatchCallback, OnMetaCallback, &cud, &srFileResult);
		if (srFileResult.bScanSuccessful) {
			bBlock |= srFileResult.bBlock;
			bLog |= srFileResult.bLog;
			bQuarantine |= srFileResult.bQuarantine;
		} else {
			EventWriteSCAN_FILE_FAILED(dwProcessId, lpszFileName, srFileResult.szError);
		}
	}
	
	// Scan the memory if requested
	SCAN_RESULT srMemoryResult;
	ZeroMemory(&srMemoryResult, sizeof(SCAN_RESULT));
	if (bScanMemory) {
		CALLBACK_USER_DATA cud = { e, dwProcessId, lpszFileName, lpvScanDataArray, dScanContext, PROCFILTER_MATCH_MEMORY };
		YarascanScanMemory(ctx, dwProcessId, OnMatchCallback, OnMetaCallback, &cud, &srMemoryResult);
		if (srMemoryResult.bScanSuccessful) {
			bBlock |= srMemoryResult.bBlock;
			bLog |= srMemoryResult.bLog;
			bQuarantine |= srMemoryResult.bQuarantine;
		} else {
			EventWriteSCAN_PROCESS_FAILED(dwProcessId, lpszFileName, srMemoryResult.szError);
		}
	}

	// Export the scan results to plugins
	ApiEventReinit(e, PROCFILTER_EVENT_YARA_SCAN_COMPLETE);
	e->dwProcessId = dwProcessId;
	e->dwParentProcessId = dwParentProcessId;
	e->lpszFileName = lpszFileName;
	e->dScanContext = dScanContext;
	e->srFileResult = bScanFile ? &srFileResult : NULL;
	e->srMemoryResult = bScanMemory ? &srMemoryResult : NULL;
	e->bBlockProcess = bBlock;
	e->lpvScanData = lpvScanDataArray;
	dwPluginResultFlags = ApiEventExport(e);
	if (dwPluginResultFlags & PROCFILTER_RESULT_BLOCK_PROCESS)     bBlock = true;
	if (dwPluginResultFlags & PROCFILTER_RESULT_QUARANTINE)        bQuarantine = true;
	
	WCHAR *szFileQuarantineRuleNames = bScanFile && srFileResult.bScanSuccessful ? srFileResult.szQuarantineRuleNames : NULL;
	WCHAR *szMemoryQuarantineRuleNames = bScanMemory && srMemoryResult.bScanSuccessful ? srMemoryResult.szQuarantineRuleNames : NULL;

	// Quarantine here
	if (bQuarantine) {
		char hexdigest[SHA1_HEXDIGEST_LENGTH+1] = { '\0' };
		if (QuarantineFile(lpszFileName, cd->szQuarantineDirectory, cd->dwQuarantineFileSizeLimit, szFileQuarantineRuleNames, szMemoryQuarantineRuleNames, hexdigest)) {
			EventWriteFILE_QUARANTINED(dwProcessId, lpszFileName, hexdigest,
				(bScanFile && srFileResult.bScanSuccessful) ? srFileResult.szQuarantineRuleNames : NULL,
				(bScanMemory && srMemoryResult.bScanSuccessful) ? srMemoryResult.szQuarantineRuleNames : NULL);
		}
	}
	
	// Write the result back to the kernel driver, which releases the process
	bool bProcessBlocked = false;
	if (dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_CREATE || dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_TERMINATE) {
		PROCFILTER_RESPONSE response;
		ZeroMemory(&response, sizeof(PROCFILTER_RESPONSE));
		response.dwEventType = dwEventType;
		response.dwProcessId = dwProcessId;

		// Block the process according to configuration
		if (dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_CREATE) {
			if (cd->bDenyProcessCreationOnFailedScan) {
				if (bScanFile && !srFileResult.bScanSuccessful) bBlock = true;
				if (bScanMemory && !srMemoryResult.bScanSuccessful) bBlock = true;
			}
			
			if (bBlock) {
				response.bBlock = true;
			}
		}

		if (DriverSendResponse(hDriver, hWriteCompletionEvent, &response)) {
			if (dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_CREATE) bProcessBlocked = true;
		}
	} else if (dScanContext == PROCFILTER_SCAN_CONTEXT_IMAGE_LOAD) {
		PROCFILTER_RESPONSE response;
		ZeroMemory(&response, sizeof(PROCFILTER_RESPONSE));
		response.dwEventType = dwEventType;
		response.dwProcessId = dwProcessId;
		response.lpImageBase = lpImageBase;
		DriverSendResponse(hDriver, hWriteCompletionEvent, &response);
	}

	// Log to event log based on what was sent to the kernel (excluding the quarantining)
	WCHAR *szFileLogRuleNames = bScanFile && srFileResult.bScanSuccessful ? srFileResult.szLogRuleNames : NULL;
	WCHAR *szFileBlockRuleNames = bScanFile && srFileResult.bScanSuccessful ? srFileResult.szBlockRuleNames : NULL;
	WCHAR *szFileMatchRuleNames = bScanFile && srFileResult.bScanSuccessful ? srFileResult.szMatchedRuleNames : NULL;
	WCHAR *szMemoryLogRuleNames = bScanMemory && srMemoryResult.bScanSuccessful ? srMemoryResult.szLogRuleNames : NULL;
	WCHAR *szMemoryBlockRuleNames = bScanMemory && srMemoryResult.bScanSuccessful ? srMemoryResult.szBlockRuleNames : NULL;
	WCHAR *szMemoryMatchRuleNames = bScanMemory && srMemoryResult.bScanSuccessful ? srMemoryResult.szMatchedRuleNames : NULL;
	
	// Log the actions taken according to which events happened
	if (dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_CREATE) {
		if (bLog) EventWriteEXECUTION_LOGGED(dwProcessId, lpszFileName, szFileLogRuleNames, szMemoryLogRuleNames);
		if (bBlock) EventWriteEXECUTION_BLOCKED(dwProcessId, lpszFileName, szFileBlockRuleNames, szMemoryBlockRuleNames);
	} else if (dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_TERMINATE) {
		if (bLog) EventWriteEXITING_PROCESS_SCAN_MATCHED_LOGGED_RULE(dwProcessId, lpszFileName, szFileLogRuleNames, szMemoryLogRuleNames);
		if (bBlock) EventWriteEXITING_PROCESS_SCAN_MATCHED_BLOCKED_RULE(dwProcessId, lpszFileName, szFileBlockRuleNames, szMemoryBlockRuleNames);
	} else if (dScanContext == PROCFILTER_SCAN_CONTEXT_PERIODIC_SCAN) {
		if (bLog) EventWriteRUNNING_PROCESS_MATCHED_LOGGED_RULE(dwProcessId, lpszFileName, szFileLogRuleNames, szMemoryLogRuleNames);	
		if (bBlock) {
			EventWriteRUNNING_PROCESS_MATCHED_BLOCKED_RULE(dwProcessId, lpszFileName, szFileBlockRuleNames, szMemoryBlockRuleNames);
			if (TerminateProcessByPid(dwProcessId, true, lpszFileName, szFileBlockRuleNames, szMemoryBlockRuleNames)) {
				bProcessBlocked = true;
			}
		}
	} else if (dScanContext == PROCFILTER_SCAN_CONTEXT_IMAGE_LOAD) {
		if (bLog || bBlock) {
			WCHAR *lpszImageLoaderProcessName = NULL;
			DWORD dwImageLoaderProcessNameSize = sizeof(WCHAR) * (MAX_PATH+1);
			
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
			if (hProcess) {
				lpszImageLoaderProcessName = (WCHAR*)_malloca(dwImageLoaderProcessNameSize);
				if (!QueryFullProcessImageNameW(hProcess, PROCESS_NAME_NATIVE, lpszImageLoaderProcessName, &dwImageLoaderProcessNameSize)) {
					_freea(lpszImageLoaderProcessName);
					lpszImageLoaderProcessName = NULL;
				}
				CloseHandle(hProcess);
			}

			if (bLog) EventWriteLOADED_IMAGE_LOGGED(dwProcessId, lpszImageLoaderProcessName, lpszFileName, szFileLogRuleNames, szMemoryLogRuleNames);	
			if (bBlock) {
				EventWriteLOADED_IMAGE_BLOCKED(dwProcessId, lpszImageLoaderProcessName, lpszFileName, szFileBlockRuleNames, szMemoryBlockRuleNames);
				if (TerminateProcessByPid(dwProcessId, true, lpszFileName, szFileBlockRuleNames, szMemoryBlockRuleNames)) {
					bProcessBlocked = true;
				}
			}

			if (lpszImageLoaderProcessName) _freea(lpszImageLoaderProcessName);
		}
	}
	
	// Export post-scan notice to plugins
	ApiEventReinit(e, PROCFILTER_EVENT_YARA_SCAN_CLEANUP);
	e->dwProcessId = dwProcessId;
	e->dwParentProcessId = dwParentProcessId;
	e->lpszFileName = lpszFileName;
	e->dScanContext = dScanContext;
	e->srFileResult = bScanFile ? &srFileResult : NULL;
	e->srMemoryResult = bScanMemory ? &srMemoryResult : NULL;
	e->bBlockProcess = bBlock;
	e->bProcessBlocked = bProcessBlocked;
	e->lpvScanData = lpvScanDataArray;
	ApiEventExport(e);

	// Performance data update
	LONG64 llDuration = GetPerformanceCount() - llStart;
	MmaUpdate(&g_Stats[dScanContext].mma, llDuration);
	MmaUpdate(&g_Stats[PROCFILTER_NUM_CONTEXTS].mma, llDuration);
}
