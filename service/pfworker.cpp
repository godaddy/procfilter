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

#include "pfworker.hpp"

#include "api.hpp"
#include "threadpool.hpp"
#include "yara.hpp"
#include "die.hpp"
#include "log.hpp"
#include "minmaxavg.hpp"
#include "hash.hpp"
#include "quarantine.hpp"
#include "file.hpp"
#include "status.hpp"
#include "strlcat.hpp"
#include "ProcFilterEvents.h"
#include "timing.hpp"
#include "umdriver.hpp"
#include "scan.hpp"
#include "terminate.hpp"
#include "warning.hpp"

typedef struct stats STATS;
struct stats {
	WCHAR *lpszScanName; // The scan name associated with the stats 
	MMA    mma;          // The moving average
};

// TODO: Refactor out commonalities between pfworker.cpp stats and scan.cpp stats
static STATS g_Stats[NUM_EVENTTYPES + 1];


void
PfWorkerStatsInit()
{
	ZeroMemory(g_Stats, sizeof(g_Stats));

	for (int i = 0; i < NUM_EVENTTYPES + 1; ++i) {
		MmaInit(&g_Stats[i].mma);
	}

	g_Stats[EVENTTYPE_NONE].lpszScanName = L"None";
	g_Stats[EVENTTYPE_PROCESSCREATE].lpszScanName = L"ProcessCreate";
	g_Stats[EVENTTYPE_PROCESSTERMINATE].lpszScanName = L"ProcessTerminate";
	g_Stats[EVENTTYPE_THREADCREATE].lpszScanName = L"ThreadCreate";
	g_Stats[EVENTTYPE_THREADTERMINATE].lpszScanName = L"ThreadTerminate";
	g_Stats[EVENTTYPE_IMAGELOAD].lpszScanName = L"ImageLoad";
	g_Stats[NUM_EVENTTYPES].lpszScanName = L"AllTypes";
}


void
PfWorkerStatusPrint()
{
	LONG64 llFrequency = GetPerformanceFrequency();
	MMA_DATA mdTotal;
	ZeroMemory(&mdTotal, sizeof(MMA_DATA));
	for (int i = 1; i < NUM_EVENTTYPES + 1; ++i) {
		WCHAR *lpszName = NULL;
		MMA_DATA md;

		lpszName = g_Stats[i].lpszScanName;
		md = MmaGet(&g_Stats[i].mma);

		LONG64 llSma = (LONG64)md.rSma;
		double rWeight = MmaGetWeight(&g_Stats[i].mma);

		StatusPrint(L"%16ls->Total     = %I64d\n", lpszName, md.llNum);
		StatusPrint(L"%16ls->MinTime   = %I64d.%03I64d seconds\n",
			lpszName, GetPerformanceSeconds(md.llMin, llFrequency), GetPerformanceMilliseconds(md.llMin, llFrequency) % 1000);
		StatusPrint(L"%16ls->MaxTime   = %I64d.%03I64d seconds\n",
			lpszName, GetPerformanceSeconds(md.llMax, llFrequency), GetPerformanceMilliseconds(md.llMax, llFrequency) % 1000);
		StatusPrint(L"%16ls->AvgTime   = %I64d.%03I64d seconds (SMA Weight=%0.02f)\n",
			lpszName, GetPerformanceSeconds(llSma, llFrequency), GetPerformanceMilliseconds(llSma, llFrequency) % 1000, rWeight);
		StatusPrint(L"%16ls->TotalTime = %I64d.%03I64d seconds\n",
			lpszName, GetPerformanceSeconds(md.llTotalSum, llFrequency), GetPerformanceMilliseconds(md.llTotalSum, llFrequency) % 1000);
		StatusPrint(L"\n");
	}
	StatusPrint(L" * Time counts include plugins\n");
}

//
// Callback used by worker threads to initialize their thread data structs
//
void
PfWorkerInit(void *lpPoolData, void *lpThreadData)
{
	POOL_DATA *pd = (POOL_DATA*)lpPoolData;
	WORKER_DATA *wd = (WORKER_DATA*)lpThreadData;
	CONFIG_DATA *cd = GetConfigData();

	LogDebug("Worker Initializing");

	ApiThreadInit();

	ApiEventInit(&wd->pfProcFilterEvent, PROCFILTER_EVENT_NONE);
	wd->hWriteCompletionEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (wd->hWriteCompletionEvent == NULL) Die("Unable to create write completion event in worker");
	WCHAR szError[512];

	YARASCAN_INPUT_FILE yifInputFiles[2];
	ZeroMemory(yifInputFiles, sizeof(yifInputFiles));
	
	wd->ctx = YarascanAllocDefault(szError, sizeof(szError), true, false);
	if (!wd->ctx) Die("Yara rulefile compilation failed: %ls", szError);

	wd->lpvScanDataArray = ApiAllocateScanDataArray();
	if (!wd->lpvScanDataArray) Die("Unable to allocate match data array in worker thread");
}


//
// Callback used by worker threads to destruct their thread data
//
void
PfWorkerDestroy(void *lpPoolData, void *lpThreadData)
{
	POOL_DATA *pd = (POOL_DATA*)lpPoolData;
	WORKER_DATA *wd = (WORKER_DATA*)lpThreadData;
	
	LogDebug("Worker stopping");

	CloseHandle(wd->hWriteCompletionEvent);
	ApiFreeScanDataArray(wd->lpvScanDataArray);
	YarascanFree(wd->ctx);
	ApiThreadShutdown();
}


//
// Callback invoked when a worker thread enters a working state
//
void
PfWorkerWork(void *lpPoolData, void *lpThreadData, void *lpTaskData, bool bCancel)
{
	if (bCancel) return;

	POOL_DATA *pd = (POOL_DATA*)lpPoolData;
	WORKER_DATA *wd = (WORKER_DATA*)lpThreadData;
	WORKER_TASK_DATA *wtd = (WORKER_TASK_DATA*)lpTaskData;
	PROCFILTER_REQUEST *req = &wtd->peProcFilterRequest;
	PROCFILTER_EVENT *e = &wd->pfProcFilterEvent;

	CONFIG_DATA *cd = GetConfigData();
	HANDLE hSelf = GetCurrentThread();

	LogDebug("Worker starting");
	
	// Map the event type from kernel mode to an api event type
	DWORD dwApiEventId = PROCFILTER_EVENT_NONE;
	switch (req->dwEventType) {
	case EVENTTYPE_PROCESSCREATE: dwApiEventId    = PROCFILTER_EVENT_PROCESS_CREATE; break;
	case EVENTTYPE_PROCESSTERMINATE: dwApiEventId = PROCFILTER_EVENT_PROCESS_TERMINATE; break;
	case EVENTTYPE_THREADCREATE: dwApiEventId     = PROCFILTER_EVENT_THREAD_CREATE; break;
	case EVENTTYPE_THREADTERMINATE: dwApiEventId  = PROCFILTER_EVENT_THREAD_TERMINATE; break;
	case EVENTTYPE_IMAGELOAD: dwApiEventId        = PROCFILTER_EVENT_IMAGE_LOAD; break;
	}

	// Reinitialize the API event structure with values corresponding to the current request
	ApiEventReinit(e, dwApiEventId);
	e->dwProcessId = req->dwProcessId;
	e->dwParentProcessId = req->dwParentProcessId;
	e->dwThreadId = req->dwThreadId;
	e->lpszFileName = req->szFileName;

	// Build the header portion of the response
	PROCFILTER_RESPONSE response;
	ZeroMemory(&response, sizeof(PROCFILTER_RESPONSE));
	response.dwProcessId = req->dwProcessId;
	response.dwEventType = req->dwEventType;
	response.dwThreadId = req->dwThreadId;
	response.lpImageBase = req->lpImageBase;

	// Handle the event according to its type
	if (req->dwEventType == EVENTTYPE_PROCESSCREATE) {
		LogDebugFmt("Worker received creation scan request for: 0x%08X %ls", req->dwProcessId, req->szFileName);
		if (ApiEventExport(e) & PROCFILTER_RESULT_BLOCK_PROCESS) {
			response.bBlock = true;
			DriverSendResponse(pd->hSharedDriverHandle, wd->hWriteCompletionEvent, &response);
			EventWriteEXECUTION_BLOCKED(req->dwProcessId, req->szFileName, NULL, NULL);
		} else {
			Scan(req->dwEventType, PROCFILTER_SCAN_CONTEXT_PROCESS_CREATE, &wd->pfProcFilterEvent, wd->ctx, pd->hSharedDriverHandle, wd->hWriteCompletionEvent, req->dwProcessId, req->dwParentProcessId, req->szFileName, NULL, wd->lpvScanDataArray);
		}
	} else if (req->dwEventType == EVENTTYPE_PROCESSTERMINATE) {
		ApiEventExport(e);
		LogDebugFmt("Worker received termination scan request for: 0x%08X %ls", req->dwProcessId, req->szFileName);
		Scan(req->dwEventType, PROCFILTER_SCAN_CONTEXT_PROCESS_TERMINATE, &wd->pfProcFilterEvent, wd->ctx, pd->hSharedDriverHandle, wd->hWriteCompletionEvent, req->dwProcessId, 0, req->szFileName, NULL, wd->lpvScanDataArray);
	} else if (req->dwEventType == EVENTTYPE_THREADCREATE) {
		if (ApiEventExport(e) & PROCFILTER_RESULT_BLOCK_PROCESS) {
			TerminateProcessByPid(req->dwProcessId, true, req->szFileName, NULL, NULL);
			response.bBlock = true;
		}
		DriverSendResponse(pd->hSharedDriverHandle, wd->hWriteCompletionEvent, &response);
	} else if (req->dwEventType == EVENTTYPE_THREADTERMINATE) {
		ApiEventExport(e);
		DriverSendResponse(pd->hSharedDriverHandle, wd->hWriteCompletionEvent, &response);
	} else if (req->dwEventType == EVENTTYPE_IMAGELOAD) {
		LogDebugFmt("Worker received image load request: 0x%08X / %ls", req->dwProcessId, req->szFileName);
		if (ApiEventExport(e) & PROCFILTER_RESULT_BLOCK_PROCESS) {
			
			LogDebugFmt("Worker image load API request to terminate process: 0x%08X / %ls", req->dwProcessId, req->szFileName);
			// XXX: Race condition here blocking on process pid while the DLL is still loading?
			TerminateProcessByPid(req->dwProcessId, true, req->szFileName, NULL, NULL);
			LogDebugFmt("Worker image load process terminated: 0x%08X / %ls", req->dwProcessId, req->szFileName);
			response.bBlock = true;
			DriverSendResponse(pd->hSharedDriverHandle, wd->hWriteCompletionEvent, &response);
			LogDebugFmt("Worker image load request to terminate process: 0x%08X / %ls", req->dwProcessId, req->szFileName);
		} else {
			LogDebugFmt("Image load scan: 0x%08X / %ls", req->dwProcessId, req->szFileName);
			Scan(req->dwEventType, PROCFILTER_SCAN_CONTEXT_IMAGE_LOAD, &wd->pfProcFilterEvent, wd->ctx, pd->hSharedDriverHandle, wd->hWriteCompletionEvent, req->dwProcessId, 0, req->szFileName, req->lpImageBase, wd->lpvScanDataArray);
			LogDebugFmt("Image load scan complete: 0x%08X / %ls", req->dwProcessId, req->szFileName);
		}
	}

	LONG64 llDuration = GetPerformanceCount() - wtd->ulStartPerformanceCount;

	MmaUpdate(&g_Stats[req->dwEventType].mma, llDuration);
	MmaUpdate(&g_Stats[NUM_EVENTTYPES].mma, llDuration);

	free(wtd);
}
