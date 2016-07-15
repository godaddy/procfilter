
#include <Windows.h>

#include "pfworker.hpp"

#include "api.hpp"
#include "threadpool.hpp"
#include "yara.hpp"
#include "die.hpp"
#include "log.hpp"
#include "sha1.hpp"
#include "quarantine.hpp"
#include "file.hpp"
#include "strlcat.hpp"
#include "ProcFilterEvents.h"
#include "umdriver.hpp"
#include "scan.hpp"
#include "terminate.hpp"
#include "warning.hpp"


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

	// Setup an array containing task -> priority mappings for worker threads
	for (int i = 0; i < NUM_EVENTTYPES; ++i) {
		pd->dEventPriorities[i] = THREAD_PRIORITY_NORMAL;
	}
	pd->dEventPriorities[EVENTTYPE_THREADCREATE] = THREAD_PRIORITY_HIGHEST;
	pd->dEventPriorities[EVENTTYPE_THREADTERMINATE] = THREAD_PRIORITY_HIGHEST;
	pd->dEventPriorities[EVENTTYPE_IMAGELOAD] = THREAD_PRIORITY_ABOVE_NORMAL;

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
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

	// Set the current thread's priority according to the task type given
	int dOriginalPriority = GetThreadPriority(hSelf);
	bool bChangePriority = dOriginalPriority != pd->dEventPriorities[req->dwEventType];
	if (bChangePriority) {
		SetThreadPriority(hSelf, pd->dEventPriorities[req->dwEventType]);
	}
	
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
	
	// Revert back to original thread priority
	if (bChangePriority) {
		SetThreadPriority(hSelf, dOriginalPriority);
	}

	free(wtd);
}
