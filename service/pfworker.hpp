
#pragma once

#include <Windows.h>

#include "yara.hpp"
#include "config.hpp"
#include "procfilter/procfilter.h"

//
// Pool-global context data
//
typedef struct pool_data POOL_DATA;
struct pool_data {
	HANDLE hSharedDriverHandle;           // The driver handled shared between workers where results are written
	int dEventPriorities[NUM_EVENTTYPES]; // The array containing thread priorities
};

//
// Worker-specific context data
//
typedef struct worker_data WORKER_DATA;
struct worker_data {
	HANDLE hWriteCompletionEvent;       // Used for overlapped writes to kernel
	PROCFILTER_EVENT pfProcFilterEvent; // The event exported to the API during processing
	YARASCAN_CONTEXT *ctx;              // The scanning context for YARA
	void *lpvScanDataArray;             // The data array used by plugins that contains match data
};

//
// A task-specific data posted to a worker
//
typedef struct worker_task_data WORKER_TASK_DATA;
struct worker_task_data {
	ULONG64 ulStartPerformanceCount;        // Performance count when scan request was received
	PROCFILTER_REQUEST peProcFilterRequest; // The request for scanning received from the kernel
};

//
// Functions for use with the threadpool
//
void PfWorkerInit(void *lpPoolData, void *lpThreadData);
void PfWorkerDestroy(void *lpPoolData, void *lpThreadData);
void PfWorkerWork(void *lpPoolData, void *lpThreadData, void *lpTaskData, bool bCancel);
