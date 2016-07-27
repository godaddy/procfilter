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
