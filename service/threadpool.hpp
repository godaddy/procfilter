
#pragma once

#include <Windows.h>

typedef struct threadpool THREADPOOL;

//
// Allocate a threadpool.
//
// dNumThreads - Number of threads in the pool, 0 to auto-size, or negative to specify a core-relative number.
// initfn - Called by each thread on threadool creation
// destroyfn - Called by each thread on threadpool shutdown
// lpPoolData - User data pointer passed in to all callbacks
// dwThreadDataSize - Size of thread data allocated for each thread and passed in as the lpThreadData argument
// nPriority - Priority for each thread
//
// Worker threads each call initfn() and destroyfn() on creation/shutdown.
//
THREADPOOL* ThreadPoolAlloc(int dNumThreads,
							void (*initfn)(void *lpPoolData, void *lpThreadData),
							void (*workfn)(void *lpPoolData, void *lpThreadData, void *lpTaskData),
							void (*destroyfn)(void *lpPoolData, void *lpThreadData),
							void *lpPoolData,
							DWORD dwThreadDataSize,
							int nPriority);
void ThreadPoolFree(THREADPOOL *tp);

//
// Post a task to the thread pool. If no threads are available in the pool this call will block.
//
bool ThreadPoolPost(THREADPOOL *tp, HANDLE hStopEvent, void *lpTaskData);
