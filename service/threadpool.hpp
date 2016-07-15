
#pragma once

#include <Windows.h>

typedef struct threadpool THREADPOOL;

//
// Allocate a threadpool. The threadpool itself is not thread safe.
//
// dNumThreads - Number of threads in the pool, 0 to auto-size, or negative to specify a core-relative number.
// dNumChannels - Number of channels in the threadpool
// initfn - Called by each thread on threadool creation
// destroyfn - Called by each thread on threadpool shutdown
// lpPoolData - User data pointer passed in to all callbacks
// dwThreadDataSize - Size of thread data allocated for each thread and passed in as the lpThreadData argument
// nPriority - Priority for each thread
//
// Worker threads each call initfn() and destroyfn() on creation/shutdown.
//
THREADPOOL* ThreadPoolAlloc(int dNumThreads,
							DWORD dwNumChannels,
							void (*initfn)(void *lpPoolData, void *lpThreadData),
							void (*workfn)(void *lpPoolData, void *lpThreadData, void *lpTaskData, bool bCancel),
							void (*destroyfn)(void *lpPoolData, void *lpThreadData),
							void *lpPoolData,
							DWORD dwThreadDataSize,
							int nPriority);
void ThreadPoolFree(THREADPOOL *tp);

//
// Post a task to the thread pool. If no threads are available in the pool this call will block if bWait is set.
//
// Channel numbering is 1-based, so for example a 1-channel pool's first channel is 1. 0 (CHANNEL_NONE) is reserved
// for tasks that can be completed by any thread in the pool that aren't associated with a specific channel.
//
#define CHANNEL_NONE 0
bool ThreadPoolPost(THREADPOOL *tp, DWORD dwChannel, bool bWait, HANDLE hStopEvent, void *lpTaskData);
