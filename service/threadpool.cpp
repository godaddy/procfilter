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

#include "threadpool.hpp"

#include "config.hpp"
#include "die.hpp"

#include "log.hpp"

#include <list>
#include <vector>
#include <algorithm>


typedef struct thread_context THREAD_CONTEXT;
struct thread_context {
	HANDLE hThread;
	HANDLE hWakeEvent;
	HANDLE hSemaphore;
	void (*lpInitFunction)(void *lpPoolData, void *lpThreadData);
	void (*lpfnWorkFunction)(void *lpPoolData, void *lpTheadData, void *lpTaskData, bool bCancel);
	void (*lpDestroyFunction)(void *lpPoolData, void *lpThreadData);
	bool bRunning;
	bool bHasTask;
	DWORD dwChannel;
	void *lpPoolData;
	void *lpTaskData;
	void *lpThreadData;
	THREADPOOL *lpThreadPool;
	CRITICAL_SECTION mtx;
};

typedef std::list<std::pair<DWORD,void*>> TaskList;


struct threadpool {
	THREAD_CONTEXT *tcThreadContextArray;
	DWORD dwNumThreads;
	DWORD dwNumChannels;
	DWORD dwChannelStartIndex;
	HANDLE hSemaphore;
	void *lpThreadDataArray;
	THREAD_CONTEXT **lpMostRecentlyUsedArray;
	DWORD dwThreadDataSize;
	TaskList *queue;
	CRITICAL_SECTION mtx;
};


static
bool
pop_next_task(THREADPOOL *tp, DWORD dwChannel, void **lplpvResult)
{
	bool rv = false;

	auto iter = tp->queue->begin();
	while (iter != tp->queue->end()) {
		if (dwChannel == CHANNEL_NONE || iter->first == dwChannel) {
			*lplpvResult = iter->second;
			tp->queue->erase(iter);
			rv = true;
			break;
		}
		++iter;
	}

	return rv;
}


static
DWORD
WINAPI
ep_WorkerThread(void *data)
{
	THREAD_CONTEXT *tc = (THREAD_CONTEXT*)data;
	THREADPOOL *tp = tc->lpThreadPool;
	
	if (tc->lpInitFunction) tc->lpInitFunction(tc->lpPoolData, tc->lpThreadData);

	DWORD rc = 0;
	bool bRunning = true;
	while (bRunning) {
		rc = WaitForSingleObject(tc->hWakeEvent, INFINITE);
		if (rc != WAIT_OBJECT_0) break;

		EnterCriticalSection(&tc->mtx);
		bRunning = tc->bRunning;
		if (tc->bHasTask) {
			LeaveCriticalSection(&tc->mtx);

			bool bContinue = false;
			do {
				LogDebugFmt("Worker activated       (Channel %u/%u): Task %p", GetCurrentThreadId(), tc->dwChannel, tc->lpTaskData);
				tc->lpfnWorkFunction(tc->lpPoolData, tc->lpThreadData, tc->lpTaskData, !bRunning);

				EnterCriticalSection(&tp->mtx);
				EnterCriticalSection(&tc->mtx);
				bRunning = tc->bRunning;
				if (bRunning) {
					bContinue = pop_next_task(tp, tc->dwChannel, &tc->lpTaskData);
					LogDebugFmt("Worker activated (Cont) (Channel %u/%u): Task %p", GetCurrentThreadId(), tc->dwChannel, tc->lpTaskData);
				} else {
					bContinue = false;
				}
				LeaveCriticalSection(&tc->mtx);
				LeaveCriticalSection(&tp->mtx);
			} while (bContinue);
				
			EnterCriticalSection(&tp->mtx);
			EnterCriticalSection(&tc->mtx);
			tc->bHasTask = false;
			// bring current thread context to head of the mru array
			for (DWORD i = 0; i < tp->dwNumThreads; ++i) {
				if (tp->lpMostRecentlyUsedArray[i] == tc) {
					for (; i > 0; --i) {
						tp->lpMostRecentlyUsedArray[i] = tp->lpMostRecentlyUsedArray[i-1];
					}
					tp->lpMostRecentlyUsedArray[0] = tc;
					break;
				}
			}

			LeaveCriticalSection(&tc->mtx);
			LeaveCriticalSection(&tp->mtx);

			if (!ReleaseSemaphore(tc->hSemaphore, 1, NULL)) Die("Failed to release semaphore in worker");
		} else {
			LeaveCriticalSection(&tc->mtx);
		}
	}

	if (tc->lpDestroyFunction) tc->lpDestroyFunction(tc->lpPoolData, tc->lpThreadData);

	return 0;
}


THREADPOOL*
ThreadPoolAlloc(int dNumThreads,
				DWORD dwNumChannels,
				void (*initfn)(void *lpPoolData, void *lpThreadData),
				void (*workfn)(void *lpPoolData, void *lpThreadData, void *lpTaskData, bool bCancel),
				void (*destroyfn)(void *lpPoolData, void *lpThreadData),
				void *lpPoolData,
				DWORD dwThreadDataSize,
				int nPriority)
{
	THREADPOOL *tp = (THREADPOOL*)calloc(1, sizeof(THREADPOOL));
	if (!tp) return NULL;

	tp->queue = new TaskList;

	SYSTEM_INFO si;
	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	GetSystemInfo(&si);
	int dNumProcessors = (int)si.dwNumberOfProcessors;
	if (dNumThreads <= 0) {
		dNumThreads = dNumProcessors > -dNumThreads ? dNumProcessors + dNumThreads : 1;
	}
	if (dNumThreads > dNumProcessors) dNumThreads = dNumProcessors;
	if (dNumThreads == 0) return NULL;
	DWORD dwNumThreads = ((DWORD)dNumThreads) + dwNumChannels;
	tp->dwChannelStartIndex = dNumThreads;
	if (dwNumThreads <= 0) return NULL;

	tp->dwThreadDataSize = dwThreadDataSize;
	tp->dwNumThreads = dwNumThreads;
	tp->dwNumChannels = dwNumChannels;
	tp->tcThreadContextArray = (THREAD_CONTEXT*)calloc(dwNumThreads, sizeof(THREAD_CONTEXT));
	if (!tp->tcThreadContextArray) {
		free(tp);
		return NULL;
	}

	tp->lpMostRecentlyUsedArray = (THREAD_CONTEXT**)calloc(dwNumThreads, sizeof(THREAD_CONTEXT*));
	if (!tp->lpMostRecentlyUsedArray) {
		free(tp->tcThreadContextArray);
		free(tp);
		return NULL;
	}

	tp->lpThreadDataArray = calloc(dwNumThreads, dwThreadDataSize);
	if (!tp->lpThreadDataArray) {
		free(tp->lpMostRecentlyUsedArray);
		free(tp->tcThreadContextArray);
		free(tp);
		return NULL;
	}

	tp->hSemaphore = CreateSemaphore(NULL, dwNumThreads, dwNumThreads, NULL);
	if (tp->hSemaphore == NULL) {
		free(tp->lpThreadDataArray);
		free(tp->lpMostRecentlyUsedArray);
		free(tp->tcThreadContextArray);
		free(tp);
		return NULL;
	}

	InitializeCriticalSection(&tp->mtx);

	bool failed = false;
	DWORD i = 0;
	for (i = 0; i < dwNumThreads; ++i) {
		THREAD_CONTEXT *tc = &tp->tcThreadContextArray[i];
		tp->lpMostRecentlyUsedArray[(dwNumThreads-1)-i] = tc;

		tc->lpInitFunction = initfn;
		tc->lpfnWorkFunction = workfn;
		tc->lpDestroyFunction = destroyfn;
		tc->bRunning = true;
		DWORD dwThreadId = 0;
		// Assign the last N threads to be channel-specific
		if (i < tp->dwChannelStartIndex) {
			tc->dwChannel = CHANNEL_NONE;
		} else {
			tc->dwChannel = (i - tp->dwChannelStartIndex) + 1;
		}
		tc->hSemaphore = tp->hSemaphore;
		tc->lpPoolData = lpPoolData;
		tc->lpThreadData = (BYTE*)tp->lpThreadDataArray + (dwThreadDataSize * i);
		tc->lpThreadPool = tp;
		InitializeCriticalSection(&tc->mtx);

		tc->hWakeEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (tc->hWakeEvent == NULL) {
			DeleteCriticalSection(&tc->mtx);
			failed = true;
			break;
		}

		tc->hThread = CreateThread(NULL, 0, ep_WorkerThread, tc, 0, &dwThreadId);
		if (tc->hThread == NULL) {
			CloseHandle(tc->hWakeEvent);
			DeleteCriticalSection(&tc->mtx);
			failed = true;
			break;
		}

		SetThreadPriority(tc->hThread, nPriority);
	}

	if (failed) {
		for (; i > 0; --i) {
			THREAD_CONTEXT *tc = &tp->tcThreadContextArray[i-1];
			EnterCriticalSection(&tc->mtx);
			tc->bRunning = false;
			LeaveCriticalSection(&tc->mtx);
			SetEvent(tc->hWakeEvent);

			WaitForSingleObject(tc->hThread, INFINITE);
			
			CloseHandle(tc->hWakeEvent);
			DeleteCriticalSection(&tc->mtx);
			CloseHandle(tc->hThread);
		}
		
		CloseHandle(tp->hSemaphore);
		DeleteCriticalSection(&tp->mtx);
		free(tp->lpMostRecentlyUsedArray);
		free(tp->lpThreadDataArray);
		free(tp->tcThreadContextArray);
		free(tp);
		tp = NULL;
	}

	return tp;
}


void
ThreadPoolFree(THREADPOOL *tp)
{
	if (!tp) return;

	// Signal all threads to stop
	for (size_t i = 0; i < tp->dwNumThreads; ++i) {
		THREAD_CONTEXT *tc = &tp->tcThreadContextArray[i];

		EnterCriticalSection(&tc->mtx);
		tc->bRunning = false;
		LeaveCriticalSection(&tc->mtx);

		SetEvent(tc->hWakeEvent);
	}
	
	// Stop all threads in pool
	for (size_t i = 0; i < tp->dwNumThreads; ++i) {
		THREAD_CONTEXT *tc = &tp->tcThreadContextArray[i];

		WaitForSingleObject(tc->hThread, INFINITE);

		CloseHandle(tc->hThread);
		CloseHandle(tc->hWakeEvent);
		DeleteCriticalSection(&tc->mtx);
	}

	delete tp->queue;
	
	free(tp->lpMostRecentlyUsedArray);
	free(tp->lpThreadDataArray);
	free(tp->tcThreadContextArray);

	DeleteCriticalSection(&tp->mtx);
	CloseHandle(tp->hSemaphore);

	free(tp);
}


bool
ThreadPoolPost(THREADPOOL *tp, DWORD dwChannel, bool bWait, HANDLE hStopEvent, void *lpTaskData)
{
	bool rv = false;
	
	THREAD_CONTEXT *tc = NULL;
	EnterCriticalSection(&tp->mtx);
	do {
		LeaveCriticalSection(&tp->mtx);
		if (bWait) {
			if (hStopEvent != NULL) {
				HANDLE handles[2] = { tp->hSemaphore, hStopEvent };
				DWORD rc = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
				if (rc != WAIT_OBJECT_0) {
					return rv;
				}
			} else {
				if (WaitForSingleObject(tp->hSemaphore, INFINITE) != WAIT_OBJECT_0) {
					return rv;
				}
			}
		} else {
			WaitForSingleObject(tp->hSemaphore, 0);
		}

		EnterCriticalSection(&tp->mtx);
		for (DWORD i = 0; i < tp->dwNumThreads; ++i) {
			tc = tp->lpMostRecentlyUsedArray[i];

			EnterCriticalSection(&tc->mtx);
			if (!tc->bHasTask && (tc->dwChannel == CHANNEL_NONE || tc->dwChannel == dwChannel)) {
				tc->bHasTask = true;
				tc->lpTaskData = lpTaskData;
				LeaveCriticalSection(&tc->mtx);
				rv = true;
				break;
			}

			LeaveCriticalSection(&tc->mtx);
			tc = NULL;
		}
	} while (bWait && !tc);

	// Free thread not found; queue task
	if (!tc) {
		tp->queue->push_back(std::pair<DWORD,void*>(dwChannel, lpTaskData));
		rv = true;
	}

	LeaveCriticalSection(&tp->mtx);
	
	if (tc) {
		// Free thread found and job posted, wake worker thread
		SetEvent(tc->hWakeEvent);
	}

	return rv;
}
