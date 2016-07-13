
#include "threadpool.hpp"

#include "config.hpp"
#include "die.hpp"

#include "log.hpp"



typedef struct thread_context THREAD_CONTEXT;
struct thread_context {
	HANDLE hThread;
	HANDLE hWakeEvent;
	HANDLE hSemaphore;
	void (*lpInitFunction)(void *lpPoolData, void *lpThreadData);
	void (*lpfnWorkFunction)(void *lpPoolData, void *lpTheadData, void *lpTaskData);
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

struct threadpool {
	THREAD_CONTEXT *tcThreadContextArray;
	DWORD dwNumThreads;
	DWORD dwNumChannels;
	HANDLE hSemaphore;
	void *lpThreadDataArray;
	THREAD_CONTEXT **lpMostRecentlyUsedArray;
	DWORD dwThreadDataSize;
	CRITICAL_SECTION mtx;
};



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

			tc->lpfnWorkFunction(tc->lpPoolData, tc->lpThreadData, tc->lpTaskData);
				
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
				int dNumChannels,
				void (*initfn)(void *lpPoolData, void *lpThreadData),
				void (*workfn)(void *lpPoolData, void *lpThreadData, void *lpTaskData),
				void (*destroyfn)(void *lpPoolData, void *lpThreadData),
				void *lpPoolData,
				DWORD dwThreadDataSize,
				int nPriority)
{
	if (dNumChannels < 0) dNumChannels = 0;

	THREADPOOL *tp = (THREADPOOL*)calloc(1, sizeof(THREADPOOL));
	if (!tp) return NULL;

	SYSTEM_INFO si;
	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	GetSystemInfo(&si);
	int dNumProcessors = (int)si.dwNumberOfProcessors;
	if (dNumThreads <= 0) {
		dNumThreads = dNumProcessors > -dNumThreads ? dNumProcessors + dNumThreads : 1;
	}
	if (dNumThreads > dNumProcessors) dNumThreads = dNumProcessors;
	if (dNumThreads == 0) return NULL;
	DWORD dwNumThreads = dNumThreads + dNumChannels;
	if (dwNumThreads <= 0) return NULL;

	tp->dwThreadDataSize = dwThreadDataSize;
	tp->dwNumThreads = dwNumThreads;
	tp->dwNumChannels = (DWORD)dNumChannels;
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
		DWORD dwChannelThreadStartIndex = tp->dwNumThreads - tp->dwNumChannels;
		if (i < dwChannelThreadStartIndex) {
			tc->dwChannel = CHANNEL_NONE;
		} else {
			tc->dwChannel = (i - dwChannelThreadStartIndex) + 1;
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

	for (size_t i = 0; i < tp->dwNumThreads; ++i) {
		THREAD_CONTEXT *tc = &tp->tcThreadContextArray[i];

		EnterCriticalSection(&tc->mtx);
		tc->bRunning = false;
		LeaveCriticalSection(&tc->mtx);

		SetEvent(tc->hWakeEvent);
	}
	
	for (size_t i = 0; i < tp->dwNumThreads; ++i) {
		THREAD_CONTEXT *tc = &tp->tcThreadContextArray[i];

		WaitForSingleObject(tc->hThread, INFINITE);

		CloseHandle(tc->hThread);
		CloseHandle(tc->hWakeEvent);
		DeleteCriticalSection(&tc->mtx);
	}
	
	free(tp->lpMostRecentlyUsedArray);
	free(tp->lpThreadDataArray);
	free(tp->tcThreadContextArray);

	DeleteCriticalSection(&tp->mtx);
	CloseHandle(tp->hSemaphore);

	free(tp);
}


//
// XXX: Why bother to rework this function and dequeue from kernel immediately if the pool is already
// consumed processing other tasks?
//
// With the current design it doesnt make sense, but if it's eventually channeled then 1 job of each
// type can be in progress and lightweight jobs (thread, image load) wont be completely blocked
// on heavier weight tasks - one job of each type will be in progress simultaneously.
//
bool
ThreadPoolPost(THREADPOOL *tp, int dChannel, HANDLE hStopEvent, void *lpTaskData)
{
	bool rv = false;

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

	THREAD_CONTEXT *tc = NULL;
	EnterCriticalSection(&tp->mtx);
	for (DWORD i = 0; i < tp->dwNumThreads; ++i) {
		tc = tp->lpMostRecentlyUsedArray[i];

		EnterCriticalSection(&tc->mtx);
		if (!tc->bHasTask) {
			tc->bHasTask = true;
			tc->lpTaskData = lpTaskData;
			LeaveCriticalSection(&tc->mtx);
			rv = true;
			break;
		} else {
			LeaveCriticalSection(&tc->mtx);
		}
	}
	LeaveCriticalSection(&tp->mtx);
	if (!tc) Die("Failed to find available thread in threadpool for post");
	SetEvent(tc->hWakeEvent);

	if (!rv) Die("Failed to post thread data when semaphore was signaled");

	return rv;
}
