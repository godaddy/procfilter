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
//
// Worker threads each call initfn() and destroyfn() on creation/shutdown.
//
THREADPOOL* ThreadPoolAlloc(int dNumThreads,
							DWORD dwNumChannels,
							void (*initfn)(void *lpPoolData, void *lpThreadData),
							void (*workfn)(void *lpPoolData, void *lpThreadData, void *lpTaskData, bool bCancel),
							void (*destroyfn)(void *lpPoolData, void *lpThreadData),
							void *lpPoolData,
							DWORD dwThreadDataSize);
void ThreadPoolFree(THREADPOOL *tp);

//
// Post a task to the thread pool. If no threads are available in the pool this call will block if bWait is set.
//
// Channel numbering is 1-based, so for example a 1-channel pool's first channel is 1. 0 (CHANNEL_NONE) is reserved
// for tasks that can be completed by any thread in the pool that aren't associated with a specific channel.
//
#define CHANNEL_NONE 0
bool ThreadPoolPost(THREADPOOL *tp, DWORD dwChannel, bool bWait, HANDLE hStopEvent, void *lpTaskData);
