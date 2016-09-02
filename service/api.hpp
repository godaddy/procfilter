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

#include "procfilter/procfilter.h"

#include "config.hpp"

//
// Init and shutdown the API globally for the process
//
void ApiInit();
void ApiShutdown();

// 
// All threads that generate API events must call this before calling ApiEventXxx
//
void ApiThreadInit();
void ApiThreadShutdown();

//
// Initialize an API event structure, reinitialize it for reuse, and export the event
// to all loaded plugins that have requested that event
//
void  ApiEventInit(PROCFILTER_EVENT *e, DWORD dwEventId);
void  ApiEventReinit(PROCFILTER_EVENT *e, DWORD dwEventId);
DWORD ApiEventExport(PROCFILTER_EVENT *e);

//
// Build a string containing information about the current thread's state with
// regard to the API module
//
void ApiGetDebugInfo(WCHAR *lpszResult, DWORD dwResultSize);

//
// Have plugins requested that they want thread and/or image load events?
//
bool ApiWantThreadEvents();
bool ApiWantImageLoadEvents();

//
// Print API stats to the stats engine
//
void ApiStatusPrint();

//
// Get the current PROCFILTER_EVENT being processed by the API if one exists
//
PROCFILTER_EVENT* ApiGetCurrentEvent();

//
// Allocate/free PROCFILTER_EVENT-specific scan data on a per-event basis
//
void* ApiAllocateScanDataArray();
void  ApiFreeScanDataArray(void *lpvScanDataArray);
