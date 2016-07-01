
#pragma once

#include "procfilter/procfilter.h"

#include "config.hpp"

//
// Init and shutdown the API
//
void ApiInit();
void ApiShutdown();

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
