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

#if defined(DRIVER_BUILD)
# include "ntddk.h"
#else
# include <Windows.h>
#endif

#define PROCFILTER_DEVICE_PATH (L"\\\\.\\ProcFilterDriver")
#define IOCTL_PROCFILTER_CONFIGURE CTL_CODE(FILE_DEVICE_NAMED_PIPE, 2048, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Structure packing required to avoid padding after last field; size mismatches between kernel/user mode
// under different compilation options could happen without it
#pragma pack(push, 1)
#define EVENTTYPE_NONE             0
#define EVENTTYPE_PROCESSCREATE    1  // Valid: dwProcessId, dwParentProcessId, szFileName
#define EVENTTYPE_PROCESSTERMINATE 2  // Valid: dwProcessId
#define EVENTTYPE_THREADCREATE     3  // Valid: dwProcessId, dwThreadId
#define EVENTTYPE_THREADTERMINATE  4  // Valid: dwProcessId, dwThreadId
#define EVENTTYPE_IMAGELOAD        5  // Valid: dwProcessId, lpImageBase, szFileName
#define NUM_EVENTTYPES             6
typedef struct procfilter_request PROCFILTER_REQUEST;
struct procfilter_request {
	DWORD dwRequestSize;      // Total bytes in the request packet
	DWORD dwEventType;        // Always valid, one of EVENTTYPE_Xxx
	DWORD dwProcessId;        // Process ID associated with the event
	DWORD dwParentProcessId;  // Parent process ID associated with event, if relevant
	DWORD dwThreadId;         // Thread ID associated with event, if relevant
	void *lpImageBase;        // Image base pointer, if relevant
	WCHAR szFileName[1];      // Filename associated with event, if relevant, always NULL-terminated
};
#define PROCFILTER_REQUEST_SIZE (sizeof(PROCFILTER_REQUEST) + ((UNICODE_STRING_MAX_CHARS + 14) * sizeof(WCHAR))) /* header + global prefix + string -- null is in the struct definition */

typedef struct procfilter_response PROCFILTER_RESPONSE;
struct procfilter_response {
	DWORD dwEventType;        // Corresponding EVENT_Xxx value
	DWORD dwProcessId;        // Corresponding Process ID
	DWORD dwThreadId;         // Corresponding Thread ID
	void *lpImageBase;        // Corresponding Image base pointer
	bool  bBlock;             // Block the event? Valid during EVENT_PROCESSCREATE
};

typedef struct procfilter_configuration PROCFILTER_CONFIGURATION;
struct procfilter_configuration {
	DWORD dwProcFilterRequestSize;          // Must be sizeof(PROCFILTER_REQUEST)
	DWORD dwProcMaxFilterRequestSize;       // Must be PROCFILTER_REQUEST_SIZE
	bool bDenyProcessCreationOnFailedScan;  // Deny process creation if scanning is unsuccessful?
	bool bWantThreadEvents;                 // Should the kernel export thread-related events?
	bool bWantImageLoadEvents;              // Should the kernel export image load events?
};
#pragma pack(pop)
