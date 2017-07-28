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

#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include <stdio.h>
#include <io.h>

#include "status.hpp"
#include "api.hpp"
#include "die.hpp"
#include "minmaxavg.hpp"
#include "strlcat.hpp"
#include "pfworker.hpp"
#include "winerr.hpp"
#include "scan.hpp"

#include "procfilter/procfilter.h"


#define PROCFILTER_STATUS_PIPE_NAME (L"\\\\.\\pipe\\ProcFilterStatusPipe")
#define NUM_PIPES 10
#define PIPE_TIMEOUT 2500


static HANDLE g_hStopEvent = NULL;
static HANDLE g_hStatusThread = NULL;
static HANDLE g_hStatusEvent = NULL;
static DWORD g_nWorkerThreads = 0;
static CRITICAL_SECTION g_cs;


static
bool
WriteToNonblockingPipe(HANDLE hPipe, HANDLE hWriteCompletionEvent, void *lpData, DWORD dwDataSize)
{
	bool rv = false;
	
	DWORD dwBytesWritten = 0;
	OVERLAPPED overlapped;
	ZeroMemory(&overlapped, sizeof(OVERLAPPED));
	overlapped.hEvent = hWriteCompletionEvent;
	BOOL rc = WriteFile(hPipe, lpData, dwDataSize, &dwBytesWritten, &overlapped);
	if (!rc && GetLastError() == ERROR_IO_PENDING) {
		if (WaitForSingleObject(hWriteCompletionEvent, PIPE_TIMEOUT) == WAIT_OBJECT_0 && 
			GetOverlappedResult(hPipe, &overlapped, &dwBytesWritten, FALSE)) {
			rc = TRUE;
		} else {
			CancelIo(hPipe);
		}
	}

	if (rc && dwBytesWritten == dwDataSize) rv = true;

	return rv;
}


static
bool
VPipeSay(HANDLE hPipe, HANDLE hWriteCompletionEvent, const WCHAR *fmt, va_list ap)
{
	bool rv = false;

	va_list ap2;
	va_copy(ap2, ap);

	WCHAR buf[2048];
	int len = _vsnwprintf(buf, sizeof(buf)/sizeof(WCHAR), fmt, ap);
	if (len > sizeof(buf)/sizeof(WCHAR) - 1 && len + 1 > len) {
		WCHAR *buf2 = (WCHAR*)calloc(len + 1, sizeof(WCHAR));
		if (buf2) {
			if (_vsnwprintf(buf2, len+1, fmt, ap2) == len) {
				rv = WriteToNonblockingPipe(hPipe, hWriteCompletionEvent, buf2, len * sizeof(WCHAR));
			}
			free(buf2);
		}
	} else if (len > 0)  {
		rv = WriteToNonblockingPipe(hPipe, hWriteCompletionEvent, buf, len * sizeof(WCHAR));
	}

	va_end(ap2);

	return rv;
}


static
bool
PipeSay(HANDLE hPipe, HANDLE hWriteCompletionEvent, const WCHAR *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	bool rv = VPipeSay(hPipe, hWriteCompletionEvent, fmt, ap);

	va_end(ap);

	return rv;
}


typedef struct event_data EVENT_DATA;
struct event_data {
	HANDLE hPipe;
	HANDLE hWriteCompletionEvent;
	bool bFailed;
};




static __declspec(thread) EVENT_DATA *g_EventData = NULL;

void
CALLBACK
Export_StatusPrintFmt(const WCHAR *lpszFmt, ...)
{
	PROCFILTER_EVENT *e = ApiGetCurrentEvent();
	EVENT_DATA *ed = (EVENT_DATA*)e->private_data->lpvEventData;

	if (ed->bFailed) return;

	va_list ap;
	va_start(ap, lpszFmt);

	ed->bFailed = !VPipeSay(ed->hPipe, ed->hWriteCompletionEvent, lpszFmt, ap);

	va_end(ap);
}


void
StatusPrint(const WCHAR *lpszFmt, ...)
{
	EVENT_DATA *ed = g_EventData;
	if (!ed) Die("Invalid invocation of StatusPrint()");
	if (ed->bFailed) return;

	va_list ap;
	va_start(ap, lpszFmt);

	ed->bFailed = !VPipeSay(ed->hPipe, ed->hWriteCompletionEvent, lpszFmt, ap);

	va_end(ap);
}


static
bool
DisplayStatus(HANDLE hPipe, HANDLE hWriteCompletionEvent)
{
	if (g_EventData != NULL) Die("Invalid invocation of DisplayStats()");

	EVENT_DATA ed = { hPipe, hWriteCompletionEvent, false };
	g_EventData = &ed;

	#define Say(fmt, ...) if (!PipeSay(hPipe, hWriteCompletionEvent, fmt, __VA_ARGS__)) return false;
	Say(L"ProcFilter %ls\n\n", PROCFILTER_VERSION);
	#undef Say

	ConfigStatusPrint();
	StatusPrint(L"\n");
	StatusPrint(L"===============================================================\n");
	StatusPrint(L"= Plugin Data\n");
	StatusPrint(L"===============================================================\n");
	StatusPrint(L"\n");
	ApiStatusPrint();

	StatusPrint(L"\n");
	StatusPrint(L"===============================================================\n");
	StatusPrint(L"= YARA Core Data\n");
	StatusPrint(L"===============================================================\n");
	StatusPrint(L"\n");
	ScanStatusPrint();

	StatusPrint(L"\n");
	StatusPrint(L"===============================================================\n");
	StatusPrint(L"= Cumulative Stats\n");
	StatusPrint(L"===============================================================\n");
	StatusPrint(L"\n");
	PfWorkerStatusPrint();

	g_EventData = NULL;

	return true;
}


DWORD
WINAPI
ep_StatusWorker(void *lpvHandle)
{
	HANDLE hPipe = (HANDLE)lpvHandle;

	HANDLE hWriteCompletionEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	
	ApiThreadInit();

	if (hWriteCompletionEvent && DisplayStatus(hPipe, hWriteCompletionEvent)) {
		EVENT_DATA ed = { hPipe, hWriteCompletionEvent, false };
		PROCFILTER_EVENT e;
		ApiEventInit(&e, PROCFILTER_EVENT_STATUS);
		e.private_data->lpvEventData = &ed;
		ApiEventExport(&e);
	}
	
	FlushFileBuffers(hPipe);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);
	
	EnterCriticalSection(&g_cs);
	g_nWorkerThreads -= 1;
	LeaveCriticalSection(&g_cs);
	
	ApiThreadShutdown();

	return 0;
}


//
// This service-only thread services external processes that connect via named pipe
//
DWORD
WINAPI
ep_StatusThread(void *lpvUnused)
{
	HANDLE hNamedPipe = INVALID_HANDLE_VALUE;
	HANDLE hClientConnectedEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!hClientConnectedEvent) Die("Unable to create event for client connection in stats thread");

	// Loop and service all connections to the named pipe
	while (1) {
		// Opan a non-blocking handle to the named pipe
		hNamedPipe = CreateNamedPipeW(PROCFILTER_STATUS_PIPE_NAME, PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, NUM_PIPES, 32 * 1024, 32 * 1024, 0, NULL);
		if (hNamedPipe == INVALID_HANDLE_VALUE) {
			if (GetLastError() == ERROR_PIPE_BUSY) {
				if (WaitForSingleObject(g_hStopEvent, 100) == WAIT_OBJECT_0) break;
				else continue;
			} else {
				Die("Unable to create named pipe in stats thread: %d %ls", GetLastError(), ErrorText(GetLastError()));
			}
		}
	
		// Asychronously wait for the named pipe
		OVERLAPPED overlapped;
		ZeroMemory(&overlapped, sizeof(OVERLAPPED));
		overlapped.hEvent = hClientConnectedEvent;
		ConnectNamedPipe(hNamedPipe, &overlapped);

		// Wait for either a stop event or a client connection event
		HANDLE handles[2] = { g_hStopEvent , hClientConnectedEvent };
		DWORD dwResult =  WaitForMultipleObjects(2, handles, FALSE, INFINITE);
		if (dwResult != WAIT_OBJECT_0 + 1) {
			CancelIo(hNamedPipe);
			break;
		};

		// Handle client connection
		if (CreateThread(NULL, 0, ep_StatusWorker, (void*)hNamedPipe, 0, NULL)) {
			EnterCriticalSection(&g_cs);
			g_nWorkerThreads += 1;
			LeaveCriticalSection(&g_cs);
		} else {
			// Unable to create a worker thread, release 
			DisconnectNamedPipe(hNamedPipe);
			CloseHandle(hNamedPipe);
		}
	}

	// Wait for all threads to exit
	bool bFinished = false;
	while (1) {
		EnterCriticalSection(&g_cs);
		bFinished = g_nWorkerThreads == 0;
		LeaveCriticalSection(&g_cs);

		if (bFinished) break;
		else Sleep(100);
	}

	// Cleanup
	if (hNamedPipe != INVALID_HANDLE_VALUE) CloseHandle(hNamedPipe);
	CloseHandle(hClientConnectedEvent);

	return 0;
}


void
StatusInit()
{
	InitializeCriticalSection(&g_cs);

	g_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!g_hStopEvent) Die("Unable to create stop event in stats thread");

	g_hStatusThread = CreateThread(NULL, 0, ep_StatusThread, NULL, 0, NULL);
	if (!g_hStatusThread) Die("Unable to create stats thread");
}


void
StatusShutdown()
{
	SetEvent(g_hStopEvent);
	WaitForSingleObject(g_hStatusThread, INFINITE);
	CloseHandle(g_hStopEvent);
	CloseHandle(g_hStatusEvent);
	CloseHandle(g_hStatusThread);

	DeleteCriticalSection(&g_cs);
}


void
StatusQuery()
{
	if (WaitNamedPipeW(PROCFILTER_STATUS_PIPE_NAME, PIPE_TIMEOUT) == 0) {
		fprintf(stderr, "ProcFilter service is not running\n");
		return;
	}

	HANDLE hPipe = CreateFile(PROCFILTER_STATUS_PIPE_NAME, GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hPipe == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "ProcFilter service unreachable: %ls\n", ErrorText(GetLastError()));
		return;
	}

	COMMTIMEOUTS ct;
	ZeroMemory(&ct, sizeof(COMMTIMEOUTS));
	ct.ReadTotalTimeoutConstant = PIPE_TIMEOUT;
	SetCommTimeouts(hPipe, &ct);

	while (1) {
		WCHAR c = '\0';
		DWORD dwBytesRead = 0;
		BOOL rv = ReadFile(hPipe, &c, sizeof(WCHAR), &dwBytesRead, NULL);
		if (rv) {
			if (dwBytesRead == sizeof(WCHAR)) {
				putwchar(c);
			} else {
				break;
			}
		} else {
			if (GetLastError() == ERROR_MORE_DATA) continue;
			if (GetLastError() == ERROR_PIPE_NOT_CONNECTED) break;
			fprintf(stderr, "Connection to ProcFilter service closed unexpectedly: %d %ls\n", GetLastError(), ErrorText(GetLastError()));
			break;
		}
	}

	CloseHandle(hPipe);
}
