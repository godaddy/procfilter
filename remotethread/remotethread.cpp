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

#include "procfilter/procfilter.h"


DWORD
ProcFilterEvent(PROCFILTER_EVENT *e)
{
	DWORD dwResultFlags = PROCFILTER_RESULT_NONE;

	if (e->dwEventId == PROCFILTER_EVENT_INIT) {
		e->RegisterPlugin(PROCFILTER_VERSION, L"RemoteThread", 0, 0, false, PROCFILTER_EVENT_THREAD_CREATE, PROCFILTER_EVENT_NONE);
	} else if (e->dwEventId == PROCFILTER_EVENT_THREAD_CREATE && e->dwParentProcessId != e->dwProcessId) {
		// Restrict remote thread interruption to only unprivileged threads since suspending/blocking
		// some system threads can lead to blue screens
		HANDLE hNewPid = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, e->dwProcessId);
		bool bIsElevated = false;
		if (hNewPid && e->IsElevated(hNewPid, &bIsElevated) && !bIsElevated) {
			WCHAR szCreator[MAX_PATH+1];
			WCHAR szDestination[MAX_PATH+1];

			ULONG64 ulProcessTime = 0;
			FILETIME ftUnused;
			FILETIME ftUserTime;

			if (GetProcessTimes(hNewPid, &ftUnused, &ftUnused, &ftUnused, &ftUserTime) && (ftUserTime.dwHighDateTime > 0 || ftUserTime.dwLowDateTime > 0)) {
				if (e->GetProcessFileName(e->dwParentProcessId, szCreator, sizeof(szCreator)) && e->GetProcessFileName(e->dwProcessId, szDestination, sizeof(szDestination))) {
					const WCHAR *lpszCreatorBaseName = e->GetProcessBaseNamePointer(szCreator);
					const WCHAR *lpszDestinationBaseName = e->GetProcessBaseNamePointer(szDestination);

					DWORD dwDialogResult = e->ShellNoticeFmt(0, true, MB_YESNO | MB_ICONQUESTION,
						L"Allow remote thread?", L"Remote thread creation detected.\n\nCreator:%ls\nDestination:%ls\n\nAllow?", lpszCreatorBaseName, lpszDestinationBaseName);
					if (dwDialogResult == IDNO) {
						dwResultFlags |= PROCFILTER_RESULT_BLOCK_PROCESS;
					}
				}
			}

			CloseHandle(hNewPid);
		}
	}

	return dwResultFlags;
}

