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
		e->RegisterPlugin(PROCFILTER_VERSION, L"Interactive", 0, 0, true,
			PROCFILTER_EVENT_YARA_SCAN_INIT, PROCFILTER_EVENT_NONE);
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_SCAN_INIT && e->dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_CREATE) {
		DWORD dwDialogResult = e->ShellNoticeFmt(0, true, MB_YESNOCANCEL | MB_ICONQUESTION,
			L"Allow process? Select 'Cancel' to scan with ProcFilter.", L"Process name:\n\n%ls", e->lpszFileName);
		if (dwDialogResult == IDNO) {
			dwResultFlags |= PROCFILTER_RESULT_BLOCK_PROCESS;
		} else if (dwDialogResult == IDYES) {
			dwResultFlags |= PROCFILTER_RESULT_DONT_SCAN;
		} else {
			// do nothing, probably IDCANCEL
		}
	}

	return dwResultFlags;
}
