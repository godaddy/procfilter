

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
