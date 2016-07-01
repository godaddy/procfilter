

#include "procfilter/procfilter.h"


DWORD
ProcFilterEvent(PROCFILTER_EVENT *e)
{
	DWORD dwResultFlags = PROCFILTER_RESULT_NONE;

	if (e->dwEventId == PROCFILTER_EVENT_INIT) {
		e->RegisterPlugin(PROCFILTER_VERSION, L"RemoteThread", 0, 0, false, PROCFILTER_EVENT_THREAD_CREATE, PROCFILTER_EVENT_NONE);
	} else if (e->dwEventId == PROCFILTER_EVENT_THREAD_CREATE && e->dwParentProcessId != e->dwProcessId) {
		HANDLE hNewPid = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, e->dwProcessId);
		if (hNewPid) {
			WCHAR szCreator[MAX_PATH+1];
			WCHAR szDestination[MAX_PATH+1];

			ULONG64 ulProcessTime = 0;
			FILETIME ftUnused;
			FILETIME ftUserTime;

			if (GetProcessTimes(hNewPid, &ftUnused, &ftUnused, &ftUnused, &ftUserTime) && (ftUserTime.dwHighDateTime > 0 || ftUserTime.dwLowDateTime > 0)) {
				if (e->GetProcessFileName(e->dwParentProcessId, szCreator, sizeof(szCreator)) && e->GetProcessFileName(e->dwProcessId, szDestination, sizeof(szDestination))) {
					WCHAR *lpszCreatorBaseName = e->GetProcessBaseNamePointer(szCreator);
					WCHAR *lpszDestinationBaseName = e->GetProcessBaseNamePointer(szDestination);

					if (lpszCreatorBaseName && lpszDestinationBaseName) {
						DWORD dwDialogResult = e->ShellNoticeFmt(0, true, MB_YESNO | MB_ICONQUESTION,
							L"Allow remote thread?", L"Remote thread creation detected.\n\nCreator:%ls\nDestination:%ls\n\nAllow?", lpszCreatorBaseName, lpszDestinationBaseName);
						if (dwDialogResult != IDYES) {
							dwResultFlags |= PROCFILTER_RESULT_BLOCK_PROCESS;
						}
					}
				}
			}

			CloseHandle(hNewPid);
		}
	}

	return dwResultFlags;
}

