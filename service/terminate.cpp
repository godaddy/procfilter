
#include "warning.hpp"

#include "terminate.hpp"

#include "ProcFilterEvents.h"


bool
TerminateProcessByPid(DWORD dwProcessId, bool bLog, const WCHAR *lpszFileName, const WCHAR *lpszFileBlockRuleNames, const WCHAR *lpszMemoryBlockRuleNames)
{
	bool rv = false;
	HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessId);
	if (h) {
		rv = TerminateProcess(h, 'ARAY') == TRUE;
		CloseHandle(h);
	}

	if (bLog) {
		if (rv) {
			EventWritePROCESS_TERMINATED(dwProcessId, lpszFileName, lpszFileBlockRuleNames, lpszMemoryBlockRuleNames);
		} else {
			Warning(L"Unable to terminate process with Process ID 0x%08X and filename \"%ls\"", dwProcessId, lpszFileName ? lpszFileName : L"None");
		}
	}

	return rv;
}

