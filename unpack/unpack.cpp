

#include "procfilter/procfilter.h"

#include <winternl.h>
#include <malloc.h>
#include <time.h>


typedef struct match_data SCAN_DATA;
struct match_data {
	bool bUnpack;
};


WCHAR g_szUnpackDirectory[MAX_PATH+1] = { '\0' };


bool
DumpProcessMemory(PROCFILTER_EVENT *e, const WCHAR *lpszFileName)
{
	PEB Peb;
	PEB_LDR_DATA LoaderData;
	LIST_ENTRY Link;
	LDR_DATA_TABLE_ENTRY LoaderDataTableEntry;
	bool rv = true;

	if (e->ReadProcessPeb(&Peb) &&
		e->ReadProcessMemory(Peb.Ldr, &LoaderData, sizeof(LoaderData)) &&
		e->ReadProcessMemory(LoaderData.InMemoryOrderModuleList.Flink, &Link, sizeof(Link)) &&
		e->ReadProcessMemory(CONTAINING_RECORD(Link.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &LoaderDataTableEntry, sizeof(LoaderDataTableEntry))) {
			
			SYSTEM_INFO si;
			GetSystemInfo(&si);
			DWORD dwPageSize = si.dwPageSize;
			BYTE *lpRemoteBaseAddress = (BYTE*)LoaderDataTableEntry.DllBase;

			HANDLE hMemoryDump = CreateFileW(lpszFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, 0, NULL);
			if (hMemoryDump != INVALID_HANDLE_VALUE) {
				BYTE *lpbaCurrentPage = (BYTE*)_alloca(dwPageSize);
				DWORD dwBytesWritten = 0;
				size_t nPages = 0;
				BOOL rc = FALSE;
				while (e->ReadProcessMemory(&lpRemoteBaseAddress[nPages * dwPageSize], lpbaCurrentPage, dwPageSize) &&
						(rc = WriteFile(hMemoryDump, lpbaCurrentPage, dwPageSize, &dwBytesWritten, NULL)) == TRUE && dwBytesWritten == dwPageSize) {
							++nPages;
				}

				if (rc == TRUE && dwBytesWritten == 0) {
					rv = true;
				}

				CloseHandle(hMemoryDump);
			}
	}

	return rv;
}


DWORD
ProcFilterEvent(PROCFILTER_EVENT *e)
{
	DWORD dwResultFlags = PROCFILTER_RESULT_NONE;
	SCAN_DATA *md = (SCAN_DATA*)e->lpvScanData;
	
	if (e->dwEventId == PROCFILTER_EVENT_INIT) {
		e->RegisterPlugin(PROCFILTER_VERSION, L"Unpack", 0, sizeof(SCAN_DATA), false,
			PROCFILTER_EVENT_YARA_SCAN_COMPLETE, PROCFILTER_EVENT_YARA_RULE_MATCH_META_TAG, PROCFILTER_EVENT_NONE);

		e->GetProcFilterDirectory(g_szUnpackDirectory, sizeof(g_szUnpackDirectory), L"unpack");
		CreateDirectoryW(g_szUnpackDirectory, NULL);
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_RULE_MATCH_META_TAG) {
		// this event happens for each meta value name in every rule that matches
		if (_stricmp(e->lpszMetaTagName, "UnpackProcess") == 0 && e->dNumericValue) {
			md->bUnpack = true;
		}
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_SCAN_COMPLETE && e->dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_TERMINATE) {
		if (md->bUnpack) {
			char szTimestamp[MAX_PATH+1] = { '\0' };
			time_t now = time(NULL);
			struct tm timeinfo;
			if (localtime_s(&timeinfo, &now) && strftime(szTimestamp, sizeof(szTimestamp)-sizeof(WCHAR), "%F-%H-%M-%S", &timeinfo) > 0) {
				WCHAR szBaseName[MAX_PATH+1] = { '\0' };
				WCHAR szUnpackFile[MAX_PATH+1];
				if (_wsplitpath_s(e->lpszFileName, NULL, 0, NULL, 0, szBaseName, sizeof(szBaseName)/sizeof(WCHAR)-1, NULL, 0) == 0 &&
					e->FormatString(szUnpackFile, sizeof(szUnpackFile), L"%ls%ls-%hs-%d.mem", g_szUnpackDirectory, szBaseName, szTimestamp, e->dwProcessId)) {
					if (DumpProcessMemory(e, szUnpackFile)) {
						e->LogFmt("Process %d %ls unpacked to: %ls", e->dwProcessId, e->lpszFileName, szUnpackFile);
					}
				}
			}
		}
	}

	return dwResultFlags;
}

