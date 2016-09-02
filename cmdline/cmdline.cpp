


#include "procfilter/procfilter.h"

#include <winternl.h>

#include <map>
#include <string>
#include <utility>


class ParentData {
public:
	ParentData(const WCHAR *lpszBasename, bool bLogSubprocess, bool bAskSubprocess) :
		wsBasename{lpszBasename}, bLogSubprocess(bLogSubprocess), bAskSubprocess(bAskSubprocess)
	{ }
	ParentData() :
		bAskSubprocess(false), bLogSubprocess(false)
	{ }
	std::wstring wsBasename;
	bool bAskSubprocess;
	bool bLogSubprocess;
};
typedef std::map<DWORD, ParentData> PidSet;
static PidSet g_pidSet;
static CRITICAL_SECTION g_pidSetMutex;
static WCHAR g_szRuleFileBaseName[MAX_PATH+1] = { '\0' };

static __declspec(thread) YARASCAN_CONTEXT *tg_CommandLineRulesContext = NULL;

typedef struct match_data SCAN_DATA;
struct match_data {
	bool   bCaptureCommandLine; // Should the command line associated with this process be captured?
	bool   bLogSubprocesses;    // Log subprocesses of this process?
	bool   bAskSubprocesses;    // Ask about creating subprocesses of this process?
	WCHAR *lpszCommandLine;     // A copy of the command line if captured
};


void
LoadCommandLineRules(PROCFILTER_EVENT *e)
{
	if (wcslen(g_szRuleFileBaseName) > 0) {
		WCHAR szError[256] = { '\0' };
		tg_CommandLineRulesContext = e->AllocateScanContextLocalAndRemote(g_szRuleFileBaseName, szError, sizeof(szError), true);
		if (!tg_CommandLineRulesContext) {
			e->LogFmt("Error compiling rules file %ls: %ls", g_szRuleFileBaseName, szError);
		}
	}
}


//
// Store the command line associated with the current process into the SCAN_DATA structure.
//
WCHAR*
CaptureCommandLine(PROCFILTER_EVENT *e)
{
	// read the processes PEB and it's Parameters structure
	WCHAR *lpszResult = NULL;
	PEB Peb;
	RTL_USER_PROCESS_PARAMETERS Parameters;
	if (e->ReadProcessPeb(&Peb) && e->ReadProcessMemory(Peb.ProcessParameters, &Parameters, sizeof(Parameters))) {
		// check to make sure the command line is present
		DWORD len = Parameters.CommandLine.Length;
		if (len > 0) {
			// allocate memory for the command line and then copy it out from the remote process
			lpszResult = (WCHAR*)e->AllocateMemory(len + 1, sizeof(WCHAR));
			if (lpszResult && e->ReadProcessMemory(Parameters.CommandLine.Buffer, lpszResult, len)) {
				lpszResult[len] = '\0';
			} else if (lpszResult) {
				e->FreeMemory(lpszResult);
				lpszResult = NULL;
			}
		}
	}

	return lpszResult;
}


//
// Log the scan result and update the process block flags
//
DWORD
LogCommandLineScanResult(PROCFILTER_EVENT *e, SCAN_RESULT *srResult, WCHAR *lpszCommandLine, bool bBlock, bool bLog)
{
	DWORD dwResultFlags = PROCFILTER_RESULT_NONE;

	if (srResult->bScanSuccessful) {
		if (bLog && srResult->bLog) e->LogFmt("Process PID %d (%ls) matched rule with Log tag: %ls\n Command Line:%ls",
			e->dwProcessId, e->lpszFileName, srResult->szLogRuleNames, lpszCommandLine);
		if (bBlock && srResult->bBlock) {
			e->LogFmt("Process PID %d (%ls) matched rule with Block tag: %ls\n Command Line:%ls",
				e->dwProcessId, e->lpszFileName, srResult->szBlockRuleNames, lpszCommandLine);
			dwResultFlags |= PROCFILTER_RESULT_BLOCK_PROCESS;
		}
	} else {
		e->LogFmt("'cmdline' plugin unable to scan command line for PID %d: %ls", e->dwProcessId, srResult->szError);
	}

	return dwResultFlags;
}

//
// ProcFilter event handler
//
DWORD
ProcFilterEvent(PROCFILTER_EVENT *e)
{
	DWORD dwResultFlags = PROCFILTER_RESULT_NONE;
	SCAN_DATA *sd = (SCAN_DATA*)e->lpvScanData;
	
	if (e->dwEventId == PROCFILTER_EVENT_INIT) {
		// register the plugin with the core
		e->RegisterPlugin(PROCFILTER_VERSION, L"CommandLine", 0, sizeof(SCAN_DATA), false,
			PROCFILTER_EVENT_YARA_SCAN_INIT, PROCFILTER_EVENT_YARA_SCAN_COMPLETE, PROCFILTER_EVENT_YARA_SCAN_CLEANUP,
			PROCFILTER_EVENT_YARA_RULE_MATCH, PROCFILTER_EVENT_YARA_RULE_MATCH_META_TAG, PROCFILTER_EVENT_PROCESS_CREATE,
			PROCFILTER_EVENT_PROCESS_TERMINATE, PROCFILTER_EVENT_NONE);
		
		InitializeCriticalSection(&g_pidSetMutex);

		e->GetConfigString(L"RuleFile", L"", g_szRuleFileBaseName, sizeof(g_szRuleFileBaseName));
	} else if (e->dwEventId == PROCFILTER_EVENT_SHUTDOWN) {
		DeleteCriticalSection(&g_pidSetMutex);
	} else if (e->dwEventId == PROCFILTER_EVENT_PROCFILTER_THREAD_INIT) {
		LoadCommandLineRules(e);
	} else if (e->dwEventId == PROCFILTER_EVENT_PROCFILTER_THREAD_SHUTDOWN) {
		if (tg_CommandLineRulesContext) e->FreeScanContext(tg_CommandLineRulesContext);
	} else if (e->dwEventId == PROCFILTER_EVENT_PROCESS_CREATE) {
		// Get the data associated with this processes parent
		ParentData parentData;
		EnterCriticalSection(&g_pidSetMutex);
		auto iter = g_pidSet.find(e->dwParentProcessId);
		if (iter != g_pidSet.end()) {
			parentData = iter->second;
		}
		LeaveCriticalSection(&g_pidSetMutex);

		// Extract the command line data associated with the current process, if needed
		WCHAR *lpszCommandLine = NULL;
		if (parentData.bLogSubprocess || parentData.bAskSubprocess || tg_CommandLineRulesContext) {
			lpszCommandLine = CaptureCommandLine(e);
		}

		// Subprocesses logged?
		if (parentData.bLogSubprocess) {
			e->LogFmt("Subprocess of %d %ls: %d %ls: %ls",
				e->dwParentProcessId, parentData.wsBasename.c_str(), e->dwProcessId, e->lpszFileName,
				lpszCommandLine ? lpszCommandLine : L"NULL");
		}

		// If the command line data, filename, and scanning context is available then scan
		// the command line arguments with the rules specified for it
		if (lpszCommandLine && e->lpszFileName && tg_CommandLineRulesContext) {
			const DWORD dwCommandLineCharCount = (DWORD)wcslen(lpszCommandLine);

			// Scan the UNICODE command line and log the result
			SCAN_RESULT srUnicodeResult;
			ZeroMemory(&srUnicodeResult, sizeof(SCAN_RESULT));
			e->ScanData(tg_CommandLineRulesContext, lpszCommandLine, dwCommandLineCharCount * sizeof(WCHAR) + sizeof(WCHAR), NULL, NULL, NULL, &srUnicodeResult);
			dwResultFlags |= LogCommandLineScanResult(e, &srUnicodeResult, lpszCommandLine, true, true);
			
			// For convenience also scan with ASCII
			char *lpszAsciiCommandLine = (char*)e->AllocateMemory(dwCommandLineCharCount + 1 , sizeof(char));
			if (lpszAsciiCommandLine) {
				snprintf(lpszAsciiCommandLine, dwCommandLineCharCount + 1, "%ls", lpszCommandLine);
				lpszAsciiCommandLine[dwCommandLineCharCount] = '\0';
				
				// Scan the ASCII command line
				SCAN_RESULT srAsciiResult;
				ZeroMemory(&srAsciiResult, sizeof(SCAN_RESULT));
				e->ScanData(tg_CommandLineRulesContext, lpszAsciiCommandLine, dwCommandLineCharCount + 1, NULL, NULL, NULL, &srAsciiResult);
				
				// Only Block/Log the result if it wasn't logged before
				dwResultFlags |= LogCommandLineScanResult(e, &srAsciiResult, lpszCommandLine, !srUnicodeResult.bBlock, !srUnicodeResult.bLog);

				// Cleanup
				e->FreeMemory(lpszAsciiCommandLine);
			}
		}

		// If the process isn't blocked yet prompt the user interactively
		if (parentData.bAskSubprocess && !(dwResultFlags & PROCFILTER_RESULT_BLOCK_PROCESS)) {
			if (e->ShellNoticeFmt(0, true, MB_ICONWARNING | MB_YESNO, L"Allow process?",
				L"The program \"%ls\" is trying to run the following file:\n%ls\n\nCommand line:\n%ls\n\nAllow? Select 'No' if unsure.",
				parentData.wsBasename.c_str(), e->lpszFileName,
				lpszCommandLine ? lpszCommandLine : L"NULL") != IDYES) {
				dwResultFlags |= PROCFILTER_RESULT_BLOCK_PROCESS;
			}
		}

		if (lpszCommandLine) e->FreeMemory(lpszCommandLine);
	} else if (e->dwEventId == PROCFILTER_EVENT_PROCESS_TERMINATE) {
		EnterCriticalSection(&g_pidSetMutex);
		auto iter = g_pidSet.find(e->dwProcessId);
		if (iter != g_pidSet.end()) {
			g_pidSet.erase(iter);
		}
		LeaveCriticalSection(&g_pidSetMutex);
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_SCAN_INIT) {
		// the match data buffer is zero-initialized by the core, but extra init can be done here if needed
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_RULE_MATCH) {
		// this event happens every time a rule is matched during a scan
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_RULE_MATCH_META_TAG) {
		// this event happens for each meta value name in every rule that matches
		// since we only care if this tag is set anywhere, its fine if this meta tag
		// is found in several rules
		if (_stricmp(e->lpszMetaTagName, "CaptureCommandLine") == 0 && e->dNumericValue) {
			sd->bCaptureCommandLine = true;
		}
		if (_stricmp(e->lpszMetaTagName, "LogSubprocesses") == 0 && e->dNumericValue) {
			sd->bLogSubprocesses = true;
		}
		if (_stricmp(e->lpszMetaTagName, "AskSubprocesses") == 0 && e->dNumericValue) {
			sd->bAskSubprocesses = true;
		}
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_SCAN_COMPLETE) {
		// here we can look at the match data as filled in during prior events and capture the command line accordingly
		// while the process is still suspended
		if (sd->bCaptureCommandLine) {
			sd->lpszCommandLine = CaptureCommandLine(e);
		}
		if (sd->bLogSubprocesses || sd->bAskSubprocesses) {
			EnterCriticalSection(&g_pidSetMutex);
			g_pidSet.insert(PidSet::value_type(e->dwProcessId, ParentData(e->GetProcessBaseNamePointer(e->lpszFileName), sd->bLogSubprocesses, sd->bAskSubprocesses)));
			LeaveCriticalSection(&g_pidSetMutex);
		}
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_SCAN_CLEANUP) {
		// here we examine the contents as filled in durring scanning, and handle our final results accordingly
		if (sd->bCaptureCommandLine && sd->lpszCommandLine) {
			e->LogFmt("Command line for %d %ls: %ls", e->dwProcessId, e->lpszFileName, sd->lpszCommandLine);

			// release previously allocated memory
			e->FreeMemory(sd->lpszCommandLine);
		}
	}

	return dwResultFlags;
}

