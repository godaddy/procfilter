
#include <Windows.h>
#include <Psapi.h>

#include "api.hpp"

#include <stdarg.h>
#include <malloc.h>

#include <map>

#include "config.hpp"
#include "die.hpp"
#include "strlcat.hpp"
#include "getfile.hpp"
#include "shellnotice.hpp"
#include "quarantine.hpp"
#include "path.hpp"
#include "yara.hpp"
#include "sha1.hpp"
#include "signing.hpp"
#include "winerr.hpp"
#include "status.hpp"
#include "timing.hpp"
#include "ProcFilterEvents.h"

#include "procfilter/procfilter.h"

#pragma comment (lib, "wintrust.lib")

#define MAX_PLUGINS 128

typedef DWORD (*ProcFilterEventCallback)(PROCFILTER_EVENT *e);
typedef struct procfilter_plugin PROCFILTER_PLUGIN;

//
// Represents a plugin
//
struct procfilter_plugin {
	// The below are read-only post-registration
	WCHAR szPlugin[MAX_PATH+1];                     // The full path of the plugin on disk
	WCHAR szConfigSection[64];                      // The plugin's section name in the INI file
	WCHAR szShortName[64];                          // The plugin's short name
	HMODULE hModule;                                // The plugin's handle
	ProcFilterEventCallback lpfnCallback;           // The callback invoked for each event in the plugin
	bool bRegistered;                               // Has the plugin registered via RegisterPlugin()?
	DWORD dwScanDataSize;                           // The size of this plugin's scan data
	DWORD dwProcessDataSize;                        // The size of this plugin's process data
	bool bSynchronizeEvents;                        // Should 
	bool bDesiredEventsArray[PROCFILTER_EVENT_NUM]; // Array of events to be exported to the plugin

	struct {		
		// These values must only be accessed via InterlockedXxx() functions!
		size_t nAllocations;                        // Number of allocations the plugin has outstanding
		size_t nEvents;                             // Number of events the plugin has handled
		LONG64 liTimeInPlugin;                      // Total time spent inside the plugin

		CRITICAL_SECTION mtx;                       // Mutex protecting non-interlocked values in this section (currently none)
	} mutable_data[1];

	CRITICAL_SECTION csEventCallbackMutex;          // The mutex that protects the api; only used if bSynchronizeEvents is set
};

static PROCFILTER_PLUGIN g_Plugins[MAX_PLUGINS] = {{ NULL, NULL }}; // Array of loaded plugins
static DWORD g_nPlugins = 0;                                        // The total number of plugins
static HANDLE g_hEventThread = NULL;                                // Handle to the event thread
static HANDLE g_hShutdownEventThreadEvent = NULL;                   // Should the event thread exit?
static _declspec(thread) PROCFILTER_PLUGIN *g_CurrentPlugin = NULL; // The current plugin with control of execution
static _declspec(thread) PROCFILTER_EVENT *g_CurrentEvent = NULL;   // The current event being processed
static DWORD g_dwMatchDataTotalSize = 0;                            // The total amount of match data space needed by all plugins, immutable after all plugins have registered
static DWORD g_dwProcessDataTotalSize = 0;                          // The total amount of process data space needed by all plugins, immutable after all plugins have regisered
static bool g_bWantThreadEvents = false;                            // Has any loaded plugin registered interest in receiving thread events?
static bool g_bWantImageLoadEvents = false;                         // Has any loaded plugin registered interest in receiving image load events?
static std::map<DWORD, BYTE*> g_ProcessDataMap;                     // PID -> void* mapping for per-process data
static CRITICAL_SECTION g_ProcessDataMapMutex;                      // Critical section that protects the process map

typedef NTSTATUS (WINAPI *NtQueryInformationProcessFunction)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
static HMODULE g_hNtdll = NULL;
NtQueryInformationProcessFunction g_NtQueryInformationProcess = NULL;

//
// These are set during plugin registation when plugins register interest in related events
//

static DWORD ExportApiEventPlugin(PROCFILTER_PLUGIN *p, PROCFILTER_EVENT *e, bool bCleanCacheAfterEvent);


//
// Get the current plugin that has control of execution.  This allows the API calls
// to do plugin-specific functions such as config value lookup without having the
// plugin API pass in a context pointer to every API call.
//
static inline
PROCFILTER_PLUGIN*
GetCurrentPlugin()
{
	if (!g_CurrentPlugin) Die("Plugin API function called from outside a plugin");
	return g_CurrentPlugin;
}

//
// The same as GetCurrentPlugin() except for events
//
static inline
PROCFILTER_EVENT*
GetCurrentEvent()
{
	if (!g_CurrentEvent) Die("Plugin API function called without being in an event");
	return g_CurrentEvent;
}


static inline
BYTE*
ProcessDataArrayAllocate()
{
	void *lpResult = malloc(g_dwProcessDataTotalSize ? g_dwProcessDataTotalSize : 1);
	if (!lpResult) Die("No memory for per-process data");
	ZeroMemory(lpResult, g_dwProcessDataTotalSize);

	return (BYTE*)lpResult;
}


static inline
void
ProcessDataArrayFree(void *lpvProcessData)
{
	free(lpvProcessData);
}


bool
ApiWantThreadEvents()
{
	return g_bWantThreadEvents;
}


bool
ApiWantImageLoadEvents()
{
	return g_bWantImageLoadEvents;
}


PROCFILTER_EVENT*
ApiGetCurrentEvent()
{
	return GetCurrentEvent();
}

//
// Build a string with debugging information pertaining to the current API state
//
void
ApiGetDebugInfo(WCHAR *lpszResult, DWORD dwResultSize)
{
	// These are not accessed through helper functions because they exit the program if null
	PROCFILTER_EVENT *e = g_CurrentEvent;
	PROCFILTER_PLUGIN *p = g_CurrentPlugin;

	wstrlprintf(lpszResult, dwResultSize, L"Plugin:%hs Event:%hs\n", p ? "Yes" : "No", e ? "Yes" : "No");
	if (p) wstrlcatf(lpszResult, dwResultSize, L"PluginName:%ls\n", p->szShortName);
	if (e) wstrlcatf(lpszResult, dwResultSize, L"EventId:%u\n", e->dwEventId);
}


//
// Display stats relating to the API to a remote procfilter process
//
void
ApiStatusPrint()
{
	LONG64 liFrequency = GetPerformanceFrequency();

	LONG64 *liTimeArray = (LONG64*)_malloca(sizeof(LONG64) * g_nPlugins);
	LONG64 liTotal = 0;

	for (DWORD i = 0; i < g_nPlugins; ++i) {
		PROCFILTER_PLUGIN *p = &g_Plugins[i];
		liTimeArray[i] = InterlockedExchangeAdd64(&p->mutable_data->liTimeInPlugin, 0);
		liTotal += liTimeArray[i];
	}
	if (liTotal <= 0) liTotal = 1;

	StatusPrint(L"Number of Plugins: %u\n\n", g_nPlugins);
	for (DWORD i = 0; i < g_nPlugins; ++i) {
		PROCFILTER_PLUGIN *p = &g_Plugins[i];
		size_t nEvents = InterlockedExchangeAddSizeT(&p->mutable_data->nEvents, 0);
		size_t nAllocations = InterlockedExchangeAddSizeT(&p->mutable_data->nAllocations, 0);
		StatusPrint(L"#%-2u Path:%ls\n",
			i + 1, p->szPlugin);
		StatusPrint(L"#%-2u Name:%ls NumEvents:%Iu NumAllocations:%Iu CfgSection:%ls\n",
			i + 1, p->szShortName, nEvents, nAllocations, p->szConfigSection);
		StatusPrint(L"#%-2u TotalTimeInPlugin:%I64d.%03I64d seconds (%.02f%% of plugin time)\n",
			i + 1, GetPerformanceSeconds(liTimeArray[i], liFrequency), GetPerformanceMilliseconds(liTimeArray[i], liFrequency) % 1000, GetPerformancePercent(liTimeArray[i], liTotal));
		StatusPrint(L"\n");
	}
	StatusPrint(L"TotalPluginOverhead:%I64d.%03I64d seconds\n", GetPerformanceSeconds(liTotal, liFrequency), GetPerformanceMilliseconds(liTotal, liFrequency) % 1000);

	_freea(liTimeArray);
}


void
CALLBACK
Export_RegisterPlugin(const WCHAR *szApiVersion, const WCHAR *lpszShortName, DWORD dwProcessDataSize, DWORD dwScanDataSize, bool bSynchronizeEvents, ...)
{
	PROCFILTER_PLUGIN *p = GetCurrentPlugin();
	
	// Make sure that the plugin hasnt registered before
	if (p->bRegistered) Die("Plugin attempted to register twice: \"%ls\"", p->szPlugin);

	// Verify that the core and plugin are the same version
	if (_wcsicmp(PROCFILTER_VERSION, szApiVersion) != 0) {
		Die("ProcFilter plugin API mismatch (Core:%ls Plugin:%ls)", PROCFILTER_VERSION, szApiVersion);
	}

	// Continue initialization originally started during the load of the plugin
	wstrlprintf(p->szShortName, sizeof(p->szShortName), L"%ls", lpszShortName);
	wstrlprintf(p->szConfigSection, sizeof(p->szConfigSection), L"%lsPlugin", lpszShortName);
	if (bSynchronizeEvents) {
		InitializeCriticalSection(&p->csEventCallbackMutex);
		p->bSynchronizeEvents = true;
	}
	InitializeCriticalSection(&p->mutable_data->mtx);
	p->dwScanDataSize = dwScanDataSize;
	g_dwMatchDataTotalSize += dwScanDataSize;
	p->dwProcessDataSize = dwProcessDataSize;
	g_dwProcessDataTotalSize += dwProcessDataSize;
	p->bRegistered = true;
	
	// Enable the requested events passed in to the call
	va_list ap;
	va_start(ap, bSynchronizeEvents);
	DWORD dEvent = PROCFILTER_EVENT_NONE;
	while ((dEvent = va_arg(ap, DWORD)) != PROCFILTER_EVENT_NONE) {
		if (dEvent == PROCFILTER_EVENT_IMAGE_LOAD) {
			g_bWantImageLoadEvents = true;
		} else if (dEvent == PROCFILTER_EVENT_THREAD_CREATE || dEvent == PROCFILTER_EVENT_THREAD_TERMINATE) {
			g_bWantThreadEvents = true;
		}

		if (dEvent == PROCFILTER_EVENT_ALL) {
			for (size_t i = 0; i < PROCFILTER_EVENT_NUM; ++i) {
				p->bDesiredEventsArray[i] = true;
			}
		} else if (dEvent > PROCFILTER_EVENT_NUM) {
			Die("Invalid event request in RegisterPlugin() for module \"%ls\": %u\n", p->szPlugin, dEvent);
		} else {
			p->bDesiredEventsArray[dEvent] = true;
		}
	}
	va_end(ap);
	
	// Force select events on
	p->bDesiredEventsArray[PROCFILTER_EVENT_SHUTDOWN] = true;
	p->bDesiredEventsArray[PROCFILTER_EVENT_STATUS] = true;
	if (dwProcessDataSize) p->bDesiredEventsArray[PROCFILTER_EVENT_PROCESS_DATA_CLEANUP] = true;
}


bool
CALLBACK
Export_GetProcessFileName(DWORD dwProcessId, WCHAR *lpszResult, DWORD dwResultSize)
{
	bool rv = false;

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId);
	if (hProcess) {
		DWORD dwNumChars = dwResultSize / sizeof(WCHAR);
		if (QueryFullProcessImageName(hProcess, PROCESS_NAME_NATIVE, lpszResult, &dwNumChars)) {
			rv = true;
		}

		CloseHandle(hProcess);
	}

	return rv;
}


//
// Get the module basename in the optimal way described in the remarks at:
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms683196%28v=vs.85%29.aspx
//
WCHAR*
CALLBACK
Export_GetProcessBaseNamePointer(WCHAR *lpszProcessFileName)
{
	WCHAR *p = wcsrchr(lpszProcessFileName, L'\\');
	if (p) return &p[1];
	return NULL;
}



void
CALLBACK
Export_LockPid()
{
	PROCFILTER_EVENT *e = GetCurrentEvent();
	if (!e->dwProcessId || e->private_data->hCurrentPid) return;
	e->private_data->hCurrentPid = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, e->dwProcessId);
}


void
CALLBACK
Export_Die(const char *fmt, ...)
{
	PROCFILTER_PLUGIN *p = GetCurrentPlugin();

	char szReason[2048];
	char szFileName[MAX_PATH+1];
	
	va_list ap;
	va_start(ap, fmt);

	strlprintf(szReason, sizeof(szReason), "Error in module \"%ls\": ", p->szPlugin);
	vstrlcatf(szReason, sizeof(szReason), fmt, ap);

	strlprintf(szFileName, sizeof(szFileName), "%ls", p->szPlugin);
	_Die(szFileName, 0, "%hs", szReason);

	va_end(ap);
}


bool
CALLBACK
Export_ReadProcessPeb(PEB *lpPeb)
{
	if (!g_NtQueryInformationProcess) return false;

	PROCFILTER_EVENT *e = GetCurrentEvent();

	HANDLE h = e->private_data->hReadMemoryCurrentProcess;
	if (!h) {
		h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, e->dwProcessId);
		e->private_data->hReadMemoryCurrentProcess = h;
	}

	bool rv = false;

	if (h) {
		PROCESS_BASIC_INFORMATION Pbi;
		DWORD dwSize = 0;
		DWORD dwStatus = g_NtQueryInformationProcess(h, ProcessBasicInformation, &Pbi, sizeof(PROCESS_BASIC_INFORMATION), &dwSize);
		if (NT_SUCCESS(dwStatus) && dwSize == sizeof(PROCESS_BASIC_INFORMATION)) {
			void *lpRemotePeb = Pbi.PebBaseAddress;
			SIZE_T dwBytesRead = 0;
			if (lpRemotePeb && ReadProcessMemory(h, lpRemotePeb, lpPeb, sizeof(PEB), &dwBytesRead) && dwBytesRead == sizeof(PEB)) {
				rv = true;
			}
		}
	}

	return rv;
}


bool
CALLBACK
Export_ReadProcessMemory(const void *lpvRemotePointer, void *lpszDestination, DWORD dwDestinationSize)
{
	bool rv = false;

	PROCFILTER_EVENT *e = GetCurrentEvent();
	if (!e->dwProcessId) return false;

	HANDLE h = e->private_data->hReadMemoryCurrentProcess;
	if (!h) {
		h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, e->dwProcessId);
		e->private_data->hReadMemoryCurrentProcess = h;
	}

	if (h) {
		SIZE_T dwBytesRead = 0;
		rv = ReadProcessMemory(h, lpvRemotePointer, lpszDestination, dwDestinationSize, &dwBytesRead) && dwBytesRead == dwDestinationSize;
	}

	return rv;
}


void
CALLBACK
Export_LogFmt(const char *fmt, ...)
{
	PROCFILTER_PLUGIN *p = GetCurrentPlugin();

	char szMessage[1024];

	va_list ap;
	va_start(ap, fmt);
	
	vstrlprintf(szMessage, sizeof(szMessage), fmt, ap);

	EventWritePLUGIN_LOG(p->szPlugin, szMessage);

	va_end(ap);
}


bool
CALLBACK
Export_FormatString(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, ...)
{
	va_list ap;
	va_start(ap, lpszFormatString);

	bool rv = vwstrlprintf(lpszDestination, dwDestinationSize, lpszFormatString, ap);

	va_end(ap);

	return rv;
}


bool
CALLBACK
Export_ConcatenateString(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, ...)
{
	va_list ap;
	va_start(ap, lpszFormatString);

	bool rv = vwstrlcatf(lpszDestination, dwDestinationSize, lpszFormatString, ap);

	va_end(ap);

	return rv;
}


bool
CALLBACK
Export_VFormatString(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, va_list ap)
{
	return vwstrlprintf(lpszDestination, dwDestinationSize, lpszFormatString, ap);
}


bool
CALLBACK
Export_VConcatenateString(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, va_list ap)
{
	return vwstrlcatf(lpszDestination, dwDestinationSize, lpszFormatString, ap);
}


YARASCAN_CONTEXT*
CALLBACK
Export_AllocateScanContext(const WCHAR *lpszYaraRuleFile, WCHAR *szError, DWORD dwErrorSize)
{
	CONFIG_DATA *cd = GetConfigData();

	if (lpszYaraRuleFile) {
		return YarascanAlloc3(lpszYaraRuleFile, szError, dwErrorSize);
	} else {
		return YarascanAllocDefault(szError, dwErrorSize, false, false);
	}
}


void
CALLBACK
Export_FreeScanContext(YARASCAN_CONTEXT *ctx)
{
	if (ctx) YarascanFree(ctx);
}


void
CALLBACK
Export_ScanFile(YARASCAN_CONTEXT *ctx, const WCHAR *lpszFileName, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *lpvUserData, SCAN_RESULT *o_result)
{
	YarascanScanFile(ctx, (WCHAR*)lpszFileName, 0, lpfnOnMatchCallback, lpfnOnMetaCallback, lpvUserData, o_result);
}


void
CALLBACK
Export_ScanMemory(YARASCAN_CONTEXT *ctx, DWORD dwProcessId, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *lpvUserData, SCAN_RESULT *o_result)
{
	YarascanScanMemory(ctx, dwProcessId, lpfnOnMatchCallback, lpfnOnMetaCallback, lpvUserData, o_result);
}



bool
CALLBACK
Export_GetFile(const WCHAR *lpszUrl, void *lpvResult, DWORD dwResultSize, DWORD *lpdwBytesUsed)
{
	return GetFile(lpszUrl, lpvResult, dwResultSize, lpdwBytesUsed);
}


void
CALLBACK
Export_Log(const char *str)
{
	Export_LogFmt("%hs", str);
}


int
CALLBACK
Export_GetConfigInt(const WCHAR *lpszKey, int dDefault)
{
	PROCFILTER_PLUGIN *p = GetCurrentPlugin();
	CONFIG_DATA *cd = GetConfigData();

	return GetPrivateProfileIntW(p->szConfigSection, lpszKey, dDefault, cd->szConfigFile);
}


bool
CALLBACK
Export_GetConfigBool(const WCHAR *lpszKey, bool bDefault)
{
	PROCFILTER_PLUGIN *p = GetCurrentPlugin();
	CONFIG_DATA *cd = GetConfigData();

	return GetPrivateProfileIntW(p->szConfigSection, lpszKey, bDefault ? 1 : 0, cd->szConfigFile) != 0;
}



void
CALLBACK
Export_GetConfigString(const WCHAR *lpszKey, const WCHAR *lpszDefault, WCHAR *lpszDestination, DWORD dwDestinationSize)
{
	PROCFILTER_PLUGIN *p = GetCurrentPlugin();
	CONFIG_DATA *cd = GetConfigData();

	if (dwDestinationSize/sizeof(WCHAR) > 0) {
		GetPrivateProfileStringW(p->szConfigSection, lpszKey, lpszDefault, lpszDestination, dwDestinationSize/sizeof(WCHAR), cd->szConfigFile);
		lpszDestination[dwDestinationSize/sizeof(WCHAR)-1] = '\0';
	}
}


bool
CALLBACK
Export_GetNtPathName(const WCHAR *lpszDosPath, WCHAR *lpszNtDevice, DWORD dwNtDeviceSize, WCHAR *lpszFilePath, DWORD dwFilePathSize, WCHAR *lpszFullPath, DWORD dwFullPathSize)
{
	return GetNtPathName(lpszDosPath, lpszNtDevice, dwNtDeviceSize, lpszFilePath, dwFilePathSize, lpszFullPath, dwFullPathSize);
}


DWORD
CALLBACK
Export_ShellNoticeFmt(DWORD dwDurationSeconds, bool bWait, DWORD dwStyle, WCHAR *lpszTitle, WCHAR *lpszMessageFmt, ...)
{
	WCHAR szMessage[1024];

	va_list ap;
	va_start(ap, lpszMessageFmt);

	vwstrlprintf(szMessage, sizeof(szMessage), lpszMessageFmt, ap);
	DWORD dwResult = ShellNoticeFmt(dwDurationSeconds, bWait, dwStyle, lpszTitle, L"%ls", szMessage);

	va_end(ap);

	return dwResult;
}


bool
CALLBACK
Export_QuarantineFile(const WCHAR *lpszFileName, char *o_lpszHexDigest, DWORD dwHexDigestSize)
{
	CONFIG_DATA *cd = GetConfigData();

	char o_hexdigest[SHA1_HEXDIGEST_LENGTH+1];
	bool rv = QuarantineFile(lpszFileName, cd->szQuarantineDirectory, 0, NULL, NULL, o_hexdigest);
	if (rv) {
		strlprintf(o_lpszHexDigest, dwHexDigestSize, "%hs", o_hexdigest);
	}

	return rv;
}


DWORD
CALLBACK
Export_ShellNotice(DWORD dwDurationSeconds, bool bWait, DWORD dwStyle, WCHAR *lpszTitle, WCHAR *lpszMessage)
{
	return Export_ShellNoticeFmt(dwDurationSeconds, bWait, dwStyle, lpszTitle, L"%ls", lpszMessage);
}


bool
CALLBACK
Export_Sha1File(const WCHAR *lpszFileName, char *lpszHexDigest, DWORD dwHexDigestSize, void *lpbaRawDigest, DWORD dwRawDigestSize)
{
	PROCFILTER_EVENT *e = GetCurrentEvent();
	
	bool rv = false;

	char hexdigest[SHA1_HEXDIGEST_LENGTH+1];
	BYTE rawdigest[SHA1_DIGEST_SIZE];

	// Check for a cache hit within the current event structure
	if (e->lpszFileName && wcscmp(lpszFileName, e->lpszFileName) == 0) {
		// Casting away the volatile is okay since the current thread is the only thread that could modify priate data
		if (e->private_data->bSha1Valid) {
			memcpy(hexdigest, (void*)e->private_data->szSha1HexDigest, SHA1_HEXDIGEST_LENGTH+1);
			memcpy(rawdigest, (void*)e->private_data->baSha1Digest, SHA1_DIGEST_SIZE);
		} else {
			rv = Sha1File(lpszFileName, hexdigest, rawdigest);
			if (rv) {
				memcpy((void*)e->private_data->szSha1HexDigest, hexdigest, SHA1_HEXDIGEST_LENGTH+1);
				memcpy((void*)e->private_data->baSha1Digest, rawdigest, SHA1_DIGEST_SIZE);
				e->private_data->bSha1Valid = true;
			}
		}
	} else {
		rv = Sha1File(lpszFileName, hexdigest, rawdigest);
	}

	if (rv) {
		if (lpszHexDigest) strlprintf(lpszHexDigest, dwHexDigestSize, "%hs", hexdigest);
		if (lpbaRawDigest) memcpy(lpbaRawDigest, rawdigest, dwRawDigestSize < sizeof(rawdigest) ? dwRawDigestSize : sizeof(rawdigest));
	}

	return rv;
}


void*
CALLBACK
Export_AllocateMemory(size_t dwNumElements, size_t dwElementSize)
{
	if (dwNumElements == 0 || dwElementSize == 0) return NULL;
		
	PROCFILTER_PLUGIN *p = GetCurrentPlugin();

	void *lpResult = calloc(dwNumElements, dwElementSize);
	if (!lpResult) {
		Die("Plugin \"%ls\" out of memory", p->szPlugin);
	}

	InterlockedIncrementSizeT(&p->mutable_data->nAllocations);

	return lpResult;
}


void
CALLBACK
Export_FreeMemory(void *lpPointer)
{
	PROCFILTER_PLUGIN *p = GetCurrentPlugin();

	free(lpPointer);
	
	size_t nAllocations = InterlockedDecrementSizeT(&p->mutable_data->nAllocations);
	if (nAllocations == -1) {
		PROCFILTER_EVENT *e = GetCurrentEvent();
		Die("Duplicate/errant free detected in \"%ls\" event %d", p->szPlugin, e->dwEventId);
	}
}


bool
CALLBACK
Export_GetProcFilterDirectory(WCHAR *lpszResult, DWORD dwResultSize, const WCHAR *lpszSubDirectoryBaseName)
{
	CONFIG_DATA *cd = GetConfigData();

	size_t dwSubDirLength = wcslen(lpszSubDirectoryBaseName);
	bool bAddTrailingSlash = dwSubDirLength > 0 && lpszSubDirectoryBaseName[dwSubDirLength-1] != '\\' && lpszSubDirectoryBaseName[dwSubDirLength-1] != '/';
	return wstrlprintf(lpszResult, dwResultSize, L"%ls%ls%hs", cd->szBaseDirectory, lpszSubDirectoryBaseName, bAddTrailingSlash ? "\\" : "");
}


bool
CALLBACK
Export_GetProcFilterFile(WCHAR *lpszResult, DWORD dwResultSize, const WCHAR *lpszFileBaseName)
{
	CONFIG_DATA *cd = GetConfigData();

	return wstrlprintf(lpszResult, dwResultSize, L"%ls%ls", cd->szBaseDirectory, lpszFileBaseName);
}


WCHAR*
CALLBACK
Export_DuplicateString(const WCHAR *lpszString)
{
	WCHAR *lpszResult = _wcsdup(lpszString);
	if (!lpszResult) Export_Die("No memory for string allocation");
	return lpszResult;
}


void
CALLBACK
Export_CreateWindowsProcess(WCHAR *lpszCommandLine, bool bWaitForExit)
{
	PROCFILTER_PLUGIN *p = GetCurrentPlugin();
}


bool
CALLBACK
Export_VerifyPeSignature(const WCHAR *lpszFileName, bool bCheckRevocations)
{
	return VerifyPeSignature(lpszFileName, bCheckRevocations);
}


void
ApiEventReinit(PROCFILTER_EVENT *e, DWORD dwEventId)
{
	// Zero the structure up until the function pointers begin
	ZeroMemory(e, (((BYTE*)(&e->private_data)) + sizeof(e->private_data)) - (BYTE*)e);

	e->RegisterPlugin = Export_RegisterPlugin; // this is a special case, since its at the beginning of the structure which gets zeroed above
	e->dwEventId = dwEventId;
	e->dwCurrentResult = PROCFILTER_RESULT_NONE;
}


void
ApiEventInit(PROCFILTER_EVENT *e, DWORD dwEventId)
{
	ZeroMemory(e, sizeof(PROCFILTER_EVENT));

#define StoreExport(name) e->##name = Export_##name
	StoreExport(RegisterPlugin);
	StoreExport(GetConfigInt);
	StoreExport(GetConfigString);
	StoreExport(GetConfigBool);
	StoreExport(AllocateScanContext);
	StoreExport(FreeScanContext);
	StoreExport(GetNtPathName);
	StoreExport(ShellNotice);
	StoreExport(ShellNoticeFmt);
	StoreExport(QuarantineFile);
	StoreExport(Sha1File);
	StoreExport(ScanFile);
	StoreExport(ScanMemory);
	StoreExport(Die);
	StoreExport(Log);
	StoreExport(LogFmt);
	StoreExport(AllocateMemory);
	StoreExport(GetFile);
	StoreExport(FreeMemory);
	StoreExport(DuplicateString);
	StoreExport(VerifyPeSignature);
	StoreExport(ConcatenateString);
	StoreExport(FormatString);
	StoreExport(VConcatenateString);
	StoreExport(VFormatString);
	StoreExport(ReadProcessMemory);
	StoreExport(ReadProcessPeb);
	StoreExport(GetProcFilterDirectory);
	StoreExport(GetProcFilterFile);
	StoreExport(StatusPrintFmt);
	StoreExport(GetProcessFileName);
	StoreExport(GetProcessBaseNamePointer);
	StoreExport(LockPid);
#undef StoreExport

#if defined(_DEBUG)
	// check all function pointers in the event structure to make sure they've been initalized to valid pointers
	void **start = (void**)(((BYTE*)&e->private_data) + sizeof(e->private_data));
	void **end = (void**)(((BYTE*)e) + sizeof(*e));
	while (start < end) {
		if (*start == NULL) Die("Function pointer not set in element %lu", (end - start) / sizeof(void*));
		++start;
	}
#endif

	ApiEventReinit(e, dwEventId);
}


static
void
LoadPlugin(PROCFILTER_EVENT *e, const WCHAR *szPluginDirectory, const WCHAR *szBasename, const WCHAR *szPluginFlags)
{
	CONFIG_DATA *cd = GetConfigData();

	// Get the plugin's path and load it
	WCHAR szPlugin[MAX_PATH+1];
	wstrlprintf(szPlugin, sizeof(szPlugin), L"%ls%ls.dll", szPluginDirectory, szBasename);
	
	if (cd->bRequireSignedPlugins && !VerifyPeSignature(szPlugin, true)) Die("Plugin not signed: %ls.  To allow loading of unsigned plugins set AllowUnsignedPlugins to 1 in procfilter.ini.", szPlugin);
	
	HMODULE hModule = LoadLibrary(szPlugin);
	if (!hModule) Die("Plugin not found: %ls", szPlugin);

	// Locate the ProcFilterEvent() callback
	ProcFilterEventCallback lpfnCallback = (ProcFilterEventCallback)GetProcAddress(hModule, "ProcFilterEvent");
	if (!lpfnCallback) Die("ProcFilterEvent() export not found in plugin \"%ls\", is it a ProcFilter plugin?", szPlugin);

	// Get the new plugin pointer and initialize it
	if (g_nPlugins >= MAX_PLUGINS) Die("Maximum number of plugins exceeded");
	PROCFILTER_PLUGIN *p = &g_Plugins[g_nPlugins++];
	ZeroMemory(p, sizeof(PROCFILTER_PLUGIN));
	wstrlprintf(p->szPlugin, sizeof(p->szPlugin), L"%ls", szPlugin);
	p->hModule = hModule;
	p->lpfnCallback = lpfnCallback;
	p->bDesiredEventsArray[PROCFILTER_EVENT_INIT] = true;
	p->bDesiredEventsArray[PROCFILTER_EVENT_SHUTDOWN] = true;

	// Export the init event to the plugin; the rest of the plugin contents are initialized during RegisterPlugin()
	e->lpszArgument = (WCHAR*)szPluginFlags;
	if (ExportApiEventPlugin(p, e, true) != PROCFILTER_RESULT_NONE) Die("Plugin returned bad init flags: \"%ls\"", szPlugin);

	// Make sure that the plugin called RegisterPlugin()
	if (!p->bRegistered) Die("Plugin failed to register: \"%ls\"", szPlugin);
}


DWORD
WINAPI
ep_ApiEventThread(void *lpUnused)
{
	PROCFILTER_EVENT e;
	ApiEventInit(&e, PROCFILTER_EVENT_TICK);

	while (WaitForSingleObject(g_hShutdownEventThreadEvent, 100) == WAIT_TIMEOUT) {
		ApiEventReinit(&e, PROCFILTER_EVENT_TICK);
		ApiEventExport(&e);
	}

	return 0;
}


void
ApiInit()
{
	CONFIG_DATA *cd = GetConfigData();

	InitializeCriticalSection(&g_ProcessDataMapMutex);

	g_hNtdll = LoadLibraryW(L"ntdll");	
	if (g_hNtdll) {
		g_NtQueryInformationProcess = (NtQueryInformationProcessFunction)GetProcAddress(g_hNtdll, "NtQueryInformationProcess");
	}

	// Get a list of the plugins to load
	WCHAR szPlugins[8192] = { '\0' };
	GetPrivateProfileString(CONFIG_APPNAME, L"Plugins", L"", szPlugins, sizeof(szPlugins)/sizeof(WCHAR), cd->szConfigFile);

	// Init the ProcFilter event
	PROCFILTER_EVENT e;
	ApiEventInit(&e, PROCFILTER_EVENT_INIT);

	// Load and export the event to all plugins listed in the config file
	static const WCHAR *delims = L" ;,|\t";
	WCHAR *next = NULL;
	WCHAR *token = wcstok_s(szPlugins, delims, &next);
	while (token) {
		WCHAR *args = L"";
		WCHAR *p = NULL;
		if ((p = wcschr(token, ':')) != NULL) { *p = '\0'; args = &p[1]; }
		LoadPlugin(&e, cd->szPluginDirectory, token, args);
		token = wcstok_s(NULL, delims, &next);
	}

	// Create the event thread
	g_hShutdownEventThreadEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!g_hShutdownEventThreadEvent) Die("Unable to create shutdown event in API module");

	g_hEventThread = CreateThread(NULL, 0, ep_ApiEventThread, NULL, 0, NULL);
	if (!g_hEventThread) Die("Unable to create API event thread");
}


void
ApiShutdown()
{
	CONFIG_DATA *cd = GetConfigData();

	// Stop the event thread
	SetEvent(g_hShutdownEventThreadEvent);
	WaitForSingleObject(g_hEventThread, INFINITE);
	CloseHandle(g_hEventThread);
	CloseHandle(g_hShutdownEventThreadEvent);

	// Export a cleanup event for all processes that havent terminated yet
	PROCFILTER_EVENT e;
	ApiEventInit(&e, PROCFILTER_EVENT_NONE);
	EnterCriticalSection(&g_ProcessDataMapMutex);
	for (auto iter = g_ProcessDataMap.begin(); iter != g_ProcessDataMap.end(); ++iter) {
		ApiEventReinit(&e, PROCFILTER_EVENT_PROCESS_DATA_CLEANUP);
		e.dwProcessId = iter->first;
		e.lpvProcessData = iter->second;
		ApiEventExport(&e);
		ApiFreeScanDataArray(iter->second);
	}
	g_ProcessDataMap.clear();
	LeaveCriticalSection(&g_ProcessDataMapMutex);

	// Init and export the shutdown event to all plugins
	ApiEventReinit(&e, PROCFILTER_EVENT_SHUTDOWN);
	ApiEventExport(&e);

	// Unload all plugins in reverse order from which they were loaded
	for (DWORD i = g_nPlugins; i > 0; --i) {
		PROCFILTER_PLUGIN *p = &g_Plugins[i-1];

#ifdef _DEBUG
		if (p->mutable_data->nAllocations != 0) Die("Memory leak detected during shutdown of plugin %ls", p->szPlugin);
#endif

		if (p->bSynchronizeEvents) DeleteCriticalSection(&p->csEventCallbackMutex);
		DeleteCriticalSection(&p->mutable_data->mtx);
		FreeLibrary(p->hModule);
	}

	// Release the libraries used for NtQueryInformationProcess()
	if (g_hNtdll) {
		g_NtQueryInformationProcess = NULL;
		FreeLibrary(g_hNtdll);
		g_hNtdll = NULL;
	}

	DeleteCriticalSection(&g_ProcessDataMapMutex);
}


int
FilterException(int dCode, PEXCEPTION_POINTERS lpepExceptionPointers, int *o_Code)
{
	*o_Code = dCode;
	return EXCEPTION_EXECUTE_HANDLER;
}


//
// Close down and deallocate cached data created while events were exported
//
static
void
ApiEventCacheCleanup(PROCFILTER_EVENT *e)
{
	// cleanup cached handles
	if (e->private_data->hReadMemoryCurrentProcess) {
		CloseHandle(e->private_data->hReadMemoryCurrentProcess);
		e->private_data->hReadMemoryCurrentProcess = NULL;
	}
	if (e->private_data->hCurrentPid) {
		CloseHandle(e->private_data->hCurrentPid);
		e->private_data->hCurrentPid = NULL;
	}
	e->private_data->bSha1Valid = false;
}


//
// Export an event to a specific plugin
//
static
DWORD
ExportApiEventPlugin(PROCFILTER_PLUGIN *p, PROCFILTER_EVENT *e, bool bCleanCacheAfterEvent)
{
	DWORD dwResult = e->dwCurrentResult;
	
	// validity check the event to be exported
	if (e->dwEventId >= PROCFILTER_EVENT_NUM) Die("Event ID out of range: %d", e->dwEventId);

	// make sure that the target plugin wants the event
	if (!p->bDesiredEventsArray[e->dwEventId]) return dwResult;

	// start performance counter
	LONG64 llStart = GetPerformanceCount();
	
	// lock the mutex if needed
	if (p->bSynchronizeEvents) EnterCriticalSection(&p->csEventCallbackMutex);

	// call the target plugin's event handler and update the result
	g_CurrentPlugin = p;
	g_CurrentEvent = e;
	int dExceptionCode = 0;
	__try {
		dwResult |= p->lpfnCallback(e);
		InterlockedIncrementSizeT(&p->mutable_data->nEvents);
		e->dwCurrentResult = dwResult;
	} __except (FilterException(GetExceptionCode(), GetExceptionInformation(), &dExceptionCode)) {
		Die("Fatal exception 0x%08X (%ls) in plugin \"%ls\" during event %u",
			(DWORD)dExceptionCode, ErrorText((DWORD)dExceptionCode), p->szPlugin, e->dwEventId);
	}
	g_CurrentEvent = NULL;
	g_CurrentPlugin = NULL;

	// unlock the mutex if needed
	if (p->bSynchronizeEvents) LeaveCriticalSection(&p->csEventCallbackMutex);

	if (bCleanCacheAfterEvent) {
		ApiEventCacheCleanup(e);
	}

	LONG64 llDuration = GetPerformanceCount() - llStart;
	InterlockedAdd64(&p->mutable_data->liTimeInPlugin, llDuration);

	return dwResult;
}


void*
ApiAllocateScanDataArray()
{
	// Always allocate at least something since the result of a zero-sized allocation is 
	// implementation specific and could return NULL, which would be interpreted as an error condition
	return calloc(1, g_dwMatchDataTotalSize ? g_dwMatchDataTotalSize : 1);
}


void
ApiFreeScanDataArray(void *lpvScanDataArray)
{
	free(lpvScanDataArray);
}


//
// Export an event to all loaded plugins
//
DWORD
ApiEventExport(PROCFILTER_EVENT *e)
{
	DWORD dwResult = e->dwCurrentResult;

	if (e->dwEventId >= PROCFILTER_EVENT_NUM) Die("Event ID out of range: %d", e->dwEventId);
	
	// Get the match data pointer to update if necessary
	BYTE *lpvScanData = (BYTE*)e->lpvScanData;
	if (lpvScanData && e->dwEventId == PROCFILTER_EVENT_YARA_SCAN_INIT) {
		ZeroMemory(lpvScanData, g_dwMatchDataTotalSize);
	}
	
	// Setup the process data pointer
	BYTE *lpvProcessData = (BYTE*)e->lpvProcessData;
	DWORD dwCleanupProcessId = 0;
	if (e->dwEventId == PROCFILTER_EVENT_PROCESS_CREATE) {
		lpvProcessData = ProcessDataArrayAllocate();
		EnterCriticalSection(&g_ProcessDataMapMutex);
		// Insertion must be done here prior to the event being exported to avoid a race condition in which
		// the new process exits before the pointer is stored into the process data map
		g_ProcessDataMap.insert(std::make_pair(e->dwProcessId, lpvProcessData));
		LeaveCriticalSection(&g_ProcessDataMapMutex);
	} else if (e->dwEventId == PROCFILTER_EVENT_PROCESS_TERMINATE) {
		EnterCriticalSection(&g_ProcessDataMapMutex);
		auto iter = g_ProcessDataMap.find(e->dwProcessId);
		if (iter != g_ProcessDataMap.end()) {
			dwCleanupProcessId = iter->first;
			lpvProcessData = iter->second;
			g_ProcessDataMap.erase(iter);
		} else {
			lpvProcessData = NULL;
		}
		LeaveCriticalSection(&g_ProcessDataMapMutex);
	}

	// Export the event to each loaded plugin
	BYTE *lpvPerPluginProcessData = lpvProcessData;
	for (DWORD i = 0; i < g_nPlugins; ++i) {
		PROCFILTER_PLUGIN *p = &g_Plugins[i];
		e->lpvScanData = lpvScanData;
		e->lpvProcessData = lpvPerPluginProcessData;
		if (p->bDesiredEventsArray[e->dwEventId]) {
			dwResult |= ExportApiEventPlugin(p, e, false);
			e->dwCurrentResult = dwResult;
		}

		// Update the match and process data pointers if in use
		if (lpvScanData) lpvScanData += p->dwScanDataSize; 
		if (lpvPerPluginProcessData) lpvPerPluginProcessData += p->dwProcessDataSize; 
	}

	ApiEventCacheCleanup(e);

	// Deallocate the associated process data if present
	if (e->dwEventId == PROCFILTER_EVENT_PROCESS_TERMINATE && lpvProcessData) {
		ApiEventReinit(e, PROCFILTER_EVENT_PROCESS_DATA_CLEANUP);
		e->dwProcessId = dwCleanupProcessId;
		e->lpvProcessData = lpvProcessData;
		ApiEventExport(e);
		ProcessDataArrayFree(lpvProcessData);
	}

	return dwResult;
}
