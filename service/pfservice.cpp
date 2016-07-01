
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <io.h>
#include <stdio.h>
#include "psapi.h"

#include "api.hpp"
#include "die.hpp"
#include "log.hpp"
#include "pfservice.hpp"
#include "ProcFilterEvents.h"
#include "quarantine.hpp"
#include "scan.hpp"
#include "service.hpp"
#include "status.hpp"
#include "strlcat.hpp"
#include "svcutil.hpp"
#include "umdriver.hpp"
#include "update.hpp"
#include "winerr.hpp"
#include "yara.hpp"



static void RunPeriodicProcFilter(YARASCAN_CONTEXT *ctx, HANDLE hStopEvent, void *lpvScanDataArray);

static bool g_RestartService = false;

//
// Determine whether or not the service is running, as determined
// by the stop event being signalled
//
static
bool
Running(HANDLE hStopEvent)
{
	DWORD rv = WaitForSingleObject(hStopEvent, 0);
	if (rv == WAIT_OBJECT_0 || rv == WAIT_FAILED) {
		return false;
	}

	return true;
}



bool
IsProcFilterServiceRunning()
{	
	bool rv = false;

	// Open the service control manager
	SC_HANDLE hSCM = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if (hSCM) {
		// Stop the old driver service if it exists
		SC_HANDLE hService = OpenService(hSCM, SERVICE_NAME, SERVICE_QUERY_STATUS);
		if (hService) {
			SERVICE_STATUS ss;
			rv = QueryServiceStatus(hService, &ss) && ss.dwCurrentState == SERVICE_STOPPED;
			CloseServiceHandle(hService);
		}

		CloseServiceHandle(hSCM);
	}

	return rv;
}


void
ProcFilterServiceRequestRestart()
{
	g_RestartService = true;
}


//
// The mainloop of the ProcFilter service
//
void
ProcFilterServiceMainloop(HANDLE hStopEvent)
{
	CONFIG_DATA *cd = GetConfigData();

	// The service thread runs at high p
	if (!SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) Die("Unable to set process priority class");

	EventWritePROCFILTERSERVICE_STARTED();

	ScanInit();
	UpdateInit();
	ApiInit();
	StatusInit();

	DWORD dwLastScanTick = GetTickCount() - (cd->dwScanIntervalSeconds * 1000);
	void *lpvScanDataArray = ApiAllocateScanDataArray();

	do {
		g_RestartService = false;
		DriverInit();
	
		WCHAR szError[512] = { '\0' };
	
		if (!lpvScanDataArray) Die("Unable to allocate match data array for periodic scanning");

		do {
			// Rescan if needed
			DWORD now = GetTickCount();
			if (cd->dwScanIntervalSeconds && now - dwLastScanTick >= cd->dwScanIntervalSeconds * 1000) {

				YARASCAN_CONTEXT *ctx = YarascanAllocDefault(szError, sizeof(szError), true, false);

				if (ctx) {
					// Start the scan and keep track of the time
					bool bUseBackgroundMode = cd->bUseBackgroundMode ? true : false;
					if (bUseBackgroundMode) SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
					RunPeriodicProcFilter(ctx, hStopEvent, lpvScanDataArray);
					if (bUseBackgroundMode) SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
					YarascanFree(ctx);
				}
			
				// Scanning may take time, so store an updated tick count instead of 'base'
				dwLastScanTick = GetTickCount();
			} else {
				Sleep(100);
			}
		} while (Running(hStopEvent) && !g_RestartService);

		DriverShutdown();
	} while (Running(hStopEvent) && g_RestartService);

	StatusShutdown();
	ApiFreeScanDataArray(lpvScanDataArray);
	ApiShutdown();
	UpdateShutdown();
	ScanShutdown();

	EventWritePROCFILTERSERVICE_STOPPED();
}


static
void
RunPeriodicProcFilter(YARASCAN_CONTEXT *ctx, HANDLE hStopEvent, void *lpvScanDataArray)
{
	CONFIG_DATA *cd = GetConfigData();

	EventWritePERIODIC_SCAN_STARTED();

	// Create the handle snapshot according to:
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684218%28v=vs.85%29.aspx
	size_t szLoopLimit = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
	while (hSnapshot == INVALID_HANDLE_VALUE && GetLastError() == ERROR_BAD_LENGTH && szLoopLimit++ < 10000) {
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
	}
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		EventWritePERIODIC_SCAN_FINISHED();
		return;
	}
	
	// Iterate through all processes
	PROCFILTER_EVENT e;
	ApiEventInit(&e, PROCFILTER_EVENT_NONE);
	bool first = true;
	DWORD dwSelfPid = GetCurrentProcessId();
	while (1) {
		PROCESSENTRY32 pe;
		ZeroMemory(&pe, sizeof(pe));
		pe.dwSize = sizeof(PROCESSENTRY32);

		// Get the next process
		if (first) {
			if (!Process32First(hSnapshot, &pe)) break;
			first = false;
		} else {
			if (!Process32Next(hSnapshot, &pe)) break;
		}

		DWORD dwProcessId = pe.th32ProcessID;
		DWORD dwParentProcessId = pe.th32ParentProcessID;
		// If the process is the service process then skip it
		if (dwProcessId == dwSelfPid) continue;
		if (dwProcessId == 0) continue;
		if (dwProcessId == 4) continue;

		// Get the module's exe file name according to:
		// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684218%28v=vs.85%29.aspx
		szLoopLimit = 0;
		MODULEENTRY32 meModuleEntry;
		BOOL rc = FALSE;
		do {
			ZeroMemory(&meModuleEntry, sizeof(MODULEENTRY32));
			meModuleEntry.dwSize = sizeof(MODULEENTRY32);
			rc = Module32First(hSnapshot, &meModuleEntry);
		} while (!rc && GetLastError() == ERROR_BAD_LENGTH && szLoopLimit++ < 1000);

		// Do the scanning
		if (rc) Scan(EVENTTYPE_NONE, PROCFILTER_SCAN_CONTEXT_PERIODIC_SCAN, &e, ctx, NULL, NULL, dwProcessId, 0, pe.szExeFile, NULL, lpvScanDataArray);

		if (WaitForSingleObject(hStopEvent, cd->dwPerProcessTimeoutMs) == WAIT_OBJECT_0) break;
	}

	CloseHandle(hSnapshot);
	
	EventWritePERIODIC_SCAN_FINISHED();
}
