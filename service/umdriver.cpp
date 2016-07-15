
#include <malloc.h>

#include "winerr.hpp" // this one has to be first otherwise a strange redefinition error appears
#include "umdriver.hpp"

#include "api.hpp"
#include "die.hpp"
#include "strlcat.hpp"
#include "config.hpp"
#include "file.hpp"
#include "yara.hpp"
#include "svcutil.hpp"
#include "log.hpp"
#include "quarantine.hpp"
#include "threadpool.hpp"
#include "pfworker.hpp"
#include "timing.hpp"
#include "ProcFilterEvents.h"

#include "pfdriver.hpp"

#define PROCFILTER_DRIVER_SERVICE_NAME (L"ProcFilter Driver")
#define PROCFILTER_DRIVER_SERVICE_DISPLAY_NAME (L"ProcFilter Driver")

static HANDLE g_hThread = NULL;
static HANDLE g_hStopTheadEvent = NULL;

static SC_HANDLE g_hSCM = NULL;
static SC_HANDLE g_hDriverService = NULL;
static HANDLE g_hDriver = INVALID_HANDLE_VALUE;

DWORD WINAPI ep_DriverService(void *arg);

static void LoadKernelDriver();
static void UnloadKernelDriver();


void
DriverInit()
{
	g_hStopTheadEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (g_hStopTheadEvent == NULL) Die("Unable to create stop thread event in driver serice");

	LoadKernelDriver();

	DWORD dwThreadId = 0;
	g_hThread = CreateThread(NULL, 0, ep_DriverService, 0, 0, &dwThreadId);
	if (g_hThread == NULL) Die("Unable to create driver service thread");
}


void
DriverShutdown()
{
	// Signal to driver to stop and cancel any in-progress io operations
	SetEvent(g_hStopTheadEvent);
	if (g_hDriver != INVALID_HANDLE_VALUE) {
		// Canceling pending io operations
		CancelIoEx(g_hDriver, NULL);
	}
	// Wait for the thread which takes care of closing the device driver
	WaitForSingleObject(g_hThread, INFINITE);
	UnloadKernelDriver();
}


bool
DriverInstall()
{
	CONFIG_DATA *cd = GetConfigData();

	// Open the service control manager
	SC_HANDLE hScm = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if (!hScm) return false;

	// Create the driver service
	bool rv = false;
	WCHAR szDriverPath[MAX_PATH+7] = { '\0' };
	wstrlprintf(szDriverPath, sizeof(szDriverPath), L"%ls", cd->szProcFilterDriver);
	SC_HANDLE hDriverService = CreateServiceW(hScm, PROCFILTER_DRIVER_SERVICE_NAME, PROCFILTER_DRIVER_SERVICE_DISPLAY_NAME, SERVICE_START | SERVICE_STOP | DELETE,
										SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, szDriverPath, 0, 0, 0, 0, 0);

	// Was the service created? Or does it already exist?
	if (hDriverService) {
		rv = true;
		CloseServiceHandle(hDriverService);
	} else if (GetLastError() == ERROR_SERVICE_EXISTS) {
		rv = true;
	}

	CloseServiceHandle(hScm);

	return rv;
}


bool
DriverUninstall()
{
	SC_HANDLE hScm = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if (!hScm) return false;

	bool rv = true;
	SC_HANDLE hDriverService = OpenService(hScm, PROCFILTER_DRIVER_SERVICE_NAME, SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
	if (hDriverService) {
		rv = ServiceStop(hDriverService, 2 * 60 * 1000) && DeleteService(hDriverService);
	} else {
		rv = true;
	}

	CloseServiceHandle(hScm);

	return rv;
}


void
LoadKernelDriver()
{
	CONFIG_DATA *cd = GetConfigData();

	// Open the service control manager
	g_hSCM = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if (!g_hSCM) Die("Unable to open the service control manager");

	// Stop the old driver service if its running
	g_hDriverService = OpenService(g_hSCM, PROCFILTER_DRIVER_SERVICE_NAME, SERVICE_START | SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
	if (g_hDriverService) {
		if (!ServiceStop(g_hDriverService, 2 * 60 * 1000)) Die("Unable to stop previously running driver service");
		LogDebugFmt("Opened driver service");
	} else {
		Die("Unable to open old driver service: %u", GetLastError());
	}

	// Service handle opened and the driver is to be started
	// Start the driver service
	BOOL rc = StartService(g_hDriverService, 0, NULL);
	DWORD dwErrorCode = GetLastError();
	if (!rc) Die("Unable to start driver service: %u", dwErrorCode);

	// It's running, so open it
	g_hDriver = CreateFileW(PROCFILTER_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (g_hDriver == INVALID_HANDLE_VALUE) {
		DWORD dwErrorCode = GetLastError();
		LogCriticalFmt("Error opening driver: 0x%08X", dwErrorCode);
		Die("Error opening driver service %ls: %ls", cd->szProcFilterDriver, ErrorText(dwErrorCode));
	}

	// Send the driver its configuration
	PROCFILTER_CONFIGURATION yc;
	ZeroMemory(&yc, sizeof(PROCFILTER_CONFIGURATION));
	yc.dwProcFilterRequestSize = sizeof(PROCFILTER_REQUEST);
	yc.dwProcMaxFilterRequestSize = PROCFILTER_REQUEST_SIZE;
	yc.bDenyProcessCreationOnFailedScan = cd->bDenyProcessCreationOnFailedScan;

	// Always force thread/image events on in debug builds
#if defined(_DEBUG)
	yc.bWantThreadEvents = true;
	yc.bWantImageLoadEvents = true;
#else
	yc.bWantThreadEvents = ApiWantThreadEvents();
	yc.bWantImageLoadEvents = cd->bScanFileOnImageLoad || cd->bScanMemoryOnImageLoad || ApiWantImageLoadEvents();
#endif

	// Create the event to be signalled when device configuration succeeds
	HANDLE hControlDeviceEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!hControlDeviceEvent) Die("Unable to create event for DeviceIoControl()");
	OVERLAPPED overlapped;
	ZeroMemory(&overlapped, sizeof(OVERLAPPED));
	overlapped.hEvent = hControlDeviceEvent;
	rc = DeviceIoControl(g_hDriver, IOCTL_PROCFILTER_CONFIGURE, &yc, sizeof(PROCFILTER_CONFIGURATION), NULL, 0, NULL, &overlapped);
	if (!rc && GetLastError() == ERROR_IO_PENDING) {
		DWORD dwBytesRead = 0;
		if (!GetOverlappedResult(g_hDriver, &overlapped, &dwBytesRead, TRUE)) {
			Die("GetOverlappedResult() failure for DeviceIoControl(): %d", GetLastError());
		}
	} else if (!rc) {
		Die("DeviceIoControl() failure: %d", GetLastError());
	}

	CloseHandle(hControlDeviceEvent);

	LogWarning("Started driver");
}


void
UnloadKernelDriver()
{
	// Stop the driver service
	if (g_hDriverService) {
		ServiceStop(g_hDriverService, 5 * 60 * 1000);
		CloseServiceHandle(g_hDriverService);
		g_hDriverService = NULL;
	}

	// Close the service manager handle
	if (g_hSCM) CloseServiceHandle(g_hSCM);
	g_hSCM = NULL;
}


DWORD
WINAPI
ep_DriverService(void *arg)
{
	const CONFIG_DATA *cd = GetConfigData();

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

	// Build the threadpool
	POOL_DATA pd;
	ZeroMemory(&pd, sizeof(POOL_DATA));
	pd.hSharedDriverHandle = g_hDriver;
	const DWORD dwNumChannels = NUM_EVENTTYPES-1; // -1 to ignore EVENT_NONE
	THREADPOOL *tp = ThreadPoolAlloc(cd->dThreadPoolSize, dwNumChannels, PfWorkerInit, PfWorkerWork, PfWorkerDestroy, &pd, sizeof(WORKER_DATA), THREAD_PRIORITY_NORMAL);
	if (!tp) Die("Unable to allocate threadpool");

	// Create the read file event for use with overlapped I/O
	HANDLE hReadFileEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (hReadFileEvent == NULL) Die("Unable to create read file event");

	// Allocate memory for the buffer to be read from the kernel
	PROCFILTER_REQUEST *req = (PROCFILTER_REQUEST*)_malloca(PROCFILTER_REQUEST_SIZE);
	while (true) {
		if (WaitForSingleObject(g_hStopTheadEvent, 0) == WAIT_OBJECT_0) break;

		// Read request from driver using synch/asynch calls according to https://support.microsoft.com/en-us/kb/156932
		DWORD dwBytesRead = 0;
		OVERLAPPED overlapped;
		ZeroMemory(&overlapped, sizeof(OVERLAPPED));
		ResetEvent(hReadFileEvent);
		overlapped.hEvent = hReadFileEvent;
		BOOL rc = ReadFile(g_hDriver, req, PROCFILTER_REQUEST_SIZE, &dwBytesRead, &overlapped);
		DWORD dwErrorCode = GetLastError();
		if (rc) {
			// Successfully completed a synchronous read, do nothing
		} else if (dwErrorCode == ERROR_IO_PENDING) {
			// Successfully completed an asynchronous read, so wait for it
			DWORD dwNumberOfBytesTransferred = 0;
			if (!GetOverlappedResult(g_hDriver, &overlapped, &dwNumberOfBytesTransferred, TRUE)) {
				dwErrorCode = GetLastError();
				if (dwErrorCode == ERROR_OPERATION_ABORTED || dwErrorCode == ERROR_INVALID_HANDLE) break;
				// Cancel the pending IO to ensure the IO operation does not complete after this function ends
				// and the result is stored to an invalid location
				CancelIo(g_hDriver);
				Die("GetOverlappedResult() failure in reader: %d", dwErrorCode);
			}
			dwErrorCode = GetLastError();
			dwBytesRead = dwNumberOfBytesTransferred;
		} else if (dwErrorCode == ERROR_OPERATION_ABORTED || dwErrorCode == ERROR_INVALID_HANDLE) {
			break;
		} else {
			Die("Unable to read data from driver: %d / %ls", dwErrorCode, ErrorText(dwErrorCode));
		}
		LogDebugFmt("Read event from driver: PID:%u Event:%u", req->dwProcessId, req->dwEventType);
		ULONG64 ulStartPerformanceCount = GetPerformanceCount();
		
		// Validate the size of data read
		if (dwBytesRead < sizeof(PROCFILTER_REQUEST) || dwBytesRead > PROCFILTER_REQUEST_SIZE) {
			Die("Read invalid size from driver device: %u < %u || %u > %u  ReadFile:%hs ErrorCode:%d",
				dwBytesRead, sizeof(PROCFILTER_REQUEST), dwBytesRead, PROCFILTER_REQUEST_SIZE, rc ? "TRUE" : "FALSE", dwErrorCode);
		}
		if (dwBytesRead != req->dwRequestSize) {
			Die("Read partial packet from driver device: Read:%u PacketSize:%u", dwBytesRead, req->dwRequestSize);
		}
		
		// Post a copy of the retrieved data to a worker thread
		LogDebug("Posting work task to worker");
		// Allocate memory for the task data, the structure of which includes only the header portion of the procfilter request,
		// so allocate only the exact size needed
		WORKER_TASK_DATA *wtd = (WORKER_TASK_DATA*)malloc(sizeof(WORKER_TASK_DATA) + (dwBytesRead - sizeof(PROCFILTER_REQUEST)));
		if (!wtd) Die("Memory allocation failure for ProcFilter request");
		memcpy(&wtd->peProcFilterRequest, req, dwBytesRead);
		wtd->ulStartPerformanceCount = ulStartPerformanceCount;
		LogDebugFmt("Posting to threadpool: PID:%u Event:%u", req->dwProcessId, req->dwEventType);
		if (ThreadPoolPost(tp, req->dwEventType, false, g_hStopTheadEvent, wtd)) {
			LogDebug("Posted work task to worker");
		} else {
			LogDebugFmt("Failed to post task to worker");
			free(wtd);
		}
	}

	_freea(req);

	ThreadPoolFree(tp);

	CloseHandle(hReadFileEvent);
	
	// Driver closing is done here since this thread could terminate due to an error situation
	// and if closing were done elsewhere (such as service exit) the driver device would be kept open, consequently
	// blocking process creation events until service shutdown
	CloseHandle(g_hDriver);
	g_hDriver = INVALID_HANDLE_VALUE;

	return 0;
}


//
// Send a response to the kernel
//
bool
DriverSendResponse(HANDLE hDriver, HANDLE hWriteCompletionEvent, const PROCFILTER_RESPONSE *response)
{
	bool rv = false;
	DWORD dwBytesWritten = 0;
	OVERLAPPED overlapped;
	ZeroMemory(&overlapped, sizeof(OVERLAPPED));
	ResetEvent(hWriteCompletionEvent);
	overlapped.hEvent = hWriteCompletionEvent;
	LogDebug("Writing data to driver: PID:%u Event:%u", response->dwProcessId, response->dwEventType);
	BOOL rc = WriteFile(hDriver, response, sizeof(PROCFILTER_RESPONSE), &dwBytesWritten, &overlapped);
	LogDebug("Data sent to driver");
	if (rc) {
		rv = true;
	} else {
		DWORD dwErrorCode = GetLastError();
		if (dwErrorCode == ERROR_IO_PENDING) {
			DWORD dwBytesTransferred = 0;
			rc = GetOverlappedResult(hDriver, &overlapped, &dwBytesTransferred, TRUE);
			if (rc) {
				dwBytesWritten = dwBytesTransferred;
				rv = true;
			} else {
				dwErrorCode = GetLastError();
				if (dwErrorCode != ERROR_OPERATION_ABORTED && dwErrorCode != ERROR_INVALID_HANDLE) {
					CancelIo(hDriver);
					Die("Failed to write data to driver: %d", GetLastError());
				}
			}
		} else if (dwErrorCode == ERROR_INVALID_HANDLE || dwErrorCode == ERROR_OPERATION_ABORTED) {
			// do nothing
		} else {
			Die("Failed to write data to driver: %d", dwErrorCode);
		}
	}
	
	if (rv && dwBytesWritten != sizeof(PROCFILTER_RESPONSE)) {
		Die("Wrote invalid data size to driver: Required:%d Actual:%d", sizeof(PROCFILTER_RESPONSE), dwBytesWritten);
	}

	if (!rv) LogDebugFmt("Write to kernel failure"); 

	return rv;
}
