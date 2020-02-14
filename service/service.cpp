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

#include <Windows.h>

#include "service.hpp"
#include "svcutil.hpp"


WCHAR *SERVICE_NAME = L"ProcFilter Service";
WCHAR *SERVICE_DISPLAY_NAME = L"ProcFilter Service";
WCHAR *SERVICE_DESCRIPTION_TEXT = L"Filters new, terminating, and existing processes";


//
// Install the service
//
bool
ProcFilterServiceInstall(bool bDelayedStart)
{
	WCHAR szPath[MAX_PATH + 1] = { '\0' };
	if (GetModuleFileName(NULL, szPath, sizeof(szPath) / sizeof(WCHAR)) <= 0) return false;

	SC_HANDLE hScm = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if (!hScm) return false;

	SC_HANDLE hService = CreateService(hScm, SERVICE_NAME, SERVICE_DISPLAY_NAME,
										SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE,
										szPath, 0, 0, 0, 0, 0);

	bool rv = false;

	if (hService) {
		// The service was just installed so set the description
		SERVICE_DESCRIPTION sdDescription = { SERVICE_DESCRIPTION_TEXT };
		ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &sdDescription);
	} else {
		// Service was unable to be created; try to open the existing one
		hService = OpenService(hScm, SERVICE_NAME, SERVICE_ALL_ACCESS);
	}

	if (hService) {
		// Also set the delayed start or immediate start option
		SERVICE_DELAYED_AUTO_START_INFO data = { bDelayedStart ? TRUE : FALSE };
		ChangeServiceConfig2(hService, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &data);

		CloseServiceHandle(hService);
		rv = true;
	}

	CloseServiceHandle(hScm);

	return rv;
}


//
// Shut down and uninstall the service
//
bool
ProcFilterServiceUninstall()
{
	SC_HANDLE hScm = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);

	bool rv = false;
	if (!hScm) return rv;

	SC_HANDLE hService = OpenService(hScm, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
	if (hService) {
		SERVICE_STATUS s;
		if (QueryServiceStatus(hService, &s) && s.dwCurrentState != SERVICE_STOPPED) {
			ServiceStop(hService, 5 * 60 * 1000);
		}

		rv = DeleteService(hService) == TRUE;

		CloseServiceHandle(hService);
	} else {
		rv = true;
	}

	CloseServiceHandle(hScm);

	return rv;
}


//
// Start the service
//
bool
ProcFilterServiceStart()
{
	SC_HANDLE hScm = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if (!hScm) return false;

	bool rv = false;

	SC_HANDLE hService = OpenService(hScm, SERVICE_NAME, SERVICE_ALL_ACCESS);

	if (hService) {
		if (StartService(hService, 0, NULL)) {
			rv = true;
		} else if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
			rv = true;
		}
		CloseServiceHandle(hService);
	}

	CloseServiceHandle(hScm);

	return rv;
}

//
// Start the service
//
bool
ProcFilterServiceStop()
{
	SC_HANDLE hScm = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
	if (!hScm) return false;

	bool rv = false;

	SC_HANDLE hService = OpenService(hScm, SERVICE_NAME, SERVICE_ALL_ACCESS);

	if (hService) {
		rv = ServiceStop(hService, 5 * 60 * 1000);

		CloseServiceHandle(hService);
	}

	CloseServiceHandle(hScm);

	return rv;
}


bool
ProcFilterServiceIsRunning()
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
