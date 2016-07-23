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

#include "svcutil.hpp"


bool
ServiceStop(SC_HANDLE hService, DWORD dwWaitMilliseconds)
{
	bool rv = false;
	
	// Send the service a stop signal.  Don't check the return code here since the call can fail for a few reasons
	// such as if the service is already off or disabled.
	SERVICE_STATUS ss;
	ControlService(hService, SERVICE_CONTROL_STOP, &ss);

	// Loop, waiting for the service to be in the stopped state.  It seems like there is a potential race condition here
	// where the service exits fast and then restarts, but this is the recommended way to determine if a service has been shut down
	// according to MSDN documentation.
	const DWORD dwLimit = 2 * 60 * 1000;
	DWORD dwBase = GetTickCount();
	BOOL rc = FALSE;
	while ((rc = QueryServiceStatus(hService, &ss)) && ss.dwCurrentState != SERVICE_STOPPED && (dwWaitMilliseconds == INFINITE || GetTickCount() - dwBase < dwLimit)) {
		Sleep(20);
	}

	// If the service is stopped this function call was a success
	if (rc && ss.dwCurrentState == SERVICE_STOPPED) rv = true;

	return rv;
}
