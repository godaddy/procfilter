
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
