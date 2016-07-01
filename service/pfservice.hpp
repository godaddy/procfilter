
#include <Windows.h>

#include "config.hpp"

//
// The service mainloop.  Takes in a HANDLE to an event that is to be signaled when
// the service should terminate.
//
void ProcFilterServiceMainloop(HANDLE hStopEvent);

//
// Request that the service restarts. This is a 'soft' restart, it reloads the service internally
// and does not use the formal Win32 API for restarting itself.
//
void ProcFilterServiceRequestRestart();

//
// Is the ProcFilter service running?
//
bool IsProcFilterServiceRunning();
