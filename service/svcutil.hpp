
#pragma once

#include <Windows.h>


//
// Stop a service and wait for it to exit.  if dwWaitMilliseconds is INFINITE then wait forever.
//
bool ServiceStop(SC_HANDLE hService, DWORD dwWaitMilliseconds);
