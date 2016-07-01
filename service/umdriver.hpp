
#pragma once

#include <Windows.h>

#include "config.hpp"

//
// Initialize and shutdown the driver communication engine
//
void DriverInit();
void DriverShutdown();

//
// Send a response to the driver, DriverInit() must have been called prior to invoking this function.
//
bool DriverSendResponse(HANDLE hDriver, HANDLE hWriteCompletionEvent, const PROCFILTER_RESPONSE *response);

//
// Used by the installer/uninstaller to unload the driver and remove the service.  Can be called without invoking
// the DriverInit() function.
//
bool DriverInstall();
bool DriverUninstall();
