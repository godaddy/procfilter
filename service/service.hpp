
#pragma once

//
// Install or uninstall the service component. The service must be stopped when this is called.
//
bool ProcFilterServiceInstall(bool bDelayedStart);
bool ProcFilterServiceUninstall();

//
// Start or stop the service.
//
bool ProcFilterServiceStart();
bool ProcFilterServiceStop();

//
// Determine whether or not the ProcFilter service is running.
//
bool ProcFilterServiceIsRunning();


extern WCHAR *SERVICE_NAME;
extern WCHAR *SERVICE_DISPLAY_NAME;
extern WCHAR *SERVICE_DESCRIPTION_TEXT;
