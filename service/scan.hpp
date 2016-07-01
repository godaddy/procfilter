
#pragma once

#include <Windows.h>

#include "yara.hpp"
#include "api.hpp"

//
// Initialize/shutdown the scanning subsystem
//
void ScanInit();
void ScanShutdown();

//
// Perform a scan of a file/pid, exporting plugin events as necessary. 'e' must have been initialized.
//
// The driver and write completion event handles must be null for periodic scans since that scan type does not write to the kernel.
//
void Scan(DWORD dwEventType, int dScanContext, PROCFILTER_EVENT *e, YARASCAN_CONTEXT *ctx, HANDLE hDriver, HANDLE hWriteCompletionEvent, DWORD dwProcessId, DWORD dwParentProcessId, WCHAR *lpszFileName, void *lpImageBase, void *lpvScanDataArray);

//
// Print current status to the stats engine
//
void ScanStatusPrint();
