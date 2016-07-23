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
