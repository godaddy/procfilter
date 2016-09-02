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

#include "yara.h"
#include "config.hpp"
#include "pfdriver.hpp"
#include "procfilter/procfilter.h"


typedef struct yarascan_input_file YARASCAN_INPUT_FILE;
struct yarascan_input_file {
	const WCHAR *lpszFileName;
	bool bRequired;
	struct {
		bool  bSuccess;
		WCHAR szError[256];
	} result;
};


//
// Allocate/free a scanning context from the named rule file.  Scan contexts can be reused
// to scan multiple targets. All YARASCAN_INPUT_FILE structs must have lpszFileName and bOptional
// initialized when calling this function.
//
// If the function returns NULL, lpszError (if given) is valid.
//
YARASCAN_CONTEXT* YarascanAllocDefault(WCHAR *lpszError, DWORD dwErrorSize, bool bLogToEventLog, bool bLogToConsole);
YARASCAN_CONTEXT* YarascanAllocLocalAndRemoteRuleFile(WCHAR *lpszBaseName, WCHAR *lpszError, DWORD dwErrorSize, bool bLogToEventLog, bool bLogToConsole);
YARASCAN_CONTEXT* YarascanAlloc3(const WCHAR *lpszFileName, WCHAR *lpszError, DWORD dwErrorSize);
YARASCAN_CONTEXT* YarascanAlloc4(YARASCAN_INPUT_FILE *yifInputFiles, size_t nInputFiles, WCHAR *lpszError, DWORD dwErrorSize);
void YarascanFree(YARASCAN_CONTEXT *ctx);


//
// Scan a file or memory using the given scan context.
//
void YarascanScanFile(YARASCAN_CONTEXT *ctx, WCHAR *lpszFile, DWORD dwScanFileSizeLimit,
	OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *user_data, SCAN_RESULT *o_result);
void YarascanScanMemory(YARASCAN_CONTEXT *ctx, DWORD pid,
	OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *user_data, SCAN_RESULT *o_result);
void YarascanScanData(YARASCAN_CONTEXT *ctx, const void *lpvData, DWORD dwDataSize,
	OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *user_data, SCAN_RESULT *o_result);
