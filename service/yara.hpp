
#pragma once

#include <Windows.h>

#include "yara.h"
#include "config.hpp"
#include "pfdriver.hpp"
#include "procfilter/procfilter.h"


typedef struct yarascan_input_file YARASCAN_INPUT_FILE;
struct yarascan_input_file {
	const WCHAR *lpszFileName;
	bool bOptional;
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
