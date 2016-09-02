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

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include "psapi.h"

#include "ProcFilterEvents.h"
#include "strlcat.hpp"
#include "log.hpp"
#include "file.hpp"
#include "winerr.hpp"
#include "sha1.hpp"
#include "quarantine.hpp"
#include "path.hpp"
#include "config.hpp"

#include "yara.hpp"


struct yarascan_context {
	WCHAR szCompilationError[512];
	YR_RULES *rules;               // Is NULL if no rules file were specified
	YR_COMPILER *compiler;         // Is NULL if no rules file were specified
};


//
// YARA callback for error reporting during compilation
//
static
void
report_error(int error_level, const char *file_name, int line_number, const char *message, void *user_data)
{
	YARASCAN_CONTEXT *ctx = (YARASCAN_CONTEXT*)user_data;

	if (error_level == YARA_ERROR_LEVEL_ERROR) {
		wstrlprintf(ctx->szCompilationError, sizeof(ctx->szCompilationError), L"%hs(%d): %hs", file_name, line_number, message);
	}
}


YARASCAN_CONTEXT*
YarascanAllocDefault(WCHAR *lpszError, DWORD dwErrorSize, bool bLogToEventLog, bool bLogToConsole)
{
	CONFIG_DATA *cd = GetConfigData();

	YARASCAN_INPUT_FILE yifInputFiles[2];
	ZeroMemory(yifInputFiles, sizeof(yifInputFiles));

	int i = 0;
	if (cd->bUseLocalRuleFile) {
		yifInputFiles[i].lpszFileName = cd->szLocalYaraRuleFile;
		yifInputFiles[i].bRequired = false;
		++i;
	}

	if (cd->bUseRemoteRuleFile) {
		yifInputFiles[i].lpszFileName = cd->szRemoteYaraRuleFile;
		yifInputFiles[i].bRequired = false;
		++i;
	}

	YARASCAN_CONTEXT *ctx = YarascanAlloc4(yifInputFiles, i, lpszError, dwErrorSize);
	if (ctx) {
		// Print a warning for rule files that didnt successfully compile
		for (int j = 0; j < i; ++j) {
			if (!yifInputFiles[j].result.bSuccess) {
				if (bLogToEventLog) {
					EventWriteRULE_COMPILATION_FAILED(yifInputFiles[j].lpszFileName, yifInputFiles[j].result.szError);
				}
				if (bLogToConsole) {
					fwprintf(stderr, L"Rule compilation failed for %ls: %ls\n", yifInputFiles[j].lpszFileName, yifInputFiles[j].result.szError);
				}
			}
		}
	}

	return ctx;
}


YARASCAN_CONTEXT*
YarascanAllocLocalAndRemoteRuleFile(WCHAR *lpszBaseName, WCHAR *lpszError, DWORD dwErrorSize, bool bLogToEventLog, bool bLogToConsole)
{
	CONFIG_DATA *cd = GetConfigData();

	YARASCAN_INPUT_FILE yifInputFiles[2];
	ZeroMemory(yifInputFiles, sizeof(yifInputFiles));
	
	WCHAR szLocalRuleFile[MAX_PATH+1] = { '\0' };
	WCHAR szRemoteRuleFile[MAX_PATH+1] = { '\0' };
	
	if (!GetProcFilterPath(szLocalRuleFile, sizeof(szLocalRuleFile), L"localrules", lpszBaseName)) {
		if (lpszError) wstrlprintf(lpszError, dwErrorSize, L"localrules path too long");
		return NULL;
	}
	if (!GetProcFilterPath(szRemoteRuleFile, sizeof(szRemoteRuleFile), L"remoterules", lpszBaseName)) {
		if (lpszError) wstrlprintf(lpszError, dwErrorSize, L"remoterules path too long");
		return NULL;
	}

	yifInputFiles[0].lpszFileName = szLocalRuleFile;
	yifInputFiles[0].bRequired = FileExists(szLocalRuleFile);

	yifInputFiles[1].lpszFileName = szRemoteRuleFile;
	yifInputFiles[1].bRequired = FileExists(szRemoteRuleFile);

	YARASCAN_CONTEXT *ctx = YarascanAlloc4(yifInputFiles, 2, lpszError, dwErrorSize);
	if (ctx) {
		// Print a warning for rule files that didnt successfully compile
		for (int i = 0; i < 2; ++i) {
			// Log if it was a required file OR the file exists but wasn't successfully compiled
			if (yifInputFiles[i].bRequired && !yifInputFiles[i].result.bSuccess) {
				if (bLogToEventLog) {
					EventWriteRULE_COMPILATION_FAILED(yifInputFiles[i].lpszFileName, yifInputFiles[i].result.szError);
				}
				if (bLogToConsole) {
					fwprintf(stderr, L"Rule compilation failed for %ls: %ls\n", yifInputFiles[i].lpszFileName, yifInputFiles[i].result.szError);
				}
			}
		}
	}

	return ctx;
}


YARASCAN_CONTEXT*
YarascanAlloc3(const WCHAR *lpszFileName, WCHAR *lpszError, DWORD dwErrorSize)
{
	YARASCAN_INPUT_FILE yifInputFile[1];
	ZeroMemory(yifInputFile, sizeof(yifInputFile));
	yifInputFile[0].lpszFileName = lpszFileName;

	return YarascanAlloc4(yifInputFile, 1, lpszError, dwErrorSize);
}


YARASCAN_CONTEXT*
YarascanAlloc4(YARASCAN_INPUT_FILE *yifInputFiles, size_t nInputFiles, WCHAR *lpszError, DWORD dwErrorSize)
{	
	YARASCAN_CONTEXT *ctx = (YARASCAN_CONTEXT*)malloc(sizeof(YARASCAN_CONTEXT));
	if (!ctx) {
		if (lpszError) wstrlprintf(lpszError, dwErrorSize, L"%hs", "No memory");
		return NULL;
	}
	ZeroMemory(ctx, sizeof(YARASCAN_CONTEXT));

	if (nInputFiles == 0) return ctx;

	YR_RULES *rules = NULL;
	YR_COMPILER *compiler = NULL;
	FILE *f = NULL;
	bool bSuccess = false;

	if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
		if (lpszError) wstrlprintf(lpszError, dwErrorSize, L"%hs", "Unable to create YARA compiler");
		goto fail;
	}

	yr_compiler_set_callback(compiler, report_error, ctx);

	for (size_t i = 0; i < nInputFiles; ++i) {
		YARASCAN_INPUT_FILE *yifInputFile = &yifInputFiles[i];
		ZeroMemory(&yifInputFile->result, sizeof(yifInputFile->result));

		f = _wfopen(yifInputFile->lpszFileName, L"r");
		if (f) {
			// Convert path to ASCII for compatibility with libyara API
			char szYaraRuleFile[MAX_PATH+1] = { '\0' };
			strlprintf(szYaraRuleFile, sizeof(szYaraRuleFile), "%ls", yifInputFile->lpszFileName);

			// Add the file to the context
			if (yr_compiler_add_file(compiler, f, szYaraRuleFile, szYaraRuleFile) == ERROR_SUCCESS) {
				yifInputFile->result.bSuccess = true;
			} else {
				char szYaraError[512] = { '\0' };
				yr_compiler_get_error_message(compiler, szYaraError, _countof(szYaraError)-1);

				if (yifInputFile->bRequired) {
					if (lpszError) wstrlprintf(lpszError, dwErrorSize, L"YARA rule file compilation error: %hs\n%ls", szYaraError, ctx->szCompilationError);
					goto fail;
				} else {
					wstrlprintf(yifInputFile->result.szError, sizeof(yifInputFile->result.szError),
							L"YARA rule file compilation error: %hs\n%ls", szYaraError, ctx->szCompilationError);
				}
			}
			fclose(f);
			f = NULL;
		} else {
			if (yifInputFile->bRequired) {
				if (lpszError) wstrlprintf(lpszError, dwErrorSize, L"Unable to read rules file: %ls", yifInputFile->lpszFileName);
				goto fail;
			} else {
				wstrlprintf(yifInputFile->result.szError, sizeof(yifInputFile->result.szError),
					L"Unable to read rules file: %ls", yifInputFile->lpszFileName);
			}
		}
	}

	if (yr_compiler_get_rules(compiler, &rules) == ERROR_SUCCESS) {
		bSuccess = true;
	} else {
		if (lpszError) wstrlprintf(lpszError, dwErrorSize, L"%hs", "Error getting compiled YARA rules");
		goto fail;
	}
	
	// successfully created rules
	if (bSuccess && rules) {
		ctx->rules = rules;
		ctx->compiler = compiler;
		return ctx;
	}

fail:
	free(ctx);
	if (rules) yr_rules_destroy(rules);
	if (compiler) yr_compiler_destroy(compiler);
	if (f) fclose(f);

	return NULL;
}


void
YarascanFree(YARASCAN_CONTEXT *ctx)
{
	if (ctx) {
		if (ctx->rules) yr_rules_destroy(ctx->rules);
		if (ctx->compiler) yr_compiler_destroy(ctx->compiler);
		free(ctx);
	}
}


static
void
callback_append(WCHAR *dst, size_t dst_sz, const char *rulename, const char *delimiter)
{
	wstrlcatf(dst, dst_sz, L"%hs%hs", dst[0] == '\0' ? "" : delimiter, rulename);
}


static
void
callback_meta_conditionally_update(const char *name, const YR_META *meta, bool *o_value)
{
	if (_stricmp(meta->identifier, name) == 0) {
		if (meta->type == META_TYPE_INTEGER || meta->type == META_TYPE_BOOLEAN) {
			*o_value = meta->integer != 0;
		}
	}
}


typedef struct callback_user_data CALLBACK_USER_DATA;
struct callback_user_data {
	SCAN_RESULT *result;
	OnMatchCallback_cb lpfnOnMatchCallback;
	OnMetaCallback_cb lpfnOnMetaCallback;
	void *user_data;
};


//
// YARA callback invoked for each rule
//
static
int
callback(int message, void *message_data, void *user_data)
{
	CALLBACK_USER_DATA *cud = (CALLBACK_USER_DATA*)user_data;
	SCAN_RESULT *result = cud->result;
	CONFIG_DATA *cd = GetConfigData();

	switch (message) {
	case CALLBACK_MSG_RULE_MATCHING: {
		YR_RULE *rule = (YR_RULE*)message_data;

		if (cud->lpfnOnMatchCallback) cud->lpfnOnMatchCallback((char*)rule->identifier, cud->user_data);

		result->bRuleMatched = true;
		callback_append(result->szMatchedRuleNames, sizeof(result->szMatchedRuleNames), rule->identifier, "|");
		
		bool bBlock = cd->bBlockDefault;
		bool bLog = cd->bLogDefault;
		bool bQuarantine = cd->bQuarantineDefault;

		YR_META *meta = NULL;
		yr_rule_metas_foreach(rule, meta) {
			callback_meta_conditionally_update("Block", meta, &bBlock);
			callback_meta_conditionally_update("Log", meta, &bLog);
			callback_meta_conditionally_update("Quarantine", meta, &bQuarantine);

			if (cud->lpfnOnMetaCallback) {
				int64_t dNumericValue = 0;
				char *lpszStringValue = NULL;
				if (meta->type == META_TYPE_INTEGER || meta->type == META_TYPE_BOOLEAN) dNumericValue = meta->integer;
				if (meta->type == META_TYPE_STRING) lpszStringValue = meta->string;
				cud->lpfnOnMetaCallback((char*)rule->identifier, (char*)meta->identifier, lpszStringValue, dNumericValue, cud->user_data);
			}
		}

		if (bBlock) {
			result->bBlock = true;
			callback_append(result->szBlockRuleNames, sizeof(result->szBlockRuleNames), rule->identifier, "|");
		}
		if (bLog) {
			result->bLog = true;
			callback_append(result->szLogRuleNames, sizeof(result->szLogRuleNames), rule->identifier, "|");
		}
		if (bQuarantine) {
			result->bQuarantine = true;
			callback_append(result->szQuarantineRuleNames, sizeof(result->szQuarantineRuleNames), rule->identifier, "|");
		}
	}
	case CALLBACK_MSG_RULE_NOT_MATCHING:
	case CALLBACK_MSG_IMPORT_MODULE:
	case CALLBACK_MSG_SCAN_FINISHED:
		return CALLBACK_CONTINUE;
	}

	return CALLBACK_ERROR;
}

//
// NOTE: These three YarascanScanXxx() functions could be refactored to remove duplication between the functions, but
// the new prototype would either require a large number of arguments or a struct/union for the various parameters and
// this would overall lead to more code.
//

//
// Scan the specified process with YARA
// 
void
YarascanScanMemory(YARASCAN_CONTEXT *ctx, DWORD pid, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *user_data, SCAN_RESULT *o_result)
{
	SCAN_RESULT *result = o_result;
	ZeroMemory(result, sizeof(SCAN_RESULT));

	// No context or rules; signal success
	if (!ctx || !ctx->rules) { result->bScanSuccessful = true; return; }

	CALLBACK_USER_DATA cud = { result, lpfnOnMatchCallback, lpfnOnMetaCallback, user_data };

	// scan the process in memory
	int error = yr_rules_scan_proc(ctx->rules, pid, SCAN_FLAGS_FAST_MODE, callback, &cud, 0);
	if (error == ERROR_SUCCESS) {
		result->bScanSuccessful = true;
	} else {
		char *szError = NULL;
		switch (error) {
		case ERROR_COULD_NOT_ATTACH_TO_PROCESS: szError = "Could not attach to process"; break;
		default: break;
		}
		if (szError) {
			wstrlprintf(result->szError, sizeof(result->szError), L"%hs", szError);
		} else {
			wstrlprintf(result->szError, sizeof(result->szError), L"YARA error during process scan: Error code 0x%08X", error);
		}
	}
}


void
YarascanScanFile(YARASCAN_CONTEXT *ctx, WCHAR *lpszFile, DWORD dwScanFileSizeLimit, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *user_data, SCAN_RESULT *o_result)
{
	SCAN_RESULT *result = o_result;
	ZeroMemory(result, sizeof(SCAN_RESULT));
	
	if (!ctx || !ctx->rules) { result->bScanSuccessful = true; return; }

	DWORD dwFileSize = 0;
	if (dwScanFileSizeLimit) {
		HANDLE hFile = CreateFile(lpszFile, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile != INVALID_HANDLE_VALUE) {
			dwFileSize = GetFileSize(hFile, NULL);
			CloseHandle(hFile);
		}
	}
	
	CALLBACK_USER_DATA cud = { result, lpfnOnMatchCallback, lpfnOnMetaCallback, user_data };

	if (dwScanFileSizeLimit == 0 || dwFileSize <= dwScanFileSizeLimit) {
		char hszFileName[MAX_PATH+1];
		strlprintf(hszFileName, sizeof(hszFileName), "%ls", lpszFile);
		int error = yr_rules_scan_file(ctx->rules, hszFileName, SCAN_FLAGS_FAST_MODE, callback, &cud, 0);
		if (error == ERROR_SUCCESS) {
			result->bScanSuccessful = true;
		} else {
			char *szError = NULL;
			switch (error) {
			case ERROR_COULD_NOT_OPEN_FILE: szError = "Could not open file"; break;
			case ERROR_COULD_NOT_MAP_FILE: szError = "Could not map file"; break;
			default: break;
			}
			if (szError) {
				wstrlprintf(result->szError, sizeof(result->szError), L"%hs", szError);
			} else {
				wstrlprintf(result->szError, sizeof(result->szError), L"YARA error during file scan: Error code 0x%08X", error);
			}
		}
	} else if (dwScanFileSizeLimit) {
		wstrlprintf(result->szError, sizeof(result->szError), L"File exceeds limit of %u bytes: %u bytes in file", dwScanFileSizeLimit, dwFileSize);
	}
}


void YarascanScanData(YARASCAN_CONTEXT *ctx, const void *lpvData, DWORD dwDataSize,
	OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *user_data, SCAN_RESULT *o_result)
{
	SCAN_RESULT *result = o_result;
	ZeroMemory(result, sizeof(SCAN_RESULT));
	
	if (!ctx || !ctx->rules) { result->bScanSuccessful = true; return; }
	
	CALLBACK_USER_DATA cud = { result, lpfnOnMatchCallback, lpfnOnMetaCallback, user_data };
	int error = yr_rules_scan_mem(ctx->rules, (uint8_t*)lpvData, dwDataSize, SCAN_FLAGS_FAST_MODE, callback, &cud, 0);
	if (error == ERROR_SUCCESS) {
		result->bScanSuccessful = true;
	} else {
		char *szError = NULL;
		switch (error) {
		case ERROR_COULD_NOT_ATTACH_TO_PROCESS: szError = "Could not scan data"; break;
		default: break;
		}
		if (szError) {
			wstrlprintf(result->szError, sizeof(result->szError), L"%hs", szError);
		} else {
			wstrlprintf(result->szError, sizeof(result->szError), L"YARA error during data scan: Error code 0x%08X", error);
		}
	}
}