//
// This file should NOT be restricted to a single inclusion; it's function is different based
// on which preprocessor macros are defined during its inclusion. This allows a list of exported
// API functions in one location rather than having multiple lists that all need to be maintained.
//
//#pragma once


#ifndef API_STORE_POINTERS

#include <Windows.h>

#include "procfilter/procfilter.h"

extern "C" {
void Export_RegisterPlugin(const WCHAR *szApiVersion, const WCHAR *lpszShortName, DWORD dwProcessDataSize, DWORD dwScanDataSize, bool bSynchronizeEvents, ...);
bool Export_GetProcessFileName(DWORD dwProcessId, WCHAR *lpszResult, DWORD dwResultSize);
const WCHAR* Export_GetProcessBaseNamePointer(WCHAR *lpszProcessFileName);
void Export_LockPid();
bool Export_IsElevated(HANDLE hProcess, bool *lpbIsElevated);
void Export_Die(const char *fmt, ...);
bool Export_ReadProcessPeb(PEB *lpPeb);
bool Export_ReadProcessMemory(const void *lpvRemotePointer, void *lpszDestination, DWORD dwDestinationSize);
void Export_LogFmt(const char *fmt, ...);
void Export_LogWarningFmt(const char *fmt, ...);
void Export_LogCriticalFmt(const char *fmt, ...);
bool Export_FormatString(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, ...);
bool Export_ConcatenateString(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, ...);
bool Export_VFormatString(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, va_list ap);
bool Export_VConcatenateString(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, va_list ap);
YARASCAN_CONTEXT* Export_AllocateScanContext(const WCHAR *lpszYaraRuleFile, WCHAR *szError, DWORD dwErrorSize);
YARASCAN_CONTEXT* Export_AllocateScanContextLocalAndRemote(const WCHAR *lpszBaseName, WCHAR *lpszError, DWORD dwErrorSize, bool bLogToEventLog);
void Export_FreeScanContext(YARASCAN_CONTEXT *ctx);
void Export_ScanFile(YARASCAN_CONTEXT *ctx, const WCHAR *lpszFileName, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *lpvUserData, SCAN_RESULT *o_result);
void Export_ScanMemory(YARASCAN_CONTEXT *ctx, DWORD dwProcessId, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *lpvUserData, SCAN_RESULT *o_result);
void Export_ScanData(YARASCAN_CONTEXT *ctx, const void *lpvData, DWORD dwDataSize, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *lpvUserData, SCAN_RESULT *o_result);
bool Export_GetFile(const WCHAR *lpszUrl, void *lpvResult, DWORD dwResultSize, DWORD *lpdwBytesUsed);
void Export_Log(const char *str);
void Export_LogWarning(const char *str);
void Export_LogCritical(const char *str);
int Export_GetConfigInt(const WCHAR *lpszKey, int dDefault);
bool Export_GetConfigBool(const WCHAR *lpszKey, bool bDefault);
void Export_GetConfigString(const WCHAR *lpszKey, const WCHAR *lpszDefault, WCHAR *lpszDestination, DWORD dwDestinationSize);
bool Export_GetNtPathName(const WCHAR *lpszDosPath, WCHAR *lpszNtDevice, DWORD dwNtDeviceSize, WCHAR *lpszFilePath, DWORD dwFilePathSize, WCHAR *lpszFullPath, DWORD dwFullPathSize);
DWORD Export_ShellNoticeFmt(DWORD dwDurationSeconds, bool bWait, DWORD dwStyle, WCHAR *lpszTitle, WCHAR *lpszMessageFmt, ...);
bool Export_QuarantineFile(const WCHAR *lpszFileName, DWORD dwFileSizeLimit, char *o_lpszHexDigest, DWORD dwHexDigestSize);
DWORD Export_ShellNotice(DWORD dwDurationSeconds, bool bWait, DWORD dwStyle, WCHAR *lpszTitle, WCHAR *lpszMessage);
bool Export_HashFile(const WCHAR *lpszFileName, DWORD dwFileSizeLimit, HASHES *hashes);
void Export_EnableEvent(DWORD dEvent);
const WCHAR* Export_GetProcessCommandLine();
void* Export_AllocateMemory(size_t dwNumElements, size_t dwElementSize);
void Export_FreeMemory(void *lpPointer);
bool Export_GetProcFilterPath(WCHAR *lpszResult, DWORD dwResultSize, const WCHAR *lpszFileBaseName, const WCHAR *lpszSubDirectoryBaseName);
WCHAR* Export_DuplicateString(const WCHAR *lpszString);
bool Export_VerifyPeSignature(const WCHAR *lpszFileName, bool bCheckRevocations);
void Export_StatusPrintFmt(const WCHAR *lpszFmt, ...);
void Export_Scan(const void *lpvData, DWORD dwDataSize, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *lpvUserData, SCAN_RESULT *o_result);
}

#else 

#define StoreExport(FunctionName) e->##FunctionName = Export_##FunctionName

StoreExport(RegisterPlugin);
StoreExport(GetConfigInt);
StoreExport(GetConfigString);
StoreExport(GetConfigBool);
StoreExport(AllocateScanContext);
StoreExport(FreeScanContext);
StoreExport(GetNtPathName);
StoreExport(ShellNotice);
StoreExport(AllocateScanContextLocalAndRemote);
StoreExport(ShellNoticeFmt);
StoreExport(QuarantineFile);
StoreExport(HashFile);
StoreExport(GetProcessCommandLine);
StoreExport(EnableEvent);
StoreExport(ScanFile);
StoreExport(ScanMemory);
StoreExport(ScanData);
StoreExport(Die);
StoreExport(Log);
StoreExport(LogWarning);
StoreExport(LogCritical);
StoreExport(LogFmt);
StoreExport(LogWarningFmt);
StoreExport(LogCriticalFmt);
StoreExport(AllocateMemory);
StoreExport(GetFile);
StoreExport(FreeMemory);
StoreExport(DuplicateString);
StoreExport(VerifyPeSignature);
StoreExport(ConcatenateString);
StoreExport(FormatString);
StoreExport(VConcatenateString);
StoreExport(VFormatString);
StoreExport(ReadProcessMemory);
StoreExport(ReadProcessPeb);
StoreExport(GetProcFilterPath);
StoreExport(StatusPrintFmt);
StoreExport(GetProcessFileName);
StoreExport(GetProcessBaseNamePointer);
StoreExport(LockPid);
StoreExport(IsElevated);
StoreExport(Scan);

#undef StoreExport

#endif
