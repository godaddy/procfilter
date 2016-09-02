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

#include <tchar.h>
#include <stdio.h>
#include <Shlwapi.h>

#include "config.hpp"
#include "file.hpp"
#include "die.hpp"
#include "log.hpp"
#include "status.hpp"
#include "strlcat.hpp"


typedef struct config_data MCONFIG_DATA;

struct config_data __config_private_config_data;


//
// Get a non-const config data pointer for use during init
//
static inline
MCONFIG_DATA*
GetMConfigData()
{
	return &__config_private_config_data;
}


//
// Load or reload a config data structure from INI.
//
static void config_load_ini(MCONFIG_DATA *cd);


static
void
update_base_directory(MCONFIG_DATA *cd)
{	
	WCHAR szTmp[MAX_PATH+1] = { 0 };

	// update the base path based on the config file, if present
	GetPrivateProfileStringW(CONFIG_APPNAME, L"BaseDirectory", cd->szBaseDirectory, szTmp, sizeof(szTmp)/sizeof(WCHAR) - 1, cd->szConfigFile);
	wstrlprintf(cd->szBaseDirectory, sizeof(cd->szBaseDirectory), L"%ls", szTmp);
	size_t bdlen = wcslen(cd->szBaseDirectory);

	// add the terminating slash
	if (bdlen > 0 && cd->szBaseDirectory[bdlen-1] != '\\' && cd->szBaseDirectory[bdlen-1] != '/') {
		wstrlcatf(cd->szBaseDirectory, sizeof(cd->szBaseDirectory), L"%s", L"\\");
	}
}


void
ConfigInit()
{
	MCONFIG_DATA *cd = GetMConfigData();
	ZeroMemory(cd, sizeof(MCONFIG_DATA));
	
	if (!GetModuleFileName(NULL, cd->szExePath, sizeof(cd->szExePath)/sizeof(WCHAR))) {
		Die("Unable to get module filename");
	}
	
	// by default use the .exe's directory as the working path, unless the config file specifies otherwise
	WCHAR drive[MAX_PATH+1];
	WCHAR dir[MAX_PATH+1];
	_wsplitpath_s(cd->szExePath, drive, sizeof(drive)/sizeof(WCHAR), dir, sizeof(dir)/sizeof(WCHAR), NULL, 0, NULL, 0);
	wstrlprintf(cd->szBaseDirectory, sizeof(cd->szBaseDirectory), L"%ls%ls", drive, dir);
	
	// get the config path
	wstrlprintf(cd->szConfigFile, sizeof(cd->szConfigFile), L"%ls%hs", cd->szBaseDirectory, "procfilter.ini");

	wstrlprintf(cd->szLogDirectory, sizeof(cd->szLogDirectory), L"%ls%ls", cd->szBaseDirectory, L"logs\\");
	
	// update the base path based on the config file, if present
	update_base_directory(cd);
	
	config_load_ini(cd);
}


static
void
lrstrip(WCHAR *str)
{
	size_t i = 0;
	size_t j = 0;

	// skip left whitespace
	while (iswspace(str[j])) ++j;

	// remove left whitespace
	while (str[j]) {
		str[i] = str[j];
		++j;
		++i;
	}
	str[i] = '\0';

	// remove right whitespace
	size_t len = wcslen(str);
	while (len > 0 && iswspace(str[len-1])) {
		str[len-1] = '\0';
		--len;
	}
}


void
GetConfigDirectory(const WCHAR *lpszKey, const WCHAR *lpszDefault, WCHAR *lpszResult, DWORD dwResultSize)
{
	if (dwResultSize == 0) return;

	MCONFIG_DATA *cd = GetMConfigData();
	WCHAR szTmp[MAX_PATH+1] = { 0 };
	
	GetPrivateProfileString(CONFIG_APPNAME, lpszKey, lpszDefault, szTmp, _countof(szTmp) - 1, cd->szConfigFile);
	wstrlprintf(lpszResult, dwResultSize, L"%s%s", cd->szBaseDirectory, szTmp);

	size_t last_char = wcslen(lpszResult) > 0 ? wcslen(lpszResult) - 1 : 0;
	if (lpszResult[last_char] != '\\' &&
		lpszResult[last_char] != '/' ) {
		wstrlcatf(lpszResult, dwResultSize, L"%ls", L"\\");
	}
}


bool
GetProcFilterPath(WCHAR *lpszResult, DWORD dwResultSize, const WCHAR *lpszSubDirectoryBaseName, const WCHAR *lpszFileBaseName)
{
	if (!lpszSubDirectoryBaseName) lpszSubDirectoryBaseName = L"";
	if (!lpszFileBaseName) lpszFileBaseName = L"";

	CONFIG_DATA *cd = GetConfigData();

	size_t dwSubDirLength = wcslen(lpszSubDirectoryBaseName);
	bool bAddSubDirTrailingSlash = dwSubDirLength > 0 && lpszSubDirectoryBaseName[dwSubDirLength-1] != '\\' && lpszSubDirectoryBaseName[dwSubDirLength-1] != '/';
	return wstrlprintf(lpszResult, dwResultSize, L"%ls%ls%hs%ls",
		cd->szBaseDirectory, lpszSubDirectoryBaseName, bAddSubDirTrailingSlash ? "\\" : "", lpszFileBaseName);
}


static
bool
GetBool(const WCHAR *lpszKey, bool bDefault)
{
	CONFIG_DATA *cd = GetConfigData();

	return GetPrivateProfileInt(CONFIG_APPNAME, lpszKey, bDefault ? 1 : 0, cd->szConfigFile) != 0;
}


static
int
GetInt(const WCHAR *lpszKey, int dDefault)
{
	CONFIG_DATA *cd = GetConfigData();

	return GetPrivateProfileInt(CONFIG_APPNAME, lpszKey, dDefault, cd->szConfigFile);
}


static
void
GetString(const WCHAR *lpszKey, WCHAR *lpszDefault, WCHAR *lpszResult, DWORD dwResultSize)
{
	if (!lpszDefault) lpszDefault = L"";

	CONFIG_DATA *cd = GetConfigData();
	
	if (dwResultSize/sizeof(WCHAR) > 0) {
		GetPrivateProfileString(CONFIG_APPNAME, lpszKey, lpszDefault, lpszResult, dwResultSize/sizeof(WCHAR) - 1, cd->szConfigFile);
		lpszResult[dwResultSize/sizeof(WCHAR)-1] = '\0';
		lrstrip(lpszResult);
	}
}


void
config_load_ini(MCONFIG_DATA *cd)
{
	update_base_directory(cd);

	WCHAR szTmp[MAX_PATH+1] = { 0 };
	GetPrivateProfileString(CONFIG_APPNAME, L"LocalRuleFile", L"master.yara", szTmp, sizeof(szTmp)/sizeof(WCHAR) - 1, cd->szConfigFile);
	wstrlprintf(cd->szLocalYaraRuleFile, sizeof(cd->szLocalYaraRuleFile), L"%slocalrules\\%s", cd->szBaseDirectory, szTmp);
	lrstrip(cd->szLocalYaraRuleFile);
	cd->bUseLocalRuleFile = wcslen(szTmp) > 0;

	GetPrivateProfileString(CONFIG_APPNAME, L"RemoteRuleFile", L"master.yara", szTmp, sizeof(szTmp)/sizeof(WCHAR) - 1, cd->szConfigFile);
	wstrlprintf(cd->szRemoteYaraRuleFile, sizeof(cd->szRemoteYaraRuleFile), L"%sremoterules\\%s", cd->szBaseDirectory, szTmp);
	lrstrip(cd->szRemoteYaraRuleFile);
	cd->bUseRemoteRuleFile = wcslen(szTmp) > 0;

	GetPrivateProfileString(CONFIG_APPNAME, L"LogFile", L"procfilter.log", szTmp, sizeof(szTmp)/sizeof(WCHAR) - 1, cd->szConfigFile);
	wstrlprintf(cd->szLogFile, sizeof(cd->szLogFile), L"%slogs\\%s", cd->szBaseDirectory, szTmp);

	GetPrivateProfileString(CONFIG_APPNAME, L"ErrorLogFile", L"error.log", szTmp, sizeof(szTmp)/sizeof(WCHAR) - 1, cd->szConfigFile);
	wstrlprintf(cd->szErrorLogFile, sizeof(cd->szErrorLogFile), L"%slogs\\%s", cd->szBaseDirectory, szTmp);
	
	GetPrivateProfileString(CONFIG_APPNAME, L"ProcFilterDriver", L"procfilter.sys", szTmp, sizeof(szTmp)/sizeof(WCHAR) - 1, cd->szConfigFile);
	wstrlprintf(cd->szProcFilterDriver, sizeof(cd->szProcFilterDriver), L"%ssys\\%s", cd->szBaseDirectory, szTmp);

	GetConfigDirectory(L"PluginFolder", L"plugins\\", cd->szPluginDirectory, sizeof(cd->szPluginDirectory));
	GetConfigDirectory(L"QuarantineFolder", L"quarantine\\", cd->szQuarantineDirectory, sizeof(cd->szQuarantineDirectory));

	cd->dwLogLevel = GetInt(L"LogLevel", LOG_CRITICAL + 1);
	if (cd->dwLogLevel > LOG_CRITICAL + 1) {
		LogWarningFmt("LogLevel configuration value out of range, setting to %u", LOG_CRITICAL + 1);
		cd->dwLogLevel = LOG_CRITICAL + 1;
	}

	static const int dOneHourInSeconds = 60 * 60;
	cd->dwScanIntervalSeconds = GetInt(L"PeriodicScanIntervalSeconds", 24 * dOneHourInSeconds);
	if (cd->dwScanIntervalSeconds > 7 * 24 * dOneHourInSeconds) {
		cd->dwScanIntervalSeconds = 7 * 24 * dOneHourInSeconds;
		LogWarningFmt("ScanIntervalSeconds configuration value too high, setting to %u", cd->dwScanIntervalSeconds);
	}

	cd->dwPerProcessTimeoutMs = GetInt(L"PerProcessTimeoutMs", 10 * 1000);
	if (cd->dwPerProcessTimeoutMs > dOneHourInSeconds * 1000) {
		cd->dwPerProcessTimeoutMs = dOneHourInSeconds * 1000;
		LogWarningFmt("PerProcessTimeoutMs configuration value out of range, setting to %u", cd->dwPerProcessTimeoutMs);
	}
	
	cd->dThreadPoolSize = GetInt(L"ThreadPoolSize", 0);
	
	cd->bRequireSignedPlugins = 
#if defined(_DEBUG)
		!GetBool(L"AllowUnsignedPlugins", true);
#else
		!GetBool(L"AllowUnsignedPlugins", false);
#endif
	
	cd->dwScanFileSizeLimit = GetInt(L"ScanFileSizeLimit", 0);
	cd->dwQuarantineFileSizeLimit = GetInt(L"QuarantineFileSizeLimit", 0);
	
	cd->bUseBackgroundMode = GetBool(L"UseBackgroundMode", true);

	cd->bScanFileOnPeriodic = GetBool(L"ScanFileOnPeriodic", true);
	cd->bScanMemoryOnPeriodic = GetBool(L"ScanMemoryOnPeriodic", true);
	cd->bScanFileOnProcessCreate = GetBool(L"ScanFileOnProcessCreate", true);
	cd->bScanMemoryOnProcessCreate = GetBool(L"ScanMemoryOnProcessCreate", false);
	cd->bScanFileOnProcessTerminate = GetBool(L"ScanFileOnProcessTerminate", false);
	cd->bScanMemoryOnProcessTerminate = GetBool(L"ScanMemoryOnProcessTerminate", true);
	cd->bScanFileOnImageLoad = GetBool(L"ScanFileOnImageLoad", false);
	cd->bScanMemoryOnImageLoad = GetBool(L"ScanMemoryOnImageLoad", false);
	
	cd->bBlockDefault = GetBool(L"BlockDefault", false);
	cd->bLogDefault = GetBool(L"LogDefault", false);
	cd->bQuarantineDefault = GetBool(L"QuarantineDefault", false);

	cd->bDisableUi = GetBool(L"DisableUi", false);

	GetString(L"RemoteGitUrl", L"", cd->szRemoteGitUrl, sizeof(cd->szRemoteGitUrl));
	cd->bUseRemoteGitUrl = wcslen(cd->szRemoteGitUrl) > 0;
	cd->dwRemotePollIntervalMinutes = GetInt(L"RemotePollIntervalMinutes", 120);
	cd->dwRemotePollIntervalOffsetRangeSeconds = GetInt(L"RemotePollIntervalOffsetRangeSeconds", 0);
	GetConfigDirectory(L"RemoteDirectory", L"remoterules", cd->szRemoteDirectory, sizeof(cd->szRemoteDirectory));
	GetString(L"RemoteGitUserName", L"", cd->szRemoteGitUserName, sizeof(cd->szRemoteGitUserName));
	GetString(L"RemoteGitPassword", L"", cd->szRemoteGitPassword, sizeof(cd->szRemoteGitPassword));
	
	cd->bDenyProcessCreationOnFailedScan = GetBool(L"DenyProcessCreationOnFailedScan", false);

	cd->dwRuleFilePollIntervalTicks = GetInt(L"RuleFilePollIntervalSeconds", 60) * 1000;
}


void
ConfigStatusPrint()
{
	CONFIG_DATA *cd = GetConfigData();

	StatusPrint(L"Config File: %ls\n", cd->szConfigFile);
	StatusPrint(L"Local Rule File: %ls\n", cd->szLocalYaraRuleFile);
	StatusPrint(L"Remote Git URL: %ls\n", cd->szRemoteGitUrl);
	StatusPrint(L"Remote Rules Path: %ls\n", cd->szRemoteDirectory);
	StatusPrint(L"Remote Rule File: %ls\n", cd->szRemoteYaraRuleFile);
}


void
ConfigDestroy()
{
	// do nothing for now
}
