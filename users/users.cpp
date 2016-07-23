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

#include <algorithm>
#include <string>
#include <vector>
#include <sstream>

#define NOMINMAX
#include <Windows.h>
#include <lmcons.h>

#include "procfilter/procfilter.h"

using std::wstring;

typedef std::vector<wstring> StringVector;

static StringVector g_UserNames;
static StringVector g_GroupNames;
static bool g_bListsAreWhitelists = true;


static
bool
InsensitiveEquals(const wstring &s1, const wstring &s2)
{
	if (s1.size() != s2.size()) return false;
	return _wcsicmp(s1.c_str(), s2.c_str()) == 0;
}


static
bool
ContainerContainsString(const StringVector &c, const wstring &str)
{
	return std::find_if(c.begin(), c.end(), [&str](const wstring &name){ return InsensitiveEquals(str, name); }) != c.end();
}


static
bool
GetUserNameAndGroup(HANDLE hToken, WCHAR *lpszName, DWORD dwNameSize, WCHAR *lpszGroup, DWORD dwGroupSize)
{
	// TokenOwner for group name
	BYTE buf[512] = { '\0' };
	TOKEN_USER *lpTokenUser = (TOKEN_USER*)buf;
	DWORD dwTokenUserSize = sizeof(buf);

	DWORD dwResultSize = 0;
	BOOL rc = GetTokenInformation(hToken, TokenUser, lpTokenUser, dwTokenUserSize, &dwResultSize);
	if (!rc && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		lpTokenUser = (TOKEN_USER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwResultSize);
		if (lpTokenUser) {
			rc = GetTokenInformation(hToken, TokenUser, lpTokenUser, dwResultSize, &dwResultSize);
		}
	}

	if (rc) {
		dwNameSize /= sizeof(WCHAR);
		dwGroupSize /= sizeof(WCHAR);
		SID_NAME_USE SidType;
		rc = LookupAccountSidW(NULL, lpTokenUser->User.Sid, lpszName, &dwNameSize, lpszGroup, &dwGroupSize, &SidType);
	}

	if (lpTokenUser && (void*)lpTokenUser != (void*)buf) {
		HeapFree(GetProcessHeap(), 0, lpTokenUser);
	}

	return rc ? true : false;
}


static
void
SplitIntoContainer(StringVector &c, const wstring &str, WCHAR delimiter)
{
	std::wstringstream ss(str);
	wstring cur;
	while (std::getline(ss, cur, delimiter)) {
		if (cur.size() > 0) c.push_back(std::move(cur));
	}
}


DWORD
ProcFilterEvent(PROCFILTER_EVENT *e)
{
	DWORD dwResultFlags = PROCFILTER_RESULT_NONE;

	if (e->dwEventId == PROCFILTER_EVENT_INIT) {
		e->RegisterPlugin(PROCFILTER_VERSION, L"Users", 0, 0, false, PROCFILTER_EVENT_YARA_SCAN_INIT, PROCFILTER_EVENT_NONE);
		WCHAR buf[8192];
		e->GetConfigString(L"ListType", L"", buf, sizeof(buf));
		if (_wcsicmp(buf, L"") == 0) {
			// use default
		}  else if (_wcsicmp(buf, L"Greylist") == 0 || _wcsicmp(buf, L"Graylist") == 0) {
			g_bListsAreWhitelists = false;
		} else if (_wcsicmp(buf, L"Whitelist") == 0) {
			g_bListsAreWhitelists = true;
		} else {
			e->Die("UsersPlugin:Whitelist must be either \"Greylist\" or \"Whitelist\"; value given was \"%ls\"", buf);
		}
		e->GetConfigString(L"UserNameList", L"", buf, sizeof(buf));
		SplitIntoContainer(g_UserNames, buf, ',');
		e->GetConfigString(L"GroupNameList", L"", buf, sizeof(buf));
		SplitIntoContainer(g_GroupNames, buf, ',');
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_SCAN_INIT) {
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, e->dwProcessId);
		if (hProcess != NULL) {
			HANDLE hToken = NULL;
			if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
				WCHAR szUserName[UNLEN+1] = { '\0' };
				WCHAR szGroupName[GNLEN+1] = { '\0' };
				if (GetUserNameAndGroup(hToken, szUserName, sizeof(szUserName), szGroupName, sizeof(szGroupName))) {
					bool bNameFound = ContainerContainsString(g_UserNames, szUserName);
					bool bGroupFound = ContainerContainsString(g_GroupNames, szGroupName);
					bool bFound = bNameFound || bGroupFound;
					if (g_bListsAreWhitelists) {
						if (bFound) {
							dwResultFlags |= PROCFILTER_RESULT_DONT_SCAN;
						}
					} else {
						if (!bFound) {
							dwResultFlags |= PROCFILTER_RESULT_DONT_SCAN;
						}
					}
				}
				CloseHandle(hToken);
			}
			CloseHandle(hProcess);
		}
	}

	return dwResultFlags;
}
