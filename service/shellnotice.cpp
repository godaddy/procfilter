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

#include <Windows.h>
#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")

#include "config.hpp"
#include "strlcat.hpp"

#include "shellnotice.hpp"

#define MESSAGEBOX_DURATION (60 * 1000)


DWORD
ShellNoticeFmt(DWORD dwDurationSeconds, bool bWait, DWORD dwStyle, WCHAR *lpszTitle, WCHAR *lpszMessageFmt, ...)
{	
	DWORD dwResult = 0;

	CONFIG_DATA *cd = GetConfigData();
	if (cd->bDisableUi) return dwResult;

	va_list ap;
	va_start(ap, lpszMessageFmt);
	
	WCHAR szMessage[256];
	vwstrlprintf(szMessage, sizeof(szMessage), lpszMessageFmt, ap);
	DWORD dwCurrentSession = WTSGetActiveConsoleSessionId();
	if (dwCurrentSession != 0xFFFFFFFF) {
		WTSSendMessage(WTS_CURRENT_SERVER_HANDLE, dwCurrentSession, lpszTitle, (DWORD)(wcslen(lpszTitle) * sizeof(WCHAR)), szMessage,
			(DWORD)(wcslen(szMessage) * sizeof(WCHAR)), dwStyle, dwDurationSeconds, &dwResult, bWait ? TRUE : FALSE);
	}

	va_end(ap);

	return dwResult;
}
