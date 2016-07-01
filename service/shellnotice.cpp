
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
