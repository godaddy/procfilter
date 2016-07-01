
#include "getfile.hpp"

#include "wininet.h"
#include <stdio.h>

#pragma comment(lib, "wininet.lib")


bool
GetFile(const WCHAR *lpszUrl, void *lpvResult, DWORD dwResultSize, DWORD *lpdwBytesUsed)
{
	*lpdwBytesUsed = 0;

	bool rv = false;

	HANDLE hInternet = NULL;
	HANDLE hUrl = NULL;
	HANDLE hRequest = NULL;

	// Open an internet handle
	hInternet = InternetOpen(L"ProcFilter Service", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hInternet) goto cleanup;

	// Set up the URL parameters
	hUrl = InternetOpenUrl(hInternet, lpszUrl, NULL, 0, INTERNET_FLAG_RELOAD, NULL);
	if (!hUrl) goto cleanup;

	// Do the download
	BYTE *p = (BYTE*)lpvResult;
	do {
		DWORD dwBytesRead = 0;
		BOOL rc = InternetReadFile(hUrl, &p[*lpdwBytesUsed], dwResultSize - *lpdwBytesUsed, &dwBytesRead);
		if (rc == TRUE && dwBytesRead == 0) {
			rv = true;
			break;
		} else if (rc == TRUE) {
			*lpdwBytesUsed += dwBytesRead;
		} else {
			break; // Error
		}
	} while (dwResultSize > *lpdwBytesUsed);
	
cleanup:
	if (hRequest) InternetCloseHandle(hRequest);
	if (hUrl) InternetCloseHandle(hUrl);
	if (hInternet) InternetCloseHandle(hInternet);

	return rv;
}
