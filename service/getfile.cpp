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
