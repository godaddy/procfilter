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

#include "strlcat.hpp"


bool
GetNtPathName(const WCHAR *lpszDosPath, WCHAR *lpszNtDevice, DWORD dwNtDeviceSize, WCHAR *lpszFilePath, DWORD dwFilePathSize, WCHAR *lpszFullPath, DWORD dwFullPathSize)
{
	DWORD dwLogicalDrives = GetLogicalDrives();

	// Iterate through the list of drives
	for (BYTE i = 0; i < 26; ++i) {
		if (dwLogicalDrives & (1 << i)) {
			WCHAR szDosDrive[3] = { (WCHAR)('a' + i), ':', '\0' };
			WCHAR szNtDevice[MAX_PATH+1] = { '\0' };
			// If the DOS path prefix matches the drive letter prefix, get that drive's NT device prefix
			if (_wcsnicmp(lpszDosPath, szDosDrive, 2) == 0 && QueryDosDevice(szDosDrive, szNtDevice, (sizeof(szNtDevice) / sizeof(WCHAR)) - 1)) {
				// NT prefix found, fill in output arguments with various portions of the path
				bool rv = true;
				if (lpszNtDevice && !wstrlprintf(lpszNtDevice, dwNtDeviceSize, L"%ls", szNtDevice)) {
					rv = false;
				}
				if (lpszFilePath && !wstrlprintf(lpszFilePath, dwFilePathSize, L"%ls", &lpszDosPath[2])) {
					rv = false;
				}
				if (lpszFullPath && !wstrlprintf(lpszFullPath, dwFullPathSize, L"%ls%ls", szNtDevice, &lpszDosPath[2])) {
					rv = false;
				}
				return rv;
			}
		}
	}

	return false;
}

