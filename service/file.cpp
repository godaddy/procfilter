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
#include <Shlwapi.h>

#include "file.hpp"

#pragma comment (lib, "shlwapi.lib")


bool
FileExists(const WCHAR *lpszFileName)
{
	return PathFileExistsW(lpszFileName) != FALSE;
}


bool
FileChanged(const WCHAR *lpszFileName, const FILETIME *ftLastWrite, FILETIME *o_ftCurrentWriteTime)
{
	bool rv = false;

	HANDLE h = CreateFile(lpszFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (h != INVALID_HANDLE_VALUE) {
		// Get the file's last written timestamp
		FILETIME cur;
		if (GetFileTime(h, NULL, NULL, &cur)) {
			ULARGE_INTEGER newli;
			newli.HighPart = cur.dwHighDateTime;
			newli.LowPart = cur.dwLowDateTime;

			// If the last time written was passed in, compare it against the timestamp just retrieved
			if (ftLastWrite) {
				ULARGE_INTEGER oldli;
				oldli.HighPart = ftLastWrite->dwHighDateTime;
				oldli.LowPart = ftLastWrite->dwLowDateTime;

				if (newli.QuadPart != oldli.QuadPart) {
					rv = true;
				}
			} else {
				rv = true;
			}

			// If the file changed and the current write time was passed in, update it to reflect the new value
			if (rv && o_ftCurrentWriteTime) {
				o_ftCurrentWriteTime->dwHighDateTime = cur.dwHighDateTime;
				o_ftCurrentWriteTime->dwLowDateTime = cur.dwLowDateTime;
			}
		} else if (o_ftCurrentWriteTime) {
			o_ftCurrentWriteTime->dwHighDateTime = -1;
			o_ftCurrentWriteTime->dwLowDateTime = -1;
		}

		CloseHandle(h);
	} else if (o_ftCurrentWriteTime) {
		o_ftCurrentWriteTime->dwHighDateTime = -1;
		o_ftCurrentWriteTime->dwLowDateTime = -1;
	}

	return rv;
}
