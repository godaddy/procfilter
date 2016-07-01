
#include "file.hpp"


bool
FileExists(const WCHAR *lpszFileName)
{
	bool rv = false;

	HANDLE h = CreateFile(lpszFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (h != INVALID_HANDLE_VALUE) {
		rv = true;
		CloseHandle(h);
	}

	return rv;
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
