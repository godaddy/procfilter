
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

