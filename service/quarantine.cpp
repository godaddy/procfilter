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

#include "quarantine.hpp"

#include <stdio.h>
#include <time.h>

#include "procfilter/procfilter.h"
#include "random.hpp"
#include "hash.hpp"
#include "strlcat.hpp"
#include "config.hpp"
#include "rc4.hpp"

#pragma comment(lib, "user32.lib")


#pragma pack(push, 1)
typedef struct quarantine_header QUARANTINE_HEADER;
struct quarantine_header {
	DWORD      dwSignature;
	WCHAR      szProcFilterVersion[16];
	ULARGE_INTEGER dwSize;
	WCHAR      szOriginalFilename[MAX_PATH];
	WCHAR      szFileQuarantineRuleMatches[256];
	WCHAR      szMemoryQuarantineRuleMatches[256];
	BYTE       baKey[32];
	__time64_t tFirstQuarantined;
};
#pragma pack(pop)

#define QUARANTINE_HEADER_SIGNATURE ('TQFP') // "PFQT"


static
bool
QuarantineStoreFile(const WCHAR *lpszSourceFileName, const WCHAR *lpszDestFileName, const WCHAR *lpszFileQuarantineRuleMatches, const WCHAR *lpszMemoryQuarantineRuleMatches)
{
	bool rv = false;
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;
	BYTE buf[4096];
	BOOL rrv = FALSE, wrv = FALSE;

	// Open handles to both the inout and output files
	HANDLE i = CreateFile(lpszSourceFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE o = CreateFile(lpszDestFileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
	if (i == INVALID_HANDLE_VALUE) goto cleanup;
	if (o == INVALID_HANDLE_VALUE) {
		if (GetLastError() == ERROR_FILE_EXISTS) {
			rv = true;
		}
		goto cleanup;
	}

	// Get the key for encryption
	BYTE baKey[32] = { 0 };
	GetRandomData(baKey, sizeof(baKey));

	// Initialize the RC4 Context
	RC4_CONTEXT rc4;
	Rc4Init(&rc4, baKey, sizeof(baKey));

	// Build the header
	QUARANTINE_HEADER qhHeader;
	ZeroMemory(&qhHeader, sizeof(QUARANTINE_HEADER));
	qhHeader.dwSignature = QUARANTINE_HEADER_SIGNATURE;
	wcsncpy(qhHeader.szProcFilterVersion, PROCFILTER_VERSION, _countof(qhHeader.szProcFilterVersion));
	qhHeader.dwSize.LowPart = GetFileSize(i, &qhHeader.dwSize.HighPart);
	wcsncpy(qhHeader.szOriginalFilename, lpszSourceFileName, _countof(qhHeader.szOriginalFilename));
	qhHeader.tFirstQuarantined = _time64(NULL);
	CopyMemory(qhHeader.baKey, baKey, sizeof(baKey));
	if (lpszFileQuarantineRuleMatches) wcsncpy(qhHeader.szFileQuarantineRuleMatches, lpszFileQuarantineRuleMatches, _countof(qhHeader.szFileQuarantineRuleMatches));
	if (lpszMemoryQuarantineRuleMatches) wcsncpy(qhHeader.szMemoryQuarantineRuleMatches, lpszMemoryQuarantineRuleMatches, _countof(qhHeader.szMemoryQuarantineRuleMatches));

	// Write the header to disk
	wrv = WriteFile(o, &qhHeader, sizeof(QUARANTINE_HEADER), &dwBytesWritten, NULL);
	if (!wrv || dwBytesWritten != sizeof(QUARANTINE_HEADER)) goto cleanup;

	while ((rrv = ReadFile(i, buf, sizeof(buf), &dwBytesRead, NULL)) == TRUE) {
		if (dwBytesRead == 0) break;

		// Encrypt the payload with RC4
		Rc4Crypt(&rc4, buf, dwBytesRead);

		// Write the block to disk
		wrv = WriteFile(o, buf, dwBytesRead, &dwBytesWritten, NULL);
		if (!wrv || dwBytesWritten != dwBytesRead) goto cleanup;
	}

	if (!rrv) goto cleanup;

	rv = true;

cleanup:
	if (i != INVALID_HANDLE_VALUE) CloseHandle(i);
	if (o != INVALID_HANDLE_VALUE) {
		CloseHandle(o);
		if (!rv) {
			DeleteFile(lpszDestFileName);
		}
	}

	return rv;
}


bool
QuarantineFile(const WCHAR *lpszFileName, const WCHAR *lpszQuarantineDirectory, DWORD dwFileSizeLimit, const WCHAR *lpszFileRuleMatches, const WCHAR *lpszMemoryRuleMatches, char o_hexdigest[SHA1_HEXDIGEST_LENGTH+1])
{
	bool rv = false;

	// Test the file's size to see if it exceeds the maximum file size to quarantine
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwFileSize = 0;
	if (dwFileSizeLimit) {
		hFile = CreateFile(lpszFileName, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile != INVALID_HANDLE_VALUE) {
			dwFileSize = GetFileSize(hFile, NULL);
		}
	}
	
	// Hash the file and copy it to the quarantine directory
	if (dwFileSizeLimit == 0 || dwFileSize <= dwFileSizeLimit) {
		WCHAR szQuarantineFileName[MAX_PATH+1] = { '\0' };
		HASHES hashes;
		if (HashFile(lpszFileName, &hashes)) {
			strlprintf(o_hexdigest, SHA1_HEXDIGEST_LENGTH+1, "%hs", hashes.sha1_hexdigest);
			wstrlprintf(szQuarantineFileName, sizeof(szQuarantineFileName), L"%ls%hs", lpszQuarantineDirectory, hashes.sha1_hexdigest);
			if (QuarantineStoreFile(lpszFileName, szQuarantineFileName, lpszFileRuleMatches, lpszMemoryRuleMatches)) {
				rv = true;
			}
		}
	}

	// This handle was kept open until now to avoid a race condition between getting the file size and then quarantining it
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

	return rv;
}


static
bool
ReadQuarantineHeader(HANDLE hFile, QUARANTINE_HEADER *qhHeader)
{
	bool rv = false;
	DWORD dwBytesRead = 0;
	if (ReadFile(hFile, qhHeader, sizeof(QUARANTINE_HEADER), &dwBytesRead, NULL) && dwBytesRead == sizeof(QUARANTINE_HEADER)) {
		if (qhHeader->dwSignature == QUARANTINE_HEADER_SIGNATURE) {
			rv = true;
		}
	}

	return rv;
}


bool
UnquarantineFile(const WCHAR *lpszFileName, const WCHAR *lpszResultFileName, WCHAR *lpszError, DWORD dwErrorSize)
{
	// Open source
	HANDLE hSource = CreateFileW(lpszFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hSource == INVALID_HANDLE_VALUE) {
		if (lpszError) wstrlprintf(lpszError, dwErrorSize, L"Unable to open source file");
		return false;
	}

	// Read the file header
	QUARANTINE_HEADER qhHeader;
	if (!ReadQuarantineHeader(hSource, &qhHeader)) {
		if (lpszError) wstrlprintf(lpszError, dwErrorSize, L"Source is not a quarantine file");
		CloseHandle(hSource);
		return false;
	}

	// Open destination
	HANDLE hDestination = CreateFileW(lpszResultFileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
	if (hDestination == INVALID_HANDLE_VALUE) {
		if (lpszError) {
			if (GetLastError() == ERROR_ALREADY_EXISTS) {
				wstrlprintf(lpszError, dwErrorSize, L"Destination file already exists");
			} else {
				wstrlprintf(lpszError, dwErrorSize, L"Unable to open destination file");
			}
		}
		CloseHandle(hSource);
		return false;
	}

	// Init the RC4 context
	RC4_CONTEXT rc4;
	Rc4Init(&rc4, qhHeader.baKey, sizeof(qhHeader.baKey));

	// Decrypt the contents of the source and store it to the destination
	BYTE buf[8192];
	DWORD dwBytesRead = 0;
	bool rv = false;
	while (ReadFile(hSource, buf, sizeof(buf), &dwBytesRead, NULL)) {
		if (dwBytesRead == 0) {
			rv = true;
			break;
		}

		// Decrypt the payload with RC4
		Rc4Crypt(&rc4, buf, dwBytesRead);

		// Write the block to disk
		DWORD dwBytesWritten = 0;
		if (!WriteFile(hDestination, buf, dwBytesRead, &dwBytesWritten, NULL) || dwBytesWritten != dwBytesRead) break;
	}

	CloseHandle(hSource);
	CloseHandle(hDestination);

	return rv;
}


void
QuarantineList()
{
	CONFIG_DATA *cd = GetConfigData();

	bool bDisplayed = false;

	// Loop through all files in the quarantine directory
	WIN32_FIND_DATA fdFindData;
	WCHAR szQuranantineWildcard[MAX_PATH+3];
	wstrlprintf(szQuranantineWildcard, sizeof(szQuranantineWildcard), L"%ls*", cd->szQuarantineDirectory);
	HANDLE hFindHandle = FindFirstFileW(szQuranantineWildcard, &fdFindData);
	if (hFindHandle != INVALID_HANDLE_VALUE) {
		do {
			if (fdFindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

			if (bDisplayed) fwprintf(stdout, L"\n");

			fwprintf(stdout, L"%ls\n", fdFindData.cFileName);
			WCHAR szFullFileName[MAX_PATH+1];
			wstrlprintf(szFullFileName, sizeof(szFullFileName), L"%ls%ls", cd->szQuarantineDirectory, fdFindData.cFileName);
			HANDLE hFile = CreateFileW(szFullFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			if (hFile != INVALID_HANDLE_VALUE) {
				QUARANTINE_HEADER qhHeader;
				if (ReadQuarantineHeader(hFile, &qhHeader)) {
					fwprintf(stdout, L"\tOriginal Filename:       %.*ls\n", (int)_countof(qhHeader.szOriginalFilename), qhHeader.szOriginalFilename);
					fwprintf(stdout, L"\tSize:                    %I64u bytes\n", qhHeader.dwSize.QuadPart);
					fwprintf(stdout, L"\tQuarantine File Rules:   %.*ls\n", (int)_countof(qhHeader.szFileQuarantineRuleMatches), qhHeader.szFileQuarantineRuleMatches);
					fwprintf(stdout, L"\tQuarantine Memory Rules: %.*ls\n", (int)_countof(qhHeader.szMemoryQuarantineRuleMatches), qhHeader.szMemoryQuarantineRuleMatches);
					char szTimestamp[64] = { '\0' };
					if (_ctime64_s(szTimestamp, sizeof(szTimestamp)-1, &qhHeader.tFirstQuarantined) == 0) {
						fwprintf(stdout, L"\tFirst Seen:              %.24hs\n", szTimestamp);
					} else {
						fwprintf(stdout, L"\tFirst Seen:              Invalid timestamp\n");
					}
				} else {
					fwprintf(stdout, L"\t* Target file is not a quarantine file\n");
				}
				CloseHandle(hFile);
			} else {
				fwprintf(stdout, L"\t* Unable to open file: %d\n", GetLastError());
			}
			bDisplayed = true;
		} while (FindNextFile(hFindHandle, &fdFindData));
	
		FindClose(hFindHandle);
	}

	if (!bDisplayed) fprintf(stderr, "No files in quarantine\n");
}
