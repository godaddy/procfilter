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
#include <SoftPub.h>
#pragma comment(lib, "wintrust.lib")

#include "signing.hpp"


bool
VerifyPeSignature(const WCHAR *lpszFileName, bool bCheckRevocations)
{
	bool rv = false;

	// Set up the file-specific parameters of the scan
	WINTRUST_FILE_INFO wfi;
	ZeroMemory(&wfi, sizeof(WINTRUST_FILE_INFO));
	wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
	wfi.pcwszFilePath = lpszFileName;

	// Set up the verification parameters, including revokation checks
	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA wd;
	ZeroMemory(&wd, sizeof(WINTRUST_DATA));
	wd.cbStruct = sizeof(WINTRUST_DATA);
	wd.dwUIChoice = WTD_UI_NONE;
	wd.fdwRevocationChecks = bCheckRevocations ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
	wd.dwUnionChoice = WTD_CHOICE_FILE;
	wd.dwStateAction = WTD_STATEACTION_VERIFY;
	wd.pFile = &wfi;

	// Call into the WinTrust API to perform the signature verification
	LONG lStatus = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &WVTPolicyGUID, &wd);
	if (lStatus == 0) {
		rv = true;
	}

	// Close the WinTrust handle
	wd.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &WVTPolicyGUID, &wd);

	return rv;
}
