
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
