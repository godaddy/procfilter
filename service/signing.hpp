
#pragma once

#include <Windows.h>

//
// Verify the code signing status of a file, optionally checking the revocations
//
bool VerifyPeSignature(const WCHAR *lpszFileName, bool bCheckRevocations);
