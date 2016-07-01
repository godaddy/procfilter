
#pragma once

#include <Windows.h>

#include "sha1.hpp"

//
// Quarantine a file if it doesn't already exist in quarantine, to be called by the service
//
bool QuarantineFile(const WCHAR *lpszFileName, const WCHAR *lpszQuarantineDirectory, DWORD dwFileSizeLimit, const WCHAR *lpszFileRuleMatches, const WCHAR *lpszMemoryRuleMatches, char o_hexdigest[SHA1_HEXDIGEST_LENGTH+1]);

//
// Unquarantine a file
//
bool UnquarantineFile(const WCHAR *lpszFileName, const WCHAR *lpszResultFileName, WCHAR *lpszError, DWORD dwErrorSize);

//
// List files in quarantine to stdout
//
void QuarantineList();
