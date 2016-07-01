
#pragma once

#include <Windows.h>

//
// Get a Windows-specified error string for a Windows error code.
// Returns a thread-specific pointer to a string that is overwritten
// by subsequent calls and does not affect GetLastError().
//
const WCHAR* ErrorText(DWORD dwErrorCode);
