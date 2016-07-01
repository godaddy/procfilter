
#pragma once

#include <Windows.h>

//
// Convenience function that logs a warning to Windows Event Log
//
void Warning(const WCHAR *lpFmt, ...);

//
// Convenience function that logs a notice to Windows Event Log
//
void Notice(const WCHAR *lpFmt, ...);
