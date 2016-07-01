
#pragma once

#include <Windows.h>

//
// Raise a notice to the current logged on user
//
// dwStyle are the style constants passed in to MSDN's MessageBox() uType argument. The result is MessageBox()'s result.
//
DWORD ShellNoticeFmt(DWORD dwDurationSeconds, bool bWait, DWORD dwStyle, WCHAR *lpszTitle, WCHAR *lpszMessageFmt, ...);
