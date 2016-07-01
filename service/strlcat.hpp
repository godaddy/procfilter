
#pragma once

#include <Windows.h>

#include <stdarg.h>

//
// String formatting functions that always NULL-terminate and that take in
// buffer sizes in bytes rather than character counts.  All project code
// should use this functions rather than alternatives provided by various
// other libraries.
//

bool strlcatf(char *dst, size_t dst_sz, const char *fmt, ...);
bool strlprintf(char *dst, size_t dst_sz, const char *fmt, ...);
bool wstrlcatf(WCHAR *dst, size_t dst_sz, const WCHAR *fmt, ...);
bool wstrlprintf(WCHAR *dst, size_t dst_sz, const WCHAR *fmt, ...);

bool vstrlcatf(char *dst, size_t dst_sz, const char *fmt, va_list ap);
bool vstrlprintf(char *dst, size_t dst_sz, const char *fmt, va_list ap);
bool vwstrlcatf(WCHAR *dst, size_t dst_sz, const WCHAR *fmt, va_list ap);
bool vwstrlprintf(WCHAR *dst, size_t dst_sz, const WCHAR *fmt, va_list ap);
