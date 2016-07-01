
#include <Windows.h>
#include <strsafe.h>

#include <stdarg.h>
#include <string.h>

#include "strlcat.hpp"


bool
strlcatf(char *dst, size_t dst_sz, const char *fmt, ...)
{
	va_list(ap);
	va_start(ap, fmt);

	bool rv = vstrlcatf(dst, dst_sz, fmt, ap);

	va_end(ap);

	return rv;
}


bool
strlprintf(char *dst, size_t dst_sz, const char *fmt, ...)
{
	va_list(ap);
	va_start(ap, fmt);

	bool rv = vstrlprintf(dst, dst_sz, fmt, ap);

	va_end(ap);

	return rv;
}


bool
wstrlcatf(WCHAR *dst, size_t dst_sz, const WCHAR *fmt, ...)
{
	va_list(ap);
	va_start(ap, fmt);

	bool rv = vwstrlcatf(dst, dst_sz, fmt, ap);

	va_end(ap);

	return rv;
}


bool
wstrlprintf(WCHAR *dst, size_t dst_sz, const WCHAR *fmt, ...)
{
	va_list(ap);
	va_start(ap, fmt);

	bool rv = vwstrlprintf(dst, dst_sz, fmt, ap);

	va_end(ap);

	return rv;
}


bool
vstrlcatf(char *dst, size_t dst_sz, const char *fmt, va_list ap)
{
	if (dst_sz == 0) return false;

	size_t dstl = strlen(dst);
	bool rv = false;
	if (dstl < dst_sz) {
		rv = SUCCEEDED(StringCbVPrintfA(&dst[dstl], dst_sz - dstl, fmt, ap));
	}

	return rv;
}


bool
vstrlprintf(char *dst, size_t dst_sz, const char *fmt, va_list ap)
{
	if (dst_sz == 0) return false;
	
	return SUCCEEDED(StringCbVPrintfA(dst, dst_sz, fmt, ap));
}


bool
vwstrlcatf(WCHAR *dst, size_t dst_sz, const WCHAR *fmt, va_list ap)
{
	if (dst_sz == 0) return false;

	bool rv = false;
	size_t dstl = wcslen(dst);
	if (dstl * sizeof(WCHAR) < dst_sz) {
		rv = SUCCEEDED(StringCbVPrintfW(&dst[dstl], dst_sz - (dstl * sizeof(WCHAR)), fmt, ap));
	}

	return rv;
}


bool
vwstrlprintf(WCHAR *dst, size_t dst_sz, const WCHAR *fmt, va_list ap)
{
	if (dst_sz == 0) return false;
	return SUCCEEDED(StringCbVPrintfW(dst, dst_sz, fmt, ap));
}
