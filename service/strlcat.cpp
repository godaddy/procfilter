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
