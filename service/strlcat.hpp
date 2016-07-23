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
