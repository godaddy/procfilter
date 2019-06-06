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

#include "hash.hpp"

//
// Quarantine a file if it doesn't already exist in quarantine, to be called by the service
//
bool QuarantineFile(DWORD dwRelatedProcessId, const WCHAR *lpszFileName, const WCHAR *lpszQuarantineDirectory, DWORD dwFileSizeLimit, const WCHAR *lpszFileRuleMatches, const WCHAR *lpszMemoryRuleMatches, char *o_lpszHexDigest, DWORD dwHexDigestSize);

//
// Unquarantine a file
//
bool UnquarantineFile(const WCHAR *lpszFileName, const WCHAR *lpszResultFileName, WCHAR *lpszError, DWORD dwErrorSize);

//
// List files in quarantine to stdout
//
void QuarantineList();
