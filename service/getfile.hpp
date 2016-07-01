
#pragma once

#include "config.hpp"

//
// Get a file from a URL, up to the specified size.
//
bool GetFile(const WCHAR *lpszUrl, void *lpvResult, DWORD dwResultSize, DWORD *lpdwBytesUsed);
