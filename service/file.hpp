
#pragma once

#include <Windows.h>


//
// Determine if the given file exists
//
bool FileExists(const WCHAR *lpszFileName);

//
// Determine if a file has changed since the last time written. Both FILETIME arguments are optional and may overlap.
//
bool FileChanged(const WCHAR *lpszFileName, const FILETIME *ftLastWrite, FILETIME *o_ftCurrentWriteTime);
