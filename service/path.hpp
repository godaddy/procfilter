
#pragma once

#include <Windows.h>

//
// Get the NT path name for a DOS path.  All output parameters are optional.
//
bool GetNtPathName(const WCHAR *lpszDosPath, WCHAR *lpszNtDevice, DWORD dwNtDeviceSize, WCHAR *lpszFilePath, DWORD dwFilePathSize, WCHAR *lpszFullPath, DWORD dwFullPathSize);
