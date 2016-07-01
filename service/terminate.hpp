
#pragma once

#include <Windows.h>

//
// Terminate a process given a PID
//
bool TerminateProcessByPid(DWORD dwProcessId, bool bLog, const WCHAR *lpszFileName=NULL, const WCHAR *lpszFileBlockRuleNames=NULL, const WCHAR *lpszMemoryBlockRuleNames=NULL);
