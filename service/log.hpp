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

//
// Init/shutdown the logging subsystems
//
void LogInit();
void LogShutdown();

//
// Log level declarations
//
#define LOG_DEBUG 0
#define LOG_INFORMATIONAL 1
#define LOG_NOTICE 2
#define LOG_WARNING 3
#define LOG_ERROR 4
#define LOG_CRITICAL 5

//
// Log a value at the specified log level.
//
void Log(DWORD level, const char *str);
void LogFmt(DWORD level, const char *fmt, ...);

//
// Convenience macros for logging at different levels
//
#define LogDebug(str) Log(LOG_DEBUG, str)
#define LogDebugFmt(fmt, ...) LogFmt(LOG_DEBUG, fmt, __VA_ARGS__)
#define LogInfo(str) Log(LOG_INFORMATIONAL, str)
#define LogInfoFmt(fmt, ...) LogFmt(LOG_INFORMATIONAL, fmt, __VA_ARGS__)
#define LogNotice(str) Log(LOG_NOTICE, str)
#define LogNoticeFmt(fmt, ...) LogFmt(LOG_NOTICE, fmt, __VA_ARGS__)
#define LogWarning(str) Log(LOG_WARNING, str)
#define LogWarningFmt(fmt, ...) LogFmt(LOG_WARNING, fmt, __VA_ARGS__)
#define LogError(str) Log(LOG_ERROR, str)
#define LogErrorFmt(fmt, ...) LogFmt(LOG_ERROR, fmt, __VA_ARGS__)
#define LogCritical(str) Log(LOG_CRITICAL, str)
#define LogCriticalFmt(fmt, ...) LogFmt(LOG_CRITICAL, fmt, __VA_ARGS__)
