
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
