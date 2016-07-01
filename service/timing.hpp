
#pragma once

#include <Windows.h>

//
// Get the performance frequency for use in GetPerformanceSeconds() and GetPerformanceMilliseconds() functions
//
inline LONG64 GetPerformanceFrequency() { LARGE_INTEGER li; QueryPerformanceFrequency(&li); return li.QuadPart; }

//
// Get the current high perormance tick count
//
inline LONG64 GetPerformanceCount() { LARGE_INTEGER li; QueryPerformanceCounter(&li); return li.QuadPart; }

//
// Convert the given performance tick count to seconds or milliseconds
//
inline LONG64 GetPerformanceSeconds(const LONG64 llValue, const LONG64 llFrequency) { return llFrequency ? llValue / llFrequency : 0; }
inline LONG64 GetPerformanceMilliseconds(const LONG64 llValue, const LONG64 llFrequency) { return llFrequency ? (llValue * 1000) / llFrequency : 0; }

//
// Get the current tick value as a percentage of the given total
//
inline double GetPerformancePercent(const LONG64 llValue, LONG64 llTotal) { return double(llTotal) != 0.0 ? (double(llValue) / double(llTotal) * 100.0) : 0.0; }

//
// Get the difference between two tick counts
//
inline LONG64 GetPerformanceCountDiff(const LONG64 llNow, const LONG64 llBase) { return (LONG64)((llNow - llBase) & 0x7FFFFFFFFFFFFFFFUL); }
