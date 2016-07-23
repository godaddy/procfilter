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
