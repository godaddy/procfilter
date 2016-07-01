
#pragma once

#include <Windows.h>

//
// Get cryptographically suitable random data
//
bool GetRandomData(void *lpvResult, DWORD szResultSize);
