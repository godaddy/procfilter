
#pragma once

//
// Determine if the current running process has Administrator privileges
//
bool IsAdmin();

//
// Determine if the target has elevated privileges
//
bool IsElevated(HANDLE hProcess, bool *lpbIsElevated);
