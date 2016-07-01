
#pragma once

#include <Windows.h>

#include "procfilter/procfilter.h"

//
// Perform a SHA1 hash of a file
//
bool Sha1File(const WCHAR *lpszFileName, char o_hexdigest[SHA1_HEXDIGEST_LENGTH+1], BYTE o_rawdigest[SHA1_DIGEST_SIZE]);

