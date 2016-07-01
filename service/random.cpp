
#include <Windows.h>
#include <Wincrypt.h>

#include "random.hpp"

#pragma comment(lib, "advapi32.lib")


bool
GetRandomData(void *lpvResult, DWORD szResultSize)
{
	bool rv = false;

	HCRYPTPROV hProvider = NULL;
	if (CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		if (CryptGenRandom(hProvider, szResultSize, (BYTE*)lpvResult)) {
			rv = true;
		}
		CryptReleaseContext(hProvider, 0);
	}

	return rv;
}
