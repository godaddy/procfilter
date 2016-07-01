
#include "sha1.hpp"

#include "strlcat.hpp"


#define BLOCK_SIZE 8192


bool
Sha1File(const WCHAR *lpszFileName, char o_hexdigest[SHA1_HEXDIGEST_LENGTH+1], unsigned char o_rawdigest[SHA1_DIGEST_SIZE])
{
	bool rv = false;
	BOOL rc = FALSE;
	HCRYPTPROV hCryptoProvider = NULL;
	HCRYPTHASH hHash = NULL;
	DWORD dwBytesRead = 0;
	BYTE baBlock[BLOCK_SIZE];
	BYTE baDigest[SHA1_DIGEST_SIZE];
	DWORD dwDigestLen = sizeof(baDigest);

	// Open the input file for reading
	HANDLE hFile = CreateFile(lpszFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) goto cleanup;

	// Open up the Wincrypt API
	if (!CryptAcquireContext(&hCryptoProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) goto cleanup;
	if (!CryptCreateHash(hCryptoProvider, CALG_SHA1, 0, 0, &hHash)) goto cleanup;

	// Loop and read all bytes in the file and pass them through the hash context
	while ((rc = ReadFile(hFile, baBlock, sizeof(baBlock), &dwBytesRead, NULL)) == TRUE) {
		if (dwBytesRead == 0) break;
		if (!CryptHashData(hHash, baBlock, dwBytesRead, 0)) goto cleanup;
	}

	if (!rc) goto cleanup;

	// Extract the hash value
	if (!CryptGetHashParam(hHash, HP_HASHVAL, baDigest, &dwDigestLen, 0)) goto cleanup;

	// Convert and store the digest if requested
	if (o_hexdigest) {
		for (size_t i = 0; i < SHA1_DIGEST_SIZE; ++i) {
			strlprintf(&o_hexdigest[i*2], 3, "%.02X", baDigest[i]);
		}
	}

	// Store the raw digest if requested
	if (o_rawdigest) {
		memcpy(o_rawdigest, baDigest, SHA1_DIGEST_SIZE);
	}

	rv = true;

cleanup:
	if (hHash) CryptDestroyHash(hHash);
	if (hCryptoProvider) CryptReleaseContext(hCryptoProvider, 0);
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

	return rv;
}
