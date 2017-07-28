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

#include "hash.hpp"

#include "strlcat.hpp"


#define BLOCK_SIZE 8192


bool
HashFile(const WCHAR *lpszFileName, HASHES *hashes)
{
	ZeroMemory(hashes, sizeof(HASHES));

	bool rv = false;
	BOOL rc = FALSE;
	HCRYPTPROV hCryptoProvider = NULL;
	HCRYPTHASH hMd5Hash = NULL;
	HCRYPTHASH hSha1Hash = NULL;
	HCRYPTHASH hSha256Hash = NULL;
	DWORD dwBytesRead = 0;
	BYTE baBlock[BLOCK_SIZE];

	// Open the input file for reading
	HANDLE hFile = CreateFile(lpszFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) goto cleanup;

	// Open up the Wincrypt API
	if (!CryptAcquireContext(&hCryptoProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) goto cleanup;
	if (!CryptCreateHash(hCryptoProvider, CALG_MD5, 0, 0, &hMd5Hash)) goto cleanup;
	if (!CryptCreateHash(hCryptoProvider, CALG_SHA1, 0, 0, &hSha1Hash)) goto cleanup;
	if (!CryptCreateHash(hCryptoProvider, CALG_SHA_256, 0, 0, &hSha256Hash)) goto cleanup;

	// Loop and read all bytes in the file and pass them through the hash context
	while ((rc = ReadFile(hFile, baBlock, sizeof(baBlock), &dwBytesRead, NULL)) == TRUE) {
		if (dwBytesRead == 0) break;
		if (!CryptHashData(hMd5Hash, baBlock, dwBytesRead, 0)) goto cleanup;
		if (!CryptHashData(hSha1Hash, baBlock, dwBytesRead, 0)) goto cleanup;
		if (!CryptHashData(hSha256Hash, baBlock, dwBytesRead, 0)) goto cleanup;
	}

	if (!rc) goto cleanup;

	// Extract the hash values
	DWORD dwDigestLen = sizeof(hashes->md5_digest);
	if (!CryptGetHashParam(hMd5Hash, HP_HASHVAL, hashes->md5_digest, &dwDigestLen, 0)) goto cleanup;

	dwDigestLen = sizeof(hashes->sha1_digest);
	if (!CryptGetHashParam(hSha1Hash, HP_HASHVAL, hashes->sha1_digest, &dwDigestLen, 0)) goto cleanup;

	dwDigestLen = sizeof(hashes->sha256_digest);
	if (!CryptGetHashParam(hSha256Hash, HP_HASHVAL, hashes->sha256_digest, &dwDigestLen, 0)) goto cleanup;

	// Convert and store the digest to hex
	for (size_t i = 0; i < MD5_DIGEST_SIZE; ++i) {
		strlprintf(&hashes->md5_hexdigest[i*2], 3, "%.02X", hashes->md5_digest[i]);
	}
	for (size_t i = 0; i < SHA1_DIGEST_SIZE; ++i) {
		strlprintf(&hashes->sha1_hexdigest[i*2], 3, "%.02X", hashes->sha1_digest[i]);
	}
	for (size_t i = 0; i < SHA256_DIGEST_SIZE; ++i) {
		strlprintf(&hashes->sha256_hexdigest[i*2], 3, "%.02X", hashes->sha256_digest[i]);
	}

	rv = true;

cleanup:
	if (hSha256Hash) CryptDestroyHash(hSha256Hash);
	if (hSha1Hash) CryptDestroyHash(hSha1Hash);
	if (hMd5Hash) CryptDestroyHash(hMd5Hash);
	if (hCryptoProvider) CryptReleaseContext(hCryptoProvider, 0);
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

	return rv;
}
