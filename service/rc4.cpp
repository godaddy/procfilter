
#include "rc4.hpp"


static inline
void
swap(BYTE &a, BYTE &b)
{
	BYTE c = a;
	a = b;
	b = c;
}


void
Rc4Init(RC4_CONTEXT *ctx, const void *lpKeyData, size_t dwKeyDataSize)
{
	ctx->i = 0;
	ctx->j = 0;

	// Initialize the state array
	BYTE i = 0;
	do {
		ctx->S[i] = i;
	} while (i++ < 255);
	
	if (lpKeyData == NULL || dwKeyDataSize == 0) return;

	// Initialize the context with the password
	BYTE j = 0;
	i = 0;
	do {
		j += ctx->S[i] + ((BYTE*)lpKeyData)[i % dwKeyDataSize];
		swap(ctx->S[i], ctx->S[j]);
	} while (i++ < 255);
}


void
Rc4Crypt(RC4_CONTEXT *ctx, void *lpData, size_t dwDataSize)
{
	for (size_t dwOffset = 0; dwOffset < dwDataSize; ++dwOffset) {
		ctx->i += 1;
		ctx->j += ctx->S[ctx->i];
		swap(ctx->S[ctx->i], ctx->S[ctx->j]);

		*((BYTE*)lpData + dwOffset) ^= ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) & 0xFF];
	}
}
