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
