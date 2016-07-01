
#pragma once

#include <Windows.h>

typedef struct rc4_context RC4_CONTEXT;
struct rc4_context {
	BYTE i;
	BYTE j;
	BYTE S[256];
};

void Rc4Init(RC4_CONTEXT *ctx, const void *lpPassword, size_t dwPasswordSize);
void Rc4Crypt(RC4_CONTEXT *ctx, void *lpData, size_t dwDataSize);
