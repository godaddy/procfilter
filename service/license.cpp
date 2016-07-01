
#include <Windows.h>

#include <stdio.h>

#include "license.hpp"


void
DisplayLicenses()
{
	HMODULE hSelf = GetModuleHandle(NULL);
	HRSRC hResource = FindResourceW(hSelf, MAKEINTRESOURCEW(256), MAKEINTRESOURCEW(256));
	if (!hResource) return;

	HGLOBAL hLicenses = LoadResource(hSelf, hResource);
	if (hLicenses) {
		const char *lpLicenses = (const char*)LockResource(hLicenses);
		if (lpLicenses) {
			printf("%.*hs\n", SizeofResource(hSelf, hResource), lpLicenses);
		}
	}
}
