
#define _CRT_SECURE_NO_WARNINGS 1
#include <conio.h>
#include <Windows.h>

#include <stdio.h>

#include <string>
#include <vector>

#include "configure.hpp"
#include "strlcat.hpp"
#include "config.hpp"


static
const WCHAR* GetNext(int argc, WCHAR *argv[], int *current_arg, int *current_char)
{
	if (*current_arg >= argc) return NULL;

	if (argv[*current_arg][*current_char] == '\0') {
		*current_arg += 1;
		*current_char = 0;
		if (*current_arg >= argc) return NULL;
	}

	const WCHAR *result = &argv[*current_arg][*current_char];

	*current_char += 1;

	return result;
}


static
void
AskBool(const WCHAR *lpszConfigFile, const WCHAR *lpszSection, const WCHAR *lpszKey, const WCHAR *lpszQuestion, bool bDefault, int argc, WCHAR *argv[], int *current_arg, int *current_char, std::vector<std::wstring> &input)
{
	bDefault = GetPrivateProfileIntW(lpszSection, lpszKey, bDefault ? 1 : 0, lpszConfigFile) != 0;
	int result = 'y';

	wprintf(L"%s [%c/%c] ", lpszQuestion, bDefault ? 'Y' : 'y', !bDefault ? 'N' : 'n');
	fflush(stdout);

	const WCHAR *answer = GetNext(argc, argv, current_arg, current_char);
	if (answer) {
		wprintf(L"%c", *answer);
		result = *answer;
	} else {
		result = _getch();
		putwchar(result);
	}
	wprintf(L"\n");

	result = towlower(result);
	bool bResult = bDefault;
	if (result == 'y' || result == 'n') {
		bResult = result == 'y' ? true : false;
	}
	
	input[input.size()-1].push_back(bResult ? 'y' : 'n');
	
	const WCHAR *szResult = bResult ? L"1" : L"0";
	WritePrivateProfileStringW(lpszSection, lpszKey, szResult, lpszConfigFile);
}


static
bool
AskModify(int argc, WCHAR *argv[], int *current_arg, int *current_char, std::vector<std::wstring> &input)
{
	wprintf(L"Modify? [m|y/N] ");
	fflush(stdout);
	const WCHAR *answer = GetNext(argc, argv, current_arg, current_char);
	WCHAR c;
	if (answer) {
		c = *answer;
	} else {
		c = _getwch();
		putwchar(c);
		putwchar('\n');
	}
	c = towlower(c);
	input[input.size()-1].push_back('m');
	return c == 'y' || c == 'm';
}


static
void
AskInt(const WCHAR *lpszConfigFile, const WCHAR *lpszSection, const WCHAR *lpszKey, const WCHAR *lpszQuestion, int dDefault, int argc, WCHAR *argv[], int *current_arg, int *current_char, std::vector<std::wstring> &input)
{
	int dFileDefault = GetPrivateProfileIntW(lpszSection, lpszKey, dDefault, lpszConfigFile);
	int result = dFileDefault;

	wprintf(L"%s? [%d] ", lpszQuestion, dFileDefault);
	if (AskModify(argc, argv, current_arg, current_char, input)) {
		const WCHAR *answer = GetNext(argc, argv, current_arg, current_char);
		if (answer) {
			wprintf(L"%s", answer);
			result = _wtoi(answer);
			*current_arg += 1;
			*current_char = 0;
		} else {
			if (wscanf(L"%d", &result) != 1) result = dFileDefault;
			wprintf(L"%d", result);
		}
		wprintf(L"\n");
	}

	WCHAR szResult[256];
	wstrlprintf(szResult, sizeof(szResult), L"%d", result);
	input.push_back(szResult);
	input.push_back(L"");
	WritePrivateProfileStringW(lpszSection, lpszKey, szResult, lpszConfigFile);
}


static
void
AskString(const WCHAR *lpszConfigFile, const WCHAR *lpszSection, const WCHAR *lpszKey, const WCHAR *lpszQuestion, const WCHAR *lpszDefault, int argc, WCHAR *argv[], int *current_arg, int *current_char, std::vector<std::wstring> &input)
{
	WCHAR lpszFileDefault[8192] = {0};
	GetPrivateProfileStringW(lpszSection, lpszKey, lpszDefault, lpszFileDefault, 8192-1, lpszConfigFile);

	wprintf(L"%s [%s] ", lpszQuestion, lpszFileDefault);
	if (AskModify(argc, argv, current_arg, current_char, input)) {
		const WCHAR *answer = GetNext(argc, argv, current_arg, current_char);
		if (answer) {
			wstrlprintf(lpszFileDefault, sizeof(lpszFileDefault), L"%s", answer);
			wprintf(L"%s\n", lpszFileDefault);
			*current_arg += 1;
			*current_char = 0;
		} else {
			wprintf(L"\nEnter new value: ");
			fflush(stdout);
			WCHAR buf[8192] = {0};
			if (wscanf(L"%8191[^\n]s", buf) == 1) {
				wstrlprintf(lpszFileDefault, sizeof(lpszFileDefault), L"%s", buf);
			}
		}
	}

	input.push_back(lpszFileDefault);
	input.push_back(L"");

	WritePrivateProfileStringW(lpszSection, lpszKey, lpszFileDefault, lpszConfigFile);
}


void
ConfigureConfigure(int argc, WCHAR *argv[])
{
	const CONFIG_DATA *cd = GetConfigData();
	const WCHAR *cf = cd->szConfigFile;

	int ca = 0;
	int cc = 0;

	wprintf(L"ProcFilter configuration\n");
	wprintf(L"\n");
	wprintf(L"Rerun any time with \"procfilter.exe -configure\"\n");
	wprintf(L"\n");
	std::vector<std::wstring> input;
	input.push_back(L"");
	AskString(cf, L"ProcFilter", L"Plugins", L"Plugins list", L"core", argc, argv, &ca, &cc, input);
	AskBool(cf, L"ProcFilter", L"ScanFileOnProcessCreate", L"Scan .EXE files with YARA?", true, argc, argv, &ca, &cc, input);
	AskBool(cf, L"CorePlugin", L"HashExes", L"Hash .EXE files (MD5/SHA1/SHA256)?", true, argc, argv, &ca, &cc, input);
	AskBool(cf, L"ProcFilter", L"ScanFileOnImageLoad", L"Scan .DLL files with YARA?", false, argc, argv, &ca, &cc, input);
	AskBool(cf, L"CorePlugin", L"HashDlls", L"Hash .DLL files (MD5/SHA1/SHA256)?", false, argc, argv, &ca, &cc, input);
	AskBool(cf, L"CorePlugin", L"LogRemoteThreads", L"Log unprivileged remote threads?", true, argc, argv, &ca, &cc, input);
	AskBool(cf, L"CorePlugin", L"LogCommandLineArguments", L"Log command line arguments?", true, argc, argv, &ca, &cc, input);

	wprintf(L"\nConfigure String: ");
	for (auto &s : input) {
		wprintf(L"\"%s\" ", s.c_str());
	}
	wprintf(L"\n");
}
