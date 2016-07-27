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

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <tchar.h>

#include <stdio.h>

#include "api.hpp"
#include "license.hpp"
#include "umdriver.hpp"
#include "pfservice.hpp"
#include "config.hpp"
#include "benchmark-timed.hpp"
#include "benchmark-counted.hpp"
#include "die.hpp"
#include "winerr.hpp"
#include "status.hpp"
#include "sha1.hpp"
#include "log.hpp"
#include "service.hpp"
#include "winmain.hpp"
#include "yara.hpp"
#include "strlcat.hpp"
#include "random.hpp"
#include "quarantine.hpp"
#include "procfilter/procfilter.h"
#include "ProcFilterEvents.h"

#include "git2/version.h"
#include "git2/global.h"


static HANDLE g_hStopService = NULL;
static SERVICE_STATUS status;
static SERVICE_STATUS_HANDLE ssh = NULL;
static bool g_bRunningAsProgram = false;


void
WINAPI
ServiceControlHandler(DWORD dwControlCode)
{
	switch (dwControlCode) {
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		status.dwCurrentState = SERVICE_STOP_PENDING;
		status.dwWaitHint = 60 * 1000;
		SetServiceStatus(ssh, &status);
		SetEvent(g_hStopService);
		break;
	default:
		break;
	}
}


static
bool
GetPrivilegeByName(WCHAR *szPrivilegeName)
{
	bool rv = false;

	HANDLE token = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
		goto cleanup;
	}

	TOKEN_PRIVILEGES newp;
	newp.PrivilegeCount = 1;
	newp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!LookupPrivilegeValue(NULL, szPrivilegeName, &newp.Privileges[0].Luid)) {
		goto cleanup;
	}

	if (!AdjustTokenPrivileges(token, FALSE, &newp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		goto cleanup;
	}

	rv = true;

cleanup:
	if (token) CloseHandle(token);

	return rv;
}


void
WINAPI
ServiceMain(DWORD argc, WCHAR *argv[])
{
	EventRegisterProcFilter();

	const CONFIG_DATA *cd = GetConfigData();
	CreateDirectoryExW(NULL, cd->szPluginDirectory, NULL);
	CreateDirectoryExW(NULL, cd->szQuarantineDirectory, NULL);
	CreateDirectoryExW(NULL, cd->szRemoteDirectory, NULL);
	SetCurrentDirectoryW(cd->szBaseDirectory);

	if (!GetPrivilegeByName(SE_DEBUG_NAME)) {
		Die(NULL, "Unable to get necessary privileges");
	}

	if (RunningAsProgram()) {
		ProcFilterServiceMainloop(g_hStopService);
	} else {
		ZeroMemory(&status, sizeof(SERVICE_STATUS));
		status.dwServiceType = SERVICE_WIN32;
		status.dwCurrentState = SERVICE_STOPPED;
		status.dwControlsAccepted = 0;
		status.dwWin32ExitCode = NO_ERROR;
		status.dwServiceSpecificExitCode = NO_ERROR;
		status.dwCheckPoint = 0;
		status.dwWaitHint = 0;

		ssh = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceControlHandler);
		if (ssh) {
			status.dwCurrentState = SERVICE_START_PENDING;
			SetServiceStatus(ssh, &status);

			status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
			status.dwCurrentState = SERVICE_RUNNING;
			SetServiceStatus(ssh, &status);

			// Start the ProcFilter service here
			ProcFilterServiceMainloop(g_hStopService);
		
			// Exit the ProcFilter service
			status.dwControlsAccepted &= ~(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
			status.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(ssh, &status);
		}
	}
	
	EventUnregisterProcFilter();
}



//
// Run the service
//
bool
ServiceRunAsService()
{
	static const SERVICE_TABLE_ENTRY table[] = {
		{ SERVICE_NAME, ServiceMain },
		{ NULL, NULL }
	};

	g_hStopService = CreateEvent(0, TRUE, FALSE, 0);
	return StartServiceCtrlDispatcher(table) && GetLastError() != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT;
}


void
ServiceRunAsProgram()
{
	g_bRunningAsProgram = true;
	g_hStopService = CreateEvent(0, TRUE, FALSE, L"Global\\ProcFilterStopEvent");
	ServiceMain(0, NULL);
}


void
ServiceStopRunAsProgram()
{
	HANDLE hStopService = CreateEvent(0, TRUE, FALSE, L"Global\\ProcFilterStopEvent");
	if (hStopService) {
		SetEvent(hStopService);
		CloseHandle(hStopService);
	} else {
		fprintf(stderr, "Service not running as program\n");
	}
}


#if defined(_DEBUG)
#pragma warning(push)
#pragma warning(disable:4091) // Disable warning due to bug as described at http://connect.microsoft.com/VisualStudio/feedbackdetail/view/888527/warnings-on-dbghelp-h
#include <dbghelp.h>
#pragma warning(pop)
#pragma comment(lib, "dbghelp.lib")
void
PrintStackTrace(FILE *f)
{
	HANDLE hSelf = GetCurrentProcess();

	const int nDepth = 99;
	void *lpvCallerStack[nDepth] = { NULL };
	if (!SymInitialize(hSelf, NULL, TRUE)) return;
	WORD wFrames = CaptureStackBackTrace(0, nDepth, lpvCallerStack, NULL);
	SYMBOL_INFOW *si = (SYMBOL_INFOW*)calloc(1, sizeof(SYMBOL_INFOW) + 256 * sizeof(WCHAR));
	if (!si) return;

	for (int i = 0; i < nDepth; ++i) {
		si->MaxNameLen = 255;
		si->SizeOfStruct = sizeof(SYMBOL_INFOW);
		if (SymFromAddrW(hSelf, (DWORD64)lpvCallerStack[i], 0, si)) {
			fwprintf(f, L"%02d: 0x%016I64X %ls - 0x%016I64X\n", i, (DWORD64)lpvCallerStack[i], si->Name ? si->Name : L"*UNKNOWN*", si->Address);
		}
	}

	free(si);
}
#else
#define PrintStackTrace(f)
#endif


LONG
WINAPI
TopLevelExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
	CONFIG_DATA *cd = GetConfigData();
	WCHAR szTleLog[MAX_PATH+1];
	wstrlprintf(szTleLog, sizeof(szTleLog), L"%ls%ls", cd->szLogDirectory, L"exception.log");
	FILE *f = _wfopen(szTleLog, L"a");
	if (f) {
		fprintf(f, "ExceptionCode: 0x%08X\n", pExceptionInfo->ExceptionRecord->ExceptionCode);
		fprintf(f, "ExceptionAddress: 0x%p\n", pExceptionInfo->ExceptionRecord->ExceptionAddress);
		PrintStackTrace(f);
		WCHAR szError[512];
		ApiGetDebugInfo(szError, sizeof(szError));
		fwprintf(f, L"%ls\n", szError);
		fflush(f);
		fclose(f);
	}

	return EXCEPTION_CONTINUE_SEARCH;
}


static
void
usage(const WCHAR *progname)
{
	const char *lpszArchitecture =
#if defined(_M_IX86)
		"x86";
#elif defined(_M_AMD64)
		"x64";
#else
		"Unknown";
#endif

	const char *lpszBuild =
#if defined(_DEBUG)
		"Debug";
#else
		"Release";
#endif

	fwprintf(stderr, L"ProcFilter (%hs %hs) %ls %hs %hs\n", lpszArchitecture, lpszBuild, PROCFILTER_VERSION, __DATE__, __TIME__);
	fwprintf(stderr, L"YARA Version %hs\n", YR_VERSION);
	int major = 0, minor = 0, revision = 0;
	git_libgit2_version(&major, &minor, &revision);
	fwprintf(stderr, L"libgit2 Version %d.%d.%d\n", major, minor, revision);
	fwprintf(stderr, L"\n");
	fwprintf(stderr, L"Usage: %ls -licenses\n", progname);
	fwprintf(stderr, L"Usage: %ls [-install|-install-delayed|-uninstall]\n", progname);
	fwprintf(stderr, L"Usage: %ls [-start|-stop]\n", progname);
#if defined(_DEBUG)
	fwprintf(stderr, L"Usage: %ls [-service|service-program-stop]\n", progname);
#endif
	fwprintf(stderr, L"Usage: %ls -filescan [rule file] <file>\n", progname);
	fwprintf(stderr, L"Usage: %ls -memoryscan [rule file] <pid>\n", progname);
	fwprintf(stderr, L"Usage: %ls -iset <section> <key> <value>\n", progname);
	fwprintf(stderr, L"Usage: %ls -iget <section> <key>\n", progname);
	fwprintf(stderr, L"Usage: %ls -compile [rule file]\n", progname);
	fwprintf(stderr, L"Usage: %ls -sha1 <file>\n", progname);
	fwprintf(stderr, L"Usage: %ls -quarantine-list\n", progname);
	fwprintf(stderr, L"Usage: %ls -quarantine <source>\n", progname);
	fwprintf(stderr, L"Usage: %ls -unquarantine <sha1> <destination>\n", progname);
	fwprintf(stderr, L"Usage: %ls -unquarantine-file <source> <destination>\n", progname);
	fwprintf(stderr, L"Usage: %ls -benchmark-timed <pool size> <duration> <target program> [args]\n", progname);
	fwprintf(stderr, L"Usage: %ls -benchmark-counted <num executions> <target program> [args]\n", progname);
	fwprintf(stderr, L"Usage: %ls -status\n", progname);
}


static
void
DoScan(WCHAR *lpszTarget, const WCHAR *lpszRuleFile, bool bFile)
{
	CONFIG_DATA *cd = GetConfigData();

	WCHAR szError[512] = { '\0' };

	YARASCAN_CONTEXT *ctx = NULL;
	if (lpszRuleFile) {
		wprintf(L"Rule File: %ls\n", lpszRuleFile);
		ctx = YarascanAlloc3(lpszRuleFile, szError, sizeof(szError));
		if (!ctx) {
			fwprintf(stderr, L"YARA Rule Error: %ls\n", szError);
		}
	} else {
		YARASCAN_INPUT_FILE yifInputFiles[2];
		ZeroMemory(yifInputFiles, sizeof(yifInputFiles));

		int i = 0;
		if (cd->bUseLocalRuleFile || cd->bUseRemoteRuleFile) {
			ctx = YarascanAllocDefault(szError, sizeof(szError), false, true);
			if (!ctx) fwprintf(stderr, L"Rule compilation failed: %ls\n", szError);
		} else {
			fwprintf(stderr, L"ProcFilter configuration does not specify a local or remote rules file\n");
		}
	}

	if (ctx) {
		if (lpszTarget) {
			wprintf(L"Target File: %ls\n", lpszTarget);
			SCAN_RESULT sr;
			if (bFile) {
				YarascanScanFile(ctx, lpszTarget, 0, NULL, NULL, NULL, &sr);
			} else {
				YarascanScanMemory(ctx, (DWORD)_wtoi(lpszTarget), NULL, NULL, NULL, &sr);
			}

			if (sr.bScanSuccessful) {
				wprintf(L"Matched Rules: %ls\n", sr.szMatchedRuleNames);
				wprintf(L"Block Rules: %ls\n", sr.szBlockRuleNames);
				wprintf(L"Log Rules: %ls\n", sr.szLogRuleNames);
				wprintf(L"Quarantine Rules: %ls\n", sr.szQuarantineRuleNames);
			} else {
				fwprintf(stderr, L"Scan Error: %ls\n", sr.szError);
			}
		} else {
			wprintf(L"Successfully compiled %ls\n", lpszRuleFile ? lpszRuleFile : L"default rules");
		}
	}
}


static
bool
TestArg(const WCHAR *lpszArgument, const WCHAR *lpszLongForm, const WCHAR *lpszShortForm)
{
	return (lpszLongForm && _wcsicmp(lpszArgument, lpszLongForm) == 0) || (lpszShortForm && _wcsicmp(lpszArgument, lpszShortForm) == 0);
}


bool
RunningAsProgram() {
	return g_bRunningAsProgram;
}


int
wmain(int argc, WCHAR *argv[])
{
	SetUnhandledExceptionFilter(TopLevelExceptionHandler);

	// Seed the prng
	DWORD dwRandSeed = GetTickCount();
	GetRandomData(&dwRandSeed, sizeof(dwRandSeed));
	srand(dwRandSeed);

	yr_initialize();
	git_libgit2_init();

	DieInit();
	LogInit();
	ConfigInit();
	CONFIG_DATA *cd = GetConfigData();

	if (argc > 1) {
		WCHAR *arg = argv[1];
		if (TestArg(arg, L"-install", L"-i")) {
			ProcFilterServiceStop();
			if (!ProcFilterServiceInstall(false)) printf("Unable to install service\n");
			if (!DriverInstall()) printf("Unable to install driver\n");
		} else if (TestArg(arg, L"-install-delayed", L"-id")) {
			ProcFilterServiceStop();
			if (!ProcFilterServiceInstall(true)) printf("Unable to install service\n");
			if (!DriverInstall()) printf("Unable to install driver\n");
		} else if (TestArg(arg, L"-uninstall", L"-u")) {
			if (!ProcFilterServiceStop()) printf("Unable to stop service\n");
			if (!ProcFilterServiceUninstall()) printf("Unable to uninstall service\n");
			if (!DriverUninstall()) printf("Unable to uninstall driver\n");
		} else if (TestArg(arg, L"-start", NULL)) {
			if (!ProcFilterServiceStart()) {
				printf("Unable to start service\n");
			}
		} else if (TestArg(arg, L"-stop", NULL)) {
			if (!ProcFilterServiceStop()) {
				printf("Unable to stop service\n");
			}
#if defined(_DEBUG)
		} else if (TestArg(arg, L"-service", L"-s")) {
			ServiceRunAsProgram();
		} else if (TestArg(arg, L"-service-program-stop", L"-sps")) {
			ServiceStopRunAsProgram();
#endif
		} else if (TestArg(arg, L"-filescan", L"-f")) {
			int i = argc > 3 ? 3 : 2;
			DoScan(argv[i], argc > 3 ? argv[2] : NULL, true);
		} else if (TestArg(arg, L"-iset", L"-is") && argc == 5) {
			WritePrivateProfileStringW(argv[2], argv[3], argv[4], cd->szConfigFile);
			wprintf(L"%ls:%ls=%ls\n", argv[2], argv[3], argv[4]);
		} else if (TestArg(arg, L"-iget", L"-ig") && argc == 4) {
			WCHAR szResult[512] = { '\0' };
			GetPrivateProfileStringW(argv[2], argv[3], L"", szResult, _countof(szResult)-1, cd->szConfigFile);
			wprintf(L"%ls:%ls=%ls\n", argv[2], argv[3], szResult);
		} else if (TestArg(arg, L"-memoryscan", L"-m")) {
			int i = argc > 3 ? 3 : 2;
			DoScan(argv[i], argc > 3 ? argv[2] : NULL, false);
		} else if (TestArg(arg, L"-compile", L"-c")) {
			DoScan(NULL, argc > 2 ? argv[2] : NULL, false);
		} else if (TestArg(arg, L"-sha1", L"-s1")) {
			char hexdigest[41];
			if (argc > 2) {
				for (int i = 2; i < argc; ++i) {
					if (Sha1File(argv[i], hexdigest, NULL)) {
						printf("%hs: %ls\n", hexdigest, argv[i]);
					} else {
						fprintf(stderr, "Unable to hash file: %ls\n", argv[i]);
					}
				}
			}
		} else if (TestArg(arg, L"-quarantine-list", L"-ql")) {
			QuarantineList();
		} else if (TestArg(arg, L"-quarantine", L"-q") && argc == 3) {
			char szHexDigest[SHA1_HEXDIGEST_LENGTH + 1] = { '\0' };
			if (QuarantineFile(argv[2], cd->szQuarantineDirectory, 0, NULL, NULL, szHexDigest)) {
				fprintf(stdout, "%hs\n", szHexDigest);
			} else {
				fwprintf(stderr, L"Unable to quarantine file: %ls\n", argv[2]);
			}
		} else if (TestArg(arg, L"-unquarantine", L"-uq") && argc == 4) {
			WCHAR szError[256];
			WCHAR szSourceFile[MAX_PATH+1];
			wstrlprintf(szSourceFile, sizeof(szSourceFile), L"%ls%ls", cd->szQuarantineDirectory, argv[2]);
			if (!UnquarantineFile(szSourceFile, argv[3], szError, sizeof(szError))) {
				fprintf(stderr, "Error: %ls\n", szError);
			}
		} else if (TestArg(arg, L"-unquarantine-file", L"-uqf") && argc == 4) {
			WCHAR szError[256];
			if (!UnquarantineFile(argv[2], argv[3], szError, sizeof(szError))) {
				fprintf(stderr, "Error: %ls\n", szError);
			}
		} else if (TestArg(arg, L"-benchmark-counted", L"-bu") && BenchmarkCounted(argc, argv) == 0) {
			// do nothing; if BenchmarkCounted() fails usage is displayed
		}  else if (TestArg(arg, L"-benchmark-timed", L"-bl") && BenchmarkTimed(argc, argv) == 0) {
			// do nothing; if BenchmarkTimed() fails usage is displayed
		} else if (TestArg(arg, L"-status", L"-st")) {
			StatusQuery();
		} else if (TestArg(arg, L"-licenses", L"-l")) {
			DisplayLicenses();
		} else {
			usage(argv[0]);
		}
	} else {
		if (!ServiceRunAsService()) {
			usage(argv[0]);
		}
	}

	ConfigDestroy();
	LogShutdown();
	DieShutdown();

	git_libgit2_shutdown();
	yr_finalize();

	return 0;
}
