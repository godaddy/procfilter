
#define _CRT_SECURE_NO_WARNINGS

#include "procfilter/procfilter.h"

#include <array>
#include <map>
#include <fstream>
#include <string>
#include <algorithm>
#include <cctype>
#include <set>
#include <regex>
#include <vector>

using std::wregex;
using std::string;
using std::wstring;
using std::ifstream;
using std::set;

typedef std::basic_string<BYTE> Hash;

class RegexData {
public:
	RegexData(const wstring &regexString) :
		regexString(regexString),
		regexObject(regexString, wregex::icase)
	{
	}

	//
	// Determinte if the given string matches the object's associated regex
	//
	bool matchesString(const wstring &str) const {
		return std::regex_search(str, regexObject);
	}

	const wstring regexString;
	const wregex regexObject;
};
typedef std::vector<RegexData> RegexVector;

typedef struct process_data PROCESS_DATA;
struct process_data {
	bool bWhitelisted;
};

static RegexVector g_WhitelistRegexes;
static RegexVector g_BlacklistRegexes;

static set<Hash> g_WhitelistHashes;
static set<Hash> g_BlacklistHashes;

static CRITICAL_SECTION g_cs;
static set<DWORD> g_WhitelistedPids;

static bool g_HashExes = true;
static bool g_LogRemoteThreads = false;
static bool g_HashDlls = false;

static WCHAR g_szCommandLineRuleFileBaseName[MAX_PATH + 1] = { '\0' };
static __declspec(thread) YARASCAN_CONTEXT *tg_CommandLineRulesContext = NULL;


//
// WhitelistFilename=whitelist.txt
// BlacklistFilename=blacklist.txt
//
// CommandLineRules=commandline.yara
//
// QuarantineMatches = 1
//
// LogRemoteThreads = 0
//

static
void
LoadCommandLineRules(PROCFILTER_EVENT *e)
{
	if (wcslen(g_szCommandLineRuleFileBaseName) > 0) {
		WCHAR szError[256] = { '\0' };
		tg_CommandLineRulesContext = e->AllocateScanContextLocalAndRemote(g_szCommandLineRuleFileBaseName, szError, sizeof(szError), true);
		if (!tg_CommandLineRulesContext) {
			e->LogFmt("Error compiling rules file %ls: %ls", g_szCommandLineRuleFileBaseName, szError);
		}
	}
}


static
void
LoadRegex(PROCFILTER_EVENT *e, RegexVector &rec, const char *value, size_t value_sz) {
	std::string value_s{ value, value_sz };
	wstring expr;
	expr.assign(value_s.begin(), value_s.end());

	// Try to conver the value to a DOS path
	WCHAR szNtPath[4096];
	WCHAR szDosDevice[MAX_PATH + 1];
	if (e->GetNtPathName(expr.c_str(), szDosDevice, sizeof(szDosDevice), szNtPath, sizeof(szNtPath), NULL, 0)) {
		wstring wsDosDevice{ szDosDevice };
		size_t pos = 0;
		while ((pos = wsDosDevice.find(L"\\", pos)) != wstring::npos) {
			wsDosDevice.replace(pos, 1, L"\\\\");
			pos += 2;
		}
		expr = wstring{ LR"(\\\\\?\\GLOBALROOT)" } + wsDosDevice + szNtPath;
	}

	// Add the regex to the container
	try {
		rec.push_back(RegexData(expr));
	} catch (std::regex_error &error) {
		e->LogFmt("Regex compilation failure for value: %s\nError: %s", value, error.what());
	}
}


static
bool
LoadHashfile(PROCFILTER_EVENT *e, set<Hash> &c, RegexVector &rec, size_t &nhashes, const WCHAR *lpszFileName)
{
	bool rv = false;
	nhashes = 0;

	ifstream infile(lpszFileName);
	if (infile.fail()) {
		return false;
	}

	size_t linenum = 0;
	string line;
	while (std::getline(infile, line)) {
		++linenum;

		// Ignore comment lines
		if (line.length() == 0) continue;

		// File regexes
		if (_strnicmp(line.c_str(), "filename:", 9) == 0) {
			// Process the filename regex
			const char *re = &line[9];

			// Skip whitespace
			while (*re != 0 && isspace(*re)) ++re;
			if (*re == 0) continue;

			// Skip trailing whitespace
			size_t len = strlen(re);
			while (len > 0 && isspace(re[len-1])) {
				len -= 1;
			}

			if (len > 0) {
				LoadRegex(e, rec, re, len);
			}
			continue;
		}

		if (line[0] == '#' || line[0] == ';') continue;

		// Erase commentted portion of lines
		auto comment = line.find_first_of('#');
		if (comment != string::npos) line.erase(comment);
		comment = line.find_first_of(';');
		if (comment != string::npos) line.erase(comment);

		// Clear whitespace
		auto space_begin = std::remove_if(line.begin(), line.end(), [](char c) { return std::isspace(c); });
		line.erase(space_begin, line.end());

		if (line.length() == 0) continue;

		// MD5, SHA1, SHA256
		Hash baRawDigest;
		bool bHashValidLength = line.length() == 32 || line.length() == 40 || line.length() == 64;
		bool bParseSuccess = true;
		if (bHashValidLength) {
			size_t digest_length = line.length() / 2;

			baRawDigest.reserve(digest_length);
			for (size_t i = 0; i < digest_length; ++i) {
				int value = 0;
				if (sscanf(&line.c_str()[i*2], "%2x", &value) == 1) {
					baRawDigest.push_back(value & 0xFF);
				} else {
					bParseSuccess = false;
					break;
				}
			}
		}

		if (bHashValidLength && bParseSuccess) {
			c.insert(baRawDigest);
			nhashes += 1;
		} else {
			e->LogFmt("Invalid hash in %ls on line %zu", lpszFileName, linenum);
		}
	}

	return true;
}


static
bool
HashInSet(PROCFILTER_EVENT *e, const set<Hash> &c, const void *hash, size_t hash_size)
{
	Hash value{ (BYTE*)hash, hash_size };
	return c.find(value) != c.end();
}


static
bool
HashesInSet(PROCFILTER_EVENT *e, const set<Hash> &c, const HASHES *hashes)
{
	bool bResult = HashInSet(e, c, hashes->md5_digest, MD5_DIGEST_SIZE);
	if (!bResult) bResult = HashInSet(e, c, hashes->sha1_digest, SHA1_DIGEST_SIZE);
	if (!bResult) bResult = HashInSet(e, c, hashes->sha256_digest, SHA256_DIGEST_SIZE);
	return bResult;
}


//
// Determine if the given string matches a regex in the container
//
static
bool
StringMatchesRegexInContainer(const RegexVector &c, const wstring &str)
{
	for (const auto &re : c) {
		if (re.matchesString(str)) {
			return true;
		}
	}

	return false;
}


//
// Store the command line associated with the current process into the SCAN_DATA structure.
//
WCHAR*
GetCommandLine(PROCFILTER_EVENT *e)
{
	// read the processes PEB and it's Parameters structure
	WCHAR *lpszResult = NULL;
	PEB Peb;
	RTL_USER_PROCESS_PARAMETERS Parameters;
	if (e->ReadProcessPeb(&Peb) && e->ReadProcessMemory(Peb.ProcessParameters, &Parameters, sizeof(Parameters))) {
		// check to make sure the command line is present
		DWORD len = Parameters.CommandLine.Length;
		if (len > 0) {
			// allocate memory for the command line and then copy it out from the remote process
			lpszResult = (WCHAR*)e->AllocateMemory(len + 1, sizeof(WCHAR));
			if (lpszResult && e->ReadProcessMemory(Parameters.CommandLine.Buffer, lpszResult, len)) {
				lpszResult[len] = '\0';
			}
			else if (lpszResult) {
				e->FreeMemory(lpszResult);
				lpszResult = NULL;
			}
		}
	}

	return lpszResult;
}

void
LoadHashFileFromBasename(PROCFILTER_EVENT *e, set<Hash> &c, RegexVector &rec, const WCHAR *szBasename)
{
	WCHAR szFullPath[MAX_PATH + 1];

	e->GetProcFilterPath(szFullPath, sizeof(szFullPath), L"localrules", szBasename);
	size_t nhashes = 0;
	if (LoadHashfile(e, c, rec, nhashes, szFullPath)) e->LogFmt("Loaded %zu hashes from %ls", nhashes, szFullPath);

	e->GetProcFilterPath(szFullPath, sizeof(szFullPath), L"remoterules", szBasename);
	nhashes = 0;
	if (LoadHashfile(e, c, rec, nhashes, szFullPath)) e->LogFmt("Loaded %zu hashes from %ls", nhashes, szFullPath);
}


DWORD
ProcFilterEvent(PROCFILTER_EVENT *e)
{
	DWORD dwResultFlags = PROCFILTER_RESULT_NONE;

	if (e->dwEventId == PROCFILTER_EVENT_INIT) {
		e->RegisterPlugin(PROCFILTER_VERSION, L"Core", 0, 0, false, PROCFILTER_EVENT_PROCESS_CREATE, PROCFILTER_EVENT_NONE);

		InitializeCriticalSection(&g_cs);

		e->GetConfigString(L"CommandLineRules", L"", g_szCommandLineRuleFileBaseName, sizeof(g_szCommandLineRuleFileBaseName));

		g_HashDlls = e->GetConfigBool(L"HashDlls", g_HashDlls);
		if (g_HashDlls) e->EnableEvent(PROCFILTER_EVENT_IMAGE_LOAD);

		g_LogRemoteThreads = e->GetConfigBool(L"LogRemoteThreads", g_LogRemoteThreads);
		if (g_LogRemoteThreads) e->EnableEvent(PROCFILTER_EVENT_THREAD_CREATE);

		WCHAR szListBasename[MAX_PATH + 1];
		e->GetConfigString(L"WhitelistFilename", L"whitelist.txt", szListBasename, sizeof(szListBasename));
		if (szListBasename[0]) LoadHashFileFromBasename(e, g_WhitelistHashes, g_WhitelistRegexes, szListBasename);

		e->GetConfigString(L"BlacklistFilename", L"blacklist.txt", szListBasename, sizeof(szListBasename));
		if (szListBasename[0]) LoadHashFileFromBasename(e, g_BlacklistHashes, g_BlacklistRegexes, szListBasename);

		g_HashExes = e->GetConfigBool(L"HashExes", g_HashExes);
	} else if (e->dwEventId == PROCFILTER_EVENT_SHUTDOWN) {
		DeleteCriticalSection(&g_cs);
	} else if (e->dwEventId == PROCFILTER_EVENT_PROCFILTER_THREAD_INIT) {
		LoadCommandLineRules(e);
	} else if (e->dwEventId == PROCFILTER_EVENT_PROCFILTER_THREAD_SHUTDOWN) {
		if (tg_CommandLineRulesContext) e->FreeScanContext(tg_CommandLineRulesContext);
	} else if (e->dwEventId == PROCFILTER_EVENT_PROCESS_CREATE && e->lpszFileName) {
		// Ignore whitelisted files
		bool bFilenameWhitelisted = StringMatchesRegexInContainer(g_WhitelistRegexes, e->lpszFileName);
		if (bFilenameWhitelisted) {
			EnterCriticalSection(&g_cs);
			g_WhitelistedPids.insert(e->dwProcessId);
			LeaveCriticalSection(&g_cs);
			return PROCFILTER_RESULT_DONT_SCAN;
		}

		// Filename blacklisted?
		bool bFilenameBlacklisted = StringMatchesRegexInContainer(g_BlacklistRegexes, e->lpszFileName);

		HASHES hashes;
		ZeroMemory(&hashes, sizeof(HASHES));

		bool bHashBlacklisted = false;
		bool bHashWhitelisted = false;
		if (g_HashExes) {
			e->HashFile(e->lpszFileName, &hashes);

			bHashWhitelisted = HashesInSet(e, g_WhitelistHashes, &hashes);
			if (bHashWhitelisted) {
				EnterCriticalSection(&g_cs);
				g_WhitelistedPids.insert(e->dwProcessId);
				LeaveCriticalSection(&g_cs);
				return PROCFILTER_RESULT_DONT_SCAN;
			}

			// Check if the hash is blocked
			bHashBlacklisted = HashesInSet(e, g_BlacklistHashes, &hashes);
		}

		//
		// Scan command lines (Two since there's UNICODE & ASCII)
		//
		SCAN_RESULT srAsciiResult;
		SCAN_RESULT srUnicodeResult;
		ZeroMemory(&srAsciiResult, sizeof(SCAN_RESULT));
		ZeroMemory(&srUnicodeResult, sizeof(SCAN_RESULT));
		const WCHAR *lpszCommandLine = e->GetProcessCommandLine();
		if (lpszCommandLine) {
			if (tg_CommandLineRulesContext) {
				const DWORD dwCommandLineCharCount = (DWORD)wcslen(lpszCommandLine);

				// Scan the UNICODE command line and log the result
				e->ScanData(tg_CommandLineRulesContext, lpszCommandLine, dwCommandLineCharCount * sizeof(WCHAR) + sizeof(WCHAR), NULL, NULL, NULL, &srUnicodeResult);

				// For convenience also scan with ASCII
				char *lpszAsciiCommandLine = (char*)e->AllocateMemory(dwCommandLineCharCount + 1, sizeof(char));
				if (lpszAsciiCommandLine) {
					snprintf(lpszAsciiCommandLine, dwCommandLineCharCount + 1, "%ls", lpszCommandLine);
					lpszAsciiCommandLine[dwCommandLineCharCount] = '\0';

					// Scan the ASCII command line
					e->ScanData(tg_CommandLineRulesContext, lpszAsciiCommandLine, dwCommandLineCharCount + 1, NULL, NULL, NULL, &srAsciiResult);

					// Cleanup
					e->FreeMemory(lpszAsciiCommandLine);
				}
			}
		} else {
			lpszCommandLine = L"";
		}

		bool bBlockProcess = !bHashWhitelisted && !bFilenameWhitelisted &&
			(bHashBlacklisted || bFilenameBlacklisted ||
				(srUnicodeResult.bScanSuccessful && srUnicodeResult.bBlock) ||
				(srAsciiResult.bScanSuccessful && srAsciiResult.bBlock)
				);
	
		bool bQuarantine = bBlockProcess || (srAsciiResult.bScanSuccessful && srAsciiResult.bQuarantine) || (srUnicodeResult.bScanSuccessful && srUnicodeResult.bQuarantine);

		// Get parent name
		WCHAR szParentName[MAX_PATH + 1];
		if (!e->GetProcessFileName(e->dwParentProcessId, szParentName, sizeof(szParentName))) {
			szParentName[0] = 0;
		}

		bool bLog = true;
		void (*LogFn)(const char *, ...) = bBlockProcess ? e->LogCriticalFmt : e->LogFmt;
		if (bLog) {
			LogFn(
				"\n" \
				"EventType:ProcessCreate\n" \
				"Process:%ls\n" \
				"PID:%u\n" \
				"MD5:%s\n" \
				"SHA1:%s\n" \
				"SHA256:%s\n" \
				"CommandLine:%ls\n" \
				"CommandLineAsciiRuleBlock:%ls\n" \
				"CommandLineUnicodeRuleBlock:%ls\n" \
				"ParentPID:%u\n" \
				"ParentName:%ls\n" \
				"HashBlacklisted:%s\n" \
				"FilenameBlacklisted:%s\n" \
				"Quarantine:%s\n" \
				"Block:%s\n" \
				"",
				e->lpszFileName,
				e->dwProcessId,
				hashes.md5_hexdigest,
				hashes.sha1_hexdigest,
				hashes.sha256_hexdigest,
				lpszCommandLine,
				tg_CommandLineRulesContext ? (srAsciiResult.bScanSuccessful ? srAsciiResult.szBlockRuleNames : L"*FAILED*") : L"*SKIPPED*",
				tg_CommandLineRulesContext ? (srUnicodeResult.bScanSuccessful ? srUnicodeResult.szBlockRuleNames : L"*FAILED*") : L"*SKIPPED*",
				e->dwParentProcessId,
				szParentName,
				bHashBlacklisted ? "Yes" : "No",
				bFilenameBlacklisted ? "Yes" : "No",
				bQuarantine ? "Yes" : "No",
				bBlockProcess ? "Yes" : "No"
				);
		}

		if (bQuarantine) e->QuarantineFile(e->lpszFileName, NULL, 0);

		if (bBlockProcess) {
			dwResultFlags = PROCFILTER_RESULT_BLOCK_PROCESS;
		}
	} else if (e->dwEventId == PROCFILTER_EVENT_PROCESS_TERMINATE) {
		EnterCriticalSection(&g_cs);
		auto iter = g_WhitelistedPids.find(e->dwProcessId);
		if (iter != g_WhitelistedPids.end()) g_WhitelistedPids.erase(iter);
		LeaveCriticalSection(&g_cs);
	} else if (e->dwEventId == PROCFILTER_EVENT_THREAD_CREATE) {
		if (g_LogRemoteThreads) {
			if (e->dwParentProcessId != e->dwProcessId) {
				// Skip whitelisted parents
				EnterCriticalSection(&g_cs);
				auto iter = g_WhitelistedPids.find(e->dwProcessId);
				bool bWhitelisted = iter != g_WhitelistedPids.end();
				LeaveCriticalSection(&g_cs);
				if (bWhitelisted) return PROCFILTER_RESULT_NONE;

				// Restrict remote thread interruption to only unprivileged threads since suspending/blocking
				// some system threads can lead to blue screens.
				HANDLE hNewPid = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, e->dwProcessId);
				bool bIsElevated = false;
				// On the other hand we aren't blocking here and the response time should be "fast" enough to where it doesn't matter
				//if (hNewPid && e->IsElevated(hNewPid, &bIsElevated) && !bIsElevated) {
				if (hNewPid) {
					WCHAR szSource[MAX_PATH + 1];
					WCHAR szTarget[MAX_PATH + 1];

					ULONG64 ulProcessTime = 0;
					FILETIME ftUnused;
					FILETIME ftUserTime;

					// Make sure this is not the first thread in the process
					if (GetProcessTimes(hNewPid, &ftUnused, &ftUnused, &ftUnused, &ftUserTime) && (ftUserTime.dwHighDateTime > 0 || ftUserTime.dwLowDateTime > 0)) {
						if (e->GetProcessFileName(e->dwParentProcessId, szSource, sizeof(szSource)) && e->GetProcessFileName(e->dwProcessId, szTarget, sizeof(szTarget))) {
							const WCHAR *lpszSourceBaseName = e->GetProcessBaseNamePointer(szSource);
							const WCHAR *lpszTargetBaseName = e->GetProcessBaseNamePointer(szTarget);

							e->LogWarningFmt(
								"\n" \
								"EventType:RemoteThreadCreate\n" \
								"ThreadID:%u\n" \
								"SourceBasename:%ls\n" \
								"Source:%ls\n" \
								"SourcePID:%u\n" \
								"TargetBasename:%ls\n"
								"Target:%ls\n" \
								"TargetPID:%u\n" \
								"",
								e->dwThreadId,
								lpszSourceBaseName,
								szSource,
								e->dwParentProcessId,
								lpszTargetBaseName,
								szTarget,
								e->dwProcessId
								);
						}
					}

					CloseHandle(hNewPid);
				}
			}
		}
	} else if (e->dwEventId == PROCFILTER_EVENT_IMAGE_LOAD) {
		if (g_HashDlls && e->lpszFileName) {

			// Don't hash DLL loads for whitelisted processes
			EnterCriticalSection(&g_cs);
			auto iter = g_WhitelistedPids.find(e->dwProcessId);
			bool bWhitelisted = iter != g_WhitelistedPids.end();
			LeaveCriticalSection(&g_cs);
			if (bWhitelisted) return PROCFILTER_RESULT_NONE;

			// Filename whitelisted?
			bool bFilenameWhitelisted = StringMatchesRegexInContainer(g_WhitelistRegexes, e->lpszFileName);
			if (bFilenameWhitelisted) return PROCFILTER_RESULT_NONE;

			// Filename blacklisted?
			bool bFilenameBlacklisted = StringMatchesRegexInContainer(g_BlacklistRegexes, e->lpszFileName);

			// Filename whitelisted?
			HASHES hashes;
			e->HashFile(e->lpszFileName, &hashes);
			if (HashesInSet(e, g_WhitelistHashes, &hashes)) return PROCFILTER_RESULT_NONE;

			// Filename blacklisted
			bool bHashBlacklisted = HashesInSet(e, g_BlacklistHashes, &hashes);
			bool bBlock = bHashBlacklisted || bFilenameBlacklisted;

			bool bQuarantine = bBlock;

			WCHAR szProcessName[MAX_PATH + 1];
			e->GetProcessFileName(e->dwProcessId, szProcessName, sizeof(szProcessName));

			void(*LogFn)(const char *, ...) = bBlock ? e->LogCriticalFmt : e->LogFmt;
			bool bLog = true;
			if (bLog) {
				LogFn(
				"\n" \
				"EventType:DllLoad\n" \
				"ProcessName:%ls\n" \
				"DllName:%ls\n" \
				"PID:%u\n" \
				"MD5:%s\n" \
				"SHA1:%s\n" \
				"SHA256:%s\n" \
				"HashBlacklisted:%s\n" \
				"FilenameBlacklisted:%s\n" \
				"Quarantine:%s\n" \
				"Blocked:%s\n" \
				"",
				szProcessName,
				e->lpszFileName,
				e->dwProcessId,
				hashes.md5_hexdigest,
				hashes.sha1_hexdigest,
				hashes.sha256_hexdigest,
				bHashBlacklisted ? "Yes" : "No",
				bFilenameBlacklisted ? "Yes" : "No",
				bQuarantine ? "Yes" : "No",
				bBlock ? "Yes" : "No"
				);
			}

			if (bQuarantine) e->QuarantineFile(e->lpszFileName, NULL, 0);

			if (bBlock) {
				dwResultFlags = PROCFILTER_RESULT_BLOCK_PROCESS;
			}
		}
	}

	return dwResultFlags;
}
