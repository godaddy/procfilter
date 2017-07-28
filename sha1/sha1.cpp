
#define _CRT_SECURE_NO_WARNINGS

#include "procfilter/procfilter.h"

#include <array>
#include <map>
#include <fstream>
#include <string>
#include <algorithm>
#include <cctype>
#include <set>

using std::string;
using std::wstring;
using std::ifstream;
using std::set;

typedef std::basic_string<BYTE> Hash;

static CRITICAL_SECTION g_CriticalSection;
static WCHAR g_WhitelistFile[MAX_PATH+1];
static WCHAR g_BlacklistFile[MAX_PATH+1];
static set<Hash> g_WhitelistHashes;
static set<Hash> g_BlacklistHashes;
static std::map<Hash,wstring> g_WhitelistAdditions;

#define MODE_BUILD_WHITELIST 0
#define MODE_CHECK_WHITELIST 1

static int g_RunningMode = MODE_BUILD_WHITELIST;
static bool g_bBlockFilesNotWhitelisted = false;


static
bool
LoadHashfile(PROCFILTER_EVENT *e, set<Hash> &c, const WCHAR *lpszFileName)
{
	using std::getline;

	bool rv = false;

	ifstream infile(lpszFileName);
	if (infile.fail()) {
		using std::ofstream;
		ofstream outfile(lpszFileName, ofstream::ate);
		if (!outfile) return false;
		outfile.close();

		infile = ifstream(lpszFileName);
		if (infile.fail()) return false;
	}

	string line;
	while (getline(infile, line)) {
		BYTE baRawDigest[20];
		auto space_begin = std::remove_if(line.begin(), line.end(), [](char c){ return std::isspace(c); });
		line.erase(space_begin, line.end());
		if (line.length() >= 40) {
			bool bSuccess = true;
			for (size_t i = 0; i < 20; ++i) {
				int value = 0;
				if (sscanf(&line.c_str()[i*2], "%2x", &value) == 1) {
					baRawDigest[i] = value & 0xFF;
				} else {
					bSuccess = false;
				}
			}
			if (bSuccess) {
				c.insert(Hash(baRawDigest));
			}
		}
	}

	return true;
}


static
void
SaveWhitelist(PROCFILTER_EVENT *e, const WCHAR *lpszFileName)
{
	FILE *f = _wfopen(lpszFileName, L"a");
	if (f) {
		for (auto &v : g_WhitelistAdditions) {
			char szDigest[41] = { '\0' };

			for (size_t i = 0; i < 20; ++i) {
				static const char *hex = "0123456789ABCDEF";
				BYTE b = v.first[i];
				szDigest[i*2] = hex[b >> 4];
				szDigest[i*2+1] = hex[b & 0x0F];
			}

			fprintf(f, "%hs # %ls\n", szDigest, v.second.c_str());
		}
		fclose(f);
	} else {
		e->LogFmt("Unable to open \"%ls\" for writing", lpszFileName);
	}
}


static
bool
Sha1InSet(PROCFILTER_EVENT *e, const set<Hash> &c, const Hash &hash)
{
	return c.find(hash) != c.end();
}


DWORD
ProcFilterEvent(PROCFILTER_EVENT *e)
{
	DWORD dwResultFlags = PROCFILTER_RESULT_NONE;

	if (e->dwEventId == PROCFILTER_EVENT_INIT) {
		e->RegisterPlugin(PROCFILTER_VERSION, L"Sha1", 0, 0, false,
			PROCFILTER_EVENT_PROCESS_CREATE, PROCFILTER_EVENT_NONE);
		InitializeCriticalSection(&g_CriticalSection);
		g_RunningMode = e->GetConfigBool(L"BuildWhitelist", false) ? MODE_BUILD_WHITELIST : MODE_CHECK_WHITELIST;
		g_bBlockFilesNotWhitelisted = e->GetConfigBool(L"BlockFilesNotWhitelisted", false);
		e->GetProcFilterPath(g_WhitelistFile, sizeof(g_WhitelistFile), NULL, L"whitelist.txt");
		if (g_RunningMode == MODE_CHECK_WHITELIST && !LoadHashfile(e, g_WhitelistHashes, g_WhitelistFile)) e->Die("Unable to load whitelist");
	} else if (e->dwEventId == PROCFILTER_EVENT_SHUTDOWN) {
		if (g_RunningMode == MODE_BUILD_WHITELIST) {
			SaveWhitelist(e, g_WhitelistFile);
		}
		DeleteCriticalSection(&g_CriticalSection);
	} else if (e->dwEventId == PROCFILTER_EVENT_PROCESS_CREATE && e->lpszFileName) {
		HASHES hashes;
		bool bFileHashed = e->HashFile(e->lpszFileName, &hashes);
		if (g_RunningMode == MODE_BUILD_WHITELIST) {
			if (bFileHashed && !Sha1InSet(e, g_WhitelistHashes, Hash(hashes.sha1_digest, 20))) {
				EnterCriticalSection(&g_CriticalSection);
				g_WhitelistAdditions.insert(std::make_pair(Hash(hashes.sha1_digest, 20), wstring(e->lpszFileName)));
				LeaveCriticalSection(&g_CriticalSection);
			}
		} else if (g_RunningMode == MODE_CHECK_WHITELIST) {
			bool bSha1Whitelisted = false;
			if (bFileHashed) bSha1Whitelisted = Sha1InSet(e, g_WhitelistHashes, Hash(hashes.sha1_digest, 20));

			if (g_bBlockFilesNotWhitelisted) {
				if (!bFileHashed || !bSha1Whitelisted) {
					dwResultFlags |= PROCFILTER_RESULT_BLOCK_PROCESS;
				}
			} else {
				if (bSha1Whitelisted) dwResultFlags |= PROCFILTER_RESULT_DONT_SCAN;
			}
		}
	}

	return dwResultFlags;
}
