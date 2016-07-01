
#include <vector>
#include <string>
#include <regex>

#include "procfilter/procfilter.h"

using std::wstring;
using std::wregex;


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
static RegexVector g_WhitelistRegexes;
static RegexVector g_WhitelistExceptionRegexes;
static bool g_bWhiteListAllFiles = false;


//
// Load the configuration file from disk
//
static
void
LoadConfigRegexList(PROCFILTER_EVENT *e, RegexVector &c, const wstring &key_base)
{
	// search sequentially through numbered keys key{1,2,...} until an empty/nonexistent key is found
	for (size_t i = 1; 1; ++i) {
		wstring key = key_base + std::to_wstring(i);
		WCHAR value[4096];
		e->GetConfigString(key.c_str(), L"", value, sizeof(value));
		if (wcslen(value) == 0) break;
		
		// key content found -- convert it to an nt path and then to a regex
		wstring expr;
		WCHAR szNtPath[4096];
		WCHAR szDosDevice[MAX_PATH+1];
		if (e->GetNtPathName(value, szDosDevice, sizeof(szDosDevice), szNtPath, sizeof(szNtPath), NULL, 0)) {
			wstring wsDosDevice{szDosDevice};
			size_t pos = 0;
			while ((pos = wsDosDevice.find(L"\\", pos)) != wstring::npos) {
				wsDosDevice.replace(pos, 1, L"\\\\");
				pos += 2;
			}
			expr = wstring{LR"(\\\\\?\\GLOBALROOT)"} + wsDosDevice + szNtPath;
		} else {
			expr = value;
		}
		
		// add the regex to the container or exit the program if compilation failed
		try {
			c.push_back(RegexData(expr));
		} catch (std::regex_error &error) {
			e->Die("Regex compilation failure for value %ls: %ls\n%hs", key.c_str(), expr.c_str(), error.what());
		}
	}
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


DWORD
ProcFilterEvent(PROCFILTER_EVENT *e)
{
	DWORD dwResultFlags = PROCFILTER_RESULT_NONE;

	if (e->dwEventId == PROCFILTER_EVENT_INIT) {
		// register with the core
		e->RegisterPlugin(PROCFILTER_VERSION, L"FileNames", 0, 0, false,
			PROCFILTER_EVENT_YARA_SCAN_INIT, PROCFILTER_EVENT_NONE);
		
		// treat all files as whitelisted by default?
		g_bWhiteListAllFiles = e->GetConfigInt(L"WhiteListAllFiles", 0) != 0;
		try {
			// load the whitelisted regexes and the exceptions to that list
			LoadConfigRegexList(e, g_WhitelistRegexes, L"WhiteListRegex");
			LoadConfigRegexList(e, g_WhitelistExceptionRegexes, L"WhiteListExceptionRegex");
		} catch (std::exception &ex) {
			e->Die("%hs", ex.what());
		}
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_SCAN_INIT) {
		if (e->dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_CREATE || e->dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_TERMINATE) {
			bool bWhitelisted = g_bWhiteListAllFiles || StringMatchesRegexInContainer(g_WhitelistRegexes, e->lpszFileName);

			if (bWhitelisted) {
				bool bInExceptionList = StringMatchesRegexInContainer(g_WhitelistExceptionRegexes, e->lpszFileName);

				if (!bInExceptionList) {
					dwResultFlags |= PROCFILTER_RESULT_DONT_SCAN;
				}
			}
		}
	}

	return dwResultFlags;
}
