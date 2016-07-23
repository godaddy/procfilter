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
#include "procfilter/procfilter.h"

#include <set>
#include <string>

typedef std::set<std::string> StringSet_t;

typedef struct match_data SCAN_DATA;
struct match_data {
	StringSet_t *lpSet;
};


DWORD
ProcFilterEvent(PROCFILTER_EVENT *e)
{
	DWORD dwResultFlags = PROCFILTER_RESULT_NONE;
	SCAN_DATA *sd = (SCAN_DATA*)e->lpvScanData;

	if (e->dwEventId == PROCFILTER_EVENT_INIT) {
		e->RegisterPlugin(PROCFILTER_VERSION, L"LaunchCommandPlugin", 0, sizeof(SCAN_DATA), false,
			PROCFILTER_EVENT_YARA_SCAN_INIT, PROCFILTER_EVENT_YARA_SCAN_COMPLETE, PROCFILTER_EVENT_YARA_RULE_MATCH_META_TAG,
			PROCFILTER_EVENT_YARA_RULE_MATCH, PROCFILTER_EVENT_YARA_SCAN_CLEANUP, PROCFILTER_EVENT_NONE);
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_SCAN_INIT) {
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_RULE_MATCH_META_TAG) {
		if (_stricmp(e->lpszMetaTagName, "LaunchCommand") == 0 && e->lpszStringValue) {
			if (!sd->lpSet) sd->lpSet = new StringSet_t;
			sd->lpSet->insert(e->lpszStringValue);
		}
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_SCAN_COMPLETE && sd->lpSet) {
		for (auto &v : *sd->lpSet) { 
			WinExec(v.c_str(), SW_SHOW);
		}
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_SCAN_CLEANUP) {
		delete sd->lpSet;
	}

	return dwResultFlags;
}
