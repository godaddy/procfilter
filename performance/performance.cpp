
#include <map>
#include <vector>
#include <algorithm>
#include <numeric>

#define NOMINMAX
#include "procfilter/procfilter.h"


typedef std::map<DWORD, LARGE_INTEGER> PidMap_t;
typedef std::vector<double> DoubleVector_t;

static DWORD g_dwNumScanned = 0;
static double g_dPerformanceFrequency;
static PidMap_t g_CreationScans;
static PidMap_t g_TerminationScans;
static DoubleVector_t g_CreationScanDurations;
static DoubleVector_t g_TerminationScanDurations;
static DWORD g_dwFlushSize = 10000;


static inline
double
GetDuration(const LARGE_INTEGER *start, const LARGE_INTEGER *end)
{
	return ((double)(end->QuadPart - start->QuadPart)) / g_dPerformanceFrequency;
}


static
void
FlushStats(PROCFILTER_EVENT *e, const char *lpszTitle, DoubleVector_t &c)
{
	size_t n = c.size();
	if (n == 0) return;

	auto minmax = std::minmax_element(c.begin(), c.end());
	double avg = std::accumulate(c.begin(), c.end(), 0.0) / n;

	e->LogFmt("Performance Data:\n\n=== %s ===\nNum: %u\nMin: %f\nMax: %f\nAvg: %f",
		lpszTitle, n, *minmax.first, *minmax.second, avg);
	c.clear();
}


DWORD
ProcFilterEvent(PROCFILTER_EVENT *e)
{
	LARGE_INTEGER now;
	DWORD dwResultFlags = PROCFILTER_RESULT_NONE;

	if (e->dwEventId == PROCFILTER_EVENT_INIT) {
		e->RegisterPlugin(PROCFILTER_VERSION, L"Performance", 0, 0, true, 
			PROCFILTER_EVENT_YARA_SCAN_INIT, PROCFILTER_EVENT_YARA_SCAN_CLEANUP,
			PROCFILTER_EVENT_NONE);
		g_dwFlushSize = (DWORD)e->GetConfigInt(L"FlushSize", (int)g_dwFlushSize);
		LARGE_INTEGER liPerformanceFrequency;
		QueryPerformanceFrequency(&liPerformanceFrequency);
		g_dPerformanceFrequency = (double)liPerformanceFrequency.QuadPart;
	} else if (e->dwEventId == PROCFILTER_EVENT_SHUTDOWN) {
		FlushStats(e, "Creation Scans", g_CreationScanDurations);
		FlushStats(e, "Termination Scans", g_TerminationScanDurations);
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_SCAN_INIT) {
		if (e->dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_CREATE) {
			QueryPerformanceCounter(&now);
			g_CreationScans[e->dwProcessId] = now;
		} else if (e->dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_TERMINATE) {
			QueryPerformanceCounter(&now);
			g_TerminationScans[e->dwProcessId] = now;
		}
	} else if (e->dwEventId == PROCFILTER_EVENT_YARA_SCAN_CLEANUP) {
		if (e->dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_CREATE) {
			QueryPerformanceCounter(&now);
			LARGE_INTEGER start = g_CreationScans.find(e->dwProcessId)->second;
			g_CreationScans.erase(e->dwProcessId);

			g_CreationScanDurations.push_back(GetDuration(&start, &now));
			if (g_dwFlushSize && g_CreationScanDurations.size() >= g_dwFlushSize) {
				FlushStats(e, "Creation Scans", g_CreationScanDurations);
			}
		} else if (e->dScanContext == PROCFILTER_SCAN_CONTEXT_PROCESS_TERMINATE) {
			QueryPerformanceCounter(&now);
			LARGE_INTEGER start = g_TerminationScans.find(e->dwProcessId)->second;
			g_TerminationScans.erase(e->dwProcessId);
		
			g_TerminationScanDurations.push_back(GetDuration(&start, &now));
			if (g_dwFlushSize && g_TerminationScanDurations.size() >= g_dwFlushSize) {
				FlushStats(e, "Termination Scans", g_TerminationScanDurations);
			}
		}
	} else if (e->dwEventId == PROCFILTER_EVENT_STATUS) {

	}

	return dwResultFlags;
}
