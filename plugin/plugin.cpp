

#include "procfilter/procfilter.h"


DWORD
ProcFilterEvent(PROCFILTER_EVENT *e)
{
	DWORD dwResultFlags = PROCFILTER_RESULT_NONE;

	if (e->dwEventId == PROCFILTER_EVENT_INIT) {
		e->RegisterPlugin(PROCFILTER_VERSION, L"Empty", 0, 0, true, PROCFILTER_EVENT_ALL, PROCFILTER_EVENT_NONE);
		e->Log("Empty plugin loaded");
	} if (e->dwEventId == PROCFILTER_EVENT_SHUTDOWN) {
		e->Log("Empty plugin unloaded");
	}

	return dwResultFlags;
}
