
#include <stdarg.h>

#include "strlcat.hpp"

#include "warning.hpp"

#include "ProcFilterEvents.h"


void
Warning(const WCHAR *lpFmt, ...)
{
	va_list ap;
	va_start(ap, lpFmt);

	WCHAR szMessage[1024];
	vwstrlprintf(szMessage, sizeof(szMessage), lpFmt, ap);

	EventWriteWARNING(szMessage);

	va_end(ap);
}


void
Notice(const WCHAR *lpFmt, ...)
{
	va_list ap;
	va_start(ap, lpFmt);

	WCHAR szMessage[1024];
	vwstrlprintf(szMessage, sizeof(szMessage), lpFmt, ap);

	EventWriteNOTICE(szMessage);

	va_end(ap);
}
