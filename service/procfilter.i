
%include <windows.i>
%include <typemaps.i>
%include <wchar.i>

// This is okay because the struct is not volatile from within the Lua module
#define volatile

// Remove the "Export_" prefix from API functions
%rename("%(strip:[Export_])s") "";

%module procfilter
%{
#include "include/procfilter/procfilter.h"
#include "api_exports.hpp"
%}

// RegisterPlugin() takes a variable length of PROCFILTER_EVENT_Xxx arguments
// and is terminated by PROCFILTER_EVENT_NONE. SWIG doesn't support vararg
// functions by default so there needs to be a %varags directive that gives
// an upper limit on the number of args it can accept.
//
// There aren't any access to constants here so they're defined manually
// and must be changed if the header changes:
//
// %varargs(PROCFILTER_EVENT_NUM, DWORD dwRequestedEventId=PROCFILTER_EVENT_NONE) Export_RegisterPlugin;
%varargs(16, DWORD dwRequestedEventId=0) Export_RegisterPlugin;

%ignore ProcFilterEvent;

typedef wchar_t WCHAR;
%include "include/procfilter/procfilter.h"
%include "api_exports.hpp"
