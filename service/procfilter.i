
%include <windows.i>
%include <typemaps.i>
//%include <cpointer.i>
//%include <wchar.i>

// This is okay because the struct is not volatile from within the Lua module
#define volatile

// Set this which is defined in Windows.h, but not Windows.i
#define CALLBACK __stdcall

%module procfilter
%{
#include "include/procfilter/procfilter.h"
#define LUA_BUILD_PROTOTYPE 1
#include "api_exports.hpp"
#undef LUA_BUILD_PROTOTYPE
using namespace ProcFilterLuaApi;
%}

%ignore ProcFilterEvent;

%include "include/procfilter/procfilter.h"
#define LUA_BUILD_PROTOTYPE 1
%include "api_exports.hpp"
#undef LUA_BUILD_PROTOTYPE
using namespace ProcFilterLuaApi;

