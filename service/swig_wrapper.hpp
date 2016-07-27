
#pragma once

#include "procfilter/procfilter.h"
#include "lua.hpp"

// SWIG defines this in procfilter_wrap.c and we need access to it call it directly
extern "C" __declspec(dllexport) int luaopen_procfilter(lua_State *L);

void SwigPushApiEvent(lua_State *L, PROCFILTER_EVENT *e);
