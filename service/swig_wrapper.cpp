//
// This includes the SWIG auto-generated .cxx wrapper file. It generates warnings
// so this file disables those warnings and includes the .cxx file directly, normally
// something that should never be done. However in this case inclusion with certain
// warnings disabled keeps the build warning-free.
//
// Additionally, fully embedding Lua and being able to export pre-made structures
// to the Lua environment (as opposed to building from within Lua) requires accessing
// some of the internals of procfilter_wrap.cxx, so this allows us to do that without
// having the changes overwritten each time the SWIG wrapper generator is rerun.
//

//#pragma warning(disable: 4244 4996 4800)
#include "procfilter_wrap.cxx"
//#pragma warning(default: 4244 4996 4800)

void SwigPushApiEvent(lua_State *L, PROCFILTER_EVENT *e) {
	SWIG_Lua_NewPointerObj(L, e, SWIGTYPE_p_procfilter_event, 0);
}
