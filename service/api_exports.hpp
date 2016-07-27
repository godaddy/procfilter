//
// This file should NOT be restricted to a single inclusion; it's function is entirely different based
// on which preprocessor macros are defined during its inclusion. This allows one single list of exported
// API functions rather than having multiple lists that all need to be maintained.
//
//#pragma once

//extern "C" {
//typedef struct table TABLE;
//struct table {
//	void (*LogString)(const char*);
//};
//void LogString(const char*) { }
//decltype(table::LogString) LogStringPtr = LogString;
//}


#ifdef LUA_BUILD_PROTOTYPE
//extern "C" {
namespace ProcFilterLuaApi {
#pragma message("1")
#define StoreExport(FunctionName) typedef decltype(procfilter_event::FunctionName) FunctionName##_type; extern const FunctionName##_type FunctionName
#endif
#ifdef LUA_BUILD_DEFINITION
//extern "C" {
namespace ProcFilterLuaApi {
#pragma message("2")
#define StoreExport(FunctionName) const FunctionName##_type FunctionName = Export_##FunctionName
#endif
#ifdef API_STORE_POINTERS
#pragma message("3")
#define StoreExport(FunctionName) e->##FunctionName = Export_##FunctionName
#endif

#ifndef StoreExport
#pragma message("4")
#define StoreExport(FunctionName)
#endif

StoreExport(RegisterPlugin);
StoreExport(GetConfigInt);
StoreExport(GetConfigString);
StoreExport(GetConfigBool);
StoreExport(AllocateScanContext);
StoreExport(FreeScanContext);
StoreExport(GetNtPathName);
StoreExport(ShellNotice);
StoreExport(ShellNoticeFmt);
StoreExport(QuarantineFile);
StoreExport(Sha1File);
StoreExport(ScanFile);
StoreExport(ScanMemory);
StoreExport(Die);
StoreExport(Log);
StoreExport(LogFmt);
StoreExport(AllocateMemory);
StoreExport(GetFile);
StoreExport(FreeMemory);
StoreExport(DuplicateString);
StoreExport(VerifyPeSignature);
StoreExport(ConcatenateString);
StoreExport(FormatString);
StoreExport(VConcatenateString);
StoreExport(VFormatString);
StoreExport(ReadProcessMemory);
StoreExport(ReadProcessPeb);
StoreExport(GetProcFilterDirectory);
StoreExport(GetProcFilterFile);
StoreExport(StatusPrintFmt);
StoreExport(GetProcessFileName);
StoreExport(GetProcessBaseNamePointer);
StoreExport(LockPid);
StoreExport(IsElevated);

#undef StoreExport

#ifdef LUA_BUILD_PROTOTYPE
//}
}
#endif
#ifdef LUA_BUILD_DEFINITION
//}
}
#endif
