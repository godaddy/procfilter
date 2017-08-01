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

#pragma once

#define NOMINMAX
#include <Windows.h>
#include <winternl.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// The ProcFilter API follows an event-driven, multi-threaded model. For each process, thread, and DLL that's
// loaded in the system an event is generated to each plugin. For each YARA scan that occurs, a prescan
// event happens, optionally followed by match and match meta events as rules are matched by the scanning
// engine, finally followed by a postscan event. The sequence of these events is guaranteed per-scan, but
// multiple threads can be doing scanning at onces, so multiple scans can be handling events simultaneously.
//

#define PROCFILTER_VERSION ((const WCHAR*)L"1.0.0")

//
// PROCFILTER_EVENT_INIT, PROCFILTER_EVENT_SHUTDOWN
//
// Plugins must call RegisterPlugin() first in PROCFILTER_EVENT_INIT to any other API calls.
// 
// Plugin must release resources and be ready for unloading after the shutdown event.
//
// Both of these events occur when only 1 thread is running within the API so it is safe to modify global values.
//
// Both of these events occur regardless of whether specified in RegisterPlugin().
//
//
// PROCFILTER_EVENT_PROCFILTER_THREAD_INIT, PROCFILTER_EVENT_PROCFILTER_THREAD_SHUTDOWN
//
// Generated whenever a thread interacting within plugins is spawned within ProcFilter's core. This provides
// the opportunity for a thread to initialize thread-global data if needed.
//
// Both of these events occur regardless of whether specified in RegisterPlugin().
//
//
// PROCFILTER_EVENT_PROCESS_CREATE, PROCFILTER_EVENT_PROCESS_TERMINATE, PROCFILTER_EVENT_PROCESS_DATA_CLEANUP
//
// Generated whenever a process is created or terminated. lpvProcessData is plugin-specific data available
// on a per process basis. It can be initialized during the process create event and deinitialized during
// the process data clenaup event. Deinitialization is not done in the process terminate event since processes
// still running when procfilter exits will not have a corresponding process terminate event, however, a
// a process data cleanup event is guaranteed to be generated.
//
// These events are not generated for processes created by the ProcFilter service.
//
//
// PROCFILTER_EVENT_THREAD_CREATE, PROCFILTER_EVENT_THREAD_TERMINATE
// 
// Generated whenever a usermode thread is created or terminated on the system, except for
// threads within the ProcFilter process itself.
//
//
// PROCFILTER_EVENT_YARA_SCAN_INIT, PROCFILTER_EVENT_YARA_SCAN_COMPLETE
//
// Generated when a process is created, terminated, or periodically scanned.  These events occur even if no scan
// is configured to be done since plugins have the option of changing that. PROCFILTER_EVENT_YARA_SCAN_INIT happens
// any time a new process is created on the system and can be denied.
//
// The process is not running during these events.
//
// lpvScanData can be initialized during the prescan event.
//
//
// PROCFILTER_EVENT_YARA_SCAN_CLEANUP
//
// Called after a corresponding prescan event regardless of whether or not a scan took place.
//
// The process is no longer blocked and may be running during this event.
//
// lpvScanData can be uninitialized during this event.
//
//
// PROCFILTER_EVENT_YARA_RULE_MATCH
//
// Called when a scan, either file or memory as specified in dScanContext, matches a rule.
//
// 
// PROCFILTER_EVENT_YARA_RULE_MATCH_META_TAG
//
// Called for each meta tag found in a scan match.
//
//
// PROCFILTER_EVENT_STATUS
//
// Generated when "procfilter.exe -status" is run. Plugins can use StatusPrintFmt() to send status information
// to the console.
//
//
// PROCFILTER_EVENT_TICK
//
// This tick event happens periodically at >= 100ms intervals. This timer is not backed by an accumulator so
// tick drift is possible over long periods. For example, 100 tick events equates to /at least/ 100 * 100ms of
// time, not exactly 100 * 100ms of time.
//

#define PROCFILTER_EVENT_NONE                        0 // Valid: None

#define PROCFILTER_EVENT_INIT                        1 // Valid: lpszArgument
#define PROCFILTER_EVENT_SHUTDOWN                    2 // Valid: None
#define PROCFILTER_EVENT_PROCFILTER_THREAD_INIT      3 // Valid: None
#define PROCFILTER_EVENT_PROCFILTER_THREAD_SHUTDOWN  4 // Valid: None

#define PROCFILTER_EVENT_PROCESS_CREATE              5 // Valid: dwProcessId, dwParentProcessId*, lpszFileName, lpvProcessData
#define PROCFILTER_EVENT_PROCESS_TERMINATE           6 // Valid: dwProcessId, lpszFileName, lpvProcessData
#define PROCFILTER_EVENT_PROCESS_DATA_CLEANUP        7 // Valid: lpvProcessData

#define PROCFILTER_EVENT_THREAD_CREATE               8 // Valid: dwProcessId, dwParentProcessId, dwThreadId
#define PROCFILTER_EVENT_THREAD_TERMINATE            9 // Valid: dwProcessId, dwThreadId

#define PROCFILTER_EVENT_IMAGE_LOAD                 10 // Valid: dwProcessId, lpszFileName*

#define PROCFILTER_EVENT_YARA_SCAN_INIT             11 // Valid: dwProcessId, lpvScanData, dwParentProcessId*, lpszFileName, dScanContext, bScanFile, bScanMemory, dwCurrentResult
#define PROCFILTER_EVENT_YARA_SCAN_COMPLETE         12 // Valid: dwProcessId, lpvScanData, dwParentProcessId*, lpszFileName, dScanContext, bScanFile, bScanMemory, dwCurrentResult
#define PROCFILTER_EVENT_YARA_SCAN_CLEANUP          13 // Valid: dwProcessId, lpvScanData, dwParentProcessId*, lpszFileName, dScanContext, bBlockProcess, bProcessBlocked, srFileResult*, srMemoryResult*
#define PROCFILTER_EVENT_YARA_RULE_MATCH            14 // Valid: dwProcessId, lpvScanData, lpszFileName*, dScanContext, dMatchLocation, lpszRuleName
#define PROCFILTER_EVENT_YARA_RULE_MATCH_META_TAG   15 // Valid: dwProcessId, lpvScanData, lpszFileName*, dScanContext, dMatchLocation, lpszRuleName, lpszMetaTagName, dNumericValue, lpszStringValue*

#define PROCFILTER_EVENT_STATUS                     16 // Valid: None

#define PROCFILTER_EVENT_TICK                       17 // Valid: None
    
#define PROCFILTER_EVENT_NUM                        18
#define PROCFILTER_EVENT_ALL                        PROCFILTER_EVENT_NUM // Convenience value to pass in to RegisterPlugin() that signifies all events
                                                    
                                                       // * - May be NULL

#define PROCFILTER_RESULT_NONE                    0x00 // Valid: Always
#define PROCFILTER_RESULT_BLOCK_PROCESS           0x01 // Valid: PROCFILTER_EVENT_YARA_SCAN_INIT, PROCFILTER_EVENT_YARA_SCAN_COMPLETE
#define PROCFILTER_RESULT_DONT_SCAN_MEMORY        0x02 // Valid: PROCFILTER_EVENT_YARA_SCAN_INIT
#define PROCFILTER_RESULT_DONT_SCAN_FILE          0x04 // Valid: PROCFILTER_EVENT_YARA_SCAN_INIT
#define PROCFILTER_RESULT_FORCE_SCAN_MEMORY       0x08 // Valid: PROCFILTER_EVENT_YARA_SCAN_INIT
#define PROCFILTER_RESULT_FORCE_SCAN_FILE         0x10 // Valid: PROCFILTER_EVENT_YARA_SCAN_INIT
#define PROCFILTER_RESULT_QUARANTINE              0x20 // Valid: PROCFILTER_EVENT_YARA_SCAN_INIT, PROCFILTER_EVENT_YARA_SCAN_COMPLETE
#define PROCFILTER_RESULT_DONT_SCAN              (PROCFILTER_RESULT_DONT_SCAN_MEMORY | PROCFILTER_RESULT_DONT_SCAN_FILE)
#define PROCFILTER_RESULT_FORCE_SCAN             (PROCFILTER_RESULT_FORCE_SCAN_FILE  | PROCFILTER_RESULT_FORCE_SCAN_MEMORY)

#define PROCFILTER_SCAN_CONTEXT_PROCESS_CREATE    0 // Process creation
#define PROCFILTER_SCAN_CONTEXT_PROCESS_TERMINATE 1 // Process termination
#define PROCFILTER_SCAN_CONTEXT_PERIODIC_SCAN     2 // Periodic process scan
#define PROCFILTER_SCAN_CONTEXT_IMAGE_LOAD        3 // Image load events
#define PROCFILTER_NUM_CONTEXTS                   4

#define PROCFILTER_MATCH_NONE                     0 // No match
#define PROCFILTER_MATCH_MEMORY                   1 // Match in address space
#define PROCFILTER_MATCH_FILE                     2 // Match in file

#define MD5_HEXDIGEST_LENGTH                     (16*2)
#define MD5_DIGEST_SIZE                          (16)
#define SHA1_HEXDIGEST_LENGTH                    (20*2)
#define SHA1_DIGEST_SIZE                         (20)
#define SHA256_HEXDIGEST_LENGTH                  (32*2)
#define SHA256_DIGEST_SIZE                       (32)

typedef struct hashes_t HASHES;
struct hashes_t {
	BYTE md5_digest[MD5_DIGEST_SIZE];
	char md5_hexdigest[MD5_HEXDIGEST_LENGTH + 1];
	BYTE sha1_digest[SHA1_DIGEST_SIZE];
	char sha1_hexdigest[SHA1_HEXDIGEST_LENGTH + 1];
	BYTE sha256_digest[SHA256_DIGEST_SIZE];
	char sha256_hexdigest[SHA256_HEXDIGEST_LENGTH + 1];
};


typedef struct yarascan_context YARASCAN_CONTEXT;
typedef void (*OnMatchCallback_cb)(char *lpszRuleName, void *user_data);
typedef void (*OnMetaCallback_cb)(char *lpszRuleName, char *lpszMetaTagName, char *lpszStringValue, int64_t dNumericValue, void *user_data);

#pragma pack(push, 1)
typedef struct scan_result SCAN_RESULT;
struct scan_result {
    bool  bScanSuccessful;            // Was the scan successful?
    bool  bRuleMatched;               // Did any YARA rule match?
    bool  bBlock;                     // Should the current scan target be blocked?
    bool  bLog;                       // Should the current scan target be logged?
    bool  bQuarantine;                // Should the current scan target be quarantined?
    BYTE  bUnusedPadding[3];          // Align following struct members to a 4-byte boundary
    WCHAR szMatchedRuleNames[256];    // |-delimited list of rules that matched
    WCHAR szBlockRuleNames[256];      // |-delimited list of rules that specified to block the process
    WCHAR szLogRuleNames[256];        // |-delimited list of rules that specified to log the process
    WCHAR szQuarantineRuleNames[256]; // |-delimited list of rules that specified to quarantine the process
    WCHAR szError[512];               // An error string if bScanSuccessful is false
};
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct procfilter_event PROCFILTER_EVENT;
struct procfilter_event {
    //
    // Registers a plugin.  Must be the first thing done during PROCFILTER_EVENT_INIT.  The variable arguments need to be
    // the events the plugin wants to receive, terminated by PROCFILTER_EVENT_NONE. PROCFILTER_EVENT_INIT and PROCFILTER_EVENT_SHUTDOWN
    // always happen regardless of whether or not they are requested.
    //
    // This is the first entry in the structure since if theres a version mismatch between core and plugin then offsets later on
    // in the structure may have changed, and the plugin's call to RegisterPlugin() could dereference a completely different
    // or invalid value and lead to a crash before the core had the chance to check for a plugin mismatch and exit gracefully.
    //
    void  (*RegisterPlugin)(const WCHAR *lpszApiVersion, const WCHAR *lpszShortName, DWORD dwProcessDataSize, DWORD dwScanDataSize, bool bSynchronizeEvents, ...);
    
    DWORD  dwEventId;            // One of PROCFILTER_EVENT_Xxx

    DWORD  dwProcessId;          // Process ID of target
    DWORD  dwParentProcessId;    // Process ID of parent; only valid during the PROCFILTER_SCAN_CONTEXT_PROCESS_CREATE context since this is the only time it's guaranteed correct
    WCHAR *lpszFileName;         // Full NT path of the processes image file
    DWORD  dwThreadId;           // Thread ID associated with event

    bool   bScanFile;            // File scan requested?
    bool   bScanMemory;          // Memory scan requested?
    bool   bBlockProcess;        // Should the process be blocked?
    bool   bProcessBlocked;      // Was the process blocked?

    SCAN_RESULT *srFileResult;   // File scan result, may be NULL if no file scan was requested
    SCAN_RESULT *srMemoryResult; // Memory scan result, may be NULL if no memory scan was requested
    
    int   dScanContext;          // One of PROCFILTER_SCAN_CONTEXT_Xxx
    int   dMatchLocation;        // One of PROCFILTER_MATCH_Xxx
    char *lpszRuleName;          // The rule name matched
    char *lpszMetaTagName;       // The meta tag name
    int64_t   dNumericValue;     // The meta tag's numeric value, 0 if the type is string
    char *lpszStringValue;       // The meta tag's string value, may be NULL

    WCHAR *lpszArgument;         // Plugin-specific INI-specified configuration flags

    void  *lpvProcessData;       // Plugin-specific process data pointer
    void  *lpvScanData;          // Plugin-specific scan data pointer

    DWORD  dwCurrentResult;      // The current set of result flags generated by other plugins

    volatile struct {
        HANDLE hReadMemoryCurrentProcess;
        HANDLE hCurrentPid;
        void  *lpvEventData;
        bool   bHashesValid;
		HASHES hashes;
		WCHAR *lpszCommandLine;
    } private_data[1];

	//
	// Enable an event after having called RegisterPlugin(). Only valid during PROCFILTER_EVENT_INIT.
	//
	void  (*EnableEvent)(DWORD dEvent);

    //
    // Get a value from configuration.  A plugin's configuration is retrieved from the section name passed in to RegisterPlugin()
    // within procfilter.ini.
    //
    int   (*GetConfigInt)(const WCHAR *lpszKey, int dDefault);
    bool  (*GetConfigBool)(const WCHAR *lpszKey, bool bDefault);
    void  (*GetConfigString)(const WCHAR *lpszKey, const WCHAR *lpszDefault, WCHAR *lpszDestination, DWORD dwDestinationSize);

    //
    // Lock the pid associated with the current event to avoid race conditions caused by PID reuse.  The pid is automatically
    // unlocked after the plugin's event handler returns.
    //
    void  (*LockPid)();

    //
    // Get a process image's full path name and basename
    //
    bool         (*GetProcessFileName)(DWORD dwProcessId, WCHAR *lpszResult, DWORD dwResultSize);
    const WCHAR* (*GetProcessBaseNamePointer)(WCHAR *lpszProcessFileName);

    //
    // Get a full path to a directory or file in ProcFilter's base directory. Directories contain a trailing slash.
    //
    // Both input argumnets are optional.
    //
    bool  (*GetProcFilterPath)(WCHAR *lpszResult, DWORD dwResultSize, const WCHAR *lpszSubDirectoryBaseName, const WCHAR *lpszFileBaseName);

    //
    // Convert a DOS path name such as 'C:\windows\system32\cmd.exe' to an NT path such as '\Device\HarddiskVolume2\Windows\system32\cmd.exe'
    //
    bool  (*GetNtPathName)(const WCHAR *lpszDosPath, WCHAR *lpszNtDevice, DWORD dwNtDeviceSize, WCHAR *lpszFilePath, DWORD dwFilePathSize, WCHAR *lpszFullPath, DWORD dwFullPathSize);
   
    //
    // Prompt the currently logged in user with a dialog.  See MSDN's WTSSendMessage() documentation for the underlying implementation details.
    //
    // These functions should be used with extreme caution! It's results are only as trustworthy as the current running user or who
    // has access to the console!
    // See https://msdn.microsoft.com/en-us/library/ms683502%28v=vs.85%29.aspx for more details
    // See https://blogs.msdn.microsoft.com/larryosterman/2005/09/14/interacting-with-services/ for even more details
    //
    DWORD (*ShellNotice)(DWORD dwDurationSeconds, bool bWait, DWORD dwStyle, WCHAR *lpszTitle, WCHAR *lpszMessage);
    DWORD (*ShellNoticeFmt)(DWORD dwDurationSeconds, bool bWait, DWORD dwStyle, WCHAR *lpszTitle, WCHAR *lpszMessageFmt, ...);

    //
    // Quarantine a file immediately.
    //
    bool  (*QuarantineFile)(const WCHAR *lpszFileName, char *lpszHexDigest, DWORD dwHexDigestSize);

    //
    // Compute the SHA1 hash of the specified file.
    //
    bool  (*HashFile)(const WCHAR *lpszFileName, HASHES *hashes);
	
	//
	// Get the command line for the current process. Only valid during EVENT_PROCESS_CREATE.
	//
	const WCHAR* (*GetProcessCommandLine)();
    
	//
    // Format a string.
    //
    bool  (*FormatString)(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, ...);
    bool  (*ConcatenateString)(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, ...);
    bool  (*VFormatString)(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, va_list ap);
    bool  (*VConcatenateString)(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, va_list ap);
    void  (*StatusPrintFmt)(const WCHAR *lpszFmt, ...);

    //
    // Allocate a scanning context.  If shared between threads this context needs to be protected by a mutex.
    //
    // A scanning context can scan memory or file.  It can be reused to scan multiple items.
    // If 'lpszYaraRuleFile' is NULL then the YARA rule file specified in procfilter.ini is used.
    //
    // Scanning done by this function does not generate ProcFilter API events.
    //
    // Scanning contexts must be freed with FreeScanContext().
    //
    YARASCAN_CONTEXT* (*AllocateScanContext)(const WCHAR *lpszYaraRuleFile, WCHAR *szError, DWORD dwErrorSize);
    YARASCAN_CONTEXT* (*AllocateScanContextLocalAndRemote)(WCHAR *lpszBaseName, WCHAR *lpszError, DWORD dwErrorSize, bool bLogToEventLog);
    void  (*FreeScanContext)(YARASCAN_CONTEXT *ctx);
    void  (*ScanFile)(YARASCAN_CONTEXT *ctx, const WCHAR *lpszFileName, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *lpvUserData, SCAN_RESULT *o_result);
    void  (*ScanMemory)(YARASCAN_CONTEXT *ctx, DWORD dwProcessId, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *lpvUserData, SCAN_RESULT *o_result);
    void  (*ScanData)(YARASCAN_CONTEXT *ctx, const void *lpvData, DWORD dwDataSize, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *lpvUserData, SCAN_RESULT *o_result);

    //
    // Scan data using the default context from ProcFilter.
    //
    void  (*Scan)(const void *lpvData, DWORD dwDataSize, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *lpvUserData, SCAN_RESULT *o_result);

    //
    // Read memory from the associated process
    //
    bool  (*ReadProcessMemory)(const void *lpvRemotePointer, void *lpszDestination, DWORD dwDestinationSize);
    bool  (*ReadProcessPeb)(PEB *lpPeb);

    //
    // Retrieve a remote file
    //
    bool (*GetFile)(const WCHAR *lpszUrl, void *lpvResult, DWORD dwResultSize, DWORD *lpdwBytesUsed);

    //
    // Exit the program with a fatal error.
    //
    void  (*Die)(const char *fmt, ...);

    //
    // Log a string to Event Log. LogFmt() is limited to 8192 characters. Log() is unlimited.
    //
    void  (*Log)(const char *str);
    void  (*LogFmt)(const char *fmt, ...);
    void  (*LogWarning)(const char *str);
    void  (*LogWarningFmt)(const char *fmt, ...);
    void  (*LogCritical)(const char *str);
    void  (*LogCriticalFmt)(const char *fmt, ...);

    //
    // Allocate and free memory.  Allocated memory is zeroed.  AllocateMemory() always succeeds; if no memory
    // is available the core exits with a fatal error and does not return.
    //
    void*  (*AllocateMemory)(size_t dwNumElements, size_t dwElementSize);
    void   (*FreeMemory)(void *lpPointer);
    WCHAR* (*DuplicateString)(const WCHAR *lpszString);

    //
    // Determine if a process is running with elevated privileges
    //
    bool   (*IsElevated)(HANDLE hProcess, bool *lpbIsElevated);

    //
    // Verify the signature on a PE file
    //
    bool   (*VerifyPeSignature)(const WCHAR* lpszFileName, bool bCheckRevocations);
};
#pragma pack(pop)


//
// The export that plugins must have in order to accept ProcFilter events.
//
#if !defined(PROCFILTER_BUILD)
__declspec(dllexport)
#else
__declspec(dllimport)
#endif
DWORD ProcFilterEvent(PROCFILTER_EVENT *e);
    
#ifdef __cplusplus
}
#endif
