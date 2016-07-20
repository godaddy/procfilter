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

#ifdef __cplusplus
extern "C" {
#endif

//
// The ProcFilter API follows an event-driven, multi-threaded model. For each scan that occurs, a prescan
// event happens, optionally followed by match and match meta events as rules are matched by the scanning
// engine, finally followed by a postscan event. The sequence of these events is guaranteed per-scan, but
// multiple threads can be doing scanning at onces, so multiple scans can be handling events simultaneously.
//

#define PROCFILTER_VERSION L"1.0.0-beta.1"

//
// PROCFILTER_EVENT_INIT / PROCFILTER_EVENT_SHUTDOWN
//
// Plugins must call RegisterPlugin() first in PROCFILTER_EVENT_INIT to any other API calls.
// 
// Plugin must release resources and be ready for unloading after the shutdown event.
//
// Both of these events occur when only 1 thread is running within the API, so it is safe to modify global values.
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
#define PROCFILTER_EVENT_NONE                        0 // Valid: None

#define PROCFILTER_EVENT_INIT                        1 // Valid: lpszArgument
#define PROCFILTER_EVENT_SHUTDOWN                    2 // Valid: None

#define PROCFILTER_EVENT_PROCESS_CREATE              3 // Valid: dwProcessId, dwParentProcessId*, lpszFileName, lpvProcessData
#define PROCFILTER_EVENT_PROCESS_TERMINATE           4 // Valid: dwProcessId, lpszFileName, lpvProcessData
#define PROCFILTER_EVENT_PROCESS_DATA_CLEANUP        5 // Valid: lpvProcessData

#define PROCFILTER_EVENT_THREAD_CREATE               6 // Valid: dwProcessId, dwParentProcessId, dwThreadId
#define PROCFILTER_EVENT_THREAD_TERMINATE            7 // Valid: dwProcessId, dwThreadId

#define PROCFILTER_EVENT_IMAGE_LOAD                  8 // Valid: dwProcessId, lpszFileName*

#define PROCFILTER_EVENT_YARA_SCAN_INIT              9 // Valid: dwProcessId, lpvScanData, dwParentProcessId*, lpszFileName, dScanContext, bScanFile, bScanMemory, dwCurrentResult
#define PROCFILTER_EVENT_YARA_SCAN_COMPLETE         10 // Valid: dwProcessId, lpvScanData, dwParentProcessId*, lpszFileName, dScanContext, bScanFile, bScanMemory, dwCurrentResult
#define PROCFILTER_EVENT_YARA_SCAN_CLEANUP          11 // Valid: dwProcessId, lpvScanData, dwParentProcessId*, lpszFileName, dScanContext, bBlockProcess, bProcessBlocked, srFileResult*, srMemoryResult*
#define PROCFILTER_EVENT_YARA_RULE_MATCH            12 // Valid: dwProcessId, lpvScanData, lpszFileName*, dScanContext, dMatchLocation, lpszRuleName
#define PROCFILTER_EVENT_YARA_RULE_MATCH_META_TAG   13 // Valid: dwProcessId, lpvScanData, lpszFileName*, dScanContext, dMatchLocation, lpszRuleName, lpszMetaTagName, dNumericValue, lpszStringValue*

#define PROCFILTER_EVENT_STATUS                     14 // Valid: None

#define PROCFILTER_EVENT_TICK                       15 // Valid: None
    
#define PROCFILTER_EVENT_NUM                        16
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

#define SHA1_HEXDIGEST_LENGTH                    (20*2)
#define SHA1_DIGEST_SIZE                         (20)

    
typedef struct yarascan_context YARASCAN_CONTEXT;
typedef void (CALLBACK *OnMatchCallback_cb)(char *lpszRuleName, void *user_data);
typedef void (CALLBACK *OnMetaCallback_cb)(char *lpszRuleName, char *lpszMetaTagName, char *lpszStringValue, int dNumericValue, void *user_data);

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
    void  (CALLBACK *RegisterPlugin)(const WCHAR *lpszApiVersion, const WCHAR *lpszShortName, DWORD dwProcessDataSize, DWORD dwScanDataSize, bool bSynchronizeEvents, ...);
    
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
    int   dNumericValue;         // The meta tag's numeric value, 0 if the type is string
    char *lpszStringValue;       // The meta tag's string value, may be NULL

    WCHAR *lpszArgument;         // Plugin-specific INI-specified configuration flags

    void  *lpvProcessData;       // Plugin-specific process data pointer
    void  *lpvScanData;          // Plugin-specific scan data pointer

    DWORD  dwCurrentResult;      // The current set of result flags generated by other plugins

    volatile struct {
        HANDLE hReadMemoryCurrentProcess;
        HANDLE hCurrentPid;
        void  *lpvEventData;
        bool   bSha1Valid;
        char   szSha1HexDigest[SHA1_HEXDIGEST_LENGTH+1];
        BYTE   baSha1Digest[SHA1_DIGEST_SIZE];
    } private_data[1];

    //
    // Get a value from configuration.  A plugin's configuration is retrieved from the section name passed in to RegisterPlugin()
    // within procfilter.ini.
    //
    int   (CALLBACK *GetConfigInt)(const WCHAR *lpszKey, int dDefault);
    bool  (CALLBACK *GetConfigBool)(const WCHAR *lpszKey, bool bDefault);
    void  (CALLBACK *GetConfigString)(const WCHAR *lpszKey, const WCHAR *lpszDefault, WCHAR *lpszDestination, DWORD dwDestinationSize);

    //
    // Lock the pid associated with the current event to avoid race conditions caused by PID reuse.  The pid is automatically
    // unlocked after the plugin's event handler returns.
    //
    void  (CALLBACK *LockPid)();

    //
    // Get a process image's full path name and basename
    //
    bool   (CALLBACK *GetProcessFileName)(DWORD dwProcessId, WCHAR *lpszResult, DWORD dwResultSize);
   const WCHAR* (CALLBACK *GetProcessBaseNamePointer)(WCHAR *lpszProcessFileName);

    //
    // Get a full path to a directory or file in ProcFilter's base directory.  Directories contain a trailing slash.
    //
    bool  (CALLBACK *GetProcFilterDirectory)(WCHAR *lpszResult, DWORD dwResultSize, const WCHAR *lpszSubDirectoryBaseName);
    bool  (CALLBACK *GetProcFilterFile)(WCHAR *lpszResult, DWORD dwResultSize, const WCHAR *lpszFileBaseName);

    //
    // Convert a DOS path name such as 'C:\windows\system32\cmd.exe' to an NT path such as '\Device\HarddiskVolume2\Windows\system32\cmd.exe'
    //
    bool  (CALLBACK *GetNtPathName)(const WCHAR *lpszDosPath, WCHAR *lpszNtDevice, DWORD dwNtDeviceSize, WCHAR *lpszFilePath, DWORD dwFilePathSize, WCHAR *lpszFullPath, DWORD dwFullPathSize);
   
    //
    // Prompt the currently logged in user with a dialog.  See MSDN's WTSSendMessage() documentation for the underlying implementation details.
    //
    // These functions should be used with extreme caution! It's results are only as trustworthy as the current running user or who
    // has access to the console!
    // See https://msdn.microsoft.com/en-us/library/ms683502%28v=vs.85%29.aspx for more details
    // See https://blogs.msdn.microsoft.com/larryosterman/2005/09/14/interacting-with-services/ for even more details
    //
    DWORD (CALLBACK *ShellNotice)(DWORD dwDurationSeconds, bool bWait, DWORD dwStyle, WCHAR *lpszTitle, WCHAR *lpszMessage);
    DWORD (CALLBACK *ShellNoticeFmt)(DWORD dwDurationSeconds, bool bWait, DWORD dwStyle, WCHAR *lpszTitle, WCHAR *lpszMessageFmt, ...);

    //
    // Quarantine a file immediately.
    //
    bool  (CALLBACK *QuarantineFile)(const WCHAR *lpszFileName, char *lpszHexDigest, DWORD dwHexDigestSize);

    //
    // Compute the SHA1 hash of the specified file.
    //
    bool  (CALLBACK *Sha1File)(const WCHAR *lpszFileName, char *lpszHexDigest, DWORD dwHexDigestSize, void *lpbaRawDigest, DWORD dwRawDigestSize);

    //
    // Format a string.
    //
    bool  (CALLBACK *FormatString)(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, ...);
    bool  (CALLBACK *ConcatenateString)(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, ...);
    bool  (CALLBACK *VFormatString)(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, va_list ap);
    bool  (CALLBACK *VConcatenateString)(WCHAR *lpszDestination, DWORD dwDestinationSize, const WCHAR *lpszFormatString, va_list ap);
    void  (CALLBACK *StatusPrintFmt)(const WCHAR *lpszFmt, ...);

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
    YARASCAN_CONTEXT* (CALLBACK *AllocateScanContext)(const WCHAR *lpszYaraRuleFile, WCHAR *szError, DWORD dwErrorSize);
    void  (CALLBACK *FreeScanContext)(YARASCAN_CONTEXT *ctx);
    void  (CALLBACK *ScanFile)(YARASCAN_CONTEXT *ctx, const WCHAR *lpszFileName, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *lpvUserData, SCAN_RESULT *o_result);
    void  (CALLBACK *ScanMemory)(YARASCAN_CONTEXT *ctx, DWORD dwProcessId, OnMatchCallback_cb lpfnOnMatchCallback, OnMetaCallback_cb lpfnOnMetaCallback, void *lpvUserData, SCAN_RESULT *o_result);

    //
    // Read memory from the associated process
    //
    bool  (CALLBACK *ReadProcessMemory)(const void *lpvRemotePointer, void *lpszDestination, DWORD dwDestinationSize);
    bool  (CALLBACK *ReadProcessPeb)(PEB *lpPeb);

    //
    // Retrieve a remote file
    //
    bool (CALLBACK *GetFile)(const WCHAR *lpszUrl, void *lpvResult, DWORD dwResultSize, DWORD *lpdwBytesUsed);

    //
    // Exit the program with a fatal error.
    //
    void  (CALLBACK *Die)(const char *fmt, ...);

    //
    // Log a string to Event Log.
    //
    void  (CALLBACK *Log)(const char *str);
    void  (CALLBACK *LogFmt)(const char *fmt, ...);

    //
    // Allocate and free memory.  Allocated memory is zeroed.  AllocateMemory() always succeeds; if no memory
    // is available the core exits with a fatal error and does not return.
    //
    void*  (CALLBACK *AllocateMemory)(size_t dwNumElements, size_t dwElementSize);
    void   (CALLBACK *FreeMemory)(void *lpPointer);
    WCHAR* (CALLBACK *DuplicateString)(const WCHAR *lpszString);

    //
    // Verify the signature on a PE file
    //
    bool   (CALLBACK *VerifyPeSignature)(const WCHAR* lpszFileName, bool bCheckRevocations);
};
#pragma pack(pop)


//
// The export that plugins must have in order to accept ProcFilter events.
//
#if !defined(PROCFILTER_BUILD)
_declspec(dllexport)
#else
_declspec(dllimport)
#endif
DWORD ProcFilterEvent(PROCFILTER_EVENT *e);
    
#ifdef __cplusplus
}
#endif
