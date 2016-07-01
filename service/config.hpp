
#pragma once

#include <Windows.h>

#include "pfdriver.hpp"

#define CONFIG_REREAD_INTERVAL (5 * 1000)
#define CONFIG_APPNAME         (L"ProcFilter")

//
// Globally available configuration declaration
//
typedef const struct config_data CONFIG_DATA;
struct config_data {
	WCHAR szExePath[MAX_PATH+1];		     // The path of procfilter.exe
	WCHAR szBaseDirectory[MAX_PATH+1];	     // The base directory of procfilter.exe or as specified in config.ini
	WCHAR szLogDirectory[MAX_PATH+1];	     // The log directory
	WCHAR szConfigFile[MAX_PATH+1];		     // Full config file path
	WCHAR szLocalYaraRuleFile[MAX_PATH+1];	 // Full yara rule file path
	WCHAR szRemoteYaraRuleFile[MAX_PATH+1];	 // Full remote yara rule file path
	WCHAR szLogFile[MAX_PATH+1];		     // Full log file path
	WCHAR szErrorLogFile[MAX_PATH+1];	     // Full error log file path
	WCHAR szProcFilterDriver[MAX_PATH+1];    // Full path to the procfilter driver component
	WCHAR szQuarantineDirectory[MAX_PATH+1]; // Full path to the quarantine directory
	WCHAR szPluginDirectory[MAX_PATH+1];     // Full path to the plugin directory

	DWORD dwScanIntervalSeconds;		     // How frequently procfilter scans all processes
	DWORD dwRuleFilePollIntervalTicks;		 // How frequently do threads poll the rule files for change?
	DWORD dwPerProcessTimeoutMs;		     // After scanning each process sleep for this amount
	DWORD dwQuarantineFileSizeLimit;         // Maximum file size to quarantine
	DWORD dwScanFileSizeLimit;               // Maximum file size to scan
	DWORD dwLogLevel;					     // Log messages below this value are ignored
	int   dThreadPoolSize;                   // Size of threadpool
	
	//
	// Scan file and/or memory on various events?
	//
	bool bScanFileOnPeriodic;
	bool bScanMemoryOnPeriodic;
	bool bScanFileOnProcessCreate;
	bool bScanMemoryOnProcessCreate;
	bool bScanFileOnProcessTerminate;
	bool bScanMemoryOnProcessTerminate;
	bool bScanFileOnImageLoad;
	bool bScanMemoryOnImageLoad;

	//
	// Default values for YARA rule meta directives if they aren't present in a rule
	//
	bool bBlockDefault;
	bool bLogDefault;
	bool bQuarantineDefault;
	
	bool bDisableUi;                         // Disable all UI interactions?

	bool bRequireSignedPlugins;              // Require plugins to be digitally signed?

	bool bUseBackgroundMode;			     // Scan in background mode?
	
	bool bDenyProcessCreationOnFailedScan;   // Deny process creation if scanning is unsuccessful?

	bool bUseLocalRuleFile;                  // Use the local rule file?
	bool bUseRemoteRuleFile;                 // Use the remote rule file?
	
	DWORD dwRemotePollIntervalMinutes;       // How often to poll the update location for changes?
	DWORD dwRemotePollIntervalOffsetRangeSeconds; // Random offset to delay polling the Git server?
	WCHAR szRemoteDirectory[512];            // Path containing rules retrieved from the update location
	WCHAR szRemoteGitUrl[512];				 // Update Url
	WCHAR szRemoteGitUserName[256];
	WCHAR szRemoteGitPassword[256];
	bool  bUseRemoteGitUrl;					 // Use the git repo?
};

//
// Initialize the global CONFIG_DATA structure with data from the ini file
//
void ConfigInit();
void ConfigDestroy();

//
// Print the stats
//
void ConfigStatusPrint();

//
// Get a pointer to the global config data structure
//
extern struct config_data __config_private_config_data;
inline CONFIG_DATA* GetConfigData() { return &__config_private_config_data; };
