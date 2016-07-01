

#if !defined(HAVE_LIBGIT2)
void UpdateInit() {}
void UpdateShutdown() {}
#else

#include <Windows.h>
#include "shellapi.h"
#pragma comment(lib, "shell32.lib")

#include "git2\clone.h"
#include "git2\global.h"
#include "git2\repository.h"
#include "git2\commit.h"
#include "git2\errors.h"
#include "git2\branch.h"
#include "git2\revparse.h"
#include "git2\merge.h"
#include "git2\reset.h"

#if defined(_WIN64)
#pragma comment(lib, "../deps/libgit2/x64/git2.lib")
#else
#pragma comment(lib, "../deps/libgit2/x86/git2.lib")
#endif

#include "update.hpp"
#include "config.hpp"
#include "getfile.hpp"
#include "die.hpp"
#include "file.hpp"
#include "strlcat.hpp"
#include "log.hpp"
#include "yara.hpp"
#include "pfservice.hpp"
#include "warning.hpp"
#include "random.hpp"


static HANDLE g_hStopEvent = NULL;
static HANDLE g_hUpdateThread = NULL;


static
int
GetLastCommit(git_repository *repo, BYTE o_sha1[GIT_OID_RAWSZ])
{
	
	git_annotated_commit *commit;
	int error = git_annotated_commit_from_revspec(&commit, repo, "origin/master");
	if (error) return error;

	ZeroMemory(o_sha1, GIT_OID_RAWSZ);
	const git_oid *id = git_annotated_commit_id(commit);
	if (id) {
		RtlCopyMemory(o_sha1, id->id, GIT_OID_RAWSZ);
	}

	git_annotated_commit_free(commit);
	
	return error;
}


static
int
GetCredentials(git_cred **out, const char *url, const char *username_from_url, unsigned int allowed_types, void *payload)
{
	CONFIG_DATA *cd = GetConfigData();

	char szUserName[256];
	char szPassword[256];
	
	strlprintf(szUserName, sizeof(szUserName), "%ls", cd->szRemoteGitUserName);
	strlprintf(szPassword, sizeof(szPassword), "%ls", cd->szRemoteGitPassword);

	return git_cred_userpass_plaintext_new(out, szUserName, szPassword);
}


//
// Returns true if an update was successfully received + compiled, otherwise false
//
static
bool
DoUpdate(CONFIG_DATA *cd)
{
	bool rv = false;

	Notice(L"Polling %ls for updates", cd->szRemoteGitUrl);

	// Convert from WCHAR to char since the libgit2 API functions don't take in WCHAR strings
	char szRemoteDirectory[MAX_PATH+1] = { '\0' };
	strlprintf(szRemoteDirectory, sizeof(szRemoteDirectory), "%ls", cd->szRemoteDirectory);
	char szRemoteGitUrl[512] = { '\0' };
	strlprintf(szRemoteGitUrl, sizeof(szRemoteGitUrl), "%ls", cd->szRemoteGitUrl);

	// Forward defintions
	git_repository *repo = NULL;
	git_remote *remote = NULL;
	git_object *tree = NULL;
	git_annotated_commit *commit = NULL;
	git_checkout_options checkout_options = GIT_CHECKOUT_OPTIONS_INIT;
	checkout_options.checkout_strategy = GIT_CHECKOUT_FORCE;
	git_fetch_options fetch_options = GIT_FETCH_OPTIONS_INIT;
	fetch_options.callbacks.credentials = GetCredentials;
	git_merge_options merge_options = GIT_MERGE_OPTIONS_INIT;
	merge_options.file_favor = GIT_MERGE_FILE_FAVOR_THEIRS;
	merge_options.file_flags = GIT_MERGE_FILE_IGNORE_WHITESPACE_CHANGE;
	BYTE last_sha1[GIT_OID_RAWSZ] = { 0 };
	BYTE updated_sha1[GIT_OID_RAWSZ] = { 0 };

	// Open the repository, or clone it if necessary
	int error = git_repository_open(&repo, szRemoteDirectory);
	if (error) {
		CreateDirectoryExW(NULL, cd->szRemoteDirectory, NULL);
		// Opening the repository failed, try cloning the source
		git_clone_options clone_options = GIT_CLONE_OPTIONS_INIT;
		clone_options.checkout_opts = checkout_options;
		clone_options.fetch_opts = fetch_options;
		error = git_clone(&repo, szRemoteGitUrl, szRemoteDirectory, &clone_options);
		if (error) goto cleanup;
		error = git_checkout_head(repo, &checkout_options);
		if (error) goto cleanup;

		Notice(L"Cloned rule repository from %hs into %hs", szRemoteGitUrl, szRemoteDirectory);

		rv = true;
	} else {
		// Attempt a checkout of the current repo if the on-disk file to include
		// doesnt exist; this way the files are extracted if the on-disk rules
		// were deleted by the end user
		if (!FileExists(cd->szRemoteYaraRuleFile)) {
			git_checkout_head(repo, &checkout_options);
		}

		// Record the current head
		error = GetLastCommit(repo, last_sha1);
		if (error) goto cleanup;

		// Pull and check out the changes from the repo
		error = git_remote_lookup(&remote, repo, "origin");
		if (error) goto cleanup;
		error = git_remote_fetch(remote, NULL, &fetch_options, "pull");
		if (error) goto cleanup;

		// Get the new head
		error = GetLastCommit(repo, updated_sha1);
		if (error) goto cleanup;

		// If a new head is available, check it out
		if (memcmp(last_sha1, updated_sha1, GIT_OID_RAWSZ) != 0) {
			// Covert the SHA1 hashes  to text for logging
			char last_sha1_hex[GIT_OID_HEXSZ+1] = { '\0' };
			for (int i = 0; i < GIT_OID_RAWSZ; ++i) {
				strlcatf(last_sha1_hex, sizeof(last_sha1_hex), "%X", last_sha1[i]);
			}
			char updated_sha1_hex[GIT_OID_HEXSZ+1] = { '\0' };
			for (int i = 0; i < GIT_OID_RAWSZ; ++i) {
				strlcatf(updated_sha1_hex, sizeof(updated_sha1_hex), "%X", updated_sha1[i]);
			}

			LogDebugFmt("Current Commit: %s   New Commit: %s", last_sha1_hex, updated_sha1_hex);

			error = git_annotated_commit_from_revspec(&commit, repo, "origin/master");
			if (error) goto cleanup;
			
			error = git_reset_from_annotated(repo, commit, GIT_RESET_HARD, &checkout_options);
			if (error) goto cleanup;

			Notice(L"Received update from %ls (Old Commit:%hs New Commit:%hs)", cd->szRemoteGitUrl, last_sha1_hex, updated_sha1_hex);

			rv = true;
		}
	}

cleanup:
	if (commit) git_annotated_commit_free(commit);
	if (remote) git_remote_free(remote);
	if (repo) git_repository_free(repo);

	if (!rv && error) Warning(L"Unable to update rules: %hs", giterr_last() ? giterr_last()->message : "None");

	LogDebugFmt("Poll result: %s (%d) %s", rv ? "true" : "false", error, giterr_last() ? giterr_last()->message : "None");

	return rv;
}


DWORD
WINAPI
ep_UpdateThread(void *lpvUnused)
{
	CONFIG_DATA *cd = GetConfigData();
	
	FILETIME ftLastLocalRuleWrite;
	FILETIME ftLastRemoteRuleWrite;
	if (cd->bUseLocalRuleFile) FileChanged(cd->szLocalYaraRuleFile, NULL, &ftLastLocalRuleWrite);
	if (cd->bUseRemoteRuleFile) FileChanged(cd->szRemoteYaraRuleFile, NULL, &ftLastRemoteRuleWrite);

	const DWORD dwUpdatePollInterval = cd->dwRemotePollIntervalMinutes * 60 * 1000;
	DWORD dwLastUpdatePoll = GetTickCount();
	DWORD dwLastFilePoll = GetTickCount();
	bool bFirstRun = true;

	// Sleep a random amount of time to prevent multiple systems from polling the Git server simultaneously
	if (cd->dwRemotePollIntervalOffsetRangeSeconds) {
		DWORD dwRandomData = rand();
		GetRandomData(&dwRandomData, sizeof(dwRandomData));
		if (dwRandomData > 0) {
			if (WaitForSingleObject(g_hStopEvent, (cd->dwRemotePollIntervalOffsetRangeSeconds*1000) % dwRandomData) == WAIT_OBJECT_0) return 0;
		}
	}

	do {
		bool bRestartService = false;

		// Poll the Git repo for an update
		if (cd->bUseRemoteGitUrl) {
			if (bFirstRun || (dwUpdatePollInterval && GetTickCount() - dwLastUpdatePoll >= dwUpdatePollInterval)) {
				if (DoUpdate(cd)) {
					// Update the file changed timestamp here since it may have just been changed; this avoids
					// detecting it as have been modified during the on-disk change detection below
					FileChanged(cd->szRemoteYaraRuleFile,  NULL, &ftLastRemoteRuleWrite);

					// Update received, see if it compiles
					WCHAR szError[512] = { '\0' };
					YARASCAN_CONTEXT *ctx = YarascanAlloc3(cd->szRemoteYaraRuleFile, szError, sizeof(szError));
					if (ctx) {
						Notice(L"Received update from %ls, reloading service", cd->szRemoteGitUrl);
						YarascanFree(ctx);
						bRestartService = true;
					} else {
						Warning(L"YARA rules update from %ls failed to compile; ignorning rule update: %ls", cd->szRemoteGitUrl, szError);
					}
				}

				bFirstRun = false;
				dwLastUpdatePoll = GetTickCount();
			}
		}

		// Check local/remote rule files for update
		if (cd->dwRuleFilePollIntervalTicks && GetTickCount() - dwLastFilePoll >= cd->dwRuleFilePollIntervalTicks) {
			if (cd->bUseLocalRuleFile) {
				if (FileChanged(cd->szLocalYaraRuleFile, &ftLastLocalRuleWrite, &ftLastLocalRuleWrite)) {
					Notice(L"Rule file changed: %ls", cd->szLocalYaraRuleFile);
					bRestartService = true;
				}
			}

			if (cd->bUseRemoteRuleFile) {
				if (FileChanged(cd->szRemoteYaraRuleFile, &ftLastRemoteRuleWrite, &ftLastRemoteRuleWrite)) {
					Notice(L"Rule file changed: %ls", cd->szRemoteYaraRuleFile);
					bRestartService = true;
				}
			}
			
			dwLastFilePoll = GetTickCount();
		}

		// Restart the service since a change has been detected
		if (bRestartService) {
			// The service should be restarted if the default yarascan context allocation succeeds (rules compile)
			WCHAR szError[512] = { '\0' };
			YARASCAN_CONTEXT *ctx = YarascanAllocDefault(szError, sizeof(szError), true, false);
			if (ctx) {
				// Rules compiled, request a soft restart of the service
				YarascanFree(ctx);
				Notice(L"Rules updated; requesting soft service restart");
				ProcFilterServiceRequestRestart();
			} else {
				Warning(L"Updated rules failed to compile: %ls", szError);
			}
		}
	} while (WaitForSingleObject(g_hStopEvent, 1000) == WAIT_TIMEOUT);

	return 0;
}


void
UpdateInit()
{
	CONFIG_DATA *cd = GetConfigData();

	LogDebugFmt("Entering UpdateInit()");

	// Determine if the git repo location changed
	bool bDelete = false;
	char szRemoteDirectory[MAX_PATH+1] = { '\0' };
	strlprintf(szRemoteDirectory, sizeof(szRemoteDirectory), "%ls", cd->szRemoteDirectory);
	git_repository *repo = NULL;
	int error = git_repository_open(&repo, szRemoteDirectory);
	if (!error) {
		LogDebugFmt("Opened repository");
		
		// Check out the head
		git_annotated_commit *commit = NULL;
		git_checkout_options checkout_options = GIT_CHECKOUT_OPTIONS_INIT;
		checkout_options.checkout_strategy = GIT_CHECKOUT_FORCE;
		git_checkout_head(repo, &checkout_options);
		error = git_annotated_commit_from_revspec(&commit, repo, "origin/master");
		if (!error && commit) {
			git_reset_from_annotated(repo, commit, GIT_RESET_HARD, &checkout_options);
		}
		if (commit) git_annotated_commit_free(commit);

		git_remote *remote = NULL;
		error = git_remote_lookup(&remote, repo, "origin");
		if (!error) {
			LogDebugFmt("Got origin");
			char szRemoteGitUrl[512] = { '\0' };
			strlprintf(szRemoteGitUrl, sizeof(szRemoteGitUrl), "%ls", cd->szRemoteGitUrl);
			const char *szOldUrl = git_remote_url(remote);
			if (szOldUrl && strlen(szRemoteGitUrl) > 0 && _stricmp(szRemoteGitUrl, szOldUrl) != 0) {
				LogDebugFmt("Old URL:%hs  NewUrl:%hs", szOldUrl, szRemoteGitUrl);
				Warning(L"Detected Git URL change (Old:%hs New:%hs), deleting old .git path",
					szOldUrl, szRemoteGitUrl);
				bDelete = true;
			}
			git_remote_free(remote);
		} else {
			LogDebugFmt("Failed to get origin");
		}

		git_repository_free(repo);
	} else {
		LogDebugFmt("Failed to open repository directory");
	}

	// Delete the old repo if necessary
	if (bDelete) {
		LogDebugFmt("Deleting update directory");
		WCHAR szRemoteDirectory[sizeof(CONFIG_DATA::szRemoteDirectory)+2] = { '\0' };
		wstrlprintf(szRemoteDirectory, sizeof(szRemoteDirectory)-(2*sizeof(WCHAR)), L"%ls", cd->szRemoteDirectory);
		SHFILEOPSTRUCTW op;
		ZeroMemory(&op, sizeof(op));
		op.wFunc = FO_DELETE;
		op.pFrom = szRemoteDirectory;
		op.pTo = NULL;
		op.fFlags = FOF_NOCONFIRMATION | FOF_SILENT;
		op.fFlags = FOF_ALLOWUNDO;
		SHFileOperationW(&op);
		LogDebugFmt("Deleted directory: %ls", szRemoteDirectory);
		CreateDirectoryExW(NULL, cd->szRemoteDirectory, NULL);
	}
	
	LogDebugFmt("Done checking git location");

	g_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!g_hStopEvent) Die("Unable to create stop event in update thread");

	HANDLE g_hStatsThread = CreateThread(NULL, 0, ep_UpdateThread, NULL, 0, NULL);
	if (!g_hStatsThread) Die("Unable to create update thread");
}


void
UpdateShutdown()
{
	SetEvent(g_hStopEvent);
	WaitForSingleObject(g_hUpdateThread, INFINITE);
	CloseHandle(g_hStopEvent);
	CloseHandle(g_hUpdateThread);
}

#endif
