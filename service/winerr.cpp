
#include "winerr.hpp"


const WCHAR*
ErrorText(DWORD dwErrorCode)
{
	DWORD dwLastError = GetLastError();

	static __declspec(thread) WCHAR msg[256];
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), msg, sizeof(msg)/sizeof(WCHAR), NULL);
	
	// remove undesireable characters from the result
	size_t j = 0;
	for (size_t i = 0; msg[i] && j < _countof(msg) - 1; ++i) {
		if (!wcschr(L"\r\n\t", msg[i])) {
			msg[j++] = msg[i];	
		}
	}
	msg[j] = '\0';

	SetLastError(dwLastError);

	return msg;
}
