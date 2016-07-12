
#include <Windows.h>

#include "isadmin.hpp"

bool
IsAdmin()
{
	bool rv = false;

	BOOL bIsAdmin = FALSE;
	
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	PSID AdminGroup;
	if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminGroup)) {
		if (CheckTokenMembership(NULL, AdminGroup, &bIsAdmin) && bIsAdmin) {
			rv = true;
		}
		FreeSid(AdminGroup);
	}

	return rv;
}
