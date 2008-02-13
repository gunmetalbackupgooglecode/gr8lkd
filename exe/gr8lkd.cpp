//
// gr8lkd control program
//
// [C] Great, 2007. http://hellknights.void.ru/
//
// Посвящается ProTeuS'у в часть его дня рождения
//
/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <windows.h>
#include <winioctl.h>
#include "resource.h"

//
// Drivers management
//

bool LoadDriver(char* path, char* name, DWORD* err)
{
	bool status = 1;
	*err = 0;
	SC_HANDLE hsvc, hsc = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
	if(!hsc)
		return 0;

	CHAR szFullPath[1024];
	GetFullPathName(path, sizeof(szFullPath), szFullPath, 0);

	static bool firstrun = 1;

	//DeleteDriver(name, err);
	
	if(firstrun)
		hsvc = CreateService(hsc, name, name, SERVICE_START|DELETE,
			SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
			szFullPath, 0, 0, 0, 0, 0);
	else
		hsvc = OpenService(hsc, name, SERVICE_START);

	if(!hsvc)
	{
		*err = GetLastError();
		status = 0;
		goto _cleanup;
	}
	
	if(!StartService(hsvc, 0, 0))
	{
		*err = GetLastError();
		status = 0;
	}
	
	CloseServiceHandle(hsvc);

_cleanup:
	CloseServiceHandle(hsc);
	firstrun = 0;
	return status;
}

// no need to delete / unload routines

// Display error
int error(HWND hWnd, DWORD err, char* fmt, char* caption)
{
	char *msg;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ALLOCATE_BUFFER, 0, err, 0, (LPTSTR) &msg, 256, 0);
	msg[lstrlen(msg)-3] = 0;
	char buffer[1024];
	wsprintf(buffer, fmt, msg);
	MessageBox(hWnd, buffer, caption, MB_ICONERROR);
	LocalFree(msg);
	return 0;
}

char* szCdoName = "\\\\.\\gr8lkdd_cdo";
char* szSysName = "gr8lkdd.sys";
char* szServiceName = "gr8lkdd";

HANDLE hCdo;

// IOCTLs
#define IOCTL_GR8LKDD_ENABLE_IRPS_FILTERING  CTL_CODE( FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_GR8LKDD_PASS_ALL_IRPS_DOWN     CTL_CODE( FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_GR8LKDD_QUERY_FILTERING_FLAG   CTL_CODE( FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS )

// Start filtering
BOOLEAN
DriverStart(
	)
{
	DWORD Written;

	if( !DeviceIoControl( hCdo, IOCTL_GR8LKDD_ENABLE_IRPS_FILTERING, NULL, 0, NULL, 0, &Written, NULL) )
	{
		error( NULL, GetLastError(), "DeviceIoControl() failed for CDO: %s", "gr8lkd control" );
		return FALSE;
	}

	return TRUE;
}

// Stop
BOOLEAN
DriverStop(
	)
{
	DWORD Written;

	if( !DeviceIoControl( hCdo, IOCTL_GR8LKDD_PASS_ALL_IRPS_DOWN, NULL, 0, NULL, 0, &Written, NULL) )
	{
		error( NULL, GetLastError(), "DeviceIoControl() failed for CDO: %s", "gr8lkd control" );
		return FALSE;
	}

	return TRUE;
}

// Query
BOOLEAN
IsDriverStarted(
	)
{
	DWORD Written;
	BOOLEAN IsStarted = FALSE;

	if( !DeviceIoControl( hCdo, IOCTL_GR8LKDD_QUERY_FILTERING_FLAG, NULL, 0, &IsStarted, 1, &Written, NULL) )
	{
		error( NULL, GetLastError(), "DeviceIoControl() failed for CDO: %s", "gr8lkd control" );
		return FALSE;
	}

	return IsStarted;
}

int CALLBACK DlgProc( HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam )
{
	DWORD err;
	static BOOLEAN loaded = false, started = false;
	BOOL status;

	switch( msg )
	{
	case WM_INITDIALOG:

		hCdo = CreateFile( szCdoName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,  OPEN_EXISTING, 0, 0 );

		if( hCdo != INVALID_HANDLE_VALUE )
		{
			loaded = true;
			started = IsDriverStarted( );
			SetDlgItemText(hWnd, IDC_STATUS, "Loaded");

			if(started) SetDlgItemText(hWnd, IDC_STATUS, "Loaded & started");
		}
		break;
		
	case WM_COMMAND:

		switch( wParam )
		{
		case IDCANCEL:

			EndDialog(hWnd, 0);
			return 0;

		case IDC_LOAD:

			status = LoadDriver( szSysName, szServiceName, &err );
			if(!status)
			{
				SetDlgItemText(hWnd, IDC_STATUS, "Driver failed to load");
				error(hWnd, err, "Failed to load driver [%s].\nMake sure you are Administrator and the file specified exists", "Error loading driver");
			}
			else
			{
				SetDlgItemText(hWnd, IDC_STATUS, "Loaded");
				loaded = 1;

				hCdo = CreateFile( szCdoName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,  OPEN_EXISTING, 0, 0 );
			}
			break;

		case IDC_START:

			if( started )
			{
				MessageBox(hWnd, "Driver has already started filtering IRPs\n", 0, MB_ICONERROR);
				break;
			}

			if( !DriverStart( ) )
			{
				MessageBox(hWnd, "Driver can't start filtering now. Try again later", 0, MB_ICONERROR);
				break;
			}

			SetDlgItemText(hWnd, IDC_STATUS, "Loaded & started");
			started = true;
			break;
			
		case IDC_STOP:

			if( !started )
			{
				MessageBox(hWnd, "Driver has already stopped filtering IRPs\n", 0, MB_ICONERROR);
				break;
			}

			if( !DriverStop( ) )
			{
				MessageBox(hWnd, "Driver can't stop filtering now. Try again later", 0, MB_ICONERROR);
				break;
			}

			SetDlgItemText(hWnd, IDC_STATUS, "Loaded & stopped");
			started = false;
			break;
		}
		break;

	}

	return 0;
}

int APIENTRY WinMain( HINSTANCE, HINSTANCE, LPSTR, int )
{
	return DialogBoxParam( GetModuleHandle(0), MAKEINTRESOURCE(IDD_CONTROL_DIALOG), HWND_DESKTOP, DlgProc, 0 );
}