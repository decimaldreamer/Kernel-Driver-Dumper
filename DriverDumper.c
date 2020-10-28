#include "DriverDumper.h"

#include <stdio.h>
#include <Windows.h>
BOOL PrintKernelModules()
{
	BOOL bPrintHeader = TRUE;

	HMODULE hNTDll = LoadLibraryW(L"ntdll.dll");
	if (!hNTDll)
	{
		printf("error loading ntdll.dll (%d)\n", GetLastError());
		return FALSE;
	}
	ZwQuerySystemInformationType ZwQuerySystemInformation = (ZwQuerySystemInformationType)GetProcAddress(hNTDll, "ZwQuerySystemInformation");
	if (!ZwQuerySystemInformation)
	{
		printf("error GetProcAddress(\"ZwQuerySystemInformation\") (%d)\n", GetLastError());
		FreeLibrary(hNTDll);
		return FALSE;
	}

	SYSTEM_ALL_MODULES* pSysAllModules = NULL;
	NTSTATUS ntStatus = 0;
	DWORD dwBytesIo;
	ntStatus = ZwQuerySystemInformation(11, pSysAllModules, 0, &dwBytesIo);
	if (ntStatus == STATUS_INFO_LENGTH_MISMATCH)
	{
		pSysAllModules = (SYSTEM_ALL_MODULES*)VirtualAlloc(NULL, dwBytesIo + 64LL, MEM_COMMIT, PAGE_READWRITE);
		if (!pSysAllModules)
		{
			printf("error VirtualAlloc(%d) (%d)\n", dwBytesIo + 64LL, GetLastError());
			FreeLibrary(hNTDll);
			return FALSE;
		}
		RtlZeroMemory(pSysAllModules, dwBytesIo);

		ntStatus = ZwQuerySystemInformation(11, pSysAllModules, dwBytesIo, &dwBytesIo);
		FreeLibrary(hNTDll);
		if (STATUS_SUCCESS == ntStatus)
		{
			for (unsigned i = 0; i < pSysAllModules->dwNumOfModules; i++) {
				SYSTEM_MODULE_INFORMATION curMod = pSysAllModules->modules[i];
				LPSTR lpTargetModName = curMod.ImageName + curMod.ModuleNameOffset;

				if (bPrintHeader)
				{
					printf("Driver Dumper by 0x7ff | Enjoy while using. \n");
					printf("%-" MAX_DRIVER_NAME_LENGTH_STR "s\t%-16s\t%-16s\r\n", "Driver Name", "Base", "Size");
					printf("%-" MAX_DRIVER_NAME_LENGTH_STR "s\t%-16s\t%-16s\r\n", "-----------", "----", "----");
					bPrintHeader = FALSE;
				}
				printf("%-0" MAX_DRIVER_NAME_LENGTH_STR "s\t0x%016x\t0x%016x\r\n", lpTargetModName, curMod.Base, curMod.Size);
			}
		}
		VirtualFree(pSysAllModules, 0, MEM_RELEASE);
	}
	else
	{
		FreeLibrary(hNTDll);
		printf("error ZwQuerySystemInformation() unexpected NT_STATUS 0x%08x (%d)", ntStatus, GetLastError());
		return FALSE;
	}

	return TRUE;
}

int wmain()
{
	return PrintKernelModules() ? EXIT_SUCCESS : EXIT_FAILURE;
}