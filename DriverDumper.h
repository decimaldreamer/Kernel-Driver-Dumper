#ifndef DRIVER_DUMPER_HEADER
#define DRIVER_DUMPER_HEADER

#include <Windows.h>

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#define MAX_DRIVER_NAME_LENGTH_STR "90"

typedef NTSTATUS (WINAPI*ZwQuerySystemInformationType)(DWORD SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

typedef struct _SYSTEM_MODULE_INFORMATION { 
	PVOID Reserved[2];						
	PVOID Base;								
	ULONG Size;								
	ULONG Flags;							
	USHORT Index;							
	USHORT Unknown;							
	USHORT LoadCount;						
	USHORT ModuleNameOffset;				
	CHAR ImageName[256];					
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_ALL_MODULES {
	DWORD dwNumOfModules;
	SYSTEM_MODULE_INFORMATION modules[ANYSIZE_ARRAY];
} SYSTEM_ALL_MODULES, * PSYSTEM_ALL_MODULES;

#endif 