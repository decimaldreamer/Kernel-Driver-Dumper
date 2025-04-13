#ifndef DRIVER_DUMPER_HEADER
#define DRIVER_DUMPER_HEADER

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Status codes
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

// Constants
#define MAX_DRIVER_NAME_LENGTH_STR "90"
#define MAX_PATH_LENGTH 260
#define HASH_BUFFER_SIZE 4096
#define LOG_FILE_NAME "DriverDumper.log"

// Function pointer types
typedef NTSTATUS (WINAPI*ZwQuerySystemInformationType)(DWORD SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS (WINAPI*ZwQuerySystemTimeType)(PLARGE_INTEGER SystemTime);

// Structures
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
	LARGE_INTEGER LoadTime;
	CHAR Hash[65];
	BOOL IsSigned;
	CHAR Version[32];
	CHAR Dependencies[MAX_PATH_LENGTH];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_ALL_MODULES {
	DWORD dwNumOfModules;
	SYSTEM_MODULE_INFORMATION modules[ANYSIZE_ARRAY];
} SYSTEM_ALL_MODULES, * PSYSTEM_ALL_MODULES;

// Function declarations
BOOL PrintKernelModules();
BOOL IsAdmin();
BOOL CalculateDriverHash(LPCSTR driverPath, LPSTR hashBuffer);
BOOL VerifyDriverSignature(LPCSTR driverPath);
BOOL GetDriverVersion(LPCSTR driverPath, LPSTR versionBuffer);
BOOL GetDriverDependencies(LPCSTR driverPath, LPSTR dependenciesBuffer);
BOOL ExportToFile(LPCSTR fileName);
BOOL SearchDriver(LPCSTR driverName);
void LogMessage(LPCSTR message);
void PrintMemoryStatistics();
void PrintLoadTimes();
void PrintDependencies();
void PrintSecurityStatus();

// Command line options
typedef struct _OPTIONS {
	BOOL exportToFile;
	CHAR exportFileName[MAX_PATH_LENGTH];
	BOOL showHashes;
	BOOL verboseMode;
	BOOL showDependencies;
	BOOL showLoadTimes;
	BOOL showMemoryStats;
	CHAR searchName[MAX_PATH_LENGTH];
} OPTIONS, *POPTIONS;

#endif 