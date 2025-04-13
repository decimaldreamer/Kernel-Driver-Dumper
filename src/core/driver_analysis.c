#include "driverdumper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>

int GetDriverInfo(const char* driverName, DriverInfo* info)
{
    if (!driverName || !info)
        return STATUS_INVALID_PARAMETER;

    // Get driver path
    char driverPath[MAX_PATH_LENGTH];
    sprintf_s(driverPath, MAX_PATH_LENGTH, "\\SystemRoot\\System32\\drivers\\%s", driverName);

    // Get basic information
    strcpy_s(info->name, MAX_DRIVER_NAME_LENGTH, driverName);

    // Get version information
    if (GetDriverVersion(driverPath, info->version) != STATUS_SUCCESS)
        strcpy_s(info->version, 32, "Unknown");

    // Calculate hash
    if (CalculateHash(driverPath, info->hash) != STATUS_SUCCESS)
        memset(info->hash, 0, 65);

    // Verify signature
    info->isSigned = VerifyDriverSignature(driverPath);

    // Get certificate information
    if (info->isSigned)
    {
        WINTRUST_FILE_INFO FileData = { 0 };
        WINTRUST_DATA WinTrustData = { 0 };
        GUID ActionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
        FileData.pcwszFilePath = driverPath;
        FileData.hFile = NULL;
        FileData.pgKnownSubject = NULL;

        WinTrustData.cbStruct = sizeof(WinTrustData);
        WinTrustData.pPolicyCallbackData = NULL;
        WinTrustData.pSIPClientData = NULL;
        WinTrustData.dwUIChoice = WTD_UI_NONE;
        WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        WinTrustData.pFile = &FileData;
        WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        WinTrustData.hWVTStateData = NULL;
        WinTrustData.pwszURLReference = NULL;
        WinTrustData.dwUIContext = 0;

        CRYPT_PROVIDER_DATA* pProvData = NULL;
        CRYPT_PROVIDER_SGNR* pSigner = NULL;
        CRYPT_PROVIDER_CERT* pCert = NULL;

        if (WinVerifyTrust(NULL, &ActionGuid, &WinTrustData) == ERROR_SUCCESS)
        {
            pProvData = WTHelperProvDataFromStateData(WinTrustData.hWVTStateData);
            if (pProvData)
            {
                pSigner = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
                if (pSigner)
                {
                    pCert = WTHelperGetProvCertFromChain(pSigner, 0);
                    if (pCert)
                    {
                        char certInfo[256];
                        DWORD certInfoLen = sizeof(certInfo);
                        if (CertGetNameStringA(pCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
                            certInfo, certInfoLen) > 1)
                        {
                            strcpy_s(info->certificateInfo, 256, certInfo);
                        }
                    }
                }
            }
        }

        WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &ActionGuid, &WinTrustData);
    }

    // Get memory protection information
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(info->baseAddress, &mbi, sizeof(mbi)))
    {
        info->memoryProtection = mbi.Protect;
        info->hasASLR = (mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY) != 0;
        info->hasDEP = (mbi.Protect & PAGE_EXECUTE_READ) != 0;
    }

    return STATUS_SUCCESS;
}

int GetDriverMemoryInfo(const char* driverName, PVOID* regions, size_t* count)
{
    if (!driverName || !regions || !count)
        return STATUS_INVALID_PARAMETER;

    // Find driver in list
    DriverInfo* driver = NULL;
    for (size_t i = 0; i < g_driverList.count; i++)
    {
        if (strcmp(g_driverList.drivers[i].name, driverName) == 0)
        {
            driver = &g_driverList.drivers[i];
            break;
        }
    }

    if (!driver)
        return STATUS_NOT_FOUND;

    // Get memory regions
    PVOID address = driver->baseAddress;
    size_t regionCount = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (VirtualQuery(address, &mbi, sizeof(mbi)) && regionCount < 100)
    {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE)
        {
            regions[regionCount++] = mbi.BaseAddress;
        }
        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    *count = regionCount;
    return STATUS_SUCCESS;
}

int GetDriverSecurityInfo(const char* driverName, double* securityScore)
{
    if (!driverName || !securityScore)
        return STATUS_INVALID_PARAMETER;

    // Find driver in list
    DriverInfo* driver = NULL;
    for (size_t i = 0; i < g_driverList.count; i++)
    {
        if (strcmp(g_driverList.drivers[i].name, driverName) == 0)
        {
            driver = &g_driverList.drivers[i];
            break;
        }
    }

    if (!driver)
        return STATUS_NOT_FOUND;

    // Calculate security score
    double score = 0.0;

    // Signature check (40%)
    if (driver->isSigned)
        score += 40.0;

    // Memory protection (30%)
    if (driver->hasASLR)
        score += 15.0;
    if (driver->hasDEP)
        score += 15.0;

    // Version check (20%)
    if (strcmp(driver->version, "Unknown") != 0)
        score += 20.0;

    // Dependencies check (10%)
    if (strlen(driver->dependencies) > 0)
        score += 10.0;

    *securityScore = score;
    return STATUS_SUCCESS;
}

int GetDriverPerformanceInfo(const char* driverName, double* performanceScore)
{
    if (!driverName || !performanceScore)
        return STATUS_INVALID_PARAMETER;

    // Find driver in list
    DriverInfo* driver = NULL;
    for (size_t i = 0; i < g_driverList.count; i++)
    {
        if (strcmp(g_driverList.drivers[i].name, driverName) == 0)
        {
            driver = &g_driverList.drivers[i];
            break;
        }
    }

    if (!driver)
        return STATUS_NOT_FOUND;

    // Calculate performance score
    double score = 0.0;

    // Load time (40%)
    LARGE_INTEGER loadTime;
    if (MeasureDriverLoadTime(driverName, &loadTime) == STATUS_SUCCESS)
    {
        // Convert to milliseconds
        double loadTimeMs = (double)loadTime.QuadPart / 10000.0;
        if (loadTimeMs < 100)
            score += 40.0;
        else if (loadTimeMs < 500)
            score += 30.0;
        else if (loadTimeMs < 1000)
            score += 20.0;
        else
            score += 10.0;
    }

    // Memory usage (30%)
    if (driver->size < 1024 * 1024) // Less than 1MB
        score += 30.0;
    else if (driver->size < 5 * 1024 * 1024) // Less than 5MB
        score += 20.0;
    else if (driver->size < 10 * 1024 * 1024) // Less than 10MB
        score += 10.0;

    // Dependencies (20%)
    if (strlen(driver->dependencies) < 100)
        score += 20.0;
    else if (strlen(driver->dependencies) < 500)
        score += 15.0;
    else if (strlen(driver->dependencies) < 1000)
        score += 10.0;

    // Version (10%)
    if (strcmp(driver->version, "Unknown") != 0)
        score += 10.0;

    *performanceScore = score;
    return STATUS_SUCCESS;
}

int AnalyzeDriverVulnerabilities(const char* driverPath)
{
    if (!driverPath)
        return STATUS_INVALID_PARAMETER;

    // Check for common vulnerabilities
    FILE* file = fopen(driverPath, "rb");
    if (!file)
        return STATUS_ERROR;

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer)
    {
        fclose(file);
        return STATUS_ERROR;
    }

    fread(buffer, 1, fileSize, file);
    fclose(file);

    // Check for buffer overflow vulnerabilities
    for (long i = 0; i < fileSize - 4; i++)
    {
        if (buffer[i] == 0x8B && buffer[i + 1] == 0x45 && buffer[i + 2] == 0xFC)
        {
            // Potential buffer overflow
            LogMessage("Potential buffer overflow vulnerability detected", 1);
        }
    }

    // Check for integer overflow vulnerabilities
    for (long i = 0; i < fileSize - 4; i++)
    {
        if (buffer[i] == 0x0F && buffer[i + 1] == 0xAF)
        {
            // Potential integer overflow
            LogMessage("Potential integer overflow vulnerability detected", 1);
        }
    }

    free(buffer);
    return STATUS_SUCCESS;
}

int CheckDriverBehavior(const char* driverPath)
{
    if (!driverPath)
        return STATUS_INVALID_PARAMETER;

    // Check for suspicious behavior patterns
    FILE* file = fopen(driverPath, "rb");
    if (!file)
        return STATUS_ERROR;

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer)
    {
        fclose(file);
        return STATUS_ERROR;
    }

    fread(buffer, 1, fileSize, file);
    fclose(file);

    // Check for kernel mode code execution
    for (long i = 0; i < fileSize - 4; i++)
    {
        if (buffer[i] == 0x0F && buffer[i + 1] == 0x01 && buffer[i + 2] == 0xC1)
        {
            // Potential kernel mode code execution
            LogMessage("Potential kernel mode code execution detected", 1);
        }
    }

    // Check for direct hardware access
    for (long i = 0; i < fileSize - 4; i++)
    {
        if (buffer[i] == 0xED && buffer[i + 1] == 0xEC)
        {
            // Potential direct hardware access
            LogMessage("Potential direct hardware access detected", 1);
        }
    }

    free(buffer);
    return STATUS_SUCCESS;
}

int AnalyzeDependencies(const char* driverName)
{
    if (!driverName)
        return STATUS_INVALID_PARAMETER;

    // Get driver path
    char driverPath[MAX_PATH_LENGTH];
    sprintf_s(driverPath, MAX_PATH_LENGTH, "\\SystemRoot\\System32\\drivers\\%s", driverName);

    // Load driver as a module
    HMODULE hModule = LoadLibraryExA(driverPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hModule)
        return STATUS_ERROR;

    // Get import table
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    char dependencies[MAX_PATH_LENGTH] = { 0 };
    char* current = dependencies;

    // Process each import
    while (importDesc->Name)
    {
        const char* moduleName = (const char*)((BYTE*)hModule + importDesc->Name);
        size_t nameLen = strlen(moduleName);

        if (current + nameLen + 2 <= dependencies + MAX_PATH_LENGTH)
        {
            strcpy_s(current, MAX_PATH_LENGTH - (current - dependencies), moduleName);
            current += nameLen;
            *current++ = ';';
            *current = '\0';
        }

        importDesc++;
    }

    // Find driver in list and update dependencies
    for (size_t i = 0; i < g_driverList.count; i++)
    {
        if (strcmp(g_driverList.drivers[i].name, driverName) == 0)
        {
            strcpy_s(g_driverList.drivers[i].dependencies, MAX_PATH_LENGTH, dependencies);
            break;
        }
    }

    FreeLibrary(hModule);
    return STATUS_SUCCESS;
} 