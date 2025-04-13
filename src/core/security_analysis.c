#include "driverdumper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>

int VerifyDriverSignature(const char* driverPath)
{
    if (!driverPath)
        return STATUS_INVALID_PARAMETER;

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

    LONG lStatus = WinVerifyTrust(NULL, &ActionGuid, &WinTrustData);

    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &ActionGuid, &WinTrustData);

    return (lStatus == ERROR_SUCCESS);
}

int AnalyzeDriverVulnerabilities(const char* driverPath)
{
    if (!driverPath)
        return STATUS_INVALID_PARAMETER;

    // Open driver file
    FILE* file = fopen(driverPath, "rb");
    if (!file)
        return STATUS_ERROR;

    // Get file size
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Read file into memory
    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer)
    {
        fclose(file);
        return STATUS_ERROR;
    }

    fread(buffer, 1, fileSize, file);
    fclose(file);

    // Check for common vulnerabilities
    int vulnerabilityCount = 0;

    // Check for buffer overflow vulnerabilities
    for (long i = 0; i < fileSize - 4; i++)
    {
        if (buffer[i] == 0x8B && buffer[i + 1] == 0x45 && buffer[i + 2] == 0xFC)
        {
            LogMessage("Potential buffer overflow vulnerability detected", 1);
            vulnerabilityCount++;
        }
    }

    // Check for integer overflow vulnerabilities
    for (long i = 0; i < fileSize - 4; i++)
    {
        if (buffer[i] == 0x0F && buffer[i + 1] == 0xAF)
        {
            LogMessage("Potential integer overflow vulnerability detected", 1);
            vulnerabilityCount++;
        }
    }

    // Check for use-after-free vulnerabilities
    for (long i = 0; i < fileSize - 4; i++)
    {
        if (buffer[i] == 0x8B && buffer[i + 1] == 0x45 && buffer[i + 2] == 0xF8)
        {
            LogMessage("Potential use-after-free vulnerability detected", 1);
            vulnerabilityCount++;
        }
    }

    // Check for race condition vulnerabilities
    for (long i = 0; i < fileSize - 4; i++)
    {
        if (buffer[i] == 0x8B && buffer[i + 1] == 0x45 && buffer[i + 2] == 0xF4)
        {
            LogMessage("Potential race condition vulnerability detected", 1);
            vulnerabilityCount++;
        }
    }

    free(buffer);

    if (vulnerabilityCount > 0)
    {
        char message[256];
        sprintf_s(message, sizeof(message), "Found %d potential vulnerabilities", vulnerabilityCount);
        LogMessage(message, 1);
    }

    return STATUS_SUCCESS;
}

int CheckDriverBehavior(const char* driverPath)
{
    if (!driverPath)
        return STATUS_INVALID_PARAMETER;

    // Open driver file
    FILE* file = fopen(driverPath, "rb");
    if (!file)
        return STATUS_ERROR;

    // Get file size
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Read file into memory
    BYTE* buffer = (BYTE*)malloc(fileSize);
    if (!buffer)
    {
        fclose(file);
        return STATUS_ERROR;
    }

    fread(buffer, 1, fileSize, file);
    fclose(file);

    // Check for suspicious behavior patterns
    int suspiciousCount = 0;

    // Check for kernel mode code execution
    for (long i = 0; i < fileSize - 4; i++)
    {
        if (buffer[i] == 0x0F && buffer[i + 1] == 0x01 && buffer[i + 2] == 0xC1)
        {
            LogMessage("Potential kernel mode code execution detected", 1);
            suspiciousCount++;
        }
    }

    // Check for direct hardware access
    for (long i = 0; i < fileSize - 4; i++)
    {
        if (buffer[i] == 0xED && buffer[i + 1] == 0xEC)
        {
            LogMessage("Potential direct hardware access detected", 1);
            suspiciousCount++;
        }
    }

    // Check for memory manipulation
    for (long i = 0; i < fileSize - 4; i++)
    {
        if (buffer[i] == 0x8B && buffer[i + 1] == 0x45 && buffer[i + 2] == 0xF0)
        {
            LogMessage("Potential memory manipulation detected", 1);
            suspiciousCount++;
        }
    }

    // Check for system call hooking
    for (long i = 0; i < fileSize - 4; i++)
    {
        if (buffer[i] == 0x8B && buffer[i + 1] == 0x45 && buffer[i + 2] == 0xEC)
        {
            LogMessage("Potential system call hooking detected", 1);
            suspiciousCount++;
        }
    }

    free(buffer);

    if (suspiciousCount > 0)
    {
        char message[256];
        sprintf_s(message, sizeof(message), "Found %d suspicious behavior patterns", suspiciousCount);
        LogMessage(message, 1);
    }

    return STATUS_SUCCESS;
}

int CalculateSecurityScore(const char* driverPath, double* score)
{
    if (!driverPath || !score)
        return STATUS_INVALID_PARAMETER;

    double totalScore = 100.0;

    // Check signature (40%)
    if (!VerifyDriverSignature(driverPath))
    {
        totalScore -= 40.0;
        LogMessage("Driver is not signed", 1);
    }

    // Check vulnerabilities (30%)
    int vulnerabilityCount = 0;
    AnalyzeDriverVulnerabilities(driverPath);
    totalScore -= vulnerabilityCount * 5.0;

    // Check behavior (20%)
    int suspiciousCount = 0;
    CheckDriverBehavior(driverPath);
    totalScore -= suspiciousCount * 4.0;

    // Check memory protection (10%)
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((PVOID)driverPath, &mbi, sizeof(mbi)))
    {
        if (!(mbi.Protect & PAGE_GUARD))
        {
            totalScore -= 5.0;
            LogMessage("Memory region lacks guard page protection", 1);
        }

        if (mbi.Protect & PAGE_EXECUTE_READWRITE)
        {
            totalScore -= 5.0;
            LogMessage("Memory region has both execute and write permissions", 1);
        }
    }

    // Ensure score is within valid range
    if (totalScore < 0.0)
        totalScore = 0.0;
    else if (totalScore > 100.0)
        totalScore = 100.0;

    *score = totalScore;

    char message[256];
    sprintf_s(message, sizeof(message), "Security score: %.2f", totalScore);
    LogMessage(message, 0);

    return STATUS_SUCCESS;
}

int DetectMaliciousDrivers(DriverList* list)
{
    if (!list)
        return STATUS_INVALID_PARAMETER;

    int maliciousCount = 0;

    for (size_t i = 0; i < list->count; i++)
    {
        DriverInfo* driver = &list->drivers[i];
        double securityScore;

        if (CalculateSecurityScore(driver->name, &securityScore) == STATUS_SUCCESS)
        {
            if (securityScore < 50.0)
            {
                char message[256];
                sprintf_s(message, sizeof(message),
                    "Potential malicious driver detected: %s (Score: %.2f)",
                    driver->name, securityScore);
                LogMessage(message, 2);
                maliciousCount++;
            }
        }
    }

    if (maliciousCount > 0)
    {
        char message[256];
        sprintf_s(message, sizeof(message), "Found %d potential malicious drivers", maliciousCount);
        LogMessage(message, 2);
    }

    return STATUS_SUCCESS;
}

int AnalyzeDriverPermissions(const char* driverPath)
{
    if (!driverPath)
        return STATUS_INVALID_PARAMETER;

    // Get file security information
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD dwLength = 0;

    if (GetFileSecurityA(driverPath, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION, pSD, 0, &dwLength) || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        return STATUS_ERROR;
    }

    pSD = (PSECURITY_DESCRIPTOR)malloc(dwLength);
    if (!pSD)
        return STATUS_ERROR;

    if (!GetFileSecurityA(driverPath, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION, pSD, dwLength, &dwLength))
    {
        free(pSD);
        return STATUS_ERROR;
    }

    // Check owner
    PSID pOwnerSid = NULL;
    BOOL bOwnerDefaulted = FALSE;

    if (!GetSecurityDescriptorOwner(pSD, &pOwnerSid, &bOwnerDefaulted))
    {
        free(pSD);
        return STATUS_ERROR;
    }

    // Check DACL
    PACL pDacl = NULL;
    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;

    if (!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted))
    {
        free(pSD);
        return STATUS_ERROR;
    }

    // Analyze permissions
    if (!bDaclPresent || !pDacl)
    {
        LogMessage("Driver has no DACL (full access to everyone)", 2);
    }
    else
    {
        ACL_SIZE_INFORMATION aclSizeInfo;
        if (GetAclInformation(pDacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation))
        {
            for (DWORD i = 0; i < aclSizeInfo.AceCount; i++)
            {
                PACE_HEADER pAceHeader;
                if (GetAce(pDacl, i, (LPVOID*)&pAceHeader))
                {
                    if (pAceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
                    {
                        PACCESS_ALLOWED_ACE pAce = (PACCESS_ALLOWED_ACE)pAceHeader;
                        if (pAce->Mask & GENERIC_ALL)
                        {
                            LogMessage("Driver has full access permissions", 1);
                        }
                    }
                }
            }
        }
    }

    free(pSD);
    return STATUS_SUCCESS;
} 