#include "DriverDumper.h"
#include <stdio.h>
#include <Windows.h>
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <VersionHelpers.h>

// Global variables
OPTIONS g_Options = { 0 };
PSYSTEM_ALL_MODULES g_pSysAllModules = NULL;

// Function implementations
BOOL IsAdmin()
{
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup))
    {
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin))
        {
            isAdmin = FALSE;
        }
        FreeSid(AdministratorsGroup);
    }
    
    return isAdmin;
}

void LogMessage(LPCSTR message)
{
    FILE* logFile = fopen(LOG_FILE_NAME, "a");
    if (logFile)
    {
        time_t now;
        time(&now);
        char timeStr[26];
        ctime_s(timeStr, sizeof(timeStr), &now);
        timeStr[strlen(timeStr) - 1] = '\0'; // Remove newline
        
        fprintf(logFile, "[%s] %s\n", timeStr, message);
        fclose(logFile);
    }
}

BOOL CalculateDriverHash(LPCSTR driverPath, LPSTR hashBuffer)
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE pbHashObject = NULL;
    PBYTE pbHash = NULL;
    DWORD cbHashObject = 0;
    DWORD cbHash = 0;
    DWORD cbData = 0;
    BOOL result = FALSE;
    
    // Open algorithm provider
    if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
    {
        LogMessage("BCryptOpenAlgorithmProvider failed");
        goto Cleanup;
    }
    
    // Calculate the size of the buffer to hold the hash object
    if (BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0) != 0)
    {
        LogMessage("BCryptGetProperty failed");
        goto Cleanup;
    }
    
    // Allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (pbHashObject == NULL)
    {
        LogMessage("Memory allocation failed");
        goto Cleanup;
    }
    
    // Calculate the length of the hash
    if (BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0) != 0)
    {
        LogMessage("BCryptGetProperty failed");
        goto Cleanup;
    }
    
    // Allocate the hash buffer on the heap
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (pbHash == NULL)
    {
        LogMessage("Memory allocation failed");
        goto Cleanup;
    }
    
    // Create a hash
    if (BCryptCreateHash(hAlgorithm, &hHash, pbHashObject, cbHashObject, NULL, 0, 0) != 0)
    {
        LogMessage("BCryptCreateHash failed");
        goto Cleanup;
    }
    
    // Read the file and hash it
    HANDLE hFile = CreateFileA(driverPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        LogMessage("CreateFile failed");
        goto Cleanup;
    }
    
    BYTE buffer[HASH_BUFFER_SIZE];
    DWORD bytesRead;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0)
    {
        if (BCryptHashData(hHash, buffer, bytesRead, 0) != 0)
        {
            LogMessage("BCryptHashData failed");
            CloseHandle(hFile);
            goto Cleanup;
        }
    }
    CloseHandle(hFile);
    
    // Finish the hash
    if (BCryptFinishHash(hHash, pbHash, cbHash, 0) != 0)
    {
        LogMessage("BCryptFinishHash failed");
        goto Cleanup;
    }
    
    // Convert hash to hex string
    for (DWORD i = 0; i < cbHash; i++)
    {
        sprintf_s(hashBuffer + (i * 2), 3, "%02x", pbHash[i]);
    }
    
    result = TRUE;
    
Cleanup:
    if (hHash)
        BCryptDestroyHash(hHash);
    if (hAlgorithm)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbHashObject)
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (pbHash)
        HeapFree(GetProcessHeap(), 0, pbHash);
    
    return result;
}

BOOL VerifyDriverSignature(LPCSTR driverPath)
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
    
    LONG lStatus = WinVerifyTrust(NULL, &ActionGuid, &WinTrustData);
    
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &ActionGuid, &WinTrustData);
    
    return (lStatus == ERROR_SUCCESS);
}

BOOL GetDriverVersion(LPCSTR driverPath, LPSTR versionBuffer)
{
    DWORD dwHandle;
    DWORD dwSize = GetFileVersionInfoSizeA(driverPath, &dwHandle);
    if (dwSize == 0)
        return FALSE;
        
    LPVOID lpData = HeapAlloc(GetProcessHeap(), 0, dwSize);
    if (!lpData)
        return FALSE;
        
    if (!GetFileVersionInfoA(driverPath, dwHandle, dwSize, lpData))
    {
        HeapFree(GetProcessHeap(), 0, lpData);
        return FALSE;
    }
    
    VS_FIXEDFILEINFO* pFileInfo;
    UINT uLen;
    if (!VerQueryValueA(lpData, "\\", (LPVOID*)&pFileInfo, &uLen))
    {
        HeapFree(GetProcessHeap(), 0, lpData);
        return FALSE;
    }
    
    sprintf_s(versionBuffer, 32, "%d.%d.%d.%d",
        HIWORD(pFileInfo->dwFileVersionMS),
        LOWORD(pFileInfo->dwFileVersionMS),
        HIWORD(pFileInfo->dwFileVersionLS),
        LOWORD(pFileInfo->dwFileVersionLS));
        
    HeapFree(GetProcessHeap(), 0, lpData);
    return TRUE;
}

BOOL PrintKernelModules()
{
    if (!IsAdmin())
    {
        printf("Bu program yönetici hakları gerektirir.\n");
        return FALSE;
    }

    BOOL bPrintHeader = TRUE;
    HMODULE hNTDll = LoadLibraryW(L"ntdll.dll");
    if (!hNTDll)
    {
        printf("ntdll.dll yüklenirken hata oluştu (%d)\n", GetLastError());
        return FALSE;
    }

    ZwQuerySystemInformationType ZwQuerySystemInformation = (ZwQuerySystemInformationType)GetProcAddress(hNTDll, "ZwQuerySystemInformation");
    if (!ZwQuerySystemInformation)
    {
        printf("GetProcAddress(\"ZwQuerySystemInformation\") hatası (%d)\n", GetLastError());
        FreeLibrary(hNTDll);
        return FALSE;
    }

    NTSTATUS ntStatus = 0;
    DWORD dwBytesIo;

    ntStatus = ZwQuerySystemInformation(11, g_pSysAllModules, 0, &dwBytesIo);
    if (ntStatus == STATUS_INFO_LENGTH_MISMATCH)
    {
        g_pSysAllModules = (PSYSTEM_ALL_MODULES)VirtualAlloc(NULL, dwBytesIo + 64LL, MEM_COMMIT, PAGE_READWRITE);
        if (!g_pSysAllModules)
        {
            printf("VirtualAlloc hatası (%d) (%d)\n", dwBytesIo + 64LL, GetLastError());
            FreeLibrary(hNTDll);
            return FALSE;
        }

        RtlZeroMemory(g_pSysAllModules, dwBytesIo);

        ntStatus = ZwQuerySystemInformation(11, g_pSysAllModules, dwBytesIo, &dwBytesIo);
        FreeLibrary(hNTDll);

        if (STATUS_SUCCESS == ntStatus)
        {
            for (unsigned i = 0; i < g_pSysAllModules->dwNumOfModules; i++)
            {
                SYSTEM_MODULE_INFORMATION* curMod = &g_pSysAllModules->modules[i];
                LPSTR lpTargetModName = curMod->ImageName + curMod->ModuleNameOffset;

                if (bPrintHeader)
                {
                    printf("Driver Dumper by 0x7ff | Kullandığınız sürece keyfini çıkarın.\n");
                    printf("%-" MAX_DRIVER_NAME_LENGTH_STR "s\t%-16s\t%-16s\t%-10s\t%-32s\n", 
                        "Sürücü İsmi", "Base", "Size", "İmzalı", "Versiyon");
                    printf("%-" MAX_DRIVER_NAME_LENGTH_STR "s\t%-16s\t%-16s\t%-10s\t%-32s\n", 
                        "-----------", "----", "----", "------", "--------");
                    bPrintHeader = FALSE;
                }

                // Get additional information
                CHAR driverPath[MAX_PATH_LENGTH];
                sprintf_s(driverPath, MAX_PATH_LENGTH, "\\SystemRoot\\System32\\drivers\\%s", lpTargetModName);
                
                curMod->IsSigned = VerifyDriverSignature(driverPath);
                GetDriverVersion(driverPath, curMod->Version);
                CalculateDriverHash(driverPath, curMod->Hash);

                printf("%-0" MAX_DRIVER_NAME_LENGTH_STR "s\t0x%016x\t0x%016x\t%-10s\t%-32s\n", 
                    lpTargetModName, curMod->Base, curMod->Size, 
                    curMod->IsSigned ? "Evet" : "Hayır", curMod->Version);
            }
        }

        VirtualFree(g_pSysAllModules, 0, MEM_RELEASE);
    }
    else
    {
        FreeLibrary(hNTDll);
        printf("ZwQuerySystemInformation() beklenmedik NT_STATUS 0x%08x (%d)\n", ntStatus, GetLastError());
        return FALSE;
    }

    return TRUE;
}

void PrintMemoryStatistics()
{
    if (!g_pSysAllModules)
        return;

    ULONG totalSize = 0;
    for (unsigned i = 0; i < g_pSysAllModules->dwNumOfModules; i++)
    {
        totalSize += g_pSysAllModules->modules[i].Size;
    }

    printf("\nBellek İstatistikleri:\n");
    printf("Toplam Sürücü Sayısı: %d\n", g_pSysAllModules->dwNumOfModules);
    printf("Toplam Bellek Kullanımı: %lu bytes (%.2f MB)\n", 
        totalSize, (float)totalSize / (1024 * 1024));
}

void PrintSecurityStatus()
{
    if (!g_pSysAllModules)
        return;

    int signedCount = 0;
    for (unsigned i = 0; i < g_pSysAllModules->dwNumOfModules; i++)
    {
        if (g_pSysAllModules->modules[i].IsSigned)
            signedCount++;
    }

    printf("\nGüvenlik Durumu:\n");
    printf("İmzalı Sürücü Sayısı: %d/%d (%.2f%%)\n", 
        signedCount, g_pSysAllModules->dwNumOfModules,
        (float)signedCount / g_pSysAllModules->dwNumOfModules * 100);
}

int wmain(int argc, wchar_t* argv[])
{
    // Parse command line arguments
    for (int i = 1; i < argc; i++)
    {
        if (wcscmp(argv[i], L"-f") == 0 || wcscmp(argv[i], L"--file") == 0)
        {
            if (i + 1 < argc)
            {
                g_Options.exportToFile = TRUE;
                wcstombs_s(NULL, g_Options.exportFileName, argv[i + 1], MAX_PATH_LENGTH);
                i++;
            }
        }
        else if (wcscmp(argv[i], L"-s") == 0 || wcscmp(argv[i], L"--search") == 0)
        {
            if (i + 1 < argc)
            {
                wcstombs_s(NULL, g_Options.searchName, argv[i + 1], MAX_PATH_LENGTH);
                i++;
            }
        }
        else if (wcscmp(argv[i], L"-h") == 0 || wcscmp(argv[i], L"--hash") == 0)
        {
            g_Options.showHashes = TRUE;
        }
        else if (wcscmp(argv[i], L"-v") == 0 || wcscmp(argv[i], L"--verbose") == 0)
        {
            g_Options.verboseMode = TRUE;
        }
        else if (wcscmp(argv[i], L"-d") == 0 || wcscmp(argv[i], L"--dependencies") == 0)
        {
            g_Options.showDependencies = TRUE;
        }
        else if (wcscmp(argv[i], L"-t") == 0 || wcscmp(argv[i], L"--time") == 0)
        {
            g_Options.showLoadTimes = TRUE;
        }
        else if (wcscmp(argv[i], L"-m") == 0 || wcscmp(argv[i], L"--memory") == 0)
        {
            g_Options.showMemoryStats = TRUE;
        }
    }

    if (!PrintKernelModules())
        return EXIT_FAILURE;

    if (g_Options.showMemoryStats)
        PrintMemoryStatistics();

    if (g_Options.verboseMode)
        PrintSecurityStatus();

    return EXIT_SUCCESS;
}
