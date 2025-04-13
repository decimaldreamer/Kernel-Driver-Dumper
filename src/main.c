#include "driverdumper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Global variables
static Config g_config = { 0 };
static DriverList g_driverList = { 0 };
static bool g_isInitialized = false;

// Function implementations
int InitializeDriverDumper(Config* config)
{
    if (g_isInitialized)
        return STATUS_ERROR;

    // Copy configuration
    memcpy(&g_config, config, sizeof(Config));

    // Initialize logging
    if (g_config.enableLogging)
    {
        FILE* logFile = fopen(g_config.logFile, "w");
        if (!logFile)
            return STATUS_ERROR;
        fclose(logFile);
    }

    // Initialize driver list
    g_driverList.capacity = 100;
    g_driverList.drivers = (DriverInfo*)malloc(g_driverList.capacity * sizeof(DriverInfo));
    if (!g_driverList.drivers)
        return STATUS_ERROR;

    g_driverList.count = 0;

    // Initialize subsystems
    if (g_config.enableGUI && InitializeGUI() != STATUS_SUCCESS)
        return STATUS_ERROR;

    if (g_config.enableAPI && InitializeAPI() != STATUS_SUCCESS)
        return STATUS_ERROR;

    if (g_config.enableWeb && StartWebInterface() != STATUS_SUCCESS)
        return STATUS_ERROR;

    g_isInitialized = true;
    return STATUS_SUCCESS;
}

int CleanupDriverDumper()
{
    if (!g_isInitialized)
        return STATUS_ERROR;

    // Cleanup subsystems
    if (g_config.enableWeb)
        StopWebInterface();

    if (g_config.enableAPI)
        StopAPIServer();

    // Free driver list
    if (g_driverList.drivers)
    {
        free(g_driverList.drivers);
        g_driverList.drivers = NULL;
    }

    g_isInitialized = false;
    return STATUS_SUCCESS;
}

int AnalyzeDrivers(DriverList* list, AnalysisType type)
{
    if (!g_isInitialized || !list)
        return STATUS_ERROR;

    // Perform analysis based on type
    switch (type)
    {
        case ANALYSIS_BASIC:
            // Basic driver information
            for (size_t i = 0; i < list->count; i++)
            {
                GetDriverInfo(list->drivers[i].name, &list->drivers[i]);
            }
            break;

        case ANALYSIS_MEMORY:
            // Memory analysis
            for (size_t i = 0; i < list->count; i++)
            {
                PVOID regions[100];
                size_t count = 0;
                GetDriverMemoryInfo(list->drivers[i].name, regions, &count);
                AnalyzeMemoryRegions(list->drivers[i].baseAddress, list->drivers[i].size);
            }
            break;

        case ANALYSIS_SECURITY:
            // Security analysis
            for (size_t i = 0; i < list->count; i++)
            {
                double score;
                GetDriverSecurityInfo(list->drivers[i].name, &score);
                list->drivers[i].securityScore = score;
            }
            break;

        case ANALYSIS_PERFORMANCE:
            // Performance analysis
            for (size_t i = 0; i < list->count; i++)
            {
                double score;
                GetDriverPerformanceInfo(list->drivers[i].name, &score);
            }
            break;

        case ANALYSIS_ADVANCED:
            // Advanced analysis
            for (size_t i = 0; i < list->count; i++)
            {
                AnalyzeDriverVulnerabilities(list->drivers[i].name);
                CheckDriverBehavior(list->drivers[i].name);
                AnalyzeDependencies(list->drivers[i].name);
            }
            break;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

int LogMessage(const char* message, int level)
{
    if (!g_config.enableLogging)
        return STATUS_SUCCESS;

    FILE* logFile = fopen(g_config.logFile, "a");
    if (!logFile)
        return STATUS_ERROR;

    time_t now;
    time(&now);
    char timeStr[26];
    ctime_s(timeStr, sizeof(timeStr), &now);
    timeStr[strlen(timeStr) - 1] = '\0';

    const char* levelStr;
    switch (level)
    {
        case 0: levelStr = "INFO"; break;
        case 1: levelStr = "WARNING"; break;
        case 2: levelStr = "ERROR"; break;
        default: levelStr = "UNKNOWN"; break;
    }

    fprintf(logFile, "[%s] [%s] %s\n", timeStr, levelStr, message);
    fclose(logFile);

    return STATUS_SUCCESS;
}

int main(int argc, char* argv[])
{
    // Initialize configuration
    Config config = {
        .enableLogging = true,
        .enableGUI = true,
        .enableAPI = true,
        .enableWeb = true,
        .enableTests = true,
        .defaultAnalysis = ANALYSIS_BASIC,
        .defaultFormat = FORMAT_HTML
    };
    strcpy_s(config.logFile, MAX_PATH_LENGTH, LOG_FILE_NAME);
    strcpy_s(config.configFile, MAX_PATH_LENGTH, CONFIG_FILE_NAME);

    // Initialize DriverDumper
    if (InitializeDriverDumper(&config) != STATUS_SUCCESS)
    {
        printf("Failed to initialize DriverDumper\n");
        return 1;
    }

    // Parse command line arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--analysis") == 0 && i + 1 < argc)
        {
            if (strcmp(argv[i + 1], "basic") == 0)
                config.defaultAnalysis = ANALYSIS_BASIC;
            else if (strcmp(argv[i + 1], "memory") == 0)
                config.defaultAnalysis = ANALYSIS_MEMORY;
            else if (strcmp(argv[i + 1], "security") == 0)
                config.defaultAnalysis = ANALYSIS_SECURITY;
            else if (strcmp(argv[i + 1], "performance") == 0)
                config.defaultAnalysis = ANALYSIS_PERFORMANCE;
            else if (strcmp(argv[i + 1], "advanced") == 0)
                config.defaultAnalysis = ANALYSIS_ADVANCED;
            i++;
        }
        else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc)
        {
            if (strcmp(argv[i + 1], "text") == 0)
                config.defaultFormat = FORMAT_TEXT;
            else if (strcmp(argv[i + 1], "html") == 0)
                config.defaultFormat = FORMAT_HTML;
            else if (strcmp(argv[i + 1], "pdf") == 0)
                config.defaultFormat = FORMAT_PDF;
            else if (strcmp(argv[i + 1], "json") == 0)
                config.defaultFormat = FORMAT_JSON;
            else if (strcmp(argv[i + 1], "xml") == 0)
                config.defaultFormat = FORMAT_XML;
            i++;
        }
    }

    // Perform analysis
    if (AnalyzeDrivers(&g_driverList, config.defaultAnalysis) != STATUS_SUCCESS)
    {
        printf("Failed to analyze drivers\n");
        CleanupDriverDumper();
        return 1;
    }

    // Generate report
    char reportFile[MAX_PATH_LENGTH];
    sprintf_s(reportFile, MAX_PATH_LENGTH, "driver_report.%s",
        config.defaultFormat == FORMAT_TEXT ? "txt" :
        config.defaultFormat == FORMAT_HTML ? "html" :
        config.defaultFormat == FORMAT_PDF ? "pdf" :
        config.defaultFormat == FORMAT_JSON ? "json" : "xml");

    if (GenerateReport(&g_driverList, config.defaultFormat, reportFile) != STATUS_SUCCESS)
    {
        printf("Failed to generate report\n");
        CleanupDriverDumper();
        return 1;
    }

    // Cleanup
    CleanupDriverDumper();
    return 0;
} 