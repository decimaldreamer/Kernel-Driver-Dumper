#ifndef DRIVER_DUMPER_H
#define DRIVER_DUMPER_H

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <json/json.h>

// Core definitions
#define DRIVER_DUMPER_VERSION "1.0.0"
#define MAX_PATH_LENGTH 260
#define MAX_DRIVER_NAME_LENGTH 256
#define HASH_BUFFER_SIZE 4096
#define LOG_FILE_NAME "driverdumper.log"
#define CONFIG_FILE_NAME "driverdumper.json"

// Status codes
#define STATUS_SUCCESS 0
#define STATUS_ERROR -1
#define STATUS_NOT_FOUND -2
#define STATUS_ACCESS_DENIED -3
#define STATUS_INVALID_PARAMETER -4

// Analysis types
typedef enum {
    ANALYSIS_BASIC = 0,
    ANALYSIS_MEMORY,
    ANALYSIS_SECURITY,
    ANALYSIS_PERFORMANCE,
    ANALYSIS_ADVANCED
} AnalysisType;

// Report formats
typedef enum {
    FORMAT_TEXT = 0,
    FORMAT_HTML,
    FORMAT_PDF,
    FORMAT_JSON,
    FORMAT_XML
} ReportFormat;

// Core structures
typedef struct {
    char name[MAX_DRIVER_NAME_LENGTH];
    PVOID baseAddress;
    ULONG size;
    bool isSigned;
    char version[32];
    char hash[65];
    LARGE_INTEGER loadTime;
    char dependencies[MAX_PATH_LENGTH];
    DWORD memoryProtection;
    bool hasASLR;
    bool hasDEP;
    char certificateInfo[256];
    double securityScore;
} DriverInfo;

typedef struct {
    DriverInfo* drivers;
    size_t count;
    size_t capacity;
} DriverList;

typedef struct {
    bool enableLogging;
    bool enableGUI;
    bool enableAPI;
    bool enableWeb;
    bool enableTests;
    AnalysisType defaultAnalysis;
    ReportFormat defaultFormat;
    char logFile[MAX_PATH_LENGTH];
    char configFile[MAX_PATH_LENGTH];
} Config;

// Core functions
int InitializeDriverDumper(Config* config);
int CleanupDriverDumper();

// Driver analysis
int AnalyzeDrivers(DriverList* list, AnalysisType type);
int GetDriverInfo(const char* driverName, DriverInfo* info);
int GetDriverMemoryInfo(const char* driverName, PVOID* regions, size_t* count);
int GetDriverSecurityInfo(const char* driverName, double* securityScore);
int GetDriverPerformanceInfo(const char* driverName, double* performanceScore);

// Memory analysis
int AnalyzeMemoryRegions(PVOID baseAddress, size_t size);
int DetectMemoryCorruption(PVOID address, size_t size);
int AnalyzeMemoryProtection(PVOID address, size_t size);
int TrackMemoryUsage(PVOID address, size_t size);

// Security analysis
int VerifyDriverSignature(const char* driverPath);
int AnalyzeDriverVulnerabilities(const char* driverPath);
int CheckDriverBehavior(const char* driverPath);
int CalculateSecurityScore(const char* driverPath, double* score);
int DetectMaliciousDrivers(DriverList* list);

// Performance analysis
int MeasureDriverLoadTime(const char* driverPath, LARGE_INTEGER* loadTime);
int AnalyzeDriverPerformance(const char* driverPath);
int OptimizeDriverPerformance(const char* driverPath);
int MonitorDriverPerformance(const char* driverPath);

// Reporting
int GenerateReport(DriverList* list, ReportFormat format, const char* outputFile);
int ExportToHTML(DriverList* list, const char* outputFile);
int ExportToPDF(DriverList* list, const char* outputFile);
int ExportToJSON(DriverList* list, const char* outputFile);
int ExportToXML(DriverList* list, const char* outputFile);

// Integration
int InitializeAPI();
int StartWebServer();
int StopWebServer();
int RegisterSIEMCallback(void (*callback)(const char* event));

// Monitoring
int StartRealTimeMonitoring();
int StopRealTimeMonitoring();
int DetectChanges(DriverList* oldList, DriverList* newList);
int AnalyzeLogs(const char* logFile);
int HandleEvents(const char* event);

// Advanced features
int LoadDriver(const char* driverPath);
int UnloadDriver(const char* driverName);
int BackupDriver(const char* driverName, const char* backupPath);
int RestoreDriver(const char* backupPath);
int CompareDrivers(const char* driver1, const char* driver2);
int CheckDriverUpdates(const char* driverName);
int AnalyzeDependencies(const char* driverName);

// Utility functions
int LogMessage(const char* message, int level);
int ParseConfig(const char* configFile, Config* config);
int SaveConfig(const char* configFile, const Config* config);
int ValidateDriver(const char* driverPath);
int CalculateHash(const char* filePath, char* hashBuffer);
int GetSystemInfo(char* infoBuffer, size_t bufferSize);

// GUI functions
#ifdef BUILD_GUI
int InitializeGUI();
int UpdateGUI(DriverList* list);
int ShowAnalysisResults(DriverList* list);
int ShowReport(DriverList* list, ReportFormat format);
#endif

// API functions
#ifdef BUILD_API
int StartAPIServer();
int StopAPIServer();
int HandleAPIRequest(const char* request, char* response);
#endif

// Web interface functions
#ifdef BUILD_WEB
int StartWebInterface();
int StopWebInterface();
int HandleWebRequest(const char* request, char* response);
#endif

#endif // DRIVER_DUMPER_H 