#include "driverdumper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

int AnalyzeMemoryRegions(PVOID baseAddress, size_t size)
{
    if (!baseAddress || size == 0)
        return STATUS_INVALID_PARAMETER;

    PVOID address = baseAddress;
    MEMORY_BASIC_INFORMATION mbi;

    while (VirtualQuery(address, &mbi, sizeof(mbi)) && 
           (ULONG_PTR)address < (ULONG_PTR)baseAddress + size)
    {
        // Log memory region information
        char message[256];
        sprintf_s(message, sizeof(message),
            "Memory Region: Base=0x%p, Size=%lu, State=%lu, Type=%lu, Protect=%lu",
            mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Type, mbi.Protect);
        LogMessage(message, 0);

        // Check for potential issues
        if (mbi.State == MEM_COMMIT)
        {
            if (mbi.Protect == PAGE_EXECUTE_READWRITE)
            {
                LogMessage("Warning: Memory region has both execute and write permissions", 1);
            }

            if (mbi.Type == MEM_PRIVATE)
            {
                LogMessage("Warning: Memory region is private (potential heap allocation)", 1);
            }
        }

        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    return STATUS_SUCCESS;
}

int DetectMemoryCorruption(PVOID address, size_t size)
{
    if (!address || size == 0)
        return STATUS_INVALID_PARAMETER;

    // Check if memory is readable
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(address, &mbi, sizeof(mbi)))
        return STATUS_ERROR;

    if (mbi.State != MEM_COMMIT)
        return STATUS_ERROR;

    // Check for common corruption patterns
    BYTE* buffer = (BYTE*)malloc(size);
    if (!buffer)
        return STATUS_ERROR;

    if (!ReadProcessMemory(GetCurrentProcess(), address, buffer, size, NULL))
    {
        free(buffer);
        return STATUS_ERROR;
    }

    // Check for buffer overflows
    for (size_t i = 0; i < size - 4; i++)
    {
        if (buffer[i] == 0xCC && buffer[i + 1] == 0xCC && 
            buffer[i + 2] == 0xCC && buffer[i + 3] == 0xCC)
        {
            LogMessage("Potential buffer overflow detected", 1);
        }
    }

    // Check for heap corruption
    if (size >= sizeof(HEAP_ENTRY))
    {
        PHEAP_ENTRY heapEntry = (PHEAP_ENTRY)buffer;
        if (heapEntry->Flags & HEAP_ENTRY_BUSY)
        {
            if (heapEntry->Size > size)
            {
                LogMessage("Potential heap corruption detected", 1);
            }
        }
    }

    free(buffer);
    return STATUS_SUCCESS;
}

int AnalyzeMemoryProtection(PVOID address, size_t size)
{
    if (!address || size == 0)
        return STATUS_INVALID_PARAMETER;

    PVOID currentAddress = address;
    size_t remainingSize = size;

    while (remainingSize > 0)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(currentAddress, &mbi, sizeof(mbi)))
            break;

        size_t regionSize = min(mbi.RegionSize, remainingSize);

        // Log protection information
        char message[256];
        sprintf_s(message, sizeof(message),
            "Memory Protection: Address=0x%p, Size=%lu, Protect=%lu",
            currentAddress, regionSize, mbi.Protect);
        LogMessage(message, 0);

        // Check for security issues
        if (mbi.Protect & PAGE_EXECUTE_READWRITE)
        {
            LogMessage("Warning: Memory region has both execute and write permissions", 1);
        }

        if (!(mbi.Protect & PAGE_GUARD) && (mbi.Protect & PAGE_EXECUTE))
        {
            LogMessage("Warning: Memory region is executable without guard page", 1);
        }

        currentAddress = (PVOID)((ULONG_PTR)currentAddress + regionSize);
        remainingSize -= regionSize;
    }

    return STATUS_SUCCESS;
}

int TrackMemoryUsage(PVOID address, size_t size)
{
    if (!address || size == 0)
        return STATUS_INVALID_PARAMETER;

    // Create memory tracking structure
    typedef struct {
        PVOID address;
        size_t size;
        DWORD initialProtect;
        DWORD currentProtect;
        LARGE_INTEGER lastAccessTime;
        size_t accessCount;
    } MemoryTrack;

    MemoryTrack* track = (MemoryTrack*)malloc(sizeof(MemoryTrack));
    if (!track)
        return STATUS_ERROR;

    // Initialize tracking
    track->address = address;
    track->size = size;
    track->accessCount = 0;
    QueryPerformanceCounter(&track->lastAccessTime);

    // Get initial protection
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi)))
    {
        track->initialProtect = mbi.Protect;
        track->currentProtect = mbi.Protect;
    }

    // Set up memory access tracking
    DWORD oldProtect;
    if (!VirtualProtect(address, size, PAGE_READWRITE | PAGE_GUARD, &oldProtect))
    {
        free(track);
        return STATUS_ERROR;
    }

    // Log initial state
    char message[256];
    sprintf_s(message, sizeof(message),
        "Memory Tracking Started: Address=0x%p, Size=%lu, InitialProtect=%lu",
        address, size, track->initialProtect);
    LogMessage(message, 0);

    // Restore original protection
    VirtualProtect(address, size, track->initialProtect, &oldProtect);

    // Cleanup
    free(track);
    return STATUS_SUCCESS;
}

int OptimizeMemoryUsage(PVOID address, size_t size)
{
    if (!address || size == 0)
        return STATUS_INVALID_PARAMETER;

    // Analyze current memory usage
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(address, &mbi, sizeof(mbi)))
        return STATUS_ERROR;

    // Check if memory is properly aligned
    if ((ULONG_PTR)address % 4096 != 0)
    {
        LogMessage("Memory region is not page-aligned", 1);
    }

    // Check if memory is properly protected
    if (mbi.Protect != PAGE_READWRITE && mbi.Protect != PAGE_READONLY)
    {
        LogMessage("Memory region has non-optimal protection", 1);
    }

    // Check for fragmentation
    if (mbi.RegionSize > size * 2)
    {
        LogMessage("Memory region may be fragmented", 1);
    }

    // Optimize memory protection
    DWORD oldProtect;
    if (mbi.Protect != PAGE_READWRITE)
    {
        if (!VirtualProtect(address, size, PAGE_READWRITE, &oldProtect))
        {
            return STATUS_ERROR;
        }
    }

    // Defragment memory if needed
    if (mbi.RegionSize > size * 2)
    {
        PVOID newAddress = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
        if (newAddress)
        {
            memcpy(newAddress, address, size);
            VirtualFree(address, 0, MEM_RELEASE);
            address = newAddress;
        }
    }

    return STATUS_SUCCESS;
}

int MonitorMemoryChanges(PVOID address, size_t size)
{
    if (!address || size == 0)
        return STATUS_INVALID_PARAMETER;

    // Create memory snapshot
    BYTE* snapshot = (BYTE*)malloc(size);
    if (!snapshot)
        return STATUS_ERROR;

    if (!ReadProcessMemory(GetCurrentProcess(), address, snapshot, size, NULL))
    {
        free(snapshot);
        return STATUS_ERROR;
    }

    // Set up memory monitoring
    DWORD oldProtect;
    if (!VirtualProtect(address, size, PAGE_READWRITE | PAGE_GUARD, &oldProtect))
    {
        free(snapshot);
        return STATUS_ERROR;
    }

    // Monitor for changes
    while (true)
    {
        BYTE* current = (BYTE*)malloc(size);
        if (!current)
        {
            free(snapshot);
            return STATUS_ERROR;
        }

        if (!ReadProcessMemory(GetCurrentProcess(), address, current, size, NULL))
        {
            free(current);
            free(snapshot);
            return STATUS_ERROR;
        }

        // Compare with snapshot
        for (size_t i = 0; i < size; i++)
        {
            if (current[i] != snapshot[i])
            {
                char message[256];
                sprintf_s(message, sizeof(message),
                    "Memory change detected at offset %lu: 0x%02X -> 0x%02X",
                    i, snapshot[i], current[i]);
                LogMessage(message, 1);
            }
        }

        free(current);
        Sleep(1000); // Check every second
    }

    // Cleanup (never reached due to infinite loop)
    free(snapshot);
    return STATUS_SUCCESS;
} 