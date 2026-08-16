#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winioctl.h>
#include <stdarg.h>
#include "R0Simulates.h"
#include <winternl.h>
#include <ntstatus.h>

#if defined(_MSC_VER) && !defined(__MINGW32__)
PVOID NTAPI RtlAllocateHeap(HANDLE HeapHandle, ULONG Flags, SIZE_T Size);
BOOLEAN NTAPI RtlFreeHeap(HANDLE HeapHandle, ULONG Flags, PVOID BaseAddress);
HANDLE NTAPI RtlCreateHeap(ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize,
                           SIZE_T CommitSize, PVOID Lock, PVOID Parameters);
#endif

ULONG NTAPI RtlNtStatusToDosError(NTSTATUS Status);
VOID NTAPI RtlSetLastWin32Error(DWORD Win32Error);

static void my_memcpy(void* dest, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}

static void my_memset(void* dest, int val, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    for (size_t i = 0; i < n; i++) d[i] = (unsigned char)val;
}

void *memset(void *dest, int c, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    while (n--) *d++ = (unsigned char)c;
    return dest;
}

static void my_zero_memory(void* dest, size_t len) {
    my_memset(dest, 0, len);
}

static size_t my_wcslen(const WCHAR* str) {
    size_t len = 0;
    while (str && str[len]) len++;
    return len;
}

static HANDLE g_hHeap = NULL;

static BOOL InitHeap(void) {
    if (!g_hHeap) {
        g_hHeap = RtlCreateHeap(0, NULL, 0, 0, NULL, NULL);
    }
    return (g_hHeap != NULL);
}

#define R0_HEAP g_hHeap

static HANDLE g_hDriver = INVALID_HANDLE_VALUE;

static BOOL R0Sim_OpenDriver(void) {
    if (!InitHeap()) {
        RtlSetLastWin32Error(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    if (g_hDriver != INVALID_HANDLE_VALUE)
        return TRUE;

    UNICODE_STRING uniPath;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE hFile = NULL;
    NTSTATUS status;

    RtlInitUnicodeString(&uniPath, L"\\Device\\R0Simulate");
    InitializeObjectAttributes(&objAttr, &uniPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(
        &hFile,
        GENERIC_READ | GENERIC_WRITE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        0,
        NULL,
        0
    );

    if (NT_SUCCESS(status)) {
        g_hDriver = hFile;
        return TRUE;
    }
    RtlSetLastWin32Error(ERROR_SERVICE_NOT_ACTIVE);
    return FALSE;
}

static void R0Sim_CloseDriver(void) {
    if (g_hDriver != INVALID_HANDLE_VALUE) {
        NtClose(g_hDriver);
        g_hDriver = INVALID_HANDLE_VALUE;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_DETACH) {
        R0Sim_CloseDriver();
    }
    return TRUE;
}

static DWORD NtStatusToWin32Error(LONG ntStatus) {
    return RtlNtStatusToDosError(ntStatus);
}

R0SIMULATES_API UINT64 R0SimulateISA(const void* pInstruction, ULONG instructionSize) {
    if (!R0Sim_OpenDriver()) return 0;
    if (!pInstruction || instructionSize == 0) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    size_t inSize = sizeof(EXEC_INSTRUCTION_INPUT) + instructionSize - 1;
    PEXEC_INSTRUCTION_INPUT pIn = (PEXEC_INSTRUCTION_INPUT)RtlAllocateHeap(R0_HEAP, HEAP_ZERO_MEMORY, inSize);
    if (!pIn) {
        RtlSetLastWin32Error(ERROR_OUTOFMEMORY);
        return 0;
    }
    pIn->InstructionSize = instructionSize;
    my_memcpy(pIn->Instruction, pInstruction, instructionSize);

    EXEC_INSTRUCTION_OUTPUT out;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_EXEC_INSTRUCTION,
        pIn, (ULONG)inSize,
        &out, sizeof(out)
    );
    RtlFreeHeap(R0_HEAP, 0, pIn);
    if (!NT_SUCCESS(status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(status));
        return 0;
    }
    if (out.Status < 0) {
        RtlSetLastWin32Error(NtStatusToWin32Error(out.Status));
        return 0;
    }
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return out.ReturnValue;
}

R0SIMULATES_API UINT64 R0SimulateAPI(const WCHAR* pwszApiName, ULONG argc, ULONG flags, ...) {
    if (!R0Sim_OpenDriver()) return 0;
    if (argc > 16) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    BOOL useAddress = (flags & R0SIMULATE_FLAG_USE_ADDRESS) ? TRUE : FALSE;
    ULONG nameLen = 0;
    size_t totalInSize;
    if (useAddress) {
        totalInSize = sizeof(CALL_KERNEL_API_INPUT) + sizeof(UINT64);
    } else {
        if (!pwszApiName) {
            RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        nameLen = (ULONG)((my_wcslen(pwszApiName) + 1) * sizeof(WCHAR));
        if (nameLen == 0 || nameLen > 512) {
            RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        totalInSize = sizeof(CALL_KERNEL_API_INPUT) + nameLen;
    }
    PCALL_KERNEL_API_INPUT pIn = (PCALL_KERNEL_API_INPUT)RtlAllocateHeap(R0_HEAP, HEAP_ZERO_MEMORY, totalInSize);
    if (!pIn) {
        RtlSetLastWin32Error(ERROR_OUTOFMEMORY);
        return 0;
    }
    pIn->ApiNameLength = useAddress ? 0 : nameLen;
    pIn->ArgumentCount = argc;
    pIn->Flags = flags;
    if (useAddress) {
        UINT64 addr = (UINT64)(ULONG_PTR)pwszApiName;
        my_memcpy(pIn->ApiName, &addr, sizeof(addr));
    } else {
        my_memcpy(pIn->ApiName, pwszApiName, nameLen);
    }
    va_list args;
    va_start(args, flags);
    for (ULONG i = 0; i < argc && i < 16; i++) {
        pIn->Arguments[i] = va_arg(args, UINT64);
    }
    va_end(args);
    CALL_KERNEL_API_OUTPUT out;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_CALL_KERNEL_API,
        pIn, (ULONG)totalInSize,
        &out, sizeof(out)
    );
    RtlFreeHeap(R0_HEAP, 0, pIn);
    if (!NT_SUCCESS(status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(status));
        return 0;
    }
    if (out.Status < 0) {
        RtlSetLastWin32Error(NtStatusToWin32Error(out.Status));
        return 0;
    }
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return out.ReturnValue;
}

R0SIMULATES_API BOOL R0SimulateKernelProcessHiding(UCHAR operation, ULONG pid, PVOID pOutBuffer, ULONG outSize) {
    if (!R0Sim_OpenDriver()) return FALSE;
    if (operation != R0SKPH_OP_ADD && operation != R0SKPH_OP_REMOVE && operation != R0SKPH_OP_LIST) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    PROCESS_HIDING_INPUT in;
    my_zero_memory(&in, sizeof(in));
    in.Operation = operation;
    ULONG inputSize = sizeof(PROCESS_HIDING_INPUT);
    if (operation == R0SKPH_OP_ADD || operation == R0SKPH_OP_REMOVE) {
        inputSize += sizeof(ULONG);
    }
    PUCHAR pInBuf = (PUCHAR)RtlAllocateHeap(R0_HEAP, HEAP_ZERO_MEMORY, inputSize);
    if (!pInBuf) {
        RtlSetLastWin32Error(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    my_memcpy(pInBuf, &in, sizeof(PROCESS_HIDING_INPUT));
    if (operation == R0SKPH_OP_ADD || operation == R0SKPH_OP_REMOVE) {
        *(PULONG)(pInBuf + sizeof(PROCESS_HIDING_INPUT)) = pid;
    }
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_KERNEL_PROCESS_HIDING,
        pInBuf, inputSize,
        pOutBuffer, outSize
    );
    RtlFreeHeap(R0_HEAP, 0, pInBuf);
    if (!NT_SUCCESS(status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(status));
        return FALSE;
    }
    if (operation == R0SKPH_OP_ADD || operation == R0SKPH_OP_REMOVE) {
        if (ioStatus.Information >= sizeof(NTSTATUS)) {
            NTSTATUS st = *(NTSTATUS*)pOutBuffer;
            if (st < 0) {
                RtlSetLastWin32Error(NtStatusToWin32Error(st));
                return FALSE;
            }
        } else {
            RtlSetLastWin32Error(ERROR_GEN_FAILURE);
            return FALSE;
        }
    }
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return TRUE;
}

R0SIMULATES_API BOOL R0SimulatePreviousModeSwitch(BOOL viewOnly, UCHAR mode, UCHAR* pOldMode, UCHAR* pNewMode) {
    if (!R0Sim_OpenDriver()) return FALSE;
    if (!viewOnly) {
        if (mode != R0SPMS_MODE_KERNEL && mode != R0SPMS_MODE_USER) {
            RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }
    PREVIOUS_MODE_SWITCH_INPUT in;
    my_zero_memory(&in, sizeof(in));
    in.Mode = mode;
    in.ViewOnly = viewOnly ? 1 : 0;
    PREVIOUS_MODE_SWITCH_OUTPUT out;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_PREVIOUS_MODE_SWITCH,
        &in, sizeof(in),
        &out, sizeof(out)
    );
    if (!NT_SUCCESS(status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(status));
        return FALSE;
    }
    if (out.Status < 0) {
        RtlSetLastWin32Error(NtStatusToWin32Error(out.Status));
        return FALSE;
    }
    if (pOldMode) *pOldMode = out.OldMode;
    if (pNewMode) *pNewMode = out.NewMode;
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return TRUE;
}

R0SIMULATES_API HANDLE R0SimulateKernelOpenHandle(ULONG pid) {
    if (!R0Sim_OpenDriver()) return NULL;
    HANDLE hProcess = NULL;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_KERNEL_OPEN_HANDLE,
        &pid, sizeof(pid),
        &hProcess, sizeof(hProcess)
    );
    if (!NT_SUCCESS(status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(status));
        return NULL;
    }
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return hProcess;
}

R0SIMULATES_API BOOL R0SimulateKernelMemoryAccess(UINT64 Address, ULONG Offset, ULONG Length, UCHAR Operation, PVOID Buffer) {
    if (!R0Sim_OpenDriver()) return FALSE;
    if (Length == 0 || !Buffer) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (Operation != R0SKMA_OP_READ && Operation != R0SKMA_OP_WRITE) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    SIZE_T totalSize = sizeof(KERNEL_MEMORY_ACCESS_INPUT) + Length;
    PKERNEL_MEMORY_ACCESS_INPUT pIn = (PKERNEL_MEMORY_ACCESS_INPUT)RtlAllocateHeap(R0_HEAP, HEAP_ZERO_MEMORY, totalSize);
    if (!pIn) {
        RtlSetLastWin32Error(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    pIn->Address = Address;
    pIn->Offset = Offset;
    pIn->Length = Length;
    pIn->Operation = Operation;

    if (Operation == R0SKMA_OP_WRITE) {
        my_memcpy(pIn->Data, Buffer, Length);
    }

    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_KERNEL_MEMORY_ACCESS,
        pIn, (ULONG)totalSize,
        pIn, (ULONG)totalSize
    );

    if (!NT_SUCCESS(status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(status));
        RtlFreeHeap(R0_HEAP, 0, pIn);
        return FALSE;
    }

    if (Operation == R0SKMA_OP_READ) {
        my_memcpy(Buffer, pIn->Data, Length);
    }

    RtlFreeHeap(R0_HEAP, 0, pIn);
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return TRUE;
}

R0SIMULATES_API HANDLE R0SimulateGetSystemToken(BOOL ReplaceToken) {
    if (!R0Sim_OpenDriver()) return NULL;

    GET_SYSTEM_TOKEN_INPUT in;
    my_zero_memory(&in, sizeof(in));
    in.ReplaceToken = ReplaceToken ? 1 : 0;

    GET_SYSTEM_TOKEN_OUTPUT out;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_GET_SYSTEM_TOKEN,
        &in, sizeof(in),
        &out, sizeof(out)
    );

    if (!NT_SUCCESS(status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(status));
        return NULL;
    }
    if (out.Status < 0) {
        RtlSetLastWin32Error(NtStatusToWin32Error(out.Status));
        return NULL;
    }

    RtlSetLastWin32Error(ERROR_SUCCESS);
    return out.TokenHandle;
}