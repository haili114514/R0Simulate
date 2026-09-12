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

static void my_zero_memory(void* dest, size_t len) {
    my_memset(dest, 0, len);
}

static size_t my_wcslen(const WCHAR* str) {
    size_t len = 0;
    while (str && str[len]) len++;
    return len;
}

static int my_ultow(unsigned long value, WCHAR* buffer, int bufsize) {
    if (bufsize <= 0) return -1;
    WCHAR tmp[32];
    int i = 0;
    if (value == 0) {
        if (bufsize < 2) return -1;
        buffer[0] = L'0';
        buffer[1] = L'\0';
        return 1;
    }
    while (value > 0) {
        if (i >= ((int)(sizeof(tmp)/sizeof(tmp[0])) - 1)) break;
        tmp[i++] = L'0' + (value % 10);
        value /= 10;
    }
    if (i >= bufsize) return -1;
    int j;
    for (j = 0; j < i; j++) {
        buffer[j] = tmp[i - 1 - j];
    }
    buffer[j] = L'\0';
    return j;
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

static ULONG g_DllErrorMode = 0;   

static void SetLastErrorByMode(ULONG errorMode, NTSTATUS status) {
    if (errorMode == 1) {
        RtlSetLastWin32Error((DWORD)status);
    } else {
        RtlSetLastWin32Error(RtlNtStatusToDosError(status));
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

static DWORD NtStatusToWin32Error(ULONG ntStatus) {
    return RtlNtStatusToDosError(ntStatus);
}

R0SIMULATES_API UINT64 R0SimulateISA(const void* pInstruction, ULONG instructionSize) {
    PEXEC_INSTRUCTION_INPUT pIn;
    EXEC_INSTRUCTION_OUTPUT out;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    size_t inSize;

    if (!R0Sim_OpenDriver()) return 0;
    if (!pInstruction || instructionSize == 0) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    inSize = sizeof(EXEC_INSTRUCTION_INPUT) + instructionSize - 1;
    pIn = (PEXEC_INSTRUCTION_INPUT)RtlAllocateHeap(R0_HEAP, HEAP_ZERO_MEMORY, inSize);
    if (!pIn) {
        RtlSetLastWin32Error(ERROR_OUTOFMEMORY);
        return 0;
    }
    pIn->InstructionSize = instructionSize;
    my_memcpy(pIn->Instruction, pInstruction, instructionSize);

    my_zero_memory(&out, sizeof(out));
    my_zero_memory(&ioStatus, sizeof(ioStatus));

    status = NtDeviceIoControlFile(
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
    if (!NT_SUCCESS((NTSTATUS)out.Status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(out.Status));
        return 0;
    }
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return out.ReturnValue;
}

R0SIMULATES_API UINT64 R0SimulateAPI(const WCHAR* pwszApiName, ULONG argc, ULONG flags, ...) {
    BOOL useAddress, useSsn;
    ULONG nameLen = 0;
    size_t totalInSize;
    WCHAR ssnStr[16] = {0};
    PCALL_KERNEL_API_INPUT pIn;
    CALL_KERNEL_API_OUTPUT out;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    va_list args;

    if (!R0Sim_OpenDriver()) return 0;
    if (argc > 16) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    useAddress = (flags & R0SIMULATE_FLAG_USE_ADDRESS) ? TRUE : FALSE;
    useSsn = (flags & R0SIMULATE_FLAG_SSN_MODE) ? TRUE : FALSE;
    if (useAddress && useSsn) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if (useAddress) {
        totalInSize = sizeof(CALL_KERNEL_API_INPUT) + sizeof(UINT64);
    } else if (useSsn) {
        ULONG ssn = (ULONG)(ULONG_PTR)pwszApiName;
        int len = my_ultow(ssn, ssnStr, sizeof(ssnStr)/sizeof(ssnStr[0]));
        if (len <= 0) {
            RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        nameLen = (ULONG)((len + 1) * sizeof(WCHAR));
        totalInSize = sizeof(CALL_KERNEL_API_INPUT) + nameLen;
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

    pIn = (PCALL_KERNEL_API_INPUT)RtlAllocateHeap(R0_HEAP, HEAP_ZERO_MEMORY, totalInSize);
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
    } else if (useSsn) {
        my_memcpy(pIn->ApiName, ssnStr, nameLen);
    } else {
        my_memcpy(pIn->ApiName, pwszApiName, nameLen);
    }

    va_start(args, flags);
    {
        ULONG i;
        for (i = 0; i < argc && i < 16; i++) {
            pIn->Arguments[i] = va_arg(args, UINT64);
        }
    }
    va_end(args);

    my_zero_memory(&out, sizeof(out));
    my_zero_memory(&ioStatus, sizeof(ioStatus));

    status = NtDeviceIoControlFile(
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
    if (!NT_SUCCESS((NTSTATUS)out.Status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(out.Status));
        return 0;
    }
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return out.ReturnValue;
}

R0SIMULATES_API BOOL R0SimulateKernelProcessHiding(UCHAR operation, ULONG pid, PVOID pOutBuffer, ULONG outSize) {
    PROCESS_HIDING_INPUT in;
    ULONG inputSize;
    PUCHAR pInBuf;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    if (!R0Sim_OpenDriver()) return FALSE;
    if (operation != R0SKPH_OP_ADD && operation != R0SKPH_OP_REMOVE && operation != R0SKPH_OP_LIST) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    my_zero_memory(&in, sizeof(in));
    in.Operation = operation;
    inputSize = sizeof(PROCESS_HIDING_INPUT);
    if (operation == R0SKPH_OP_ADD || operation == R0SKPH_OP_REMOVE) {
        inputSize += sizeof(ULONG);
    }

    pInBuf = (PUCHAR)RtlAllocateHeap(R0_HEAP, HEAP_ZERO_MEMORY, inputSize);
    if (!pInBuf) {
        RtlSetLastWin32Error(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    my_memcpy(pInBuf, &in, sizeof(PROCESS_HIDING_INPUT));
    if (operation == R0SKPH_OP_ADD || operation == R0SKPH_OP_REMOVE) {
        *(PULONG)(pInBuf + sizeof(PROCESS_HIDING_INPUT)) = pid;
    }

    my_zero_memory(&ioStatus, sizeof(ioStatus));

    status = NtDeviceIoControlFile(
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
            if (!NT_SUCCESS(st)) {
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
    PREVIOUS_MODE_SWITCH_INPUT in;
    PREVIOUS_MODE_SWITCH_OUTPUT out;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    if (!R0Sim_OpenDriver()) return FALSE;
    if (!viewOnly) {
        if (mode != R0SPMS_MODE_KERNEL && mode != R0SPMS_MODE_USER) {
            RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }
    my_zero_memory(&in, sizeof(in));
    in.Mode = mode;
    in.ViewOnly = viewOnly ? 1 : 0;

    my_zero_memory(&out, sizeof(out));
    my_zero_memory(&ioStatus, sizeof(ioStatus));

    status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_PREVIOUS_MODE_SWITCH,
        &in, sizeof(in),
        &out, sizeof(out)
    );
    if (!NT_SUCCESS(status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(status));
        return FALSE;
    }
    if (!NT_SUCCESS((NTSTATUS)out.Status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(out.Status));
        return FALSE;
    }
    if (pOldMode) *pOldMode = out.OldMode;
    if (pNewMode) *pNewMode = out.NewMode;
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return TRUE;
}

R0SIMULATES_API HANDLE R0SimulateKernelOpenHandle(
    ULONG       Type,
    ACCESS_MASK DesiredAccess,
    UINT64      Target,
    ULONG       Attributes)
{
    KERNEL_OPEN_HANDLE_INPUT in;
    KERNEL_OPEN_HANDLE_OUTPUT out;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    if (!R0Sim_OpenDriver()) return NULL;

    if (Type != R0SKOH_TYPE_POINTER && Type != R0SKOH_TYPE_PID) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    my_zero_memory(&in, sizeof(in));
    in.Flags         = R0SKOH_MAKE_FLAGS(Type, Attributes);
    in.DesiredAccess = DesiredAccess;
    in.Target        = Target;

    my_zero_memory(&out, sizeof(out));
    my_zero_memory(&ioStatus, sizeof(ioStatus));

    status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_KERNEL_OPEN_HANDLE,
        &in, sizeof(in),
        &out, sizeof(out)
    );

    if (!NT_SUCCESS(status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(status));
        return NULL;
    }
    if (!NT_SUCCESS(out.Status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(out.Status));
        return NULL;
    }
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return out.ResultHandle;
}

R0SIMULATES_API BOOL R0SimulateKernelMemoryAccess(UINT64 Address, ULONG Offset, ULONG Length, UCHAR Operation, PVOID Buffer) {
    SIZE_T totalSize;
    PKERNEL_MEMORY_ACCESS_INPUT pIn;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    if (!R0Sim_OpenDriver()) return FALSE;
    if (Length == 0 || !Buffer) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (Operation != R0SKMA_OP_READ && Operation != R0SKMA_OP_WRITE) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    totalSize = sizeof(KERNEL_MEMORY_ACCESS_INPUT) + Length;
    pIn = (PKERNEL_MEMORY_ACCESS_INPUT)RtlAllocateHeap(R0_HEAP, HEAP_ZERO_MEMORY, totalSize);
    if (!pIn) {
        RtlSetLastWin32Error(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    pIn->Address   = Address;
    pIn->Offset    = Offset;
    pIn->Length    = Length;
    pIn->Operation = Operation;
    if (Operation == R0SKMA_OP_WRITE) {
        my_memcpy(pIn->Data, Buffer, Length);
    }

    my_zero_memory(&ioStatus, sizeof(ioStatus));

    status = NtDeviceIoControlFile(
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
    GET_SYSTEM_TOKEN_INPUT in;
    GET_SYSTEM_TOKEN_OUTPUT out;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    if (!R0Sim_OpenDriver()) return NULL;
    my_zero_memory(&in, sizeof(in));
    in.ReplaceToken = ReplaceToken ? 1 : 0;

    my_zero_memory(&out, sizeof(out));
    my_zero_memory(&ioStatus, sizeof(ioStatus));

    status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_GET_SYSTEM_TOKEN,
        &in, sizeof(in),
        &out, sizeof(out)
    );
    if (!NT_SUCCESS(status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(status));
        return NULL;
    }
    if (!NT_SUCCESS((NTSTATUS)out.Status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(out.Status));
        return NULL;
    }
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return out.TokenHandle;
}

R0SIMULATES_API BOOL R0SimulateSetInternalVariables(
    ULONG  Operation,
    ULONG  VariableId,
    UINT64 Value,
    PVOID  pOutBuffer,
    ULONG  outSize,
    PULONG pInfoCount,
    ULONG  ErrorMode)
{
    ULONG actualMode;
    PSET_INTERNAL_VAR_INPUT pIn;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    if (!R0Sim_OpenDriver()) return FALSE;

    
    if (ErrorMode == R0SIMULATE_ERROR_MODE_DEFAULT) {
        actualMode = g_DllErrorMode;
    } else {
        actualMode = (ErrorMode == 0) ? 0 : 1;
    }

    
    if (VariableId == R0SIMULATE_VAR_DLL_ERROR_MODE) {
        if (Operation == R0SIMULATE_VAR_OP_SET) {
            g_DllErrorMode = (ULONG)Value;
            RtlSetLastWin32Error(ERROR_SUCCESS);
            return TRUE;
        } else if (Operation == R0SIMULATE_VAR_OP_GET) {
            if (!pOutBuffer || outSize < sizeof(UINT64)) {
                RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            *(UINT64*)pOutBuffer = g_DllErrorMode;
            RtlSetLastWin32Error(ERROR_SUCCESS);
            return TRUE;
        } else {
            RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }

    
    if (Operation != R0SIMULATE_VAR_OP_GET &&
        Operation != R0SIMULATE_VAR_OP_SET &&
        Operation != R0SIMULATE_VAR_OP_LIST)
    {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (Operation == R0SIMULATE_VAR_OP_LIST) {
        if (!pOutBuffer || outSize < sizeof(ULONG)) {
            RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    } else if (Operation == R0SIMULATE_VAR_OP_GET) {
        if (!pOutBuffer || outSize < sizeof(UINT64)) {
            RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    }

    
    pIn = (PSET_INTERNAL_VAR_INPUT)RtlAllocateHeap(
        R0_HEAP, HEAP_ZERO_MEMORY, sizeof(SET_INTERNAL_VAR_INPUT));
    if (!pIn) {
        RtlSetLastWin32Error(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    pIn->Operation  = Operation;
    pIn->VariableId = VariableId;
    pIn->Value      = Value;
    pIn->NameLength = 0;   
    

    my_zero_memory(&ioStatus, sizeof(ioStatus));

    status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_SET_INTERNAL_VARS,
        pIn, sizeof(SET_INTERNAL_VAR_INPUT),
        pOutBuffer, outSize
    );
    RtlFreeHeap(R0_HEAP, 0, pIn);

    if (!NT_SUCCESS(status)) {
        SetLastErrorByMode(actualMode, status);
        return FALSE;
    }

    if (Operation == R0SIMULATE_VAR_OP_LIST && pInfoCount) {
        if (ioStatus.Information >= sizeof(ULONG)) {
            *pInfoCount = *(ULONG*)pOutBuffer;
        } else {
            *pInfoCount = 0;
        }
    }

    RtlSetLastWin32Error(ERROR_SUCCESS);
    return TRUE;
}

R0SIMULATES_API BOOL R0SimulateGetKernelFunction(
    const WCHAR* FunctionName,
    PVOID pOutBuffer,
    ULONG outSize,
    PULONG pInfoCount)
{
    ULONG nameLen = 0;
    SIZE_T totalInSize = sizeof(GET_KERNEL_FUNCTION_INPUT);
    PGET_KERNEL_FUNCTION_INPUT pIn;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    if (!R0Sim_OpenDriver()) return FALSE;

    if (FunctionName) {
        nameLen = (ULONG)((my_wcslen(FunctionName) + 1) * sizeof(WCHAR));
        if (nameLen > 512) {
            RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        totalInSize += nameLen - 1;
    }

    pIn = (PGET_KERNEL_FUNCTION_INPUT)RtlAllocateHeap(R0_HEAP, HEAP_ZERO_MEMORY, totalInSize);
    if (!pIn) {
        RtlSetLastWin32Error(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    pIn->NameLength = nameLen;
    if (FunctionName) {
        my_memcpy(pIn->Name, FunctionName, nameLen);
    }

    my_zero_memory(&ioStatus, sizeof(ioStatus));

    status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_GET_KERNEL_FUNCTION,
        pIn, (ULONG)totalInSize,
        pOutBuffer, outSize
    );
    RtlFreeHeap(R0_HEAP, 0, pIn);

    if (!NT_SUCCESS(status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(status));
        return FALSE;
    }
    if (!FunctionName && pInfoCount) {
        if (outSize >= sizeof(ULONG)) {
            *pInfoCount = *(PULONG)pOutBuffer;
        } else {
            *pInfoCount = 0;
        }
    }
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return TRUE;
}

R0SIMULATES_API BOOL R0SimulateIO(
    ULONG Operation,
    ULONG Port,
    ULONG Value,
    PULONG pResult)
{
    R0S_IO_INPUT in;
    R0S_IO_OUTPUT out;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    if (!R0Sim_OpenDriver()) return FALSE;
    switch (Operation) {
        case R0SIO_READ_BYTE:
        case R0SIO_READ_WORD:
        case R0SIO_READ_DWORD:
        case R0SIO_WRITE_BYTE:
        case R0SIO_WRITE_WORD:
        case R0SIO_WRITE_DWORD:
            break;
        default:
            RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
            return FALSE;
    }

    my_zero_memory(&in, sizeof(in));
    in.Operation = Operation;
    in.Port      = Port;
    in.Value     = Value;

    my_zero_memory(&out, sizeof(out));
    my_zero_memory(&ioStatus, sizeof(ioStatus));

    status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_IO,
        &in, sizeof(in),
        &out, sizeof(out)
    );
    if (!NT_SUCCESS(status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(status));
        return FALSE;
    }
    if (!NT_SUCCESS((NTSTATUS)out.Status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(out.Status));
        return FALSE;
    }
    if (pResult) *pResult = out.Value;
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return TRUE;
}