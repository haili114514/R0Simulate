#define _CRT_SECURE_NO_WARNINGS

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

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
VOID  NTAPI RtlSetLastWin32Error(DWORD Win32Error);

#pragma function(memcpy)
#pragma function(memset)

void* memcpy(void* dest, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) *d++ = *s++;
    return dest;
}

void* memset(void* dest, int c, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    while (n--) *d++ = (unsigned char)c;
    return dest;
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

static DWORD NtStatusToWin32Error(LONG ntStatus) {
    return RtlNtStatusToDosError(ntStatus);
}

R0SIMULATES_API UINT64 R0SimulateISA(const void* pInstruction, ULONG instructionSize) {
    UINT64 result = 0;
    size_t inSize;
    PEXEC_INSTRUCTION_INPUT pIn;
    EXEC_INSTRUCTION_OUTPUT out;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

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
    memcpy(pIn->Instruction, pInstruction, instructionSize);

    memset(&out, 0, sizeof(out));

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
        RtlSetLastWin32Error(NtStatusToWin32Error((NTSTATUS)out.Status));
        return 0;
    }
    RtlSetLastWin32Error(ERROR_SUCCESS);
    result = out.ReturnValue;
    return result;
}

R0SIMULATES_API UINT64 R0SimulateAPI(const WCHAR* pwszApiName, ULONG argc, ULONG flags, ...) {
    UINT64 result = 0;
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
        int idx = 0;
        if (ssn == 0) {
            ssnStr[idx++] = L'0';
        } else {
            WCHAR tmp[16];
            int t = 0;
            while (ssn > 0 && t < 15) {
                tmp[t++] = L'0' + (ssn % 10);
                ssn /= 10;
            }
            while (t > 0) ssnStr[idx++] = tmp[--t];
        }
        ssnStr[idx] = L'\0';
        nameLen = (ULONG)((idx + 1) * sizeof(WCHAR));
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
        memcpy(pIn->ApiName, &addr, sizeof(addr));
    } else if (useSsn) {
        memcpy(pIn->ApiName, ssnStr, nameLen);
    } else {
        memcpy(pIn->ApiName, pwszApiName, nameLen);
    }

    va_start(args, flags);
    {
        ULONG i;
        for (i = 0; i < argc && i < 16; i++) {
            pIn->Arguments[i] = va_arg(args, UINT64);
        }
    }
    va_end(args);

    memset(&out, 0, sizeof(out));

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
        RtlSetLastWin32Error(NtStatusToWin32Error((NTSTATUS)out.Status));
        return 0;
    }
    RtlSetLastWin32Error(ERROR_SUCCESS);
    result = out.ReturnValue;
    return result;
}

R0SIMULATES_API BOOL R0SimulateKernelProcessHiding(UCHAR operation, ULONG pid, PVOID pOutBuffer, ULONG outSize) {
    BOOL result = FALSE;
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

    memset(&in, 0, sizeof(in));
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
    memcpy(pInBuf, &in, sizeof(PROCESS_HIDING_INPUT));
    if (operation == R0SKPH_OP_ADD || operation == R0SKPH_OP_REMOVE) {
        *(PULONG)(pInBuf + sizeof(PROCESS_HIDING_INPUT)) = pid;
    }

    memset(&ioStatus, 0, sizeof(ioStatus));

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
    result = TRUE;
    return result;
}

R0SIMULATES_API BOOL R0SimulatePreviousModeSwitch(BOOL viewOnly, UCHAR mode, UCHAR* pOldMode, UCHAR* pNewMode) {
    BOOL result = FALSE;
    PREVIOUS_MODE_SWITCH_INPUT  in;
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

    memset(&in, 0, sizeof(in));
    in.Mode = mode;
    in.ViewOnly = viewOnly ? 1 : 0;

    memset(&out, 0, sizeof(out));

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
        RtlSetLastWin32Error(NtStatusToWin32Error((NTSTATUS)out.Status));
        return FALSE;
    }
    if (pOldMode) *pOldMode = out.OldMode;
    if (pNewMode) *pNewMode = out.NewMode;
    RtlSetLastWin32Error(ERROR_SUCCESS);
    result = TRUE;
    return result;
}

R0SIMULATES_API BOOL R0SimulateKernelOpenHandle(
    ULONG       Type,
    ACCESS_MASK DesiredAccess,
    UINT64      Target,
    ULONG       AccessMode,
    ULONG       HandleAttributes,
    UINT64      ObjectType,
    PKERNEL_OPEN_HANDLE_OUTPUT pOut)
{
    KERNEL_OPEN_HANDLE_INPUT in;
    IO_STATUS_BLOCK          ioStatus;
    NTSTATUS                 status;

    if (!R0Sim_OpenDriver()) return FALSE;
    if (!pOut) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (Type != R0SKOH_TYPE_HANDLE &&
        Type != R0SKOH_TYPE_POINTER &&
        Type != R0SKOH_TYPE_PID) {
        RtlSetLastWin32Error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    memset(&in, 0, sizeof(in));
    memset(pOut, 0, sizeof(KERNEL_OPEN_HANDLE_OUTPUT));

    in.Type             = Type;
    in.Reserved0        = 0;
    in.DesiredAccess    = DesiredAccess;
    in.Target           = Target;
    in.AccessMode       = AccessMode;
    in.HandleAttributes = HandleAttributes;
    in.ObjectType       = ObjectType;

    memset(&ioStatus, 0, sizeof(ioStatus));
    status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_KERNEL_OPEN_HANDLE,
        &in, sizeof(in),
        pOut, sizeof(KERNEL_OPEN_HANDLE_OUTPUT));

    if (!NT_SUCCESS(status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error(status));
        return FALSE;
    }
    if (!NT_SUCCESS((NTSTATUS)pOut->Status)) {
        RtlSetLastWin32Error(NtStatusToWin32Error((NTSTATUS)pOut->Status));
        return FALSE;
    }
    RtlSetLastWin32Error(ERROR_SUCCESS);
    return TRUE;
}

R0SIMULATES_API BOOL R0SimulateKernelMemoryAccess(UINT64 Address, ULONG Offset, ULONG Length, UCHAR Operation, PVOID Buffer) {
    BOOL result = FALSE;
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
        memcpy(pIn->Data, Buffer, Length);
    }

    memset(&ioStatus, 0, sizeof(ioStatus));

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
        memcpy(Buffer, pIn->Data, Length);
    }
    RtlFreeHeap(R0_HEAP, 0, pIn);
    RtlSetLastWin32Error(ERROR_SUCCESS);
    result = TRUE;
    return result;
}

R0SIMULATES_API HANDLE R0SimulateGetSystemToken(BOOL ReplaceToken) {
    HANDLE result = NULL;
    GET_SYSTEM_TOKEN_INPUT  in;
    GET_SYSTEM_TOKEN_OUTPUT out;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    if (!R0Sim_OpenDriver()) return NULL;

    memset(&in, 0, sizeof(in));
    in.ReplaceToken = ReplaceToken ? 1 : 0;

    memset(&out, 0, sizeof(out));

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
        RtlSetLastWin32Error(NtStatusToWin32Error((NTSTATUS)out.Status));
        return NULL;
    }
    RtlSetLastWin32Error(ERROR_SUCCESS);
    result = out.TokenHandle;
    return result;
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
    BOOL result = FALSE;
    ULONG actualMode;
    SET_INTERNAL_VAR_INPUT in;
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
        Operation != R0SIMULATE_VAR_OP_LIST) {
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

    memset(&in, 0, sizeof(in));
    in.Operation  = Operation;
    in.VariableId = VariableId;
    in.Value      = Value;
    in.NameLength = 0;

    memset(&ioStatus, 0, sizeof(ioStatus));

    status = NtDeviceIoControlFile(
        g_hDriver, NULL, NULL, NULL, &ioStatus,
        IOCTL_R0SIMULATE_SET_INTERNAL_VARS,
        &in, sizeof(in),
        pOutBuffer, outSize
    );

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
    result = TRUE;
    return result;
}

R0SIMULATES_API BOOL R0SimulateGetKernelFunction(
    const WCHAR* FunctionName,
    PVOID pOutBuffer,
    ULONG outSize,
    PULONG pInfoCount)
{
    BOOL result = FALSE;
    ULONG nameLen = 0;
    SIZE_T totalInSize;
    PGET_KERNEL_FUNCTION_INPUT pIn;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    if (!R0Sim_OpenDriver()) return FALSE;

    totalInSize = sizeof(GET_KERNEL_FUNCTION_INPUT);
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
        memcpy(pIn->Name, FunctionName, nameLen);
    }

    memset(&ioStatus, 0, sizeof(ioStatus));

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
    result = TRUE;
    return result;
}

R0SIMULATES_API BOOL R0SimulateIO(
    ULONG  Operation,
    ULONG  Port,
    ULONG  Value,
    PULONG pResult)
{
    BOOL result = FALSE;
    R0S_IO_INPUT  in;
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

    memset(&in, 0, sizeof(in));
    in.Operation = Operation;
    in.Port      = Port;
    in.Value     = Value;

    memset(&out, 0, sizeof(out));

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
        RtlSetLastWin32Error(NtStatusToWin32Error((NTSTATUS)out.Status));
        return FALSE;
    }

    if (pResult) *pResult = out.Value;
    RtlSetLastWin32Error(ERROR_SUCCESS);
    result = TRUE;
    return result;
}