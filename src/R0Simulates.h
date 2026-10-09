#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#ifdef R0SIMULATES_EXPORTS
#define R0SIMULATES_API __declspec(dllexport)
#else
#define R0SIMULATES_API __declspec(dllimport)
#endif

#include <windows.h>
#include <winioctl.h>

// ----- IOCTL -----
#define IOCTL_R0SIMULATE_EXEC_INSTRUCTION           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_CALL_KERNEL_API            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_KERNEL_PROCESS_HIDING      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_PREVIOUS_MODE_SWITCH       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_KERNEL_OPEN_HANDLE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_KERNEL_MEMORY_ACCESS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_GET_SYSTEM_TOKEN           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_SET_INTERNAL_VARS          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_GET_KERNEL_FUNCTION        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_IO                         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_AUTHORIZED_LIST            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_CREATE_SYSTEM_THREAD       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_DIRECT_CREATE_DRIVER       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_MSR                        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80D, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_IRQL                       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_ARBITRARY_DRIVER_CALL      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80F, METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_INDEX_EXEC_INSTRUCTION      0
#define IOCTL_INDEX_CALL_KERNEL_API       1
#define IOCTL_INDEX_PROCESS_HIDING        2
#define IOCTL_INDEX_PREVIOUS_MODE_SWITCH  3
#define IOCTL_INDEX_KERNEL_OPEN_HANDLE    4
#define IOCTL_INDEX_KERNEL_MEMORY_ACCESS  5
#define IOCTL_INDEX_GET_SYSTEM_TOKEN      6
#define IOCTL_INDEX_SET_INTERNAL_VARS     7
#define IOCTL_INDEX_GET_KERNEL_FUNCTION   8
#define IOCTL_INDEX_IO                    9
#define IOCTL_INDEX_AUTHORIZED_LIST       10
#define IOCTL_INDEX_CREATE_SYSTEM_THREAD  11
#define IOCTL_INDEX_DIRECT_CREATE_DRIVER  12
#define IOCTL_INDEX_MSR                   13
#define IOCTL_INDEX_IRQL                  14
#define IOCTL_INDEX_ARBITRARY_DRIVER_CALL 15

// ----- Flags -----
#define R0SIMULATE_FLAG_USE_ADDRESS  0x00000001
#define R0SIMULATE_FLAG_SSN_MODE     0x00000002

// ----- Previous Mode -----
#define R0SPMS_MODE_KERNEL  0x00
#define R0SPMS_MODE_USER    0x01

// ----- Process Hiding -----
#define R0SKPH_OP_ADD      0x10
#define R0SKPH_OP_REMOVE   0x11
#define R0SKPH_OP_LIST     0x12

// ----- Memory Access -----
#define R0SKMA_OP_READ     0
#define R0SKMA_OP_WRITE    1

// ----- R0SKOH -----
#define R0SKOH_TYPE_HANDLE   0
#define R0SKOH_TYPE_POINTER  1
#define R0SKOH_TYPE_PID      2

// ----- R0SKOH Access Mode -----
#define R0SKOH_ACCESS_MODE_KERNEL   0
#define R0SKOH_ACCESS_MODE_USER     1

// ----- Internal Variables Operation -----
#define R0SIMULATE_VAR_OP_GET   0x01
#define R0SIMULATE_VAR_OP_SET   0x02
#define R0SIMULATE_VAR_OP_LIST  0x03
#define R0SIMULATE_VAR_NAME_FLAG  0x8000000000000000ULL
#define R0SIMULATE_VAR_ID_MASK    0x7FFFFFFFFFFFFFFFULL

// ----- DLL internal variable ID -----
#define R0SIMULATE_VAR_DLL_ERROR_MODE   0x1000

// ----- Error mode control -----
#define R0SIMULATE_ERROR_MODE_DEFAULT   ((ULONG)-1)

// ----- I/O Port -----
#define R0SIO_READ_BYTE     0x01
#define R0SIO_READ_WORD     0x02
#define R0SIO_READ_DWORD    0x03
#define R0SIO_WRITE_BYTE    0x11
#define R0SIO_WRITE_WORD    0x12
#define R0SIO_WRITE_DWORD   0x13

// ----- Authorized List -----
#define R0SAUTH_OP_ADD      0x01
#define R0SAUTH_OP_REMOVE   0x02
#define R0SAUTH_OP_LIST     0x03

// ----- MSR -----
#define R0SMSR_OP_READ      0x01
#define R0SMSR_OP_WRITE     0x02

// ----- IRQL -----
#define R0SIRQL_OP_QUERY    0x01
#define R0SIRQL_OP_RAISE    0x02
#define R0SIRQL_OP_LOWER    0x03

#define R0S_REQUESTOR_MODE_KERNEL   0x00
#define R0S_REQUESTOR_MODE_USER     0x01

// ----- Structures -----
typedef struct _EXEC_INSTRUCTION_INPUT {
    ULONG   InstructionSize;
    UCHAR   Instruction[1];
} EXEC_INSTRUCTION_INPUT, *PEXEC_INSTRUCTION_INPUT;

typedef struct _EXEC_INSTRUCTION_OUTPUT {
    UINT64   ReturnValue;
    NTSTATUS Status;
} EXEC_INSTRUCTION_OUTPUT, *PEXEC_INSTRUCTION_OUTPUT;

typedef struct _CALL_KERNEL_API_INPUT {
    ULONG   ApiNameLength;
    ULONG   ArgumentCount;
    ULONG   Flags;
    UINT64  Arguments[16];
    WCHAR   ApiName[1];
} CALL_KERNEL_API_INPUT, *PCALL_KERNEL_API_INPUT;

typedef struct _CALL_KERNEL_API_OUTPUT {
    UINT64   ReturnValue;
    NTSTATUS Status;
} CALL_KERNEL_API_OUTPUT, *PCALL_KERNEL_API_OUTPUT;

typedef struct _PROCESS_HIDING_INPUT {
    UINT64  Address;
    ULONG   Length;
    UCHAR   Operation;
    UCHAR   Reserved[3];
} PROCESS_HIDING_INPUT, *PPROCESS_HIDING_INPUT;

typedef struct _PROCESS_HIDING_LIST_OUTPUT {
    ULONG   Count;
    HANDLE  Pids[1];
} PROCESS_HIDING_LIST_OUTPUT, *PPROCESS_HIDING_LIST_OUTPUT;

typedef struct _PREVIOUS_MODE_SWITCH_INPUT {
    UCHAR   Mode;
    UCHAR   ViewOnly;
    UCHAR   Reserved[6];
} PREVIOUS_MODE_SWITCH_INPUT, *PPREVIOUS_MODE_SWITCH_INPUT;

typedef struct _PREVIOUS_MODE_SWITCH_OUTPUT {
    NTSTATUS Status;
    UCHAR    OldMode;
    UCHAR    NewMode;
} PREVIOUS_MODE_SWITCH_OUTPUT, *PPREVIOUS_MODE_SWITCH_OUTPUT;

typedef struct _KERNEL_OPEN_HANDLE_INPUT {
    ULONG       Type;
    ULONG       Reserved0;
    ACCESS_MASK DesiredAccess;
    UINT64      Target;
    ULONG       AccessMode;
    ULONG       HandleAttributes;
    UINT64      ObjectType;
} KERNEL_OPEN_HANDLE_INPUT, *PKERNEL_OPEN_HANDLE_INPUT;

typedef struct _KERNEL_OPEN_HANDLE_OUTPUT {
    HANDLE      ResultHandle;
    ACCESS_MASK ActualGrantedAccess;
    NTSTATUS    Status;
    PVOID       KernelPointer;
    ULONG       Type;
    ULONG       Reserved;
} KERNEL_OPEN_HANDLE_OUTPUT, *PKERNEL_OPEN_HANDLE_OUTPUT;

typedef struct _KERNEL_MEMORY_ACCESS_INPUT {
    UINT64  Address;
    ULONG   Offset;
    ULONG   Length;
    UCHAR   Operation;
    UCHAR   Reserved[3];
} KERNEL_MEMORY_ACCESS_INPUT, *PKERNEL_MEMORY_ACCESS_INPUT;

typedef struct _GET_SYSTEM_TOKEN_INPUT {
    UCHAR   ReplaceToken;
    UCHAR   Reserved[7];
} GET_SYSTEM_TOKEN_INPUT, *PGET_SYSTEM_TOKEN_INPUT;

typedef struct _GET_SYSTEM_TOKEN_OUTPUT {
    NTSTATUS Status;
    HANDLE   TokenHandle;
} GET_SYSTEM_TOKEN_OUTPUT, *PGET_SYSTEM_TOKEN_OUTPUT;

typedef struct _SET_INTERNAL_VAR_INPUT {
    ULONG   Operation;
    ULONG   VariableId;
    UINT64  Value;
    ULONG   NameLength;
    UCHAR   Reserved[4];
} SET_INTERNAL_VAR_INPUT, *PSET_INTERNAL_VAR_INPUT;

typedef struct _VAR_INFO {
    ULONG   Id;
    ULONG   Size;
    UINT64  Value;
    WCHAR   Name[64];
} VAR_INFO, *PVAR_INFO;

typedef struct _GET_KERNEL_FUNCTION_INPUT {
    ULONG   NameLength;
    WCHAR   Name[1];
} GET_KERNEL_FUNCTION_INPUT, *PGET_KERNEL_FUNCTION_INPUT;

typedef struct _KERNEL_FUNCTION_ENTRY {
    UINT64  Address;
    WCHAR   Name[64];
} KERNEL_FUNCTION_ENTRY, *PKERNEL_FUNCTION_ENTRY;

typedef struct _SSDT_FUNC_ENTRY {
    ULONG   Ssn;
    UINT64  Address;
    WCHAR   Name[64];
} SSDT_FUNC_ENTRY, *PSSDT_FUNC_ENTRY;

typedef SSDT_FUNC_ENTRY SSDT_ENTRY_INFO, *PSSDT_ENTRY_INFO;

typedef struct _R0S_IO_INPUT {
    ULONG   Operation;
    ULONG   Port;
    ULONG   Value;
} R0S_IO_INPUT, *PR0S_IO_INPUT;

typedef struct _R0S_IO_OUTPUT {
    ULONG    Value;
    NTSTATUS Status;
} R0S_IO_OUTPUT, *PR0S_IO_OUTPUT;

typedef struct _R0S_AUTH_LIST_INPUT {
    ULONG Operation;
    ULONG Pid;
} R0S_AUTH_LIST_INPUT, *PR0S_AUTH_LIST_INPUT;

typedef struct _R0S_AUTH_ENTRY_INFO {
    HANDLE Pid;
    ULONG  Reserved;
    UCHAR  Valid;
    UCHAR  Pad[7];
} R0S_AUTH_ENTRY_INFO, *PR0S_AUTH_ENTRY_INFO;

typedef struct _R0S_AUTH_LIST_OUTPUT {
    ULONG Count;
    ULONG Reserved;
    R0S_AUTH_ENTRY_INFO Entries[1];
} R0S_AUTH_LIST_OUTPUT, *PR0S_AUTH_LIST_OUTPUT;

typedef struct _R0S_CREATE_THREAD_INPUT {
    UINT64 StartRoutine;
    UINT64 StartContext;
    ULONG  DesiredAccess;
    ULONG  Reserved;
} R0S_CREATE_THREAD_INPUT, *PR0S_CREATE_THREAD_INPUT;

typedef struct _R0S_CREATE_THREAD_OUTPUT {
    HANDLE   ThreadHandle;
    NTSTATUS Status;
} R0S_CREATE_THREAD_OUTPUT, *PR0S_CREATE_THREAD_OUTPUT;

typedef struct _R0S_CREATE_DRIVER_INPUT {
    UINT64 InitFunction;
    ULONG  NameLength;
    ULONG  Reserved;
    WCHAR  Name[1];
} R0S_CREATE_DRIVER_INPUT, *PR0S_CREATE_DRIVER_INPUT;

typedef struct _R0S_CREATE_DRIVER_OUTPUT {
    UINT64   DriverObject;
    NTSTATUS Status;
} R0S_CREATE_DRIVER_OUTPUT, *PR0S_CREATE_DRIVER_OUTPUT;

typedef struct _R0S_MSR_INPUT {
    ULONG  Operation;
    ULONG  Msr;
    UINT64 Value;
} R0S_MSR_INPUT, *PR0S_MSR_INPUT;

typedef struct _R0S_MSR_OUTPUT {
    UINT64   Value;
    NTSTATUS Status;
} R0S_MSR_OUTPUT, *PR0S_MSR_OUTPUT;

typedef struct _R0S_IRQL_INPUT {
    ULONG Operation;
    UCHAR TargetIrql;
    UCHAR Reserved[3];
} R0S_IRQL_INPUT, *PR0S_IRQL_INPUT;

typedef struct _R0S_IRQL_OUTPUT {
    UCHAR    OldIrql;
    UCHAR    NewIrql;
    UCHAR    Reserved[2];
    NTSTATUS Status;
} R0S_IRQL_OUTPUT, *PR0S_IRQL_OUTPUT;

typedef struct _R0S_CALL_DRIVER_INPUT {
    UINT64 DriverObject;
    ULONG  MajorFunction;
    ULONG  MinorFunction;
    ULONG  IoControlCode;
    ULONG  InputLength;
    ULONG  OutputLength;
    ULONG  RequestorMode;
    UCHAR  Data[1];
} R0S_CALL_DRIVER_INPUT, *PR0S_CALL_DRIVER_INPUT;

typedef struct _R0S_CALL_DRIVER_OUTPUT {
    NTSTATUS Status;
    ULONG    Information;
    ULONG    Reserved;
    UCHAR    Data[1];
} R0S_CALL_DRIVER_OUTPUT, *PR0S_CALL_DRIVER_OUTPUT;

// ----- Exported Functions -----
R0SIMULATES_API UINT64 R0SimulateISA(
    const void* pInstruction,
    ULONG       instructionSize);

R0SIMULATES_API UINT64 R0SimulateAPI(
    const WCHAR* pwszApiName,
    ULONG        argc,
    ULONG        flags,
    ...);

R0SIMULATES_API BOOL R0SimulateKernelProcessHiding(
    UCHAR operation,
    ULONG pid,
    PVOID pOutBuffer,
    ULONG outSize);

R0SIMULATES_API BOOL R0SimulatePreviousModeSwitch(
    BOOL   viewOnly,
    UCHAR  mode,
    UCHAR* pOldMode,
    UCHAR* pNewMode);

R0SIMULATES_API BOOL R0SimulateKernelOpenHandle(
    ULONG       Type,
    ACCESS_MASK DesiredAccess,
    UINT64      Target,
    ULONG       AccessMode,
    ULONG       HandleAttributes,
    UINT64      ObjectType,
    PKERNEL_OPEN_HANDLE_OUTPUT pOut);

R0SIMULATES_API BOOL R0SimulateKernelMemoryAccess(
    UINT64 Address,
    ULONG  Offset,
    ULONG  Length,
    UCHAR  Operation,
    PVOID  Buffer);

R0SIMULATES_API HANDLE R0SimulateGetSystemToken(
    BOOL ReplaceToken);

R0SIMULATES_API BOOL R0SimulateSetInternalVariables(
    ULONG  Operation,
    UINT64 VariableId,
    UINT64 Value,
    PVOID  pOutBuffer,
    ULONG  outSize,
    PULONG pInfoCount,
    ULONG  ErrorMode);

R0SIMULATES_API BOOL R0SimulateGetKernelFunction(
    const WCHAR* FunctionName,
    PVOID pOutBuffer,
    ULONG outSize,
    PULONG pInfoCount);

R0SIMULATES_API BOOL R0SimulateIO(
    ULONG  Operation,
    ULONG  Port,
    ULONG  Value,
    PULONG pResult);

R0SIMULATES_API BOOL R0SimulateAuthorizedListOperations(
    ULONG  operation,
    ULONG  pid,
    PVOID  pOutBuffer,
    ULONG  outSize,
    PULONG pInfoCount);

R0SIMULATES_API BOOL R0SimulateCreateSystemThread(
    UINT64  startRoutine,
    UINT64  startContext,
    ULONG   desiredAccess,
    PHANDLE pOutThreadHandle);

R0SIMULATES_API BOOL R0SimulateDirectCreateDriver(
    UINT64       initFunction,
    const WCHAR* driverName,
    PUINT64      pOutDriverObject);

R0SIMULATES_API BOOL R0SimulateMSR(
    ULONG   operation,
    ULONG   msr,
    UINT64  value,
    PUINT64 pOutValue);

R0SIMULATES_API BOOL R0SimulateIRQL(
    ULONG  operation,
    UCHAR  targetIrql,
    PUCHAR pOldIrql,
    PUCHAR pNewIrql);

R0SIMULATES_API BOOL R0SimulateArbitraryDriverCall(
    UINT64 driverObject,
    ULONG  majorFunction,
    ULONG  minorFunction,
    ULONG  ioControlCode,
    PVOID  pInputData,
    ULONG  inputLength,
    PVOID  pOutBuffer,
    ULONG  outSize,
    PULONG pInformation,
    ULONG  requestorMode);

#ifdef __cplusplus
}
#endif