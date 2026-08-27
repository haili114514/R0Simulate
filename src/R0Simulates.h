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
#define IOCTL_R0SIMULATE_EXEC_INSTRUCTION           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_CALL_KERNEL_API            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_KERNEL_PROCESS_HIDING      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_PREVIOUS_MODE_SWITCH       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_KERNEL_OPEN_HANDLE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_KERNEL_MEMORY_ACCESS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_GET_SYSTEM_TOKEN           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_SET_INTERNAL_VARS          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_GET_KERNEL_FUNCTION        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_IO                         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

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

// ----- Internal Variables Operation -----
#define R0SIMULATE_VAR_OP_GET   0x01
#define R0SIMULATE_VAR_OP_SET   0x02
#define R0SIMULATE_VAR_OP_LIST  0x03

// ----- Internal Variable IDs (Sync with driver VAR_DESC 1~28) -----
#define R0SIMULATE_VAR_PREVIOUS_MODE_OFFSET         1
#define R0SIMULATE_VAR_ACTIVE_PROCESS_LINKS_OFFSET  2
#define R0SIMULATE_VAR_PRIMARY_TOKEN_FROZEN_OFFSET  3
#define R0SIMULATE_VAR_FUNCTION_LOOKUP_MODE         4
#define R0SIMULATE_VAR_GET_FUNCTION_MODE            5

#define VAR_IOCTL_DISABLE_EXEC_INSTRUCTION     6
#define VAR_IOCTL_DISABLE_CALL_KERNEL_API      7
#define VAR_IOCTL_DISABLE_PROCESS_HIDING       8
#define VAR_IOCTL_DISABLE_PREVIOUS_MODE_SWITCH 9
#define VAR_IOCTL_DISABLE_KERNEL_OPEN_HANDLE   10
#define VAR_IOCTL_DISABLE_KERNEL_MEMORY_ACCESS 11
#define VAR_IOCTL_DISABLE_GET_SYSTEM_TOKEN     12
#define VAR_IOCTL_DISABLE_SET_INTERNAL_VARS    13
#define VAR_IOCTL_DISABLE_GET_KERNEL_FUNCTION  14
#define VAR_IOCTL_DISABLE_IO                   15

#define VAR_SECURE_MODE                        16
#define VAR_COUNT_EXEC_INSTRUCTION             17
#define VAR_COUNT_CALL_KERNEL_API              18
#define VAR_COUNT_PROCESS_HIDING               19
#define VAR_COUNT_PREVIOUS_MODE_SWITCH         20
#define VAR_COUNT_KERNEL_OPEN_HANDLE           21
#define VAR_COUNT_KERNEL_MEMORY_ACCESS         22
#define VAR_COUNT_GET_SYSTEM_TOKEN             23
#define VAR_COUNT_SET_INTERNAL_VARS            24
#define VAR_COUNT_GET_KERNEL_FUNCTION          25
#define VAR_COUNT_IO                           26

#define VAR_ATTR_DESCRIPTOR                    27
#define VAR_ANTI_KILL                          28

// ----- I/O Port Operations -----
#define R0SIO_READ_BYTE     0x01
#define R0SIO_READ_WORD     0x02
#define R0SIO_READ_DWORD    0x03
#define R0SIO_WRITE_BYTE    0x11
#define R0SIO_WRITE_WORD    0x12
#define R0SIO_WRITE_DWORD   0x13

// ----- Structures (must match driver binary layout exactly) -----
typedef struct _EXEC_INSTRUCTION_INPUT {
    ULONG   InstructionSize;
    UCHAR   Instruction[1];
} EXEC_INSTRUCTION_INPUT, *PEXEC_INSTRUCTION_INPUT;

typedef struct _EXEC_INSTRUCTION_OUTPUT {
    UINT64  ReturnValue;
    ULONG   Status;
} EXEC_INSTRUCTION_OUTPUT, *PEXEC_INSTRUCTION_OUTPUT;

typedef struct _CALL_KERNEL_API_INPUT {
    ULONG   ApiNameLength;
    ULONG   ArgumentCount;
    ULONG   Flags;
    UINT64  Arguments[16];
    WCHAR   ApiName[1];
} CALL_KERNEL_API_INPUT, *PCALL_KERNEL_API_INPUT;

typedef struct _CALL_KERNEL_API_OUTPUT {
    UINT64  ReturnValue;
    ULONG   Status;
} CALL_KERNEL_API_OUTPUT, *PCALL_KERNEL_API_OUTPUT;

typedef struct _PROCESS_HIDING_INPUT {
    UINT64  Address;
    ULONG   Length;
    UCHAR   Operation;
    UCHAR   Reserved[3];
} PROCESS_HIDING_INPUT, *PPROCESS_HIDING_INPUT;

typedef struct _PREVIOUS_MODE_SWITCH_INPUT {
    UCHAR   Mode;
    UCHAR   ViewOnly;
    UCHAR   Reserved[6];
} PREVIOUS_MODE_SWITCH_INPUT, *PPREVIOUS_MODE_SWITCH_INPUT;

typedef struct _PREVIOUS_MODE_SWITCH_OUTPUT {
    ULONG   Status;
    UCHAR   OldMode;
    UCHAR   NewMode;
} PREVIOUS_MODE_SWITCH_OUTPUT, *PPREVIOUS_MODE_SWITCH_OUTPUT;

typedef struct _KERNEL_MEMORY_ACCESS_INPUT {
    UINT64  Address;
    ULONG   Offset;
    ULONG   Length;
    UCHAR   Operation;
    UCHAR   Reserved[3];
    UCHAR   Data[1];
} KERNEL_MEMORY_ACCESS_INPUT, *PKERNEL_MEMORY_ACCESS_INPUT;

typedef struct _GET_SYSTEM_TOKEN_INPUT {
    UCHAR   ReplaceToken;
    UCHAR   Reserved[7];
} GET_SYSTEM_TOKEN_INPUT, *PGET_SYSTEM_TOKEN_INPUT;

typedef struct _GET_SYSTEM_TOKEN_OUTPUT {
    ULONG   Status;
    HANDLE  TokenHandle;
} GET_SYSTEM_TOKEN_OUTPUT, *PGET_SYSTEM_TOKEN_OUTPUT;

typedef struct _SET_INTERNAL_VAR_INPUT {
    ULONG   Operation;
    ULONG   VariableId;
    UINT64  Value;
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

typedef struct _R0S_IO_INPUT {
    ULONG   Operation;
    ULONG   Port;
    ULONG   Value;
} R0S_IO_INPUT, *PR0S_IO_INPUT;

typedef struct _R0S_IO_OUTPUT {
    ULONG   Value;
    ULONG   Status;
} R0S_IO_OUTPUT, *PR0S_IO_OUTPUT;

R0SIMULATES_API UINT64 R0SimulateISA(const void* pInstruction, ULONG instructionSize);
R0SIMULATES_API UINT64 R0SimulateAPI(const WCHAR* pwszApiName, ULONG argc, ULONG flags, ...);
R0SIMULATES_API BOOL R0SimulateKernelProcessHiding(UCHAR operation, ULONG pid, PVOID pOutBuffer, ULONG outSize);
R0SIMULATES_API BOOL R0SimulatePreviousModeSwitch(BOOL viewOnly, UCHAR mode, UCHAR* pOldMode, UCHAR* pNewMode);
R0SIMULATES_API HANDLE R0SimulateKernelOpenHandle(ULONG pid);
R0SIMULATES_API BOOL R0SimulateKernelMemoryAccess(UINT64 Address, ULONG Offset, ULONG Length, UCHAR Operation, PVOID Buffer);
R0SIMULATES_API HANDLE R0SimulateGetSystemToken(BOOL ReplaceToken);
R0SIMULATES_API BOOL R0SimulateSetInternalVariables(
    ULONG  Operation,
    ULONG  VariableId,
    UINT64 Value,
    PVOID  pOutBuffer,
    ULONG  outSize,
    PULONG pInfoCount
);
R0SIMULATES_API BOOL R0SimulateGetKernelFunction(
    const WCHAR* FunctionName,
    PVOID pOutBuffer,
    ULONG outSize,
    PULONG pInfoCount
);
R0SIMULATES_API BOOL R0SimulateIO(
    ULONG Operation,
    ULONG Port,
    ULONG Value,
    PULONG pResult
);

#ifdef __cplusplus
}
#endif
