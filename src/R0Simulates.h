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

#define IOCTL_R0SIMULATE_EXEC_INSTRUCTION           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_CALL_KERNEL_API            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_KERNEL_PROCESS_HIDING      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_PREVIOUS_MODE_SWITCH       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_KERNEL_OPEN_HANDLE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_KERNEL_MEMORY_ACCESS       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_GET_SYSTEM_TOKEN           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define R0SIMULATE_FLAG_USE_ADDRESS  0x00000001

#define R0SPMS_MODE_KERNEL  0x00
#define R0SPMS_MODE_USER    0x01

#define R0SKPH_OP_ADD      0x10
#define R0SKPH_OP_REMOVE   0x11
#define R0SKPH_OP_LIST     0x12

#define R0SKMA_OP_READ     0
#define R0SKMA_OP_WRITE    1

typedef struct _EXEC_INSTRUCTION_INPUT {
    ULONG   InstructionSize;
    UCHAR   Instruction[1];
} EXEC_INSTRUCTION_INPUT, *PEXEC_INSTRUCTION_INPUT;

typedef struct _EXEC_INSTRUCTION_OUTPUT {
    UINT64  ReturnValue;
    LONG    Status;
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
    LONG    Status;
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
    LONG    Status;
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
    LONG    Status;
    HANDLE  TokenHandle;
} GET_SYSTEM_TOKEN_OUTPUT, *PGET_SYSTEM_TOKEN_OUTPUT;

R0SIMULATES_API UINT64 R0SimulateISA(const void* pInstruction, ULONG instructionSize);
R0SIMULATES_API UINT64 R0SimulateAPI(const WCHAR* pwszApiName, ULONG argc, ULONG flags, ...);
R0SIMULATES_API BOOL R0SimulateKernelProcessHiding(UCHAR operation, ULONG pid, PVOID pOutBuffer, ULONG outSize);
R0SIMULATES_API BOOL R0SimulatePreviousModeSwitch(BOOL viewOnly, UCHAR mode, UCHAR* pOldMode, UCHAR* pNewMode);
R0SIMULATES_API HANDLE R0SimulateKernelOpenHandle(ULONG pid);
R0SIMULATES_API BOOL R0SimulateKernelMemoryAccess(UINT64 Address, ULONG Offset, ULONG Length, UCHAR Operation, PVOID Buffer);
R0SIMULATES_API HANDLE R0SimulateGetSystemToken(BOOL ReplaceToken);

#ifdef __cplusplus
}
#endif