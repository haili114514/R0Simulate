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
#define IOCTL_R0SIMULATE_PROCESS_HIDING             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_PREVIOUS_MODE_SWITCH       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_OPEN_HANDLE                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_KERNEL_READWRITE_EPROCESS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define R0SIMULATE_FLAG_USE_ADDRESS  0x00000001

#define R0SPMS_MODE_KERNEL  0x00
#define R0SPMS_MODE_USER    0x01

#define R0SKRE_OP_READ   0
#define R0SKRE_OP_WRITE  1
#define R0SKRE_SIZE_1    0
#define R0SKRE_SIZE_2    1
#define R0SKRE_SIZE_4    2
#define R0SKRE_SIZE_8    3
#define R0SKRE_MAKE_OP(sizeCode, op)  (((sizeCode) << 1) | ((op) & 1))

#define R0SKPH_OP_ADD      0x10
#define R0SKPH_OP_REMOVE   0x11
#define R0SKPH_OP_LIST     0x12

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

typedef struct _KERNEL_RW_EPROCESS_INPUT {
    ULONG   Offset;
    UCHAR   Operation;
    UCHAR   Reserved[3];
    UINT64  Value;
} KERNEL_RW_EPROCESS_INPUT, *PKERNEL_RW_EPROCESS_INPUT;

typedef struct _KERNEL_RW_EPROCESS_OUTPUT {
    LONG    Status;
    UINT64  ReturnValue;
} KERNEL_RW_EPROCESS_OUTPUT, *PKERNEL_RW_EPROCESS_OUTPUT;

R0SIMULATES_API UINT64 R0SimulateISA(const void* pInstruction, ULONG instructionSize);

R0SIMULATES_API UINT64 R0SimulateAPI(const WCHAR* pwszApiName, ULONG argc, ULONG flags, ...);

R0SIMULATES_API BOOL R0SimulateProcessHiding(UCHAR operation, ULONG pid, PVOID pOutBuffer, ULONG outSize);

R0SIMULATES_API BOOL R0SimulatePreviousModeSwitch(BOOL viewOnly, UCHAR mode, UCHAR* pOldMode, UCHAR* pNewMode);

R0SIMULATES_API HANDLE R0SimulateKernelOpenHandle(ULONG pid);

R0SIMULATES_API UINT64 R0SimulateKernelReadWriteEprocess(ULONG offset, UCHAR operation, UCHAR sizeCode, UINT64 value);

#ifdef __cplusplus
}
#endif
