
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>

#define IOCTL_R0SIMULATE_CALLBACK_CONTROL  0x222030UL

#define R0SCB_OP_LIST   5

typedef struct _R0S_CB_BASE_INPUT {
    ULONG Operation;
    ULONG TargetTid;
} R0S_CB_BASE_INPUT;

typedef struct _R0S_CALLBACK_ENTRY_INFO {
    HANDLE    ThreadId;
    NTSTATUS  ExitStatus;
    ULONG     Priority;
    UINT64    Mask;
    ULONG     Active;
    ULONG     CallCount;
    UINT64    LastResult;
} R0S_CALLBACK_ENTRY_INFO;

typedef struct _R0S_CALLBACK_CTL_OUTPUT {
    ULONG  Count;
    ULONG  Reserved;          
    UINT64 Enabled;           
    WCHAR  Altitude[32];      
    R0S_CALLBACK_ENTRY_INFO Entries[1];
} R0S_CALLBACK_CTL_OUTPUT;

int main(void)
{
    HANDLE h;
    R0S_CB_BASE_INPUT in;
    BYTE  outBuf[64 * 1024];
    DWORD bytesReturned = 0;
    R0S_CALLBACK_CTL_OUTPUT *pOut;
    ULONG i;

    h = CreateFileW(L"\\\\.\\R0Simulate",
                    GENERIC_READ | GENERIC_WRITE,
                    0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed: 0x%08lX\n", GetLastError());
        return 1;
    }

    in.Operation = R0SCB_OP_LIST;
    in.TargetTid = 0;
    ZeroMemory(outBuf, sizeof(outBuf));

    if (!DeviceIoControl(h,
                         IOCTL_R0SIMULATE_CALLBACK_CONTROL,
                         &in, sizeof(in),
                         outBuf, sizeof(outBuf),
                         &bytesReturned, NULL)) {
        printf("DeviceIoControl failed: 0x%08lX\n", GetLastError());
        CloseHandle(h);
        return 1;
    }

    pOut = (R0S_CALLBACK_CTL_OUTPUT *)outBuf;

    printf("Enabled  = %llu\n",  (unsigned long long)pOut->Enabled);
    printf("Mask     = 0x%04X\n", (unsigned)pOut->Reserved);
    printf("Altitude = %ls\n",   pOut->Altitude);
    printf("Count    = %lu  (returned bytes = %lu)\n\n",
           (unsigned long)pOut->Count, (unsigned long)bytesReturned);

    if (pOut->Count == 0) {
        printf("(no client entries registered via R0SCB_OP_ADD)\n");
        CloseHandle(h);
        return 0;
    }

    printf("%-10s %-12s %-6s %-18s %-6s %-10s %s\n",
           "ThreadId", "ExitStatus", "Prio", "Mask",
           "Active", "CallCount", "LastResult");
    printf("%-10s %-12s %-6s %-18s %-6s %-10s %s\n",
           "--------", "----------", "----", "------------------",
           "------", "---------", "----------");

    for (i = 0; i < pOut->Count; i++) {
        R0S_CALLBACK_ENTRY_INFO *e = &pOut->Entries[i];
        printf("%-10llu 0x%08X   %-6lu 0x%016llX %-6lu %-10lu 0x%016llX\n",
               (unsigned long long)(ULONG_PTR)e->ThreadId,
               (unsigned)e->ExitStatus,
               (unsigned long)e->Priority,
               (unsigned long long)e->Mask,
               (unsigned long)e->Active,
               (unsigned long)e->CallCount,
               (unsigned long long)e->LastResult);
    }

    CloseHandle(h);
    return 0;
}