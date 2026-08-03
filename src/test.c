#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>   // 提供 NT_SUCCESS 宏
#include "R0Simulates.h"

#pragma comment(lib, "ntdll.lib")   // 如需链接 ntdll（可选）

static void print_last_error(const char* msg) {
    DWORD err = GetLastError();
    fprintf(stderr, "[!] %s failed, error code: %lu\n", msg, err);
}

int main() {
    printf("===== R0Simulate Full Feature Demo =====\n");
    printf("Make sure driver R0Simulate.sys is loaded and Test Signing is enabled.\n\n");

    // ------------------------------------------------------------
    // 1. R0SISA - Execute arbitrary machine code
    // ------------------------------------------------------------
    printf("[1] R0SimulateISA: mov eax, 1234; ret\n");
    BYTE code[] = {0xB8, 0xD2, 0x04, 0x00, 0x00, 0xC3}; // mov eax, 1234; ret
    UINT64 isa_result = R0SimulateISA(code, sizeof(code));
    if (isa_result == 1234) {
        printf("    OK: returned 0x%llX (expected 0x4D2)\n", isa_result);
    } else {
        printf("    FAIL: returned 0x%llX, GetLastError = %lu\n", isa_result, GetLastError());
    }

    // ------------------------------------------------------------
    // 2. R0SAPI - Call kernel API by name
    // ------------------------------------------------------------
    printf("\n[2] R0SAPI: Call ZwQuerySystemInformation (SystemBasicInfo)\n");
    typedef struct _SYSTEM_BASIC_INFORMATION {
        ULONG Unknown;
        ULONG MaximumIncrement;
        ULONG PhysicalPageSize;
        ULONG NumberOfPhysicalPages;
        ULONG LowestPhysicalPage;
        ULONG HighestPhysicalPage;
        ULONG AllocationGranularity;
        ULONG MinimumUserModeAddress;
        ULONG MaximumUserModeAddress;
        ULONG ActiveProcessorsAffinityMask;
        UCHAR NumberOfProcessors;
    } SYSTEM_BASIC_INFORMATION;

    SYSTEM_BASIC_INFORMATION sbi = {0};
    // SystemBasicInformation = 0
    UINT64 api_status = R0SimulateAPI(
        L"ZwQuerySystemInformation",   // API name
        3,                             // argc = 3
        0,                             // flags = 0 (name mode)
        (UINT64)0,                     // arg1: SystemInformationClass
        (UINT64)&sbi,                  // arg2: SystemInformation
        (UINT64)sizeof(sbi)            // arg3: Length
    );

    if (api_status == 0) {
        printf("    OK: CPU cores = %u, PageSize = %u KB\n",
               sbi.NumberOfProcessors, sbi.PhysicalPageSize / 1024);
    } else {
        printf("    FAIL: status 0x%llX\n", api_status);
    }

    // ------------------------------------------------------------
    // 3. R0SPMS - Switch PreviousMode (view then modify)
    // ------------------------------------------------------------
    printf("\n[3] R0SPMS: Read and switch thread PreviousMode\n");
    UCHAR oldMode, newMode;
    BOOL ok = R0SimulatePreviousModeSwitch(TRUE, 0, &oldMode, &newMode);
    if (ok) {
        printf("    Current PreviousMode: %s (%u)\n",
               (oldMode == 0) ? "Kernel" : "User", oldMode);
        printf("    Switching to Kernel mode...\n");
        ok = R0SimulatePreviousModeSwitch(FALSE, R0SPMS_MODE_KERNEL, &oldMode, &newMode);
        if (ok) {
            printf("    Switch succeeded: %u -> %u, restoring to User...\n", oldMode, newMode);
            R0SimulatePreviousModeSwitch(FALSE, R0SPMS_MODE_USER, &oldMode, &newMode);
            printf("    Restored to %u\n", newMode);
        } else {
            print_last_error("R0SPMS (write)");
        }
    } else {
        print_last_error("R0SPMS (read)");
    }

    // ------------------------------------------------------------
    // 4. R0SKOH - Open full-access handle to any process
    // ------------------------------------------------------------
    printf("\n[4] R0SKOH: Open current process (PID = %lu)\n", GetCurrentProcessId());
    HANDLE hProc = R0SimulateKernelOpenHandle(GetCurrentProcessId());
    if (hProc != NULL) {
        printf("    OK: handle = %p\n", hProc);
        CloseHandle(hProc);
    } else {
        print_last_error("R0SKOH");
    }

    // ------------------------------------------------------------
    // 5. R0SKRE - Read/Write EPROCESS (read 8 bytes at offset 0)
    // ------------------------------------------------------------
    printf("\n[5] R0SKRE: Read 8 bytes from current EPROCESS at offset 0\n");
    UINT64 eprocess_val = R0SimulateKernelReadWriteEprocess(
        0,                  // offset
        R0SKRE_OP_READ,     // read
        R0SKRE_SIZE_8,      // 8 bytes
        0                   // value (ignored on read)
    );
    DWORD err = GetLastError();
    if (err == ERROR_SUCCESS) {
        printf("    OK: read value = 0x%016llX\n", eprocess_val);
    } else {
        printf("    FAIL: error = %lu\n", err);
    }

    // ------------------------------------------------------------
    // 6. R0SKPH - Hide/Unhide process
    // ------------------------------------------------------------
    printf("\n[6] R0SKPH: Hide current process (PID = %lu)\n", GetCurrentProcessId());
    NTSTATUS status;
    ok = R0SimulateProcessHiding(R0SKPH_OP_ADD, GetCurrentProcessId(),
                                 &status, sizeof(status));
    if (ok && NT_SUCCESS(status)) {
        printf("    OK: process hidden\n");
        // List hidden processes
        ULONG listBuf[64] = {0};
        ok = R0SimulateProcessHiding(R0SKPH_OP_LIST, 0, listBuf, sizeof(listBuf));
        if (ok) {
            ULONG count = listBuf[0];
            printf("    Hidden count: %lu\n", count);
            for (ULONG i = 0; i < count && i < 20; i++) {
                printf("      PID: %lu\n", listBuf[1 + i]);
            }
        } else {
            print_last_error("R0SKPH LIST");
        }
        // Unhide
        ok = R0SimulateProcessHiding(R0SKPH_OP_REMOVE, GetCurrentProcessId(),
                                     &status, sizeof(status));
        if (ok && NT_SUCCESS(status)) {
            printf("    OK: process restored\n");
        } else {
            print_last_error("R0SKPH REMOVE");
        }
    } else {
        print_last_error("R0SKPH ADD");
    }

    printf("\n===== Demo finished. Press any key to exit =====\n");
    getchar();
    return 0;
}
