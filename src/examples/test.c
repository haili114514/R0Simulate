#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <securitybaseapi.h>
#include "R0Simulates.h"

static void print_last_error(const char* msg) {
    DWORD err = GetLastError();
    fprintf(stderr, "[!] %s failed, error code: %lu\n", msg, err);
}

// Get current process user name for token verification
static void PrintCurrentUserName() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        printf("    [Failed to get process token]\n");
        return;
    }
    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    if (size == 0) {
        CloseHandle(hToken);
        printf("    [Failed to get user info]\n");
        return;
    }
    PTOKEN_USER pUser = (PTOKEN_USER)malloc(size);
    if (!pUser) {
        CloseHandle(hToken);
        printf("    [Memory allocation failed]\n");
        return;
    }
    if (GetTokenInformation(hToken, TokenUser, pUser, size, &size)) {
        WCHAR name[256], domain[256];
        DWORD nameLen = 256, domainLen = 256;
        SID_NAME_USE sidType;
        if (LookupAccountSidW(NULL, pUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
            wprintf(L"    Current user: %s\\%s\n", domain, name);
        } else {
            printf("    [Unable to resolve username]\n");
        }
    } else {
        printf("    [Failed to get user info]\n");
    }
    free(pUser);
    CloseHandle(hToken);
}

int main() {
    printf("===== R0Simulate Full Feature Demo =====\n");
    printf("Make sure driver R0Simulate.sys is loaded and Test Signing is enabled.\n\n");

    // 1. R0SISA
    printf("[1] R0SimulateISA: mov eax, 1234; ret\n");
    BYTE code[] = {0xB8, 0xD2, 0x04, 0x00, 0x00, 0xC3};
    UINT64 isa_result = R0SimulateISA(code, sizeof(code));
    if (isa_result == 1234) {
        printf("    OK: returned 0x%llX (expected 0x4D2)\n", isa_result);
    } else {
        printf("    FAIL: returned 0x%llX, GetLastError = %lu\n", isa_result, GetLastError());
    }

    // 2. R0SAPI - Allocate kernel memory
    printf("\n[2] R0SAPI: Allocate 256 bytes in kernel pool (tag = 'DEMO')\n");
    UINT64 kernelAddr = R0SimulateAPI(
        L"ExAllocatePoolWithTag",
        3,
        0,
        (UINT64)0x200,
        (UINT64)256,
        (UINT64)'DEMO'
    );
    if (kernelAddr == 0) {
        printf("    FAIL: ExAllocatePoolWithTag returned 0, error = %lu\n", GetLastError());
        return 1;
    }
    printf("    OK: allocated at 0x%016llX\n", kernelAddr);

    // 3. R0SKMA - Write
    printf("\n[3] R0SKMA: Write test pattern\n");
    BYTE writeData[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};
    UINT32 writeLen = sizeof(writeData);
    BOOL ok = R0SimulateKernelMemoryAccess(
        kernelAddr, 0, writeLen, R0SKMA_OP_WRITE, writeData
    );
    if (!ok) {
        printf("    FAIL: write error = %lu\n", GetLastError());
        R0SimulateAPI(L"ExFreePoolWithTag", 2, 0, kernelAddr, (UINT64)'DEMO');
        return 1;
    }
    printf("    OK: wrote %u bytes\n", writeLen);

    // 4. R0SKMA - Read
    printf("\n[4] R0SKMA: Read back\n");
    BYTE readBuf[64] = {0};
    ok = R0SimulateKernelMemoryAccess(
        kernelAddr, 0, writeLen, R0SKMA_OP_READ, readBuf
    );
    if (!ok) {
        printf("    FAIL: read error = %lu\n", GetLastError());
        R0SimulateAPI(L"ExFreePoolWithTag", 2, 0, kernelAddr, (UINT64)'DEMO');
        return 1;
    }
    printf("    OK: read %u bytes: ", writeLen);
    for (int i = 0; i < writeLen; i++) printf("%02X ", readBuf[i]);
    printf("\n");
    if (memcmp(writeData, readBuf, writeLen) == 0)
        printf("    PASS: data matches\n");
    else
        printf("    FAIL: data mismatch\n");

    // 5. Free kernel memory
    printf("\n[5] R0SAPI: Free kernel memory\n");
    R0SimulateAPI(L"ExFreePoolWithTag", 2, 0, kernelAddr, (UINT64)'DEMO');
    if (GetLastError() == ERROR_SUCCESS)
        printf("    OK: memory freed\n");
    else
        printf("    FAIL: free error = %lu\n", GetLastError());

    // 6. R0SKPH - Hide/Unhide
    printf("\n[6] R0SKPH: Hide current process (PID = %lu)\n", GetCurrentProcessId());
    NTSTATUS status;
    ok = R0SimulateKernelProcessHiding(R0SKPH_OP_ADD, GetCurrentProcessId(),
                                 &status, sizeof(status));
    if (ok && NT_SUCCESS(status)) {
        printf("    OK: process hidden\n");
        ok = R0SimulateKernelProcessHiding(R0SKPH_OP_REMOVE, GetCurrentProcessId(),
                                     &status, sizeof(status));
        if (ok && NT_SUCCESS(status))
            printf("    OK: process restored\n");
        else
            print_last_error("R0SKPH REMOVE");
    } else {
        print_last_error("R0SKPH ADD");
    }

    // 7. R0SKGT - Get SYSTEM token (no replacement)
    printf("\n[7] R0SKGT: Get SYSTEM token (do NOT replace current)\n");
    HANDLE hToken = R0SimulateGetSystemToken(FALSE);
    if (hToken != NULL) {
        printf("    OK: token handle = %p\n", hToken);
        CloseHandle(hToken);
        printf("    Token handle closed.\n");
    } else {
        print_last_error("R0SKGT");
    }

    // 8. R0SKGT - Replace current process token with SYSTEM token (high risk)
    printf("\n[8] R0SKGT: Replace current process token with SYSTEM token (all privileges)\n");
    printf("    [WARNING] This operation elevates current process to SYSTEM, may cause unexpected behavior, but will exit after test.\n");
    printf("    Current process user info:\n");
    PrintCurrentUserName();

    HANDLE hDummy = R0SimulateGetSystemToken(TRUE);
    if (hDummy == NULL && GetLastError() == ERROR_SUCCESS) {
        printf("    OK: token replaced successfully.\n");
        printf("    After replacement process user info:\n");
        PrintCurrentUserName();
    } else {
        print_last_error("R0SKGT replace");
        printf("    Hint: If failed, driver may not implement replacement correctly, or insufficient privilege.\n");
    }

    // 9. R0SimulateSetInternalVariables - GET/SET/LIST
    printf("\n[9] R0SimulateSetInternalVariables: LIST, GET, SET operations\n");

    // 9.1 LIST
    printf("\n    [9.1] LIST all internal variables\n");
    UCHAR listBuffer[4096] = {0};
    ULONG infoCount = 0;
    ok = R0SimulateSetInternalVariables(
        R0SIMULATE_VAR_OP_LIST,
        0,
        0,
        listBuffer,
        sizeof(listBuffer),
        &infoCount
    );
    if (ok) {
        printf("    OK: Retrieved %lu variables:\n", infoCount);
        PVAR_INFO pInfo = (PVAR_INFO)(listBuffer + sizeof(ULONG));
        for (ULONG i = 0; i < infoCount; i++) {
            wprintf(L"        ID=%lu, Name=%s, Size=%lu, Value=0x%llX\n",
                    pInfo[i].Id, pInfo[i].Name, pInfo[i].Size, pInfo[i].Value);
        }
    } else {
        print_last_error("R0SimulateSetInternalVariables LIST");
    }

    // 9.2 GET previous mode offset
    printf("\n    [9.2] GET g_PreviousModeOffset\n");
    UINT64 prevOffset = 0;
    ok = R0SimulateSetInternalVariables(
        R0SIMULATE_VAR_OP_GET,
        R0SIMULATE_VAR_PREVIOUS_MODE_OFFSET,
        0,
        &prevOffset,
        sizeof(prevOffset),
        NULL
    );
    if (ok) {
        printf("    OK: g_PreviousModeOffset = 0x%llX\n", prevOffset);
    } else {
        print_last_error("R0SimulateSetInternalVariables GET");
    }

    // 9.3 SET previous mode offset to a new value (only for demo, restore later)
    printf("\n    [9.3] SET g_PreviousModeOffset to 0x1234 (temporary)\n");
    UINT64 newVal = 0x1234;
    ok = R0SimulateSetInternalVariables(
        R0SIMULATE_VAR_OP_SET,
        R0SIMULATE_VAR_PREVIOUS_MODE_OFFSET,
        newVal,
        NULL,
        0,
        NULL
    );
    if (ok) {
        printf("    OK: set to 0x1234\n");
        // Verify
        UINT64 checkVal = 0;
        ok = R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_GET,
            R0SIMULATE_VAR_PREVIOUS_MODE_OFFSET,
            0,
            &checkVal,
            sizeof(checkVal),
            NULL
        );
        if (ok && checkVal == newVal) {
            printf("    Verification: read back 0x%llX, matched.\n", checkVal);
        } else {
            printf("    Verification: read back 0x%llX, mismatch or error.\n", checkVal);
        }
        // Restore original value
        printf("    Restoring original value 0x%llX\n", prevOffset);
        R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_SET,
            R0SIMULATE_VAR_PREVIOUS_MODE_OFFSET,
            prevOffset,
            NULL,
            0,
            NULL
        );
        // Verify restore
        UINT64 restoredVal = 0;
        R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_GET,
            R0SIMULATE_VAR_PREVIOUS_MODE_OFFSET,
            0,
            &restoredVal,
            sizeof(restoredVal),
            NULL
        );
        printf("    Restored value: 0x%llX\n", restoredVal);
    } else {
        print_last_error("R0SimulateSetInternalVariables SET");
    }

    // 10. R0SimulateGetKernelFunction - query single function
    printf("\n[10] R0SimulateGetKernelFunction - query single function\n");
    UINT64 funcAddr = 0;
    ok = R0SimulateGetKernelFunction(L"ExAllocatePoolWithTag", &funcAddr, sizeof(funcAddr), NULL);
    if (ok && funcAddr != 0) {
        printf("    OK: ExAllocatePoolWithTag @ 0x%016llX\n", funcAddr);
    } else {
        print_last_error("R0SimulateGetKernelFunction (single)");
    }

    // 11. R0SimulateIO - read I/O port (0x60, keyboard controller)
    printf("\n[11] R0SimulateIO - read I/O port (0x60, keyboard controller)\n");
    ULONG ioValue = 0;
    ok = R0SimulateIO(R0SIO_READ_BYTE, 0x60, 0, &ioValue);
    if (ok) {
        printf("    OK: Port 0x60 = 0x%02X\n", ioValue);
    } else {
        print_last_error("R0SimulateIO read byte (0x60)");
    }

    // 12. R0SimulateIO - write I/O port (0x80, debug port)
    printf("\n[12] R0SimulateIO - write I/O port (0x80, debug port)\n");
    ok = R0SimulateIO(R0SIO_WRITE_BYTE, 0x80, 0xAA, NULL);
    if (ok) {
        printf("    OK: wrote 0xAA to port 0x80\n");
        // Try read-back (may not be supported)
        ok = R0SimulateIO(R0SIO_READ_BYTE, 0x80, 0, &ioValue);
        if (ok) {
            printf("    Read-back: 0x%02X\n", ioValue);
        } else {
            printf("    (Read-back not supported or failed, error code: %lu)\n", GetLastError());
        }
    } else {
        print_last_error("R0SimulateIO write byte (0x80)");
    }

    printf("\n===== Demo finished. Press any key to exit =====\n");
    getchar();
    return 0;
}