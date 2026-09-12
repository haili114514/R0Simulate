#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <securitybaseapi.h>
#include "R0Simulates.h"

static void print_last_error(const char* msg)
{
    DWORD err = GetLastError();
    fprintf(stderr, "[!] %s failed, error code: %lu (0x%08lX)\n", msg, err, err);
}

static void PrintCurrentUserName(void)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        printf("    [Failed to get process token]\n");
        return;
    }
    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    if (size == 0)
    {
        CloseHandle(hToken);
        printf("    [Failed to get user info]\n");
        return;
    }
    PTOKEN_USER pUser = (PTOKEN_USER)malloc(size);
    if (!pUser)
    {
        CloseHandle(hToken);
        printf("    [Memory allocation failed]\n");
        return;
    }
    if (GetTokenInformation(hToken, TokenUser, pUser, size, &size))
    {
        WCHAR name[256], domain[256];
        DWORD nameLen = 256, domainLen = 256;
        SID_NAME_USE sidType;
        if (LookupAccountSidW(NULL, pUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType))
        {
            wprintf(L"    Current user: %s\\%s\n", domain, name);
        }
        else
        {
            printf("    [Unable to resolve username]\n");
        }
    }
    else
    {
        printf("    [Failed to get user info]\n");
    }
    free(pUser);
    CloseHandle(hToken);
}

int main(void)
{
    const UINT64 tag_DEMO = 0x4F4D4544ULL;

    printf("===== R0Simulate IOCTL Test Suite =====\n");
    printf("Driver: R0Simulate.sys, Test Signing ON\n");
    printf("DLL:    R0Simulates.dll (1 function <-> 1 IOCTL)\n\n");

    
    
    
    printf("[1] IOCTL_R0SIMULATE_SET_INTERNAL_VARS  (R0S SIV)\n");
    {
        UCHAR listBuffer[10000] = {0};
        ULONG infoCount = 0;
        BOOL  ok;
        printf("  [1.1] OP_LIST: enumerate all driver internal variables\n");
        ok = R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_LIST,
            0, 0,
            listBuffer, sizeof(listBuffer),
            &infoCount,
            R0SIMULATE_ERROR_MODE_DEFAULT
        );
        if (ok)
        {
            PVAR_INFO pInfo = (PVAR_INFO)(listBuffer + sizeof(ULONG));
            printf("      OK: Retrieved %lu variables\n", infoCount);
            for (ULONG i = 0; i < infoCount; i++)
            {
                wprintf(L"        ID=%lu, Name=%s, Size=%lu, Value=0x%llX\n",
                        pInfo[i].Id, pInfo[i].Name, pInfo[i].Size, pInfo[i].Value);
            } 
            if (infoCount > 0)
            {
                ULONG  firstId = pInfo[0].Id;
                UINT64 val = 0;
                printf("  [1.2] OP_GET on first enumerated ID=%lu\n", firstId);
                ok = R0SimulateSetInternalVariables(
                    R0SIMULATE_VAR_OP_GET,
                    firstId,
                    0,
                    &val, sizeof(val),
                    NULL,
                    R0SIMULATE_ERROR_MODE_DEFAULT
                );
                if (ok)
                    printf("      OK: value = 0x%llX\n", val);
                else
                    print_last_error("R0S SIV OP_GET");
            }
        }
        else
        {
            print_last_error("R0S SIV OP_LIST");
        }
        printf("  [1.3] OP_GET DLL internal variable (ErrorMode)\n");
        {
            UINT64 currentMode = 0;
            ok = R0SimulateSetInternalVariables(
                R0SIMULATE_VAR_OP_GET,
                R0SIMULATE_VAR_DLL_ERROR_MODE,
                0,
                &currentMode, sizeof(currentMode),
                NULL,
                R0SIMULATE_ERROR_MODE_DEFAULT
            );
            if (ok)
                printf("      Current DLL_ErrorMode = %llu (0=convert, 1=raw NTSTATUS)\n", currentMode);
            else
                print_last_error("R0S SIV GET DLL_ErrorMode");
        }
        printf("  [1.4] Force ErrorMode=0 (convert) with invalid ID 0xFFFFFFFF\n");
        SetLastError(0);
        {
            UINT64 dummy = 0;
            ok = R0SimulateSetInternalVariables(
                R0SIMULATE_VAR_OP_GET,
                0xFFFFFFFF, 0,
                &dummy, sizeof(dummy),
                NULL, 0
            );
            if (!ok)
            {
                DWORD err = GetLastError();
                printf("      FAIL returned, error code = 0x%08lX (%lu)\n", err, err);
                if (err == ERROR_INVALID_PARAMETER)
                    printf("      PASS: error converted to Win32 ERROR_INVALID_PARAMETER\n");
                else
                    printf("      FAIL: unexpected error code\n");
            }
            else
                printf("      UNEXPECTED: call succeeded with invalid ID\n");
        }
        printf("  [1.5] Force ErrorMode=1 (raw) with invalid ID 0xFFFFFFFF\n");
        SetLastError(0);
        {
            UINT64 dummy = 0;
            ok = R0SimulateSetInternalVariables(
                R0SIMULATE_VAR_OP_GET,
                0xFFFFFFFF, 0,
                &dummy, sizeof(dummy),
                NULL, 1
            );
            if (!ok)
            {
                DWORD err = GetLastError();
                printf("      FAIL returned, error code = 0x%08lX (%lu)\n", err, err);
                if (err == 0xC000000D)
                    printf("      PASS: error is raw NTSTATUS 0xC000000D\n");
                else
                    printf("      FAIL: unexpected error code\n");
            }
            else
                printf("      UNEXPECTED: call succeeded with invalid ID\n");
        }

        printf("  [1.6] Set DLL_ErrorMode=1, then use ErrorMode=DEFAULT\n");
        ok = R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_SET,
            R0SIMULATE_VAR_DLL_ERROR_MODE,
            1,
            NULL, 0, NULL,
            R0SIMULATE_ERROR_MODE_DEFAULT
        );
        if (ok) printf("      DLL_ErrorMode set to 1 successfully\n");
        else    print_last_error("R0S SIV SET DLL_ErrorMode=1");

        SetLastError(0);
        {
            UINT64 dummy = 0;
            ok = R0SimulateSetInternalVariables(
                R0SIMULATE_VAR_OP_GET,
                0xFFFFFFFF, 0,
                &dummy, sizeof(dummy),
                NULL,
                R0SIMULATE_ERROR_MODE_DEFAULT
            );
            if (!ok)
            {
                DWORD err = GetLastError();
                printf("      FAIL returned, error code = 0x%08lX (%lu)\n", err, err);
                if (err == 0xC000000D)
                    printf("      PASS: default mode used internal value 1 -> raw NTSTATUS\n");
                else
                    printf("      FAIL: unexpected error code\n");
            }
        }
        printf("  [1.7] Restore DLL_ErrorMode=0\n");
        ok = R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_SET,
            R0SIMULATE_VAR_DLL_ERROR_MODE,
            0,
            NULL, 0, NULL,
            R0SIMULATE_ERROR_MODE_DEFAULT
        );
        if (ok) printf("      DLL_ErrorMode restored to 0\n");
        else    print_last_error("R0S SIV SET DLL_ErrorMode=0");

        printf("\n");
    }
    printf("[2] IOCTL_R0SIMULATE_EXEC_INSTRUCTION  (R0S EI)\n");
    {
        printf("  [2.1] Execute machine code: mov eax,1234; ret\n");
        BYTE code[] = {0xB8, 0xD2, 0x04, 0x00, 0x00, 0xC3};
        UINT64 retVal = R0SimulateISA(code, sizeof(code));
        if (retVal == 1234)
        {
            printf("      OK: return = 0x%llX (expected 0x4D2)\n\n", retVal);
        }
        else
        {
            printf("      FAIL: return = 0x%llX\n", retVal);
            print_last_error("R0S EI");
            printf("\n");
        }
    }
    printf("[3] IOCTL_R0SIMULATE_CALL_KERNEL_API  (R0S API)\n");
    {
        UINT64 kernelAddr;

        printf("  [3.1] ExAllocatePoolWithTag allocate kernel memory\n");
        kernelAddr = R0SimulateAPI(
            L"ExAllocatePoolWithTag",
            3, 0,
            (UINT64)0x200,   
            (UINT64)256,     
            tag_DEMO         
        );
        if (kernelAddr == 0)
        {
            print_last_error("R0S API ExAllocatePoolWithTag");
        }
        else
        {
            printf("      OK: kernel virtual address = 0x%016llX\n", kernelAddr);

            printf("  [3.2] ExFreePoolWithTag release kernel memory\n");
            R0SimulateAPI(L"ExFreePoolWithTag", 2, 0, kernelAddr, tag_DEMO);
            if (GetLastError() == ERROR_SUCCESS)
                printf("      OK: memory freed\n");
            else
                print_last_error("R0S API ExFreePoolWithTag");
        }
        printf("\n");
    }
    printf("[4] IOCTL_R0SIMULATE_KERNEL_MEMORY_ACCESS  (R0S KMA)\n");
    {
        BYTE   writeData[] = {0xDE,0xAD,0xBE,0xEF,0x12,0x34,0x56,0x78,0x90,0xAB,0xCD,0xEF};
        BYTE   readBuf[64] = {0};
        UINT32 writeLen = sizeof(writeData);
        BOOL   ok;
        UINT64 kernelAddr;

        kernelAddr = R0SimulateAPI(
            L"ExAllocatePoolWithTag",
            3, 0,
            (UINT64)0x200,
            (UINT64)256,
            tag_DEMO
        );
        if (kernelAddr == 0)
        {
            print_last_error("R0S KMA prereq allocate");
            printf("\n");
            goto kma_done;
        }

        printf("  [4.1] Write pattern to kernel buffer\n");
        ok = R0SimulateKernelMemoryAccess(kernelAddr, 0, writeLen, R0SKMA_OP_WRITE, writeData);
        if (!ok)
        {
            print_last_error("R0S KMA write");
        }
        else
        {
            printf("      OK: wrote %u bytes\n", writeLen);
        }

        printf("  [4.2] Read back from kernel buffer\n");
        ok = R0SimulateKernelMemoryAccess(kernelAddr, 0, writeLen, R0SKMA_OP_READ, readBuf);
        if (!ok)
        {
            print_last_error("R0S KMA read");
        }
        else
        {
            printf("      OK: read %u bytes: ", writeLen);
            for (int i = 0; i < (int)writeLen; i++) printf("%02X ", readBuf[i]);
            printf("\n");
            if (memcmp(writeData, readBuf, writeLen) == 0)
                printf("      PASS: data compare match\n");
            else
                printf("      FAIL: data mismatch\n");
        }

        R0SimulateAPI(L"ExFreePoolWithTag", 2, 0, kernelAddr, tag_DEMO);

kma_done:
        printf("\n");
    }
    printf("[5] IOCTL_R0SIMULATE_KERNEL_PROCESS_HIDING  (R0S KPH)\n");
    {
        NTSTATUS status;
        BOOL     ok;
        ULONG    pid = GetCurrentProcessId();

        printf("  [5.1] Hide current process PID=%lu\n", pid);
        ok = R0SimulateKernelProcessHiding(R0SKPH_OP_ADD, pid, &status, sizeof(status));
        if (ok && NT_SUCCESS(status))
        {
            printf("      OK: process hidden\n");
            printf("  [5.2] Restore(unhide) current process\n");
            ok = R0SimulateKernelProcessHiding(R0SKPH_OP_REMOVE, pid, &status, sizeof(status));
            if (ok && NT_SUCCESS(status))
                printf("      OK: process restored\n");
            else
                print_last_error("R0S KPH REMOVE");
        }
        else
        {
            print_last_error("R0S KPH ADD");
        }
        printf("\n");
    }

    printf("[6] IOCTL_R0SIMULATE_GET_SYSTEM_TOKEN  (R0S GST)\n");
    {
        HANDLE hToken;

        printf("  [6.1] Get SYSTEM token handle (no replace)\n");
        hToken = R0SimulateGetSystemToken(FALSE);
        if (hToken != NULL)
        {
            printf("      OK: token handle = %p\n", hToken);
            CloseHandle(hToken);
            printf("      Token handle closed\n");
        }
        else
        {
            print_last_error("R0S GST no replace");
        }

        printf("  [6.2] Replace current process token to SYSTEM (warning!)\n");
        printf("      Before:\n");
        PrintCurrentUserName();
        {
            HANDLE hDummy = R0SimulateGetSystemToken(TRUE);
            if (hDummy == NULL && GetLastError() == ERROR_SUCCESS)
            {
                printf("      OK: token replaced\n");
                printf("      After:\n");
                PrintCurrentUserName();
            }
            else
            {
                print_last_error("R0S GST replace");
            }
        }
        printf("\n");
    }

    printf("[7] IOCTL_R0SIMULATE_GET_KERNEL_FUNCTION  (R0S GKF)\n");
    {
        printf("  [7.1] Lookup symbol: ExAllocatePoolWithTag\n");
        {
            UINT64 funcAddr = 0;
            BOOL   ok = R0SimulateGetKernelFunction(
                L"ExAllocatePoolWithTag",
                &funcAddr, sizeof(funcAddr), NULL);
            if (ok && funcAddr != 0)
                printf("      OK: ExAllocatePoolWithTag = 0x%016llX\n", funcAddr);
            else
                print_last_error("R0S GKF symbol lookup");
        }
        printf("\n");
    }

    printf("[8] IOCTL_R0SIMULATE_IO  (R0S IO)\n");
    {
        ULONG ioValue;
        BOOL  ok;

        printf("  [8.1] Read byte port 0x60\n");
        ok = R0SimulateIO(R0SIO_READ_BYTE, 0x60, 0, &ioValue);
        if (ok)
            printf("      OK: port 0x60 = 0x%02X\n", ioValue);
        else
            print_last_error("R0S IO read byte 0x60");

        printf("  [8.2] Write byte port 0x80 value 0xAA\n");
        ok = R0SimulateIO(R0SIO_WRITE_BYTE, 0x80, 0xAA, NULL);
        if (ok)
        {
            printf("      OK: write done\n");
            printf("  [8.3] Read back port 0x80\n");
            ok = R0SimulateIO(R0SIO_READ_BYTE, 0x80, 0, &ioValue);
            if (ok)
                printf("      OK: port 0x80 = 0x%02X\n", ioValue);
            else
                printf("      Read back not supported\n");
        }
        else
        {
            print_last_error("R0S IO write byte 0x80");
        }
        printf("\n");
    }

    printf("[9] IOCTL_R0SIMULATE_PREVIOUS_MODE_SWITCH  (R0S PMS)\n");
    {
        UCHAR oldMode, newMode;
        BOOL  ok;

        printf("  [9.1] View only: get current previous mode\n");
        ok = R0SimulatePreviousModeSwitch(TRUE, 0, &oldMode, &newMode);
        if (ok)
            printf("      OK: current mode = %u, new mode = %u (view only)\n", oldMode, newMode);
        else
            print_last_error("R0S PMS view only");

        printf("  [9.2] Switch to kernel mode (0) and verify\n");
        ok = R0SimulatePreviousModeSwitch(FALSE, R0SPMS_MODE_KERNEL, &oldMode, &newMode);
        if (ok)
        {
            printf("      OK: old mode = %u, new mode = %u\n", oldMode, newMode);
            if (newMode == R0SPMS_MODE_KERNEL)
                printf("      PASS: switched to kernel mode\n");
            else
                printf("      FAIL: new mode not kernel\n");
        }
        else
        {
            print_last_error("R0S PMS switch to kernel");
        }

        printf("  [9.3] Restore to user mode (1)\n");
        ok = R0SimulatePreviousModeSwitch(FALSE, R0SPMS_MODE_USER, &oldMode, &newMode);
        if (ok)
        {
            printf("      OK: old mode = %u, new mode = %u\n", oldMode, newMode);
            if (newMode == R0SPMS_MODE_USER)
                printf("      PASS: restored to user mode\n");
            else
                printf("      FAIL: new mode not user\n");
        }
        else
        {
            print_last_error("R0S PMS restore to user");
        }
        printf("\n");
    }

    printf("[10] IOCTL_R0SIMULATE_KERNEL_OPEN_HANDLE  (R0S KOH)\n");
    {
        ULONG pid = GetCurrentProcessId();

        printf("  [10.1] Open handle to current process (PID=%lu)\n", pid);
        {
            HANDLE hProcess = R0SimulateKernelOpenHandle(
                R0SKOH_TYPE_PID,
                PROCESS_ALL_ACCESS,
                (UINT64)pid,
                0);
            if (hProcess != NULL)
            {
                printf("      OK: got handle = %p\n", hProcess);
                CloseHandle(hProcess);
                printf("      Handle closed\n");
            }
            else
            {
                print_last_error("R0S KOH open current process");
            }
        }

        printf("  [10.2] Open handle to system process (PID=4)\n");
        {
            HANDLE hProcess = R0SimulateKernelOpenHandle(
                R0SKOH_TYPE_PID,
                PROCESS_QUERY_INFORMATION,
                (UINT64)4,
                0);
            if (hProcess != NULL)
            {
                printf("      OK: got handle = %p\n", hProcess);
                CloseHandle(hProcess);
                printf("      Handle closed\n");
            }
            else
            {
                print_last_error("R0S KOH open system process");
            }
        }
        printf("\n");
    }

    printf("===== All test finished. Press Enter to exit =====\n");
    (void)getchar();
    return 0;
}