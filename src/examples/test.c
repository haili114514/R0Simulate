#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <securitybaseapi.h>
#include "R0Simulates.h"

#define IRP_MJ_CREATE                       0x00
#define IRP_MJ_CREATE_NAMED_PIPE            0x01
#define IRP_MJ_CLOSE                        0x02
#define IRP_MJ_READ                         0x03
#define IRP_MJ_WRITE                        0x04
#define IRP_MJ_QUERY_INFORMATION            0x05
#define IRP_MJ_SET_INFORMATION              0x06
#define IRP_MJ_QUERY_EA                     0x07
#define IRP_MJ_SET_EA                       0x08
#define IRP_MJ_FLUSH_BUFFERS                0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION     0x0A
#define IRP_MJ_SET_VOLUME_INFORMATION       0x0B
#define IRP_MJ_DIRECTORY_CONTROL            0x0C
#define IRP_MJ_FILE_SYSTEM_CONTROL          0x0D
#define IRP_MJ_DEVICE_CONTROL               0x0E
#define IRP_MJ_INTERNAL_DEVICE_CONTROL      0x0F
#define IRP_MJ_SHUTDOWN                     0x10
#define IRP_MJ_LOCK_CONTROL                 0x11
#define IRP_MJ_CLEANUP                      0x12
#define IRP_MJ_CREATE_MAILSLOT              0x13
#define IRP_MJ_QUERY_SECURITY               0x14
#define IRP_MJ_SET_SECURITY                 0x15
#define IRP_MJ_POWER                        0x16
#define IRP_MJ_SYSTEM_CONTROL               0x17
#define IRP_MJ_DEVICE_CHANGE                0x18
#define IRP_MJ_QUERY_QUOTA                  0x19
#define IRP_MJ_SET_QUOTA                    0x1A
#define IRP_MJ_PNP                          0x1B
#ifndef OBJ_KERNEL_HANDLE
#define OBJ_KERNEL_HANDLE        0x00000200L
#endif
#ifndef OBJ_FORCE_ACCESS_CHECK
#define OBJ_FORCE_ACCESS_CHECK   0x00000400L
#endif
#ifndef OBJ_INHERIT
#define OBJ_INHERIT              0x00000002L
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE     0x00000040L
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define R0SKOH_ACCESS_MODE_USER         1
#define R0SKOH_ACCESS_MODE_KERNEL       0

#define VAR_ID_G_DRIVEROBJECT   0x002A

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
        UCHAR listBuffer[16384] = {0};
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

    printf("[10] IOCTL_R0SIMULATE_KERNEL_OPEN_HANDLE (R0S KOH) - handle/pointer conversion (unsafe demo)\n");
    {
        ULONG pid = GetCurrentProcessId();
        KERNEL_OPEN_HANDLE_OUTPUT out = {0};
        KERNEL_OPEN_HANDLE_OUTPUT out2 = {0};
        HANDLE hProcess = NULL;
        BOOL ok;

        printf("  [10.1] Open handle to current process by PID (PID=%lu)\n", pid);
        ok = R0SimulateKernelOpenHandle(
            R0SKOH_TYPE_PID,
            PROCESS_ALL_ACCESS,
            (UINT64)pid,
            R0SKOH_ACCESS_MODE_KERNEL,
            OBJ_KERNEL_HANDLE,
            0,
            &out
        );
        if (ok && NT_SUCCESS(out.Status) && out.ResultHandle != NULL)
        {
            printf("      OK: got handle = %p\n", out.ResultHandle);
            CloseHandle(out.ResultHandle);
            printf("      Handle closed\n");
        }
        else
        {
            print_last_error("R0S KOH open current process by PID");
        }

        printf("  [10.2] Open handle to system process (PID=4)\n");
        ok = R0SimulateKernelOpenHandle(
            R0SKOH_TYPE_PID,
            PROCESS_QUERY_INFORMATION,
            (UINT64)4,
            R0SKOH_ACCESS_MODE_KERNEL,
            OBJ_KERNEL_HANDLE,
            0,
            &out
        );
        if (ok && NT_SUCCESS(out.Status) && out.ResultHandle != NULL)
        {
            printf("      OK: got handle = %p\n", out.ResultHandle);
            CloseHandle(out.ResultHandle);
            printf("      Handle closed\n");
        }
        else
        {
            print_last_error("R0S KOH open system process");
        }

        printf("  [10.3] Open a real handle to the current process with OpenProcess\n");
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProcess == NULL)
        {
            print_last_error("OpenProcess");
            goto test10_end;
        }
        printf("      OK: hProcess = %p\n", hProcess);

        printf("  [10.4] Convert handle to kernel pointer (Type=R0SKOH_TYPE_HANDLE)\n");
        ok = R0SimulateKernelOpenHandle(
            R0SKOH_TYPE_HANDLE,
            PROCESS_QUERY_INFORMATION,
            (UINT64)(ULONG_PTR)hProcess,
            R0SKOH_ACCESS_MODE_USER,
            0,
            0,
            &out
        );
        if (!ok || !NT_SUCCESS(out.Status))
        {
            print_last_error("R0S KOH handle to pointer");
            goto test10_end;
        }

        printf("      OK: KernelPointer = 0x%p\n", out.KernelPointer);
        printf("      Warning: this pointer was dereferenced in kernel and is now dangling.\n");

        printf("  [10.5] Convert kernel pointer back to handle (Type=R0SKOH_TYPE_POINTER)\n");
        printf("      Warning: unsafe operation, may cause a bugcheck. Demo only.\n");
        ok = R0SimulateKernelOpenHandle(
            R0SKOH_TYPE_POINTER,
            PROCESS_QUERY_INFORMATION,
            (UINT64)(ULONG_PTR)out.KernelPointer,
            R0SKOH_ACCESS_MODE_KERNEL,
            OBJ_KERNEL_HANDLE,
            0,
            &out2
        );
        if (ok && NT_SUCCESS(out2.Status))
        {
            printf("      OK: ResultHandle = 0x%p\n", out2.ResultHandle);
            if (out2.ResultHandle != NULL && out2.ResultHandle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(out2.ResultHandle);
                printf("      Handle closed\n");
            }
        }
        else
        {
            printf("      Failed: Status = 0x%08X\n", out2.Status);
            print_last_error("R0S KOH pointer to handle");
        }

test10_end:
        if (hProcess != NULL)
            CloseHandle(hProcess);
        printf("\n");
    }

    printf("[11] IOCTL_R0SIMULATE_AUTHORIZED_LIST  (R0S AUTH)\n");
    {
        BYTE  buf[16 * 1024] = {0};
        ULONG count = 0;
        BOOL  ok;

        printf("  [11.1] LIST: enumerate authorized list\n");
        ok = R0SimulateAuthorizedListOperations(
            R0SAUTH_OP_LIST, 0, buf, (ULONG)sizeof(buf), &count);
        if (!ok)
        {
            print_last_error("R0S AUTH LIST");
        }
        else
        {
            R0S_AUTH_LIST_OUTPUT* pOut = (R0S_AUTH_LIST_OUTPUT*)buf;
            printf("      OK: %lu entries\n", (unsigned long)pOut->Count);
            printf("      %-12s  %-6s\n", "PID", "Valid");
            for (ULONG i = 0; i < pOut->Count; i++)
            {
                printf("      %-12lu  %-6s\n",
                    (unsigned long)(ULONG_PTR)pOut->Entries[i].Pid,
                    pOut->Entries[i].Valid ? "yes" : "no");
            }
        }

        printf("  [11.2] ADD current process (PID=%lu)\n", (unsigned long)GetCurrentProcessId());
        {
            NTSTATUS st = 0;
            ok = R0SimulateAuthorizedListOperations(
                R0SAUTH_OP_ADD, GetCurrentProcessId(), &st, sizeof(st), NULL);
            if (ok && NT_SUCCESS(st))
                printf("      OK: added\n");
            else
            {
                printf("      Status=0x%08X\n", st);
                if (!ok) print_last_error("R0S AUTH ADD");
            }
        }

        printf("  [11.3] LIST again\n");
        memset(buf, 0, sizeof(buf));
        count = 0;
        ok = R0SimulateAuthorizedListOperations(
            R0SAUTH_OP_LIST, 0, buf, (ULONG)sizeof(buf), &count);
        if (ok)
        {
            R0S_AUTH_LIST_OUTPUT* pOut = (R0S_AUTH_LIST_OUTPUT*)buf;
            printf("      OK: %lu entries\n", (unsigned long)pOut->Count);
        }

        printf("  [11.4] REMOVE current process\n");
        {
            NTSTATUS st = 0;
            ok = R0SimulateAuthorizedListOperations(
                R0SAUTH_OP_REMOVE, GetCurrentProcessId(), &st, sizeof(st), NULL);
            if (ok && NT_SUCCESS(st))
                printf("      OK: removed\n");
            else
            {
                printf("      Status=0x%08X\n", st);
                if (!ok) print_last_error("R0S AUTH REMOVE");
            }
        }
        printf("\n");
    }

    printf("[12] IOCTL_R0SIMULATE_CREATE_SYSTEM_THREAD  (R0S THREAD)\n");
    {
        BYTE   shellcode[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
        UINT64 execAddr = 0;
        HANDLE hThread = NULL;
        BOOL   ok;

        printf("  [12.1] Allocate executable kernel memory (NonPagedPoolExecute, 64 bytes)\n");
        execAddr = R0SimulateAPI(
            L"ExAllocatePoolWithTag",
            3, 0,
            (UINT64)0x00000000,   /* NonPagedPoolExecute */
            (UINT64)64,
            tag_DEMO
        );
        if (execAddr == 0)
        {
            print_last_error("alloc exec mem");
            printf("\n");
            goto thread_done;
        }
        printf("      OK: exec = 0x%016llX\n", execAddr);

        printf("  [12.2] Write shellcode (B8 01 00 00 00 C3 = mov eax,1; ret)\n");
        ok = R0SimulateKernelMemoryAccess(
            execAddr, 0, sizeof(shellcode), R0SKMA_OP_WRITE, shellcode);
        if (!ok)
        {
            print_last_error("write shellcode");
            goto thread_free;
        }

        printf("  [12.3] Create system thread at that address\n");
        ok = R0SimulateCreateSystemThread(
            execAddr, 0, 0, &hThread);
        if (!ok)
        {
            print_last_error("R0S THREAD");
        }
        else
        {
            printf("      OK: kernel thread handle = 0x%p (note: kernel handle, not closable from user mode)\n", hThread);
            Sleep(200);
            printf("      Sleep 200ms waiting for thread to finish\n");
        }

thread_free:
        printf("  [12.4] Free executable memory\n");
        R0SimulateAPI(L"ExFreePoolWithTag", 2, 0, execAddr, tag_DEMO);
        if (GetLastError() == ERROR_SUCCESS)
            printf("      OK: freed\n");
        else
            print_last_error("free exec mem");

thread_done:
        printf("\n");
    }

    printf("[13] IOCTL_R0SIMULATE_MSR  (R0S MSR)\n");
    {
        UINT64 value = 0;
        BOOL   ok;
        /* IA32_LSTAR - KiSystemCall64 address */
        ULONG  targetMsr = 0xC0000082;

        printf("  [13.1] Read MSR 0x%08X (IA32_LSTAR)\n", targetMsr);
        ok = R0SimulateMSR(R0SMSR_OP_READ, targetMsr, 0, &value);
        if (ok)
            printf("      OK: value = 0x%016llX\n", value);
        else
            print_last_error("R0S MSR read");

        /* read another one */
        printf("  [13.2] Read MSR 0xC0000100 (IA32_FS_BASE)\n");
        ok = R0SimulateMSR(R0SMSR_OP_READ, 0xC0000100, 0, &value);
        if (ok)
            printf("      OK: value = 0x%016llX\n", value);
        else
            print_last_error("R0S MSR read FS_BASE");
        printf("\n");
    }

    printf("[14] IOCTL_R0SIMULATE_IRQL  (R0S IRQL)\n");
    {
        UCHAR oldIrql = 0, newIrql = 0;
        BOOL  ok;

        printf("  [14.1] QUERY: read current IRQL\n");
        ok = R0SimulateIRQL(R0SIRQL_OP_QUERY, 0, &oldIrql, &newIrql);
        if (ok)
            printf("      OK: current IRQL = %u\n", oldIrql);
        else
            print_last_error("R0S IRQL QUERY");
        printf("\n");
    }

    printf("[15] IOCTL_R0SIMULATE_ARBITRARY_DRIVER_CALL  (R0S IRP)\n");
    {
        UINT64 driverObject = 0;
        BOOL   ok;
        UCHAR  inData[8]  = {0};
        UCHAR  outData[64] = {0};
        ULONG  info = 0;

        printf("  [15.1] Read g_DriverObject from variable table (ID=0x%04X)\n", VAR_ID_G_DRIVEROBJECT);
        ok = R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_GET,
            VAR_ID_G_DRIVEROBJECT,
            0,
            &driverObject, sizeof(driverObject),
            NULL,
            R0SIMULATE_ERROR_MODE_DEFAULT
        );
        if (!ok || driverObject == 0)
        {
            print_last_error("get g_DriverObject");
            printf("\n");
            goto irp_done;
        }
        printf("      OK: DRIVER_OBJECT = 0x%016llX\n", driverObject);

        printf("  [15.2] Send IRP_MJ_CREATE to the driver\n");
        ok = R0SimulateArbitraryDriverCall(
            driverObject,
            IRP_MJ_CREATE,      /* 0x00 */
            0,
            0,
            inData, sizeof(inData),
            outData, sizeof(outData),
            &info
        );
        if (!ok)
        {
            print_last_error("R0S IRP CREATE");
        }
        else
        {
            printf("      OK: driver returned Information = %lu bytes\n", (unsigned long)info);
        }

        printf("  [15.3] Send IRP_MJ_CLEANUP to a NULL driver object (expect failure)\n");
        info = 0;
        memset(outData, 0, sizeof(outData));
        SetLastError(0);
        ok = R0SimulateArbitraryDriverCall(
            0,                  /* NULL driver object */
            IRP_MJ_CLEANUP,     /* 0x12 */
            0,
            0,
            inData, sizeof(inData),
            outData, sizeof(outData),
            &info
        );
        if (!ok)
        {
            DWORD err = GetLastError();
            printf("      FAIL returned as expected, error code = 0x%08lX (%lu)\n",
                   err, err);
            if (err == ERROR_INVALID_PARAMETER)
                printf("      PASS: NULL driver object rejected with ERROR_INVALID_PARAMETER\n");
            else
                printf("      FAIL: unexpected error code (expected 87 / ERROR_INVALID_PARAMETER)\n");
        }
        else
        {
            printf("      UNEXPECTED: call succeeded with NULL driver object\n");
        }

irp_done:
        printf("\n");
    }

    printf("===== All test finished. Press Enter to exit =====\n");
    (void)getchar();
    return 0;
}