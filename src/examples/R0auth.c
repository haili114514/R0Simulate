#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "R0Simulates.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_PENDING
#define STATUS_PENDING ((NTSTATUS)0x00000103L)
#endif

#define AUTH_MODE_VAR_NAME  L"g_AuthMode"
#define AUTH_MODE_VAR_ID    (R0SIMULATE_VAR_NAME_FLAG | (UINT64)(ULONG_PTR)AUTH_MODE_VAR_NAME)

static void PrintWin32Error(const char* what)
{
    DWORD  err = GetLastError();
    LPWSTR msg = NULL;
    char   buf[512];
    if (FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPWSTR)&msg, 0, NULL) && msg) {
        WideCharToMultiByte(CP_ACP, 0, msg, -1, buf, sizeof(buf), NULL, NULL);
        {
            size_t l = strlen(buf);
            while (l > 0 && (buf[l-1] == '\r' || buf[l-1] == '\n')) buf[--l] = 0;
        }
        fprintf(stderr, "[!] %s failed: %s (code=%lu)\n", what, buf, (unsigned long)err);
        LocalFree(msg);
    } else {
        fprintf(stderr, "[!] %s failed, code=%lu\n", what, (unsigned long)err);
    }
}

static int cmd_add(ULONG pid)
{
    if (pid == 0) { fprintf(stderr, "[!] invalid PID\n"); return 1; }
    if (!R0SimulateAuthorizedListOperations(R0SAUTH_OP_ADD, pid,
                                             0, 0, NULL, 0, NULL)) {
        PrintWin32Error("add");
        return 1;
    }
    printf("[+] added PID %lu (mask = g_AuthDefaultMask)\n", (unsigned long)pid);
    return 0;
}

static int cmd_remove(ULONG pid)
{
    if (pid == 0) { fprintf(stderr, "[!] invalid PID\n"); return 1; }
    if (!R0SimulateAuthorizedListOperations(R0SAUTH_OP_REMOVE, pid,
                                             0, 0, NULL, 0, NULL)) {
        PrintWin32Error("remove");
        return 1;
    }
    printf("[+] removed PID %lu\n", (unsigned long)pid);
    return 0;
}

static int cmd_set(ULONG pid, UINT64 mask)
{
    if (pid == 0) { fprintf(stderr, "[!] invalid PID\n"); return 1; }
    if (!R0SimulateAuthorizedListOperations(R0SAUTH_OP_SET, pid,
                                             mask, 0, NULL, 0, NULL)) {
        PrintWin32Error("set");
        return 1;
    }
    printf("[+] PID %lu mask = 0x%016llX\n",
           (unsigned long)pid, (unsigned long long)mask);
    return 0;
}

static int cmd_get(ULONG pid, const char* what)
{
    UINT64 value = 0;
    ULONG  getType;

    if (pid == 0) {
        fprintf(stderr, "[!] invalid PID\n");
        return 1;
    }

    if (_stricmp(what, "mask") == 0) {
        getType = R0SAUTH_GET_MASK;
    } else if (_stricmp(what, "status") == 0 ||
               _stricmp(what, "exitstatus") == 0) {
        getType = R0SAUTH_GET_EXITSTATUS;
    } else {
        fprintf(stderr, "[!] unknown get type '%s' (expected mask or status)\n", what);
        return 1;
    }

    if (!R0SimulateAuthorizedListOperations(R0SAUTH_OP_GET, pid,
                                             0, getType,
                                             &value, sizeof(value), NULL)) {
        PrintWin32Error("get");
        return 1;
    }

    if (getType == R0SAUTH_GET_MASK) {
        printf("[+] PID %lu mask = 0x%016llX\n",
               (unsigned long)pid, (unsigned long long)value);
    } else {
        NTSTATUS st = (NTSTATUS)(ULONG)value;
        printf("[+] PID %lu exit status = 0x%08X%s\n",
               (unsigned long)pid,
               (unsigned)st,
               (st == STATUS_PENDING) ? " (alive)" : " (exited)");
    }
    return 0;
}

static int cmd_list(void)
{
    static BYTE buf[64 * 1024];
    R0S_AUTH_LIST_OUTPUT* pOut;
    ULONG count = 0, i;

    memset(buf, 0, sizeof(buf));
    if (!R0SimulateAuthorizedListOperations(R0SAUTH_OP_LIST, 0,
                                             0, 0,
                                             buf, (ULONG)sizeof(buf), &count)) {
        PrintWin32Error("list");
        return 1;
    }

    pOut = (R0S_AUTH_LIST_OUTPUT*)buf;
    printf("Authorized list: %lu entries\n", (unsigned long)pOut->Count);
    printf("  g_AuthDefaultMask = 0x%016llX\n",
           (unsigned long long)pOut->DefaultMask);
    printf("  %-12s  %-12s  %-18s\n", "PID", "ExitStatus", "Mask");
    printf("  %-12s  %-12s  %-18s\n", "----", "----------", "----");

    for (i = 0; i < pOut->Count; i++) {
        ULONG    pid = (ULONG)(ULONG_PTR)pOut->Entries[i].Pid;
        NTSTATUS st  = pOut->Entries[i].ExitStatus;
        printf("  %-12lu  0x%08X   0x%016llX%s\n",
               (unsigned long)pid,
               (unsigned)st,
               (unsigned long long)pOut->Entries[i].IoctlMask,
               (st == STATUS_PENDING) ? "   (alive)" : "   (exited)");
    }
    return 0;
}

static int cmd_start(const char* cmdline, UINT64 mask, BOOL setMask)
{
    STARTUPINFOA        si = {0};
    PROCESS_INFORMATION pi = {0};
    char                cmdBuf[1024];
    DWORD               resumeRet;
    int                 failed = 0;

    if (!cmdline || !cmdline[0]) {
        fprintf(stderr, "[!] empty command line\n");
        return 1;
    }
    strncpy(cmdBuf, cmdline, sizeof(cmdBuf) - 1);
    cmdBuf[sizeof(cmdBuf) - 1] = 0;
    si.cb = sizeof(si);

    if (!CreateProcessA(NULL, cmdBuf, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                        NULL, NULL, &si, &pi)) {
        PrintWin32Error("CreateProcess");
        return 1;
    }
    printf("[*] suspended process started: PID=%lu, TID=%lu\n",
           (unsigned long)pi.dwProcessId, (unsigned long)pi.dwThreadId);

    if (!R0SimulateAuthorizedListOperations(R0SAUTH_OP_ADD, pi.dwProcessId,
                                             0, 0, NULL, 0, NULL)) {
        PrintWin32Error("add");
        failed = 1;
        goto cleanup;
    }

    if (setMask) {
        if (!R0SimulateAuthorizedListOperations(R0SAUTH_OP_SET, pi.dwProcessId,
                                                 mask, 0, NULL, 0, NULL)) {
            PrintWin32Error("set mask");
            failed = 1;
            goto cleanup;
        }
        printf("[+] mask = 0x%016llX\n", (unsigned long long)mask);
    }

    resumeRet = ResumeThread(pi.hThread);
    if (resumeRet == (DWORD)-1) {
        PrintWin32Error("ResumeThread");
        failed = 1;
        goto cleanup;
    }
    printf("[+] process resumed\n");

cleanup:
    if (failed) {
        fprintf(stderr, "[*] rollback: terminating process\n");
        TerminateProcess(pi.hProcess, 1);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return failed ? 1 : 0;
}

static int cmd_set_auth_mode(ULONG mode)
{
    if (!R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_SET, AUTH_MODE_VAR_ID, mode,
            NULL, 0, NULL)) {
        PrintWin32Error("set g_AuthMode");
        return 1;
    }
    printf("[+] g_AuthMode = %lu (%s)\n",
           (unsigned long)mode, mode ? "enabled" : "disabled");
    return 0;
}

static int cmd_status(void)
{
    UINT64 value = 0;
    if (!R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_GET, AUTH_MODE_VAR_ID, 0,
            &value, sizeof(value), NULL)) {
        PrintWin32Error("get g_AuthMode");
        return 1;
    }
    printf("g_AuthMode = %lu (%s)\n",
           (unsigned long)value, value ? "enabled" : "disabled");
    return 0;
}

static void usage(const char* prog)
{
    printf("R0S Authorization Manager\n\n");
    printf("Usage:\n");
    printf("  %s add <pid>                              - add process, mask=g_AuthDefaultMask\n", prog);
    printf("  %s remove <pid>                           - remove process\n", prog);
    printf("  %s set <pid> <mask>                       - set mask (bit N = IOCTL 0x8NN)\n", prog);
    printf("  %s get <pid> mask|status                  - query mask or exit status\n", prog);
    printf("  %s list                                   - list authorized entries\n", prog);
    printf("  %s start <commandline> [mask]             - launch suspended, ADD, SET(mask), resume\n", prog);
    printf("  %s on | off | status                      - enable/disable/show auth mode\n", prog);
    printf("\n");
    printf("Mask examples (bit N = IOCTL 0x8NN):\n");
    printf("  0x00000001  = 0x800 (EXEC)\n");
    printf("  0x00000403  = 0x800 | 0x801 | 0x80A (EXEC|API|AUTH)\n");
    printf("  0xFFFFFFFFFFFFFFFF = all\n");
    printf("\n");
    printf("Get examples:\n");
    printf("  %s get 2804 mask     - query mask of PID 2804\n", prog);
    printf("  %s get 2804 status   - query exit status of PID 2804\n", prog);
    printf("\n");
    printf("Start examples:\n");
    printf("  %s start \"C:\\Windows\\System32\\notepad.exe\"\n", prog);
    printf("  %s start \"C:\\game\\app.exe -foo\" 0xFFFFFFFFFFFFFFFF\n", prog);
}

int main(int argc, char** argv)
{
    int rc;
    if (argc < 2) { usage(argv[0]); return 1; }
    if      (_stricmp(argv[1], "add")    == 0 && argc == 3)
        rc = cmd_add((ULONG)strtoul(argv[2], NULL, 0));
    else if (_stricmp(argv[1], "remove") == 0 && argc == 3)
        rc = cmd_remove((ULONG)strtoul(argv[2], NULL, 0));
    else if (_stricmp(argv[1], "set")    == 0 && argc == 4)
        rc = cmd_set((ULONG)strtoul(argv[2], NULL, 0),
                     (UINT64)strtoull(argv[3], NULL, 0));
    else if (_stricmp(argv[1], "get")    == 0 && argc == 4)
        rc = cmd_get((ULONG)strtoul(argv[2], NULL, 0), argv[3]);
    else if (_stricmp(argv[1], "list")   == 0) rc = cmd_list();
    else if (_stricmp(argv[1], "on")     == 0) rc = cmd_set_auth_mode(1);
    else if (_stricmp(argv[1], "off")    == 0) rc = cmd_set_auth_mode(0);
    else if (_stricmp(argv[1], "status") == 0) rc = cmd_status();
    else if (_stricmp(argv[1], "start")  == 0 && (argc == 3 || argc == 4)) {
        if (argc == 4)
            rc = cmd_start(argv[2], (UINT64)strtoull(argv[3], NULL, 0), TRUE);
        else
            rc = cmd_start(argv[2], 0, FALSE);
    }
    else { usage(argv[0]); rc = 1; }
    return rc;
}