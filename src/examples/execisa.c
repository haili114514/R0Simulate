#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "R0Simulates.h"

static void show_help(const char* progName) {
    printf(
        "R0Simulate Executive - Machine Code Executor (Silent Mode)\n"
        "Usage: %s [-R3] [-L file] <hex bytes...>\n\n"
        "Options:\n"
        "  -R3          Execute in user mode (Ring3). Default is kernel mode (Ring0).\n"
        "  -L file      Load machine code from a binary file instead of hex string.\n"
        "  <hex bytes>  Space-separated hexadecimal bytes (case-insensitive).\n"
        "               e.g. F4 90 B8 01 00 00 00 C3\n\n"
        "Examples:\n"
        "  %s F4                          # Execute HLT instruction in Ring0\n"
        "  %s -R3 90 90                   # Execute two NOPs in Ring3\n"
        "  %s -L shellcode.bin            # Execute code from file in Ring0\n"
        "  %s B8 01 00 00 00 C3           # Return 1 (mov eax,1; ret)\n\n"
        "Return Value: RAX/EAX after execution.\n"
        "Requirements:\n"
        "  - Ring0 mode requires admin privileges and R0Simulate.sys loaded\n"
        "  - R0Simulates.dll must be available\n",
        progName, progName, progName, progName, progName
    );
}

static int is_option(const char* arg, const char* opt) {
    if (arg[0] != '-' || opt[0] != '-') return 0;
    const char* a = arg + 1;
    const char* b = opt + 1;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
        a++; b++;
    }
    return (*a == '\0' && *b == '\0');
}

static BYTE* parse_hex_args(int argc, char* argv[], int startIdx, size_t* outSize) {
    size_t totalLen = 0;
    for (int i = startIdx; i < argc; i++) {
        for (char* p = argv[i]; *p; p++) {
            if (!isspace((unsigned char)*p)) totalLen++;
        }
    }
    if (totalLen == 0) return NULL;
    if (totalLen % 2 != 0) {
        fprintf(stderr, "Error: Hex string length must be even.\n");
        return NULL;
    }
    *outSize = totalLen / 2;
    BYTE* data = (BYTE*)malloc(*outSize);
    if (!data) return NULL;

    char* hexStr = (char*)malloc(totalLen + 1);
    if (!hexStr) { free(data); return NULL; }
    char* q = hexStr;
    for (int i = startIdx; i < argc; i++) {
        for (char* p = argv[i]; *p; p++) {
            if (!isspace((unsigned char)*p)) *q++ = *p;
        }
    }
    *q = '\0';

    for (size_t i = 0; i < *outSize; i++) {
        char byteStr[3] = { hexStr[2 * i], hexStr[2 * i + 1], 0 };
        unsigned int byte;
        if (sscanf(byteStr, "%02x", &byte) != 1) {
            free(hexStr); free(data);
            fprintf(stderr, "Error: Invalid hex byte: %s\n", byteStr);
            return NULL;
        }
        data[i] = (BYTE)byte;
    }
    free(hexStr);
    return data;
}

static BYTE* read_file(const char* path, size_t* outSize) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile); return NULL;
    }
    BYTE* data = (BYTE*)malloc(fileSize);
    if (!data) { CloseHandle(hFile); return NULL; }
    DWORD bytesRead;
    if (!ReadFile(hFile, data, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(data); CloseHandle(hFile); return NULL;
    }
    CloseHandle(hFile);
    *outSize = fileSize;
    return data;
}

static LONG WINAPI veh_handler(PEXCEPTION_POINTERS ExceptionInfo) {
    fprintf(stderr, "\n[!] User-mode execution crashed with exception 0x%08X at RIP=0x%llX\n",
            ExceptionInfo->ExceptionRecord->ExceptionCode,
            (unsigned long long)ExceptionInfo->ContextRecord->Rip);
    ExitProcess(1);
    return EXCEPTION_EXECUTE_HANDLER;
}

static unsigned long long execute_user_mode(const BYTE* code, size_t size) {
    BYTE* execMem = (BYTE*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        fprintf(stderr, "VirtualAlloc failed\n");
        return 0;
    }
    memcpy(execMem, code, size);

    typedef unsigned long long (*func_t)();

    PVOID veh = AddVectoredExceptionHandler(1, veh_handler);

    func_t func = (func_t)execMem;
    unsigned long long result = func();

    RemoveVectoredExceptionHandler(veh);
    VirtualFree(execMem, 0, MEM_RELEASE);
    return result;
}

static unsigned long long execute_driver_mode(const BYTE* code, size_t size) {
    unsigned long long result = 0;
    DWORD err;
    UCHAR oldMode = 0, newMode = 0;

    HANDLE hToken = R0SimulateGetSystemToken(TRUE);
    if (hToken == NULL && GetLastError() != ERROR_SUCCESS) {
        fprintf(stderr, "R0SimulateGetSystemToken (replace) failed, error: %lu\n", GetLastError());
        return 0;
    }

    if (!R0SimulatePreviousModeSwitch(FALSE, R0SPMS_MODE_KERNEL, &oldMode, &newMode)) {
        fprintf(stderr, "R0SimulatePreviousModeSwitch (set kernel) failed, error: %lu\n", GetLastError());
        return 0;
    }

    result = R0SimulateISA(code, (unsigned long)size);
    err = GetLastError();
    if (result == 0 && err != ERROR_SUCCESS) {
        fprintf(stderr, "R0SimulateISA failed, error code: %lu\n", err);
    }

    if (!R0SimulatePreviousModeSwitch(FALSE, oldMode, NULL, NULL)) {
        fprintf(stderr, "Warning: Failed to restore PreviousMode, error: %lu\n", GetLastError());
    }

    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        show_help(argv[0]);
        return 0;
    }

    int userMode = 0;
    int loadFile = 0;
    char* filePath = NULL;
    int hexStart = -1;

    int i = 1;
    while (i < argc) {
        if (is_option(argv[i], "-r3") || is_option(argv[i], "-R3")) {
            userMode = 1;
            i++;
        } else if (is_option(argv[i], "-l") || is_option(argv[i], "-L")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -L requires a file path.\n");
                return 1;
            }
            loadFile = 1;
            filePath = argv[++i];
            i++;
        } else if (is_option(argv[i], "-h") || is_option(argv[i], "--help")) {
            show_help(argv[0]);
            return 0;
        } else {
            hexStart = i;
            break;
        }
    }

    if (hexStart == -1 && !loadFile) {
        show_help(argv[0]);
        return 0;
    }

    if (loadFile && hexStart != -1) {
        fprintf(stderr, "Error: cannot specify both -L and hex arguments.\n");
        return 1;
    }

    BYTE* machineCode = NULL;
    size_t codeSize = 0;

    if (loadFile) {
        machineCode = read_file(filePath, &codeSize);
        if (!machineCode) {
            fprintf(stderr, "Failed to read file: %s\n", filePath);
            return 1;
        }
    } else {
        machineCode = parse_hex_args(argc, argv, hexStart, &codeSize);
        if (!machineCode) {
            fprintf(stderr, "Invalid hex input.\n");
            return 1;
        }
    }

    unsigned long long result = 0;
    if (userMode) {
        result = execute_user_mode(machineCode, codeSize);
    } else {
        result = execute_driver_mode(machineCode, codeSize);
    }

    printf("\nFinal Result (RAX/EAX): 0x%llX (%llu)\n", result, result);

    free(machineCode);
    return 0;
}
