#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "R0Simulates.h"

#define LIST_BUFFER_SIZE 16384

static BOOL IsNumericId(const char* str) {
    if (!str || !*str) return FALSE;
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        if (!str[2]) return FALSE;
        for (const char* p = str + 2; *p; p++) {
            if (!isxdigit((unsigned char)*p)) return FALSE;
        }
        return TRUE;
    }
    for (const char* p = str; *p; p++) {
        if (*p < '0' || *p > '9') return FALSE;
    }
    return TRUE;
}

static UINT64 ParseValue(const char* str) {
    char* endptr = NULL;
    unsigned long long val = strtoull(str, &endptr, 0);
    if (endptr == str || *endptr != '\0') {
        fprintf(stderr, "Error: invalid value '%s'\n", str);
        exit(1);
    }
    return (UINT64)val;
}

static void PrintHelp(const char* prog) {
    printf(
        "Usage:\n"
        "  %s list                              - List all internal variables\n"
        "  %s get  <ID_or_name>                 - Get variable value (hex)\n"
        "  %s set  <ID_or_name> <value>         - Set variable value (hex or decimal)\n"
        "\n"
        "ID mode examples:\n"
        "  %s get  16\n"
        "  %s set  16 1\n"
        "  %s set  0x1000 1\n"
        "\n"
        "Name mode examples (case-insensitive, resolved by driver):\n"
        "  %s get  g_SecureMode\n"
        "  %s set  g_SecureMode 1\n"
        "  %s get  g_PreviousModeOffset\n"
        "  %s set  g_IoctlDisable[0] 1\n"
        "  %s get  DLL_ErrorMode\n"
        "\n"
        "Notes: requires admin privileges; R0Simulate.sys must be loaded.\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog
    );
}

typedef struct _DLL_VAR {
    const char* name;
    ULONG       id;
} DLL_VAR;

static const DLL_VAR g_DllVars[] = {
    { "DLL_ErrorMode",    R0SIMULATE_VAR_DLL_ERROR_MODE },
    { "DLL_ERRORMODE",    R0SIMULATE_VAR_DLL_ERROR_MODE },
    { "ErrorMode",        R0SIMULATE_VAR_DLL_ERROR_MODE },
};
#define DLL_VARS_COUNT (sizeof(g_DllVars) / sizeof(g_DllVars[0]))

static ULONG LookupDllVar(const char* name) {
    ULONG i;
    for (i = 0; i < DLL_VARS_COUNT; i++) {
        if (_stricmp(g_DllVars[i].name, name) == 0)
            return g_DllVars[i].id;
    }
    return 0;
}

static BOOL BuildVarId(const char* arg,
                       PUINT64     pOutVarId,
                       PWCHAR      pOutName,
                       ULONG       nameChars,
                       PWCHAR*     pAllocName)
{
    ULONG dllId;
    size_t need;
    WCHAR* nameW;

    *pAllocName = NULL;

    if (IsNumericId(arg)) {
        *pOutVarId = (UINT64)strtoul(arg, NULL, 0);
        if (pOutName && nameChars > 0) pOutName[0] = L'\0';
        return TRUE;
    }

    
    dllId = LookupDllVar(arg);
    if (dllId != 0) {
        *pOutVarId = (UINT64)dllId;
        if (pOutName && nameChars > 0)
            MultiByteToWideChar(CP_ACP, 0, arg, -1, pOutName, (int)nameChars);
        return TRUE;
    }

    
    need = strlen(arg) + 1;
    if (need > 256) {
        fprintf(stderr, "Error: variable name too long.\n");
        return FALSE;
    }

    nameW = (WCHAR*)calloc(need, sizeof(WCHAR));
    if (!nameW) {
        fprintf(stderr, "Error: memory allocation failed.\n");
        return FALSE;
    }

    if (MultiByteToWideChar(CP_ACP, 0, arg, -1, nameW, (int)need) == 0) {
        free(nameW);
        fprintf(stderr, "Error: failed to convert name to wide chars.\n");
        return FALSE;
    }

    *pAllocName = nameW;
    *pOutVarId  = R0SIMULATE_VAR_NAME_FLAG | (UINT64)(ULONG_PTR)nameW;

    if (pOutName && nameChars > 0) {
        wcsncpy(pOutName, nameW, nameChars - 1);
        pOutName[nameChars - 1] = L'\0';
    }
    return TRUE;
}

int main(int argc, char* argv[]) {
    const char* cmd;
    BOOL result = FALSE;
    ULONG errorMode = R0SIMULATE_ERROR_MODE_DEFAULT;

    if (argc < 2) {
        PrintHelp(argv[0]);
        return 1;
    }

    cmd = argv[1];

    if (strcmp(cmd, "list") == 0) {
        UCHAR* buffer;
        ULONG infoCount = 0;
        ULONG count;
        PVAR_INFO vars;
        ULONG i;

        if (argc != 2) {
            fprintf(stderr, "Error: 'list' takes no extra arguments.\n");
            return 1;
        }

        buffer = (UCHAR*)calloc(1, LIST_BUFFER_SIZE);
        if (!buffer) {
            fprintf(stderr, "Error: memory allocation failed.\n");
            return 1;
        }

        result = R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_LIST,
            0, 0,
            buffer, LIST_BUFFER_SIZE,
            &infoCount,
            errorMode);

        if (!result) {
            DWORD err = GetLastError();
            fprintf(stderr, "Error: 'list' failed (GetLastError = %lu / 0x%08lX)\n", err, err);
            free(buffer);
            return 1;
        }

        count = *(PULONG)buffer;
        vars  = (PVAR_INFO)(buffer + sizeof(ULONG));

        printf("Driver returned %lu internal variable(s):\n", count);
        printf("  %-6s  %-40s  %-6s  %-18s\n", "ID", "Name", "Size", "Value");
        printf("  %-6s  %-40s  %-6s  %-18s\n", "----", "----", "----", "-----");
        for (i = 0; i < count; i++) {
            printf("  0x%04lX  ", vars[i].Id);
            wprintf(L"%-40s", vars[i].Name);
            printf("  %-6lu  0x%016llX\n", vars[i].Size, vars[i].Value);
        }

        {
            UINT64 dllMode = 0;
            if (R0SimulateSetInternalVariables(
                    R0SIMULATE_VAR_OP_GET,
                    R0SIMULATE_VAR_DLL_ERROR_MODE,
                    0,
                    &dllMode, sizeof(dllMode),
                    NULL,
                    errorMode)) {
                printf("\nDLL internal variable(s):\n");
                printf("  %-6s  %-40s  %-6s  %-18s\n", "ID", "Name", "Size", "Value");
                printf("  0x%-4X  %-40s  %-6d  0x%016llX\n",
                       R0SIMULATE_VAR_DLL_ERROR_MODE,
                       "DLL_ErrorMode",
                       4,
                       dllMode);
            }
        }

        free(buffer);
        result = TRUE;
    }
    else if (strcmp(cmd, "get") == 0) {
        UINT64 varId = 0;
        WCHAR  resolvedName[64] = {0};
        WCHAR* allocatedName = NULL;
        BOOL   isNamed;
        UINT64 value = 0;

        if (argc != 3) {
            fprintf(stderr, "Error: 'get' requires a variable ID or name.\n");
            return 1;
        }

        isNamed = !IsNumericId(argv[2]);

        if (!BuildVarId(argv[2], &varId, resolvedName, 64, &allocatedName)) {
            return 1;
        }

        result = R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_GET,
            varId,
            0,
            &value, sizeof(value),
            NULL,
            errorMode);

        free(allocatedName);   

        if (!result) {
            DWORD err = GetLastError();
            fprintf(stderr, "Error: 'get' failed (GetLastError = %lu / 0x%08lX)\n", err, err);
            return 1;
        }

        if (isNamed) {
            printf("Name = ");
            wprintf(L"%ls", resolvedName);
            printf("  value = 0x%016llX  (%llu)\n", value, value);
        } else {
            printf("ID = 0x%llX (%llu)  value = 0x%016llX  (%llu)\n",
                   varId, varId, value, value);
        }
    }
    else if (strcmp(cmd, "set") == 0) {
        UINT64 varId = 0;
        WCHAR  resolvedName[64] = {0};
        WCHAR* allocatedName = NULL;
        BOOL   isNamed;
        UINT64 value;

        if (argc != 4) {
            fprintf(stderr, "Error: 'set' requires a variable ID or name and a value.\n");
            return 1;
        }

        isNamed = !IsNumericId(argv[2]);

        if (!BuildVarId(argv[2], &varId, resolvedName, 64, &allocatedName)) {
            return 1;
        }

        value = ParseValue(argv[3]);
        result = R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_SET,
            varId,
            value,
            NULL, 0,
            NULL,
            errorMode);

        free(allocatedName);

        if (!result) {
            DWORD err = GetLastError();
            fprintf(stderr, "Error: 'set' failed (GetLastError = %lu / 0x%08lX)\n", err, err);
            return 1;
        }

        if (isNamed) {
            printf("Set Name = ");
            wprintf(L"%ls", resolvedName);
            printf("  = 0x%016llX\n", value);
        } else {
            printf("Set ID = 0x%llX (%llu) = 0x%016llX\n", varId, varId, value);
        }
    }
    else {
        fprintf(stderr, "Error: unknown subcommand '%s'.\n", cmd);
        PrintHelp(argv[0]);
        return 1;
    }

    return result ? 0 : 1;
}