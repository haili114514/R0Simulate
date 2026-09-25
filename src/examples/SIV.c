#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "R0Simulates.h"

#define LIST_BUFFER_SIZE 16384

static int wcs_icmp_char(const WCHAR* a, const char* b) {
    if (!a || !b) return -1;
    while (*b) {
        WCHAR ca = *a;
        WCHAR cb = (WCHAR)(unsigned char)*b;
        if (ca >= L'A' && ca <= L'Z') ca = (WCHAR)(ca + 32);
        if (cb >= L'A' && cb <= L'Z') cb = (WCHAR)(cb + 32);
        if (ca != cb) return (ca < cb) ? -1 : 1;
        a++;
        b++;
    }
    return (*a == 0) ? 0 : 1;
}

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
        "Name mode examples (case-insensitive):\n"
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

static BOOL FindIdByName(const char* name, PULONG pOutId, PWCHAR pOutName, ULONG nameChars) {
    ULONG i;

    for (i = 0; i < DLL_VARS_COUNT; i++) {
        if (_stricmp(g_DllVars[i].name, name) == 0) {
            *pOutId = g_DllVars[i].id;
            if (pOutName && nameChars > 0) {
                MultiByteToWideChar(CP_ACP, 0, g_DllVars[i].name, -1, pOutName, (int)nameChars);
            }
            return TRUE;
        }
    }

    UCHAR* buffer = (UCHAR*)calloc(1, LIST_BUFFER_SIZE);
    if (!buffer) {
        fprintf(stderr, "Error: memory allocation failed.\n");
        return FALSE;
    }

    ULONG infoCount = 0;
    BOOL ok = R0SimulateSetInternalVariables(
        R0SIMULATE_VAR_OP_LIST,
        0, 0,
        buffer, LIST_BUFFER_SIZE,
        &infoCount,
        R0SIMULATE_ERROR_MODE_DEFAULT);

    if (!ok) {
        fprintf(stderr, "Error: LIST failed during name resolution (GetLastError = %lu)\n", GetLastError());
        free(buffer);
        return FALSE;
    }

    ULONG count = *(PULONG)buffer;
    PVAR_INFO vars = (PVAR_INFO)(buffer + sizeof(ULONG));

    BOOL found = FALSE;
    for (i = 0; i < count; i++) {
        if (wcs_icmp_char(vars[i].Name, name) == 0) {
            *pOutId = vars[i].Id;
            if (pOutName && nameChars > 0) {
                wcsncpy(pOutName, vars[i].Name, nameChars - 1);
                pOutName[nameChars - 1] = L'\0';
            }
            found = TRUE;
            break;
        }
    }

    free(buffer);
    if (!found) {
        fprintf(stderr, "Error: variable '%s' not found. Use 'SIV list' to see all names.\n", name);
    }
    return found;
}

static BOOL ResolveId(const char* arg, PULONG pOutId, PWCHAR pOutName, ULONG nameChars) {
    if (IsNumericId(arg)) {
        *pOutId = (ULONG)strtoul(arg, NULL, 0);
        if (pOutName && nameChars > 0) pOutName[0] = L'\0';
        return TRUE;
    }
    return FindIdByName(arg, pOutId, pOutName, nameChars);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintHelp(argv[0]);
        return 1;
    }

    const char* cmd = argv[1];
    BOOL result = FALSE;
    ULONG errorMode = R0SIMULATE_ERROR_MODE_DEFAULT;

    if (strcmp(cmd, "list") == 0) {
        if (argc != 2) {
            fprintf(stderr, "Error: 'list' takes no extra arguments.\n");
            return 1;
        }

        UCHAR* buffer = (UCHAR*)calloc(1, LIST_BUFFER_SIZE);
        if (!buffer) {
            fprintf(stderr, "Error: memory allocation failed.\n");
            return 1;
        }

        ULONG infoCount = 0;
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

        ULONG count = *(PULONG)buffer;
        PVAR_INFO vars = (PVAR_INFO)(buffer + sizeof(ULONG));

        printf("Driver returned %lu internal variable(s):\n", count);
        printf("  %-6s  %-40s  %-6s  %-18s\n", "ID", "Name", "Size", "Value");
        printf("  %-6s  %-40s  %-6s  %-18s\n", "----", "----", "----", "-----");
        for (ULONG i = 0; i < count; i++) {
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
        if (argc != 3) {
            fprintf(stderr, "Error: 'get' requires a variable ID or name.\n");
            return 1;
        }

        ULONG  id = 0;
        WCHAR  resolvedName[64] = {0};
        BOOL   isNamed = !IsNumericId(argv[2]);

        if (!ResolveId(argv[2], &id, resolvedName, 64)) {
            return 1;
        }

        UINT64 value = 0;
        result = R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_GET,
            id,
            0,
            &value, sizeof(value),
            NULL,
            errorMode);

        if (!result) {
            DWORD err = GetLastError();
            fprintf(stderr, "Error: 'get' failed (GetLastError = %lu / 0x%08lX)\n", err, err);
            return 1;
        }

        if (isNamed) {
            printf("ID = 0x%lX (%lu)  Name = ", id, id);
            wprintf(L"%ls", resolvedName);
            printf("  value = 0x%016llX  (%llu)\n", value, value);
        } else {
            printf("ID = 0x%lX (%lu)  value = 0x%016llX  (%llu)\n",
                   id, id, value, value);
        }
    }
    else if (strcmp(cmd, "set") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: 'set' requires a variable ID or name and a value.\n");
            return 1;
        }

        ULONG  id = 0;
        WCHAR  resolvedName[64] = {0};
        BOOL   isNamed = !IsNumericId(argv[2]);

        if (!ResolveId(argv[2], &id, resolvedName, 64)) {
            return 1;
        }

        UINT64 value = ParseValue(argv[3]);

        if (id == 4 && value > 2) {
            fprintf(stderr, "Warning: g_FunctionLookupMode accepts only 0, 1, 2.\n");
        }
        if (id == R0SIMULATE_VAR_DLL_ERROR_MODE && value > 1) {
            fprintf(stderr, "Warning: DLL_ErrorMode accepts only 0, 1.\n");
        }

        result = R0SimulateSetInternalVariables(
            R0SIMULATE_VAR_OP_SET,
            id,
            value,
            NULL, 0,
            NULL,
            errorMode);

        if (!result) {
            DWORD err = GetLastError();
            fprintf(stderr, "Error: 'set' failed (GetLastError = %lu / 0x%08lX)\n", err, err);
            return 1;
        }

        if (isNamed) {
            printf("Set ID = 0x%lX (%lu)  Name = ", id, id);
            wprintf(L"%ls", resolvedName);
            printf("  = 0x%016llX\n", value);
        } else {
            printf("Set ID = 0x%lX (%lu) = 0x%016llX\n", id, id, value);
        }
    }
    else {
        fprintf(stderr, "Error: unknown subcommand '%s'.\n", cmd);
        PrintHelp(argv[0]);
        return 1;
    }

    return result ? 0 : 1;
}