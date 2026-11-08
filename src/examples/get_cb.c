#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include "R0Simulates.h"

int main(void)
{
    BYTE  outBuf[64 * 1024];
    ULONG infoCount = 0;
    PR0S_CALLBACK_CTL_OUTPUT pOut;
    ULONG i;

    ZeroMemory(outBuf, sizeof(outBuf));

    if (!R0SimulateCallbackControl(
            R0SCB_OP_LIST,       
            0,                   
            0,                   
            0,                   
            0,                   
            0,                   
            NULL,                
            NULL,                
            NULL,                
            0,                   
            outBuf,              
            sizeof(outBuf),      
            &infoCount)) {       
        printf("R0SimulateCallbackControl failed: 0x%08lX\n",
               GetLastError());
        return 1;
    }

    pOut = (PR0S_CALLBACK_CTL_OUTPUT)outBuf;

    printf("Enabled  = %llu\n",  (unsigned long long)pOut->Enabled);
    printf("Reserved = 0x%04X\n", (unsigned)pOut->Reserved);
    printf("Altitude = %ls\n",   pOut->Altitude);
    printf("Count    = %lu  (infoCount = %lu)\n\n",
           (unsigned long)pOut->Count, (unsigned long)infoCount);

    if (pOut->Count == 0) {
        printf("(no client entries registered via R0SCB_OP_ADD)\n");
        return 0;
    }

    printf("%-10s %-12s %-6s %-18s %-10s %s\n",
           "ThreadId", "ExitStatus", "Prio", "Mask",
           "CallCount", "LastResult");
    printf("%-10s %-12s %-6s %-18s %-10s %s\n",
           "--------", "----------", "----", "------------------",
           "---------", "----------");

    for (i = 0; i < pOut->Count; i++) {
        PR0S_CALLBACK_ENTRY_INFO e = &pOut->Entries[i];
        printf("%-10llu 0x%08X   %-6lu 0x%016llX %-10lu 0x%016llX\n",
               (unsigned long long)(ULONG_PTR)e->ThreadId,
               (unsigned)e->ExitStatus,
               (unsigned long)e->Priority,
               (unsigned long long)e->Mask,
               (unsigned long)e->CallCount,
               (unsigned long long)e->LastResult);
    }

    return 0;
}