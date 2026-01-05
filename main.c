//
// Created by mikul on 05.01.2026.
//

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
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
    FILE* hFile = fopen(filename, "w");
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

int main() {
    const char * inputFileName = "C:\\Users\\mikul\\Cat-and-mouse\\cmake-build-debug\\libCat_and_mouse_updater.dll";
    const char * outputPath = "C:\\Users\\mikul\\Cat-and-mouse\\updater.h";

    FILE *inFile = fopen(inputFileName, "rb");
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


    u_char * comprBuff = nullptr;
    u_long comprBuffSize = 0;
    NTSTATUS compressionResult = GetCompressedBuffer(buffer, fileSize, &comprBuff, &comprBuffSize);
    if (compressionResult != 0) {
        printf("Compression failed.\n");
        return -1;
    }

    GenerateHeaderFile(outputPath, "updaterBin", comprBuff, comprBuffSize, fileSize);
    free(buffer);
    free(comprBuff);
    return 0;
}
