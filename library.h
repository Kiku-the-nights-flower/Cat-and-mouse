#ifndef CAT_AND_MOUSE_LIBRARY_H
#define CAT_AND_MOUSE_LIBRARY_H

#include <windows.h>
#include <winternl.h>

HMODULE GetLibraryBase(const wchar_t *);
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID);
void OnProcessAttach();
void InitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
HANDLE CreateRegistryKey();
int RegisterService();
NTSTATUS SetRegistryKeyValue(HANDLE keyHandle, PCWSTR name, unsigned long type, void * value, unsigned long dataSize);

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

typedef struct API_TABLE {
    pNtCreateKey   NtCreateKey;
    pNtSetValueKey NtSetValueKey;
    pNtClose       NtClose;
    pNtOpenKey     NtOpenKey;
} API_TABLE, *PAPI_TABLE;

#endif // CAT_AND_MOUSE_LIBRARY_H