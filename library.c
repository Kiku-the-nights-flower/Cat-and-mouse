#include "library.h"
#include <stdio.h>
#include <windows.h>

#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT
#endif


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(nullptr,
                        "C Library Injection Successful!",
                        "CVE-2025-59489 Test",
                        MB_OK | MB_ICONEXCLAMATION);
            break;

        case DLL_PROCESS_DETACH:
            break;
        default:
            return FALSE;
    }
    return TRUE;
}






