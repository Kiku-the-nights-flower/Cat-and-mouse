#ifndef CAT_AND_MOUSE_LIBRARY_H
#define CAT_AND_MOUSE_LIBRARY_H

#include <windows.h>
#include <winternl.h>

HMODULE GetLibraryBase(const wchar_t *);
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID);
void OnProcessAttach();
void InitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

#endif // CAT_AND_MOUSE_LIBRARY_H