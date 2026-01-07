#include "library.h"

#include <stdint.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif


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



