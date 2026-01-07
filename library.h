#ifndef CAT_AND_MOUSE_LIBRARY_H
#define CAT_AND_MOUSE_LIBRARY_H
#include "ntlib.h"

void InitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

const unsigned short * padString(const wchar_t * pref);


#endif // CAT_AND_MOUSE_LIBRARY_H
