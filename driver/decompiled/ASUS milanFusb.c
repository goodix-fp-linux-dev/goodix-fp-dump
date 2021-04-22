typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef unsigned int    ImageBaseOffset32;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined6;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

struct _s__RTTIClassHierarchyDescriptor {
    dword signature;
    dword attributes; // bit flags
    dword numBaseClasses; // number of base classes (i.e. rtti1Count)
    ImageBaseOffset32 pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef int __ehstate_t;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    ImageBaseOffset32 dispUnwindMap;
    uint nTryBlocks;
    ImageBaseOffset32 dispTryBlockMap;
    uint nIPMapEntries;
    ImageBaseOffset32 dispIPToStateMap;
    int dispUnwindHelp;
    ImageBaseOffset32 dispESTypeList;
    int EHFlags;
};

typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

typedef struct PMD PMD, *PPMD;

struct PMD {
    int mdisp;
    int pdisp;
    int vdisp;
};

struct _s__RTTIBaseClassDescriptor {
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    dword numContainedBases; // count of extended classes in BaseClassArray (RTTI 2)
    struct PMD where; // member displacement structure
    dword attributes; // bit flags
    ImageBaseOffset32 pClassHierarchyDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3) for class
};

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    ImageBaseOffset32 action;
};

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator {
    dword signature;
    dword offset; // offset of vbtable within class
    dword cdOffset; // constructor displacement offset
    ImageBaseOffset32 pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    ImageBaseOffset32 pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef unsigned short    wchar16;
typedef struct _s_IPToStateMapEntry _s_IPToStateMapEntry, *P_s_IPToStateMapEntry;

struct _s_IPToStateMapEntry {
    ImageBaseOffset32 Ip;
    __ehstate_t state;
};

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef struct _s_IPToStateMapEntry IPToStateMapEntry;

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

typedef struct _s_FuncInfo FuncInfo;

typedef ulonglong __uint64;

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor {
    void * pVFTable;
    void * spare;
    char[0] name;
};

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulonglong ULONG_PTR;

typedef union _union_538 _union_538, *P_union_538;

typedef void * HANDLE;

typedef struct _struct_539 _struct_539, *P_struct_539;

typedef void * PVOID;

typedef ulong DWORD;

struct _struct_539 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_538 {
    struct _struct_539 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_538 u;
    HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void * LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

typedef ushort WORD;

struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

typedef struct _WIN32_FIND_DATAW _WIN32_FIND_DATAW, *P_WIN32_FIND_DATAW;

typedef struct _WIN32_FIND_DATAW * LPWIN32_FIND_DATAW;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

typedef wchar_t WCHAR;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAW {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    WCHAR cFileName[260];
    WCHAR cAlternateFileName[14];
};

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY * Flink;
    struct _LIST_ENTRY * Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION * CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (* PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT * PCONTEXT;

typedef ulonglong DWORD64;

typedef union _union_52 _union_52, *P_union_52;

typedef struct _M128A _M128A, *P_M128A;

typedef struct _M128A M128A;

typedef struct _XSAVE_FORMAT _XSAVE_FORMAT, *P_XSAVE_FORMAT;

typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32;

typedef struct _struct_53 _struct_53, *P_struct_53;

typedef ulonglong ULONGLONG;

typedef longlong LONGLONG;

typedef uchar BYTE;

struct _M128A {
    ULONGLONG Low;
    LONGLONG High;
};

struct _XSAVE_FORMAT {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

struct _struct_53 {
    M128A Header[2];
    M128A Legacy[8];
    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;
    M128A Xmm6;
    M128A Xmm7;
    M128A Xmm8;
    M128A Xmm9;
    M128A Xmm10;
    M128A Xmm11;
    M128A Xmm12;
    M128A Xmm13;
    M128A Xmm14;
    M128A Xmm15;
};

union _union_52 {
    XMM_SAVE_AREA32 FltSave;
    struct _struct_53 s;
};

struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union _union_52 u;
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct _SYSTEMTIME * LPSYSTEMTIME;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueSearch=1,
    ExceptionNestedException=2,
    ExceptionCollidedUnwind=3,
    ExceptionContinueExecution=0
} _EXCEPTION_DISPOSITION;

typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbname[77];
};

typedef struct _iobuf _iobuf, *P_iobuf;

typedef struct _iobuf FILE;

struct _iobuf {
    char * _ptr;
    int _cnt;
    char * _base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char * _tmpfname;
};

typedef int PMFN;

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

typedef struct _s_ThrowInfo ThrowInfo;

struct _s_ThrowInfo {
    uint attributes;
    PMFN pmfnUnwind;
    int pForwardCompat;
    int pCatchableTypeArray;
};

typedef ulonglong uintptr_t;

typedef longlong __time64_t;

typedef ulonglong size_t;

typedef int errno_t;

typedef size_t rsize_t;

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Class Structure
};

typedef struct bad_exception bad_exception, *Pbad_exception;

struct bad_exception { // PlaceHolder Class Structure
};

typedef struct _struct_314 _struct_314, *P_struct_314;

typedef union anon__struct_314_bitfield_1 anon__struct_314_bitfield_1, *Panon__struct_314_bitfield_1;

typedef union anon__struct_314_bitfield_2 anon__struct_314_bitfield_2, *Panon__struct_314_bitfield_2;

union anon__struct_314_bitfield_1 {
    ULONGLONG Depth:16; // : bits 0-15
    ULONGLONG Sequence:48; // : bits 16-63
};

union anon__struct_314_bitfield_2 {
    ULONGLONG HeaderType:1; // : bits 0
    ULONGLONG Init:1; // : bits 1
    ULONGLONG Reserved:2; // : bits 2-3
    ULONGLONG NextEntry:60; // : bits 4-63
};

struct _struct_314 {
    union anon__struct_314_bitfield_1 field_0x0;
    union anon__struct_314_bitfield_2 field_0x8;
};

typedef struct _struct_313 _struct_313, *P_struct_313;

typedef union anon__struct_313_bitfield_1 anon__struct_313_bitfield_1, *Panon__struct_313_bitfield_1;

typedef union anon__struct_313_bitfield_2 anon__struct_313_bitfield_2, *Panon__struct_313_bitfield_2;

union anon__struct_313_bitfield_2 {
    ULONGLONG HeaderType:1; // : bits 0
    ULONGLONG Init:1; // : bits 1
    ULONGLONG Reserved:59; // : bits 2-60
    ULONGLONG Region:3; // : bits 61-63
};

union anon__struct_313_bitfield_1 {
    ULONGLONG Depth:16; // : bits 0-15
    ULONGLONG Sequence:9; // : bits 16-24
    ULONGLONG NextEntry:39; // : bits 25-63
};

struct _struct_313 {
    union anon__struct_313_bitfield_1 field_0x0;
    union anon__struct_313_bitfield_2 field_0x8;
};

typedef struct _struct_312 _struct_312, *P_struct_312;

struct _struct_312 {
    ULONGLONG Alignment;
    ULONGLONG Region;
};

typedef struct _struct_315 _struct_315, *P_struct_315;

typedef union anon__struct_315_bitfield_1 anon__struct_315_bitfield_1, *Panon__struct_315_bitfield_1;

typedef union anon__struct_315_bitfield_2 anon__struct_315_bitfield_2, *Panon__struct_315_bitfield_2;

union anon__struct_315_bitfield_1 {
    ULONGLONG Depth:16; // : bits 0-15
    ULONGLONG Sequence:48; // : bits 16-63
};

union anon__struct_315_bitfield_2 {
    ULONGLONG HeaderType:1; // : bits 0
    ULONGLONG Reserved:3; // : bits 1-3
    ULONGLONG NextEntry:60; // : bits 4-63
};

struct _struct_315 {
    union anon__struct_315_bitfield_1 field_0x0;
    union anon__struct_315_bitfield_2 field_0x8;
};

typedef struct _RUNTIME_FUNCTION _RUNTIME_FUNCTION, *P_RUNTIME_FUNCTION;

struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef union _union_236 _union_236, *P_union_236;

union _union_236 {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
};

struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union _union_236 Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};

typedef struct _RUNTIME_FUNCTION * PRUNTIME_FUNCTION;

typedef struct _SLIST_ENTRY _SLIST_ENTRY, *P_SLIST_ENTRY;

typedef struct _SLIST_ENTRY * PSLIST_ENTRY;

struct _SLIST_ENTRY {
    PSLIST_ENTRY Next;
};

typedef struct _UNWIND_HISTORY_TABLE_ENTRY _UNWIND_HISTORY_TABLE_ENTRY, *P_UNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY UNWIND_HISTORY_TABLE_ENTRY;

struct _UNWIND_HISTORY_TABLE_ENTRY {
    DWORD64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
};

typedef union _union_61 _union_61, *P_union_61;

typedef ulonglong * PDWORD64;

typedef struct _struct_62 _struct_62, *P_struct_62;

struct _struct_62 {
    PDWORD64 Rax;
    PDWORD64 Rcx;
    PDWORD64 Rdx;
    PDWORD64 Rbx;
    PDWORD64 Rsp;
    PDWORD64 Rbp;
    PDWORD64 Rsi;
    PDWORD64 Rdi;
    PDWORD64 R8;
    PDWORD64 R9;
    PDWORD64 R10;
    PDWORD64 R11;
    PDWORD64 R12;
    PDWORD64 R13;
    PDWORD64 R14;
    PDWORD64 R15;
};

union _union_61 {
    PDWORD64 IntegerContext[16];
    struct _struct_62 s;
};

typedef EXCEPTION_DISPOSITION (EXCEPTION_ROUTINE)(struct _EXCEPTION_RECORD *, PVOID, struct _CONTEXT *, PVOID);

typedef union _SLIST_HEADER _SLIST_HEADER, *P_SLIST_HEADER;

union _SLIST_HEADER {
    struct _struct_312 s;
    struct _struct_313 Header8;
    struct _struct_314 Header16;
    struct _struct_315 HeaderX64;
};

typedef struct _struct_60 _struct_60, *P_struct_60;

typedef struct _M128A * PM128A;

struct _struct_60 {
    PM128A Xmm0;
    PM128A Xmm1;
    PM128A Xmm2;
    PM128A Xmm3;
    PM128A Xmm4;
    PM128A Xmm5;
    PM128A Xmm6;
    PM128A Xmm7;
    PM128A Xmm8;
    PM128A Xmm9;
    PM128A Xmm10;
    PM128A Xmm11;
    PM128A Xmm12;
    PM128A Xmm13;
    PM128A Xmm14;
    PM128A Xmm15;
};

typedef struct _UNWIND_HISTORY_TABLE _UNWIND_HISTORY_TABLE, *P_UNWIND_HISTORY_TABLE;

struct _UNWIND_HISTORY_TABLE {
    DWORD Count;
    BYTE LocalHint;
    BYTE GlobalHint;
    BYTE Search;
    BYTE Once;
    DWORD64 LowAddress;
    DWORD64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[12];
};

typedef char CHAR;

typedef CHAR * LPCSTR;

typedef LONG * PLONG;

typedef DWORD ACCESS_MASK;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

typedef union _union_59 _union_59, *P_union_59;

union _union_59 {
    PM128A FloatingContext[16];
    struct _struct_60 s;
};

struct _KNONVOLATILE_CONTEXT_POINTERS {
    union _union_59 u;
    union _union_61 u2;
};

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _IMAGE_SECTION_HEADER * PIMAGE_SECTION_HEADER;

typedef WCHAR * LPCWSTR;

typedef struct _UNWIND_HISTORY_TABLE * PUNWIND_HISTORY_TABLE;

typedef union _SLIST_HEADER * PSLIST_HEADER;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS * PKNONVOLATILE_CONTEXT_POINTERS;

typedef EXCEPTION_ROUTINE * PEXCEPTION_ROUTINE;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef struct tm tm, *Ptm;

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef longlong INT_PTR;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD * LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef BYTE * LPBYTE;

typedef struct _FILETIME * LPFILETIME;

typedef INT_PTR (* FARPROC)(void);

typedef struct HKEY__ * HKEY;

typedef HKEY * PHKEY;

typedef BYTE * PBYTE;

typedef void * LPCVOID;

typedef uint UINT;

typedef struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    word Flags;
    word Catalog;
    dword CatalogOffset;
    dword Reserved;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER64 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

typedef enum IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION=8192,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION=32768,
    IMAGE_GUARD_CF_INSTRUMENTED=256,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT=16384,
    IMAGE_GUARD_CFW_INSTRUMENTED=512,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4=1073741824,
    IMAGE_GUARD_RF_INSTRUMENTED=131072,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2=536870912,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT=65536,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1=268435456,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT=4096,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED=2048,
    IMAGE_GUARD_RF_STRICT=524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT=1024,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8=2147483648,
    IMAGE_GUARD_RF_ENABLE=262144
} IMAGE_GUARD_FLAGS;

struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    qword DeCommitFreeBlockThreshold;
    qword DeCommitTotalFreeThreshold;
    pointer64 LockPrefixTable;
    qword MaximumAllocationSize;
    qword VirtualMemoryThreshold;
    qword ProcessAffinityMask;
    dword ProcessHeapFlags;
    word CsdVersion;
    word DependentLoadFlags;
    pointer64 EditList;
    pointer64 SecurityCookie;
    pointer64 SEHandlerTable;
    qword SEHandlerCount;
    pointer64 GuardCFCCheckFunctionPointer;
    pointer64 GuardCFDispatchFunctionPointer;
    pointer64 GuardCFFunctionTable;
    qword GuardCFFunctionCount;
    enum IMAGE_GUARD_FLAGS GuardFlags;
    struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    pointer64 GuardAddressTakenIatEntryTable;
    qword GuardAddressTakenIatEntryCount;
    pointer64 GuardLongJumpTargetTable;
    qword GuardLongJumpTargetCount;
    pointer64 DynamicValueRelocTable;
    pointer64 CHPEMetadataPointer;
    pointer64 GuardRFFailureRoutine;
    pointer64 GuardRFFailureRoutineFunctionPointer;
    dword DynamicValueRelocTableOffset;
    word DynamicValueRelocTableSection;
    word Reserved1;
    pointer64 GuardRFVerifyStackPointerFunctionPointer;
    dword HotPatchTableOffset;
    dword Reserved2;
    qword Reserved3;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_MEM_WRITE=2147483648,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_MEM_NOT_CACHED=67108864
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    dword AddressOfFunctions;
    dword AddressOfNames;
    dword AddressOfNameOrdinals;
};

typedef ACCESS_MASK REGSAM;

typedef LONG LSTATUS;

typedef UINT MMRESULT;

typedef struct _xDISPATCHER_CONTEXT _xDISPATCHER_CONTEXT, *P_xDISPATCHER_CONTEXT;

struct _xDISPATCHER_CONTEXT { // PlaceHolder Structure
};

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

struct _s_HandlerType { // PlaceHolder Structure
};

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord { // PlaceHolder Structure
};

typedef struct _s_ESTypeList _s_ESTypeList, *P_s_ESTypeList;

struct _s_ESTypeList { // PlaceHolder Structure
};

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

struct _s_CatchableType { // PlaceHolder Structure
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry { // PlaceHolder Structure
};




LPBYTE FUN_180001080(HKEY param_1,LPCWSTR param_2,DWORD *param_3,LPBYTE *param_4,uint *param_5)

{
  LSTATUS LVar1;
  LPBYTE lpData;
  uint local_res20 [2];
  DWORD local_18 [4];
  
  if (param_4 != (LPBYTE *)0x0) {
    local_res20[0] = 0;
    LVar1 = RegQueryValueExW(param_1,param_2,(LPDWORD)0x0,local_18,(LPBYTE)0x0,local_res20);
    if (LVar1 == 0) {
      *param_4 = (LPBYTE)0x0;
      lpData = (LPBYTE)calloc(1,(ulonglong)local_res20[0]);
      *param_4 = lpData;
      LVar1 = RegQueryValueExW(param_1,param_2,(LPDWORD)0x0,local_18,lpData,local_res20);
      if (LVar1 == 0) {
        if (param_3 != (DWORD *)0x0) {
          *param_3 = local_18[0];
        }
        if (param_5 != (uint *)0x0) {
          *param_5 = local_res20[0];
        }
        return *param_4;
      }
      free(*param_4);
    }
  }
  return (LPBYTE)0x0;
}



LPBYTE FUN_18000114c(longlong param_1,LPCWSTR param_2,LPCWSTR param_3,DWORD *param_4,LPBYTE *param_5
                    ,uint *param_6)

{
  LSTATUS LVar1;
  LPBYTE pBVar2;
  HKEY hKey;
  HKEY local_res8;
  
  local_res8 = (HKEY)0x0;
  if (param_1 == -0x7ffffffe) {
    hKey = (HKEY)0xffffffff80000002;
  }
  else {
    if (param_1 != -0x7fffffff) goto LAB_1800011cb;
    LVar1 = RegOpenCurrentUser(1,(PHKEY)&local_res8);
    hKey = local_res8;
    if (LVar1 != 0) {
      return (LPBYTE)0x0;
    }
  }
  LVar1 = RegOpenKeyExW(hKey,param_2,0,1,(PHKEY)&local_res8);
  if (LVar1 != 0) {
    return (LPBYTE)0x0;
  }
LAB_1800011cb:
  pBVar2 = FUN_180001080(local_res8,param_3,param_4,param_5,param_6);
  return pBVar2;
}



void Get_LogOutput_config_FUN_180001200(void)

{
  undefined4 *puVar1;
  undefined4 *local_res8;
  
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"..\\common\\cmtest.c",
             (undefined *)L"Get_LogOutput_config",0x29d,0,(undefined *)L"CONFIG DATA: enter");
  local_res8 = (undefined4 *)0x0;
  FUN_18000114c(-0x7ffffffe,L"Software\\Goodix\\FP\\LogOutput\\",L"LogLevel",(DWORD *)0x0,
                (LPBYTE *)&local_res8,(uint *)0x0);
  puVar1 = local_res8;
  if (local_res8 != (undefined4 *)0x0) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"..\\common\\cmtest.c",
               (undefined *)L"Get_LogOutput_config",0x2a4,0,(undefined *)L"CONFIG DATA: LogLevel %d"
              );
    DAT_180036000 = *puVar1;
    free(puVar1);
    local_res8 = (undefined4 *)0x0;
  }
  FUN_18000114c(-0x7ffffffe,L"Software\\Goodix\\FP\\LogOutput\\",L"LogTarget",(DWORD *)0x0,
                (LPBYTE *)&local_res8,(uint *)0x0);
  puVar1 = local_res8;
  if (local_res8 != (undefined4 *)0x0) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"..\\common\\cmtest.c",
               (undefined *)L"Get_LogOutput_config",0x2ac,0,
               (undefined *)L"CONFIG DATA: LogTarget %d");
    DAT_180036004 = *puVar1;
    free(puVar1);
    local_res8 = (undefined4 *)0x0;
  }
  FUN_18000114c(-0x7ffffffe,L"Software\\Goodix\\FP\\LogOutput\\",L"LogPath",(DWORD *)0x0,
                (LPBYTE *)&local_res8,(uint *)0x0);
  puVar1 = local_res8;
  if (local_res8 != (undefined4 *)0x0) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"..\\common\\cmtest.c",
               (undefined *)L"Get_LogOutput_config",0x2b4,0,(undefined *)L"CONFIG DATA: LogPath %s")
    ;
    wcscpy_s(u_C__ProgramData_Goodix_180036008,0x103,(wchar_t *)puVar1);
    free(puVar1);
  }
  return;
}



void Init_LogOutput_WBDI_FUN_1800013fc(void)

{
  uint local_240;
  uint local_238;
  wchar_t *local_230;
  wchar_t local_228 [264];
  ulonglong local_18;
  
  local_18 = DAT_180037758 ^ (ulonglong)&stack0xfffffffffffffd88;
  memset(local_228,0,0x208);
  FID_conflict__sprintf_p(local_228,0x104,L"%s\\%s");
  if (PTR_DAT_180036ca8 != (undefined *)0x0) {
    FUN_180001c78(PTR_DAT_180036ca8);
  }
  PTR_DAT_180036ca8 = (undefined *)FUN_180001b84(L"GFWBDI",DAT_180036000,local_228,DAT_180036004);
  local_230 = local_228;
  local_238 = DAT_180036004;
  local_240 = DAT_180036000;
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"..\\common\\cmtest.c",
             (undefined *)L"Init_LogOutput_WBDI",0x2d0,0,
             (undefined *)L"created print object: LogLevel %d, LogTarget %d, fullLogPath %s");
  FUN_180018b70(local_18 ^ (ulonglong)&stack0xfffffffffffffd88);
  return;
}



void FUN_1800014f4(longlong param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  longlong lVar1;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 local_res20;
  
  if (DAT_180037cd8 != '\0') {
    lVar1 = -1;
    do {
      lVar1 = lVar1 + 1;
    } while (*(short *)(&DAT_1800378c0 + lVar1 * 2) != 0);
    if (lVar1 != 0) {
      local_res10 = param_2;
      local_res18 = param_3;
      local_res20 = param_4;
      FUN_18000169c((wchar_t *)&DAT_1800378c0,param_1,&local_res10);
    }
  }
  return;
}



void FUN_180001544(longlong param_1)

{
  errno_t eVar1;
  longlong lVar2;
  wchar_t *pwVar3;
  undefined auStack2168 [32];
  uint local_858;
  uint local_850;
  uint local_848;
  longlong local_840;
  FILE *local_838;
  _SYSTEMTIME local_830;
  wchar_t local_818 [1024];
  ulonglong local_18;
  
  if (param_1 != 0) {
    local_18 = DAT_180037758 ^ (ulonglong)auStack2168;
    lVar2 = 0x800;
    pwVar3 = local_818;
    while (lVar2 != 0) {
      lVar2 = lVar2 + -1;
      *(undefined *)pwVar3 = 0;
      pwVar3 = (wchar_t *)((longlong)pwVar3 + 1);
    }
    local_838 = (FILE *)0x0;
    GetLocalTime((LPSYSTEMTIME)&local_830);
    local_848 = (uint)local_830.wMilliseconds;
    local_850 = (uint)local_830.wSecond;
    local_858 = (uint)local_830.wMinute;
    local_840 = param_1;
    FID_conflict__sprintf_p
              (local_818,0x3ff,L"%02d:%02d:%02d.%03d [%s]\n",(ulonglong)local_830.wHour);
    eVar1 = _wfopen_s(&local_838,(wchar_t *)PTR_u_c__fingerprintlog_WbioUXLog_log_180036260,
                      L"at+,ccs=UTF-8");
    if ((eVar1 == 0) && (local_838 != (FILE *)0x0)) {
      lVar2 = -1;
      do {
        lVar2 = lVar2 + 1;
      } while (local_818[lVar2] != L'\0');
      fwrite(local_818,lVar2 * 2,1,local_838);
      fclose(local_838);
    }
    FUN_180018b70(local_18 ^ (ulonglong)auStack2168);
  }
  return;
}



void FUN_180001658(longlong param_1)

{
  ulonglong uVar1;
  
  uVar1 = 0xffffffffffffffff;
  do {
    uVar1 = uVar1 + 1;
  } while (*(short *)(param_1 + uVar1 * 2) != 0);
  if (uVar1 < 0x104) {
    FID_conflict__sprintf_p((wchar_t *)&DAT_1800378c0,0x103,L"%s",param_1);
  }
  return;
}



void FUN_180001694(undefined param_1)

{
  DAT_180037cd8 = param_1;
  return;
}



void FUN_18000169c(wchar_t *param_1,longlong param_2,undefined8 param_3)

{
  longlong lVar1;
  undefined8 *puVar2;
  size_t _Size;
  undefined auStack1256 [32];
  wchar_t *local_4c8;
  undefined8 local_4c0;
  undefined8 local_4b8;
  FILE *local_4a8;
  __time64_t local_4a0;
  tm local_498;
  char local_468 [64];
  char local_428 [512];
  wchar_t local_228 [256];
  ulonglong local_28;
  size_t sVar3;
  
  if (param_2 != 0) {
    local_28 = DAT_180037758 ^ (ulonglong)auStack1256;
    local_4a8 = (FILE *)0x0;
    _wfopen_s(&local_4a8,param_1,L"a+");
    if (local_4a8 != (FILE *)0x0) {
      memset(local_428,0,0x200);
      memset(local_468,0,0x40);
      _time64(&local_4a0);
      _localtime64_s(&local_498,&local_4a0);
      strftime(local_468,0x3f,"%Y/%m/%d %X",&local_498);
      memset(local_228,0,0x200);
      local_4c8 = (wchar_t *)param_2;
      FID_conflict__sprintf_p(local_228,0x1ff,(wchar_t *)"[%s] %s\n",local_468);
      puVar2 = (undefined8 *)FUN_1800017f8();
      local_4c8 = local_228;
      local_4c0 = 0;
      local_4b8 = param_3;
      __stdio_common_vsnprintf_s(*puVar2,local_428,0x1ff,0x1ff);
      sVar3 = 0xffffffffffffffff;
      do {
        _Size = sVar3 + 1;
        lVar1 = sVar3 + 1;
        sVar3 = _Size;
      } while (local_428[lVar1] != '\0');
      fwrite(local_428,_Size,1,local_4a8);
      fclose(local_4a8);
    }
    FUN_180018b70(local_28 ^ (ulonglong)auStack1256);
  }
  return;
}



undefined * FUN_1800017f8(void)

{
  return &DAT_18005b5c0;
}



undefined8 FUN_180001800(int *param_1)

{
  ulonglong uVar1;
  int iVar2;
  _FILETIME local_res8 [4];
  
  if (param_1 != (int *)0x0) {
    GetSystemTimeAsFileTime((LPFILETIME)local_res8);
    uVar1 = ((longlong)local_res8[0] + 0xffd6a169b779c000U) / 10;
    iVar2 = (int)(uVar1 / 1000000);
    *param_1 = iVar2;
    param_1[1] = (int)uVar1 + iVar2 * -1000000;
  }
  return 0;
}



undefined8 FUN_180001870(wchar_t *param_1,void *param_2,ulonglong param_3,wchar_t *param_4)

{
  FILE *local_res10 [3];
  
  if (param_2 != (void *)0x0) {
    local_res10[0] = (FILE *)0x0;
    _wfopen_s(local_res10,param_1,param_4);
    if (local_res10[0] != (FILE *)0x0) {
      fread_s(param_2,param_3 & 0xffffffff,1,param_3 & 0xffffffff,local_res10[0]);
      fclose(local_res10[0]);
      return 0;
    }
  }
  return 0xffffffff;
}



// Library Function - Multiple Matches With Different Base Names
// Name: _snprintf_c, _sprintf_p, _swprintf_c, _swprintf_p, sprintf_s, swprintf, swprintf_s
// Library: Visual Studio 2015 Release

int FID_conflict__sprintf_p(wchar_t *_Dst,size_t _SizeInWords,wchar_t *_Format,...)

{
  int iVar1;
  undefined8 *puVar2;
  undefined8 in_R9;
  undefined8 local_res20;
  
  local_res20 = in_R9;
  puVar2 = (undefined8 *)FUN_1800017f8();
  iVar1 = __stdio_common_vsprintf_s(*puVar2,_Dst,_SizeInWords,_Format,0,&local_res20);
  if (iVar1 < 0) {
    iVar1 = -1;
  }
  return iVar1;
}



// Library Function - Multiple Matches With Different Base Names
// Name: _snprintf_c, _sprintf_p, _swprintf_c, _swprintf_p, sprintf_s, swprintf, swprintf_s
// Library: Visual Studio 2015 Release

int FID_conflict__sprintf_p(wchar_t *_Dst,size_t _SizeInWords,wchar_t *_Format,...)

{
  int iVar1;
  undefined8 *puVar2;
  undefined8 in_R9;
  undefined8 local_res20;
  
  local_res20 = in_R9;
  puVar2 = (undefined8 *)FUN_1800017f8();
  iVar1 = __stdio_common_vswprintf_s(*puVar2,_Dst,_SizeInWords,_Format,0,&local_res20);
  if (iVar1 < 0) {
    iVar1 = -1;
  }
  return iVar1;
}



undefined8 FUN_180001984(wchar_t *param_1,void *param_2,ulonglong param_3,wchar_t *param_4)

{
  FILE *local_res10 [3];
  
  if (param_2 != (void *)0x0) {
    local_res10[0] = (FILE *)0x0;
    _wfopen_s(local_res10,param_1,param_4);
    if (local_res10[0] != (FILE *)0x0) {
      fwrite(param_2,1,param_3 & 0xffffffff,local_res10[0]);
      fclose(local_res10[0]);
      return 0;
    }
  }
  return 0xffffffff;
}



void FUN_1800019e8(wchar_t *param_1)

{
  BOOL BVar1;
  DWORD DVar2;
  short *psVar3;
  undefined auStack584 [32];
  wchar_t local_228;
  short local_226;
  short local_222 [261];
  ulonglong local_18;
  
  local_18 = DAT_180037758 ^ (ulonglong)auStack584;
  memset(&local_228,0,0x208);
  if (((param_1 != (wchar_t *)0x0) && (*param_1 != L'\0')) &&
     (wcscpy_s(&local_228,0x104,param_1), local_226 == 0x3a)) {
    psVar3 = local_222;
    while (local_222[0] != 0) {
      if ((*psVar3 == 0x5c) || (*psVar3 == 0x2f)) {
        *psVar3 = 0;
        BVar1 = CreateDirectoryW(&local_228,(LPSECURITY_ATTRIBUTES)0x0);
        if ((BVar1 == 0) && (DVar2 = GetLastError(), DVar2 != 0xb7)) break;
        *psVar3 = 0x5c;
      }
      psVar3 = psVar3 + 1;
      local_222[0] = *psVar3;
    }
  }
  FUN_180018b70(local_18 ^ (ulonglong)auStack584);
  return;
}



void FUN_180001abc(LPCWSTR param_1,DWORD *param_2,DWORD *param_3)

{
  HANDLE hFindFile;
  undefined auStack392 [32];
  undefined local_168 [336];
  
  local_168._320_8_ = DAT_180037758 ^ (ulonglong)auStack392;
  memset(local_168,0,0x140);
  hFindFile = FindFirstFileW(param_1,(LPWIN32_FIND_DATAW)local_168);
  if ((longlong)hFindFile - 1U < 0xfffffffffffffffe) {
    if ((local_168[0] & 0x10) == 0) {
      *param_2 = local_168._32_4_;
      if (param_3 != (DWORD *)0x0) {
        *param_3 = local_168._28_4_;
      }
      FindClose(hFindFile);
    }
    else {
      FindClose(hFindFile);
    }
  }
  FUN_180018b70(local_168._320_8_ ^ (ulonglong)auStack392);
  return;
}



void FUN_180001b60(void)

{
  if (*(HANDLE *)(PTR_DAT_180036ca8 + 0x348) != (HANDLE)0x0) {
    FlushFileBuffers(*(HANDLE *)(PTR_DAT_180036ca8 + 0x348));
  }
  return;
}



wchar_t * FUN_180001b84(wchar_t *param_1,uint param_2,wchar_t *param_3,uint param_4)

{
  HANDLE hHeap;
  wchar_t *_Dst;
  uint uVar1;
  
  uVar1 = 9;
  if (param_2 < 10) {
    uVar1 = param_2;
  }
  if (((param_4 & 1) == 0) || ((param_3 != (wchar_t *)0x0 && (*param_3 != L'\0')))) {
    hHeap = GetProcessHeap();
    _Dst = (wchar_t *)HeapAlloc(hHeap,8,0x350);
    if (_Dst != (wchar_t *)0x0) {
      if (param_1 != (wchar_t *)0x0) {
        wcscpy_s(_Dst,0x80,param_1);
      }
      *(uint *)(_Dst + 0x80) = uVar1;
      if (param_3 != (wchar_t *)0x0) {
        wcscpy_s(_Dst + 0x82,0x104,param_3);
      }
      *(uint *)(_Dst + 0x186) = param_4;
      InitializeCriticalSection((LPCRITICAL_SECTION)(_Dst + 0x18c));
      *(undefined *)(_Dst + 0x1a0) = 1;
      if ((param_4 & 1) == 0) {
        return _Dst;
      }
      FUN_1800019e8(_Dst + 0x82);
      return _Dst;
    }
  }
  return (wchar_t *)0x0;
}



void FUN_180001c78(undefined *param_1)

{
  HANDLE hHeap;
  
  if (((param_1 != (undefined *)0x0) && (param_1 != &DAT_180036600)) && (param_1 != &DAT_180036950))
  {
    if ((longlong)*(HANDLE *)(param_1 + 0x348) - 1U < 0xfffffffffffffffe) {
      CloseHandle(*(HANDLE *)(param_1 + 0x348));
    }
    param_1[0x340] = 0;
    DeleteCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x318));
    hHeap = GetProcessHeap();
    HeapFree(hHeap,0,param_1);
  }
  return;
}



void debug_print_FUN_180001ce4
               (longlong param_1,uint param_2,undefined *param_3,undefined *param_4,
               undefined4 param_5,uint param_6,undefined *param_7)

{
  uint uVar1;
  LPCWSTR lpOutputString;
  HANDLE hHeap;
  undefined *puVar2;
  undefined4 in_register_00000014;
  ulonglong uVar3;
  undefined *puVar4;
  longlong lVar5;
  undefined *puVar6;
  
  uVar3 = CONCAT44(in_register_00000014,param_2);
  if (param_1 == 0) {
    return;
  }
  if (param_2 == 0) {
    if (param_6 == 0) {
      return;
    }
    uVar1 = param_6 >> 0x1e;
    if (param_6 >> 0x1e == 0) {
      uVar3 = 6;
    }
    else {
      if (uVar1 != 1) {
        if (uVar1 == 2) {
          uVar3 = 5;
          goto LAB_180001d40;
        }
        if (uVar1 == 3) {
          uVar3 = 4;
          goto LAB_180001d40;
        }
      }
      uVar3 = 7;
    }
  }
LAB_180001d40:
  if ((uint)uVar3 < *(uint *)(param_1 + 0x100) || (uint)uVar3 == *(uint *)(param_1 + 0x100)) {
    puVar4 = &DAT_18001d894;
    if (param_3 != (undefined *)0x0) {
      puVar4 = param_3;
    }
    puVar6 = &DAT_18001d894;
    if (param_4 != (undefined *)0x0) {
      puVar6 = param_4;
    }
    puVar2 = &DAT_18001d894;
    if (param_7 != (undefined *)0x0) {
      puVar2 = param_7;
    }
    lpOutputString =
         (LPCWSTR)FUN_180001fdc(param_1,uVar3,(longlong)puVar4,(longlong)puVar6,param_5,puVar2,
                                (ulonglong)&stack0x00000040);
    if (lpOutputString != (LPCWSTR)0x0) {
      if ((*(byte *)(param_1 + 0x30c) & 2) != 0) {
        FUN_18000228c(lpOutputString,uVar3,puVar4,puVar6);
      }
      if ((*(byte *)(param_1 + 0x30c) & 4) != 0) {
        OutputDebugStringW(lpOutputString);
      }
      if ((*(byte *)(param_1 + 0x30c) & 1) != 0) {
        lVar5 = -1;
        do {
          lVar5 = lVar5 + 1;
        } while (lpOutputString[lVar5] != L'\0');
        FUN_180001e10(param_1,lpOutputString,lVar5 * 2);
      }
      hHeap = GetProcessHeap();
      HeapFree(hHeap,0,lpOutputString);
    }
  }
  return;
}



void FUN_180001e10(longlong param_1,LPCVOID param_2,longlong param_3)

{
  LPCWSTR lpExistingFileName;
  int iVar1;
  BOOL BVar2;
  HANDLE pvVar3;
  uint local_258;
  DWORD local_254 [3];
  wchar_t local_248 [264];
  ulonglong local_38;
  
  if (param_1 == 0) {
    return;
  }
  local_38 = DAT_180037758 ^ (ulonglong)&stack0xfffffffffffffd68;
  local_254[0] = 0;
  if ((param_2 == (LPCVOID)0x0) || (param_3 == 0)) goto LAB_180001fbb;
  if (*(char *)(param_1 + 0x340) != '\0') {
    EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x318));
  }
  local_258 = 0;
  memset(local_248,0,0x208);
  lpExistingFileName = (LPCWSTR)(param_1 + 0x104);
  if (((*lpExistingFileName != L'\0') &&
      (iVar1 = FUN_180001abc(lpExistingFileName,&local_258,(DWORD *)0x0), iVar1 != 0)) &&
     (4999999 < local_258)) {
    if ((longlong)*(HANDLE *)(param_1 + 0x348) - 1U < 0xfffffffffffffffe) {
      CloseHandle(*(HANDLE *)(param_1 + 0x348));
      *(undefined8 *)(param_1 + 0x348) = 0;
    }
    FID_conflict__sprintf_p(local_248,0x104,L"%s.bak",lpExistingFileName);
    CopyFileW(lpExistingFileName,local_248,0);
    DeleteFileW(lpExistingFileName);
  }
  if ((*(longlong *)(param_1 + 0x348) + 1U & 0xfffffffffffffffe) == 0) {
    if ((*lpExistingFileName != L'\0') &&
       (pvVar3 = CreateFileW(lpExistingFileName,0x40000000,1,(LPSECURITY_ATTRIBUTES)0x0,4,0,
                             (HANDLE)0x0), (longlong)pvVar3 - 1U < 0xfffffffffffffffe)) {
      *(HANDLE *)(param_1 + 0x348) = pvVar3;
      goto LAB_180001f58;
    }
  }
  else {
LAB_180001f58:
    SetFilePointer(*(HANDLE *)(param_1 + 0x348),0,(PLONG)0x0,2);
    BVar2 = WriteFile(*(HANDLE *)(param_1 + 0x348),param_2,(DWORD)param_3,local_254,
                      (LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      CloseHandle(*(HANDLE *)(param_1 + 0x348));
      *(undefined8 *)(param_1 + 0x348) = 0;
    }
  }
  if (*(char *)(param_1 + 0x340) != '\0') {
    LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x318));
  }
LAB_180001fbb:
  FUN_180018b70(local_38 ^ (ulonglong)&stack0xfffffffffffffd68);
  return;
}



void FUN_180001fdc(longlong param_1,ulonglong param_2,longlong param_3,longlong param_4,
                  undefined4 param_5,undefined8 param_6,ulonglong param_7)

{
  size_t _SizeInWords;
  int iVar1;
  int iVar2;
  ulonglong *puVar3;
  ulonglong uVar4;
  HANDLE pvVar5;
  wchar_t *_Dst;
  longlong lVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  undefined auStack248 [32];
  ulonglong local_d8;
  ulonglong local_d0;
  uint local_c8;
  uint local_c0;
  uint local_b8;
  DWORD local_b0;
  DWORD local_a8;
  longlong local_a0;
  undefined *local_98;
  longlong local_90;
  undefined4 local_88;
  ulonglong local_78;
  undefined8 local_70;
  longlong local_68;
  _SYSTEMTIME local_60;
  ulonglong local_50;
  
  local_50 = DAT_180037758 ^ (ulonglong)auStack248;
  local_70 = param_6;
  iVar2 = 0;
  local_78 = param_7;
  local_68 = param_3;
  GetLocalTime((LPSYSTEMTIME)&local_60);
  uVar8 = 0xffffffffffffffff;
  do {
    uVar8 = uVar8 + 1;
  } while (*(short *)(param_1 + uVar8 * 2) != 0);
  uVar9 = 0xffffffffffffffff;
  do {
    uVar9 = uVar9 + 1;
  } while (*(short *)((&PTR_DAT_180036cc0)[param_2 & 0xffffffff] + uVar9 * 2) != 0);
  uVar7 = 0xffffffffffffffff;
  do {
    uVar7 = uVar7 + 1;
  } while (*(short *)(param_4 + uVar7 * 2) != 0);
  puVar3 = (ulonglong *)FUN_1800017f8();
  local_d0 = local_78;
  local_d8 = 0;
  iVar1 = __stdio_common_vswprintf(*puVar3 | 2,0);
  lVar6 = -1;
  do {
    lVar6 = lVar6 + 1;
  } while (*(short *)(local_68 + lVar6 * 2) != 0);
  if (iVar1 < 0) {
    iVar1 = -1;
  }
  uVar4 = 0x24;
  if (0x24 < uVar7) {
    uVar4 = uVar7;
  }
  uVar7 = 5;
  if (5 < uVar9) {
    uVar7 = uVar9;
  }
  uVar9 = 8;
  if (8 < uVar8) {
    uVar9 = uVar8;
  }
  lVar6 = uVar9 + lVar6 + iVar1 + uVar4 + uVar7;
  _SizeInWords = lVar6 + 0x81;
  pvVar5 = GetProcessHeap();
  _Dst = (wchar_t *)HeapAlloc(pvVar5,8,lVar6 * 2 + 0x102);
  if ((*(uint *)(param_1 + 0x30c) & 0x1000) == 0) {
    local_a8 = GetCurrentThreadId();
    local_b0 = GetCurrentProcessId();
    local_88 = param_5;
    local_98 = (&PTR_DAT_180036cc0)[param_2 & 0xffffffff];
    local_b8 = (uint)local_60.wMilliseconds;
    local_c0 = (uint)local_60.wSecond;
    local_c8 = (uint)local_60.wMinute;
    local_d0 = local_d0 & 0xffffffff00000000 | (ulonglong)local_60.wHour;
    local_d8 = local_d8 & 0xffffffff00000000 | (ulonglong)local_60.wDay;
    local_a0 = param_1;
    local_90 = param_4;
    iVar2 = FID_conflict__sprintf_p
                      (_Dst,_SizeInWords,
                                              
                       L"[%02d%02d-%02d:%02d:%02d:%03d][PID:%6d][TID:%6d][%8s][%5s][%36s:%4d] Goodix>> "
                       ,(ulonglong)local_60.wMonth);
    if (0 < iVar2) goto LAB_1800021fd;
  }
  else {
LAB_1800021fd:
    local_d0 = local_78;
    local_d8 = 0;
    iVar1 = __stdio_common_vswprintf_s(*puVar3,_Dst + iVar2,_SizeInWords - (longlong)iVar2,local_70)
    ;
    if (iVar1 < 0) {
      iVar1 = -1;
    }
    if (-1 < iVar1) {
      iVar2 = iVar2 + iVar1;
      if ((_Dst[iVar2 + -1] != L'\n') && (iVar2 + 1 < (int)_SizeInWords)) {
        _Dst[iVar2] = L'\n';
        _Dst[iVar2 + 1] = L'\0';
      }
      goto LAB_180002267;
    }
  }
  if (_Dst != (wchar_t *)0x0) {
    pvVar5 = GetProcessHeap();
    HeapFree(pvVar5,0,_Dst);
  }
LAB_180002267:
  FUN_180018b70(local_50 ^ (ulonglong)auStack248);
  return;
}



void FUN_18000228c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  undefined8 uVar1;
  undefined8 *puVar2;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 local_res20;
  
  local_res10 = param_2;
  local_res18 = param_3;
  local_res20 = param_4;
  uVar1 = __acrt_iob_func(1);
  puVar2 = (undefined8 *)FUN_1800017f8();
  __stdio_common_vfwprintf(*puVar2,uVar1,param_1,0,&local_res10);
  return;
}



void FUN_1800022e0(undefined8 *param_1,ulonglong param_2)

{
  ushort uVar1;
  
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_180037ef0);
  uVar1 = DAT_180037f80;
  memcpy_FUN_180019c80
            (*(undefined8 **)((longlong)&DAT_180037f20 + (ulonglong)DAT_180037f80 * 8),param_1,
             param_2 & 0xffff);
  DAT_180037f80 = uVar1 + 1;
  if (0xb < DAT_180037f80) {
    DAT_180037f80 = 0;
  }
                    // WARNING: Could not recover jumptable at 0x000180002344. Too many branches
                    // WARNING: Treating indirect jump as call
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_180037ef0);
  return;
}



void FUN_18000234c(ushort param_1)

{
  void **ppvVar1;
  longlong lVar2;
  
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_180037ef0);
  ppvVar1 = (void **)&DAT_180037f20;
  lVar2 = 0xc;
  do {
    memset(*ppvVar1,0,(ulonglong)param_1);
    ppvVar1 = ppvVar1 + 1;
    lVar2 = lVar2 + -1;
  } while (lVar2 != 0);
  DAT_180037f80 = 0;
  DAT_180037f18 = 0;
                    // WARNING: Could not recover jumptable at 0x0001800023b4. Too many branches
                    // WARNING: Treating indirect jump as call
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_180037ef0);
  return;
}



void FUN_1800023bc(void)

{
  void **ppvVar1;
  longlong lVar2;
  
  DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_180037ef0);
  ppvVar1 = (void **)&DAT_180037f20;
  lVar2 = 0xc;
  do {
    if (*ppvVar1 != (void *)0x0) {
      free(*ppvVar1);
      *ppvVar1 = (void *)0x0;
    }
    ppvVar1 = ppvVar1 + 1;
    lVar2 = lVar2 + -1;
  } while (lVar2 != 0);
  return;
}



void FUN_180002408(undefined8 *param_1,ulonglong param_2)

{
  ushort uVar1;
  
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_180037ef0);
  uVar1 = DAT_180037f18;
  memcpy_FUN_180019c80
            (param_1,*(undefined8 **)((longlong)&DAT_180037f20 + (ulonglong)DAT_180037f18 * 8),
             param_2 & 0xffff);
  DAT_180037f18 = uVar1 + 1;
  if (0xb < DAT_180037f18) {
    DAT_180037f18 = 0;
  }
                    // WARNING: Could not recover jumptable at 0x00018000246c. Too many branches
                    // WARNING: Treating indirect jump as call
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_180037ef0);
  return;
}



void FUN_180002474(ushort param_1)

{
  void *pvVar1;
  byte bVar2;
  ulonglong uVar3;
  
  InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_180037ef0);
  uVar3 = 0;
  do {
    pvVar1 = malloc((ulonglong)param_1);
    *(void **)((longlong)&DAT_180037f20 + uVar3 * 8) = pvVar1;
    if (pvVar1 == (void *)0x0) {
      return;
    }
    bVar2 = (char)uVar3 + 1;
    uVar3 = (ulonglong)bVar2;
  } while (bVar2 < 0xc);
  FUN_18000234c(param_1);
  return;
}



ulonglong FUN_1800024d4(void)

{
  bool bVar1;
  
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_180037ef0);
  bVar1 = DAT_180037f80 == DAT_180037f18;
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_180037ef0);
  return (ulonglong)bVar1;
}



ulonglong FUN_180002510(undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  ulonglong in_RAX;
  longlong lVar5;
  undefined4 *puVar6;
  short sVar7;
  undefined4 *puVar8;
  
  if (param_1 == (undefined4 *)0x0) {
    return in_RAX & 0xffffffffffffff00;
  }
  puVar8 = (undefined4 *)(&DAT_180036d40 + (longlong)DAT_18005b4a0 * 0x100);
  lVar5 = 2;
  puVar6 = param_1;
  do {
    uVar2 = puVar8[1];
    uVar3 = puVar8[2];
    uVar4 = puVar8[3];
    *puVar6 = *puVar8;
    puVar6[1] = uVar2;
    puVar6[2] = uVar3;
    puVar6[3] = uVar4;
    uVar2 = puVar8[5];
    uVar3 = puVar8[6];
    uVar4 = puVar8[7];
    puVar6[4] = puVar8[4];
    puVar6[5] = uVar2;
    puVar6[6] = uVar3;
    puVar6[7] = uVar4;
    uVar2 = puVar8[9];
    uVar3 = puVar8[10];
    uVar4 = puVar8[0xb];
    puVar6[8] = puVar8[8];
    puVar6[9] = uVar2;
    puVar6[10] = uVar3;
    puVar6[0xb] = uVar4;
    uVar2 = puVar8[0xd];
    uVar3 = puVar8[0xe];
    uVar4 = puVar8[0xf];
    puVar6[0xc] = puVar8[0xc];
    puVar6[0xd] = uVar2;
    puVar6[0xe] = uVar3;
    puVar6[0xf] = uVar4;
    uVar2 = puVar8[0x11];
    uVar3 = puVar8[0x12];
    uVar4 = puVar8[0x13];
    puVar6[0x10] = puVar8[0x10];
    puVar6[0x11] = uVar2;
    puVar6[0x12] = uVar3;
    puVar6[0x13] = uVar4;
    uVar2 = puVar8[0x15];
    uVar3 = puVar8[0x16];
    uVar4 = puVar8[0x17];
    puVar6[0x14] = puVar8[0x14];
    puVar6[0x15] = uVar2;
    puVar6[0x16] = uVar3;
    puVar6[0x17] = uVar4;
    uVar2 = puVar8[0x19];
    uVar3 = puVar8[0x1a];
    uVar4 = puVar8[0x1b];
    puVar6[0x18] = puVar8[0x18];
    puVar6[0x19] = uVar2;
    puVar6[0x1a] = uVar3;
    puVar6[0x1b] = uVar4;
    puVar1 = puVar8 + 0x1c;
    uVar2 = puVar8[0x1d];
    uVar3 = puVar8[0x1e];
    uVar4 = puVar8[0x1f];
    puVar8 = puVar8 + 0x20;
    puVar6[0x1c] = *puVar1;
    puVar6[0x1d] = uVar2;
    puVar6[0x1e] = uVar3;
    puVar6[0x1f] = uVar4;
    lVar5 = lVar5 + -1;
    puVar6 = puVar6 + 0x20;
  } while (lVar5 != 0);
  sVar7 = -0x5a5b;
  lVar5 = 0x7f;
  puVar6 = param_1;
  do {
    sVar7 = sVar7 + *(short *)puVar6;
    puVar6 = (undefined4 *)((longlong)puVar6 + 2);
    lVar5 = lVar5 + -1;
  } while (lVar5 != 0);
  *(char *)((longlong)param_1 + 0xfe) = (char)-sVar7;
  *(char *)((longlong)param_1 + 0xff) = (char)((ushort)-sVar7 >> 8);
  return 1;
}



ulonglong FUN_1800025b8(undefined param_1,ulonglong *param_2)

{
  ulonglong in_RAX;
  ulonglong uVar1;
  ulonglong *puVar2;
  short sVar3;
  int iVar4;
  longlong lVar5;
  ulonglong uVar6;
  
  if (param_2 == (ulonglong *)0x0) {
    uVar1 = in_RAX & 0xffffffffffffff00;
  }
  else {
    uVar1 = *param_2 >> 0x30 & 0xff;
    if ((int)uVar1 != 0) {
      iVar4 = ((uint)(*param_2 >> 0x28) & 0xff) + 2;
      uVar6 = (ulonglong)(((int)uVar1 - 1U >> 2) + 1);
      do {
        uVar1 = 0;
        if ((ushort)((ushort)*(byte *)((ulonglong)(iVar4 - 1) + (longlong)param_2) * 0x100 +
                    (ushort)*(byte *)((ulonglong)(iVar4 - 2) + (longlong)param_2)) == 0x82) {
          uVar1 = (ulonglong)(iVar4 + 1);
          *(undefined *)(uVar1 + (longlong)param_2) = param_1;
        }
        iVar4 = iVar4 + 4;
        uVar6 = uVar6 - 1;
      } while (uVar6 != 0);
    }
    sVar3 = -0x5a5b;
    lVar5 = 0x7f;
    puVar2 = param_2;
    do {
      sVar3 = sVar3 + *(short *)puVar2;
      puVar2 = (ulonglong *)((longlong)puVar2 + 2);
      lVar5 = lVar5 + -1;
    } while (lVar5 != 0);
    uVar1 = CONCAT71((int7)(uVar1 >> 8),1);
    *(char *)((longlong)param_2 + 0xfe) = (char)-sVar3;
    *(char *)((longlong)param_2 + 0xff) = (char)((ushort)-sVar3 >> 8);
  }
  return uVar1;
}



ulonglong FUN_180002668(short param_1,undefined (*param_2) [16],short *param_3)

{
  byte bVar1;
  ulonglong in_RAX;
  ulonglong uVar2;
  undefined (*pauVar3) [16];
  short sVar4;
  uint uVar5;
  longlong lVar7;
  ulonglong uVar8;
  ulonglong uVar6;
  
  if (param_2 == (undefined (*) [16])0x0) {
    uVar2 = in_RAX & 0xffffffffffffff00;
  }
  else {
    bVar1 = SUB161(*param_2 >> 0x50,0);
    uVar2 = 0;
    if (bVar1 != 0) {
      uVar5 = (SUB164(*param_2 >> 0x48,0) & 0xff) + 2;
      uVar8 = (ulonglong)((bVar1 - 1 >> 2) + 1);
      do {
        uVar6 = (ulonglong)uVar5;
        uVar2 = 0;
        if ((ushort)((ushort)(byte)(*param_2)[uVar5 - 1] * 0x100 +
                    (ushort)(byte)(*param_2)[uVar5 - 2]) == 0x5c) {
          if (param_3 != (short *)0x0) {
            *param_3 = (ushort)(byte)(*param_2)[uVar5 + 1] * 0x100 + (ushort)(byte)(*param_2)[uVar6]
            ;
            uVar2 = uVar6;
          }
          if (param_1 != 0) {
            (*param_2)[uVar6] = (char)param_1;
            uVar2 = (ulonglong)(uVar5 + 1);
            (*param_2)[uVar2] = (char)((ushort)param_1 >> 8);
          }
        }
        uVar5 = uVar5 + 4;
        uVar8 = uVar8 - 1;
      } while (uVar8 != 0);
    }
    sVar4 = -0x5a5b;
    lVar7 = 0x7f;
    pauVar3 = param_2;
    do {
      sVar4 = sVar4 + *(short *)*pauVar3;
      pauVar3 = (undefined (*) [16])(*pauVar3 + 2);
      lVar7 = lVar7 + -1;
    } while (lVar7 != 0);
    uVar2 = CONCAT71((int7)(uVar2 >> 8),1);
    param_2[0xf][0xe] = (char)-sVar4;
    param_2[0xf][0xf] = (char)((ushort)-sVar4 >> 8);
  }
  return uVar2;
}



void FUN_180002770(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  longlong lVar5;
  
  uVar2 = 0;
  puVar4 = &DAT_180037f90;
  do {
    uVar3 = uVar2 << 0x18;
    uVar1 = 0;
    lVar5 = 8;
    do {
      if ((int)(uVar1 ^ uVar3) < 0) {
        uVar1 = uVar1 * 2 ^ 0x4c11db7;
      }
      else {
        uVar1 = uVar1 * 2;
      }
      uVar3 = uVar3 * 2;
      lVar5 = lVar5 + -1;
    } while (lVar5 != 0);
    *puVar4 = uVar1;
    uVar2 = uVar2 + 1;
    puVar4 = puVar4 + 1;
  } while (uVar2 < 0x100);
  return;
}



ulonglong FUN_1800027b4(byte *param_1,int param_2)

{
  byte bVar1;
  
  if (param_2 != 0) {
    do {
      bVar1 = *param_1;
      param_1 = param_1 + 1;
      DAT_180037440 =
           *(uint *)((longlong)&DAT_180037f90 +
                    ((ulonglong)(DAT_180037440 >> 0x18) ^ (ulonglong)bVar1) * 4) ^
           DAT_180037440 << 8;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return (ulonglong)DAT_180037440;
}



ulonglong FUN_1800027fc(byte *param_1,char param_2)

{
  byte bVar1;
  ulonglong in_RAX;
  byte bVar2;
  
  bVar2 = 0;
  if (param_2 != '\0') {
    do {
      bVar1 = *param_1;
      param_1 = param_1 + 1;
      in_RAX = (ulonglong)(bVar1 ^ bVar2);
      bVar2 = (&DAT_18001da10)[in_RAX];
      param_2 = param_2 + -1;
    } while (param_2 != '\0');
  }
  return in_RAX & 0xffffffffffffff00 | (ulonglong)(byte)~bVar2;
}



void ActivateDevice_FUN_180002828(longlong param_1,undefined8 param_2,undefined8 param_3)

{
  int iVar1;
  
  if (param_1 == 0) {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0xc,&DAT_18001db20);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"Device.c",(undefined *)L"ActivateDevice"
               ,0x134,0,(undefined *)L"device Null!");
  }
  else {
    iVar1 = (**(code **)(DAT_18005ad20 + 0x7c0))(DAT_18005ad28,param_1,1,0,0x138,"Device.c");
    if (iVar1 != 0) {
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0xd,&DAT_18001db20);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"Device.c",
                 (undefined *)L"ActivateDevice",0x13c,0,(undefined *)L"WdfDeviceStopIdle failed!");
    }
    (**(code **)(DAT_18005ad20 + 0x7c8))(DAT_18005ad28,param_1,0,0x141,"Device.c");
  }
  return;
}



void FUN_180002964(undefined4 *param_1)

{
  *param_1 = 0x30;
  param_1[1] = 0x20;
  param_1[2] = 0x16220;
  *(undefined8 *)(param_1 + 5) = 0;
  param_1[7] = 0;
  *(undefined8 *)(param_1 + 3) = 0x50;
  param_1[8] = 0x111107c0;
  *(undefined *)(param_1 + 9) = 0x20;
  param_1[10] = 8;
  *(undefined2 *)(param_1 + 0xb) = 0x9fff;
  *(undefined *)((longlong)param_1 + 0x2e) = 0xfe;
  param_1[0x12] = 0x401001b;
  *(undefined8 *)(param_1 + 0x14) = 0x38;
  param_1[0x16] = 0x46495200;
  param_1[0x17] = 0x30313000;
  param_1[0x18] = 0x401001b;
  *(short *)(param_1 + 0x19) = (short)DAT_18005b4a0;
  *(undefined2 *)(param_1 + 0x1a) = *(undefined2 *)(&DAT_1800376a0 + (longlong)DAT_18005b4a0 * 0xe);
  *(undefined2 *)(param_1 + 0x1b) = *(undefined2 *)(&DAT_1800376a0 + (longlong)DAT_18005b4a0 * 0xe);
  *(undefined2 *)((longlong)param_1 + 0x6a) =
       *(undefined2 *)(&DAT_1800376a2 + (longlong)DAT_18005b4a0 * 0xe);
  *(undefined2 *)((longlong)param_1 + 0x6e) =
       *(undefined2 *)(&DAT_1800376a2 + (longlong)DAT_18005b4a0 * 0xe);
  *(undefined2 *)(param_1 + 0x1c) = 0x101;
  *(undefined *)((longlong)param_1 + 0x72) = 0x10;
  param_1[0x1e] = 0x161f8;
  *(undefined2 *)(param_1 + 0x1f) = *(undefined2 *)(&DAT_1800376a0 + (longlong)DAT_18005b4a0 * 0xe);
  *(undefined2 *)((longlong)param_1 + 0x7e) =
       *(undefined2 *)(&DAT_1800376a2 + (longlong)DAT_18005b4a0 * 0xe);
  *(undefined2 *)((longlong)param_1 + 0x81) = 0x101;
  *(undefined *)((longlong)param_1 + 0x83) = 0xfe;
  *(undefined *)((longlong)param_1 + 0x85) = 0;
  return;
}



void FUN_180002f54(longlong param_1,undefined8 *param_2,undefined8 *param_3,undefined param_4)

{
  ushort uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  longlong lVar9;
  wchar_t *pwVar10;
  
  uVar1 = *(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe);
  DAT_180038418._0_1_ = param_4;
  memcpy_FUN_180019c80((undefined8 *)((longlong)&DAT_180038418 + 1),param_3,(ulonglong)(uint)uVar1);
  memcpy_FUN_180019c80((undefined8 *)&DAT_18003fa10,param_2,(ulonglong)(uint)uVar1);
  if ((*(longlong *)(param_1 + 0x138) != 0) && (*(longlong *)(param_1 + 0x140) != 0)) {
    FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x3f,&DAT_18001db20,param_4);
    pwVar10 = L"CaptureFramedoneForTest";
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"Device.c",
               (undefined *)L"CaptureFramedoneForTest",0x78b,0,
               (undefined *)L"Capture fingerprint entry needupdate:%d");
    lVar9 = 0x2c4;
    **(undefined4 **)(param_1 + 0x140) = 0x16288;
    *(undefined4 *)(*(longlong *)(param_1 + 0x140) + 8) = 1;
    *(undefined4 *)(*(longlong *)(param_1 + 0x140) + 4) = 0;
    *(undefined4 *)(*(longlong *)(param_1 + 0x140) + 0x10) = 0x16270;
    *(undefined4 *)(*(longlong *)(param_1 + 0x140) + 0xc) = 0;
    puVar5 = (undefined4 *)(*(longlong *)(param_1 + 0x140) + 0x14);
    puVar6 = &DAT_180038390;
    do {
      puVar8 = puVar6;
      puVar7 = puVar5;
      uVar2 = puVar8[1];
      uVar3 = puVar8[2];
      uVar4 = puVar8[3];
      *puVar7 = *puVar8;
      puVar7[1] = uVar2;
      puVar7[2] = uVar3;
      puVar7[3] = uVar4;
      uVar2 = puVar8[5];
      uVar3 = puVar8[6];
      uVar4 = puVar8[7];
      puVar7[4] = puVar8[4];
      puVar7[5] = uVar2;
      puVar7[6] = uVar3;
      puVar7[7] = uVar4;
      uVar2 = puVar8[9];
      uVar3 = puVar8[10];
      uVar4 = puVar8[0xb];
      puVar7[8] = puVar8[8];
      puVar7[9] = uVar2;
      puVar7[10] = uVar3;
      puVar7[0xb] = uVar4;
      uVar2 = puVar8[0xd];
      uVar3 = puVar8[0xe];
      uVar4 = puVar8[0xf];
      puVar7[0xc] = puVar8[0xc];
      puVar7[0xd] = uVar2;
      puVar7[0xe] = uVar3;
      puVar7[0xf] = uVar4;
      uVar2 = puVar8[0x11];
      uVar3 = puVar8[0x12];
      uVar4 = puVar8[0x13];
      puVar7[0x10] = puVar8[0x10];
      puVar7[0x11] = uVar2;
      puVar7[0x12] = uVar3;
      puVar7[0x13] = uVar4;
      uVar2 = puVar8[0x15];
      uVar3 = puVar8[0x16];
      uVar4 = puVar8[0x17];
      puVar7[0x14] = puVar8[0x14];
      puVar7[0x15] = uVar2;
      puVar7[0x16] = uVar3;
      puVar7[0x17] = uVar4;
      uVar2 = puVar8[0x19];
      uVar3 = puVar8[0x1a];
      uVar4 = puVar8[0x1b];
      puVar7[0x18] = puVar8[0x18];
      puVar7[0x19] = uVar2;
      puVar7[0x1a] = uVar3;
      puVar7[0x1b] = uVar4;
      uVar2 = puVar8[0x1d];
      uVar3 = puVar8[0x1e];
      uVar4 = puVar8[0x1f];
      puVar7[0x1c] = puVar8[0x1c];
      puVar7[0x1d] = uVar2;
      puVar7[0x1e] = uVar3;
      puVar7[0x1f] = uVar4;
      lVar9 = lVar9 + -1;
      puVar5 = puVar7 + 0x20;
      puVar6 = puVar8 + 0x20;
    } while (lVar9 != 0);
    uVar2 = puVar8[0x21];
    uVar3 = puVar8[0x22];
    uVar4 = puVar8[0x23];
    puVar7[0x20] = puVar8[0x20];
    puVar7[0x21] = uVar2;
    puVar7[0x22] = uVar3;
    puVar7[0x23] = uVar4;
    uVar2 = puVar8[0x25];
    uVar3 = puVar8[0x26];
    uVar4 = puVar8[0x27];
    puVar7[0x24] = puVar8[0x24];
    puVar7[0x25] = uVar2;
    puVar7[0x26] = uVar3;
    puVar7[0x27] = uVar4;
    uVar2 = puVar8[0x29];
    uVar3 = puVar8[0x2a];
    uVar4 = puVar8[0x2b];
    puVar7[0x28] = puVar8[0x28];
    puVar7[0x29] = uVar2;
    puVar7[0x2a] = uVar3;
    puVar7[0x2b] = uVar4;
    uVar2 = puVar8[0x2d];
    uVar3 = puVar8[0x2e];
    uVar4 = puVar8[0x2f];
    puVar7[0x2c] = puVar8[0x2c];
    puVar7[0x2d] = uVar2;
    puVar7[0x2e] = uVar3;
    puVar7[0x2f] = uVar4;
    uVar2 = puVar8[0x31];
    uVar3 = puVar8[0x32];
    uVar4 = puVar8[0x33];
    puVar7[0x30] = puVar8[0x30];
    puVar7[0x31] = uVar2;
    puVar7[0x32] = uVar3;
    puVar7[0x33] = uVar4;
    uVar2 = puVar8[0x35];
    uVar3 = puVar8[0x36];
    uVar4 = puVar8[0x37];
    puVar7[0x34] = puVar8[0x34];
    puVar7[0x35] = uVar2;
    puVar7[0x36] = uVar3;
    puVar7[0x37] = uVar4;
    uVar2 = puVar8[0x39];
    uVar3 = puVar8[0x3a];
    uVar4 = puVar8[0x3b];
    puVar7[0x38] = puVar8[0x38];
    puVar7[0x39] = uVar2;
    puVar7[0x3a] = uVar3;
    puVar7[0x3b] = uVar4;
    FUN_1800014f4((longlong)"%s %d ******** CompletePendingRequest for test ********",
                  "CaptureFramedoneForTest",0x798,pwVar10);
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x40,&DAT_18001db20);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"Device.c",
               (undefined *)L"CaptureFramedoneForTest",0x79a,0,
               (undefined *)L"******** CompletePendingRequest for test ********");
    FUN_18000320c(param_1,0,**(uint **)(param_1 + 0x140));
    *(undefined *)(param_1 + 0x40) = 0;
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x41,&DAT_18001db20);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"Device.c",
               (undefined *)L"CaptureFramedoneForTest",0x7a4,0,
               (undefined *)L"Capture fingerprint done");
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_18000320c(longlong param_1,uint param_2,uint param_3)

{
  int iVar1;
  
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"Device.c",
             (undefined *)L"CompletePendingRequest",0x99c,0,(undefined *)L"Entry");
  if (param_1 != 0) {
    FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x69,&DAT_18001db20,(char)param_1);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"Device.c",
               (undefined *)L"CompletePendingRequest",0x9a8,0,(undefined *)L"deviceContext 0x%x");
    EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x110));
    if (*(longlong *)(param_1 + 0x138) != 0) {
      iVar1 = (**(code **)(DAT_18005ad20 + 0x4e0))(DAT_18005ad28);
      if (iVar1 != -0x3ffffee0) {
        FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x6a,&DAT_18001db20,
                      (char)param_2,(char)param_3);
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"Device.c",
                   (undefined *)L"CompletePendingRequest",0x9bb,0,
                   (undefined *)L"WdfRequestCompleteWithInformation status=0x%x, information=%u");
        (**(code **)(DAT_18005ad20 + 0x520))
                  (DAT_18005ad28,*(undefined8 *)(param_1 + 0x138),param_2,param_3);
        *(undefined8 *)(param_1 + 0x138) = 0;
        _DAT_18004ead8 = 0;
      }
    }
    LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x110));
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"Device.c",
               (undefined *)L"CompletePendingRequest",0x9c3,0,(undefined *)L"Exit");
  }
  return;
}



void EvtUsbReadPipeReadComplete_FUN_18000349c
               (undefined8 param_1,undefined8 param_2,longlong param_3,longlong param_4)

{
  char *pcVar1;
  ushort uVar2;
  undefined local_res20 [8];
  
  if (param_4 == 0) {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0x17,&DAT_18001db20);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"Device.c",
               (undefined *)L"EvtUsbReadPipeReadComplete",0x2c0,0,
               (undefined *)L"Device Context NULL");
  }
  else {
    if (param_3 != 0) {
      EnterCriticalSection((LPCRITICAL_SECTION)(param_4 + 0xe0));
      pcVar1 = (char *)(**(code **)(DAT_18005ad20 + 0x3b8))(DAT_18005ad28,param_2,local_res20);
      if ((pcVar1 != (char *)0x0) && (*pcVar1 != '\0')) {
        uVar2 = 0;
        do {
          if (*pcVar1 != '\0') {
            data_from_device_FUN_1800127e8((byte *)(pcVar1 + uVar2));
          }
          uVar2 = uVar2 + 0x40;
        } while (uVar2 < 0x8000);
      }
      LeaveCriticalSection((LPCRITICAL_SECTION)(param_4 + 0xe0));
    }
  }
  return;
}



void FUN_18000359c(undefined8 param_1,undefined8 *param_2,undefined8 param_3,undefined8 *param_4,
                  undefined8 param_5)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 local_18 [2];
  
  iVar1 = (**(code **)(DAT_18005ad20 + 0x530))(DAT_18005ad28,param_1,local_18);
  if (-1 < iVar1) {
    uVar2 = (**(code **)(DAT_18005ad20 + 0x3b8))(DAT_18005ad28,local_18[0],param_3);
    *param_2 = uVar2;
  }
  iVar1 = (**(code **)(DAT_18005ad20 + 0x538))(DAT_18005ad28,param_1,local_18);
  if (-1 < iVar1) {
    uVar2 = (**(code **)(DAT_18005ad20 + 0x3b8))(DAT_18005ad28,local_18[0],param_5);
    *param_4 = uVar2;
  }
  return;
}



void OnActivate_FUN_180003654(undefined8 param_1)

{
  undefined8 uVar1;
  longlong lVar2;
  char *local_res10;
  undefined8 local_res18;
  undefined local_res20 [8];
  undefined8 local_18 [2];
  
  local_res10 = (char *)0x0;
  local_res18 = 0;
  FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x77,&DAT_18001db20);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",(undefined *)L"OnActivate",0xb27
             ,0,(undefined *)L"Entry");
  uVar1 = (**(code **)(DAT_18005ad20 + 0x578))(DAT_18005ad28,param_1);
  lVar2 = (**(code **)(DAT_18005ad20 + 0x2d0))(DAT_18005ad28,uVar1);
  if (((lVar2 == 0) ||
      (lVar2 = (**(code **)(DAT_18005ad20 + 0x3d8))(DAT_18005ad28,lVar2,PTR_DAT_180036d28),
      lVar2 == 0)) ||
     (FUN_18000359c(param_1,&local_res10,&local_res18,local_18,local_res20),
     local_res10 == (char *)0x0)) {
    (**(code **)(DAT_18005ad20 + 0x518))(DAT_18005ad28,param_1,0xc000000d);
  }
  else {
    if (*local_res10 == '\0') {
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",(undefined *)L"OnActivate",
                 0xb45,0,(undefined *)L"pull high and SetEvent:eventEChandle");
      *(undefined4 *)(lVar2 + 0xdc) = 0;
      SetEvent(*(HANDLE *)(lVar2 + 0xd0));
      *(undefined4 *)(lVar2 + 0xb8) = 1;
    }
    (**(code **)(DAT_18005ad20 + 0x520))(DAT_18005ad28,param_1,0,1);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"Device.c",(undefined *)L"OnActivate",
               0xb4d,0,(undefined *)L"Exit");
  }
  return;
}



void OnCalibrate_FUN_180003838(undefined8 param_1)

{
  undefined4 *puVar1;
  undefined8 uVar2;
  longlong lVar3;
  undefined4 uVar4;
  undefined4 *local_res10;
  undefined8 local_res18;
  ulonglong local_res20;
  undefined8 local_18 [2];
  
  local_res18 = 0;
  local_res10 = (undefined4 *)0x0;
  FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x1f,&DAT_18001db20);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",(undefined *)L"OnCalibrate",
             0x4a7,0,(undefined *)L"Entry");
  uVar2 = (**(code **)(DAT_18005ad20 + 0x578))(DAT_18005ad28,param_1);
  lVar3 = (**(code **)(DAT_18005ad20 + 0x2d0))(DAT_18005ad28,uVar2);
  if ((((lVar3 == 0) ||
       (lVar3 = (**(code **)(DAT_18005ad20 + 0x3d8))(DAT_18005ad28,lVar3,PTR_DAT_180036d28),
       lVar3 == 0)) ||
      (FUN_18000359c(param_1,local_18,&local_res18,&local_res10,&local_res20), puVar1 = local_res10,
      local_res10 == (undefined4 *)0x0)) || (local_res20 < 4)) {
    (**(code **)(DAT_18005ad20 + 0x518))(DAT_18005ad28,param_1,0xc000000d);
  }
  else {
    if (local_res20 < 0x16280) {
      *local_res10 = 0x16280;
      uVar4 = 4;
    }
    else {
      memset(local_res10,0,local_res20);
      *puVar1 = 0x16280;
      puVar1[2] = 0x16270;
      puVar1[1] = 0;
      uVar4 = *puVar1;
    }
    (**(code **)(DAT_18005ad20 + 0x520))(DAT_18005ad28,param_1,0,uVar4);
  }
  return;
}



void OnSetpowerAction_FUN_180006dd0(undefined8 param_1)

{
  undefined8 uVar1;
  longlong lVar2;
  byte *local_res10;
  undefined8 local_res18;
  undefined local_res20 [8];
  undefined8 local_18 [2];
  
  local_res10 = (byte *)0x0;
  local_res18 = 0;
  FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x76,&DAT_18001db20);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",(undefined *)L"OnSetpoweraction"
             ,0xaf1,0,(undefined *)L"Entry");
  uVar1 = (**(code **)(DAT_18005ad20 + 0x578))(DAT_18005ad28,param_1);
  lVar2 = (**(code **)(DAT_18005ad20 + 0x2d0))(DAT_18005ad28,uVar1);
  if (((lVar2 == 0) ||
      (lVar2 = (**(code **)(DAT_18005ad20 + 0x3d8))(DAT_18005ad28,lVar2,PTR_DAT_180036d28),
      lVar2 == 0)) ||
     (FUN_18000359c(param_1,&local_res10,&local_res18,local_18,local_res20),
     local_res10 == (byte *)0x0)) {
    (**(code **)(DAT_18005ad20 + 0x518))(DAT_18005ad28,param_1,0xc000000d);
  }
  else {
    if (*local_res10 < 8) {
      *local_res10 = 8;
      (**(code **)(DAT_18005ad20 + 0x520))(DAT_18005ad28,param_1,0,1);
    }
    else {
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"Device.c",
                 (undefined *)L"OnSetpoweraction",0xb13,0,(undefined *)L"PowerEventType:0x%x");
      (**(code **)(DAT_18005ad20 + 0x520))(DAT_18005ad28,param_1,0,8);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"Device.c",
                 (undefined *)L"OnSetpoweraction",0xb16,0,(undefined *)L"Exit");
    }
  }
  return;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180006fb8(undefined8 param_1)

{
  byte bVar1;
  char cVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  undefined8 uVar5;
  ulonglong uVar6;
  byte bVar7;
  byte bVar8;
  undefined4 local_80;
  byte local_77;
  undefined8 *local_70;
  undefined4 local_68;
  undefined4 local_64;
  byte local_60;
  undefined8 *local_58;
  undefined8 local_48;
  undefined8 local_40;
  undefined4 local_38;
  ulonglong local_30;
  
  local_30 = DAT_180037758 ^ (ulonglong)&stack0xffffffffffffff48;
  puVar3 = (undefined8 *)
           (**(code **)(DAT_18005ad20 + 0x3d8))(DAT_18005ad28,param_1,PTR_DAT_180036d28);
  bVar1 = (**(code **)(DAT_18005ad20 + 0x690))();
  uVar6 = (ulonglong)bVar1;
  local_77 = bVar1;
  puVar4 = (undefined8 *)malloc(uVar6 << 4);
  local_70 = puVar4;
  if (puVar4 != (undefined8 *)0x0) {
    bVar8 = 0;
    if (bVar1 != 0) {
      do {
        uVar5 = (**(code **)(DAT_18005ad20 + 0x760))(DAT_18005ad28,*puVar3);
        *puVar4 = uVar5;
        *(undefined *)(puVar4 + 1) = 0;
        bVar1 = (**(code **)(DAT_18005ad20 + 0x770))(DAT_18005ad28);
        bVar7 = 0;
        if (bVar1 != 0) {
          do {
            local_40 = 0;
            local_38 = 0;
            local_48 = 0x14;
            uVar5 = (**(code **)(DAT_18005ad20 + 0x778))();
            FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,10,&DAT_18001db20,
                          (char)((ulonglong)local_40 >> 0x20));
            local_80 = local_40._4_4_;
            debug_print_FUN_180001ce4
                      ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"Device.c",
                       (undefined *)L"SelectInterfaces",0xce,0,(undefined *)L"PipeType:0x%x");
            (**(code **)(DAT_18005ad20 + 0x6e0))(DAT_18005ad28);
            if (local_40._4_4_ == 4) {
              puVar3[4] = uVar5;
            }
            if (local_40._4_4_ == 3) {
              cVar2 = (**(code **)(DAT_18005ad20 + 0x6c8))(DAT_18005ad28);
              if (cVar2 != '\0') {
                puVar3[2] = uVar5;
              }
              if ((local_40._4_4_ == 3) &&
                 (cVar2 = (**(code **)(DAT_18005ad20 + 0x6d0))(DAT_18005ad28), cVar2 != '\0')) {
                puVar3[3] = uVar5;
              }
            }
            bVar7 = bVar7 + 1;
          } while (bVar7 < bVar1);
          uVar6 = (ulonglong)local_77;
        }
        bVar8 = bVar8 + 1;
        puVar4 = puVar4 + 2;
        bVar1 = (byte)uVar6;
      } while (bVar8 < bVar1);
    }
    puVar4 = local_70;
    memset(&local_68,0,0x20);
    local_68 = 0x20;
    if (bVar1 == 0) {
      local_64 = 3;
    }
    else {
      local_64 = 4;
      local_60 = bVar1;
      local_58 = puVar4;
    }
    (**(code **)(DAT_18005ad20 + 0x698))(DAT_18005ad28,*puVar3,0,&local_68);
    if (((puVar3[3] == 0) || (puVar3[2] == 0)) || (puVar3[4] == 0)) {
      FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0xb,&DAT_18001db20,0x84);
      local_80 = 0xc0000184;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"Device.c",
                 (undefined *)L"SelectInterfaces",0xff,0,(undefined *)L"Exit, status:0x%x");
    }
    else {
      free(puVar4);
    }
  }
  FUN_180018b70(local_30 ^ (ulonglong)&stack0xffffffffffffff48);
  return;
}



undefined8 FUN_1800072f4(longlong param_1)

{
  longlong lVar1;
  LPBYTE local_res8;
  undefined4 uVar2;
  wchar_t *pwVar3;
  
  local_res8 = (LPBYTE)0x0;
  if (param_1 == 0) {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x78,&DAT_18001db20);
    pwVar3 = L"NULL Device";
    uVar2 = 0xb58;
  }
  else {
    lVar1 = (**(code **)(DAT_18005ad20 + 0x3d8))(DAT_18005ad28);
    if (lVar1 != 0) {
      FUN_18000114c(-0x7ffffffe,L"Software\\Goodix\\FP\\parameter\\",L"RemoteWakeup",(DWORD *)0x0,
                    &local_res8,(uint *)0x0);
      if (local_res8 == (LPBYTE)0x0) {
        return 0;
      }
      *(BYTE *)(lVar1 + 0x5fc) = *local_res8;
      DAT_180037690 = *local_res8;
      free(local_res8);
      local_res8 = (LPBYTE)0x0;
      FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x7a,&DAT_18001db20,
                    *(undefined *)(lVar1 + 0x5fc));
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",
                 (undefined *)L"WBDIGetRegister",0xb6f,0,
                 (undefined *)L"Get WBDI register value: bRemoteWakeup:%d ");
      return 0;
    }
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x79,&DAT_18001db20);
    pwVar3 = L"NULL deviceContext";
    uVar2 = 0xb5f;
  }
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",(undefined *)L"WBDIGetRegister",
             uVar2,0,(undefined *)pwVar3);
  return 0x80004003;
}



void FUN_1800074b8(undefined8 param_1,byte param_2,uint param_3,ushort param_4,undefined8 param_5)

{
  longlong lVar1;
  ulonglong in_stack_ffffffffffffffe8;
  
  if (((*(uint *)(PTR_LOOP_180037650 +
                 ((ulonglong)(param_3 - 1 >> 5 & 0x7ff) + (ulonglong)(param_3 >> 0x10) * 0xe) * 4 +
                 0x1c) >> (param_3 - 1 & 0x1f) & 1) != 0) &&
     (lVar1 = (ulonglong)(param_3 >> 0x10) * 0x38, param_2 <= (byte)PTR_LOOP_180037650[lVar1 + 0x19]
     )) {
    in_stack_ffffffffffffffe8 = 0;
    TraceMessage(*(undefined8 *)(PTR_LOOP_180037650 + lVar1 + 0x10),0x2b,param_5,param_4,0);
  }
  WppAutoLogTrace(param_1,param_2,param_3,param_5,
                  in_stack_ffffffffffffffe8 & 0xffffffffffff0000 | (ulonglong)param_4,0);
  return;
}



void FUN_18000756c(undefined8 param_1,byte param_2,ulonglong param_3,ushort param_4,
                  undefined8 param_5,undefined param_6,undefined param_7)

{
  longlong lVar1;
  ulonglong uVar2;
  uint uVar3;
  undefined1 *in_stack_ffffffffffffffb8;
  
  uVar2 = (param_3 & 0xffffffff) >> 0x10;
  uVar3 = (int)(param_3 & 0xffffffff) - 1;
  if (((*(uint *)(PTR_LOOP_180037650 + ((ulonglong)(uVar3 >> 5 & 0x7ff) + uVar2 * 0xe) * 4 + 0x1c)
        >> (uVar3 & 0x1f) & 1) != 0) &&
     (lVar1 = uVar2 * 0x38, param_2 <= (byte)PTR_LOOP_180037650[lVar1 + 0x19])) {
    in_stack_ffffffffffffffb8 = &param_6;
    TraceMessage(*(undefined8 *)(PTR_LOOP_180037650 + lVar1 + 0x10),0x2b,param_5,param_4,
                 in_stack_ffffffffffffffb8,4,&param_7,4,0);
  }
  WppAutoLogTrace(param_1,param_2,param_3 & 0xffffffff,param_5,
                  (ulonglong)in_stack_ffffffffffffffb8 & 0xffffffffffff0000 | (ulonglong)param_4,
                  &param_6,4,&param_7,4,0);
  return;
}



void FUN_180007680(undefined8 param_1,byte param_2,uint param_3,ushort param_4,undefined8 param_5,
                  undefined param_6)

{
  longlong lVar1;
  undefined *in_stack_ffffffffffffffd8;
  
  if (((*(uint *)(PTR_LOOP_180037650 +
                 ((ulonglong)(param_3 - 1 >> 5 & 0x7ff) + (ulonglong)(param_3 >> 0x10) * 0xe) * 4 +
                 0x1c) >> (param_3 - 1 & 0x1f) & 1) != 0) &&
     (lVar1 = (ulonglong)(param_3 >> 0x10) * 0x38, param_2 <= (byte)PTR_LOOP_180037650[lVar1 + 0x19]
     )) {
    in_stack_ffffffffffffffd8 = &param_6;
    TraceMessage(*(undefined8 *)(PTR_LOOP_180037650 + lVar1 + 0x10),0x2b,param_5,param_4,
                 in_stack_ffffffffffffffd8,4,0);
  }
  WppAutoLogTrace(param_1,param_2,param_3,param_5,
                  (ulonglong)in_stack_ffffffffffffffd8 & 0xffffffffffff0000 | (ulonglong)param_4,
                  &param_6,4,0);
  return;
}



void FUN_18000775c(undefined8 param_1,byte param_2,ulonglong param_3,ushort param_4,
                  undefined8 param_5,undefined param_6,undefined param_7,undefined param_8,
                  undefined param_9)

{
  longlong lVar1;
  ulonglong uVar2;
  uint uVar3;
  undefined1 *in_stack_ffffffffffffff98;
  
  uVar2 = (param_3 & 0xffffffff) >> 0x10;
  uVar3 = (int)(param_3 & 0xffffffff) - 1;
  if (((*(uint *)(PTR_LOOP_180037650 + ((ulonglong)(uVar3 >> 5 & 0x7ff) + uVar2 * 0xe) * 4 + 0x1c)
        >> (uVar3 & 0x1f) & 1) != 0) &&
     (lVar1 = uVar2 * 0x38, param_2 <= (byte)PTR_LOOP_180037650[lVar1 + 0x19])) {
    in_stack_ffffffffffffff98 = &param_6;
    TraceMessage(*(undefined8 *)(PTR_LOOP_180037650 + lVar1 + 0x10),0x2b,param_5,param_4,
                 in_stack_ffffffffffffff98,4,&param_7,4,&param_8,4,&param_9,4,0);
  }
  WppAutoLogTrace(param_1,param_2,param_3 & 0xffffffff,param_5,
                  (ulonglong)in_stack_ffffffffffffff98 & 0xffffffffffff0000 | (ulonglong)param_4,
                  &param_6,4,&param_7,4,&param_8,4,&param_9,4,0);
  return;
}



void FUN_1800078b8(undefined8 param_1,byte param_2,ulonglong param_3,ushort param_4,
                  undefined8 param_5,undefined param_6,undefined param_7)

{
  longlong lVar1;
  ulonglong uVar2;
  uint uVar3;
  undefined1 *in_stack_ffffffffffffffc8;
  
  uVar2 = (param_3 & 0xffffffff) >> 0x10;
  uVar3 = (int)(param_3 & 0xffffffff) - 1;
  if (((*(uint *)(PTR_LOOP_180037650 + ((ulonglong)(uVar3 >> 5 & 0x7ff) + uVar2 * 0xe) * 4 + 0x1c)
        >> (uVar3 & 0x1f) & 1) != 0) &&
     (lVar1 = uVar2 * 0x38, param_2 <= (byte)PTR_LOOP_180037650[lVar1 + 0x19])) {
    in_stack_ffffffffffffffc8 = &param_6;
    TraceMessage(*(undefined8 *)(PTR_LOOP_180037650 + lVar1 + 0x10),0x2b,param_5,param_4,
                 in_stack_ffffffffffffffc8,8,&param_7,4,0);
  }
  WppAutoLogTrace(param_1,param_2,param_3 & 0xffffffff,param_5,
                  (ulonglong)in_stack_ffffffffffffffc8 & 0xffffffffffff0000 | (ulonglong)param_4,
                  &param_6,8,&param_7,4,0);
  return;
}



void FUN_1800079d8(undefined8 param_1,byte param_2,ulonglong param_3,ushort param_4,
                  undefined8 param_5,undefined *param_6)

{
  longlong lVar1;
  longlong lVar2;
  ulonglong uVar3;
  char *pcVar4;
  longlong lVar5;
  uint uVar6;
  char *in_stack_ffffffffffffffb8;
  
  uVar3 = (param_3 & 0xffffffff) >> 0x10;
  uVar6 = (int)(param_3 & 0xffffffff) - 1;
  if (((*(uint *)(PTR_LOOP_180037650 + ((ulonglong)(uVar6 >> 5 & 0x7ff) + uVar3 * 0xe) * 4 + 0x1c)
        >> (uVar6 & 0x1f) & 1) != 0) &&
     (lVar5 = uVar3 * 0x38, param_2 <= (byte)PTR_LOOP_180037650[lVar5 + 0x19])) {
    if (param_6 == (undefined *)0x0) {
      lVar2 = 5;
    }
    else {
      lVar1 = -1;
      do {
        lVar2 = lVar1;
        lVar1 = lVar2 + 1;
      } while (param_6[lVar1] != '\0');
      lVar2 = lVar2 + 2;
    }
    in_stack_ffffffffffffffb8 = "NULL";
    if (param_6 != (undefined *)0x0) {
      in_stack_ffffffffffffffb8 = param_6;
    }
    TraceMessage(*(undefined8 *)(PTR_LOOP_180037650 + lVar5 + 0x10),0x2b,param_5,param_4,
                 in_stack_ffffffffffffffb8,lVar2,0);
  }
  lVar5 = -1;
  if (param_6 == (undefined *)0x0) {
    lVar2 = 5;
  }
  else {
    do {
      lVar2 = lVar5;
      lVar5 = lVar2 + 1;
    } while (param_6[lVar5] != '\0');
    lVar2 = lVar2 + 2;
  }
  pcVar4 = "NULL";
  if (param_6 != (undefined *)0x0) {
    pcVar4 = param_6;
  }
  WppAutoLogTrace(param_1,param_2,param_3 & 0xffffffff,param_5,
                  (ulonglong)in_stack_ffffffffffffffb8 & 0xffffffffffff0000 | (ulonglong)param_4,
                  pcVar4,lVar2,0);
  return;
}



void Entry_FUN_180007b14(void *param_1)

{
  int iVar1;
  void *_ArgList;
  HANDLE hThread;
  byte bVar2;
  longlong *plVar4;
  undefined4 uVar5;
  wchar_t *pwVar6;
  uint local_e0;
  uint local_d8;
  uint local_d0;
  uint local_c8;
  uint local_c0;
  uint local_b8;
  uint local_b0;
  uint local_a8;
  uint local_a0;
  uint local_98;
  ushort local_88;
  undefined4 local_84;
  undefined4 local_78;
  undefined4 uStack116;
  undefined4 uStack112;
  undefined4 uStack108;
  undefined4 local_68;
  undefined4 uStack100;
  undefined4 uStack96;
  undefined4 uStack92;
  undefined4 local_58;
  undefined4 uStack84;
  undefined4 uStack80;
  undefined4 uStack76;
  undefined4 local_48;
  undefined4 uStack68;
  undefined4 uStack64;
  undefined4 uStack60;
  ulonglong local_38;
  uint uVar3;
  
  local_38 = DAT_180037758 ^ (ulonglong)&stack0xfffffffffffffee8;
  local_88 = 0;
  local_84 = 0;
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",(undefined *)L"deviceInit",0xc97
             ,0,(undefined *)L"Entry");
  if (param_1 == (void *)0x0) {
    pwVar6 = L"device is NULL";
    uVar5 = 0xc99;
  }
  else {
    _ArgList = (void *)(**(code **)(DAT_18005ad20 + 0x3d8))(DAT_18005ad28,param_1,PTR_DAT_180036d28)
    ;
    if (_ArgList != (void *)0x0) {
      if (*(int *)((longlong)_ArgList + 0x3c) != 0) goto LAB_180007f7d;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",(undefined *)L"deviceInit",
                 0xca3,0,(undefined *)L"called device_enable");
      iVar1 = device_enable_FUN_180014424(param_1);
      if (iVar1 == 0) {
        FUN_180013e38();
      }
      else {
        hThread = (HANDLE)_beginthreadex((void *)0x0,0,FUN_180007fec,_ArgList,4,(uint *)0x0);
        *(HANDLE *)((longlong)_ArgList + 200) = hThread;
        if (hThread != (HANDLE)0x0) {
          ResumeThread(hThread);
        }
        device_action_FUN_180012f20(0xf,(longlong *)&local_84,0);
        plVar4 = (longlong *)((longlong)_ArgList + 0x88);
        device_action_FUN_180012f20(7,plVar4,0x20);
        uVar3 = 0;
        do {
          local_d8 = uVar3 + 7;
          local_98 = (uint)*(byte *)((ulonglong)local_d8 + 0x88 + (longlong)_ArgList);
          local_a0 = (uint)*(byte *)((ulonglong)(uVar3 + 6) + 0x88 + (longlong)_ArgList);
          local_a8 = (uint)*(byte *)((ulonglong)(uVar3 + 5) + 0x88 + (longlong)_ArgList);
          local_b0 = (uint)*(byte *)((ulonglong)(uVar3 + 4) + 0x88 + (longlong)_ArgList);
          local_b8 = (uint)*(byte *)((ulonglong)(uVar3 + 3) + 0x88 + (longlong)_ArgList);
          local_c0 = (uint)*(byte *)((ulonglong)(uVar3 + 2) + 0x88 + (longlong)_ArgList);
          local_c8 = (uint)*(byte *)((ulonglong)(uVar3 + 1) + 0x88 + (longlong)_ArgList);
          local_d0 = (uint)*(byte *)plVar4;
          local_e0 = uVar3;
          debug_print_FUN_180001ce4
                    ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"Device.c",
                     (undefined *)L"deviceInit",0xcb1,0,
                     (undefined *)
                                          
                     L"otp[%02d-%02d] from sensor:0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x"
                    );
          bVar2 = (char)uVar3 + 8;
          uVar3 = (uint)bVar2;
          plVar4 = plVar4 + 1;
        } while (bVar2 < 0x20);
        device_action_FUN_180012f20(0xb,(longlong *)((longlong)_ArgList + 0x88),0);
        device_action_FUN_180012f20(0,(longlong *)&local_78,0);
        *(undefined4 *)((longlong)_ArgList + 0x48) = local_78;
        *(undefined4 *)((longlong)_ArgList + 0x4c) = uStack116;
        *(undefined4 *)((longlong)_ArgList + 0x50) = uStack112;
        *(undefined4 *)((longlong)_ArgList + 0x54) = uStack108;
        *(undefined4 *)((longlong)_ArgList + 0x58) = local_68;
        *(undefined4 *)((longlong)_ArgList + 0x5c) = uStack100;
        *(undefined4 *)((longlong)_ArgList + 0x60) = uStack96;
        *(undefined4 *)((longlong)_ArgList + 100) = uStack92;
        *(undefined4 *)((longlong)_ArgList + 0x68) = local_58;
        *(undefined4 *)((longlong)_ArgList + 0x6c) = uStack84;
        *(undefined4 *)((longlong)_ArgList + 0x70) = uStack80;
        *(undefined4 *)((longlong)_ArgList + 0x74) = uStack76;
        *(undefined4 *)((longlong)_ArgList + 0x78) = local_48;
        *(undefined4 *)((longlong)_ArgList + 0x7c) = uStack68;
        *(undefined4 *)((longlong)_ArgList + 0x80) = uStack64;
        *(undefined4 *)((longlong)_ArgList + 0x84) = uStack60;
        local_88 = 0;
        device_action_FUN_180012f20(9,(longlong *)&local_88,0);
        if (*(int *)((longlong)_ArgList + 0x108) == 0xf0) {
          local_e0 = 0x24 / local_88;
          local_d8 = 0x24 % (uint)local_88;
          debug_print_FUN_180001ce4
                    ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",
                     (undefined *)L"deviceInit",0xcbb,0,(undefined *)L"Get spi clk:%d.%d Mhz");
          local_88 = 8;
          device_action_FUN_180012f20(8,(longlong *)&local_88,0);
          local_e0 = 0x24 / local_88;
          local_d8 = 0x24 % (uint)local_88;
          uVar5 = 0xcbf;
LAB_180007f2b:
          debug_print_FUN_180001ce4
                    ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",
                     (undefined *)L"deviceInit",uVar5,0,(undefined *)L"Set spi clk:%d.%d Mhz");
        }
        else {
          if (*(int *)((longlong)_ArgList + 0x108) == 0xf1) {
            local_e0 = 0x30 / local_88;
            local_d8 = 0x30 % (uint)local_88;
            debug_print_FUN_180001ce4
                      ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",
                       (undefined *)L"deviceInit",0xcc2,0,(undefined *)L"Get spi clk:%d.%d Mhz");
            local_88 = 10;
            device_action_FUN_180012f20(8,(longlong *)&local_88,0);
            local_e0 = 0x30 / local_88;
            local_d8 = 0x30 % (uint)local_88;
            uVar5 = 0xcc6;
            goto LAB_180007f2b;
          }
        }
        device_action_FUN_180012f20(0x13,(longlong *)0x0,0);
        local_84 = 1;
        device_action_FUN_180012f20(0xf,(longlong *)&local_84,0);
        *(undefined4 *)((longlong)_ArgList + 0x3c) = 1;
      }
      SetEvent(*(HANDLE *)((longlong)_ArgList + 0xc0));
      goto LAB_180007f7d;
    }
    pwVar6 = L"deviceContext is NULL";
    uVar5 = 0xc9e;
  }
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"Device.c",(undefined *)L"deviceInit",uVar5
             ,0,(undefined *)pwVar6);
LAB_180007f7d:
  DAT_180037658 = 0xffffffffffffffff;
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",(undefined *)L"deviceInit",0xcd6
             ,0,(undefined *)L"Exit");
  FUN_180018b70(local_38 ^ (ulonglong)&stack0xfffffffffffffee8);
  return;
}



undefined8 FUN_180007fec(longlong param_1)

{
  undefined8 uVar1;
  
  if (param_1 == 0) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"Device.c",
               (undefined *)L"device_event_analyze",0xd0d,0,(undefined *)L"Device context NULL");
    uVar1 = 0;
  }
  else {
    *(undefined4 *)(param_1 + 0xd8) = 0;
    do {
      WaitForSingleObject(*(HANDLE *)(param_1 + 0xd0),0xffffffff);
      ResetEvent(*(HANDLE *)(param_1 + 0xd0));
      if ((*(int *)(param_1 + 0xdc) == 0) && (*(int *)(param_1 + 0xb4) == 0)) {
        device_action_FUN_180012f20(0x14,(longlong *)0x0,0);
      }
    } while (*(int *)(param_1 + 0xd8) == 0);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",
               (undefined *)L"device_event_analyze",0xd1b,0,(undefined *)L"Exit");
    uVar1 = 1;
  }
  return uVar1;
}



void FUN_18000838c(longlong param_1)

{
  int iVar1;
  longlong lVar2;
  undefined4 uVar3;
  wchar_t *pwVar4;
  undefined8 local_58;
  undefined4 local_50;
  undefined4 uStack76;
  undefined4 uStack72;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined8 local_30;
  undefined8 uStack40;
  undefined4 local_20;
  ulonglong local_18;
  
  local_18 = DAT_180037758 ^ (ulonglong)&stack0xffffffffffffff68;
  if (param_1 == 0) {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0xf,&DAT_18001db20);
    pwVar4 = L"WdfRequestComplete STATUS_INVALID_PARAMETER for Device NULL";
    uVar3 = 0x1df;
  }
  else {
    lVar2 = (**(code **)(DAT_18005ad20 + 0x3d8))(DAT_18005ad28);
    if (lVar2 != 0) {
      if ((DAT_18004ead0 == '\x01') || (*(char *)(lVar2 + 0x5fc) == '\x01')) {
        memset(&local_40,0,0x24);
        local_3c = 3;
        local_38 = 5;
      }
      else {
        memset(&local_40,0,0x24);
        local_3c = 1;
        local_38 = 4;
      }
      local_20 = 2;
      local_30 = 0x200000002;
      uStack40 = 2;
      local_40 = 0x24;
      local_34 = 5000;
      iVar1 = (**(code **)(DAT_18005ad20 + 0x80))(0x200000002,DAT_18005ad28,param_1,&local_40);
      if ((-1 < iVar1) &&
         (debug_print_FUN_180001ce4
                    ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",
                     (undefined *)L"gfSetPowerPolicy",0x1f5,0,
                     (undefined *)L"bSelectiveSuspend:1(5s)"), *(char *)(lVar2 + 0x5fc) != '\0')) {
        uStack76 = 2;
        uStack72 = 0;
        local_58 = 0x500000014;
        local_50 = 2;
        (**(code **)(DAT_18005ad20 + 0x88))(DAT_18005ad28,param_1,&local_58);
      }
      goto LAB_1800085ae;
    }
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0x10,&DAT_18001db20);
    pwVar4 = L"WdfRequestComplete STATUS_INVALID_PARAMETER for deviceContext NULL";
    uVar3 = 0x1e5;
  }
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"Device.c",(undefined *)L"gfSetPowerPolicy"
             ,uVar3,0,(undefined *)pwVar4);
LAB_1800085ae:
  FUN_180018b70(local_18 ^ (ulonglong)&stack0xffffffffffffff68);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_180008d48(longlong param_1,int param_2)

{
  longlong lVar1;
  uint uVar2;
  uint uVar3;
  bool bVar4;
  undefined4 uVar5;
  wchar_t *pwVar6;
  
  uVar3 = 8;
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"Device.c",
             (undefined *)L"milanFusbEvtDeviceD0Exit",0xc03,0,
             (undefined *)L"--------D0Exit start--------");
  if (param_1 == 0) {
    pwVar6 = L"device is NULL";
    uVar5 = 0xc06;
  }
  else {
    lVar1 = (**(code **)(DAT_18005ad20 + 0x3d8))(DAT_18005ad28,param_1,PTR_DAT_180036d28);
    if (lVar1 != 0) {
      if (*(int *)(lVar1 + 0xb4) == 1) {
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",
                   (undefined *)L"milanFusbEvtDeviceD0Exit",0xc12,0,
                   (undefined *)L"set sleep mode after uninstall driver");
        UsbEcControl_FUN_180011e20(0,0);
      }
      uVar2 = uVar3;
      if (param_2 == 0) {
        uVar5 = 0xc17;
      }
      else {
        if (param_2 == 1) {
          uVar5 = 0xc1a;
        }
        else {
          if (param_2 == 2) {
            uVar5 = 0xc1d;
          }
          else {
            if (param_2 == 3) {
              uVar5 = 0xc20;
            }
            else {
              if (param_2 == 4) {
                uVar5 = 0xc23;
              }
              else {
                if (param_2 == 5) {
                  uVar5 = 0xc26;
                }
                else {
                  if (param_2 == 6) {
                    uVar5 = 0xc29;
                  }
                  else {
                    if (param_2 == 7) {
                      uVar5 = 0xc2c;
                    }
                    else {
                      uVar5 = 0xc2f;
                      uVar2 = 4;
                    }
                  }
                }
              }
            }
          }
        }
      }
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,uVar2,(undefined *)L"Device.c",
                 (undefined *)L"milanFusbEvtDeviceD0Exit",uVar5,0,(undefined *)L"TargetState:%s");
      _DAT_18004eae0 = (**(code **)(DAT_18005ad20 + 0x148))(DAT_18005ad28);
      if (_DAT_18004eae0 == 0) {
        uVar5 = 0xc35;
      }
      else {
        if (_DAT_18004eae0 == 1) {
          uVar5 = 0xc38;
        }
        else {
          if (_DAT_18004eae0 == 2) {
            uVar5 = 0xc3b;
          }
          else {
            if (_DAT_18004eae0 == 3) {
              uVar5 = 0xc3e;
            }
            else {
              if (_DAT_18004eae0 == 4) {
                uVar5 = 0xc41;
              }
              else {
                if (_DAT_18004eae0 == 5) {
                  uVar5 = 0xc44;
                }
                else {
                  if (_DAT_18004eae0 == 6) {
                    uVar5 = 0xc47;
                  }
                  else {
                    if (_DAT_18004eae0 == 7) {
                      uVar5 = 0xc4a;
                    }
                    else {
                      if (_DAT_18004eae0 == 8) {
                        uVar3 = 4;
                        uVar5 = 0xc4d;
                      }
                      else {
                        uVar5 = 0xc50;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,uVar3,(undefined *)L"Device.c",
                 (undefined *)L"milanFusbEvtDeviceD0Exit",uVar5,0,
                 (undefined *)L"System power state:%s");
      if ((DAT_18004ead0 == '\0') && (1 < _DAT_18004eae0)) {
        device_action_FUN_180012f20(0x11,(longlong *)0x0,0);
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",
                   (undefined *)L"milanFusbEvtDeviceD0Exit",0xc5a,0,
                   (undefined *)L"**********pull high**********");
        bVar4 = *(char *)(lVar1 + 0x5fc) != '\0';
        if (bVar4) {
          debug_print_FUN_180001ce4
                    ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",
                     (undefined *)L"milanFusbEvtDeviceD0Exit",0xc5c,0,
                     (undefined *)L"remoteWakeup: set FDT mode(20HZ)");
        }
        UsbEcControl_FUN_180011e20(0,bVar4);
      }
      if (*(longlong *)(lVar1 + 0x10) != 0) {
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"Device.c",
                   (undefined *)L"milanFusbEvtDeviceD0Exit",0xc66,0,(undefined *)L"stop readpipe!!!"
                  );
        (**(code **)(DAT_18005ad20 + 0x358))(DAT_18005ad28,*(undefined8 *)(lVar1 + 0x10),1);
      }
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"Device.c",
                 (undefined *)L"milanFusbEvtDeviceD0Exit",0xc6c,0,
                 (undefined *)L"--------D0Exit end--------");
      FUN_180001b60();
      return 0;
    }
    pwVar6 = L"deviceContext is NULL";
    uVar5 = 0xc0b;
  }
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"Device.c",
             (undefined *)L"milanFusbEvtDeviceD0Exit",uVar5,0,(undefined *)pwVar6);
  return 0xc0000001;
}



void milanFusbEvtDevicePepareHardware_FUN_180009394(longlong param_1)

{
  int iVar1;
  longlong *plVar2;
  undefined4 uVar3;
  wchar_t *pwVar4;
  uint local_b0;
  uint local_a8;
  undefined4 local_98 [2];
  ulonglong local_90;
  undefined local_78;
  code *local_68;
  longlong *local_60;
  undefined *local_58;
  undefined8 local_48;
  undefined8 local_40;
  uint local_38;
  ulonglong local_30;
  
  local_30 = DAT_180037758 ^ (ulonglong)&stack0xffffffffffffff18;
  FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x11,&DAT_18001db20);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",
             (undefined *)L"milanFusbEvtDevicePrepareHardware",0x222,0,(undefined *)L"Entry");
  plVar2 = (longlong *)(**(code **)(DAT_18005ad20 + 0x3d8))(DAT_18005ad28,param_1);
  if ((*plVar2 == 0) && (iVar1 = (**(code **)(DAT_18005ad20 + 0x650))(DAT_18005ad28), iVar1 < 0)) {
    FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0x12,&DAT_18001db20,(char)iVar1);
    pwVar4 = L"WdfUsbTargetDeviceCreate error, status:0x%x";
    uVar3 = 0x23d;
    local_b0 = iVar1;
  }
  else {
    local_40 = 0;
    local_38 = 0;
    local_48 = 0x14;
    iVar1 = (**(code **)(DAT_18005ad20 + 0x660))(DAT_18005ad28);
    if (iVar1 < 0) {
      *(undefined4 *)(plVar2 + 5) = 0;
    }
    else {
      FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x13,&DAT_18001db20,
                    (char)local_38);
      local_b0 = local_38;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"Device.c",
                 (undefined *)L"milanFusbEvtDevicePrepareHardware",0x252,0,
                 (undefined *)L"deviceInfo.Traits:0x%x");
      local_a8 = local_38 & 2;
      *(uint *)(plVar2 + 5) = local_38;
    }
    iVar1 = FUN_180006fb8(param_1);
    if (-1 < iVar1) {
      if (local_a8 != 0) {
        *(undefined *)((longlong)plVar2 + 0x5fc) = 1;
        FUN_1800072f4(param_1);
        local_b0 = (uint)*(byte *)((longlong)plVar2 + 0x5fc);
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"Device.c",
                   (undefined *)L"milanFusbEvtDevicePrepareHardware",0x276,0,
                   (undefined *)L"bRemoteWakeup:%d");
        iVar1 = FUN_18000838c(param_1);
        if (iVar1 < 0) {
          FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0x15,&DAT_18001db20,
                        (char)iVar1);
          pwVar4 = L"gfSetPowerPolicy error, status:0x%x";
          uVar3 = 0x27f;
          local_b0 = iVar1;
          goto LAB_1800094c2;
        }
      }
      memset(local_98,0,0x48);
      local_68 = EvtUsbReadPipeReadComplete_FUN_18000349c;
      local_90 = (ulonglong)*(ushort *)((longlong)plVar2 + 0x2c);
      local_58 = &LAB_18000340c;
      local_98[0] = 0x48;
      local_78 = 1;
      local_60 = plVar2;
      iVar1 = (**(code **)(DAT_18005ad20 + 0x708))(DAT_18005ad28);
      FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x16,&DAT_18001db20,(char)iVar1);
      local_b0 = iVar1;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",
                 (undefined *)L"milanFusbEvtDevicePrepareHardware",0x291,0,
                 (undefined *)L"Exit, status=0x%x");
      goto LAB_180009757;
    }
    FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0x14,&DAT_18001db20,(char)iVar1);
    pwVar4 = L"SelectInterfaces error, status:0x%x";
    uVar3 = 0x26c;
    local_b0 = iVar1;
  }
LAB_1800094c2:
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"Device.c",
             (undefined *)L"milanFusbEvtDevicePrepareHardware",uVar3,0,(undefined *)pwVar4);
LAB_180009757:
  FUN_180018b70(local_30 ^ (ulonglong)&stack0xffffffffffffff18);
  return;
}



undefined8 FUN_180009da0(longlong param_1)

{
  undefined8 uVar1;
  
  if (param_1 == 0) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"Device.c",
               (undefined *)L"stopEventAnalyzeMonitoring",0xcf5,0,
               (undefined *)L"Device context NULL");
    uVar1 = 0;
  }
  else {
    if (*(longlong *)(param_1 + 200) != -1) {
      *(undefined4 *)(param_1 + 0xd8) = 1;
      *(undefined4 *)(param_1 + 0xdc) = 1;
      SetEvent(*(HANDLE *)(param_1 + 0xd0));
      WaitForSingleObject(*(HANDLE *)(param_1 + 200),0xffffffff);
      if (*(HANDLE *)(param_1 + 200) != (HANDLE)0xffffffffffffffff) {
        CloseHandle(*(HANDLE *)(param_1 + 200));
      }
      *(undefined8 *)(param_1 + 200) = 0xffffffffffffffff;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Device.c",
                 (undefined *)L"stopEventAnalyzeMonitoring",0xd04,0,
                 (undefined *)L"eventThreadHandle released");
    }
    uVar1 = 1;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulonglong DriverEntry_FUN_180009e8c(undefined8 param_1,undefined8 param_2)

{
  uint uVar1;
  undefined4 local_68 [2];
  undefined *local_60;
  undefined4 local_48 [2];
  undefined *local_40;
  undefined4 local_30;
  undefined4 local_2c;
  
  _DAT_18005b598 = 1;
  _DAT_18005b590 = 0;
  DAT_18005b5b8 = &DAT_18001db10;
  PTR_LOOP_180037650 = &DAT_18005b580;
  _DAT_18005b580 = 0;
  _DAT_18005b5a8 = 0;
  _DAT_18005b5b0 = 0;
  FUN_18000a1f0(param_1,param_2);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,6,(undefined *)L"Driver.c",(undefined *)L"DriverEntry",0x39
             ,0,(undefined *)L"driver Entry");
  Get_LogOutput_config_FUN_180001200();
  Init_LogOutput_WBDI_FUN_1800013fc();
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Driver.c",(undefined *)L"DriverEntry",0x3c
             ,0,(undefined *)L"Init LogOutput for WBDI********************************");
  DAT_18004ead0 = FUN_18000f0a0();
  memset(local_48,0,0x38);
  local_48[0] = 0x38;
  local_40 = &LAB_18000a230;
  local_30 = 1;
  local_2c = 1;
  memset(local_68,0,0x20);
  local_60 = &LAB_18000a228;
  local_68[0] = 0x20;
  uVar1 = (**(code **)(DAT_18005ad20 + 0x1c8))(DAT_18005ad28,param_1,param_2,local_48,local_68,0);
  if ((int)uVar1 < 0) {
    FUN_18000a098();
  }
  else {
    if (DAT_18004ead0 == '\x01') {
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"Driver.c",(undefined *)L"DriverEntry",
                 0x58,0,(undefined *)L"RegisterPowerNotification");
      FUN_18000f454();
    }
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,6,(undefined *)L"Driver.c",(undefined *)L"DriverEntry",
               0x5e,0,(undefined *)L"driver Exit");
  }
  return (ulonglong)uVar1;
}



void FUN_18000a098(void)

{
  longlong *plVar1;
  
  if (PTR_LOOP_180037650 != &PTR_LOOP_180037650) {
    plVar1 = (longlong *)PTR_LOOP_180037650;
    if (PTR_LOOP_180037650 != (undefined **)0x0) {
      do {
        if (plVar1[1] != 0) {
          UnregisterTraceGuids();
          plVar1[1] = 0;
        }
        plVar1 = (longlong *)*plVar1;
      } while (plVar1 != (longlong *)0x0);
    }
    WppAutoLogStop(PTR_LOOP_180037650);
    PTR_LOOP_180037650 = &PTR_LOOP_180037650;
  }
  return;
}



void FUN_18000a178(void)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  undefined8 local_18;
  undefined8 local_10;
  
  puVar2 = &DAT_18005b5b8;
  puVar1 = (undefined8 *)PTR_LOOP_180037650;
  while (puVar1 != (undefined8 *)0x0) {
    local_18 = *puVar2;
    local_10 = 0;
    puVar2 = puVar2 + 1;
    puVar1[4] = local_18;
    RegisterTraceGuidsW(&LAB_18000a0f8,puVar1,local_18,1,&local_18,0,0,puVar1 + 1);
    puVar1 = (undefined8 *)*puVar1;
  }
  return;
}



void FUN_18000a1f0(undefined8 param_1,undefined8 param_2)

{
  FUN_18000a178();
                    // WARNING: Could not recover jumptable at 0x00018001863c. Too many branches
                    // WARNING: Treating indirect jump as call
  WppAutoLogStart(PTR_LOOP_180037650,param_1,param_2);
  return;
}



void FUN_18000a2fc(int param_1,byte param_2,ushort param_3)

{
  undefined uVar1;
  byte bVar2;
  byte bVar3;
  undefined uVar4;
  byte bVar5;
  
  if ((param_2 == 0) && (param_3 == 0)) {
    param_2 = 0x15;
    param_3 = 0x80;
  }
  if (param_1 == 0) {
    bVar5 = 0xe;
    uVar4 = 0xc;
    bVar3 = 0x6c;
    bVar2 = 0x58;
LAB_18000a3b8:
    uVar1 = 7;
  }
  else {
    if (param_1 == 1) {
      bVar2 = 0x40;
    }
    else {
      if (param_1 != 2) {
        if (param_1 != 3) {
          return;
        }
        bVar5 = 0x18;
        uVar4 = 10;
        bVar3 = 0x84;
        bVar2 = 0x70;
        goto LAB_18000a3b8;
      }
      bVar2 = 0x36;
    }
    bVar5 = 0x10;
    uVar4 = 0x38;
    bVar3 = 0xb0;
    uVar1 = 6;
  }
  FUN_18000a3cc(uVar1,0x100,param_2,param_3,bVar2,bVar3,0x80,uVar4,4,bVar5);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_18000a3cc(undefined param_1,ulonglong param_2,byte param_3,ushort param_4,byte param_5,
                  byte param_6,ushort param_7,undefined param_8,undefined param_9,byte param_10)

{
  if (param_5 == 0x36) {
    DAT_18004e900 = &DAT_180020f2c;
    DAT_18004e908 = &DAT_180020f30;
    DAT_18004e918 = (undefined *)0x180037674;
    DAT_180037670._5_1_ = param_10 >> 2;
    _DAT_18004e8f0 = 2;
    _DAT_18004e8f9 = 0x502;
    _DAT_18004e910 = 0x205;
    DAT_180037670._6_1_ = (undefined)((int)((uint)param_10 + (uint)param_10) >> 2);
    DAT_18004e958 = 0x36;
    DAT_180037670._4_1_ = 0;
    DAT_180037670._7_1_ = (undefined)((int)((uint)param_10 + (uint)param_10 * 2) >> 2);
    DAT_180037678._0_1_ = param_10 - 2;
    DAT_18004e920 = (undefined *)0x18003767c;
    DAT_18004e928 = &DAT_18004e790;
    DAT_18004e930 = &DAT_18004e7b8;
    DAT_18004e938 = &DAT_18004e7e0;
    DAT_18004e940 = &DAT_18004e808;
  }
  else {
    if (param_5 == 0x40) {
      _DAT_18004e8f0 = 0;
      DAT_18004e900 = &DAT_180020f18;
      DAT_18004e908 = &DAT_180020f1c;
      DAT_18004e918 = &DAT_180037660;
      DAT_180037661 = param_10 >> 2;
      _DAT_18004e8f9 = 0x502;
      _DAT_18004e910 = 0x205;
      DAT_18004e958 = 0x40;
      DAT_180037660 = 0;
      DAT_180037662 = (undefined)((int)((uint)param_10 + (uint)param_10) >> 2);
      DAT_180037663 = (undefined)((int)((uint)param_10 + (uint)param_10 * 2) >> 2);
      DAT_180037664 = param_10 - 2;
      DAT_18004e920 = &DAT_180037668;
      DAT_18004e928 = &DAT_18004e630;
      DAT_18004e930 = &DAT_18004e658;
      DAT_18004e938 = &DAT_18004e680;
      DAT_18004e940 = &DAT_18004e6a8;
    }
    else {
      if (param_5 == 0x58) {
        _DAT_18004e8f0 = 1;
        DAT_18004e900 = &DAT_180020f24;
        DAT_18004e908 = &DAT_180020f28;
        DAT_18004e918 = &DAT_18003766c;
        DAT_18003766d = param_10 >> 1;
        DAT_18003766e = param_10 - 2;
        DAT_18004e920 = (undefined *)&DAT_180037670;
        DAT_18004e928 = &DAT_18004e6d0;
        DAT_18004e930 = &DAT_18004e700;
        DAT_18004e938 = &DAT_18004e730;
        DAT_18004e940 = &DAT_18004e760;
        _DAT_18004e8f9 = 0x403;
        _DAT_18004e910 = 0x403;
        DAT_18004e958 = param_6;
        DAT_18003766c = 0;
      }
      else {
        if (param_5 == 0x70) {
          _DAT_18004e8f0 = 3;
          DAT_18004e900 = &DAT_180020f38;
          DAT_18004e908 = &DAT_180020f3c;
          DAT_18004e918 = &DAT_180037680;
          DAT_180037681 = param_10 >> 1;
          DAT_180037682 = param_10 - 2;
          DAT_18004e920 = &DAT_180037684;
          DAT_18004e928 = &DAT_18004e830;
          DAT_18004e930 = &DAT_18004e860;
          DAT_18004e938 = &DAT_18004e890;
          DAT_18004e940 = &DAT_18004e8c0;
          _DAT_18004e8f9 = 0x403;
          _DAT_18004e910 = 0x403;
          DAT_18004e958 = param_6;
          DAT_180037680 = 0;
        }
        else {
          _DAT_18004e8f0 = 4;
        }
      }
    }
  }
  DAT_18004e94c =
       (undefined4)((ulonglong)((uint)param_4 * (uint)param_3 * 0x10) / (param_2 & 0xffff));
  DAT_18004e960 =
       (undefined4)((ulonglong)((uint)param_7 * (uint)param_3 * 0x10) / (param_2 & 0xffff));
  DAT_18004e8f8 = param_1;
  DAT_18004e948 = param_5;
  DAT_18004e949 = param_6;
  DAT_18004e950 = DAT_18004e94c;
  _DAT_18004e954 = ((uint)param_5 * (uint)param_6) / 10;
  DAT_18004e959 = param_8;
  DAT_18004e95a = param_9;
  DAT_18004e95b = param_10;
  DAT_18004e95c = 2;
  DAT_18004e964 = DAT_18004e960;
  return;
}



void FUN_18000a7cc(undefined4 *param_1,int param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = 2;
  if (param_2 == 0) {
    if (param_3 == 0) {
      param_3 = 0;
LAB_18000a844:
      uVar1 = param_3;
      if (uVar1 != 2) goto LAB_18000a7fd;
    }
    else {
      if (param_3 == 1) goto LAB_18000a808;
      if (param_3 == 2) {
        uVar1 = 0;
        goto LAB_18000a7fd;
      }
      if (param_3 == 3) goto LAB_18000a7f7;
    }
  }
  else {
    if (param_2 == 1) {
      if (param_3 < 4) {
LAB_18000a808:
        uVar1 = 1;
        goto LAB_18000a7fd;
      }
    }
    else {
      if (param_2 == 2) {
        if (param_3 < 4) goto LAB_18000a844;
      }
      else {
        if (param_2 == 3) {
          if (param_3 != 0) {
            if (param_3 == 1) goto LAB_18000a808;
            if (1 < param_3 - 2) goto LAB_18000a84a;
          }
LAB_18000a7f7:
          uVar1 = 3;
          goto LAB_18000a7fd;
        }
      }
    }
  }
LAB_18000a84a:
  if (((DAT_180037688 & 0xfffffffc) == 0) && (DAT_180037688 != 1)) {
    *param_1 = 1;
    return;
  }
LAB_18000a7fd:
  DAT_180037688 = uVar1;
  *param_1 = 0;
  return;
}



ulonglong FUN_18000b140(longlong param_1,longlong param_2)

{
  ushort *puVar1;
  int *piVar2;
  uint *puVar3;
  ushort uVar4;
  ushort uVar5;
  bool bVar6;
  bool bVar7;
  byte bVar8;
  uint uVar9;
  ulonglong uVar10;
  uint uVar11;
  int iVar12;
  uint uVar13;
  ulonglong uVar14;
  ulonglong uVar15;
  int iVar16;
  int iVar17;
  uint uVar18;
  int iVar19;
  int iVar20;
  uint uVar21;
  bool bVar22;
  bool bVar23;
  byte local_res8;
  byte local_58;
  
  DAT_18004e8f4 = 0;
  local_res8 = 0;
  uVar18 = 0;
  bVar6 = false;
  bVar7 = false;
  local_58 = 0;
  bVar8 = DAT_18004e8fa;
  if (DAT_18004e8f9 != 0) {
    do {
      uVar11 = 0;
      if (bVar8 != 0) {
        do {
          *(undefined4 *)(DAT_18004e928 + (ulonglong)(DAT_18004e8fa * uVar18 + uVar11) * 4) = 0;
          *(undefined4 *)(DAT_18004e930 + (ulonglong)(DAT_18004e8fa * uVar18 + uVar11) * 4) = 0;
          *(undefined4 *)(DAT_18004e938 + (ulonglong)(DAT_18004e8fa * uVar18 + uVar11) * 4) = 0;
          uVar9 = DAT_18004e8fa * uVar18 + uVar11;
          uVar11 = uVar11 + 1;
          *(undefined4 *)(DAT_18004e940 + (ulonglong)uVar9 * 4) = 0;
          bVar8 = DAT_18004e8fa;
        } while (uVar11 < DAT_18004e8fa);
      }
      uVar18 = uVar18 + 1;
    } while (uVar18 < DAT_18004e8f9);
  }
  if (DAT_18004e8f4 == 0) {
    uVar15 = 0;
    if (DAT_18004e8f9 != 0) {
      do {
        uVar14 = 0;
        iVar17 = (int)uVar15;
        if (DAT_18004e8fa != 0) {
          do {
            uVar18 = 0;
            iVar12 = (int)uVar14;
            do {
              uVar11 = 0;
              do {
                uVar9 = (uint)*(byte *)(DAT_18004e908 + uVar14) +
                        uVar11 + (*(byte *)(DAT_18004e900 + uVar15) + uVar18) * (uint)DAT_18004e949;
                uVar10 = (ulonglong)uVar9;
                uVar4 = *(ushort *)(param_2 + (ulonglong)uVar9 * 2);
                puVar1 = (ushort *)(param_1 + uVar10 * 2);
                if (*puVar1 < uVar4 || *puVar1 == uVar4) {
                  uVar5 = *(ushort *)(param_1 + uVar10 * 2);
                }
                else {
                  uVar5 = uVar4;
                  uVar4 = *(ushort *)(param_1 + uVar10 * 2);
                }
                uVar11 = uVar11 + 1;
                piVar2 = (int *)(DAT_18004e938 +
                                (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar12) * 4);
                *piVar2 = *piVar2 + ((uint)uVar4 - (uint)uVar5);
                piVar2 = (int *)(DAT_18004e928 +
                                (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar12) * 4);
                *piVar2 = *piVar2 + (uint)*(ushort *)(param_1 + uVar10 * 2);
                piVar2 = (int *)(DAT_18004e930 +
                                (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar12) * 4);
                *piVar2 = *piVar2 + (uint)*(ushort *)(param_2 + uVar10 * 2);
              } while (uVar11 < 8);
              uVar18 = uVar18 + 1;
            } while (uVar18 < 8);
            puVar3 = (uint *)(DAT_18004e938 + (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar12) * 4
                             );
            *puVar3 = *puVar3 >> 6;
            puVar3 = (uint *)(DAT_18004e928 + (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar12) * 4
                             );
            *puVar3 = *puVar3 >> 6;
            uVar14 = (ulonglong)(iVar12 + 1U);
            puVar3 = (uint *)(DAT_18004e930 + (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar12) * 4
                             );
            *puVar3 = *puVar3 >> 6;
          } while (iVar12 + 1U < (uint)DAT_18004e8fa);
        }
        uVar15 = (ulonglong)(iVar17 + 1U);
      } while (iVar17 + 1U < (uint)DAT_18004e8f9);
    }
  }
  else {
    uVar15 = 0;
    if (DAT_18004e910 != 0) {
      do {
        uVar14 = 0;
        iVar17 = (int)uVar15;
        if (DAT_18004e911 != 0) {
          do {
            uVar18 = 0;
            iVar12 = (int)uVar14;
            if (DAT_18004e95c != 0) {
              do {
                uVar11 = 0;
                do {
                  uVar9 = (uint)*(byte *)(DAT_18004e920 + uVar14) +
                          uVar11 + (*(byte *)(DAT_18004e918 + uVar15) + uVar18) *
                                   (uint)DAT_18004e958;
                  uVar10 = (ulonglong)uVar9;
                  uVar4 = *(ushort *)(param_2 + (ulonglong)uVar9 * 2);
                  puVar1 = (ushort *)(param_1 + uVar10 * 2);
                  if (*puVar1 < uVar4 || *puVar1 == uVar4) {
                    uVar5 = *(ushort *)(param_1 + uVar10 * 2);
                  }
                  else {
                    uVar5 = uVar4;
                    uVar4 = *(ushort *)(param_1 + uVar10 * 2);
                  }
                  uVar11 = uVar11 + 1;
                  piVar2 = (int *)(DAT_18004e938 +
                                  (ulonglong)((uint)DAT_18004e911 * iVar17 + iVar12) * 4);
                  *piVar2 = *piVar2 + ((uint)uVar4 - (uint)uVar5);
                  piVar2 = (int *)(DAT_18004e928 +
                                  (ulonglong)((uint)DAT_18004e911 * iVar17 + iVar12) * 4);
                  *piVar2 = *piVar2 + (uint)*(ushort *)(param_1 + uVar10 * 2);
                  piVar2 = (int *)(DAT_18004e930 +
                                  (ulonglong)((uint)DAT_18004e911 * iVar17 + iVar12) * 4);
                  *piVar2 = *piVar2 + (uint)*(ushort *)(param_2 + uVar10 * 2);
                } while (uVar11 < 8);
                uVar18 = uVar18 + 1;
              } while (uVar18 < DAT_18004e95c);
            }
            uVar18 = (uint)DAT_18004e911 * iVar17 + iVar12;
            *(int *)(DAT_18004e938 + (ulonglong)uVar18 * 4) =
                 (int)((ulonglong)*(uint *)(DAT_18004e938 + (ulonglong)uVar18 * 4) /
                      ((ulonglong)DAT_18004e95c << 3));
            uVar18 = (uint)DAT_18004e911 * iVar17 + iVar12;
            *(int *)(DAT_18004e928 + (ulonglong)uVar18 * 4) =
                 (int)((ulonglong)*(uint *)(DAT_18004e928 + (ulonglong)uVar18 * 4) /
                      ((ulonglong)DAT_18004e95c << 3));
            uVar18 = (uint)DAT_18004e911 * iVar17 + iVar12;
            uVar14 = (ulonglong)(iVar12 + 1U);
            *(int *)(DAT_18004e930 + (ulonglong)uVar18 * 4) =
                 (int)((ulonglong)*(uint *)(DAT_18004e930 + (ulonglong)uVar18 * 4) /
                      ((ulonglong)DAT_18004e95c << 3));
          } while (iVar12 + 1U < (uint)DAT_18004e911);
        }
        uVar15 = (ulonglong)(iVar17 + 1U);
      } while (iVar17 + 1U < (uint)DAT_18004e910);
    }
  }
  uVar15 = 0;
  if (DAT_18004e8f4 == 0) {
    if (DAT_18004e8f9 != 0) {
      do {
        uVar14 = 0;
        iVar17 = (int)uVar15;
        if (DAT_18004e8fa != 0) {
          do {
            uVar18 = 0;
            do {
              uVar11 = 0;
              do {
                uVar10 = (ulonglong)
                         ((uint)*(byte *)(DAT_18004e908 + uVar14) +
                         uVar11 + (*(byte *)(DAT_18004e900 + uVar15) + uVar18) * (uint)DAT_18004e949
                         );
                uVar4 = *(ushort *)(param_2 + uVar10 * 2);
                uVar5 = *(ushort *)(param_1 + uVar10 * 2);
                uVar9 = (uint)uVar5;
                uVar13 = (uint)uVar4;
                if (uVar5 < uVar4) {
                  iVar12 = uVar13 - uVar9;
                  iVar19 = uVar13 - uVar9;
                }
                else {
                  iVar12 = uVar9 - uVar13;
                  iVar19 = uVar9 - uVar13;
                }
                uVar11 = uVar11 + 1;
                iVar16 = (int)uVar14;
                uVar10 = (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar16);
                iVar20 = *(int *)(DAT_18004e938 + uVar10 * 4);
                piVar2 = (int *)(DAT_18004e940 + uVar10 * 4);
                *piVar2 = *piVar2 + (iVar20 - iVar19) * (iVar20 - iVar12);
              } while (uVar11 < 8);
              uVar18 = uVar18 + 1;
            } while (uVar18 < 8);
            uVar18 = (uint)DAT_18004e8fa * iVar17 + iVar16;
            uVar14 = (ulonglong)(iVar16 + 1U);
            *(uint *)(DAT_18004e940 + (ulonglong)uVar18 * 4) =
                 *(uint *)(DAT_18004e940 + (ulonglong)uVar18 * 4) / 0x3f;
          } while (iVar16 + 1U < (uint)DAT_18004e8fa);
        }
        uVar15 = (ulonglong)(iVar17 + 1U);
      } while (iVar17 + 1U < (uint)DAT_18004e8f9);
    }
  }
  else {
    if (DAT_18004e910 != 0) {
      do {
        uVar14 = 0;
        iVar17 = (int)uVar15;
        if (DAT_18004e911 != 0) {
          do {
            uVar18 = 0;
            iVar12 = (int)uVar14;
            if (DAT_18004e95c != 0) {
              do {
                uVar11 = 0;
                do {
                  uVar10 = (ulonglong)
                           ((uint)*(byte *)(DAT_18004e920 + uVar14) +
                           uVar11 + (*(byte *)(DAT_18004e918 + uVar15) + uVar18) *
                                    (uint)DAT_18004e958);
                  uVar4 = *(ushort *)(param_2 + uVar10 * 2);
                  uVar5 = *(ushort *)(param_1 + uVar10 * 2);
                  uVar9 = (uint)uVar5;
                  uVar13 = (uint)uVar4;
                  if (uVar5 < uVar4) {
                    iVar19 = uVar13 - uVar9;
                    iVar20 = uVar13 - uVar9;
                  }
                  else {
                    iVar19 = uVar9 - uVar13;
                    iVar20 = uVar9 - uVar13;
                  }
                  uVar11 = uVar11 + 1;
                  uVar10 = (ulonglong)((uint)DAT_18004e911 * iVar17 + iVar12);
                  iVar16 = *(int *)(DAT_18004e938 + uVar10 * 4);
                  piVar2 = (int *)(DAT_18004e940 + uVar10 * 4);
                  *piVar2 = *piVar2 + (iVar16 - iVar20) * (iVar16 - iVar19);
                } while (uVar11 < 8);
                uVar18 = uVar18 + 1;
              } while (uVar18 < DAT_18004e95c);
            }
            uVar10 = (ulonglong)((uint)DAT_18004e911 * iVar17 + iVar12);
            uVar14 = (ulonglong)(iVar12 + 1U);
            *(uint *)(DAT_18004e940 + uVar10 * 4) =
                 *(uint *)(DAT_18004e940 + uVar10 * 4) / ((uint)DAT_18004e95c * 8 - 1);
          } while (iVar12 + 1U < (uint)DAT_18004e911);
        }
        uVar15 = (ulonglong)(iVar17 + 1U);
      } while (iVar17 + 1U < (uint)DAT_18004e910);
    }
  }
  uVar18 = 0;
  if (DAT_18004e8f9 != 0) {
    bVar8 = 0;
    do {
      if (DAT_18004e8fa != 0) {
        uVar11 = DAT_18004e8fa * uVar18;
        uVar15 = (ulonglong)DAT_18004e8fa;
        local_res8 = bVar8;
        do {
          if (DAT_18004e8f4 == 0) {
            bVar8 = local_res8 + 1;
            if (*(uint *)(DAT_18004e940 + (ulonglong)uVar11 * 4) <=
                (uint)(longlong)((double)(ulonglong)DAT_18004e94c * 1.4)) {
              bVar8 = local_res8;
            }
          }
          else {
            puVar3 = (uint *)(DAT_18004e940 + (ulonglong)uVar11 * 4);
            uVar9 = (uint)(longlong)((double)(ulonglong)DAT_18004e960 * 1.4);
            bVar8 = local_res8;
            if (uVar9 <= *puVar3 && *puVar3 != uVar9) {
              bVar8 = local_res8 + 1;
            }
          }
          local_res8 = bVar8;
          uVar11 = uVar11 + 1;
          uVar15 = uVar15 - 1;
          bVar8 = local_res8;
        } while (uVar15 != 0);
      }
      uVar18 = uVar18 + 1;
    } while (uVar18 < DAT_18004e8f9);
  }
  uVar18 = 0;
  if (DAT_18004e8f9 != 0) {
    do {
      if (DAT_18004e8fa != 0) {
        uVar11 = DAT_18004e8fa * uVar18;
        uVar15 = (ulonglong)DAT_18004e8fa;
        do {
          uVar14 = (ulonglong)uVar11;
          uVar9 = DAT_18004e964;
          if (DAT_18004e8f4 == 0) {
            uVar9 = DAT_18004e950;
          }
          puVar3 = (uint *)(DAT_18004e938 + uVar14 * 4);
          uVar21 = (uint)(longlong)((double)(ulonglong)uVar9 * 1.4);
          bVar22 = *puVar3 < uVar21;
          uVar13 = *puVar3;
          if (bVar22) {
            puVar3 = (uint *)(DAT_18004e938 + uVar14 * 4);
            uVar9 = (uint)(longlong)((double)(ulonglong)uVar9 * 0.6);
            if (uVar9 <= *puVar3 && *puVar3 != uVar9) {
              local_58 = local_58 + 1;
            }
            puVar3 = (uint *)(DAT_18004e938 + uVar14 * 4);
            bVar22 = *puVar3 < uVar21;
            uVar13 = *puVar3;
          }
          bVar7 = (bool)(*(int *)(DAT_18004e928 + uVar14 * 4) + uVar21 <
                         *(uint *)(DAT_18004e930 + uVar14 * 4) | bVar7);
          uVar11 = uVar11 + 1;
          bVar6 = (bool)((!bVar22 && uVar13 != uVar21) | bVar6);
          uVar15 = uVar15 - 1;
        } while (uVar15 != 0);
      }
      uVar18 = uVar18 + 1;
    } while (uVar18 < DAT_18004e8f9);
  }
  uVar11 = 0;
  uVar18 = 0;
  if (DAT_18004e8f4 == 0) {
    uVar9 = 1;
    if (1 < DAT_18004e948 - 1) {
      do {
        uVar13 = 1;
        if (1 < DAT_18004e949 - 1) {
          do {
            uVar15 = (ulonglong)(DAT_18004e949 * uVar9 + uVar13);
            uVar4 = *(ushort *)(param_1 + uVar15 * 2);
            uVar5 = *(ushort *)(param_2 + uVar15 * 2);
            uVar21 = uVar18 + 1;
            if ((uint)uVar5 <= uVar4 + 0x20) {
              uVar21 = uVar18;
            }
            uVar18 = uVar21;
            uVar21 = uVar11 + 1;
            if ((uint)uVar4 <= uVar5 + 0x20) {
              uVar21 = uVar11;
            }
            uVar11 = uVar21;
            uVar13 = uVar13 + 1;
          } while (uVar13 < DAT_18004e949 - 1);
        }
        uVar9 = uVar9 + 1;
      } while (uVar9 < DAT_18004e948 - 1);
    }
    uVar9 = (uint)(longlong)
                  ((double)((DAT_18004e949 - 2) * (uint)DAT_18004e948 +
                           (2 - (uint)DAT_18004e949) * 2) * 0.1);
    bVar22 = uVar9 <= uVar18;
    bVar23 = uVar9 <= uVar11;
  }
  else {
    uVar9 = 0;
    if (DAT_18004e95b != 0) {
      do {
        uVar13 = 1;
        if (1 < DAT_18004e958 - 1) {
          do {
            uVar15 = (ulonglong)(DAT_18004e958 * uVar9 + uVar13);
            uVar4 = *(ushort *)(param_1 + uVar15 * 2);
            uVar5 = *(ushort *)(param_2 + uVar15 * 2);
            uVar21 = uVar18 + 1;
            if ((uint)uVar5 <= uVar4 + 0x20) {
              uVar21 = uVar18;
            }
            uVar18 = uVar21;
            uVar21 = uVar11 + 1;
            if ((uint)uVar4 <= uVar5 + 0x20) {
              uVar21 = uVar11;
            }
            uVar11 = uVar21;
            uVar13 = uVar13 + 1;
          } while (uVar13 < DAT_18004e958 - 1);
        }
        uVar9 = uVar9 + 1;
      } while (uVar9 < DAT_18004e95b);
    }
    bVar23 = true;
    uVar9 = (uint)(longlong)((double)((DAT_18004e958 - 2) * (uint)DAT_18004e95b) * 0.1);
    bVar22 = uVar9 <= uVar18;
    if (uVar11 < uVar9) {
      bVar23 = false;
    }
  }
  uVar18 = (uint)(DAT_18004e8f8 == 0) + (uint)DAT_18004e8f8;
  if (local_res8 < uVar18) {
    if (!bVar6) {
      return (ulonglong)(((uint)local_58 - (uint)local_58) - (uint)(local_58 < uVar18) & 2);
    }
    if (bVar7) {
      return 3;
    }
  }
  else {
    if ((bVar22) && (!bVar23)) {
      return 3;
    }
  }
  return 1;
}



ulonglong FUN_18000b15c(longlong param_1,longlong param_2)

{
  ushort *puVar1;
  int *piVar2;
  uint *puVar3;
  ushort uVar4;
  ushort uVar5;
  bool bVar6;
  bool bVar7;
  byte bVar8;
  uint uVar9;
  ulonglong uVar10;
  uint uVar11;
  int iVar12;
  uint uVar13;
  ulonglong uVar14;
  ulonglong uVar15;
  int iVar16;
  int iVar17;
  uint uVar18;
  int iVar19;
  int iVar20;
  uint uVar21;
  bool bVar22;
  bool bVar23;
  byte bStackX8;
  byte bStack88;
  
  DAT_18004e8f4 = 1;
  bStackX8 = 0;
  uVar18 = 0;
  bVar6 = false;
  bVar7 = false;
  bStack88 = 0;
  bVar8 = DAT_18004e8fa;
  if (DAT_18004e8f9 != 0) {
    do {
      uVar11 = 0;
      if (bVar8 != 0) {
        do {
          *(undefined4 *)(DAT_18004e928 + (ulonglong)(DAT_18004e8fa * uVar18 + uVar11) * 4) = 0;
          *(undefined4 *)(DAT_18004e930 + (ulonglong)(DAT_18004e8fa * uVar18 + uVar11) * 4) = 0;
          *(undefined4 *)(DAT_18004e938 + (ulonglong)(DAT_18004e8fa * uVar18 + uVar11) * 4) = 0;
          uVar9 = DAT_18004e8fa * uVar18 + uVar11;
          uVar11 = uVar11 + 1;
          *(undefined4 *)(DAT_18004e940 + (ulonglong)uVar9 * 4) = 0;
          bVar8 = DAT_18004e8fa;
        } while (uVar11 < DAT_18004e8fa);
      }
      uVar18 = uVar18 + 1;
    } while (uVar18 < DAT_18004e8f9);
  }
  if (DAT_18004e8f4 == 0) {
    uVar15 = 0;
    if (DAT_18004e8f9 != 0) {
      do {
        uVar14 = 0;
        iVar17 = (int)uVar15;
        if (DAT_18004e8fa != 0) {
          do {
            uVar18 = 0;
            iVar12 = (int)uVar14;
            do {
              uVar11 = 0;
              do {
                uVar9 = (uint)*(byte *)(DAT_18004e908 + uVar14) +
                        uVar11 + (*(byte *)(DAT_18004e900 + uVar15) + uVar18) * (uint)DAT_18004e949;
                uVar10 = (ulonglong)uVar9;
                uVar4 = *(ushort *)(param_2 + (ulonglong)uVar9 * 2);
                puVar1 = (ushort *)(param_1 + uVar10 * 2);
                if (*puVar1 < uVar4 || *puVar1 == uVar4) {
                  uVar5 = *(ushort *)(param_1 + uVar10 * 2);
                }
                else {
                  uVar5 = uVar4;
                  uVar4 = *(ushort *)(param_1 + uVar10 * 2);
                }
                uVar11 = uVar11 + 1;
                piVar2 = (int *)(DAT_18004e938 +
                                (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar12) * 4);
                *piVar2 = *piVar2 + ((uint)uVar4 - (uint)uVar5);
                piVar2 = (int *)(DAT_18004e928 +
                                (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar12) * 4);
                *piVar2 = *piVar2 + (uint)*(ushort *)(param_1 + uVar10 * 2);
                piVar2 = (int *)(DAT_18004e930 +
                                (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar12) * 4);
                *piVar2 = *piVar2 + (uint)*(ushort *)(param_2 + uVar10 * 2);
              } while (uVar11 < 8);
              uVar18 = uVar18 + 1;
            } while (uVar18 < 8);
            puVar3 = (uint *)(DAT_18004e938 + (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar12) * 4
                             );
            *puVar3 = *puVar3 >> 6;
            puVar3 = (uint *)(DAT_18004e928 + (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar12) * 4
                             );
            *puVar3 = *puVar3 >> 6;
            uVar14 = (ulonglong)(iVar12 + 1U);
            puVar3 = (uint *)(DAT_18004e930 + (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar12) * 4
                             );
            *puVar3 = *puVar3 >> 6;
          } while (iVar12 + 1U < (uint)DAT_18004e8fa);
        }
        uVar15 = (ulonglong)(iVar17 + 1U);
      } while (iVar17 + 1U < (uint)DAT_18004e8f9);
    }
  }
  else {
    uVar15 = 0;
    if (DAT_18004e910 != 0) {
      do {
        uVar14 = 0;
        iVar17 = (int)uVar15;
        if (DAT_18004e911 != 0) {
          do {
            uVar18 = 0;
            iVar12 = (int)uVar14;
            if (DAT_18004e95c != 0) {
              do {
                uVar11 = 0;
                do {
                  uVar9 = (uint)*(byte *)(DAT_18004e920 + uVar14) +
                          uVar11 + (*(byte *)(DAT_18004e918 + uVar15) + uVar18) *
                                   (uint)DAT_18004e958;
                  uVar10 = (ulonglong)uVar9;
                  uVar4 = *(ushort *)(param_2 + (ulonglong)uVar9 * 2);
                  puVar1 = (ushort *)(param_1 + uVar10 * 2);
                  if (*puVar1 < uVar4 || *puVar1 == uVar4) {
                    uVar5 = *(ushort *)(param_1 + uVar10 * 2);
                  }
                  else {
                    uVar5 = uVar4;
                    uVar4 = *(ushort *)(param_1 + uVar10 * 2);
                  }
                  uVar11 = uVar11 + 1;
                  piVar2 = (int *)(DAT_18004e938 +
                                  (ulonglong)((uint)DAT_18004e911 * iVar17 + iVar12) * 4);
                  *piVar2 = *piVar2 + ((uint)uVar4 - (uint)uVar5);
                  piVar2 = (int *)(DAT_18004e928 +
                                  (ulonglong)((uint)DAT_18004e911 * iVar17 + iVar12) * 4);
                  *piVar2 = *piVar2 + (uint)*(ushort *)(param_1 + uVar10 * 2);
                  piVar2 = (int *)(DAT_18004e930 +
                                  (ulonglong)((uint)DAT_18004e911 * iVar17 + iVar12) * 4);
                  *piVar2 = *piVar2 + (uint)*(ushort *)(param_2 + uVar10 * 2);
                } while (uVar11 < 8);
                uVar18 = uVar18 + 1;
              } while (uVar18 < DAT_18004e95c);
            }
            uVar18 = (uint)DAT_18004e911 * iVar17 + iVar12;
            *(int *)(DAT_18004e938 + (ulonglong)uVar18 * 4) =
                 (int)((ulonglong)*(uint *)(DAT_18004e938 + (ulonglong)uVar18 * 4) /
                      ((ulonglong)DAT_18004e95c << 3));
            uVar18 = (uint)DAT_18004e911 * iVar17 + iVar12;
            *(int *)(DAT_18004e928 + (ulonglong)uVar18 * 4) =
                 (int)((ulonglong)*(uint *)(DAT_18004e928 + (ulonglong)uVar18 * 4) /
                      ((ulonglong)DAT_18004e95c << 3));
            uVar18 = (uint)DAT_18004e911 * iVar17 + iVar12;
            uVar14 = (ulonglong)(iVar12 + 1U);
            *(int *)(DAT_18004e930 + (ulonglong)uVar18 * 4) =
                 (int)((ulonglong)*(uint *)(DAT_18004e930 + (ulonglong)uVar18 * 4) /
                      ((ulonglong)DAT_18004e95c << 3));
          } while (iVar12 + 1U < (uint)DAT_18004e911);
        }
        uVar15 = (ulonglong)(iVar17 + 1U);
      } while (iVar17 + 1U < (uint)DAT_18004e910);
    }
  }
  uVar15 = 0;
  if (DAT_18004e8f4 == 0) {
    if (DAT_18004e8f9 != 0) {
      do {
        uVar14 = 0;
        iVar17 = (int)uVar15;
        if (DAT_18004e8fa != 0) {
          do {
            uVar18 = 0;
            do {
              uVar11 = 0;
              do {
                uVar10 = (ulonglong)
                         ((uint)*(byte *)(DAT_18004e908 + uVar14) +
                         uVar11 + (*(byte *)(DAT_18004e900 + uVar15) + uVar18) * (uint)DAT_18004e949
                         );
                uVar4 = *(ushort *)(param_2 + uVar10 * 2);
                uVar5 = *(ushort *)(param_1 + uVar10 * 2);
                uVar9 = (uint)uVar5;
                uVar13 = (uint)uVar4;
                if (uVar5 < uVar4) {
                  iVar12 = uVar13 - uVar9;
                  iVar19 = uVar13 - uVar9;
                }
                else {
                  iVar12 = uVar9 - uVar13;
                  iVar19 = uVar9 - uVar13;
                }
                uVar11 = uVar11 + 1;
                iVar16 = (int)uVar14;
                uVar10 = (ulonglong)((uint)DAT_18004e8fa * iVar17 + iVar16);
                iVar20 = *(int *)(DAT_18004e938 + uVar10 * 4);
                piVar2 = (int *)(DAT_18004e940 + uVar10 * 4);
                *piVar2 = *piVar2 + (iVar20 - iVar19) * (iVar20 - iVar12);
              } while (uVar11 < 8);
              uVar18 = uVar18 + 1;
            } while (uVar18 < 8);
            uVar18 = (uint)DAT_18004e8fa * iVar17 + iVar16;
            uVar14 = (ulonglong)(iVar16 + 1U);
            *(uint *)(DAT_18004e940 + (ulonglong)uVar18 * 4) =
                 *(uint *)(DAT_18004e940 + (ulonglong)uVar18 * 4) / 0x3f;
          } while (iVar16 + 1U < (uint)DAT_18004e8fa);
        }
        uVar15 = (ulonglong)(iVar17 + 1U);
      } while (iVar17 + 1U < (uint)DAT_18004e8f9);
    }
  }
  else {
    if (DAT_18004e910 != 0) {
      do {
        uVar14 = 0;
        iVar17 = (int)uVar15;
        if (DAT_18004e911 != 0) {
          do {
            uVar18 = 0;
            iVar12 = (int)uVar14;
            if (DAT_18004e95c != 0) {
              do {
                uVar11 = 0;
                do {
                  uVar10 = (ulonglong)
                           ((uint)*(byte *)(DAT_18004e920 + uVar14) +
                           uVar11 + (*(byte *)(DAT_18004e918 + uVar15) + uVar18) *
                                    (uint)DAT_18004e958);
                  uVar4 = *(ushort *)(param_2 + uVar10 * 2);
                  uVar5 = *(ushort *)(param_1 + uVar10 * 2);
                  uVar9 = (uint)uVar5;
                  uVar13 = (uint)uVar4;
                  if (uVar5 < uVar4) {
                    iVar19 = uVar13 - uVar9;
                    iVar20 = uVar13 - uVar9;
                  }
                  else {
                    iVar19 = uVar9 - uVar13;
                    iVar20 = uVar9 - uVar13;
                  }
                  uVar11 = uVar11 + 1;
                  uVar10 = (ulonglong)((uint)DAT_18004e911 * iVar17 + iVar12);
                  iVar16 = *(int *)(DAT_18004e938 + uVar10 * 4);
                  piVar2 = (int *)(DAT_18004e940 + uVar10 * 4);
                  *piVar2 = *piVar2 + (iVar16 - iVar20) * (iVar16 - iVar19);
                } while (uVar11 < 8);
                uVar18 = uVar18 + 1;
              } while (uVar18 < DAT_18004e95c);
            }
            uVar10 = (ulonglong)((uint)DAT_18004e911 * iVar17 + iVar12);
            uVar14 = (ulonglong)(iVar12 + 1U);
            *(uint *)(DAT_18004e940 + uVar10 * 4) =
                 *(uint *)(DAT_18004e940 + uVar10 * 4) / ((uint)DAT_18004e95c * 8 - 1);
          } while (iVar12 + 1U < (uint)DAT_18004e911);
        }
        uVar15 = (ulonglong)(iVar17 + 1U);
      } while (iVar17 + 1U < (uint)DAT_18004e910);
    }
  }
  uVar18 = 0;
  if (DAT_18004e8f9 != 0) {
    bVar8 = 0;
    do {
      if (DAT_18004e8fa != 0) {
        uVar11 = DAT_18004e8fa * uVar18;
        uVar15 = (ulonglong)DAT_18004e8fa;
        bStackX8 = bVar8;
        do {
          if (DAT_18004e8f4 == 0) {
            bVar8 = bStackX8 + 1;
            if (*(uint *)(DAT_18004e940 + (ulonglong)uVar11 * 4) <=
                (uint)(longlong)((double)(ulonglong)DAT_18004e94c * 1.4)) {
              bVar8 = bStackX8;
            }
          }
          else {
            puVar3 = (uint *)(DAT_18004e940 + (ulonglong)uVar11 * 4);
            uVar9 = (uint)(longlong)((double)(ulonglong)DAT_18004e960 * 1.4);
            bVar8 = bStackX8;
            if (uVar9 <= *puVar3 && *puVar3 != uVar9) {
              bVar8 = bStackX8 + 1;
            }
          }
          bStackX8 = bVar8;
          uVar11 = uVar11 + 1;
          uVar15 = uVar15 - 1;
          bVar8 = bStackX8;
        } while (uVar15 != 0);
      }
      uVar18 = uVar18 + 1;
    } while (uVar18 < DAT_18004e8f9);
  }
  uVar18 = 0;
  if (DAT_18004e8f9 != 0) {
    do {
      if (DAT_18004e8fa != 0) {
        uVar11 = DAT_18004e8fa * uVar18;
        uVar15 = (ulonglong)DAT_18004e8fa;
        do {
          uVar14 = (ulonglong)uVar11;
          uVar9 = DAT_18004e964;
          if (DAT_18004e8f4 == 0) {
            uVar9 = DAT_18004e950;
          }
          puVar3 = (uint *)(DAT_18004e938 + uVar14 * 4);
          uVar21 = (uint)(longlong)((double)(ulonglong)uVar9 * 1.4);
          bVar22 = *puVar3 < uVar21;
          uVar13 = *puVar3;
          if (bVar22) {
            puVar3 = (uint *)(DAT_18004e938 + uVar14 * 4);
            uVar9 = (uint)(longlong)((double)(ulonglong)uVar9 * 0.6);
            if (uVar9 <= *puVar3 && *puVar3 != uVar9) {
              bStack88 = bStack88 + 1;
            }
            puVar3 = (uint *)(DAT_18004e938 + uVar14 * 4);
            bVar22 = *puVar3 < uVar21;
            uVar13 = *puVar3;
          }
          bVar7 = (bool)(*(int *)(DAT_18004e928 + uVar14 * 4) + uVar21 <
                         *(uint *)(DAT_18004e930 + uVar14 * 4) | bVar7);
          uVar11 = uVar11 + 1;
          bVar6 = (bool)((!bVar22 && uVar13 != uVar21) | bVar6);
          uVar15 = uVar15 - 1;
        } while (uVar15 != 0);
      }
      uVar18 = uVar18 + 1;
    } while (uVar18 < DAT_18004e8f9);
  }
  uVar11 = 0;
  uVar18 = 0;
  if (DAT_18004e8f4 == 0) {
    uVar9 = 1;
    if (1 < DAT_18004e948 - 1) {
      do {
        uVar13 = 1;
        if (1 < DAT_18004e949 - 1) {
          do {
            uVar15 = (ulonglong)(DAT_18004e949 * uVar9 + uVar13);
            uVar4 = *(ushort *)(param_1 + uVar15 * 2);
            uVar5 = *(ushort *)(param_2 + uVar15 * 2);
            uVar21 = uVar18 + 1;
            if ((uint)uVar5 <= uVar4 + 0x20) {
              uVar21 = uVar18;
            }
            uVar18 = uVar21;
            uVar21 = uVar11 + 1;
            if ((uint)uVar4 <= uVar5 + 0x20) {
              uVar21 = uVar11;
            }
            uVar11 = uVar21;
            uVar13 = uVar13 + 1;
          } while (uVar13 < DAT_18004e949 - 1);
        }
        uVar9 = uVar9 + 1;
      } while (uVar9 < DAT_18004e948 - 1);
    }
    uVar9 = (uint)(longlong)
                  ((double)((DAT_18004e949 - 2) * (uint)DAT_18004e948 +
                           (2 - (uint)DAT_18004e949) * 2) * 0.1);
    bVar22 = uVar9 <= uVar18;
    bVar23 = uVar9 <= uVar11;
  }
  else {
    uVar9 = 0;
    if (DAT_18004e95b != 0) {
      do {
        uVar13 = 1;
        if (1 < DAT_18004e958 - 1) {
          do {
            uVar15 = (ulonglong)(DAT_18004e958 * uVar9 + uVar13);
            uVar4 = *(ushort *)(param_1 + uVar15 * 2);
            uVar5 = *(ushort *)(param_2 + uVar15 * 2);
            uVar21 = uVar18 + 1;
            if ((uint)uVar5 <= uVar4 + 0x20) {
              uVar21 = uVar18;
            }
            uVar18 = uVar21;
            uVar21 = uVar11 + 1;
            if ((uint)uVar4 <= uVar5 + 0x20) {
              uVar21 = uVar11;
            }
            uVar11 = uVar21;
            uVar13 = uVar13 + 1;
          } while (uVar13 < DAT_18004e958 - 1);
        }
        uVar9 = uVar9 + 1;
      } while (uVar9 < DAT_18004e95b);
    }
    bVar23 = true;
    uVar9 = (uint)(longlong)((double)((DAT_18004e958 - 2) * (uint)DAT_18004e95b) * 0.1);
    bVar22 = uVar9 <= uVar18;
    if (uVar11 < uVar9) {
      bVar23 = false;
    }
  }
  uVar18 = (uint)(DAT_18004e8f8 == 0) + (uint)DAT_18004e8f8;
  if (bStackX8 < uVar18) {
    if (!bVar6) {
      return (ulonglong)(((uint)bStack88 - (uint)bStack88) - (uint)(bStack88 < uVar18) & 2);
    }
    if (bVar7) {
      return 3;
    }
  }
  else {
    if ((bVar22) && (!bVar23)) {
      return 3;
    }
  }
  return 1;
}



ulonglong FUN_18000b178(byte *param_1,ushort param_2)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  ulonglong uVar5;
  
  DAT_180037440 = 0xffffffff;
  uVar5 = (ulonglong)param_2;
  FUN_180002770();
  bVar1 = param_1[uVar5 - 1];
  bVar2 = param_1[uVar5 - 2];
  bVar3 = param_1[uVar5 - 4];
  bVar4 = param_1[uVar5 - 3];
  uVar5 = FUN_1800027b4(param_1,param_2 - 4);
  return uVar5 & 0xffffffffffffff00 |
         (ulonglong)
         ((uint)bVar2 * 0x1000000 + (uint)bVar1 * 0x10000 + (uint)bVar3 * 0x100 + (uint)bVar4 ==
         (int)uVar5);
}



void FUN_18000b1dc(undefined4 *param_1,longlong param_2,int param_3,ulonglong param_4,int param_5)

{
  undefined4 *puVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  longlong lVar10;
  longlong lVar11;
  ulonglong uVar12;
  undefined4 *puVar13;
  ulonglong uVar14;
  longlong lVar15;
  short *psVar16;
  short *psVar17;
  ulonglong local_38;
  undefined8 uStack48;
  
  uStack48 = 0x18000b1f5;
  lVar11 = _alloca_probe();
  lVar11 = -lVar11;
  local_38 = DAT_180037758 ^ (ulonglong)(&stack0xffffffffffffffd8 + lVar11);
  uVar12 = param_4 & 0xffffffff;
  *(undefined8 *)((longlong)&uStack48 + lVar11) = 0x18000b227;
  memset(&stack0xfffffffffffffff8 + lVar11,0,0x4200,*(undefined *)((longlong)&uStack48 + lVar11));
  uVar14 = 0;
  iVar5 = (int)uVar12;
  iVar6 = (param_3 + -4) / iVar5;
  puVar13 = (undefined4 *)(&stack0xfffffffffffffff8 + lVar11);
  lVar15 = (longlong)(iVar5 * 0x60);
  if (param_5 == 0) {
    if (0 < iVar5) {
      do {
        uVar7 = param_1[1];
        uVar8 = param_1[2];
        uVar9 = param_1[3];
        *puVar13 = *param_1;
        puVar13[1] = uVar7;
        puVar13[2] = uVar8;
        puVar13[3] = uVar9;
        uVar7 = param_1[5];
        uVar8 = param_1[6];
        uVar9 = param_1[7];
        puVar13[4] = param_1[4];
        puVar13[5] = uVar7;
        puVar13[6] = uVar8;
        puVar13[7] = uVar9;
        uVar7 = param_1[9];
        uVar8 = param_1[10];
        uVar9 = param_1[0xb];
        puVar13[8] = param_1[8];
        puVar13[9] = uVar7;
        puVar13[10] = uVar8;
        puVar13[0xb] = uVar9;
        uVar7 = param_1[0xd];
        uVar8 = param_1[0xe];
        uVar9 = param_1[0xf];
        puVar13[0xc] = param_1[0xc];
        puVar13[0xd] = uVar7;
        puVar13[0xe] = uVar8;
        puVar13[0xf] = uVar9;
        uVar7 = param_1[0x11];
        uVar8 = param_1[0x12];
        uVar9 = param_1[0x13];
        puVar13[0x10] = param_1[0x10];
        puVar13[0x11] = uVar7;
        puVar13[0x12] = uVar8;
        puVar13[0x13] = uVar9;
        puVar1 = param_1 + 0x14;
        uVar7 = param_1[0x15];
        uVar8 = param_1[0x16];
        uVar9 = param_1[0x17];
        param_1 = (undefined4 *)((longlong)param_1 + (longlong)iVar6);
        puVar13[0x14] = *puVar1;
        puVar13[0x15] = uVar7;
        puVar13[0x16] = uVar8;
        puVar13[0x17] = uVar9;
        uVar12 = uVar12 - 1;
        puVar13 = puVar13 + 0x18;
      } while (uVar12 != 0);
    }
    if (0 < iVar5 * 0x60) {
      psVar16 = (short *)(param_2 + 4);
      do {
        bVar2 = (&stack0xfffffffffffffff8)[uVar14 + lVar11];
        bVar4 = (&stack0xfffffffffffffffb)[uVar14 + lVar11];
        bVar3 = (&stack0xfffffffffffffffd)[uVar14 + lVar11];
        psVar16[-2] = (ushort)(bVar2 & 0xf) * 0x100 +
                      (ushort)(byte)(&stack0xfffffffffffffff9)[uVar14 + lVar11];
        psVar16[-1] = (ushort)bVar4 * 0x10 + (ushort)(bVar2 >> 4);
        bVar2 = (&stack0xfffffffffffffffc)[uVar14 + lVar11];
        lVar10 = uVar14 + lVar11;
        uVar14 = uVar14 + 6;
        *psVar16 = (ushort)(bVar3 & 0xf) * 0x100 + (ushort)(byte)(&stack0xfffffffffffffffa)[lVar10];
        psVar16[1] = (ushort)bVar2 * 0x10 + (ushort)(bVar3 >> 4);
        psVar16 = psVar16 + 4;
      } while ((longlong)uVar14 < lVar15);
    }
  }
  else {
    if (0 < iVar5 / 2) {
      uVar12 = (ulonglong)(uint)(iVar5 / 2);
      do {
        uVar7 = param_1[1];
        uVar8 = param_1[2];
        uVar9 = param_1[3];
        *puVar13 = *param_1;
        puVar13[1] = uVar7;
        puVar13[2] = uVar8;
        puVar13[3] = uVar9;
        uVar7 = param_1[5];
        uVar8 = param_1[6];
        uVar9 = param_1[7];
        puVar13[4] = param_1[4];
        puVar13[5] = uVar7;
        puVar13[6] = uVar8;
        puVar13[7] = uVar9;
        uVar7 = param_1[9];
        uVar8 = param_1[10];
        uVar9 = param_1[0xb];
        puVar13[8] = param_1[8];
        puVar13[9] = uVar7;
        puVar13[10] = uVar8;
        puVar13[0xb] = uVar9;
        uVar7 = param_1[0xd];
        uVar8 = param_1[0xe];
        uVar9 = param_1[0xf];
        puVar13[0xc] = param_1[0xc];
        puVar13[0xd] = uVar7;
        puVar13[0xe] = uVar8;
        puVar13[0xf] = uVar9;
        uVar7 = param_1[0x11];
        uVar8 = param_1[0x12];
        uVar9 = param_1[0x13];
        puVar13[0x10] = param_1[0x10];
        puVar13[0x11] = uVar7;
        puVar13[0x12] = uVar8;
        puVar13[0x13] = uVar9;
        uVar7 = param_1[0x15];
        uVar8 = param_1[0x16];
        uVar9 = param_1[0x17];
        puVar13[0x14] = param_1[0x14];
        puVar13[0x15] = uVar7;
        puVar13[0x16] = uVar8;
        puVar13[0x17] = uVar9;
        uVar7 = param_1[0x19];
        uVar8 = param_1[0x1a];
        uVar9 = param_1[0x1b];
        puVar13[0x18] = param_1[0x18];
        puVar13[0x19] = uVar7;
        puVar13[0x1a] = uVar8;
        puVar13[0x1b] = uVar9;
        uVar7 = param_1[0x1d];
        uVar8 = param_1[0x1e];
        uVar9 = param_1[0x1f];
        puVar13[0x1c] = param_1[0x1c];
        puVar13[0x1d] = uVar7;
        puVar13[0x1e] = uVar8;
        puVar13[0x1f] = uVar9;
        uVar7 = param_1[0x21];
        uVar8 = param_1[0x22];
        uVar9 = param_1[0x23];
        puVar13[0x20] = param_1[0x20];
        puVar13[0x21] = uVar7;
        puVar13[0x22] = uVar8;
        puVar13[0x23] = uVar9;
        uVar7 = param_1[0x25];
        uVar8 = param_1[0x26];
        uVar9 = param_1[0x27];
        puVar13[0x24] = param_1[0x24];
        puVar13[0x25] = uVar7;
        puVar13[0x26] = uVar8;
        puVar13[0x27] = uVar9;
        uVar7 = param_1[0x29];
        uVar8 = param_1[0x2a];
        uVar9 = param_1[0x2b];
        puVar13[0x28] = param_1[0x28];
        puVar13[0x29] = uVar7;
        puVar13[0x2a] = uVar8;
        puVar13[0x2b] = uVar9;
        uVar7 = param_1[0x2d];
        uVar8 = param_1[0x2e];
        uVar9 = param_1[0x2f];
        puVar13[0x2c] = param_1[0x2c];
        puVar13[0x2d] = uVar7;
        puVar13[0x2e] = uVar8;
        puVar13[0x2f] = uVar9;
        uVar12 = uVar12 - 1;
        param_1 = (undefined4 *)((longlong)param_1 + (longlong)(iVar6 * 2));
        puVar13 = puVar13 + 0x30;
      } while (uVar12 != 0);
    }
    if (0 < lVar15) {
      psVar16 = (short *)(param_2 + ((longlong)(iVar5 << 5) + 2) * 2);
      psVar17 = (short *)(param_2 + 4);
      uVar12 = uVar14;
      do {
        bVar2 = (&stack0xfffffffffffffff8)[uVar12 + lVar11];
        bVar3 = (&stack0xfffffffffffffffb)[uVar12 + lVar11];
        if ((int)uVar14 % 0xc0 < 0x60) {
          bVar4 = (&stack0xfffffffffffffffd)[uVar12 + lVar11];
          psVar17[-2] = (ushort)(bVar2 & 0xf) * 0x100 +
                        (ushort)(byte)(&stack0xfffffffffffffff9)[uVar12 + lVar11];
          psVar17[-1] = (ushort)bVar3 * 0x10 + (ushort)(bVar2 >> 4);
          bVar2 = (&stack0xfffffffffffffffc)[uVar12 + lVar11];
          *psVar17 = (ushort)(bVar4 & 0xf) * 0x100 +
                     (ushort)(byte)(&stack0xfffffffffffffffa)[uVar12 + lVar11];
          psVar17[1] = (ushort)bVar2 * 0x10 + (ushort)(bVar4 >> 4);
          psVar17 = psVar17 + 4;
        }
        else {
          bVar4 = (&stack0xfffffffffffffffd)[uVar12 + lVar11];
          psVar16[-2] = (ushort)(bVar2 & 0xf) * 0x100 +
                        (ushort)(byte)(&stack0xfffffffffffffff9)[uVar12 + lVar11];
          psVar16[-1] = (ushort)bVar3 * 0x10 + (ushort)(bVar2 >> 4);
          bVar2 = (&stack0xfffffffffffffffc)[uVar12 + lVar11];
          *psVar16 = (ushort)(bVar4 & 0xf) * 0x100 +
                     (ushort)(byte)(&stack0xfffffffffffffffa)[uVar12 + lVar11];
          psVar16[1] = (ushort)bVar2 * 0x10 + (ushort)(bVar4 >> 4);
          psVar16 = psVar16 + 4;
        }
        uVar12 = uVar12 + 6;
        uVar14 = (ulonglong)((int)uVar14 + 6);
      } while ((longlong)uVar12 < lVar15);
    }
  }
  *(undefined8 *)((longlong)&uStack48 + lVar11) = 0x18000b51d;
  FUN_180018b70(local_38 ^ (ulonglong)(&stack0xffffffffffffffd8 + lVar11),
                *(undefined *)((longlong)&uStack48 + lVar11));
  return;
}



void FUN_18000b52c(longlong param_1)

{
  ushort uVar1;
  ulonglong uVar2;
  ushort uVar3;
  ushort uVar4;
  longlong lVar5;
  
  uVar3 = 0;
  lVar5 = 0xc;
  do {
    uVar2 = (ulonglong)uVar3;
    uVar1 = *(ushort *)(param_1 + uVar2 * 2);
    uVar4 = uVar1 & 0xfffe;
    *(ushort *)(param_1 + uVar2 * 2) = uVar4 * 0x80 + (uVar1 >> 1);
    if ((ushort)(uVar3 - 8) < 2) {
      *(ushort *)(param_1 + uVar2 * 2) = uVar4 << 7;
    }
    if ((ushort)(uVar3 - 10) < 2) {
      *(undefined2 *)(param_1 + uVar2 * 2) = 0;
    }
    uVar3 = uVar3 + 1;
    lVar5 = lVar5 + -1;
  } while (lVar5 != 0);
  return;
}



undefined8 FUN_18000b5b4(void)

{
  DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_18005b548);
  return 1;
}



ulonglong set_callbacks_FUN_18000b5d0(longlong param_1)

{
  if (param_1 != 0) {
                    // milanEGet_fd_data
    *(code **)(param_1 + 0xa990) = milanEGet_fdtdata_FUN_18000c3e0;
    *(code **)(param_1 + 0xa988) = FUN_18000c814;
    *(code **)(param_1 + 0xa980) = FUN_18000c904;
    *(code **)(param_1 + 0xa9a8) = FUN_18000b52c;
    *(code **)(param_1 + 0xa978) = FUN_18000ca8c;
                    // milanEGSetMode
    *(code **)(param_1 + 0xa970) = milanEGSetMode_FUN_18000bf8c;
    *(code **)(param_1 + 0xa998) = FUN_18000cb38;
    DAT_18005b540 = param_1;
    InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_18005b548);
  }
  return (ulonglong)(param_1 != 0);
}



void FUN_18000b660(undefined4 *param_1,longlong param_2,int param_3,uint param_4,int param_5,
                  int param_6,int param_7)

{
  undefined4 *puVar1;
  byte bVar2;
  byte bVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  ushort uVar7;
  uint uVar8;
  int iVar9;
  longlong lVar10;
  int iVar11;
  ulonglong uVar12;
  longlong lVar13;
  longlong lVar14;
  longlong lVar15;
  ulonglong uVar16;
  uint uVar17;
  int iVar18;
  undefined4 *puVar19;
  ulonglong uVar20;
  int iVar21;
  int iVar22;
  ulonglong local_48;
  undefined8 uStack64;
  
  uVar12 = (ulonglong)param_4;
  uStack64 = 0x18000b67d;
  lVar10 = _alloca_probe();
  lVar10 = -lVar10;
  local_48 = DAT_180037758 ^ (ulonglong)(&stack0xffffffffffffffc8 + lVar10);
  uVar12 = uVar12 & 0xffffffff;
  uVar16 = 0;
  *(undefined8 *)((longlong)&uStack64 + lVar10) = 0x18000b6b3;
  memset(&stack0xfffffffffffffff8 + lVar10,0,0x3860,*(undefined *)((longlong)&uStack64 + lVar10));
  puVar19 = (undefined4 *)(&stack0xfffffffffffffff8 + lVar10);
  iVar22 = (int)uVar12;
  iVar18 = (param_3 + -4) / iVar22;
  lVar15 = (longlong)(iVar22 * 0x52);
  if (param_6 == 0) {
    if (0 < iVar22) {
      do {
        uVar4 = param_1[1];
        uVar5 = param_1[2];
        uVar6 = param_1[3];
        *puVar19 = *param_1;
        puVar19[1] = uVar4;
        puVar19[2] = uVar5;
        puVar19[3] = uVar6;
        uVar4 = param_1[5];
        uVar5 = param_1[6];
        uVar6 = param_1[7];
        puVar19[4] = param_1[4];
        puVar19[5] = uVar4;
        puVar19[6] = uVar5;
        puVar19[7] = uVar6;
        uVar4 = param_1[9];
        uVar5 = param_1[10];
        uVar6 = param_1[0xb];
        puVar19[8] = param_1[8];
        puVar19[9] = uVar4;
        puVar19[10] = uVar5;
        puVar19[0xb] = uVar6;
        uVar4 = param_1[0xd];
        uVar5 = param_1[0xe];
        uVar6 = param_1[0xf];
        puVar19[0xc] = param_1[0xc];
        puVar19[0xd] = uVar4;
        puVar19[0xe] = uVar5;
        puVar19[0xf] = uVar6;
        uVar4 = param_1[0x11];
        uVar5 = param_1[0x12];
        uVar6 = param_1[0x13];
        puVar19[0x10] = param_1[0x10];
        puVar19[0x11] = uVar4;
        puVar19[0x12] = uVar5;
        puVar19[0x13] = uVar6;
        puVar1 = param_1 + 0x14;
        param_1 = (undefined4 *)((longlong)param_1 + (longlong)iVar18);
        *(undefined2 *)(puVar19 + 0x14) = *(undefined2 *)puVar1;
        uVar12 = uVar12 - 1;
        puVar19 = (undefined4 *)((longlong)puVar19 + 0x52);
      } while (uVar12 != 0);
    }
    if (0 < lVar15) {
      uVar12 = uVar16;
      uVar20 = uVar16;
      do {
        bVar2 = (&stack0xfffffffffffffff8)[uVar12 + lVar10];
        *(ushort *)(param_2 + uVar20 * 2) =
             (ushort)(bVar2 & 0xf) * 0x100 +
             (ushort)(byte)(&stack0xfffffffffffffff9)[uVar12 + lVar10];
        uVar7 = (ushort)(bVar2 >> 4);
        if ((int)uVar16 % 0x36 == 0x34) {
          iVar18 = 2;
          *(ushort *)(param_2 + 2 + uVar20 * 2) =
               (ushort)(byte)(&stack0xfffffffffffffffb)[uVar12 + lVar10] * 0x10 + uVar7;
          lVar13 = 2;
          lVar14 = 4;
        }
        else {
          bVar2 = (&stack0xfffffffffffffffd)[uVar12 + lVar10];
          *(ushort *)(param_2 + 2 + uVar20 * 2) =
               (ushort)(byte)(&stack0xfffffffffffffffb)[uVar12 + lVar10] * 0x10 + uVar7;
          bVar3 = (&stack0xfffffffffffffffc)[uVar12 + lVar10];
          *(ushort *)(param_2 + 4 + uVar20 * 2) =
               (ushort)(bVar2 & 0xf) * 0x100 +
               (ushort)(byte)(&stack0xfffffffffffffffa)[uVar12 + lVar10];
          *(ushort *)(param_2 + 6 + uVar20 * 2) = (ushort)bVar3 * 0x10 + (ushort)(bVar2 >> 4);
          iVar18 = 4;
          lVar13 = 4;
          lVar14 = 6;
        }
        uVar12 = uVar12 + lVar14;
        uVar16 = (ulonglong)(uint)((int)uVar16 + iVar18);
        uVar20 = uVar20 + lVar13;
      } while ((longlong)uVar12 < lVar15);
    }
  }
  else {
    uVar8 = iVar22 / 2;
    uVar12 = (ulonglong)uVar8;
    *(uint *)(&stack0xffffffffffffffe8 + lVar10) = uVar8;
    if (0 < (int)uVar8) {
      do {
        uVar4 = param_1[1];
        uVar5 = param_1[2];
        uVar6 = param_1[3];
        *puVar19 = *param_1;
        puVar19[1] = uVar4;
        puVar19[2] = uVar5;
        puVar19[3] = uVar6;
        uVar4 = param_1[5];
        uVar5 = param_1[6];
        uVar6 = param_1[7];
        puVar19[4] = param_1[4];
        puVar19[5] = uVar4;
        puVar19[6] = uVar5;
        puVar19[7] = uVar6;
        uVar4 = param_1[9];
        uVar5 = param_1[10];
        uVar6 = param_1[0xb];
        puVar19[8] = param_1[8];
        puVar19[9] = uVar4;
        puVar19[10] = uVar5;
        puVar19[0xb] = uVar6;
        uVar4 = param_1[0xd];
        uVar5 = param_1[0xe];
        uVar6 = param_1[0xf];
        puVar19[0xc] = param_1[0xc];
        puVar19[0xd] = uVar4;
        puVar19[0xe] = uVar5;
        puVar19[0xf] = uVar6;
        uVar4 = param_1[0x11];
        uVar5 = param_1[0x12];
        uVar6 = param_1[0x13];
        puVar19[0x10] = param_1[0x10];
        puVar19[0x11] = uVar4;
        puVar19[0x12] = uVar5;
        puVar19[0x13] = uVar6;
        uVar4 = param_1[0x15];
        uVar5 = param_1[0x16];
        uVar6 = param_1[0x17];
        puVar19[0x14] = param_1[0x14];
        puVar19[0x15] = uVar4;
        puVar19[0x16] = uVar5;
        puVar19[0x17] = uVar6;
        uVar4 = param_1[0x19];
        uVar5 = param_1[0x1a];
        uVar6 = param_1[0x1b];
        puVar19[0x18] = param_1[0x18];
        puVar19[0x19] = uVar4;
        puVar19[0x1a] = uVar5;
        puVar19[0x1b] = uVar6;
        uVar4 = param_1[0x1d];
        uVar5 = param_1[0x1e];
        uVar6 = param_1[0x1f];
        puVar19[0x1c] = param_1[0x1c];
        puVar19[0x1d] = uVar4;
        puVar19[0x1e] = uVar5;
        puVar19[0x1f] = uVar6;
        uVar4 = param_1[0x21];
        uVar5 = param_1[0x22];
        uVar6 = param_1[0x23];
        puVar19[0x20] = param_1[0x20];
        puVar19[0x21] = uVar4;
        puVar19[0x22] = uVar5;
        puVar19[0x23] = uVar6;
        uVar4 = param_1[0x25];
        uVar5 = param_1[0x26];
        uVar6 = param_1[0x27];
        puVar19[0x24] = param_1[0x24];
        puVar19[0x25] = uVar4;
        puVar19[0x26] = uVar5;
        puVar19[0x27] = uVar6;
        puVar1 = param_1 + 0x28;
        param_1 = (undefined4 *)((longlong)param_1 + (longlong)(iVar18 * 2));
        puVar19[0x28] = *puVar1;
        uVar12 = uVar12 - 1;
        puVar19 = puVar19 + 0x29;
      } while (uVar12 != 0);
    }
    uVar12 = uVar16;
    uVar20 = uVar16;
    if (0 < lVar15) {
      do {
        iVar18 = (int)uVar16;
        iVar21 = (int)uVar20;
        uVar8 = iVar21 / 0x52;
        if (iVar21 == uVar8 * 0x52) {
          if (param_7 == 0) {
            uVar17 = uVar8 & 0x80000001;
            if ((int)uVar17 < 0) {
              uVar17 = (uVar17 - 1 | 0xfffffffe) + 1;
            }
            iVar18 = uVar17 * *(int *)(&stack0xffffffffffffffe8 + lVar10) + (int)uVar8 / 2;
          }
          else {
            if (param_7 == 1) {
              if ((uVar8 & 1) != 0) {
                iVar18 = ((int)uVar8 / 2) * param_5;
                uVar17 = iVar18 >> 0x1f & 3;
                uVar8 = iVar18 + uVar17;
                iVar18 = (uVar8 & 3) - uVar17;
                uVar7 = *(ushort *)(&DAT_1800376a0 + (longlong)DAT_18005b4a0 * 0xe);
LAB_18000b97e:
                iVar18 = (iVar18 + (((int)((uVar7 - 1) + ((int)(uVar7 - 1) >> 0x1f & 3U)) >> 2) -
                                   ((int)uVar8 >> 2)) * 4) / param_5;
                goto LAB_18000b9f9;
              }
            }
            else {
              if (param_7 != 2) goto LAB_18000ba0d;
              uVar8 = (iVar22 - uVar8) - 1;
              if ((uVar8 & 1) == 0) {
                iVar18 = ((int)uVar8 / 2) * param_5;
                uVar17 = iVar18 >> 0x1f & 3;
                uVar8 = iVar18 + uVar17;
                iVar18 = (uVar8 & 3) - uVar17;
                uVar7 = *(ushort *)(&DAT_1800376a0 + (longlong)DAT_18005b4a0 * 0xe);
                goto LAB_18000b97e;
              }
            }
            iVar18 = (int)uVar8 / 2;
          }
LAB_18000b9f9:
          iVar18 = iVar18 * (uint)*(ushort *)(&DAT_1800376a2 + (longlong)DAT_18005b4a0 * 0xe);
        }
LAB_18000ba0d:
        bVar2 = (&stack0xfffffffffffffff8)[uVar12 + lVar10];
        *(ushort *)(param_2 + (longlong)iVar18 * 2) =
             (ushort)(bVar2 & 0xf) * 0x100 +
             (ushort)(byte)(&stack0xfffffffffffffff9)[uVar12 + lVar10];
        *(ushort *)(param_2 + (longlong)(iVar18 + 1) * 2) =
             (ushort)(byte)(&stack0xfffffffffffffffb)[uVar12 + lVar10] * 0x10 + (ushort)(bVar2 >> 4)
        ;
        if (iVar18 % 0x36 == 0x34) {
          iVar9 = 2;
          iVar11 = 4;
          lVar14 = 4;
        }
        else {
          bVar2 = (&stack0xfffffffffffffffd)[uVar12 + lVar10];
          *(ushort *)(param_2 + (longlong)(iVar18 + 2) * 2) =
               (ushort)(bVar2 & 0xf) * 0x100 +
               (ushort)(byte)(&stack0xfffffffffffffffa)[uVar12 + lVar10];
          iVar9 = 4;
          *(ushort *)(param_2 + (longlong)(iVar18 + 3) * 2) =
               (ushort)(byte)(&stack0xfffffffffffffffc)[uVar12 + lVar10] * 0x10 +
               (ushort)(bVar2 >> 4);
          iVar11 = 6;
          lVar14 = 6;
        }
        uVar12 = uVar12 + lVar14;
        uVar16 = (ulonglong)(uint)(iVar18 + iVar9);
        uVar20 = (ulonglong)(uint)(iVar21 + iVar11);
      } while ((longlong)uVar12 < lVar15);
    }
  }
  *(undefined8 *)((longlong)&uStack64 + lVar10) = 0x18000bafc;
  FUN_180018b70(local_48 ^ (ulonglong)(&stack0xffffffffffffffc8 + lVar10),
                *(undefined *)((longlong)&uStack64 + lVar10));
  return;
}



void gfFDTDownbase_FUN_18000bb10(ushort *param_1)

{
  ushort uVar1;
  char cVar2;
  longlong lVar3;
  ulonglong uVar4;
  short sVar5;
  
  uVar4 = 0;
  lVar3 = 0xc;
  do {
    uVar1 = *param_1;
    cVar2 = (char)uVar4;
    if ((byte)(cVar2 - 8U) < 2) {
      sVar5 = (uVar1 & 0xfffe) << 7;
    }
    else {
      sVar5 = (uVar1 & 0xfffe) * 0x80 + (uVar1 >> 1);
    }
    if ((byte)(cVar2 - 10U) < 2) {
      sVar5 = 0;
    }
    *(short *)((longlong)&DAT_18004e988 + uVar4 * 2) = sVar5;
    FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,10,&DAT_180020f58,cVar2,(char)sVar5
                 );
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanEG.c",
               (undefined *)L"gfFDTDownbase",99,0,(undefined *)L"fdt_downbase[%d]:0x%x");
    uVar4 = (ulonglong)(byte)(cVar2 + 1);
    param_1 = param_1 + 1;
    lVar3 = lVar3 + -1;
  } while (lVar3 != 0);
  return;
}



void gfDFTUPbase_FUN_18000bc3c(byte *param_1,int param_2)

{
  short sVar1;
  ushort uVar2;
  code *pcVar3;
  ulonglong uVar4;
  longlong lVar5;
  ulonglong uVar6;
  uint uVar7;
  ushort uVar8;
  longlong lVar9;
  ushort uVar10;
  byte bVar11;
  byte bVar12;
  uint local_60;
  uint local_58;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  ulonglong local_30;
  
  lVar5 = DAT_18005b540;
  local_30 = DAT_180037758 ^ (ulonglong)&stack0xffffffffffffff68;
  lVar9 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  bVar11 = 0;
  if ((DAT_18005b540 != 0) && (param_1 != (byte *)0x0)) {
    sVar1 = *(short *)(DAT_18005b540 + 0x50de);
    uVar6 = 0;
    uVar8 = (ushort)param_1[1] * 0x100 + (ushort)*param_1;
    do {
      uVar10 = *(ushort *)(param_1 + uVar6 + 2) >> 1;
      if (sVar1 == 0) {
        uVar2 = (uVar10 + 0x15) * 0x100;
        uVar4 = (ulonglong)bVar11 * 2;
        uVar10 = uVar2 | uVar10 + 0x15;
        if ((byte)(bVar11 - 8) < 2) {
          uVar10 = uVar2;
        }
        *(ushort *)((longlong)&local_48 + uVar4) = uVar10;
        if ((byte)(bVar11 - 10) < 2) {
          if (0x17 < uVar4) {
            __report_rangecheckfailure();
            pcVar3 = (code *)swi(3);
            (*pcVar3)();
            return;
          }
          *(undefined2 *)((longlong)&local_48 + uVar4) = 0;
        }
      }
      else {
        uVar2 = (sVar1 + uVar10) * 0x100;
        uVar4 = (ulonglong)bVar11 * 2;
        uVar10 = uVar10 + 0x15 | uVar2;
        if ((byte)(bVar11 - 8) < 2) {
          uVar10 = uVar2;
        }
        *(ushort *)((longlong)&local_48 + uVar4) = uVar10;
        if ((byte)(bVar11 - 10) < 2) {
          if (0x17 < uVar4) {
            __report_rangecheckfailure();
            pcVar3 = (code *)swi(3);
            (*pcVar3)();
            return;
          }
          *(undefined2 *)((longlong)&local_48 + uVar4) = 0;
        }
      }
      bVar11 = bVar11 + 1;
      bVar12 = (char)uVar6 + 2;
      uVar6 = (ulonglong)bVar12;
    } while (bVar12 < 0x18);
    if (param_2 == 0) {
      if (*(int *)(DAT_18005b540 + 0x50fc) == 1) {
        uVar8 = uVar8 | *(ushort *)(DAT_18005b540 + 0xa868);
        local_60 = (uint)uVar8;
        FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0xb,&DAT_180020f58,(char)uVar8)
        ;
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanEG.c",
                   (undefined *)L"gfFDTUPbase",0x9b,0,(undefined *)L"get new touchflag:0x%x");
      }
      uVar6 = 0;
      do {
        bVar11 = (byte)uVar6;
        if ((uVar8 >> (bVar11 & 0x1f) & 1) == 0) {
          sVar1 = *(short *)(lVar5 + 0x50de);
          if (sVar1 == 0) {
            uVar6 = uVar6 * 2;
            *(ushort *)((longlong)&local_48 + uVar6) =
                 *(byte *)((longlong)&local_48 + uVar6 + 1) | 0x1300;
            if ((byte)(bVar11 - 10) < 2) {
              if (0x17 < uVar6) {
                __report_rangecheckfailure();
                pcVar3 = (code *)swi(3);
                (*pcVar3)();
                return;
              }
              *(undefined2 *)((longlong)&local_48 + uVar6) = 0;
            }
          }
          else {
            uVar6 = uVar6 * 2;
            *(ushort *)((longlong)&local_48 + uVar6) =
                 (ushort)*(byte *)((longlong)&local_48 + uVar6 + 1) | (sVar1 + -2) * 0x100;
            if ((byte)(bVar11 - 10) < 2) {
              if (0x17 < uVar6) {
                __report_rangecheckfailure();
                pcVar3 = (code *)swi(3);
                (*pcVar3)();
                return;
              }
              *(undefined2 *)((longlong)&local_48 + uVar6) = 0;
            }
          }
        }
        uVar6 = (ulonglong)(byte)(bVar11 + 1);
      } while ((byte)(bVar11 + 1) < 0xc);
    }
    uVar7 = 0;
    do {
      if (*(int *)(lVar5 + 0x50fc) == 1) {
        uVar10 = *(ushort *)((longlong)&local_48 + lVar9);
        uVar8 = *(ushort *)((longlong)&DAT_18004e9a8 + lVar9);
        if (uVar10 < *(ushort *)((longlong)&DAT_18004e9a8 + lVar9)) {
          *(ushort *)((longlong)&DAT_18004e9a8 + lVar9) = uVar10;
          uVar8 = uVar10;
        }
      }
      else {
        uVar8 = *(ushort *)((longlong)&local_48 + lVar9);
        *(ushort *)((longlong)&DAT_18004e9a8 + lVar9) = uVar8;
      }
      FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0xc,&DAT_180020f58,(char)uVar7,
                    (char)uVar8);
      local_58 = (uint)*(ushort *)((longlong)&DAT_18004e9a8 + lVar9);
      local_60 = uVar7;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanEG.c",
                 (undefined *)L"gfFDTUPbase",0xbf,0,(undefined *)L"fdt_upbase[%d]:0x%x");
      bVar11 = (char)uVar7 + 1;
      uVar7 = (uint)bVar11;
      lVar9 = lVar9 + 2;
    } while (bVar11 < 0xc);
  }
  FUN_180018b70(local_30 ^ (ulonglong)&stack0xffffffffffffff68);
  return;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void milanEGSetMode_FUN_18000bf8c(byte mode,ulonglong param_2,byte param_3)

{
  char cVar1;
  int iVar2;
  byte bVar3;
  uint uVar4;
  longlong lVar5;
  uint uVar6;
  byte bVar7;
  longlong lVar8;
  byte bVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  uint local_b0;
  uint local_a8;
  uint local_98;
  longlong local_90;
  short local_88;
  undefined local_86 [16];
  undefined8 local_76;
  ulonglong local_48;
  
  local_48 = DAT_180037758 ^ (ulonglong)&stack0xffffffffffffff18;
  memset(&local_88,0,0x40);
  bVar3 = 0;
  if (DAT_18005b540 == (longlong *)0x0) goto LAB_18000c3b6;
  lVar8 = *DAT_18005b540;
  local_90 = lVar8;
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18005b548);
  uVar6 = (uint)mode;
  local_98 = (uint)mode;
  bVar9 = (byte)(param_2 & 0xff);
  if (uVar6 == 2) {
    iVar2 = 100;
    local_88 = 1;
    cVar1 = UsbSendDataToDevice_FUN_180012240(lVar8,2,0,(undefined8 *)&local_88,2,'\x01',100);
    if (cVar1 == '\0') {
      bVar3 = 2;
      goto LAB_18000c30f;
    }
    goto LAB_18000c32f;
  }
  if (uVar6 == 3) {
    if (bVar9 == 1) {
      bVar3 = param_3 * ' ' + 2;
      local_88 = CONCAT11(param_3,0xc);
      uVar10 = _DAT_18004e988;
      uVar11 = DAT_18004e98c;
      uVar12 = DAT_18004e990;
      uVar13 = DAT_18004e994;
      local_76 = DAT_18004e998;
LAB_18000c28f:
      local_86 = CONCAT412(uVar13,CONCAT48(uVar12,CONCAT44(uVar11,uVar10)));
    }
    else {
      if (bVar9 == 2) {
        bVar3 = param_3 * ' ' + 2;
        local_88 = CONCAT11(param_3,0xe);
        uVar10 = _DAT_18004e9a8;
        uVar11 = DAT_18004e9ac;
        uVar12 = DAT_18004e9b0;
        uVar13 = DAT_18004e9b4;
        local_76 = DAT_18004e9b8;
        goto LAB_18000c28f;
      }
      if (bVar9 == 3) {
        bVar3 = param_3 * ' ' + 2;
        local_88 = CONCAT11(param_3,0xd);
        uVar6 = 0;
        lVar5 = 0;
        do {
          *(undefined2 *)((longlong)&DAT_18004e9c8 + lVar5) =
               *(undefined2 *)((longlong)&DAT_18004e988 + lVar5);
          FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0xd,&DAT_180020f58,
                        (char)uVar6,(char)*(undefined2 *)((longlong)&DAT_18004e988 + lVar5));
          local_a8 = (uint)*(ushort *)((longlong)&DAT_18004e9c8 + lVar5);
          local_b0 = uVar6;
          debug_print_FUN_180001ce4
                    ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanEG.c",
                     (undefined *)L"milanEGSetMode",0x228,0,(undefined *)L"fdt_manualbase[%d]:0x%x")
          ;
          bVar7 = (char)uVar6 + 1;
          uVar6 = (uint)bVar7;
          lVar5 = lVar5 + 2;
          lVar8 = local_90;
          uVar10 = _DAT_18004e9c8;
          uVar11 = DAT_18004e9cc;
          uVar12 = DAT_18004e9d0;
          uVar13 = DAT_18004e9d4;
          local_76 = DAT_18004e9d8;
        } while (bVar7 < 0xc);
        goto LAB_18000c28f;
      }
    }
    uVar6 = local_98;
    uVar4 = (uint)bVar3;
    cVar1 = UsbSendDataToDevice_FUN_180012240
                      (lVar8,3,bVar9,(undefined8 *)&local_88,uVar4,'\x01',100);
    if (cVar1 == '\0') {
      iVar2 = 100;
      bVar3 = 3;
      bVar7 = bVar9;
LAB_18000c320:
      UsbSendDataToDevice_FUN_180012240
                (lVar8,bVar3,bVar7,(undefined8 *)&local_88,uVar4,'\x01',iVar2);
    }
  }
  else {
    if (uVar6 == 4) {
      local_88 = (ushort)param_3 << 8;
      local_76 = DAT_18004e978;
      uVar4 = (uint)(byte)(param_3 * ' ' + 2);
      local_86 = CONCAT412(DAT_18004e974,
                           CONCAT48(DAT_18004e970,CONCAT44(DAT_18004e96c,DAT_18004e968)));
      cVar1 = UsbSendDataToDevice_FUN_180012240(lVar8,4,0,(undefined8 *)&local_88,uVar4,'\x01',100);
      if (cVar1 == '\0') {
        iVar2 = 100;
        bVar3 = 4;
LAB_18000c31d:
        bVar7 = 0;
        goto LAB_18000c320;
      }
    }
    else {
      if (uVar6 == 5) {
        iVar2 = 200;
        local_88 = 1;
        cVar1 = UsbSendDataToDevice_FUN_180012240(lVar8,5,0,(undefined8 *)&local_88,2,'\x01',200);
        if (cVar1 == '\0') {
          bVar3 = 5;
LAB_18000c30f:
          uVar4 = 2;
          goto LAB_18000c31d;
        }
      }
      else {
        if (uVar6 == 6) {
          iVar2 = 100;
          local_88 = 1;
          cVar1 = UsbSendDataToDevice_FUN_180012240(lVar8,6,0,(undefined8 *)&local_88,2,'\x01',100);
          if (cVar1 == '\0') {
            bVar3 = 6;
            goto LAB_18000c30f;
          }
        }
        else {
          if (uVar6 == 7) {
            iVar2 = 200;
            local_88 = 0x14;
            cVar1 = UsbSendDataToDevice_FUN_180012240
                              (lVar8,7,0,(undefined8 *)&local_88,2,'\x01',200);
            if (cVar1 == '\0') {
              bVar3 = 7;
              goto LAB_18000c30f;
            }
          }
        }
      }
    }
  }
LAB_18000c32f:
  FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0xe,&DAT_180020f58,(char)uVar6,bVar9)
  ;
  local_b0 = uVar6;
  local_a8 = (uint)(param_2 & 0xff);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanEG.c",
             (undefined *)L"milanEGSetMode",0x26d,0,(undefined *)L"change mode to %d type:%d");
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18005b548);
LAB_18000c3b6:
  FUN_180018b70(local_48 ^ (ulonglong)&stack0xffffffffffffff18);
  return;
}



void milanEGet_fdtdata_FUN_18000c3e0(byte *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  longlong lVar3;
  ushort uVar4;
  undefined4 uVar5;
  wchar_t *pwVar6;
  
  lVar3 = DAT_18005b540;
  if (DAT_18005b540 == 0) {
    return;
  }
  uVar4 = (ushort)param_1[1] * 0x100 + (ushort)*param_1;
  FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0xf,&DAT_180020f58,(char)uVar4);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"gf_milanEG.c",
             (undefined *)L"milanEGget_fdtdata",0x27c,0,(undefined *)L"MilanIrqStatus:0x%x");
  if (uVar4 < 0x21) {
    if (uVar4 == 0x20) {
      return;
    }
    if (uVar4 == 0) {
      return;
    }
    if (uVar4 == 1) {
      return;
    }
    if (uVar4 == 2) {
      FUN_18000234c(*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
      *(ushort *)(lVar3 + 0xa868) = (ushort)param_1[3] * 0x100 + (ushort)param_1[2];
      gfDFTUPbase_FUN_18000bc3c(param_1 + 2,0);
      *(undefined4 *)(lVar3 + 0x50d8) = 1;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x10,&DAT_180020f58);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanEG.c",
                 (undefined *)L"milanEGget_fdtdata",0x28b,0,
                 (undefined *)L"got data for GF_FDT_DOWN_MODE");
      FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x11,&DAT_180020f58,
                    (char)*(undefined2 *)(lVar3 + 0xa868));
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanEG.c",
                 (undefined *)L"milanEGget_fdtdata",0x28d,0,
                 (undefined *)L"devcontext->touchflag:0x%x");
      return;
    }
    if (uVar4 == 4) {
      return;
    }
    if (uVar4 == 8) {
      return;
    }
    if (uVar4 == 0x10) {
      return;
    }
  }
  else {
    if (uVar4 == 0x40) {
      return;
    }
    if ((uVar4 == 0x80) || (uVar4 == 0x82)) {
      gfFDTDownbase_FUN_18000bb10((ushort *)(param_1 + 4));
      *(undefined4 *)(lVar3 + 0x50d8) = 8;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x12,&DAT_180020f58);
      pwVar6 = L"got data for GF_REVERSE_MODE";
      uVar5 = 0x29f;
      goto LAB_18000c7de;
    }
    if (uVar4 == 0x100) {
      FUN_18000234c(*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
      uVar5 = *(undefined4 *)(param_1 + 8);
      uVar1 = *(undefined4 *)(param_1 + 0xc);
      uVar2 = *(undefined4 *)(param_1 + 0x10);
      *(undefined4 *)(lVar3 + 0xa848) = *(undefined4 *)(param_1 + 4);
      *(undefined4 *)(lVar3 + 0xa84c) = uVar5;
      *(undefined4 *)(lVar3 + 0xa850) = uVar1;
      *(undefined4 *)(lVar3 + 0xa854) = uVar2;
      *(undefined8 *)(lVar3 + 0xa858) = *(undefined8 *)(param_1 + 0x14);
      if (*(int *)(lVar3 + 0x50fc) == 1) {
        gfDFTUPbase_FUN_18000bc3c(param_1 + 2,0);
      }
      else {
        gfFDTDownbase_FUN_18000bb10((ushort *)(param_1 + 4));
      }
      *(undefined4 *)(lVar3 + 0x50d8) = 3;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x13,&DAT_180020f58);
      pwVar6 = L"got data for GF_FDT_MANUAL";
      uVar5 = 0x2af;
      goto LAB_18000c7de;
    }
    if (uVar4 == 0x200) {
      gfFDTDownbase_FUN_18000bb10((ushort *)(param_1 + 4));
      *(undefined4 *)(lVar3 + 0x50fc) = 0;
      *(undefined4 *)(lVar3 + 0x50d8) = 2;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x14,&DAT_180020f58);
      pwVar6 = L"got data for GF_FDT_UP_MODE";
      uVar5 = 0x2b7;
      goto LAB_18000c7de;
    }
    if (uVar4 == 0x400) {
      *(undefined4 *)(lVar3 + 0x50fc) = 0;
      *(undefined4 *)(lVar3 + 0x50d8) = 9;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x15,&DAT_180020f58);
      pwVar6 = L"Got fingerprint module reset event";
      uVar5 = 0x2bd;
      goto LAB_18000c7de;
    }
  }
  *(undefined4 *)(lVar3 + 0x50fc) = 0;
  pwVar6 = L"got data for abnormal irq";
  uVar5 = 0x2c2;
  *(undefined4 *)(lVar3 + 0x50d8) = 9;
LAB_18000c7de:
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanEG.c",
             (undefined *)L"milanEGget_fdtdata",uVar5,0,(undefined *)pwVar6);
  return;
}



undefined8 * FUN_18000c814(undefined4 *param_1,ushort param_2)

{
  undefined8 *_Memory;
  ulonglong uVar1;
  ulonglong extraout_RAX;
  
  _Memory = (undefined8 *)
            malloc((ulonglong)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe))
  ;
  if (_Memory != (undefined8 *)0x0) {
    uVar1 = FUN_18000b178((byte *)param_1,param_2);
    if ((char)uVar1 == '\0') {
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
      if (DAT_18005b4a0 == 1) {
        FUN_18000b1dc(param_1,(longlong)_Memory,(uint)param_2,0x10,0);
      }
      else {
        if (DAT_18005b4a0 == 2) {
          FUN_18000b660(param_1,(longlong)_Memory,(uint)param_2,0x10,4,0,0);
        }
      }
      FUN_1800022e0(_Memory,(ulonglong)
                            *(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe));
    }
    free(_Memory);
    _Memory = (undefined8 *)(extraout_RAX & 0xffffffffffffff00 | uVar1);
  }
  return _Memory;
}



ulonglong FUN_18000c904(undefined4 *param_1,ushort param_2)

{
  int iVar1;
  void *_Memory;
  undefined8 *_Memory_00;
  ulonglong uVar2;
  ulonglong extraout_RAX;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  ulonglong uVar6;
  
  _Memory = malloc((ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe))
  ;
  _Memory_00 = (undefined8 *)
               malloc((ulonglong)
                      *(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
  if ((_Memory == (void *)0x0) || (_Memory_00 == (undefined8 *)0x0)) {
    uVar2 = (ulonglong)_Memory_00 & 0xffffffffffffff00;
  }
  else {
    uVar2 = FUN_18000b178((byte *)param_1,param_2);
    if ((char)uVar2 == '\0') {
      uVar2 = 0;
    }
    else {
      uVar2 = 1;
      if (DAT_18005b4a0 == 1) {
        FUN_18000b1dc(param_1,(longlong)_Memory,0x4624,0xb0,0);
        uVar6 = 0;
        uVar3 = 0;
        do {
          uVar5 = 0;
          do {
            uVar4 = uVar5 + 1;
            *(undefined2 *)((longlong)_Memory_00 + uVar6 * 2) =
                 *(undefined2 *)((longlong)_Memory + (ulonglong)(uVar5 * 0x40 + uVar3) * 2);
            uVar6 = (ulonglong)((int)uVar6 + 1);
            uVar5 = uVar4;
          } while (uVar4 < 0xb0);
          uVar3 = uVar3 + 1;
        } while (uVar3 < 0x40);
      }
      else {
        if (DAT_18005b4a0 == 2) {
          FUN_18000b660(param_1,(longlong)_Memory,0x4624,0xb0,1,0,0);
          uVar6 = 0;
          uVar3 = 0;
          do {
            uVar5 = 0;
            do {
              iVar1 = uVar5 * 0x36;
              uVar5 = uVar5 + 1;
              *(undefined2 *)((longlong)_Memory_00 + uVar6 * 2) =
                   *(undefined2 *)((longlong)_Memory + (ulonglong)(iVar1 + uVar3) * 2);
              uVar6 = (ulonglong)((int)uVar6 + 1);
            } while (uVar5 < 0xb0);
            uVar3 = uVar3 + 1;
          } while (uVar3 < 0x36);
        }
      }
      FUN_1800022e0(_Memory_00,
                    (ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe)
                   );
    }
    free(_Memory);
    free(_Memory_00);
    uVar2 = extraout_RAX & 0xffffffffffffff00 | uVar2;
  }
  return uVar2;
}



void FUN_18000ca8c(char param_1,short *param_2)

{
  short sVar1;
  short sVar2;
  undefined local_res18;
  undefined local_res19;
  
  sVar1 = 0;
  if (DAT_18005b540 == 0) {
    return;
  }
  if (*(ushort *)(DAT_18005b540 + 0x50dc) != 0) {
    sVar1 = (short)(0x200 / (ulonglong)*(ushort *)(DAT_18005b540 + 0x50dc));
  }
  sVar2 = *(short *)(DAT_18005b540 + 0x5128);
  if (param_1 == '\0') {
    sVar1 = sVar1 << 4;
  }
  else {
    if (param_1 != '\x01') {
      local_res18 = (undefined)sVar2;
      local_res19 = *(undefined *)(DAT_18005b540 + 0x5129);
      goto LAB_18000cb03;
    }
    sVar1 = sVar1 * -0x10;
  }
  sVar2 = sVar2 + sVar1;
  local_res18 = (undefined)sVar2;
  local_res19 = (undefined)((ushort)sVar2 >> 8);
LAB_18000cb03:
  FUN_180011880(0x220,&local_res18,2,100);
  if (param_2 != (short *)0x0) {
    *param_2 = sVar2;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_18000cb38(undefined4 *param_1,char param_2)

{
  if (param_1 != (undefined4 *)0x0) {
    if (param_2 == '\0') {
      _DAT_18004e988 = *param_1;
      DAT_18004e98c = param_1[1];
      DAT_18004e990 = param_1[2];
      DAT_18004e994 = param_1[3];
      DAT_18004e998 = *(undefined8 *)(param_1 + 4);
    }
    else {
      if (param_2 == '\x01') {
        _DAT_18004e988 = *param_1;
        DAT_18004e98c = param_1[1];
        DAT_18004e990 = param_1[2];
        DAT_18004e994 = param_1[3];
        DAT_18004e998 = *(undefined8 *)(param_1 + 4);
        return;
      }
    }
    _DAT_18004e9a8 = *param_1;
    DAT_18004e9ac = param_1[1];
    DAT_18004e9b0 = param_1[2];
    DAT_18004e9b4 = param_1[3];
    DAT_18004e9b8 = *(undefined8 *)(param_1 + 4);
  }
  return;
}



undefined8 FUN_18000cbb4(void)

{
  DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_18005b508);
  return 1;
}



ulonglong FUN_18000cbd0(longlong param_1)

{
  if (param_1 != 0) {
    *(code **)(param_1 + 0xa990) = FUN_18000d448;
    *(undefined **)(param_1 + 0xa9a0) = &LAB_18000d8d8;
    *(undefined **)(param_1 + 0xa980) = &LAB_18000d954;
    *(undefined **)(param_1 + 0xa9a8) = &LAB_18000cb90;
    *(code **)(param_1 + 0xa978) = FUN_18000d9f0;
    *(undefined **)(param_1 + 0xa970) = &LAB_18000d014;
    *(undefined **)(param_1 + 0xa998) = &LAB_18000da9c;
    DAT_18005b500 = param_1;
    InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_18005b508);
  }
  return (ulonglong)(param_1 != 0);
}



void FUN_18000cc60(ushort *param_1)

{
  short sVar1;
  longlong lVar2;
  byte bVar3;
  
  lVar2 = 0xc;
  bVar3 = 0;
  do {
    sVar1 = (*param_1 | 1) << 7;
    *(short *)((longlong)&DAT_18004ea00 + (ulonglong)bVar3 * 2) = sVar1;
    FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,10,&DAT_1800212d0,bVar3,(char)sVar1
                 );
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanF.c",
               (undefined *)L"gfFDTDownbase",0x44,0,(undefined *)L"fdt_downbase[%d]:0x%x");
    bVar3 = bVar3 + 1;
    param_1 = param_1 + 1;
    lVar2 = lVar2 + -1;
  } while (lVar2 != 0);
  return;
}



void FUN_18000cd54(byte *param_1)

{
  ushort uVar1;
  longlong lVar2;
  ushort uVar3;
  short sVar4;
  ushort *puVar5;
  byte bVar6;
  ulonglong uVar7;
  longlong lVar8;
  longlong lVar9;
  ushort *puVar10;
  ushort uVar11;
  uint local_60;
  uint local_58;
  ulonglong local_30;
  
  lVar2 = DAT_18005b500;
  local_30 = DAT_180037758 ^ (ulonglong)&stack0xffffffffffffff68;
  uVar7 = 0;
  if (DAT_18005b500 != 0) {
    uVar11 = (ushort)param_1[1] * 0x100 + (ushort)*param_1;
    local_60 = (uint)uVar11;
    FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0xb,&DAT_1800212d0,(char)uVar11);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanF.c",(undefined *)L"gfFDTUPbase"
               ,0x5a,0,(undefined *)L"touchflag:0x%x");
    puVar10 = (ushort *)(param_1 + 2);
    lVar9 = 0xc;
    puVar5 = puVar10;
    lVar8 = lVar9;
    do {
      if (*(short *)(lVar2 + 0x50de) == 0) {
        sVar4 = (*puVar5 >> 1) + 0x15;
      }
      else {
        sVar4 = (*puVar5 >> 1) + *(short *)(lVar2 + 0x50de);
      }
      *puVar5 = sVar4 * 0x100 | 0x80;
      puVar5 = puVar5 + 1;
      lVar8 = lVar8 + -1;
    } while (lVar8 != 0);
    if (*(int *)(lVar2 + 0x50fc) == 1) {
      uVar11 = uVar11 | *(ushort *)(lVar2 + 0xa868);
      FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0xc,&DAT_1800212d0,(char)uVar11);
      local_60 = (uint)uVar11;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanF.c",
                 (undefined *)L"gfFDTUPbase",0x6a,0,(undefined *)L"get new touchflag:0x%x");
    }
    do {
      bVar6 = (byte)uVar7;
      if ((uVar11 >> (bVar6 & 0x1f) & 1) == 0) {
        if (*(short *)(lVar2 + 0x50de) == 0) {
          uVar3 = 0x1380;
        }
        else {
          uVar3 = (*(short *)(lVar2 + 0x50de) + -2) * 0x100 | 0x80;
        }
        *puVar10 = uVar3;
      }
      puVar5 = (ushort *)((longlong)&DAT_18004ea18 + uVar7 * 2);
      if (*(int *)(lVar2 + 0x50fc) == 1) {
        uVar1 = *puVar10;
        uVar3 = *puVar5;
        if (uVar1 < *puVar5) {
          *puVar5 = uVar1;
          uVar3 = uVar1;
        }
      }
      else {
        uVar3 = *puVar10;
        *puVar5 = uVar3;
      }
      FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0xd,&DAT_1800212d0,bVar6,
                    (char)uVar3);
      local_58 = (uint)*puVar5;
      local_60 = (uint)uVar7;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanF.c",
                 (undefined *)L"gfFDTUPbase",0x83,0,(undefined *)L"fdt_upbase[%d]:0x%x");
      puVar10 = puVar10 + 1;
      uVar7 = (ulonglong)(byte)(bVar6 + 1);
      lVar9 = lVar9 + -1;
    } while (lVar9 != 0);
  }
  FUN_180018b70(local_30 ^ (ulonglong)&stack0xffffffffffffff68);
  return;
}



void FUN_18000d448(byte *param_1,char param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  longlong lVar3;
  ushort uVar4;
  undefined4 uVar5;
  wchar_t *pwVar6;
  
  lVar3 = DAT_18005b500;
  if (DAT_18005b500 == 0) {
    return;
  }
  uVar4 = (ushort)param_1[1] * 0x100 + (ushort)*param_1;
  FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x10,&DAT_1800212d0,(char)uVar4);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanF.c",
             (undefined *)L"milanFget_fdtdata",0x154,0,(undefined *)L"MilanIrqStatus:0x%x");
  if (param_2 == '\x03') {
    FUN_18000234c(*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
    uVar5 = *(undefined4 *)(param_1 + 8);
    uVar1 = *(undefined4 *)(param_1 + 0xc);
    uVar2 = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(lVar3 + 0xa848) = *(undefined4 *)(param_1 + 4);
    *(undefined4 *)(lVar3 + 0xa84c) = uVar5;
    *(undefined4 *)(lVar3 + 0xa850) = uVar1;
    *(undefined4 *)(lVar3 + 0xa854) = uVar2;
    *(undefined8 *)(lVar3 + 0xa858) = *(undefined8 *)(param_1 + 0x14);
    if (*(int *)(lVar3 + 0x50fc) == 1) {
      FUN_18000cd54(param_1 + 2);
    }
    else {
      FUN_18000cc60((ushort *)(param_1 + 4));
    }
    FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x11,&DAT_1800212d0,param_1[2]);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanF.c",
               (undefined *)L"milanFget_fdtdata",0x163,0,(undefined *)L"fdt manual touchflag:0x%x");
    *(undefined4 *)(lVar3 + 0x50d8) = 3;
    return;
  }
  if (uVar4 < 0x11) {
    if (uVar4 == 0x10) {
      return;
    }
    if (uVar4 == 0) {
      return;
    }
    if (uVar4 == 1) {
      return;
    }
    if (uVar4 == 2) {
      FUN_18000234c(*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
      if (param_2 != '\x02') {
        if (param_2 != '\x01') {
          return;
        }
        *(ushort *)(lVar3 + 0xa868) = (ushort)param_1[3] * 0x100 + (ushort)param_1[2];
        FUN_18000cd54(param_1 + 2);
        *(undefined4 *)(lVar3 + 0x50d8) = 1;
        FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x13,&DAT_1800212d0);
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanF.c",
                   (undefined *)L"milanFget_fdtdata",0x180,0,
                   (undefined *)L"got data for GF_FDT_DOWN_MODE");
        FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x14,&DAT_1800212d0,
                      (char)*(undefined2 *)(lVar3 + 0xa868));
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanF.c",
                   (undefined *)L"milanFget_fdtdata",0x182,0,
                   (undefined *)L"devcontext->touchflag:0x%x");
        return;
      }
      FUN_18000cc60((ushort *)(param_1 + 4));
      *(undefined4 *)(lVar3 + 0x50fc) = 0;
      *(undefined4 *)(lVar3 + 0x50d8) = 2;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x12,&DAT_1800212d0);
      pwVar6 = L"got data for GF_FDT_UP_MODE";
      uVar5 = 0x176;
      goto LAB_18000d8a0;
    }
    if (uVar4 == 4) {
      return;
    }
    if (uVar4 == 8) {
      return;
    }
  }
  else {
    if (uVar4 == 0x20) {
      return;
    }
    if (uVar4 == 0x40) {
      return;
    }
    if ((uVar4 == 0x80) || (uVar4 == 0x82)) {
      FUN_18000cc60((ushort *)(param_1 + 4));
      *(undefined4 *)(lVar3 + 0x50d8) = 8;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x15,&DAT_1800212d0);
      pwVar6 = L"got data for GF_REVERSE_MODE";
      uVar5 = 0x197;
      goto LAB_18000d8a0;
    }
    if (uVar4 == 0x100) {
      *(undefined4 *)(lVar3 + 0x50fc) = 0;
      *(undefined4 *)(lVar3 + 0x50d8) = 9;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x16,&DAT_1800212d0);
      pwVar6 = L"got data for GF_DETECT_FP_RESET_MODE";
      uVar5 = 0x19d;
      goto LAB_18000d8a0;
    }
  }
  *(undefined4 *)(lVar3 + 0x50fc) = 0;
  pwVar6 = L"got data for abnormal irq";
  uVar5 = 0x1a2;
  *(undefined4 *)(lVar3 + 0x50d8) = 9;
LAB_18000d8a0:
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanF.c",
             (undefined *)L"milanFget_fdtdata",uVar5,0,(undefined *)pwVar6);
  return;
}



void FUN_18000d9f0(char param_1,short *param_2)

{
  short sVar1;
  short sVar2;
  undefined local_res18;
  undefined local_res19;
  
  sVar1 = 0;
  if (DAT_18005b500 == 0) {
    return;
  }
  if (*(ushort *)(DAT_18005b500 + 0x50dc) != 0) {
    sVar1 = (short)(0x200 / (ulonglong)*(ushort *)(DAT_18005b500 + 0x50dc));
  }
  sVar2 = *(short *)(DAT_18005b500 + 0x5128);
  if (param_1 == '\0') {
    sVar1 = sVar1 << 4;
  }
  else {
    if (param_1 != '\x01') {
      local_res18 = (undefined)sVar2;
      local_res19 = *(undefined *)(DAT_18005b500 + 0x5129);
      goto LAB_18000da67;
    }
    sVar1 = sVar1 * -0x10;
  }
  sVar2 = sVar2 + sVar1;
  local_res18 = (undefined)sVar2;
  local_res19 = (undefined)((ushort)sVar2 >> 8);
LAB_18000da67:
  FUN_180011880(0x220,&local_res18,2,100);
  if (param_2 != (short *)0x0) {
    *param_2 = sVar2;
  }
  return;
}



ulonglong FUN_18000daf4(byte *param_1,longlong param_2,int param_3)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  ulonglong uVar5;
  longlong lVar6;
  short *psVar7;
  int iVar8;
  
  FUN_180002770();
  DAT_180037440 = 0xffffffff;
  iVar8 = param_3 + -4;
  bVar1 = param_1[param_3 + -2];
  bVar2 = param_1[param_3 + -1];
  bVar3 = param_1[iVar8];
  bVar4 = param_1[param_3 + -3];
  uVar5 = FUN_1800027b4(param_1,param_3 + -4);
  if ((uint)bVar1 * 0x1000000 + (uint)bVar2 * 0x10000 + (uint)bVar3 * 0x100 + (uint)bVar4 ==
      (int)uVar5) {
    if (*(char *)(DAT_18005b500 + 0xa9c0) == '\x01') {
      uVar5 = FUN_18000f04c(0x12345678,(longlong)param_1,(ushort *)param_1,iVar8 / 2);
    }
    if (0 < iVar8) {
      lVar6 = ((longlong)iVar8 - 1U) / 6 + 1;
      psVar7 = (short *)(param_2 + 4);
      do {
        psVar7[-2] = (ushort)(*param_1 & 0xf) * 0x100 + (ushort)param_1[1];
        psVar7[-1] = (ushort)param_1[3] * 0x10 + (ushort)(*param_1 >> 4);
        uVar5 = 0;
        *psVar7 = (ushort)(param_1[5] & 0xf) * 0x100 + (ushort)param_1[2];
        psVar7[1] = (ushort)param_1[4] * 0x10 + (ushort)(param_1[5] >> 4);
        lVar6 = lVar6 + -1;
        param_1 = param_1 + 6;
        psVar7 = psVar7 + 4;
      } while (lVar6 != 0);
    }
    uVar5 = CONCAT71((int7)(uVar5 >> 8),1);
  }
  else {
    uVar5 = uVar5 & 0xffffffffffffff00;
  }
  return uVar5;
}



void FUN_18000dc5c(longlong param_1,longlong param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  if (param_3 != 0) {
    uVar2 = 2;
    uVar3 = 3;
    do {
      *(ushort *)(param_2 + (ulonglong)(uVar2 - 2) * 2) =
           (ushort)*(byte *)((ulonglong)(uVar3 - 2) + param_1) +
           (ushort)(*(byte *)((ulonglong)(uVar3 - 3) + param_1) & 0xf) * 0x100;
      *(ushort *)(param_2 + (ulonglong)(uVar2 - 1) * 2) =
           (ushort)*(byte *)((ulonglong)uVar3 + param_1) * 0x10 +
           (ushort)(*(byte *)((ulonglong)(uVar3 - 3) + param_1) >> 4);
      *(ushort *)(param_2 + (ulonglong)uVar2 * 2) =
           (ushort)*(byte *)((ulonglong)(uVar3 - 1) + param_1) +
           (ushort)(*(byte *)((ulonglong)(uVar3 + 2) + param_1) & 0xf) * 0x100;
      uVar1 = uVar2 + 1;
      uVar2 = uVar2 + 4;
      *(ushort *)(param_2 + (ulonglong)uVar1 * 2) =
           (ushort)*(byte *)((ulonglong)(uVar3 + 1) + param_1) * 0x10 +
           (ushort)(*(byte *)((ulonglong)(uVar3 + 2) + param_1) >> 4);
      uVar1 = uVar3 + 3;
      uVar3 = uVar3 + 6;
    } while (uVar1 < param_3);
  }
  return;
}



undefined8 FUN_18000dda0(void)

{
  DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_18005b4c8);
  return 1;
}



ulonglong FUN_18000ddbc(longlong param_1)

{
  if (param_1 != 0) {
    *(code **)(param_1 + 0xa990) = FUN_18000e624;
    *(undefined **)(param_1 + 0xa988) = &LAB_18000ea00;
    *(undefined **)(param_1 + 0xa980) = &LAB_18000eaa8;
    *(undefined **)(param_1 + 0xa9a8) = &LAB_18000dd48;
    *(undefined **)(param_1 + 0xa978) = &LAB_18000eb78;
    *(undefined **)(param_1 + 0xa970) = &LAB_18000e1d0;
    *(undefined **)(param_1 + 0xa998) = &LAB_18000ec24;
    DAT_18005b4c0 = param_1;
    InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_18005b4c8);
  }
  return (ulonglong)(param_1 != 0);
}



void FUN_18000de4c(ushort *param_1)

{
  short sVar1;
  longlong lVar2;
  byte bVar3;
  
  bVar3 = 0;
  lVar2 = 0xc;
  do {
    sVar1 = (*param_1 & 0xfffe) * 0x80 + (*param_1 >> 1);
    *(short *)((longlong)&DAT_18004ea68 + (ulonglong)bVar3 * 2) = sVar1;
    FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,10,&DAT_180021420,bVar3,(char)sVar1
                 );
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanL.c",
               (undefined *)L"gfFDTDownbase",0x5a,0,(undefined *)L"fdt_downbase[%d]:0x%x");
    bVar3 = bVar3 + 1;
    param_1 = param_1 + 1;
    lVar2 = lVar2 + -1;
  } while (lVar2 != 0);
  return;
}



void FUN_18000df4c(byte *param_1,int param_2)

{
  short sVar1;
  longlong lVar2;
  ushort uVar3;
  longlong lVar4;
  byte bVar5;
  ushort uVar6;
  byte bVar7;
  ulonglong uVar8;
  ushort *puVar9;
  longlong lVar10;
  uint local_60;
  uint local_58;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  ulonglong local_30;
  
  lVar2 = DAT_18005b4c0;
  local_30 = DAT_180037758 ^ (ulonglong)&stack0xffffffffffffff68;
  lVar4 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  if ((DAT_18005b4c0 != 0) && (param_1 != (byte *)0x0)) {
    lVar10 = 0xc;
    sVar1 = *(short *)(DAT_18005b4c0 + 0x50de);
    uVar6 = (ushort)param_1[1] * 0x100 + (ushort)*param_1;
    puVar9 = (ushort *)(param_1 + 2);
    uVar8 = 0;
    do {
      if (sVar1 == 0) {
        uVar3 = (*puVar9 >> 1) + 0x15;
      }
      else {
        uVar3 = (*puVar9 >> 1) + sVar1;
      }
      puVar9 = puVar9 + 1;
      *(ushort *)((longlong)&local_48 + uVar8 * 2) = uVar3 * 0x100 | uVar3;
      lVar10 = lVar10 + -1;
      uVar8 = (ulonglong)(byte)((char)uVar8 + 1);
    } while (lVar10 != 0);
    uVar8 = 0;
    bVar7 = 0;
    if (param_2 == 0) {
      if (*(int *)(DAT_18005b4c0 + 0x50fc) == 1) {
        uVar6 = uVar6 | *(ushort *)(DAT_18005b4c0 + 0xa868);
        local_60 = (uint)uVar6;
        FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0xb,&DAT_180021420,(char)uVar6)
        ;
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanL.c",
                   (undefined *)L"gfFDTUPbase",0x86,0,(undefined *)L"get new touchflag:0x%x");
      }
      do {
        if ((uVar6 >> ((byte)uVar8 & 0x1f) & 1) == 0) {
          sVar1 = *(short *)(lVar2 + 0x50de);
          if (sVar1 == 0) {
            uVar3 = 0x1300;
          }
          else {
            uVar3 = (sVar1 + -2) * 0x100;
          }
          *(ushort *)((longlong)&local_48 + uVar8 * 2) =
               *(byte *)((longlong)&local_48 + uVar8 * 2 + 1) | uVar3;
        }
        bVar7 = (byte)uVar8 + 1;
        uVar8 = (ulonglong)bVar7;
      } while (bVar7 < 0xc);
    }
    bVar5 = 0;
    do {
      if (*(int *)(lVar2 + 0x50fc) == 1) {
        uVar3 = *(ushort *)((longlong)&local_48 + lVar4);
        uVar6 = *(ushort *)((longlong)&DAT_18004ea88 + lVar4);
        if (uVar3 < *(ushort *)((longlong)&DAT_18004ea88 + lVar4)) {
          *(ushort *)((longlong)&DAT_18004ea88 + lVar4) = uVar3;
          uVar6 = uVar3;
        }
      }
      else {
        uVar6 = *(ushort *)((longlong)&local_48 + lVar4);
        *(ushort *)((longlong)&DAT_18004ea88 + lVar4) = uVar6;
      }
      FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0xc,&DAT_180021420,bVar5,
                    (char)uVar6);
      local_58 = (uint)*(ushort *)((longlong)&DAT_18004ea88 + (ulonglong)bVar7 * 2);
      local_60 = (uint)bVar7;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanL.c",
                 (undefined *)L"gfFDTUPbase",0xa6,0,(undefined *)L"fdt_upbase[%d]:0x%x");
      bVar5 = bVar5 + 1;
      lVar4 = lVar4 + 2;
    } while (bVar5 < 0xc);
  }
  FUN_180018b70(local_30 ^ (ulonglong)&stack0xffffffffffffff68);
  return;
}



void FUN_18000e624(byte *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  longlong lVar3;
  short sVar4;
  undefined4 uVar5;
  wchar_t *pwVar6;
  
  lVar3 = DAT_18005b4c0;
  if (DAT_18005b4c0 != 0) {
    sVar4 = (ushort)param_1[1] * 0x100 + (ushort)*param_1;
    FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0xf,&DAT_180021420,(char)sVar4);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanL.c",
               (undefined *)L"milanLget_fdtdata",0x195,0,(undefined *)L"MilanIrqStatus:0x%x");
    if (sVar4 == 2) {
      FUN_18000234c(*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
      *(ushort *)(lVar3 + 0xa868) = (ushort)param_1[3] * 0x100 + (ushort)param_1[2];
      FUN_18000df4c(param_1 + 2,0);
      *(undefined4 *)(lVar3 + 0x50d8) = 1;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x10,&DAT_180021420);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanL.c",
                 (undefined *)L"milanLget_fdtdata",0x1a4,0,
                 (undefined *)L"got data for GF_FDT_DOWN_MODE");
      FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x11,&DAT_180021420,
                    (char)*(undefined2 *)(lVar3 + 0xa868));
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanL.c",
                 (undefined *)L"milanLget_fdtdata",0x1a6,0,
                 (undefined *)L"devcontext->touchflag:0x%x");
    }
    else {
      if ((sVar4 == 0x80) || (sVar4 == 0x82)) {
        FUN_18000de4c((ushort *)(param_1 + 4));
        *(undefined4 *)(lVar3 + 0x50d8) = 8;
        FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x12,&DAT_180021420);
        pwVar6 = L"got data for GF_REVERSE_MODE";
        uVar5 = 0x1b8;
      }
      else {
        if (sVar4 == 0x100) {
          FUN_18000234c(*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
          uVar5 = *(undefined4 *)(param_1 + 8);
          uVar1 = *(undefined4 *)(param_1 + 0xc);
          uVar2 = *(undefined4 *)(param_1 + 0x10);
          *(undefined4 *)(lVar3 + 0xa848) = *(undefined4 *)(param_1 + 4);
          *(undefined4 *)(lVar3 + 0xa84c) = uVar5;
          *(undefined4 *)(lVar3 + 0xa850) = uVar1;
          *(undefined4 *)(lVar3 + 0xa854) = uVar2;
          *(undefined8 *)(lVar3 + 0xa858) = *(undefined8 *)(param_1 + 0x14);
          if (*(int *)(lVar3 + 0x50fc) == 1) {
            FUN_18000df4c(param_1 + 2,0);
          }
          else {
            FUN_18000de4c((ushort *)(param_1 + 4));
          }
          *(undefined4 *)(lVar3 + 0x50d8) = 3;
          FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x13,&DAT_180021420);
          pwVar6 = L"got data for GF_FDT_MANUAL";
          uVar5 = 0x1c8;
        }
        else {
          if (sVar4 == 0x200) {
            FUN_18000de4c((ushort *)(param_1 + 4));
            *(undefined4 *)(lVar3 + 0x50fc) = 0;
            *(undefined4 *)(lVar3 + 0x50d8) = 2;
            FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x14,&DAT_180021420);
            pwVar6 = L"got data for GF_FDT_UP_MODE";
            uVar5 = 0x1d0;
          }
          else {
            if (sVar4 != 0x400) {
              return;
            }
            *(undefined4 *)(lVar3 + 0x50fc) = 0;
            *(undefined4 *)(lVar3 + 0x50d8) = 9;
            FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x15,&DAT_180021420);
            pwVar6 = L"Got fingerprint module reset event";
            uVar5 = 0x1d6;
          }
        }
      }
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"gf_milanL.c",
                 (undefined *)L"milanLget_fdtdata",uVar5,0,(undefined *)pwVar6);
    }
  }
  return;
}



undefined FUN_18000ec7c(undefined4 *param_1)

{
  char cVar1;
  
  if (param_1 != (undefined4 *)0x0) {
    cVar1 = FUN_18000ed98(param_1);
    if (cVar1 != '\0') {
      if (DAT_18004eac8 != '\x01') {
        return 1;
      }
      *(undefined2 *)((longlong)param_1 + 0x1b) = 0;
      *(undefined *)((longlong)param_1 + 0x1a) = 0;
      return 1;
    }
    *(undefined2 *)((longlong)param_1 + 10) = 0xa55a;
    *(undefined2 *)((longlong)param_1 + 0x1b) = 0x9fb;
    *(undefined *)((longlong)param_1 + 0x1a) = 0xf1;
  }
  return 0;
}



void FUN_18000ecc0(undefined4 *param_1)

{
  char cVar1;
  byte bVar2;
  undefined auStack72 [32];
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  ulonglong local_10;
  
  local_10 = DAT_180037758 ^ (ulonglong)auStack72;
  if (param_1 != (undefined4 *)0x0) {
    cVar1 = FUN_18000ed98(param_1);
    if (cVar1 == '\0') {
      *(undefined2 *)((longlong)param_1 + 10) = 0xa55a;
      *(undefined2 *)((longlong)param_1 + 0x1b) = 0x9fb;
      *(undefined *)((longlong)param_1 + 0x1a) = 0xf1;
    }
    else {
      if (DAT_18004eac8 == '\x01') {
        *(undefined2 *)((longlong)param_1 + 0x1b) = 0;
        *(undefined *)((longlong)param_1 + 0x1a) = 0;
      }
      local_28 = 0xb0a0908;
      local_24 = 0xf0e0d0c;
      local_20 = 0x15141110;
      local_1c = 0x19181716;
      local_18 = 0x1e1c1b1a;
      if (((*(char *)(param_1 + 5) == '\0') || (*(char *)((longlong)param_1 + 0x15) == '\0')) &&
         (((*(byte *)(param_1 + 2) & 0x3e) != 0x20 ||
          (3 < (byte)((*(byte *)(param_1 + 2) >> 6) +
                     (*(byte *)((longlong)param_1 + 9) & 3) * '\x04'))))) {
        bVar2 = 0;
        do {
          if (*(char *)((ulonglong)*(byte *)((longlong)&local_28 + (ulonglong)bVar2) +
                       (longlong)param_1) != '\0') break;
          bVar2 = bVar2 + 1;
        } while (bVar2 < 0x14);
      }
    }
  }
  FUN_180018b70(local_10 ^ (ulonglong)auStack72);
  return;
}



void FUN_18000ed98(undefined4 *param_1)

{
  undefined4 uVar1;
  longlong lVar2;
  char cVar3;
  byte bVar4;
  undefined auStack88 [32];
  undefined4 local_38;
  undefined4 local_34;
  undefined local_30;
  undefined uStack47;
  undefined uStack46;
  undefined uStack45;
  undefined4 uStack44;
  undefined4 uStack40;
  char cStack36;
  char cStack35;
  char cStack34;
  undefined uStack33;
  undefined uStack32;
  ulonglong local_18;
  
  local_18 = DAT_180037758 ^ (ulonglong)auStack88;
  DAT_18004eac8 = 0;
  local_38 = 0xb0a0908;
  local_34 = 0xf0e0d0c;
  bVar4 = 0;
  local_30 = 0x10;
  uStack47 = 0x11;
  uStack46 = 0x1e;
  while (*(char *)((ulonglong)*(byte *)((longlong)&local_38 + (ulonglong)bVar4) + (longlong)param_1)
         == '\0') {
    bVar4 = bVar4 + 1;
    if (10 < bVar4) goto LAB_18000edf7;
  }
  cVar3 = '\0';
  lVar2 = 0;
  do {
    cVar3 = cVar3 + *(char *)(lVar2 + (longlong)param_1);
    lVar2 = lVar2 + 1;
  } while (lVar2 < 0x14);
  if ((char)(*(char *)((longlong)param_1 + 0x1f) + *(char *)((longlong)param_1 + 0x1d) + cVar3) !=
      *(char *)((longlong)param_1 + 0x1e)) {
    local_38 = *param_1;
    local_34 = param_1[1];
    uVar1 = param_1[2];
    uStack44 = param_1[3];
    uStack40 = param_1[4];
    local_30 = (undefined)uVar1;
    uStack47 = (undefined)((uint)uVar1 >> 8);
    uStack46 = (undefined)((uint)uVar1 >> 0x10);
    uStack45 = (undefined)((uint)uVar1 >> 0x18);
    cStack36 = *(char *)((longlong)param_1 + 0x1d);
    cStack35 = *(char *)((longlong)param_1 + 0x1f);
    cVar3 = FUN_1800027fc(&local_38,0x16);
    if (cVar3 != *(char *)((longlong)param_1 + 0x1e)) {
      local_38 = *param_1;
      local_34 = param_1[1];
      uVar1 = param_1[2];
      uStack44 = param_1[3];
      cStack34 = *(char *)(param_1 + 7);
      local_30 = (undefined)uVar1;
      uStack47 = (undefined)((uint)uVar1 >> 8);
      uStack46 = (undefined)((uint)uVar1 >> 0x10);
      uStack45 = (undefined)((uint)uVar1 >> 0x18);
      if (cStack34 == -0x40) {
        uStack40 = param_1[4];
        cStack35 = *(char *)((longlong)param_1 + 0x1d);
        cStack36 = cStack34;
        cStack34 = *(char *)((longlong)param_1 + 0x1f);
        FUN_1800027fc(&local_38,0x17);
      }
      else {
        uStack40 = param_1[4];
        cStack36 = *(char *)((longlong)param_1 + 0x1a);
        cStack35 = *(char *)((longlong)param_1 + 0x1b);
        uStack33 = *(undefined *)((longlong)param_1 + 0x1d);
        uStack32 = *(undefined *)((longlong)param_1 + 0x1f);
        FUN_1800027fc(&local_38,0x19);
      }
      goto LAB_18000edfe;
    }
  }
LAB_18000edf7:
  DAT_18004eac8 = 1;
LAB_18000edfe:
  FUN_180018b70(local_18 ^ (ulonglong)auStack88);
  return;
}



ulonglong FUN_18000eef8(uint param_1)

{
  ushort uVar1;
  uint uVar2;
  uint uVar3;
  byte local_res8;
  
  uVar3 = param_1 >> 1 ^ param_1;
  uVar1 = (ushort)(param_1 >> 0x10);
  uVar2 = ((((((((param_1 >> 0xf & 0x2000 | param_1 & 0x1000000) >> 1 | param_1 & 0x20000) >> 2 |
               param_1 & 0x1000) >> 3 | (param_1 >> 7 ^ param_1) & 0x80000) >> 1 |
             (param_1 >> 0xf ^ param_1) & 0x4000) >> 2 | param_1 & 0x2000) >> 1 |
           (param_1 >> 0xe ^ param_1) & 0x200) >> 1 | uVar3 & 0x40 | param_1 & 0x20) >> 1;
  local_res8 = (byte)uVar2 | ((byte)(param_1 >> 0x14) ^ (byte)param_1 * '\x02') & 4 |
               (byte)param_1 & 1;
  DAT_18003768c = (uVar3 >> 0x1e ^ param_1 >> 10 & 0xff ^ param_1 & 0xff) << 0x1f | param_1 >> 1;
  return (ulonglong)
         (ushort)(((ushort)(uVar2 >> 8) | (uVar1 >> 8 ^ (ushort)((param_1 << 3) >> 8)) & 0x40 |
                   (uVar1 >> 1 ^ (ushort)param_1) & 8 |
                   ((ushort)((param_1 << 6) >> 8) ^ (ushort)((param_1 >> 7) >> 8)) & 1 |
                  (ushort)(((param_1 & 0x100) << 7) >> 8)) + (ushort)local_res8 * 0x100);
}



void FUN_18000f04c(uint param_1,longlong param_2,ushort *param_3,uint param_4)

{
  ulonglong uVar1;
  ulonglong uVar2;
  longlong lVar3;
  
  DAT_18003768c = param_1;
  if (param_4 != 0) {
    lVar3 = param_2 - (longlong)param_3;
    uVar2 = (ulonglong)param_4;
    do {
      uVar1 = FUN_18000eef8(DAT_18003768c);
      *param_3 = (ushort)uVar1 ^ *(ushort *)(lVar3 + (longlong)param_3);
      param_3 = param_3 + 1;
      uVar2 = uVar2 - 1;
    } while (uVar2 != 0);
  }
  return;
}



void FUN_18000f0a0(void)

{
  int iVar1;
  undefined *local_70;
  undefined local_68 [20];
  char local_54;
  ulonglong local_18;
  
  local_18 = DAT_180037758 ^ (ulonglong)&stack0xffffffffffffff58;
  memset(local_68,0,0x4c);
  iVar1 = CallNtPowerInformation(4,0,0,local_68);
  if (iVar1 < 0) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"notifypower.c",
               (undefined *)L"GetPowerInformation",0x23,0,
               (undefined *)L"obtain system power capabilities failed!!!");
  }
  else {
    local_70 = &DAT_180021538;
    if (local_54 == '\x01') {
      local_70 = &DAT_180021530;
    }
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"notifypower.c",
               (undefined *)L"GetPowerInformation",0x27,0,
               (undefined *)L"supports Modern Standby: %s");
  }
  FUN_180018b70(local_18 ^ (ulonglong)&stack0xffffffffffffff58);
  return;
}



ulonglong FUN_18000f454(void)

{
  uint uVar1;
  undefined *local_18;
  undefined8 local_10;
  
  local_10 = 0;
  local_18 = &LAB_18000f188;
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"notifypower.c",
             (undefined *)L"RegisterPowerNotification",0x7c,0,(undefined *)L"entry");
  uVar1 = PowerSettingRegisterNotification(&DAT_18001d9e0,2,&local_18,&DAT_18004eae8);
  if (DAT_18004eae8 == 0) {
    uVar1 = GetLastError();
  }
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"notifypower.c",
             (undefined *)L"RegisterPowerNotification",0x85,0,(undefined *)L"exit...Error:0x%x");
  return (ulonglong)uVar1;
}



void FUN_18000f51c(void)

{
                    // WARNING: Could not recover jumptable at 0x000180018654. Too many branches
                    // WARNING: Treating indirect jump as call
  PowerSettingUnregisterNotification(DAT_18004eae8);
  return;
}



void FUN_18000faa4(undefined8 param_1)

{
  undefined local_res10 [24];
  undefined4 local_68;
  undefined4 local_64;
  uint local_60;
  undefined local_5b;
  undefined *local_40;
  undefined *local_30;
  undefined4 local_18;
  
  memset(&local_68,0,0x60);
  local_18 = 0xffffffff;
  local_68 = 0x60;
  local_5b = 1;
  local_64 = 2;
  local_60 = (uint)(DAT_18004ead0 != '\x01');
  local_40 = &LAB_18000f528;
  if (DAT_18004ead0 == '\0') {
    local_30 = &LAB_18000f7dc;
  }
  (**(code **)(DAT_18005ad20 + 0x2a8))(DAT_18005ad28,param_1,&local_68,0,local_res10);
  return;
}



void FUN_18000fc74(undefined8 param_1,undefined8 param_2,undefined8 param_3,longlong param_4,
                  undefined8 param_5,undefined4 *param_6)

{
  *param_6 = 1;
  *(undefined4 *)(param_4 + 4) = 0;
  FUN_18001113c();
                    // WARNING: Could not recover jumptable at 0x00018000fcb1. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(DAT_18005ad20 + 0x520))(DAT_18005ad28,param_1,0,0x2c8);
  return;
}



void FUN_18000fe2c(undefined8 param_1,undefined8 param_2,undefined8 param_3,longlong param_4,
                  undefined8 param_5,int *param_6)

{
  char local_res20 [8];
  
  local_res20[0] = '\x02';
  UsbEcGpioStatus_FUN_1800120d8(local_res20);
  if (local_res20[0] == '\x01') {
    *(undefined4 *)(param_4 + 4) = 0;
  }
  else {
    *(undefined4 *)(param_4 + 4) = 1;
  }
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"TestUnit.c",(undefined *)L"GPIOTestFunc",
             0x1bb,0,(undefined *)
                                          
                     L"whole test for GPIO: after operation_status:%d, test_progress:%d, gpioStatus:%d, test_result:%d"
            );
  if (*param_6 == 1) {
    (**(code **)(DAT_18005ad20 + 0x520))(DAT_18005ad28,param_1,0,0x2c8);
  }
  return;
}



undefined * FUN_18000feec(int param_1)

{
  if (param_1 == 0) {
    return (undefined *)&DAT_18005b500;
  }
  if (0 < param_1) {
    if (param_1 < 3) {
      return (undefined *)&DAT_18005b540;
    }
    if (param_1 == 3) {
      return (undefined *)&DAT_18005b4c0;
    }
  }
  return (undefined *)0x0;
}



void FUN_18000ff18(void)

{
  FUN_1800188a0((undefined8 *)L"FirmwareVersion",&LAB_18000fcb8,1);
  FUN_1800188a0((undefined8 *)L"SensorInfo",&LAB_180010b24,5);
  FUN_1800188a0((undefined8 *)&DAT_180021a38,&LAB_1800108ac,0x16);
  FUN_1800188a0((undefined8 *)L"Reset",&LAB_1800107a0,0x14);
  FUN_1800188a0((undefined8 *)L"CheckOTP",&LAB_18000fb48,0x1c);
  FUN_1800188a0((undefined8 *)L"FDTDown",FUN_18000fc74,0x3c);
  FUN_1800188a0((undefined8 *)L"PixelOpenShort",&LAB_1800106fc,0x17);
  FUN_1800188a0((undefined8 *)L"Performance",&LAB_180010664,0x1d);
  FUN_1800188a0((undefined8 *)L"GPIO",FUN_18000fe2c,0x1e);
  return;
}



void OnCapturedataTest_FUN_180010004(undefined8 param_1)

{
  uint uVar1;
  int iVar2;
  undefined8 uVar3;
  longlong lVar4;
  undefined8 *_Memory;
  int iVar5;
  ulonglong uVar6;
  undefined4 local_res18;
  uint local_res20;
  undefined4 uVar7;
  wchar_t *pwVar8;
  ulonglong local_58;
  undefined8 *local_50;
  int *local_48;
  longlong local_40;
  
  local_48 = (int *)0x0;
  local_50 = (undefined8 *)0x0;
  local_40 = 0;
  local_58 = 0;
  iVar5 = 0;
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"TestUnit.c",
             (undefined *)L"OnCaptureDataTest",0x22c,0,(undefined *)L"enter");
  uVar3 = (**(code **)(DAT_18005ad20 + 0x578))(DAT_18005ad28,param_1);
  lVar4 = (**(code **)(DAT_18005ad20 + 0x2d0))(DAT_18005ad28,uVar3);
  if (lVar4 == 0) {
    (**(code **)(DAT_18005ad20 + 0x518))(DAT_18005ad28,param_1,0xc000000d);
    return;
  }
  FUN_18000359c(param_1,&local_48,&local_40,&local_50,&local_58);
  if ((local_48 != (int *)0x0) && (local_40 != 0)) {
    iVar5 = *local_48;
  }
  if ((local_50 == (undefined8 *)0x0) || (local_58 < 4)) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"TestUnit.c",
               (undefined *)L"OnCaptureDataTest",0x251,0,
               (undefined *)L"!!!!fail to check output parameters");
    uVar3 = 0xc000000d;
    goto LAB_1800104d0;
  }
  lVar4 = (**(code **)(DAT_18005ad20 + 0x3d8))(DAT_18005ad28,lVar4,PTR_DAT_180036d28);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"TestUnit.c",(undefined *)L"Test_read_data"
             ,0x1e0,0,(undefined *)L"enter, capture_type=%d");
  uVar1 = *(uint *)(lVar4 + 0xa8);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"TestUnit.c",(undefined *)L"Test_read_data"
             ,0x1e7,0,(undefined *)L"sensor_type=%d, row=%d, col=%d");
  local_res20 = (uint)*(ushort *)(&DAT_1800376a0 + (longlong)(int)uVar1 * 0xe) *
                (uint)*(ushort *)(&DAT_1800376a2 + (longlong)(int)uVar1 * 0xe) * 2;
  uVar6 = (ulonglong)local_res20;
  _Memory = (undefined8 *)malloc((ulonglong)local_res20);
  if (_Memory == (undefined8 *)0x0) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"TestUnit.c",
               (undefined *)L"Test_read_data",0x1ed,0,(undefined *)L"!!!!fail to allocate memory");
  }
  else {
    iVar2 = -1;
    if (iVar5 == 1) {
      pwVar8 = L"to read base frame";
      uVar7 = 0x1f5;
LAB_180010257:
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"TestUnit.c",
                 (undefined *)L"Test_read_data",uVar7,0,(undefined *)pwVar8);
      if (uVar1 < 3) {
LAB_18001027b:
        uVar3 = FUN_180011184(_Memory,500,uVar1);
        iVar2 = (int)uVar3;
      }
    }
    else {
      if (iVar5 == 2) {
        pwVar8 = L"to read image frame";
        uVar7 = 0x1fe;
        goto LAB_180010257;
      }
      if (iVar5 == 3) {
        if (2 < uVar1) goto LAB_18001028d;
        local_res18 = 0;
        device_action_FUN_180012f20(2,(longlong *)&local_res18,0);
        goto LAB_18001027b;
      }
      if (iVar5 != 4) {
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"TestUnit.c",
                   (undefined *)L"Test_read_data",0x21f,0,(undefined *)L"exit");
        goto LAB_180010440;
      }
      if (uVar1 < 3) goto LAB_18001027b;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"TestUnit.c",
                 (undefined *)L"Test_read_data",0x21a,0,(undefined *)L"!!!!not HV type for flat end"
                );
    }
LAB_18001028d:
    if (((iVar2 == 0) && (local_res20 != 0)) && (uVar6 <= local_58)) {
      if (local_58 != uVar6) {
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,1,(undefined *)L"TestUnit.c",
                   (undefined *)L"OnCaptureDataTest",0x261,0,
                   (undefined *)L"expected frame size not equal to captured size: %d != %d");
      }
      if (local_58 < uVar6) {
        uVar6 = local_58;
      }
      memcpy_FUN_180019c80(local_50,_Memory,uVar6);
      free(_Memory);
      (**(code **)(DAT_18005ad20 + 0x520))(DAT_18005ad28,param_1,0,local_58);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"TestUnit.c",
                 (undefined *)L"OnCaptureDataTest",0x265,0,(undefined *)L"got one frame exit");
      return;
    }
  }
LAB_180010440:
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"TestUnit.c",
             (undefined *)L"OnCaptureDataTest",0x25a,0,
             (undefined *)
                          
             L"!!!!fail when reading image: gfErrCode:%d, pframe:%p, framelen:%lu, outputBufferSize:%lu"
            );
  uVar3 = 0xc0000229;
LAB_1800104d0:
  (**(code **)(DAT_18005ad20 + 0x520))(DAT_18005ad28,param_1,uVar3,0);
  return;
}



void Test_OpenShortBackToOriginal_FUN_180010c50
               (longlong param_1,longlong param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  
  FUN_180011160();
  FUN_1800014f4((longlong)"%s %d ENUM_TEST_PixelOpenShort_STAGE_BackToOriginal change to Idle mode",
                "Test_OpenShortBackToOriginal",0x141,param_4);
  FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x12,&DAT_1800219f0);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"TestUnit.c",
             (undefined *)L"Test_OpenShortBackToOriginal",0x143,0,
             (undefined *)L"ENUM_TEST_PixelOpenShort_STAGE_BackToOriginal change to Idle mode");
  iVar1 = FUN_180011880((ulonglong)*(ushort *)(param_2 + 0x12),(undefined *)(param_1 + 0x5f0),2,200)
  ;
  if (iVar1 == 0) {
    iVar1 = FUN_180011880((ulonglong)*(ushort *)(param_2 + 0x12),(undefined *)(param_1 + 0x5f0),2,
                          200);
  }
  FUN_1800014f4((longlong)
                                
                "%s %d whole test for OPEN_SHORT:OPEN_SHORT_Stage:%d, original DAC:%d Succeedded or not: %d"
                ,"Test_OpenShortBackToOriginal",0x14a,3);
  FUN_180012528(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x13,&DAT_1800219f0,3,
                (char)*(undefined2 *)(param_1 + 0x5f0),(char)iVar1);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"TestUnit.c",
             (undefined *)L"Test_OpenShortBackToOriginal",0x14f,0,
             (undefined *)
             L"whole test for OPEN_SHORT:OPEN_SHORT_Stage:%d, original DAC:%d Succeedded or not: %d"
            );
  return;
}



void FUN_180010df0(longlong param_1,longlong param_2,longlong param_3,undefined8 param_4)

{
  FUN_1800014f4((longlong)"%s %d ENUM_TEST_PixelOpenShort_STAGE_BeforeDACChange change to IDLE mode"
                ,"Test_OpenShortBeforeDACChange",0x154,param_4);
  FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x14,&DAT_1800219f0);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"TestUnit.c",
             (undefined *)L"Test_OpenShortBeforeDACChange",0x156,0,
             (undefined *)L"ENUM_TEST_PixelOpenShort_STAGE_BeforeDACChange change to Idle mode");
  ChipRegRead_FUN_1800116dc
            ((ulonglong)*(ushort *)(param_2 + 0x12),(undefined8 *)(param_1 + 0x5f0),2,200);
  *(undefined2 *)(param_3 + 0x12) = *(undefined2 *)(param_1 + 0x5f0);
  FUN_1800014f4((longlong)"%s %d whole test for OPEN_SHORT:OPEN_SHORT_Stage:%d, original DAC:%d",
                "Test_OpenShortBeforeDACChange",0x15a,0);
  FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x15,&DAT_1800219f0,0,
                (char)*(undefined2 *)(param_1 + 0x5f0));
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"TestUnit.c",
             (undefined *)L"Test_OpenShortBeforeDACChange",0x15f,0,
             (undefined *)
             L"ENUM_TEST_PixelOpenShort_STAGE_BeforeDACChange OPEN_SHORT_Stage:%d, original DAC:%d")
  ;
  return;
}



void FUN_180010f68(longlong param_1,longlong param_2,longlong param_3,undefined8 param_4)

{
  short sVar1;
  undefined local_res8;
  ushort local_res10;
  
  FUN_180011160();
  FUN_1800014f4((longlong)"%s %d ENUM_TEST_PixelOpenShort_STAGE_UpdateDAC change to Idle mode",
                "Test_OpenShortUpdateDAC",0x126,param_4);
  FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x10,&DAT_1800219f0);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"TestUnit.c",
             (undefined *)L"Test_OpenShortUpdateDAC",0x128,0,
             (undefined *)L"ENUM_TEST_PixelOpenShort_STAGE_UpdateDAC change to Idle mode");
  local_res10 = 0x80;
  ChipRegRead_FUN_1800116dc((ulonglong)*(ushort *)(param_2 + 0x10),(undefined8 *)&local_res10,2,200)
  ;
  *(ushort *)(param_3 + 0x10) = local_res10;
  sVar1 = (short)(0x1400 / (ulonglong)local_res10) * 0x10 + *(short *)(param_1 + 0x5f0);
  *(short *)(param_1 + 0x5f2) = sVar1;
  *(short *)(param_3 + 0x14) = sVar1;
  FUN_180011880((ulonglong)*(ushort *)(param_2 + 0x12),(undefined *)(short *)(param_1 + 0x5f2),2,200
               );
  ChipRegRead_FUN_1800116dc((ulonglong)*(ushort *)(param_2 + 0x12),(undefined8 *)&local_res8,2,200);
  FUN_1800014f4((longlong)
                "%s %d whole test for OPEN_SHORT:OPEN_SHORT_Stage:%d, tcode=%d, Updated DAC:%d",
                "Test_OpenShortUpdateDAC",0x135,1);
  FUN_180012528(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x11,&DAT_1800219f0,1,
                (char)*(undefined2 *)(param_3 + 0x10),local_res8);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"TestUnit.c",
             (undefined *)L"Test_OpenShortUpdateDAC",0x13a,0,
             (undefined *)L"whole test for OPEN_SHORT:OPEN_SHORT_Stage:%d, tcode:%d, Updated DAC:%d"
            );
  return;
}



void FUN_18001113c(void)

{
  undefined4 local_res8;
  
  local_res8 = 1;
  device_action_FUN_180012f20(2,(longlong *)&local_res8,0);
  return;
}



void FUN_180011160(void)

{
  undefined4 local_res8;
  
  local_res8 = 6;
  device_action_FUN_180012f20(2,(longlong *)&local_res8,0);
  return;
}



undefined8 FUN_180011184(undefined8 *param_1,uint param_2,int param_3)

{
  DWORD DVar1;
  longlong *plVar2;
  undefined8 uVar3;
  
  plVar2 = (longlong *)FUN_18000feec(param_3);
  (**(code **)(*plVar2 + 0xa970))(2,0);
  DVar1 = WaitForSingleObject(*(HANDLE *)(*plVar2 + 0x10),param_2 & 0xffff);
  if (DVar1 == 0x102) {
    uVar3 = 0xffffffff;
  }
  else {
    memcpy_FUN_180019c80
              (param_1,*(undefined8 **)(*plVar2 + 0xa808),
               (ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)param_3 * 0xe));
    memset(*(void **)(*plVar2 + 0xa808),0,
           (ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)param_3 * 0xe));
    uVar3 = 0;
  }
  return uVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void CheckTcodeAndDiff_FUN_180011228(longlong *param_1)

{
  bool bVar1;
  char cVar2;
  byte bVar3;
  undefined4 *puVar5;
  undefined4 uVar6;
  wchar_t *pwVar7;
  uint local_b0;
  uint local_a8;
  uint local_a0;
  uint local_98;
  uint local_90;
  uint local_88;
  uint local_80;
  uint local_78;
  uint local_70;
  uint local_68;
  undefined2 local_58 [4];
  undefined4 local_50;
  undefined4 uStack76;
  undefined4 local_48;
  undefined4 uStack68;
  undefined4 local_40;
  undefined4 uStack60;
  undefined4 uStack56;
  undefined4 uStack52;
  ulonglong local_30;
  uint uVar4;
  
  local_30 = DAT_180037758 ^ (ulonglong)&stack0xffffffffffffff18;
  FUN_180002510(&DAT_18005936a);
  if (param_1 == (longlong *)0x0) goto LAB_180011543;
  FUN_180001870(L"C:\\ProgramData\\Goodix\\goodix.dat",&local_50,0x20,L"rb");
  bVar1 = false;
  puVar5 = &local_50;
  uVar4 = 0;
  do {
    local_a8 = uVar4 + 7;
    local_68 = (uint)*(byte *)((longlong)&local_50 + (ulonglong)local_a8);
    local_70 = (uint)*(byte *)((longlong)&local_50 + (ulonglong)(uVar4 + 6));
    local_78 = (uint)*(byte *)((longlong)&local_50 + (ulonglong)(uVar4 + 5));
    local_80 = (uint)*(byte *)((longlong)&local_50 + (ulonglong)(uVar4 + 4));
    local_88 = (uint)*(byte *)((longlong)&local_50 + (ulonglong)(uVar4 + 3));
    local_90 = (uint)*(byte *)((longlong)&local_50 + (ulonglong)(uVar4 + 2));
    local_98 = (uint)*(byte *)((longlong)&local_50 + (ulonglong)(uVar4 + 1));
    local_a0 = (uint)*(byte *)puVar5;
    local_b0 = uVar4;
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
               (undefined *)L"CheckTcodeAndDiff",0x81f,0,
               (undefined *)
               L"otp[%02d-%02d] from file:0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x");
    bVar3 = (char)uVar4 + 8;
    uVar4 = (uint)bVar3;
    puVar5 = puVar5 + 2;
  } while (bVar3 < 0x20);
  if (((CONCAT44(uStack76,local_50) == *param_1) && (CONCAT44(uStack68,local_48) == param_1[1])) &&
     (cVar2 = FUN_18000ec7c(&local_50), cVar2 == '\x01')) {
    *(undefined4 *)param_1 = local_50;
    *(undefined4 *)((longlong)param_1 + 4) = uStack76;
    *(undefined4 *)(param_1 + 1) = local_48;
    *(undefined4 *)((longlong)param_1 + 0xc) = uStack68;
    *(undefined4 *)(param_1 + 2) = local_40;
    *(undefined4 *)((longlong)param_1 + 0x14) = uStack60;
    *(undefined4 *)(param_1 + 3) = uStack56;
    *(undefined4 *)((longlong)param_1 + 0x1c) = uStack52;
    bVar1 = true;
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
               (undefined *)L"CheckTcodeAndDiff",0x82a,0,
               (undefined *)L"otp CRC check pass...using otp from file");
  }
  DAT_180053c2d = *(undefined4 *)param_1;
  DAT_180053c31 = *(undefined4 *)((longlong)param_1 + 4);
  DAT_180053c35 = *(undefined4 *)(param_1 + 1);
  DAT_180053c39 = *(undefined4 *)((longlong)param_1 + 0xc);
  DAT_180053c3d = *(undefined4 *)(param_1 + 2);
  DAT_180053c41 = *(undefined4 *)((longlong)param_1 + 0x14);
  DAT_180053c45 = *(undefined4 *)(param_1 + 3);
  DAT_180053c49 = *(undefined4 *)((longlong)param_1 + 0x1c);
  if (bVar1) {
    if (_DAT_180053c10 == 0) {
      DAT_180053c28 =
           (*(byte *)((longlong)param_1 + 0x13) & 0xff80) * 0x100 +
           (ushort)*(byte *)((longlong)param_1 + 0x1f);
      uVar6 = 0x85a;
LAB_18001147b:
      local_b0 = (uint)DAT_180053c28;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                 (undefined *)L"CheckTcodeAndDiff",uVar6,0,(undefined *)L"read dac from otp :0x%x");
    }
LAB_180011499:
    bVar3 = *(byte *)((longlong)param_1 + 0x16);
    if ((bVar3 == 0) || ((uint)*(byte *)((longlong)param_1 + 0x17) + (uint)bVar3 != 0xff)) {
      DAT_180053bde = 0;
      goto LAB_1800114be;
    }
    DAT_180053bdc = ((bVar3 >> 4) + 1) * 0x10;
    FUN_180002668();
    DAT_180053bde =
         (ushort)((int)(((ulonglong)(((*(byte *)((longlong)param_1 + 0x16) & 0xf) + 2) * 0x6400) /
                         (ulonglong)DAT_180053bdc & 0xffff) / 3) >> 4);
    FUN_1800025b8();
    FUN_18000a2fc(DAT_18005b4a0,(byte)DAT_180053bde,DAT_180053bdc);
    pwVar7 = L"diff/tcode check pass: diff=%u, tcode=%u";
    uVar6 = 0x874;
  }
  else {
    cVar2 = FUN_18000ec7c((undefined4 *)param_1);
    if (cVar2 == '\x01') {
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                 (undefined *)L"CheckTcodeAndDiff",0x832,0,
                 (undefined *)L"otp CRC check pass...using otp from chip");
      if (_DAT_180053c10 == 0) {
        DAT_180053c28 =
             (*(byte *)((longlong)param_1 + 0x13) & 0xff80) * 0x100 +
             (ushort)*(byte *)((longlong)param_1 + 0x1f);
        uVar6 = 0x837;
        goto LAB_18001147b;
      }
      goto LAB_180011499;
    }
    if ((*(char *)((longlong)param_1 + 10) == 'Z') && (*(char *)((longlong)param_1 + 0xb) == -0x5b))
    {
      local_58[0] = 8;
      FUN_180011880(0x220,(undefined *)local_58,2,100);
    }
    DAT_180053bde = 0;
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"usbhal.c",
               (undefined *)L"CheckTcodeAndDiff",0x853,0,(undefined *)L"otp CRC check fail");
LAB_1800114be:
    FUN_18000a2fc(DAT_18005b4a0,0,0);
    FUN_180002668(0,&DAT_18005936a);
    pwVar7 = L"diff/tcode check pass(default): diff=%u, tcode=%u";
    uVar6 = 0x870;
  }
  local_a8 = (uint)DAT_180053bdc;
  local_b0 = (uint)DAT_180053bde;
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
             (undefined *)L"CheckTcodeAndDiff",uVar6,0,(undefined *)pwVar7);
  DlCfg_FUN_180016cc0((undefined8 *)&DAT_18005936a,0x100,200);
LAB_180011543:
  FUN_180018b70(local_30 ^ (ulonglong)&stack0xffffffffffffff18);
  return;
}



// WARNING: Variable defined which should be unmapped: local_78
// WARNING: Could not reconcile some variable overlaps

void ChipRegRead_FUN_1800116dc(undefined8 param_1,undefined8 *param_2,ushort param_3,ushort param_4)

{
  char cVar2;
  DWORD DVar3;
  byte bVar4;
  undefined *puVar5;
  int iVar6;
  undefined4 uVar2;
  wchar_t *local_78;
  undefined local_68;
  undefined local_67;
  undefined local_66;
  byte local_65;
  undefined local_64;
  ulonglong local_28;
  undefined uVar1;
  
  local_28 = DAT_180037758 ^ (ulonglong)&stack0xffffffffffffff58;
  local_67 = (undefined)(undefined2)param_1;
  local_66 = (undefined)((ushort)(undefined2)param_1 >> 8);
  local_78 = (wchar_t *)CONCAT44(local_78._4_4_,200);
  local_68 = 0;
  bVar4 = (byte)param_3;
  local_64 = (undefined)(param_3 >> 8);
  local_65 = bVar4;
  cVar2 = UsbSendDataToDevice_FUN_180012240(DAT_18004eb00,8,1,(undefined8 *)&local_68,5,'\x01',200);
  if (cVar2 == '\0') {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),3,3,10,&DAT_18002fad8);
    local_78 = L"UsbSendDataToDevice no Ack received";
    uVar2 = 0xbb;
  }
  else {
    DVar3 = WaitForSingleObject(DAT_18004eb18,(uint)param_4);
    if (DVar3 != 0x102) {
      memcpy_FUN_180019c80(param_2,(undefined8 *)&DAT_18004eb53,(ulonglong)param_3);
      if (1 < bVar4) {
        iVar6 = 1;
        puVar5 = (undefined *)((longlong)param_2 + 1);
        do {
          uVar1 = puVar5[-1];
          iVar6 = iVar6 + 2;
          puVar5[-1] = *puVar5;
          *puVar5 = uVar1;
          puVar5 = puVar5 + 2;
        } while (iVar6 < (int)(uint)bVar4);
      }
      goto LAB_180011863;
    }
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),3,3,0xb,&DAT_18002fad8);
    local_78 = L"getreghandle timeout";
    uVar2 = 0xc5;
  }
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,5,(undefined *)L"usbhal.c",(undefined *)L"ChipRegRead",
             uVar2,0,(undefined *)local_78);
LAB_180011863:
  FUN_180018b70(local_28 ^ (ulonglong)&stack0xffffffffffffff58);
  return;
}



// WARNING: Could not reconcile some variable overlaps

void FUN_180011880(undefined8 param_1,undefined *param_2,ushort param_3,undefined8 param_4)

{
  undefined uVar1;
  uint uVar2;
  undefined8 local_218;
  ulonglong local_18;
  
  local_18 = DAT_180037758 ^ (ulonglong)&stack0xfffffffffffffda8;
  local_218._1_1_ = (undefined)(undefined2)param_1;
  local_218._0_1_ = 0;
  local_218._2_1_ = (undefined)((ushort)(undefined2)param_1 >> 8);
  uVar2 = 0;
  while ((ushort)uVar2 < param_3) {
    uVar1 = *param_2;
    param_2 = param_2 + 1;
    *(undefined *)((longlong)&local_218 + (ulonglong)(uVar2 + 3)) = uVar1;
    uVar2 = (uint)(ushort)((ushort)uVar2 + 1);
  }
  UsbSendDataToDevice_FUN_180012240
            (DAT_18004eb00,8,0,&local_218,param_3 + 3,'\x01',(uint)(ushort)param_4);
  FUN_180018b70(local_18 ^ (ulonglong)&stack0xfffffffffffffda8);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void GetEvkVersion_FUN_180011918(undefined4 *param_1,uint param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  DWORD DVar4;
  undefined8 local_58 [8];
  ulonglong local_18;
  
  local_18 = DAT_180037758 ^ (ulonglong)&stack0xffffffffffffff68;
  memset(local_58,0,0x40);
  if (param_1 != (undefined4 *)0x0) {
    UsbSendDataToDevice_FUN_180012240(DAT_18004eb00,10,4,local_58,2,'\x01',200);
    DVar4 = WaitForSingleObject(DAT_18004eb38,param_2 & 0xffff);
    uVar3 = DAT_18004eb5f;
    uVar2 = DAT_18004eb5b;
    uVar1 = DAT_18004eb57;
    if (DVar4 != 0x102) {
      *param_1 = _DAT_18004eb53;
      param_1[1] = uVar1;
      param_1[2] = uVar2;
      param_1[3] = uVar3;
      uVar3 = DAT_18004eb6f;
      uVar2 = DAT_18004eb6b;
      uVar1 = DAT_18004eb67;
      param_1[4] = DAT_18004eb63;
      param_1[5] = uVar1;
      param_1[6] = uVar2;
      param_1[7] = uVar3;
      uVar3 = DAT_18004eb7f;
      uVar2 = DAT_18004eb7b;
      uVar1 = DAT_18004eb77;
      param_1[8] = DAT_18004eb73;
      param_1[9] = uVar1;
      param_1[10] = uVar2;
      param_1[0xb] = uVar3;
      uVar3 = DAT_18004eb8f;
      uVar2 = DAT_18004eb8b;
      uVar1 = DAT_18004eb87;
      param_1[0xc] = DAT_18004eb83;
      param_1[0xd] = uVar1;
      param_1[0xe] = uVar2;
      param_1[0xf] = uVar3;
      memset(&DAT_18004eb53,0,0x40);
    }
  }
  FUN_180018b70(local_18 ^ (ulonglong)&stack0xffffffffffffff68);
  return;
}



undefined8 FUN_180011a00(void)

{
  LPBYTE local_res8 [4];
  
  local_res8[0] = (LPBYTE)0x0;
  FUN_18000114c(-0x7ffffffe,L"Software\\Goodix\\FP\\parameter\\",L"IsDecrypt",(DWORD *)0x0,
                local_res8,(uint *)0x0);
  if (local_res8[0] != (LPBYTE)0x0) {
    DAT_1800594c0 = *local_res8[0];
    free(local_res8[0]);
    local_res8[0] = (LPBYTE)0x0;
    FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x5d,&DAT_18002fad8,DAT_1800594c0);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"GetRegister_withPlugin",0xdc1,0,
               (undefined *)L"Get register of isDecrypt:%d ");
  }
  return 0;
}



ulonglong FUN_180011ad8(longlong param_1,undefined8 *param_2,ulonglong param_3)

{
  ulonglong uVar1;
  uint local_res8 [2];
  undefined8 local_28;
  undefined8 *local_20;
  ulonglong local_18;
  
  uVar1 = 0;
  local_res8[0] = 0;
  if (param_1 != 0) {
    if ((DAT_18004ead0 == '\x01') && (DAT_1800594b0 != 0)) {
      ActivateDevice_FUN_180002828(DAT_1800594b0,param_2,param_3);
    }
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_180053b80);
    local_20 = (undefined8 *)(**(code **)(DAT_18005ad20 + 0x3b8))(DAT_18005ad28,DAT_180053bd0);
    memcpy_FUN_180019c80(local_20,param_2,param_3 & 0xff);
    local_18 = param_3 & 0xff;
    local_28 = 1;
    (**(code **)(DAT_18005ad20 + 0x6e8))(DAT_18005ad28,param_1,0,0,&local_28,local_res8);
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_180053b80);
    uVar1 = (ulonglong)local_res8[0];
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void OnTimerTemperature_FUN_180011bd4(void)

{
  int iVar1;
  undefined8 *_Memory;
  ulonglong uVar2;
  byte bVar3;
  undefined4 uVar4;
  wchar_t *pwVar5;
  
  _Memory = (undefined8 *)
            malloc((ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe))
  ;
  if (_Memory == (undefined8 *)0x0) {
    return;
  }
  FUN_18000234c(*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
  DAT_180053bd8 = 0xc;
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
  uVar2 = gf_get_oneframe_FUN_1800166c4(_Memory,500);
  if ((int)uVar2 == 0) {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,(short)uVar2 + 0x28,&DAT_18002fad8)
    ;
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"OnTimertemperature",0x5ba,0,
               (undefined *)L"gf_get_oneframe timeout, restart timer 2 seconds");
    (**(code **)(DAT_18005ad20 + 0x638))(DAT_18005ad28,DAT_180053c20,0xfffffffffeced300);
    goto LAB_180011d4f;
  }
  uVar2 = FUN_18000b140(DAT_180059310,(longlong)_Memory);
  iVar1 = (int)uVar2;
  if (iVar1 == 0) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"OnTimertemperature",0x5cf,0,(undefined *)L"imageret: temp");
LAB_180011df2:
    if (iVar1 == 0) {
      _DAT_180053c00 = 1;
      gf_temperatureoccure_FUN_180016fc8();
      goto LAB_180011d4f;
    }
    if (iVar1 - 2U < 2) goto LAB_180011d42;
LAB_180011e16:
    bVar3 = 2;
  }
  else {
    if (iVar1 == 1) {
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"OnTimertemperature",0x5d8,0,(undefined *)L"imageret: finger");
      goto LAB_180011e16;
    }
    if (iVar1 == 2) {
      pwVar5 = L"imageret: void";
      uVar4 = 0x5d5;
    }
    else {
      if (iVar1 != 3) goto LAB_180011df2;
      pwVar5 = L"imageret: bad";
      uVar4 = 0x5d2;
    }
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"OnTimertemperature",uVar4,0,(undefined *)pwVar5);
LAB_180011d42:
    bVar3 = 1;
  }
  gf_set_mode_FUN_180016d04(3,bVar3,1);
LAB_180011d4f:
  free(_Memory);
  return;
}



undefined8 UsbEcControl_FUN_180011e20(undefined param_1,undefined param_2)

{
  byte bVar1;
  char cVar2;
  undefined local_res8;
  undefined local_res9;
  undefined4 local_res10;
  
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"UsbEcControl",
             0xd48,0,(undefined *)L"Entry");
  local_res8 = param_1;
  local_res9 = param_2;
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"usbhal.c",(undefined *)L"UsbEcControl",
             0xd53,0,(undefined *)L"Power Isolate:%S...isFDT:%S");
  bVar1 = UsbSendDataToDevice_FUN_180012240
                    (DAT_18004eb00,10,7,(undefined8 *)&local_res8,2,'\x01',200);
  if ((bVar1 & 3) == 3) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"UsbEcControl",
               0xd60,0,(undefined *)L"####################################### Re-set config");
    DlCfg_FUN_180016cc0((undefined8 *)&DAT_18005936a,0x100,200);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"UsbEcControl",
               0xd62,0,(undefined *)L"####################################### Set mode again");
    local_res10 = 1;
    device_action_FUN_180012f20(2,(longlong *)&local_res10,0);
  }
  else {
    if (bVar1 != 0) goto LAB_180012067;
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"UsbEcControl",
               0xd71,0,(undefined *)L"############################## Set mode Ack Timeout");
  }
  cVar2 = UsbSendDataToDevice_FUN_180012240
                    (DAT_18004eb00,10,7,(undefined8 *)&local_res8,2,'\x01',200);
  if (cVar2 == '\0') {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0x5b,&DAT_18002fad8);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"usbhal.c",(undefined *)L"UsbEcControl",
               0xd7f,0,(undefined *)L"EC_CONTROL no response");
    return 0;
  }
LAB_180012067:
  FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x5c,&DAT_18002fad8);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"UsbEcControl",
             0xd85,0,(undefined *)L"Exit");
  return 1;
}



undefined8 UsbEcGpioStatus_FUN_1800120d8(undefined *param_1)

{
  DWORD DVar1;
  undefined2 local_res10;
  
  local_res10 = 0;
  UsbSendDataToDevice_FUN_180012240(DAT_18004eb00,9,2,(undefined8 *)&local_res10,2,'\x01',200);
  DVar1 = WaitForSingleObject(DAT_18004eb20,2000);
  if (DVar1 == 0x102) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"usbhal.c",
               (undefined *)L"UsbGetEcGpioStatus",0xd9e,0,(undefined *)L"try twice");
    UsbSendDataToDevice_FUN_180012240(DAT_18004eb00,9,2,(undefined8 *)&local_res10,2,'\x01',200);
    DVar1 = WaitForSingleObject(DAT_18004eb20,2000);
    if (DVar1 == 0x102) {
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"usbhal.c",
                 (undefined *)L"UsbGetEcGpioStatus",0xdaa,0,(undefined *)L"set config timeout");
      return 0;
    }
  }
  *param_1 = DAT_1800594b8;
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"usbhal.c",
             (undefined *)L"UsbGetEcGpioStatus",0xdaf,0,
             (undefined *)L"********************gpioStatus = 0x%x");
  return 1;
}



void UsbSendDataToDevice_FUN_180012240
               (longlong param_1,byte param_2,byte param_3,undefined8 *param_4,int param_5,
               char param_6,int param_7)

{
  undefined4 uVar1;
  char cVar2;
  ulonglong uVar3;
  longlong lVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  wchar_t *pwVar8;
  byte bVar9;
  longlong lVar10;
  ulonglong uVar11;
  uint local_d0;
  uint local_c8;
  longlong local_b8;
  int local_b0;
  longlong local_a8;
  undefined local_98 [2];
  undefined uStack150;
  undefined2 uStack149;
  undefined2 uStack147;
  undefined2 uStack145;
  undefined2 uStack143;
  undefined2 uStack141;
  undefined2 uStack139;
  undefined2 uStack137;
  undefined2 uStack135;
  undefined2 local_85;
  undefined2 uStack131;
  undefined2 uStack129;
  undefined2 uStack127;
  undefined2 uStack125;
  undefined2 uStack123;
  undefined2 uStack121;
  undefined2 uStack119;
  undefined2 local_75;
  undefined2 uStack115;
  undefined2 uStack113;
  undefined2 uStack111;
  undefined2 uStack109;
  undefined2 uStack107;
  undefined2 uStack105;
  undefined2 local_67;
  undefined6 uStack101;
  undefined2 uStack95;
  undefined2 uStack93;
  undefined2 uStack91;
  undefined local_59;
  ulonglong local_58;
  
  local_58 = DAT_180037758 ^ (ulonglong)&stack0xfffffffffffffef8;
  uVar11 = SEXT48(param_5);
  local_c8 = (uint)param_3;
  bVar9 = (param_2 << 3 | param_3) * '\x02';
  local_b0 = param_5;
  local_d0 = (uint)param_2;
  local_b8 = param_1;
  FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x23,&DAT_18002fad8,param_2,param_3);
  pwVar8 = L"usbhal.c";
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
             (undefined *)L"UsbSendDataToDevice",0x349,0,
             (undefined *)L"UsbSendDataToDevice cmd0:0x:%x, cmd1:0x%x");
  uVar3 = (ulonglong)(byte)(param_2 * '\b' + param_3);
  lVar10 = uVar3 * 3;
  (&DAT_1800594e0)[uVar3 * 0x18] = 0;
  if (param_6 == '\x01') {
    cVar2 = (char)((uint)(param_5 + 1) >> 8) + '\x01' + (char)param_5 + bVar9;
    if ((uVar11 & 0xffff) != 0) {
      lVar4 = 0;
      do {
        cVar2 = cVar2 + *(char *)(lVar4 + (longlong)param_4);
        lVar4 = lVar4 + 1;
      } while (lVar4 < (longlong)(uVar11 & 0xffff));
    }
    cVar2 = -0x56 - cVar2;
  }
  else {
    cVar2 = -0x78;
  }
  iVar7 = param_5 + 3;
  local_98[1] = (char)param_5 + '\x01';
  iVar5 = (uint)(0 < iVar7 % 0x3f) + iVar7 / 0x3f;
  uStack150 = (undefined)((uint)(param_5 + 1) >> 8);
  local_a8 = lVar10;
  local_98[0] = bVar9;
  if (iVar5 == 1) {
    memcpy_FUN_180019c80((undefined8 *)&uStack149,param_4,uVar11);
    local_98[iVar7] = cVar2;
  }
  else {
    uVar3 = CONCAT71((int7)((ulonglong)pwVar8 >> 8),0x40);
    uStack149 = (undefined2)*(undefined4 *)param_4;
    uStack147 = (undefined2)((uint)*(undefined4 *)param_4 >> 0x10);
    uStack145 = (undefined2)*(undefined4 *)((longlong)param_4 + 4);
    uStack143 = (undefined2)((uint)*(undefined4 *)((longlong)param_4 + 4) >> 0x10);
    uStack141 = (undefined2)*(undefined4 *)(param_4 + 1);
    uStack139 = (undefined2)((uint)*(undefined4 *)(param_4 + 1) >> 0x10);
    uStack137 = (undefined2)*(undefined4 *)((longlong)param_4 + 0xc);
    uStack135 = (undefined2)((uint)*(undefined4 *)((longlong)param_4 + 0xc) >> 0x10);
    uStack93 = (undefined2)*(undefined4 *)(param_4 + 7);
    uStack91 = (undefined2)((uint)*(undefined4 *)(param_4 + 7) >> 0x10);
    local_59 = *(undefined *)((longlong)param_4 + 0x3c);
    local_85 = (undefined2)*(undefined4 *)(param_4 + 2);
    uStack131 = (undefined2)((uint)*(undefined4 *)(param_4 + 2) >> 0x10);
    uStack129 = (undefined2)*(undefined4 *)((longlong)param_4 + 0x14);
    uStack127 = (undefined2)((uint)*(undefined4 *)((longlong)param_4 + 0x14) >> 0x10);
    uStack125 = (undefined2)*(undefined4 *)(param_4 + 3);
    uStack123 = (undefined2)((uint)*(undefined4 *)(param_4 + 3) >> 0x10);
    uStack121 = (undefined2)*(undefined4 *)((longlong)param_4 + 0x1c);
    uStack119 = (undefined2)((uint)*(undefined4 *)((longlong)param_4 + 0x1c) >> 0x10);
    local_75 = (undefined2)*(undefined4 *)(param_4 + 4);
    uStack115 = (undefined2)((uint)*(undefined4 *)(param_4 + 4) >> 0x10);
    uStack113 = (undefined2)*(undefined4 *)((longlong)param_4 + 0x24);
    uStack111 = (undefined2)((uint)*(undefined4 *)((longlong)param_4 + 0x24) >> 0x10);
    uStack109 = (undefined2)*(undefined4 *)(param_4 + 5);
    uStack107 = (undefined2)((uint)*(undefined4 *)(param_4 + 5) >> 0x10);
    uStack105 = (undefined2)*(undefined4 *)((longlong)param_4 + 0x2c);
    local_67 = (undefined2)((uint)*(undefined4 *)((longlong)param_4 + 0x2c) >> 0x10);
    uStack101 = (undefined6)param_4[6];
    uStack95 = (undefined2)((ulonglong)param_4[6] >> 0x30);
    FUN_180011ad8(local_b8,(undefined8 *)local_98,uVar3);
    lVar4 = local_b8;
    bVar9 = bVar9 | 1;
    local_98[0] = bVar9;
    if (iVar5 == 2) {
      uVar11 = SEXT48(param_5 + -0x3d);
      memcpy_FUN_180019c80
                ((undefined8 *)(local_98 + 1),(undefined8 *)((longlong)param_4 + 0x3d),uVar11);
      iVar5 = param_5 + -0x3c;
    }
    else {
      iVar7 = 0x3d;
      if (1 < iVar5 + -1) {
        puVar6 = (undefined4 *)((longlong)param_4 + 0x3d);
        uVar11 = (ulonglong)(iVar5 - 2U);
        iVar7 = (iVar5 - 2U) * 0x3f + 0x3d;
        do {
          uVar1 = *puVar6;
          uVar3 = CONCAT71((int7)(uVar3 >> 8),0x40);
          uStack95 = (undefined2)puVar6[0xe];
          uStack93 = (undefined2)((uint)puVar6[0xe] >> 0x10);
          uStack91 = *(undefined2 *)(puVar6 + 0xf);
          local_98[1] = (char)uVar1;
          uStack150 = (undefined)((uint)uVar1 >> 8);
          uStack149 = (undefined2)((uint)uVar1 >> 0x10);
          uStack147 = (undefined2)puVar6[1];
          uStack145 = (undefined2)((uint)puVar6[1] >> 0x10);
          uStack143 = (undefined2)puVar6[2];
          uStack141 = (undefined2)((uint)puVar6[2] >> 0x10);
          uStack139 = (undefined2)puVar6[3];
          uStack137 = (undefined2)((uint)puVar6[3] >> 0x10);
          local_59 = *(undefined *)((longlong)puVar6 + 0x3e);
          uStack135 = (undefined2)puVar6[4];
          local_85 = (undefined2)((uint)puVar6[4] >> 0x10);
          uStack131 = (undefined2)puVar6[5];
          uStack129 = (undefined2)((uint)puVar6[5] >> 0x10);
          uStack127 = (undefined2)puVar6[6];
          uStack125 = (undefined2)((uint)puVar6[6] >> 0x10);
          uStack123 = (undefined2)puVar6[7];
          uStack121 = (undefined2)((uint)puVar6[7] >> 0x10);
          uStack119 = (undefined2)puVar6[8];
          local_75 = (undefined2)((uint)puVar6[8] >> 0x10);
          uStack115 = (undefined2)puVar6[9];
          uStack113 = (undefined2)((uint)puVar6[9] >> 0x10);
          uStack111 = (undefined2)puVar6[10];
          uStack109 = (undefined2)((uint)puVar6[10] >> 0x10);
          uStack107 = (undefined2)puVar6[0xb];
          uStack105 = (undefined2)((uint)puVar6[0xb] >> 0x10);
          local_67 = (undefined2)*(undefined8 *)(puVar6 + 0xc);
          uStack101 = (undefined6)((ulonglong)*(undefined8 *)(puVar6 + 0xc) >> 0x10);
          FUN_180011ad8(lVar4,(undefined8 *)local_98,uVar3);
          puVar6 = (undefined4 *)((longlong)puVar6 + 0x3f);
          uVar11 = uVar11 - 1;
          lVar10 = local_a8;
          param_5 = local_b0;
        } while (uVar11 != 0);
      }
      uVar11 = SEXT48(param_5 - iVar7);
      local_98[0] = bVar9;
      memcpy_FUN_180019c80
                ((undefined8 *)(local_98 + 1),(undefined8 *)((longlong)iVar7 + (longlong)param_4),
                 uVar11);
      iVar5 = (param_5 - iVar7) + 1;
    }
    local_98[iVar5] = cVar2;
  }
  FUN_180011ad8(local_b8,(undefined8 *)local_98,CONCAT71((int7)(uVar11 >> 8),0x40));
  if (param_7 != 0) {
    do {
      param_7 = param_7 + -1;
      if (((&DAT_1800594e0)[lVar10 * 8] & 1) != 0) break;
      timeBeginPeriod(1);
      Sleep(1);
      timeEndPeriod(1);
    } while (param_7 != 0);
  }
  FUN_180018b70(local_58 ^ (ulonglong)&stack0xfffffffffffffef8);
  return;
}



void FUN_180012528(undefined8 param_1,byte param_2,ulonglong param_3,ushort param_4,
                  undefined8 param_5,undefined param_6,undefined param_7,undefined param_8)

{
  longlong lVar1;
  ulonglong uVar2;
  uint uVar3;
  undefined1 *in_stack_ffffffffffffffa8;
  
  uVar2 = (param_3 & 0xffffffff) >> 0x10;
  uVar3 = (int)(param_3 & 0xffffffff) - 1;
  if (((*(uint *)(PTR_LOOP_180037650 + ((ulonglong)(uVar3 >> 5 & 0x7ff) + uVar2 * 0xe) * 4 + 0x1c)
        >> (uVar3 & 0x1f) & 1) != 0) &&
     (lVar1 = uVar2 * 0x38, param_2 <= (byte)PTR_LOOP_180037650[lVar1 + 0x19])) {
    in_stack_ffffffffffffffa8 = &param_6;
    TraceMessage(*(undefined8 *)(PTR_LOOP_180037650 + lVar1 + 0x10),0x2b,param_5,param_4,
                 in_stack_ffffffffffffffa8,4,&param_7,4,&param_8,4,0);
  }
  WppAutoLogTrace(param_1,param_2,param_3 & 0xffffffff,param_5,
                  (ulonglong)in_stack_ffffffffffffffa8 & 0xffffffffffff0000 | (ulonglong)param_4,
                  &param_6,4,&param_7,4,&param_8,4,0);
  return;
}



void FUN_180012660(undefined8 param_1,byte param_2,ulonglong param_3,ushort param_4,
                  undefined8 param_5,undefined param_6,undefined param_7,undefined param_8,
                  undefined param_9,undefined param_10)

{
  longlong lVar1;
  ulonglong uVar2;
  uint uVar3;
  undefined1 *in_stack_ffffffffffffff88;
  
  uVar2 = (param_3 & 0xffffffff) >> 0x10;
  uVar3 = (int)(param_3 & 0xffffffff) - 1;
  if (((*(uint *)(PTR_LOOP_180037650 + ((ulonglong)(uVar3 >> 5 & 0x7ff) + uVar2 * 0xe) * 4 + 0x1c)
        >> (uVar3 & 0x1f) & 1) != 0) &&
     (lVar1 = uVar2 * 0x38, param_2 <= (byte)PTR_LOOP_180037650[lVar1 + 0x19])) {
    in_stack_ffffffffffffff88 = &param_6;
    TraceMessage(*(undefined8 *)(PTR_LOOP_180037650 + lVar1 + 0x10),0x2b,param_5,param_4,
                 in_stack_ffffffffffffff88,4,&param_7,4,&param_8,4,&param_9,4,&param_10,4,0);
  }
  WppAutoLogTrace(param_1,param_2,param_3 & 0xffffffff,param_5,
                  (ulonglong)in_stack_ffffffffffffff88 & 0xffffffffffff0000 | (ulonglong)param_4,
                  &param_6,4,&param_7,4,&param_8,4,&param_9,4,&param_10,4,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void data_from_device_FUN_1800127e8(byte *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined uVar3;
  char cVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  longlong lVar7;
  HANDLE hEvent;
  byte bVar8;
  byte bVar9;
  uint uVar10;
  wchar_t *pwVar11;
  byte bVar12;
  undefined uVar13;
  byte bVar14;
  bool bVar15;
  undefined4 uVar16;
  wchar_t *pwVar17;
  
  uVar10 = DAT_18005acf8;
  bVar9 = *param_1;
  DAT_18005ad09 = DAT_18005ad0a;
  bVar8 = bVar9 >> 1;
  if (DAT_18005ad0a != bVar8) {
    DAT_18005ad08 = '\0';
  }
  if ((bVar9 & 1) == 0) {
    bVar14 = bVar9 & 0xfe;
    bVar9 = bVar9 >> 4;
    bVar12 = bVar8 & 7;
    DAT_18005ad10 = (ushort)param_1[2] * 0x100 + (ushort)param_1[1];
    uVar10 = (uint)DAT_18005ad10;
    DAT_18005ad0e = 0;
    DAT_18005ad0f = 1;
    _DAT_18005ad04 = (uint)((uVar10 + 2) % 0x3f != 0) + (uVar10 + 2) / 0x3f;
    DAT_18005acf8 = uVar10;
    DAT_18005ad0b = bVar14;
    DAT_18005ad0c = bVar9;
    DAT_18005ad0d = bVar12;
    if ((_DAT_18005ad04 == 1) && (uVar10 < 0x3e)) {
      DAT_18005ad0a = bVar8;
      memcpy_FUN_180019c80
                ((undefined8 *)&DAT_180053c4d,(undefined8 *)(param_1 + 3),(ulonglong)DAT_18005ad10);
      DAT_18005ad08 = 0;
      bVar15 = true;
    }
    else {
      _DAT_180053c4d = *(undefined4 *)(param_1 + 3);
      DAT_180053c51 = *(undefined4 *)(param_1 + 7);
      DAT_180053c55 = *(undefined4 *)(param_1 + 0xb);
      DAT_180053c59 = *(undefined4 *)(param_1 + 0xf);
      DAT_18005ad08 = 1;
      _DAT_180053c5d = *(undefined4 *)(param_1 + 0x13);
      DAT_180053c61 = *(undefined4 *)(param_1 + 0x17);
      DAT_180053c65 = *(undefined4 *)(param_1 + 0x1b);
      DAT_180053c69 = *(undefined4 *)(param_1 + 0x1f);
      _DAT_180053c6d = *(undefined4 *)(param_1 + 0x23);
      DAT_180053c71 = *(undefined4 *)(param_1 + 0x27);
      DAT_180053c75 = *(undefined4 *)(param_1 + 0x2b);
      DAT_180053c79 = *(undefined4 *)(param_1 + 0x2f);
      _DAT_180053c7d = *(undefined8 *)(param_1 + 0x33);
      _DAT_180053c85 = *(undefined4 *)(param_1 + 0x3b);
      DAT_180053c89 = param_1[0x3f];
      bVar15 = false;
      DAT_18005ad0a = bVar8;
    }
    DAT_18005acfc = 0x3d;
    DAT_18005ad00 = 1;
    uVar13 = 0;
  }
  else {
    if (DAT_18005ad08 != '\x01') {
      DAT_18005ad0a = bVar8;
      return;
    }
    DAT_18005ad00 = DAT_18005ad00 + 1;
    lVar7 = (longlong)(int)DAT_18005acfc;
    if (DAT_18005ad00 < _DAT_18005ad04) {
      uVar16 = *(undefined4 *)(param_1 + 5);
      uVar1 = *(undefined4 *)(param_1 + 9);
      uVar2 = *(undefined4 *)(param_1 + 0xd);
      DAT_18005ad0a = bVar8;
      *(undefined4 *)(&DAT_180053c4d + lVar7) = *(undefined4 *)(param_1 + 1);
      *(undefined4 *)((longlong)&DAT_180053c51 + lVar7) = uVar16;
      *(undefined4 *)((longlong)&DAT_180053c55 + lVar7) = uVar1;
      *(undefined4 *)((longlong)&DAT_180053c59 + lVar7) = uVar2;
      uVar16 = *(undefined4 *)(param_1 + 0x15);
      uVar1 = *(undefined4 *)(param_1 + 0x19);
      uVar2 = *(undefined4 *)(param_1 + 0x1d);
      *(undefined4 *)(&DAT_180053c5d + lVar7) = *(undefined4 *)(param_1 + 0x11);
      *(undefined4 *)((longlong)&DAT_180053c61 + lVar7) = uVar16;
      *(undefined4 *)((longlong)&DAT_180053c65 + lVar7) = uVar1;
      *(undefined4 *)((longlong)&DAT_180053c69 + lVar7) = uVar2;
      uVar16 = *(undefined4 *)(param_1 + 0x25);
      uVar1 = *(undefined4 *)(param_1 + 0x29);
      uVar2 = *(undefined4 *)(param_1 + 0x2d);
      *(undefined4 *)(&DAT_180053c6d + lVar7) = *(undefined4 *)(param_1 + 0x21);
      *(undefined4 *)((longlong)&DAT_180053c71 + lVar7) = uVar16;
      *(undefined4 *)((longlong)&DAT_180053c75 + lVar7) = uVar1;
      *(undefined4 *)((longlong)&DAT_180053c79 + lVar7) = uVar2;
      *(undefined8 *)(&DAT_180053c7d + lVar7) = *(undefined8 *)(param_1 + 0x31);
      *(undefined4 *)(&DAT_180053c85 + lVar7) = *(undefined4 *)(param_1 + 0x39);
      *(undefined2 *)(&DAT_180053c89 + lVar7) = *(undefined2 *)(param_1 + 0x3d);
      *(byte *)((longlong)&DAT_180053c8a + lVar7 + 1) = param_1[0x3f];
      DAT_18005acfc = DAT_18005acfc + 0x3f;
    }
    else {
      DAT_18005ad0a = bVar8;
      if ((int)(DAT_18005acf8 - DAT_18005acfc) < 0x40) {
        memcpy_FUN_180019c80
                  ((undefined8 *)(&DAT_180053c4d + lVar7),(undefined8 *)(param_1 + 1),
                   (longlong)(int)(DAT_18005acf8 - DAT_18005acfc));
        DAT_18005acfc = uVar10;
      }
    }
    if ((int)DAT_18005acfc < (int)uVar10) {
      return;
    }
    bVar15 = true;
    uVar10 = (uint)DAT_18005ad10;
    DAT_18005ad08 = 0;
    bVar14 = DAT_18005ad0b;
    bVar9 = DAT_18005ad0c;
    bVar12 = DAT_18005ad0d;
    uVar13 = DAT_18005ad0e;
  }
  uVar3 = DAT_18005ad0f;
  lVar7 = 0;
  if (!bVar15) {
    return;
  }
  if (*(char *)((longlong)&DAT_180053c49 + (ulonglong)uVar10 + 3) == -0x78) {
    bVar15 = true;
  }
  else {
    cVar4 = (char)(uVar10 >> 8) + (char)uVar10 + bVar14;
    if (uVar10 != 0) {
      do {
        cVar4 = cVar4 + (&DAT_180053c4d)[lVar7];
        lVar7 = lVar7 + 1;
      } while (lVar7 < (int)uVar10);
    }
    bVar15 = cVar4 == -0x56;
  }
  if (!bVar15) {
    return;
  }
  uVar5 = (ulonglong)bVar8;
  DAT_18005ad12 = bVar8;
  (&DAT_1800594d0)[uVar5 * 0x18] = bVar14;
  (&DAT_1800594d1)[uVar5 * 0x18] = bVar9;
  (&DAT_1800594d2)[uVar5 * 0x18] = bVar12;
  (&DAT_1800594d3)[uVar5 * 0x18] = uVar13;
  *(short *)(&DAT_1800594d4 + uVar5 * 0x18) = (short)uVar10;
  (&DAT_1800594d6)[uVar5 * 0x18] = uVar3;
  *(undefined1 **)(&DAT_1800594d8 + uVar5 * 0x18) = &DAT_180053c4d;
  uVar5 = 0;
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"data_from_device"
             ,0x534,0,(undefined *)L"data from device 0x%x");
  uVar6 = (ulonglong)DAT_18005ad12;
  cVar4 = (&DAT_1800594d1)[uVar6 * 0x18];
  if (cVar4 == '\x02') {
    if (DAT_180059480 == (code *)0x0) {
      return;
    }
    cVar4 = (*DAT_180059480)(*(longlong *)(&DAT_1800594d8 + uVar6 * 0x18) + 5);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"data_from_device",0x53f,0,
               (undefined *)L"receive image data...length:%u");
    pwVar11 = L"data_from_device";
    if (cVar4 == '\x01') {
      DAT_180053bd8 = 0;
      pwVar17 = L"image crc check Ok...";
      uVar16 = 0x542;
    }
    else {
      pwVar17 = L"image crc check failed...";
      uVar16 = 0x545;
    }
  }
  else {
    if (cVar4 == '\x03') {
      if (DAT_180059490 == (code *)0x0) {
        return;
      }
      (*DAT_180059490)(*(undefined8 *)(&DAT_1800594d8 + uVar6 * 0x18),
                       uVar5 & 0xffffffffffffff00 | (ulonglong)(byte)(&DAT_1800594d2)[uVar6 * 0x18])
      ;
      return;
    }
    if (cVar4 != '\x05') {
      if (cVar4 == '\b') {
        memcpy_FUN_180019c80
                  ((undefined8 *)&DAT_18004eb53,*(undefined8 **)(&DAT_1800594d8 + uVar6 * 0x18),
                   (ulonglong)*(ushort *)(&DAT_1800594d4 + uVar6 * 0x18) - 1);
        hEvent = DAT_18004eb18;
      }
      else {
        if (cVar4 == '\t') {
          hEvent = DAT_18004eb20;
          if ((&DAT_1800594d2)[uVar6 * 0x18] == '\x02') {
            _DAT_1800594b8 = (ulonglong)**(byte **)(&DAT_1800594d8 + uVar6 * 0x18);
            debug_print_FUN_180001ce4
                      ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"usbhal.c",
                       (undefined *)L"data_from_device",0x55a,0,
                       (undefined *)L"pData[0]:0x%x, pData[1]:0x%x");
            hEvent = DAT_18004eb20;
          }
        }
        else {
          if (cVar4 == '\n') {
            FUN_180015340((&DAT_1800594d2)[uVar6 * 0x18],
                          *(undefined8 **)(&DAT_1800594d8 + uVar6 * 0x18),
                          (&DAT_1800594d4)[uVar6 * 0x18] - 1);
            return;
          }
          if (cVar4 == '\v') {
            bVar9 = **(byte **)(&DAT_1800594d8 + uVar6 * 0x18);
            if ((&DAT_1800594d2)[uVar6 * 0x18] != '\0') {
              return;
            }
            (&DAT_1800594e0)[(ulonglong)(byte)((bVar9 >> 4) * '\b' + (bVar9 >> 1 & 7)) * 0x18] =
                 (*(byte **)(&DAT_1800594d8 + uVar6 * 0x18))[1];
            return;
          }
          if (cVar4 == '\f') {
            if ((&DAT_1800594d2)[uVar6 * 0x18] == '\0') {
              DAT_180053bd8 = 10;
              memcpy_FUN_180019c80
                        ((undefined8 *)&DAT_18004eb53,
                         *(undefined8 **)(&DAT_1800594d8 + uVar6 * 0x18),
                         (ulonglong)(byte)((&DAT_1800594d4)[uVar6 * 0x18] - 1));
              pwVar17 = L"ESD happened";
              uVar16 = 0x681;
            }
            else {
              if ((&DAT_1800594d2)[uVar6 * 0x18] != '\x01') {
                return;
              }
              DAT_180053bd8 = 0xb;
              pwVar17 = L"wakeup.....";
              uVar16 = 0x685;
            }
            pwVar11 = L"get_notice_data";
            goto LAB_180012efc;
          }
          if (cVar4 != '\x0f') {
            return;
          }
          DAT_18004eb53 = *param_1;
          hEvent = DAT_18004eb30;
        }
      }
      SetEvent(hEvent);
      return;
    }
    if (DAT_180059488 == (code *)0x0) {
      return;
    }
    cVar4 = (*DAT_180059488)(*(longlong *)(&DAT_1800594d8 + uVar6 * 0x18) + 5);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"data_from_device",0x562,0,(undefined *)L"receive nav data...length:%u"
              );
    pwVar11 = L"data_from_device";
    if (cVar4 == '\x01') {
      DAT_180053bd8 = 7;
      pwVar17 = L"nav crc check ok";
      uVar16 = 0x565;
    }
    else {
      pwVar17 = L"nav crc check failed";
      uVar16 = 0x568;
    }
  }
LAB_180012efc:
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)pwVar11,uVar16,0,
             (undefined *)pwVar17);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulonglong device_action_FUN_180012f20(int action,longlong *param_2,ulonglong param_3)

{
  undefined uVar1;
  uint uVar2;
  ulonglong uVar3;
  byte bVar4;
  byte bVar5;
  undefined8 uVar6;
  char cVar7;
  ulonglong uVar8;
  byte bVar9;
  ushort uVar10;
  ulonglong uVar11;
  undefined8 local_res20;
  undefined4 uVar12;
  wchar_t *pwVar13;
  
  uVar3 = 0;
  local_res20._0_4_ = 0;
  uVar8 = 1;
  if (DAT_180053c2c == '\0') {
    return 0;
  }
  uVar11 = param_3;
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_180053b58);
  if (0xb < action) {
    if (action == 0xc) {
      uVar1 = DAT_180053bf0;
      if (param_2 == (longlong *)0x0) goto LAB_18001332e;
LAB_18001332c:
      *(undefined *)param_2 = uVar1;
      uVar3 = uVar8;
      goto LAB_18001332e;
    }
    if (action == 0xd) {
      uVar3 = uVar8;
      if (param_2 != (longlong *)0x0) {
        bVar5 = *(byte *)param_2;
        if ((chip_id_DAT_180053be0 != 0x2202) && (chip_id_DAT_180053be0 == 0x2207)) {
          bVar5 = bVar5 | 4;
        }
        local_res20._0_4_ = (uint)local_res20 & 0xffff0000 | (uint)(byte)(bVar5 << 3);
        UsbSendDataToDevice_FUN_180012240(DAT_18004eb00,9,1,&local_res20,2,'\x01',200);
      }
      goto LAB_18001332e;
    }
    if (action == 0xe) {
      uVar3 = gf_getdowndacframe_FUN_180016814(param_2);
      uVar2 = (uint)uVar3;
LAB_1800132c1:
      uVar3 = (ulonglong)uVar2;
    }
    else {
      if (action == 0xf) {
        uVar3 = uVar8;
        if (param_2 != (longlong *)0x0) {
          _DAT_180053c14 = (uint)*(byte *)param_2;
        }
        goto LAB_18001332e;
      }
      if (action == 0x10) {
        if (param_2 != (longlong *)0x0) {
          *(undefined *)param_2 = DAT_180053c08;
        }
        pwVar13 = L"fdt_is_down: %d";
        uVar12 = 0x4ba;
      }
      else {
        if (action == 0x11) {
          pwVar13 = L"fdt_is_down: %d";
          uVar12 = 0x4be;
          _DAT_180053c08 = 0;
        }
        else {
          if (action != 0x12) {
            if (action != 0x13) {
              if (action == 0x14) {
                Sleep(500);
                UsbEcControl_FUN_180011e20(0,0);
                uVar3 = uVar8;
              }
              goto LAB_18001332e;
            }
            uVar2 = gf_update_all_base_FUN_18001715c();
            goto LAB_1800132c1;
          }
          if (param_2 != (longlong *)0x0) {
            DAT_180053c18 = (uint)*(byte *)param_2;
          }
          pwVar13 = L"bcanceldata: %d";
          uVar12 = 0x4c4;
        }
      }
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"device_action",uVar12,0,(undefined *)pwVar13);
      uVar3 = uVar8;
    }
    goto LAB_18001332e;
  }
  if (action == 0xb) {
    CheckTcodeAndDiff_FUN_180011228(param_2);
    uVar3 = uVar8;
    goto LAB_18001332e;
  }
  if (5 < action) {
    if (action != 6) {
      if (action == 7) {
        GetOTP_FUN_18001540c(param_2,(ushort)param_3,200);
        uVar3 = uVar8;
      }
      else {
        if (action == 8) {
          cVar7 = '\0';
        }
        else {
          if (action != 9) goto LAB_18001332e;
          cVar7 = '\x01';
        }
        SetSPIClk_FUN_180017f48((ushort *)param_2,cVar7,CONCAT71((int7)(uVar11 >> 8),200));
        uVar3 = uVar8;
      }
      goto LAB_18001332e;
    }
    uVar10 = 5000;
    cVar7 = '\x01';
LAB_180012faa:
    gfresetMCUAndfingerprint_FUN_180017ce4('\x01',cVar7,uVar10,(int *)param_2);
    uVar3 = uVar8;
    goto LAB_18001332e;
  }
  if (action == 5) {
    gfresetMCUAndfingerprint_FUN_180017ce4('\0','\x01',5000,(int *)&local_res20);
    uVar3 = uVar8;
    if (param_2 != (longlong *)0x0) {
      *(short *)param_2 = (short)((uint)local_res20 >> 8);
    }
    goto LAB_18001332e;
  }
  if (action == 0) {
    GetEvkVersion_FUN_180011918((undefined4 *)param_2,200);
    uVar3 = uVar8;
    goto LAB_18001332e;
  }
  if (action == 1) {
    DlCfg_FUN_180016cc0(param_2,param_3 & 0xffff,200);
    uVar3 = uVar8;
    goto LAB_18001332e;
  }
  if (action != 2) {
    uVar1 = (undefined)DAT_180053bd8;
    if (action == 3) goto LAB_18001332c;
    if (action != 4) goto LAB_18001332e;
    param_2 = (longlong *)0x0;
    uVar10 = 3000;
    cVar7 = '\0';
    goto LAB_180012faa;
  }
  if (param_2 == (longlong *)0x0) goto LAB_18001332e;
  bVar5 = *(byte *)param_2;
  if (bVar5 == 0) {
    uVar6 = 2;
LAB_1800130d0:
    (*DAT_180059470)(uVar6,0,0);
    uVar3 = uVar8;
    goto LAB_18001332e;
  }
  if (bVar5 == 1) {
    if ((ushort)param_3 != 0xff) {
      if (DAT_180053c20 != 0) {
        (**(code **)(DAT_18005ad20 + 0x640))();
        DAT_180053c20 = 0;
      }
      uVar3 = uVar8;
      if (_DAT_180053c00 != 0) goto LAB_18001332e;
      bVar5 = 1;
LAB_18001302f:
      bVar4 = 3;
      goto LAB_180013043;
    }
    bVar9 = 0;
    bVar5 = 1;
    bVar4 = 3;
  }
  else {
    if (bVar5 == 2) goto LAB_18001302f;
    bVar4 = bVar5;
    if (bVar5 != 3) {
      if (bVar5 == 6) {
        if (DAT_180053c20 != 0) {
          (**(code **)(DAT_18005ad20 + 0x640))
                    (DAT_18005ad28,DAT_180053c20,uVar11 & 0xffffffffffffff00 | 1);
          DAT_180053c20 = 0;
        }
        uVar3 = uVar8;
        if (_DAT_180053c00 != 0) goto LAB_18001332e;
        uVar6 = 7;
      }
      else {
        uVar3 = uVar8;
        if (bVar5 != 4) goto LAB_18001332e;
        if (DAT_180053c20 != 0) {
          (**(code **)(DAT_18005ad20 + 0x640))
                    (DAT_18005ad28,DAT_180053c20,uVar11 & 0xffffffffffffff00 | 1);
          DAT_180053c20 = 0;
        }
        if (_DAT_180053c00 != 0) goto LAB_18001332e;
        uVar6 = 6;
      }
      goto LAB_1800130d0;
    }
LAB_180013043:
    bVar9 = 1;
  }
  gf_set_mode_FUN_180016d04(bVar4,bVar5,bVar9);
  uVar3 = uVar8;
LAB_18001332e:
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_180053b58);
  return uVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_180013350(void)

{
  int iVar1;
  byte *_Buf1;
  undefined8 uVar2;
  ulonglong uVar3;
  undefined8 uVar4;
  byte bVar5;
  uint uVar6;
  byte *pbVar7;
  undefined4 uVar8;
  wchar_t *pwVar9;
  
  uVar4 = 1;
  uVar6 = (uint)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe) +
          *(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe) + 0x3c;
  _Buf1 = (byte *)malloc((ulonglong)uVar6);
  if (_Buf1 == (byte *)0x0) {
    return 0;
  }
  uVar2 = FUN_180001870(L"C:\\ProgramData\\Goodix\\goodix.dat",_Buf1,(ulonglong)uVar6,L"rb");
  if ((int)uVar2 == -1) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"usbhal.c",
               (undefined *)L"device_check_imagebase_exist",0x88f,0,(undefined *)L"read file failed"
              );
    DAT_180053bec = 0;
    uVar4 = 0;
  }
  else {
    FUN_180002770();
    DAT_180037440 = 0xffffffff;
    uVar3 = FUN_1800027b4(_Buf1,uVar6 - 4);
    if ((int)uVar3 ==
        (uint)_Buf1[uVar6 - 1] * 0x1000000 + (uint)_Buf1[uVar6 - 2] * 0x10000 +
        (uint)_Buf1[uVar6 - 3] * 0x100 + (uint)_Buf1[uVar6 - 4]) {
      bVar5 = 0;
      pbVar7 = _Buf1;
      do {
        FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x2c,&DAT_18002fad8,bVar5,
                      *pbVar7);
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                   (undefined *)L"device_check_imagebase_exist",0x8af,0,
                   (undefined *)L"get file otp[%d]:0x%x");
        bVar5 = bVar5 + 1;
        pbVar7 = pbVar7 + 1;
      } while (bVar5 < 0x20);
      iVar1 = memcmp(_Buf1,&DAT_180053c2d,0x20);
      if (iVar1 == 0) {
        DAT_180059328 = *(undefined4 *)(_Buf1 + 0x20);
        DAT_18005932c = *(undefined4 *)(_Buf1 + 0x24);
        DAT_180059330 = *(undefined4 *)(_Buf1 + 0x28);
        DAT_180059334 = *(undefined4 *)(_Buf1 + 0x2c);
        DAT_180059338 = *(undefined8 *)(_Buf1 + 0x30);
        memcpy_FUN_180019c80
                  (DAT_180059320,(undefined8 *)(_Buf1 + 0x38),
                   (ulonglong)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe))
        ;
        memcpy_FUN_180019c80
                  (DAT_180059310,
                   (undefined8 *)
                   (_Buf1 + (ulonglong)
                            *(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe) +
                            0x38),
                   (ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe))
        ;
        DAT_180053bec = 1;
        (*_DAT_180059498)(&DAT_180059328,0);
        goto LAB_1800135d6;
      }
      pwVar9 = L"sensor id is unequal";
      uVar8 = 0x8be;
    }
    else {
      pwVar9 = L"otp crc failed";
      uVar8 = 0x8a2;
    }
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"usbhal.c",
               (undefined *)L"device_check_imagebase_exist",uVar8,0,(undefined *)pwVar9);
    DAT_180053bec = 0;
  }
LAB_1800135d6:
  free(_Buf1);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
             (undefined *)L"device_check_imagebase_exist",0x8cd,0,(undefined *)L"imagebase exist:%d"
            );
  return uVar4;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 device_data_analyze_FUN_180013640(longlong param_1)

{
  longlong lVar1;
  ulonglong uVar2;
  DWORD dwMilliseconds;
  HANDLE hEvent;
  uint uVar3;
  char cVar4;
  uint uVar5;
  undefined8 local_res8;
  uint local_res10 [2];
  undefined4 uVar6;
  wchar_t *pwVar7;
  
  uVar5 = 0;
  if (param_1 == 0) {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0x1d,&DAT_18002fad8);
    pwVar7 = L"Error, Device NULL";
    uVar6 = 0x26b;
  }
  else {
    lVar1 = (**(code **)(DAT_18005ad20 + 0x3d8))();
    if (lVar1 != 0) {
      _DAT_180053be4 = 0;
      do {
        if (DAT_180053bd8 == 0) {
          pwVar7 = L"device_data_analyze";
          debug_print_FUN_180001ce4
                    ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                     (undefined *)L"device_data_analyze",0x27c,0,
                     (undefined *)L"got data for GF_IMAGE_MODE");
          uVar2 = FUN_1800024d4();
          if ((int)uVar2 == 0) {
            EnterCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
            DAT_180053bd8 = 0xc;
            LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
            FUN_180002408(DAT_180059308,
                          (ulonglong)
                          *(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
            if (*(char *)(lVar1 + 0x564) == '\x04') {
              if ((*(uint *)(lVar1 + 0x598) & 0xfffffffd) != 0) goto LAB_180013da0;
              if (DAT_1800594c8 != (code *)0x0) {
                pwVar7 = (wchar_t *)(ulonglong)DAT_180053bf4;
                (*DAT_1800594c8)(lVar1,DAT_180059310,DAT_180059308);
              }
              FUN_1800014f4((longlong)"%s %d caputure one frame for DEAD_PIXEL",
                            "device_data_analyze",0x290,pwVar7);
              FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x1f,&DAT_18002fad8);
              pwVar7 = L"caputure one frame for DEAD_PIXEL";
              uVar6 = 0x292;
            }
            else {
              hEvent = DAT_18004eb10;
              if ((*(char *)(lVar1 + 0x564) != '\x03') ||
                 ((*(uint *)(lVar1 + 0x588) & 0xfffffffd) != 0)) goto LAB_180013d9a;
              if (DAT_1800594c8 != (code *)0x0) {
                pwVar7 = (wchar_t *)(ulonglong)DAT_180053bf4;
                (*DAT_1800594c8)(lVar1,DAT_180059310,DAT_180059308);
              }
              FUN_1800014f4((longlong)"%s %d caputure one frame for OPEN_SHORT",
                            "device_data_analyze",0x29d,pwVar7);
              FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x20,&DAT_18002fad8);
              pwVar7 = L"caputure one frame for OPEN_SHORT";
              uVar6 = 0x29f;
            }
            debug_print_FUN_180001ce4
                      ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                       (undefined *)L"device_data_analyze",uVar6,0,(undefined *)pwVar7);
LAB_180013da0:
            FUN_18000234c(*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
          }
          else {
LAB_180013bfb:
            dwMilliseconds = 10;
LAB_180013c00:
            Sleep(dwMilliseconds);
          }
        }
        else {
          if (DAT_180053bd8 == 3) {
            EnterCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
            DAT_180053bd8 = 0xc;
            LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
            SetEvent(DAT_18004eb28);
          }
          else {
            if (DAT_180053bd8 == 7) {
              FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x21,&DAT_18002fad8);
              debug_print_FUN_180001ce4
                        ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                         (undefined *)L"device_data_analyze",0x2a8,0,
                         (undefined *)L"got data for GF_NAV_MODE");
              uVar2 = FUN_1800024d4();
              if ((int)uVar2 != 0) goto LAB_180013bfb;
              EnterCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
              DAT_180053bd8 = 0xc;
              LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
              FUN_180002408(DAT_180059318,
                            (ulonglong)
                            *(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe));
              hEvent = DAT_18004eb08;
LAB_180013d9a:
              SetEvent(hEvent);
              goto LAB_180013da0;
            }
            if (DAT_180053bd8 == 10) {
              EnterCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
              DAT_180053bd8 = 0xc;
              LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
              if (_DAT_180053c14 == 1) {
                uVar3 = (uint)DAT_18004eb54 * 0x100 + (uint)DAT_18004eb53;
                local_res10[0] = uVar3;
                debug_print_FUN_180001ce4
                          ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                           (undefined *)L"device_data_analyze",0x2c7,0,
                           (undefined *)L"fingerprint esd...IRQ:0x%x");
                if (DAT_18005b4a0 == 0) {
                  uVar5 = 0x100;
                }
                else {
                  if (DAT_18005b4a0 - 1U < 3) {
                    uVar5 = 0x400;
                  }
                }
                cVar4 = '\n';
                if (uVar3 == uVar5) {
                  do {
                    (*DAT_180059470)(7,0);
                    ChipRegRead_FUN_1800116dc(0,&local_res8,4,100);
                    if ((ushort)((ushort)local_res8._2_1_ * 0x100 + (ushort)local_res8._1_1_) ==
                        chip_id_DAT_180053be0) {
                      DAT_180053bd8 = 9;
                      goto LAB_180013db5;
                    }
                    cVar4 = cVar4 + -1;
                    Sleep(100);
                  } while ('\0' < cVar4);
                }
                else {
                  do {
                    uVar2 = gfresetMCUAndfingerprint_FUN_180017ce4
                                      ('\0','\x01',3000,(int *)local_res10);
                    uVar3 = local_res10[0];
                    if ((char)uVar2 == '\x01') {
                      debug_print_FUN_180001ce4
                                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                                 (undefined *)L"device_data_analyze",0x2ec,0,
                                 (undefined *)L"IRQ:0x%x");
                      if (uVar3 >> 8 == uVar5) {
                        (*DAT_180059470)(7,0);
                        ChipRegRead_FUN_1800116dc(0,&local_res8,4,100);
                        if ((ushort)((ushort)local_res8._2_1_ * 0x100 + (ushort)local_res8._1_1_) ==
                            chip_id_DAT_180053be0) {
                          DAT_180053bd8 = 9;
                          goto LAB_180013db5;
                        }
                      }
                      Sleep(100);
                    }
                    else {
                      Sleep(100);
                    }
                    cVar4 = cVar4 + -1;
                  } while ('\0' < cVar4);
                }
                if (cVar4 == '\0') {
                  debug_print_FUN_180001ce4
                            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                             (undefined *)L"device_data_analyze",0x308,0,(undefined *)L"retry >= 10"
                            );
                  gfresetMCUAndfingerprint_FUN_180017ce4('\x01','\x01',3000,(int *)local_res10);
                }
              }
            }
            else {
              if (DAT_180053bd8 != 0xb) {
                dwMilliseconds = 5;
                goto LAB_180013c00;
              }
              EnterCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
              DAT_180053bd8 = 0xc;
              LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
              if (DAT_180053c20 != 0) {
                (**(code **)(DAT_18005ad20 + 0x640))(DAT_18005ad28,DAT_180053c20,1);
                DAT_180053c20 = 0;
                debug_print_FUN_180001ce4
                          ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                           (undefined *)L"device_data_analyze",0x317,0,
                           (undefined *)L"Stop temperature timer......");
              }
              if (_DAT_180053c00 == 0) {
                if (((_DAT_18004eae0 < 2) || (DAT_180037690 != '\x01')) || (DAT_18004ead0 != '\0'))
                {
                  if (_DAT_180053c08 == 0) {
                    gf_set_mode_FUN_180016d04(3,1,1);
                    pwVar7 = L"wakeup:fdt_down";
                    uVar6 = 0x323;
                  }
                  else {
                    gf_set_mode_FUN_180016d04(3,2,1);
                    pwVar7 = L"wakeup:fdt_up";
                    uVar6 = 0x328;
                  }
                  uVar3 = 9;
                }
                else {
                  _DAT_18004eae0 = 0;
                  pwVar7 = L"gPowerAction>=S3:do nothing";
                  uVar3 = 7;
                  uVar6 = 0x31c;
                }
                debug_print_FUN_180001ce4
                          ((longlong)PTR_DAT_180036ca8,uVar3,(undefined *)L"usbhal.c",
                           (undefined *)L"device_data_analyze",uVar6,0,(undefined *)pwVar7);
              }
            }
          }
        }
LAB_180013db5:
        if (_DAT_180053be4 != 0) {
          FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x22,&DAT_18002fad8);
          debug_print_FUN_180001ce4
                    ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                     (undefined *)L"device_data_analyze",0x333,0,(undefined *)L"Exit");
          return 1;
        }
      } while( true );
    }
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0x1e,&DAT_18002fad8);
    pwVar7 = L"Error, DeviceContext NULL";
    uVar6 = 0x272;
  }
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"usbhal.c",
             (undefined *)L"device_data_analyze",uVar6,0,(undefined *)pwVar7);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_180013e38(void)

{
  undefined8 uVar1;
  byte bVar2;
  HANDLE *ppvVar3;
  
  if (DAT_180053c2c == '\0') {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0x12,&DAT_18002fad8);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"usbhal.c",(undefined *)L"device_disable"
               ,0x1dc,0,(undefined *)L"User zero");
    uVar1 = 0;
  }
  else {
    DAT_180053c2c = '\0';
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"device_disable"
               ,0x1e0,0,(undefined *)L"Entry");
    if (DAT_18004eb40 != (HANDLE)0xffffffffffffffff) {
      _DAT_180053be4 = 1;
      WaitForSingleObject(DAT_18004eb40,0xffffffff);
      if (DAT_18004eb40 != (HANDLE)0xffffffffffffffff) {
        CloseHandle(DAT_18004eb40);
      }
      DAT_18004eb40 = (HANDLE)0xffffffffffffffff;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x13,&DAT_18002fad8);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"device_disable",0x1eb,0,(undefined *)L"data analyze handle released"
                );
    }
    if (DAT_18004eb48 != (HANDLE)0xffffffffffffffff) {
      _DAT_180053be8 = 1;
      WaitForSingleObject(DAT_18004eb48,0xffffffff);
      if (DAT_18004eb48 != (HANDLE)0xffffffffffffffff) {
        CloseHandle(DAT_18004eb48);
      }
      DAT_18004eb48 = (HANDLE)0xffffffffffffffff;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"device_disable",0x1f6,0,
                 (undefined *)L"fdt data analyze handle released");
    }
    bVar2 = 0;
    ppvVar3 = (HANDLE *)&DAT_18004eb08;
    do {
      if (*ppvVar3 != (HANDLE)0x0) {
        CloseHandle(*ppvVar3);
        *ppvVar3 = (HANDLE)0xffffffffffffffff;
        FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x14,&DAT_18002fad8,bVar2);
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                   (undefined *)L"device_disable",0x1fe,0,
                   (undefined *)L"gethandle released index:%d");
      }
      bVar2 = bVar2 + 1;
      ppvVar3 = ppvVar3 + 1;
    } while (bVar2 < 7);
    if (DAT_180053c20 != 0) {
      (**(code **)(DAT_18005ad20 + 0x640))(DAT_18005ad28);
      DAT_180053c20 = 0;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x15,&DAT_18002fad8);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"device_disable",0x207,0,(undefined *)L"temperaturetimer released");
    }
    DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_180053b58);
    DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_180053b80);
    DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
    DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_18005acd0);
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x16,&DAT_18002fad8);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"device_disable"
               ,0x211,0,(undefined *)L"Critical sections deleted");
    if (DAT_180053bd0 != 0) {
      (**(code **)(DAT_18005ad20 + 0x408))(DAT_18005ad28);
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x17,&DAT_18002fad8);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"device_disable",0x216,0,(undefined *)L"localMemory released");
    }
    if (DAT_180059308 != (void *)0x0) {
      free(DAT_180059308);
      DAT_180059308 = (void *)0x0;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x18,&DAT_18002fad8);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"device_disable",0x21d,0,(undefined *)L"g_halcontext.frame released")
      ;
    }
    if (DAT_180059310 != (void *)0x0) {
      free(DAT_180059310);
      DAT_180059310 = (void *)0x0;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x19,&DAT_18002fad8);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"device_disable",0x225,0,
                 (undefined *)L"g_halcontext.imagebase released");
    }
    if (DAT_180059318 != (void *)0x0) {
      free(DAT_180059318);
      DAT_180059318 = (void *)0x0;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x1a,&DAT_18002fad8);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"device_disable",0x22d,0,
                 (undefined *)L"g_halcontext.navbase released");
    }
    if (DAT_180059320 != (void *)0x0) {
      free(DAT_180059320);
      DAT_180059320 = (void *)0x0;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x1b,&DAT_18002fad8);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"device_disable",0x234,0,
                 (undefined *)L"g_halcontext.filenavbase released");
    }
    if (DAT_18005b4a0 == 0) {
      FUN_18000cbb4();
    }
    else {
      if (DAT_18005b4a0 - 1U < 2) {
        FUN_18000b5b4();
      }
      else {
        if (DAT_18005b4a0 == 3) {
          FUN_18000dda0();
        }
      }
    }
    FUN_1800023bc();
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x1c,&DAT_18002fad8);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"device_disable"
               ,0x244,0,(undefined *)L"Exit");
    uVar1 = 1;
  }
  return uVar1;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void device_enable_FUN_180014424(void *param_1)

{
  longlong lVar1;
  char cVar2;
  longlong lVar3;
  HANDLE pvVar4;
  longlong lVar5;
  byte *pbVar6;
  byte bVar7;
  ulonglong uVar8;
  uint uVar9;
  int iVar10;
  undefined4 uVar11;
  uint local_98;
  undefined4 local_90;
  undefined local_88 [5];
  byte bStack131;
  byte bStack129;
  int local_7c;
  undefined4 local_78;
  ulonglong local_38;
  
  local_38 = DAT_180037758 ^ (ulonglong)&stack0xffffffffffffff18;
  local_88._0_4_ = 0xf2;
  stack0xffffffffffffff7c = 0;
  local_7c = 0;
  if (((param_1 == (void *)0x0) || (DAT_180053c2c != '\0')) ||
     (lVar3 = (**(code **)(DAT_18005ad20 + 0x3d8))(DAT_18005ad28,param_1,PTR_DAT_180036d28),
     lVar3 == 0)) goto LAB_180014daa;
  DAT_18004eb00 = *(longlong *)(lVar3 + 0x18);
  uVar8 = 0;
  do {
    pvVar4 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCWSTR)0x0);
    *(HANDLE *)((longlong)&DAT_18004eb08 + uVar8 * 8) = pvVar4;
    if (pvVar4 == (HANDLE)0x0) goto LAB_180014daa;
    bVar7 = (char)uVar8 + 1;
    uVar8 = (ulonglong)bVar7;
  } while (bVar7 < 7);
  DAT_180053c2c = DAT_180053c2c + '\x01';
  _DAT_180053bec = 0;
  _DAT_180053bf4 = 0;
  DAT_180053c20 = 0;
  DAT_18004eb40 = (HANDLE)0x0;
  _DAT_180053c04 = 1;
  _DAT_180053bfc = 0;
  _DAT_180053c08 = 0;
  DAT_180053bd8 = 0xc;
  _DAT_180053c10 = 0;
  DAT_180053c18 = 0;
  _DAT_1800594b8 = 2;
  DAT_1800594c0 = 1;
  _DAT_1800594c4 = 0;
  DAT_1800594b0 = param_1;
  FUN_180011a00();
  InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_180053b58);
  InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_180053b80);
  InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_180053ba8);
  InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_18005acd0);
  (**(code **)(DAT_18005ad20 + 0x3a8))(DAT_18005ad28,0,0,0);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"device_enable",
             0x12d,0,(undefined *)L"base flow version=%S");
  cVar2 = UsbSendDataToDevice_FUN_180012240
                    (DAT_18004eb00,0,0,(undefined8 *)(local_88 + 4),2,'\x01',100);
  if (cVar2 == '\0') {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"device_enable",
               0x134,0,(undefined *)L"NOP cmd timeout");
  }
  FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0xc,&DAT_18002fad8);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",(undefined *)L"device_enable",
             0x138,0,(undefined *)L"Reset fingerprint sensor");
  gfresetMCUAndfingerprint_FUN_180017ce4('\0','\x01',3000,(int *)0x0);
  FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0xd,&DAT_18002fad8);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",(undefined *)L"device_enable",
             0x13c,0,(undefined *)L"Get Evk Version");
  cVar2 = GetEvkVersion_FUN_180011918(&local_78,100);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",(undefined *)L"device_enable",
             0x141,0,(undefined *)L"firmware version=%S, ren=%d");
  if (cVar2 == '\0') goto LAB_180014daa;
  lVar5 = -1;
  do {
    lVar1 = lVar5 + 1;
    lVar5 = lVar5 + 1;
  } while (*(char *)((longlong)&local_78 + lVar1) != '\0');
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"device_enable",
             0x144,0,(undefined *)L"firmware version:%S...len:%d");
  FUN_1800164b8((char *)&local_78,(undefined4 *)local_88);
  *(int *)(lVar3 + 0x108) = local_88._0_4_;
  if (local_88._0_4_ == 0xf0) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"device_enable",
               0x14e,0,(undefined *)L"St platform");
    iVar10 = 0x7aa8;
    pbVar6 = &DAT_180022000;
LAB_1800148b6:
    gfUpdatefirmware_FUN_1800154d8((char *)&local_78,pbVar6,iVar10);
  }
  else {
    if (local_88._0_4_ == 0xf1) {
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"device_enable",0x14a,0,(undefined *)L"Ht platform");
      iVar10 = 0x6024;
      pbVar6 = &DAT_180029ab0;
      goto LAB_1800148b6;
    }
    if (local_88._0_4_ == 0xf2) {
      uVar11 = 0x152;
    }
    else {
      uVar11 = 0x155;
    }
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"device_enable",
               uVar11,0,(undefined *)L"Unknown platform");
  }
  if (_DAT_1800594c4 == 1) goto LAB_180014daa;
  DAT_18004eb40 =
       (HANDLE)_beginthreadex((void *)0x0,0,device_data_analyze_FUN_180013640,param_1,4,(uint *)0x0)
  ;
  if (DAT_18004eb40 != (HANDLE)0x0) {
    ResumeThread(DAT_18004eb40);
  }
  DAT_18004eb48 =
       (HANDLE)_beginthreadex((void *)0x0,0,(_StartAddress *)&LAB_180014dd8,param_1,4,(uint *)0x0);
  if (DAT_18004eb48 != (HANDLE)0x0) {
    ResumeThread(DAT_18004eb48);
  }
  local_88._0_4_ = CONCAT22(local_88._2_2_,0x1010);
  FUN_180011880(8,local_88,2,100);
  FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0xe,&DAT_18002fad8,8,0x10);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"device_enable",
             0x16f,0,(undefined *)L"write vendorId(0x%x) to:0x%x");
  cVar2 = ChipRegRead_FUN_1800116dc(6,(undefined8 *)local_88,2,100);
  if (cVar2 != '\0') {
    FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0xf,&DAT_18002fad8,6,
                  (char)local_88._0_4_);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"device_enable",
               0x17a,0,(undefined *)L"get vendorId(0x%x):0x%x");
  }
  local_88._0_4_ = CONCAT22(local_88._2_2_,0x1111);
  FUN_180011880(8,local_88,2,100);
  FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x10,&DAT_18002fad8,8,0x11);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"device_enable",
             0x18a,0,(undefined *)L"write vendorId(0x%x) to:0x%x");
  gfresetMCUAndfingerprint_FUN_180017ce4('\0','\x01',3000,&local_7c);
  cVar2 = ChipRegRead_FUN_1800116dc(0,(undefined8 *)(local_88 + 4),4,100);
  if (cVar2 != '\x01') goto LAB_180014daa;
  local_98 = (uint)bStack129;
  uVar9 = stack0xffffffffffffff7c >> 0x10 & 0xff;
  iVar10 = uVar9 * 0x100 + local_98 * 0x10000 + (uint)bStack131;
  chip_id_DAT_180053be0 = (undefined2)iVar10;
  FUN_180012660(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x11,&DAT_18002fad8,
                (char)stack0xffffffffffffff7c,bStack131,(char)uVar9,bStack129,1);
  local_90 = 1;
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"device_enable",
             0x194,0,(undefined *)L"Chip id[0] %x [1] %x [2] %x [3] %x... ren:%d");
  if (iVar10 == 0x2202) {
    *(undefined4 *)(lVar3 + 0xa8) = 0;
    DAT_18005b4a0 = 0;
    FUN_18000cbd0((longlong)&DAT_18004eb00);
  }
  else {
    if (iVar10 == 0x2207) {
      *(undefined4 *)(lVar3 + 0xa8) = 1;
      DAT_18005b4a0 = 1;
    }
    else {
      if (iVar10 != 0x2208) {
        if (iVar10 != 0x2205) goto LAB_180014daa;
        *(undefined4 *)(lVar3 + 0xa8) = 3;
        DAT_18005b4a0 = 3;
        FUN_18000ddbc((longlong)&DAT_18004eb00);
        goto LAB_180014c76;
      }
      *(undefined4 *)(lVar3 + 0xa8) = 2;
      DAT_18005b4a0 = 2;
    }
    set_callbacks_FUN_18000b5d0((longlong)&DAT_18004eb00);
  }
LAB_180014c76:
  FUN_180002474(*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
  DAT_180059308 =
       malloc((ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
  if (((DAT_180059308 != (void *)0x0) &&
      (DAT_180059310 =
            malloc((ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe))
      , DAT_180059310 != (void *)0x0)) &&
     ((DAT_180059318 =
            malloc((ulonglong)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe))
      , DAT_180059318 != (void *)0x0 &&
      (DAT_180059320 =
            malloc((ulonglong)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe))
      , DAT_180059320 != (void *)0x0)))) {
    memset(DAT_180059308,0,
           (ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
    memset(DAT_180059310,0,
           (ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
    memset(DAT_180059318,0,
           (ulonglong)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe));
    memset(DAT_180059320,0,
           (ulonglong)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe));
  }
LAB_180014daa:
  FUN_180018b70(local_38 ^ (ulonglong)&stack0xffffffffffffff18);
  return;
}



undefined8 FUN_1800152d8(longlong param_1,byte param_2)

{
  undefined8 uVar1;
  
  if (DAT_180053c2c == '\0') {
    uVar1 = 0;
  }
  else {
    FUN_18000234c(*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
    if (param_1 != 0) {
      DAT_1800594c8 = param_1;
    }
    DAT_180053bf8 = (uint)param_2;
    uVar1 = 1;
  }
  return uVar1;
}



void FUN_180015340(char param_1,undefined8 *param_2,byte param_3)

{
  byte bVar1;
  
  if (param_1 != '\0') {
    if (param_1 == '\x01') {
      memcpy_FUN_180019c80((undefined8 *)&DAT_18004eb53,param_2,(ulonglong)param_3);
      bVar1 = 0;
      if (param_3 != 0) {
        do {
          debug_print_FUN_180001ce4
                    ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                     (undefined *)L"get_other_data",0x664,0,(undefined *)L"buf[%d]:0x%x");
          bVar1 = bVar1 + 1;
        } while (bVar1 < param_3);
      }
      goto LAB_18001537f;
    }
    if ((param_1 != '\x03') && (param_1 != '\x04')) {
      return;
    }
  }
  memcpy_FUN_180019c80((undefined8 *)&DAT_18004eb53,param_2,(ulonglong)param_3);
LAB_18001537f:
  SetEvent(DAT_18004eb38);
  return;
}



void GetOTP_FUN_18001540c(undefined8 *param_1,ushort param_2,uint param_3)

{
  DWORD DVar1;
  uint dwMilliseconds;
  undefined2 local_res20;
  
  local_res20 = 0;
  dwMilliseconds = param_3 & 0xffff;
  UsbSendDataToDevice_FUN_180012240
            (DAT_18004eb00,10,3,(undefined8 *)&local_res20,2,'\x01',dwMilliseconds);
  DVar1 = WaitForSingleObject(DAT_18004eb38,dwMilliseconds);
  if (DVar1 == 0x102) {
    UsbSendDataToDevice_FUN_180012240
              (DAT_18004eb00,10,3,(undefined8 *)&local_res20,2,'\x01',dwMilliseconds);
    DVar1 = WaitForSingleObject(DAT_18004eb38,dwMilliseconds);
    if (DVar1 == 0x102) {
      return;
    }
  }
  memcpy_FUN_180019c80(param_1,(undefined8 *)&DAT_18004eb53,(ulonglong)(uint)param_2);
  memset(&DAT_18004eb53,0,(ulonglong)(uint)param_2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gfUpdatefirmware_FUN_1800154d8(char *param_1,byte *param_2,int param_3)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  int iVar6;
  ulonglong uVar7;
  undefined2 local_res8;
  
  if (param_1 == (char *)0x0) {
    return;
  }
  if (param_2 == (byte *)0x0) {
    return;
  }
  iVar6 = FUN_180016314(param_1,&DAT_180030a88);
  if (iVar6 == 0) {
    iVar6 = FUN_180016314(param_1,&DAT_180030b80);
    if (iVar6 != 0) {
      bVar1 = *param_2;
      FUN_180002770();
      DAT_180037440 = 0xffffffff;
      uVar7 = FUN_1800027b4(param_2,param_3 - 4U);
      bVar2 = param_2[param_3 - 1];
      bVar3 = param_2[param_3 - 2];
      bVar4 = param_2[param_3 - 3];
      bVar5 = param_2[param_3 - 4U];
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"usbhal.c",
                 (undefined *)L"gfUpdatefirmware",0x775,0,
                 (undefined *)L"check firmware filecrc:%x realcrc:%x");
      if ((uint)bVar2 * 0x1000000 + (uint)bVar3 * 0x10000 + (uint)bVar4 * 0x100 + (uint)bVar5 ==
          (int)uVar7) {
        UpdateFirmware_FUN_180017fe0
                  (param_2 + (byte)(bVar1 + 1),(param_3 - (uint)(byte)(bVar1 + 1)) - 4);
        _DAT_1800594c4 = 1;
        return;
      }
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"usbhal.c",
                 (undefined *)L"gfUpdatefirmware",0x77d,0,
                 (undefined *)L"check firmware crc failed , Do not update firmware!!!!");
      _DAT_1800594c4 = 1;
      return;
    }
    iVar6 = FUN_180016314(param_1,"TESTAPP");
    if (iVar6 == 0) {
      return;
    }
  }
  else {
    iVar6 = FUN_180016144(param_1,(char *)(param_2 + 1));
    if (iVar6 != 0) {
      return;
    }
    FUN_180002770();
    DAT_180037440 = 0xffffffff;
    uVar7 = FUN_1800027b4(param_2,param_3 - 4U);
    bVar1 = param_2[param_3 - 1];
    bVar2 = param_2[param_3 - 2];
    bVar3 = param_2[param_3 - 3];
    bVar4 = param_2[param_3 - 4U];
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"usbhal.c",
               (undefined *)L"gfUpdatefirmware",0x754,0,
               (undefined *)L"check firmware filecrc:%x realcrc:%x");
    if ((uint)bVar1 * 0x1000000 + (uint)bVar2 * 0x10000 + (uint)bVar3 * 0x100 + (uint)bVar4 !=
        (int)uVar7) {
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"usbhal.c",
                 (undefined *)L"gfUpdatefirmware",0x764,0,
                 (undefined *)L"check firmware crc failed , Do not update firmware!!!!");
      return;
    }
  }
  local_res8 = 0x3200;
  UsbSendDataToDevice_FUN_180012240(DAT_18004eb00,10,2,(undefined8 *)&local_res8,2,'\x01',0);
  _DAT_1800594c4 = 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 gf_captureFingerdata_FUN_180015760(longlong param_1)

{
  uint *puVar1;
  int iVar2;
  undefined8 *_Memory;
  ULONGLONG UVar3;
  ulonglong uVar4;
  ULONGLONG UVar5;
  undefined8 uVar6;
  wchar_t *pwVar7;
  undefined4 local_res8;
  undefined4 uVar8;
  undefined4 local_48 [8];
  
  uVar6 = 1;
  FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x43,&DAT_18002fad8);
  pwVar7 = L"gf_captureFingerdata";
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
             (undefined *)L"gf_captureFingerdata",0xb07,0,(undefined *)L"Entry");
  puVar1 = (uint *)(param_1 + 0x5f4);
  FUN_180001800((int *)puVar1);
  if (*(char *)(param_1 + 0x564) == '\x04') {
    if (*(int *)(param_1 + 0x598) == 2) {
      local_res8 = 0;
      device_action_FUN_180012f20(2,(longlong *)&local_res8,0);
      FUN_1800014f4((longlong)
                                        
                    "%s %d OPEN_SHORT-BeforeDACChange & AfterDACChange, DEAD_PIXEL-STAGE_Base to image mode for capture base frame"
                    ,"gf_captureFingerdata",0xb10,pwVar7);
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x44,&DAT_18002fad8);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_captureFingerdata",0xb12,0,
                 (undefined *)
                                  
                 L"whole:OPEN_SHORT-BeforeDACChange & AfterDACChange, DEAD_PIXEL-STAGE_Base to image mode for capture base frame"
                );
      return 1;
    }
  }
  else {
    if ((*(char *)(param_1 + 0x564) == '\x05') && (*(int *)(param_1 + 0x580) == 0)) {
      FUN_180001800((int *)puVar1);
      FUN_1800014f4((longlong)"%s %d capture the begin time %lu.%lu","gf_captureFingerdata",0xb1a,
                    (ulonglong)*puVar1);
      FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),1,3,0x45,&DAT_18002fad8,(char)*puVar1
                    ,(char)*(undefined4 *)(param_1 + 0x5f8));
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,2,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_captureFingerdata",0xb1c,0,
                 (undefined *)L"capture the begin time %lu.%lu");
    }
  }
  _Memory = (undefined8 *)
            malloc((ulonglong)
                   ((uint)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe) +
                   (uint)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe)));
  if (_Memory == (undefined8 *)0x0) {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),1,3,0x46,&DAT_18002fad8);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,2,(undefined *)L"usbhal.c",
               (undefined *)L"gf_captureFingerdata",0xb26,0,(undefined *)L"Memory malloc failed");
    return 0;
  }
  if (*(int *)(param_1 + 0x150) != 0) {
    FUN_180001544((longlong)L"start capture data for identify");
  }
  UVar3 = GetTickCount64();
  uVar4 = gf_get_oneframe_FUN_1800166c4(_Memory,500);
  if ((int)uVar4 == 0) {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,(short)uVar4 + 0x47,&DAT_18002fad8)
    ;
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"gf_captureFingerdata",0xb37,0,(undefined *)L"gf_get_oneframe timeout")
    ;
    uVar6 = 0;
    goto LAB_180015adc;
  }
  UVar5 = GetTickCount64();
  *(char *)(param_1 + 0x5fd) = (char)UVar5 - (char)UVar3;
  uVar4 = FUN_18000b140(DAT_180059310,(longlong)_Memory);
  iVar2 = (int)uVar4;
  if (iVar2 == 0) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"gf_captureFingerdata",0xb44,0,(undefined *)L"imageret: temp");
LAB_180015b81:
    iVar2 = (int)(uVar4 & 0xffffffff);
    if (iVar2 != 1) {
      if (iVar2 == 0) {
        if (_DAT_180053c00 == 0) {
          if (DAT_180053c20 != 0) {
            (**(code **)(DAT_18005ad20 + 0x640))(DAT_18005ad28);
            DAT_180053c20 = 0;
            FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,
                          (short)(uVar4 & 0xffffffff) + 0x4e,&DAT_18002fad8);
            debug_print_FUN_180001ce4
                      ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                       (undefined *)L"gf_captureFingerdata",0xbc0,0,
                       (undefined *)L"Stop temperature timer......");
            if (_DAT_180053c00 != 0) goto LAB_180015adc;
          }
          gf_temperatureoccure_FUN_180016fc8();
        }
        goto LAB_180015adc;
      }
LAB_180015acf:
      gf_set_mode_FUN_180016d04(3,1,1);
      goto LAB_180015adc;
    }
  }
  else {
    if (iVar2 != 1) {
      if (iVar2 == 2) {
        pwVar7 = L"imageret: void";
        uVar8 = 0xb4a;
      }
      else {
        if (iVar2 != 3) goto LAB_180015b81;
        pwVar7 = L"imageret: bad";
        uVar8 = 0xb47;
      }
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_captureFingerdata",uVar8,0,(undefined *)pwVar7);
      goto LAB_180015acf;
    }
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"gf_captureFingerdata",0xb4d,0,(undefined *)L"imageret: finger");
  }
  _DAT_180053bfc = 1;
  if (DAT_1800594c8 != (code *)0x0) {
    (*DAT_1800594c8)(param_1,DAT_180059310,_Memory,DAT_180053bf4);
    DAT_180053bf8 = 0;
    if (DAT_180053bf4 == 1) {
      DAT_180053bf4 = 0;
    }
  }
  gf_get_fdtbase_FUN_1800165a4(local_48,200);
  gf_set_mode_FUN_180016d04(3,2,1);
  _DAT_180053bfc = 0;
LAB_180015adc:
  free(_Memory);
  return uVar6;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_check_baseisvalid_FUN_180015c98(void)

{
  int iVar1;
  uint uVar2;
  undefined8 *_Memory;
  undefined8 *_Memory_00;
  ulonglong uVar3;
  undefined8 uVar4;
  undefined4 uVar5;
  wchar_t *pwVar6;
  
  _Memory = (undefined8 *)
            malloc((ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe))
  ;
  if (_Memory == (undefined8 *)0x0) {
    return;
  }
  _Memory_00 = (undefined8 *)
               malloc((ulonglong)
                      *(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe));
  if (_Memory_00 == (undefined8 *)0x0) goto LAB_1800160ab;
  FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x3f,&DAT_18002fad8,
                (char)_DAT_180053bf0);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
             (undefined *)L"gf_check_baseisvalid",0xa82,0,(undefined *)L"base_is_valid:%d");
  if (_DAT_180053bf0 != 0) goto LAB_1800160ab;
  uVar3 = gf_get_oneframe_FUN_1800166c4(_Memory,500);
  if ((int)uVar3 == 0) {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x40,&DAT_18002fad8);
    pwVar6 = L"gf_get_oneframe timeout";
    uVar5 = 0xa89;
  }
  else {
    uVar3 = FUN_18000b140((longlong)DAT_180059310,(longlong)_Memory);
    iVar1 = (int)uVar3;
    if (iVar1 == 0) {
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_check_baseisvalid",0xa9d,0,(undefined *)L"imageret: temp");
LAB_180015ec1:
      if (iVar1 != 1) {
LAB_180015ec6:
        memcpy_FUN_180019c80
                  (DAT_180059310,_Memory,
                   (ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe))
        ;
        if ((iVar1 == 0) || (_DAT_180053bf0 == 0)) {
          DAT_180053bf4 = 1;
        }
      }
    }
    else {
      if (iVar1 != 1) {
        if (iVar1 == 2) {
          pwVar6 = L"imageret: void";
          uVar5 = 0xaa3;
        }
        else {
          if (iVar1 != 3) goto LAB_180015ec1;
          pwVar6 = L"imageret: bad";
          uVar5 = 0xaa0;
        }
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_check_baseisvalid",uVar5,0,(undefined *)pwVar6);
        goto LAB_180015ec6;
      }
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_check_baseisvalid",0xaa6,0,(undefined *)L"imageret: finger");
    }
    uVar4 = gf_get_navbase_FUN_180016608(_Memory_00,200);
    if ((int)uVar4 != 0) {
      uVar3 = FUN_18000b15c((longlong)DAT_180059320,(longlong)_Memory_00);
      uVar2 = (uint)uVar3;
      if (uVar2 == 0) {
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_check_baseisvalid",0xac2,0,(undefined *)L"navret: temp");
LAB_180016029:
        if (uVar2 != 1) {
LAB_18001602e:
          memcpy_FUN_180019c80
                    (DAT_180059320,_Memory_00,
                     (ulonglong)
                     *(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe));
        }
      }
      else {
        if (uVar2 != 1) {
          if (uVar2 == 2) {
            pwVar6 = L"navret: void";
            uVar5 = 0xac8;
          }
          else {
            if (uVar2 != 3) goto LAB_180016029;
            pwVar6 = L"navret: bad";
            uVar5 = 0xac5;
          }
          debug_print_FUN_180001ce4
                    ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                     (undefined *)L"gf_check_baseisvalid",uVar5,0,(undefined *)pwVar6);
          goto LAB_18001602e;
        }
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_check_baseisvalid",0xacb,0,(undefined *)L"navret: finger");
      }
      if ((iVar1 != 1) || (uVar2 != 1)) {
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,8,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_check_baseisvalid",0xad8,0,(undefined *)L"Save base to file");
        FUN_180016a70();
      }
      FUN_18000a7cc((undefined4 *)&DAT_180053bf0,iVar1,uVar2);
      goto LAB_1800160ab;
    }
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,(short)uVar4 + 0x41,&DAT_18002fad8)
    ;
    pwVar6 = L"gf_get_navbase timeout";
    uVar5 = 0xabc;
  }
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
             (undefined *)L"gf_check_baseisvalid",uVar5,0,(undefined *)pwVar6);
LAB_1800160ab:
  free(_Memory);
  if (_Memory_00 != (undefined8 *)0x0) {
    free(_Memory_00);
  }
  FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x42,&DAT_18002fad8,
                (char)_DAT_180053bf0);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
             (undefined *)L"gf_check_baseisvalid",0xaf3,0,(undefined *)L"Exit, base_is_valid:%d");
  return;
}



void FUN_180016144(char *param_1,char *param_2)

{
  int iVar1;
  char *pcVar2;
  longlong lVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  byte bVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  size_t _Size;
  char local_218 [192];
  char local_158 [64];
  char local_118 [192];
  undefined local_58 [64];
  ulonglong local_18;
  size_t sVar10;
  
  local_18 = DAT_180037758 ^ (ulonglong)&stack0xfffffffffffffda8;
  uVar5 = 0;
  uVar4 = 0;
  if ((param_1 != (char *)0x0) && (param_2 != (char *)0x0)) {
    uVar8 = 0xffffffffffffffff;
    do {
      uVar8 = uVar8 + 1;
    } while (param_1[uVar8] != '\0');
    bVar7 = (byte)uVar8;
    if (bVar7 < 0x41) {
      if (bVar7 != 0) {
        uVar6 = uVar8 & 0xff;
        do {
          lVar3 = uVar5 * 0x40;
          pcVar2 = local_218 + uVar4;
          if (*param_1 == '_') {
            uVar5 = (ulonglong)(byte)((char)uVar5 + 1);
            pcVar2[lVar3] = '\0';
            uVar4 = 0;
          }
          else {
            uVar4 = (ulonglong)(byte)((char)uVar4 + 1);
            pcVar2[lVar3] = *param_1;
          }
          param_1 = param_1 + 1;
          uVar6 = uVar6 - 1;
        } while (uVar6 != 0);
      }
      uVar9 = 0;
      uVar6 = 0;
      local_218[uVar5 * 0x40 + uVar4] = '\0';
      if (bVar7 != 0) {
        uVar8 = uVar8 & 0xff;
        do {
          lVar3 = uVar6 * 0x40;
          pcVar2 = local_118 + uVar9;
          if (*param_2 == '_') {
            uVar6 = (ulonglong)(byte)((char)uVar6 + 1);
            pcVar2[lVar3] = '\0';
            uVar9 = 0;
          }
          else {
            uVar9 = (ulonglong)(byte)((char)uVar9 + 1);
            pcVar2[lVar3] = *param_2;
          }
          param_2 = param_2 + 1;
          uVar8 = uVar8 - 1;
        } while (uVar8 != 0);
      }
      local_118[uVar6 * 0x40 + uVar9] = '\0';
      sVar10 = 0xffffffffffffffff;
      do {
        _Size = sVar10 + 1;
        lVar3 = sVar10 + 1;
        sVar10 = _Size;
      } while (local_158[lVar3] != '\0');
      iVar1 = memcmp(local_58,local_158,_Size);
      if (iVar1 == 0) {
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_compareVersionNum",0xd3f,0,
                   (undefined *)L"firmware version equal,Do not update firmware!!!!");
      }
      else {
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_compareVersionNum",0xd42,0,
                   (undefined *)L"firmware version not equal,update firmware!!!");
      }
    }
  }
  FUN_180018b70(local_18 ^ (ulonglong)&stack0xfffffffffffffda8);
  return;
}



void FUN_180016314(char *param_1,undefined *param_2)

{
  int iVar1;
  ulonglong uVar2;
  char *pcVar3;
  ulonglong uVar4;
  size_t _Size;
  ulonglong uVar5;
  byte bVar6;
  undefined *local_120;
  char local_118 [256];
  ulonglong local_18;
  
  local_18 = DAT_180037758 ^ (ulonglong)&stack0xfffffffffffffea8;
  bVar6 = 0;
  uVar5 = 0;
  if ((param_1 != (char *)0x0) && (param_2 != (undefined *)0x0)) {
    uVar2 = 0xffffffffffffffff;
    do {
      uVar2 = uVar2 + 1;
    } while (param_1[uVar2] != '\0');
    if ((byte)uVar2 < 0x41) {
      if ((byte)uVar2 != 0) {
        uVar2 = uVar2 & 0xff;
        do {
          uVar4 = (ulonglong)bVar6;
          pcVar3 = local_118 + uVar5;
          if (*param_1 == '_') {
            bVar6 = bVar6 + 1;
            pcVar3[uVar4 * 0x40] = '\0';
            uVar5 = 0;
          }
          else {
            uVar5 = (ulonglong)(byte)((char)uVar5 + 1);
            pcVar3[uVar4 * 0x40] = *param_1;
          }
          param_1 = param_1 + 1;
          uVar2 = uVar2 - 1;
        } while (uVar2 != 0);
      }
      uVar2 = 0;
      local_118[(ulonglong)bVar6 * 0x40 + uVar5] = '\0';
      do {
        _Size = 0xffffffffffffffff;
        do {
          _Size = _Size + 1;
        } while (param_2[_Size] != '\0');
        iVar1 = memcmp(local_118 + uVar2 * 0x40,param_2,_Size);
        if (iVar1 == 0) {
          FUN_1800079d8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x59,&DAT_18002fad8,param_2);
          goto LAB_180016461;
        }
        bVar6 = (char)uVar2 + 1;
        uVar2 = (ulonglong)bVar6;
      } while (bVar6 < 4);
      FUN_1800079d8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x5a,&DAT_18002fad8,param_2);
      local_120 = param_2;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_findAPPOrIAP",0xd0a,0,(undefined *)L"Not Find :%S");
    }
  }
LAB_180016461:
  FUN_180018b70(local_18 ^ (ulonglong)&stack0xfffffffffffffea8);
  return;
}



void FUN_1800164b8(char *param_1,undefined4 *param_2)

{
  ulonglong uVar1;
  ulonglong uVar2;
  longlong lVar3;
  byte bVar4;
  byte bVar6;
  char local_118 [64];
  short local_d8;
  ulonglong local_18;
  ulonglong uVar5;
  
  local_18 = DAT_180037758 ^ (ulonglong)local_118;
  uVar5 = 0;
  bVar4 = 0;
  bVar6 = 0;
  if ((param_1 != (char *)0x0) && (param_2 != (undefined4 *)0x0)) {
    uVar1 = 0xffffffffffffffff;
    do {
      uVar1 = uVar1 + 1;
    } while (param_1[uVar1] != '\0');
    if ((byte)uVar1 < 0x41) {
      if ((byte)uVar1 != 0) {
        uVar1 = uVar1 & 0xff;
        do {
          uVar2 = (ulonglong)bVar6;
          lVar3 = uVar5 * 0x40;
          if (*param_1 == '_') {
            uVar5 = (ulonglong)(byte)((char)uVar5 + 1);
            (local_118 + uVar2)[lVar3] = '\0';
            bVar6 = 0;
          }
          else {
            bVar6 = bVar6 + 1;
            (local_118 + uVar2)[lVar3] = *param_1;
          }
          bVar4 = (byte)uVar5;
          param_1 = param_1 + 1;
          uVar1 = uVar1 - 1;
        } while (uVar1 != 0);
      }
      local_118[(ulonglong)bVar4 * 0x40 + (ulonglong)bVar6] = '\0';
      if (local_d8 == 0x5448) {
        *param_2 = 0xf1;
      }
      else {
        if (local_d8 == 0x5453) {
          *param_2 = 0xf0;
        }
      }
    }
    else {
      *param_2 = 0xf2;
    }
  }
  FUN_180018b70(local_18 ^ (ulonglong)local_118);
  return;
}



undefined8 gf_get_fdtbase_FUN_1800165a4(undefined4 *param_1,ushort param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  DWORD DVar4;
  
  if (param_1 != (undefined4 *)0x0) {
    gf_set_mode_FUN_180016d04(3,3,1);
    DVar4 = WaitForSingleObject(DAT_18004eb28,(uint)param_2);
    uVar3 = DAT_180059354;
    uVar2 = DAT_180059350;
    uVar1 = DAT_18005934c;
    if (DVar4 != 0x102) {
      *param_1 = DAT_180059348;
      param_1[1] = uVar1;
      param_1[2] = uVar2;
      param_1[3] = uVar3;
      *(undefined8 *)(param_1 + 4) = DAT_180059358;
      return 1;
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 gf_get_navbase_FUN_180016608(undefined8 *param_1,uint param_2)

{
  DWORD DVar1;
  
  if (DAT_18005b4a0 == 0) {
    (*DAT_180059470)(2,0,0);
    DVar1 = WaitForSingleObject(DAT_18004eb10,param_2 & 0xffff);
    if (DVar1 == 0x102) {
      return 0;
    }
    (*_DAT_1800594a0)(param_1,DAT_180059308);
  }
  else {
    if (DAT_18005b4a0 - 1U < 3) {
      (*DAT_180059470)(5,0);
      DVar1 = WaitForSingleObject(DAT_18004eb08,param_2 & 0xffff);
      if (DVar1 == 0x102) {
        return 0;
      }
      memcpy_FUN_180019c80
                (param_1,DAT_180059318,
                 (ulonglong)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe));
    }
  }
  return 1;
}



ulonglong gf_get_oneframe_FUN_1800166c4(undefined8 *param_1,uint param_2)

{
  byte bVar1;
  DWORD DVar2;
  undefined4 uVar3;
  wchar_t *pwVar4;
  
  bVar1 = (*DAT_180059470)(2,0);
  if ((bVar1 & 3) == 3) {
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"gf_get_oneframe",0x920,0,
               (undefined *)L"####################################### Re-set config");
    DlCfg_FUN_180016cc0((undefined8 *)&DAT_18005936a,0x100,200);
    pwVar4 = L"####################################### Set mode again";
    uVar3 = 0x923;
  }
  else {
    if (bVar1 != 0) goto LAB_1800167a2;
    pwVar4 = L"############################## Set mode Ack Timeout";
    uVar3 = 0x928;
  }
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"gf_get_oneframe",
             uVar3,0,(undefined *)pwVar4);
  (*DAT_180059470)(2,0);
LAB_1800167a2:
  DVar2 = WaitForSingleObject(DAT_18004eb10,param_2 & 0xffff);
  if (DVar2 != 0x102) {
    memcpy_FUN_180019c80
              (param_1,DAT_180059308,
               (ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
    memset(DAT_180059308,0,
           (ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
  }
  return (ulonglong)(DVar2 != 0x102);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulonglong gf_getdowndacframe_FUN_180016814(undefined8 *param_1)

{
  ulonglong uVar1;
  bool bVar2;
  
  if (param_1 != (undefined8 *)0x0) {
    if (_DAT_180053bf0 != 0) {
      (*DAT_180059470)(7,0);
      (*_DAT_180059478)();
      FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x56,&DAT_18002fad8,
                    (char)DAT_180053c28,0);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_getdowndacframe",0xc99,0,(undefined *)L"get dac:%x down dac:0x%x"
                );
      uVar1 = gf_get_oneframe_FUN_1800166c4(param_1,500);
      bVar2 = (int)uVar1 != 0;
      if (!bVar2) {
        FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,(short)uVar1 + 0x57,
                      &DAT_18002fad8);
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_getdowndacframe",0xc9e,0,
                   (undefined *)L"gf_get_oneframe for downdac timeout");
      }
      (*_DAT_180059478)();
      FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x58,&DAT_18002fad8,
                    (char)DAT_180053c28,0);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_getdowndacframe",0xca9,0,(undefined *)L"get dac:%x back dac:0x%x"
                );
      gf_set_mode_FUN_180016d04(3,2,1);
      return (ulonglong)bVar2;
    }
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x55,&DAT_18002fad8);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"gf_getdowndacframe",0xc8d,0,
               (undefined *)L"base is not valid, not down dac now");
  }
  return 0;
}



void FUN_180016a70(void)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 *_Dst;
  ulonglong uVar4;
  uint uVar5;
  
  _Dst = (undefined4 *)
         malloc((ulonglong)
                ((uint)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe) +
                *(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe) + 0x3c));
  if (_Dst != (undefined4 *)0x0) {
    memset(_Dst,0,(ulonglong)
                  ((uint)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe) +
                  *(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe) + 0x3c));
    FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x3d,&DAT_18002fad8,
                  (char)*(undefined2 *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe),
                  (char)*(undefined2 *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
               (undefined *)L"gf_savebaseTofile",0xa47,0,
               (undefined *)L"nav buffer size:%u buffer size:%u");
    uVar3 = DAT_180053c39;
    uVar2 = DAT_180053c35;
    uVar1 = DAT_180053c31;
    *_Dst = DAT_180053c2d;
    _Dst[1] = uVar1;
    _Dst[2] = uVar2;
    _Dst[3] = uVar3;
    uVar3 = DAT_180053c49;
    uVar2 = DAT_180053c45;
    uVar1 = DAT_180053c41;
    _Dst[4] = DAT_180053c3d;
    _Dst[5] = uVar1;
    _Dst[6] = uVar2;
    _Dst[7] = uVar3;
    uVar3 = DAT_180059334;
    uVar2 = DAT_180059330;
    uVar1 = DAT_18005932c;
    _Dst[8] = DAT_180059328;
    _Dst[9] = uVar1;
    _Dst[10] = uVar2;
    _Dst[0xb] = uVar3;
    *(undefined8 *)(_Dst + 0xc) = DAT_180059338;
    memcpy_FUN_180019c80
              ((undefined8 *)(_Dst + 0xe),DAT_180059320,
               (ulonglong)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe));
    memcpy_FUN_180019c80
              ((undefined8 *)
               ((ulonglong)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe) +
                0x38 + (longlong)_Dst),DAT_180059310,
               (ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
    uVar5 = (uint)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe) +
            *(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe) + 0x38;
    _wmkdir(L"C:\\ProgramData\\Goodix");
    FUN_180002770();
    DAT_180037440 = 0xffffffff;
    uVar4 = FUN_1800027b4((byte *)_Dst,uVar5);
    *(int *)((ulonglong)uVar5 + (longlong)_Dst) = (int)uVar4;
    FUN_180001984(L"C:\\ProgramData\\Goodix\\goodix.dat",_Dst,(ulonglong)(uVar5 + 4),L"wb");
    free(_Dst);
    FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x3e,&DAT_18002fad8,
                  (char)(uVar5 + 4));
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"gf_savebaseTofile",0xa67,0,(undefined *)L"Exit size:%u(dec)");
  }
  return;
}



void DlCfg_FUN_180016cc0(undefined8 *param_1,undefined8 param_2,uint param_3)

{
  UsbSendDataToDevice_FUN_180012240
            (DAT_18004eb00,9,0,param_1,(uint)(ushort)param_2,'\x01',param_3 & 0xffff);
                    // WARNING: Could not recover jumptable at 0x000180016cfc. Too many branches
                    // WARNING: Treating indirect jump as call
  WaitForSingleObject(DAT_18004eb20,param_3 & 0xffff);
  return;
}



ulonglong gf_set_mode_FUN_180016d04(byte param_1,byte param_2,byte param_3)

{
  ulonglong uVar1;
  undefined7 in_register_00000009;
  undefined *puVar2;
  byte bVar3;
  wchar_t *pwVar4;
  undefined4 uVar5;
  wchar_t *pwVar6;
  
  bVar3 = 0;
  if (DAT_180059470 == (code *)0x0) {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0x27,&DAT_18002fad8);
    uVar1 = debug_print_FUN_180001ce4
                      ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"usbhal.c",
                       (undefined *)L"gf_set_mode",0x433,0,(undefined *)L"Set Mode Function NULL");
  }
  else {
    uVar1 = (*DAT_180059470)(CONCAT71(in_register_00000009,param_1));
    bVar3 = (byte)uVar1;
    if ((bVar3 & 3) == 3) {
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x24,&DAT_18002fad8);
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"gf_set_mode",
                 0x41f,0,(undefined *)L"####################################### Re-set config");
      DlCfg_FUN_180016cc0((undefined8 *)&DAT_18005936a,0x100,200);
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x25,&DAT_18002fad8);
      pwVar6 = L"####################################### Set mode again";
      uVar5 = 0x422;
    }
    else {
      if (((uVar1 & 1) != 0) || (bVar3 != 0)) goto LAB_180016ee6;
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x26,&DAT_18002fad8);
      pwVar6 = L"############################## Set mode Ack Timeout";
      uVar5 = 0x42c;
    }
    pwVar4 = L"usbhal.c";
    uVar1 = 0;
    puVar2 = PTR_DAT_180036ca8;
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",(undefined *)L"gf_set_mode",
               uVar5,0,(undefined *)pwVar6);
    uVar1 = (*DAT_180059470)((ulonglong)puVar2 & 0xffffffffffffff00 | (ulonglong)param_1,
                             uVar1 & 0xffffffffffffff00 | (ulonglong)param_2,
                             (ulonglong)pwVar4 & 0xffffffffffffff00 | (ulonglong)param_3);
    bVar3 = (byte)uVar1;
  }
LAB_180016ee6:
  return uVar1 & 0xffffffffffffff00 | (ulonglong)bVar3;
}



ulonglong FUN_180016f04(undefined8 param_1)

{
  uint uVar1;
  undefined4 local_68 [2];
  code *local_60;
  undefined4 local_58;
  undefined local_54;
  undefined4 local_50;
  undefined4 local_40 [6];
  undefined4 local_28;
  undefined4 local_24;
  undefined8 local_20;
  
  memset(local_68,0,0x28);
  local_58 = 0;
  local_50 = 0;
  local_68[0] = 0x28;
  local_60 = OnTimerTemperature_FUN_180011bd4;
  local_54 = 1;
  memset(local_40,0,0x38);
  local_40[0] = 0x38;
  local_24 = 1;
  local_28 = 2;
  local_20 = param_1;
  uVar1 = (**(code **)(DAT_18005ad20 + 0x630))(DAT_18005ad28,local_68,local_40,&DAT_180053c20);
  (**(code **)(DAT_18005ad20 + 0x638))(DAT_18005ad28,DAT_180053c20,0xfffffffffd050f80);
  return (ulonglong)uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_temperatureoccure_FUN_180016fc8(void)

{
  int iVar1;
  
  _DAT_180053bf0 = 0;
  FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x52,&DAT_18002fad8);
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
             (undefined *)L"gf_temperatureoccure",0xc60,0,(undefined *)L"Entry");
  iVar1 = gf_update_all_base_FUN_18001715c();
  if (iVar1 == 0) {
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x53,&DAT_18002fad8);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"gf_temperatureoccure",0xc65,0,(undefined *)L"restart timer 2 seconds")
    ;
    if (DAT_180053c20 != 0) {
                    // WARNING: Could not recover jumptable at 0x0001800170c2. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(DAT_18005ad20 + 0x638))(DAT_18005ad28,DAT_180053c20,0xfffffffffeced300);
      return;
    }
    FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),3,3,0x54,&DAT_18002fad8);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,5,(undefined *)L"usbhal.c",
               (undefined *)L"gf_temperatureoccure",0xc6d,0,
               (undefined *)L"Unexpected, temperaturetimer NULL ################");
  }
  else {
    (*_DAT_180059498)();
    gf_set_mode_FUN_180016d04(3,1,1);
    _DAT_180053c00 = 0;
    DAT_180053bf4 = 1;
  }
  return;
}



// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void gf_update_all_base_FUN_18001715c(void)

{
  ushort *puVar1;
  ushort *puVar2;
  ushort uVar3;
  ushort uVar4;
  bool bVar5;
  undefined8 *puVar6;
  uint uVar7;
  undefined8 *puVar8;
  undefined8 *_Memory;
  undefined8 uVar9;
  ulonglong uVar10;
  int iVar11;
  byte bVar12;
  int iVar13;
  longlong lVar14;
  longlong lVar15;
  undefined4 *puVar16;
  undefined4 uVar17;
  wchar_t *pwVar18;
  uint local_c8;
  uint local_c0;
  undefined2 local_b8;
  int local_b4;
  int local_b0;
  undefined8 *local_a8;
  undefined8 *local_a0;
  undefined4 local_98;
  undefined4 uStack148;
  undefined4 uStack144;
  undefined4 uStack140;
  undefined8 local_88;
  undefined4 local_78 [8];
  undefined4 local_58 [8];
  ulonglong local_38;
  
  local_38 = DAT_180037758 ^ (ulonglong)&stack0xfffffffffffffef8;
  local_b8 = 0;
  bVar5 = false;
  local_b4 = 0;
  puVar8 = (undefined8 *)
           malloc((ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
  local_a8 = puVar8;
  if (puVar8 == (undefined8 *)0x0) goto LAB_180017cb3;
  _Memory = (undefined8 *)
            malloc((ulonglong)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe))
  ;
  local_a0 = _Memory;
  if (_Memory != (undefined8 *)0x0) {
    FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x2d,&DAT_18002fad8,
                  (char)*(undefined2 *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe),
                  (char)*(undefined2 *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe));
    local_c8 = (uint)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
               (undefined *)L"gf_update_all_base",0x95c,0,
               (undefined *)L"BUFF_SIZE:%u NAV_BUFF_SIZE:%u");
    FUN_180013350();
LAB_18001729e:
    bVar12 = 0;
    uVar9 = gf_get_fdtbase_FUN_1800165a4(local_58,200);
    if ((int)uVar9 == 0) {
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x2e,&DAT_18002fad8);
      pwVar18 = L"gf_get_fdtbase timeout";
      uVar17 = 0x963;
    }
    else {
      uVar9 = gf_get_navbase_FUN_180016608(_Memory,500);
      if ((int)uVar9 == 0) {
        FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x2f,&DAT_18002fad8);
        pwVar18 = L"gf_get_navbase timeout";
        uVar17 = 0x96c;
        goto LAB_180017c84;
      }
      uVar9 = gf_get_fdtbase_FUN_1800165a4(local_78,200);
      if ((int)uVar9 == 0) {
        FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x30,&DAT_18002fad8);
        pwVar18 = L"gf_get_fdtbase timeout";
        uVar17 = 0x975;
        goto LAB_180017c84;
      }
      puVar16 = local_78;
      do {
        uVar3 = *(ushort *)puVar16;
        FUN_18000756c(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x31,&DAT_18002fad8,bVar12,
                      (char)uVar3);
        local_c8 = (uint)uVar3;
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_update_all_base",0x97c,0,(undefined *)L"fdt base1[%d]:0x%x");
        _Memory = local_a0;
        puVar8 = local_a8;
        bVar12 = bVar12 + 1;
        puVar16 = (undefined4 *)((longlong)puVar16 + 2);
      } while (bVar12 < 0xc);
      local_b0 = ChipRegRead_FUN_1800116dc(0x82,(undefined8 *)&local_b8,2,100);
      if (local_b0 != 1) {
        FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x32,&DAT_18002fad8);
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_update_all_base",0x986,0,(undefined *)L"Get FDT Delta timeout")
        ;
        goto LAB_180017c9e;
      }
      DAT_180053c2a = (ushort)local_b8._1_1_;
      FUN_180012528(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x33,&DAT_18002fad8,
                    local_b8._1_1_,(byte)local_b8,local_b8._1_1_);
      local_c8 = (uint)(byte)local_b8;
      local_c0 = (uint)local_b8._1_1_;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_update_all_base",0x98b,0,
                 (undefined *)L"fdt_delta: 0x%x buf[0]:0x%x buf[1]:0x%x");
      lVar14 = 0;
      lVar15 = 0xc;
      do {
        uVar3 = *(ushort *)((longlong)local_78 + lVar14);
        uVar4 = *(ushort *)((longlong)local_58 + lVar14);
        iVar13 = (uint)uVar4 - (uint)uVar3;
        iVar11 = iVar13;
        if (iVar13 < 1) {
          iVar11 = (uint)uVar3 - (uint)uVar4;
        }
        FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x34,&DAT_18002fad8,
                      (char)iVar11);
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_update_all_base",0x992,0,(undefined *)L"fdt diff:0x%x");
        _Memory = local_a0;
        puVar6 = local_a8;
        lVar14 = lVar14 + 2;
        if (iVar13 < 1) {
          iVar13 = (uint)uVar3 - (uint)uVar4;
        }
        if ((int)(uint)DAT_180053c2a < iVar13) {
          bVar5 = true;
        }
        lVar15 = lVar15 + -1;
      } while (lVar15 != 0);
      puVar8 = puVar6;
      if (bVar5) {
        if (DAT_180053bec == 1) {
          FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0x35,&DAT_18002fad8);
          debug_print_FUN_180001ce4
                    ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"usbhal.c",
                     (undefined *)L"gf_update_all_base",0x99c,0,
                     (undefined *)L"First detect fdt wrong");
          goto LAB_180017c9e;
        }
        FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x36,&DAT_18002fad8);
        pwVar18 = L"first detect fdt failed";
        uVar17 = 0x9a2;
LAB_180017566:
        bVar5 = false;
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_update_all_base",uVar17,0,(undefined *)pwVar18);
LAB_180017739:
        if (local_b4 == 1) goto code_r0x000180017741;
        goto LAB_18001729e;
      }
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x37,&DAT_18002fad8);
      lVar14 = 0;
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_update_all_base",0x9ad,0,(undefined *)L"first detect fdt OK");
      uVar10 = gf_get_oneframe_FUN_1800166c4(puVar6,500);
      if ((int)uVar10 != 0) {
        uVar9 = gf_get_fdtbase_FUN_1800165a4(&local_98,200);
        puVar8 = local_a8;
        if ((int)uVar9 == 0) {
          FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x39,&DAT_18002fad8);
          pwVar18 = L"gf_get_fdtbase timeout";
          uVar17 = 0x9bd;
          puVar8 = puVar6;
          goto LAB_180017c84;
        }
        lVar15 = 0xc;
        do {
          puVar1 = (ushort *)((longlong)local_78 + lVar14);
          puVar2 = (ushort *)((longlong)&local_98 + lVar14);
          lVar14 = lVar14 + 2;
          iVar11 = (uint)*puVar1 - (uint)*puVar2;
          if (iVar11 < 1) {
            iVar11 = (uint)*puVar2 - (uint)*puVar1;
          }
          if ((int)(uint)DAT_180053c2a < iVar11) {
            bVar5 = true;
          }
          lVar15 = lVar15 + -1;
        } while (lVar15 != 0);
        if (!bVar5) {
          FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),5,3,0x3c,&DAT_18002fad8);
          debug_print_FUN_180001ce4
                    ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                     (undefined *)L"gf_update_all_base",0x9e1,0,(undefined *)L"second detect fdt OK"
                    );
          (*_DAT_1800594a8)(&local_98);
          DAT_180059328 = local_98;
          DAT_18005932c = uStack148;
          DAT_180059330 = uStack144;
          DAT_180059334 = uStack140;
          local_b4 = 1;
          DAT_180059338 = local_88;
          goto LAB_180017739;
        }
        if (DAT_180053bec != 1) {
          FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x3b,&DAT_18002fad8);
          pwVar18 = L"second detect fdt failed";
          uVar17 = 0x9d7;
          goto LAB_180017566;
        }
        FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),2,3,0x3a,&DAT_18002fad8);
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_update_all_base",0x9d1,0,
                   (undefined *)L"second detect fdt wrong");
        goto LAB_180017c9e;
      }
      FUN_1800074b8(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x38,&DAT_18002fad8);
      pwVar18 = L"gf_get_oneframe timeout";
      uVar17 = 0x9b4;
    }
LAB_180017c84:
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"gf_update_all_base",uVar17,0,(undefined *)pwVar18);
    goto LAB_180017c9e;
  }
  free(puVar8);
  goto LAB_180017c9e;
code_r0x000180017741:
  if (DAT_180053bec == 1) {
    uVar10 = FUN_18000b15c((longlong)DAT_180059320,(longlong)_Memory);
    uVar7 = (uint)uVar10;
    if (uVar7 == 0) {
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_update_all_base",0x9ee,0,(undefined *)L"navret: temp");
LAB_180017916:
      if (uVar7 != 1) {
LAB_18001791b:
        memcpy_FUN_180019c80
                  (DAT_180059320,_Memory,
                   (ulonglong)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe))
        ;
      }
    }
    else {
      if (uVar7 != 1) {
        if (uVar7 == 2) {
          pwVar18 = L"navret: void";
          uVar17 = 0x9f4;
        }
        else {
          if (uVar7 != 3) goto LAB_180017916;
          pwVar18 = L"navret: bad";
          uVar17 = 0x9f1;
        }
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_update_all_base",uVar17,0,(undefined *)pwVar18);
        goto LAB_18001791b;
      }
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_update_all_base",0x9f7,0,(undefined *)L"navret: finger");
    }
    uVar10 = FUN_18000b140((longlong)DAT_180059310,(longlong)puVar8);
    iVar11 = (int)uVar10;
    if (iVar11 == 0) {
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_update_all_base",0xa09,0,(undefined *)L"imageret: tempe");
LAB_180017a3b:
      if (iVar11 != 1) {
LAB_180017a40:
        memcpy_FUN_180019c80
                  (DAT_180059310,puVar8,
                   (ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe))
        ;
      }
    }
    else {
      if (iVar11 != 1) {
        if (iVar11 == 2) {
          pwVar18 = L"imageret: void";
          uVar17 = 0xa0f;
        }
        else {
          if (iVar11 != 3) goto LAB_180017a3b;
          pwVar18 = L"imageret: bad";
          uVar17 = 0xa0c;
        }
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                   (undefined *)L"gf_update_all_base",uVar17,0,(undefined *)pwVar18);
        goto LAB_180017a40;
      }
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                 (undefined *)L"gf_update_all_base",0xa12,0,(undefined *)L"imageret: finger");
    }
    FUN_18000a7cc((undefined4 *)&DAT_180053bf0,iVar11,uVar7);
  }
  else {
    memcpy_FUN_180019c80
              (DAT_180059310,puVar8,
               (ulonglong)*(ushort *)((longlong)&DAT_1800376a8 + (longlong)DAT_18005b4a0 * 0xe));
    memcpy_FUN_180019c80
              (DAT_180059320,_Memory,
               (ulonglong)*(ushort *)((longlong)&DAT_1800376aa + (longlong)DAT_18005b4a0 * 0xe));
  }
LAB_180017c9e:
  free(puVar8);
  if (_Memory != (undefined8 *)0x0) {
    free(_Memory);
  }
LAB_180017cb3:
  FUN_180018b70(local_38 ^ (ulonglong)&stack0xfffffffffffffef8);
  return;
}



ulonglong gfresetMCUAndfingerprint_FUN_180017ce4
                    (char param_1,char param_2,ushort param_3,int *param_4)

{
  byte bVar1;
  DWORD DVar2;
  void *pvVar3;
  ulonglong uVar4;
  int iVar5;
  byte bVar6;
  byte bVar7;
  byte local_res8;
  undefined local_res9;
  
  bVar6 = 0;
  bVar1 = -(param_1 != '\0') & 2;
  pvVar3 = (void *)0x0;
  bVar7 = bVar1 + 5;
  if (param_2 == '\0') {
    bVar7 = bVar1;
  }
  if (bVar7 != 0) {
    local_res9 = 0x14;
    if ((bVar7 == 2) || (bVar7 == 7)) {
      local_res9 = 0x32;
    }
    local_res8 = bVar7;
    FUN_1800014f4((longlong)"%s %d reset device: %d","gfresetMCUAndfingerprint",0x6e4,
                  (ulonglong)bVar7);
    FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x29,&DAT_18002fad8,bVar7);
    debug_print_FUN_180001ce4
              ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
               (undefined *)L"gfresetMCUAndfingerprint",0x6e6,0,(undefined *)L"reset device: %d");
    pvVar3 = (void *)UsbSendDataToDevice_FUN_180012240
                               (DAT_18004eb00,10,1,(undefined8 *)&local_res8,2,'\x01',200);
    bVar6 = (byte)pvVar3;
    if (param_2 == '\x01') {
      DVar2 = WaitForSingleObject(DAT_18004eb38,(uint)param_3);
      if (DVar2 == 0x102) {
        FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x2a,&DAT_18002fad8,bVar6);
        uVar4 = debug_print_FUN_180001ce4
                          ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                           (undefined *)L"gfresetMCUAndfingerprint",0x6f6,0,
                           (undefined *)L"timeout ren:%d");
        return uVar4 & 0xffffffffffffff00;
      }
      if (param_4 != (int *)0x0) {
        iVar5 = (uint)DAT_18004eb54 * 0x100 + (uint)DAT_18004eb55 * 0x10000 + (uint)DAT_18004eb53;
        *param_4 = iVar5;
        FUN_180007680(*(undefined8 *)(PTR_LOOP_180037650 + 0x28),4,3,0x2b,&DAT_18002fad8,(char)iVar5
                     );
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,7,(undefined *)L"usbhal.c",
                   (undefined *)L"gfresetMCUAndfingerprint",0x700,0,(undefined *)L"irqstatus:0x%x");
      }
      pvVar3 = memset(&DAT_18004eb53,0,0x40);
    }
  }
  return (ulonglong)pvVar3 & 0xffffffffffffff00 | (ulonglong)bVar6;
}



void SetSPIClk_FUN_180017f48(ushort *param_1,char param_2,undefined8 param_3)

{
  DWORD DVar1;
  undefined local_res10;
  char local_res11;
  
  local_res10 = *(undefined *)param_1;
  local_res11 = param_2;
  UsbSendDataToDevice_FUN_180012240(DAT_18004eb00,10,0,(undefined8 *)&local_res10,2,'\x01',100);
  DVar1 = WaitForSingleObject(DAT_18004eb38,(uint)(byte)param_3);
  if (DVar1 != 0x102) {
    if (param_2 == '\x01') {
      *param_1 = (ushort)DAT_18004eb54;
    }
    memset(&DAT_18004eb53,0,0x40);
  }
  return;
}



ulonglong UpdateFirmware_FUN_180017fe0(byte *param_1,uint param_2)

{
  undefined uVar1;
  byte bVar2;
  DWORD DVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulonglong extraout_RAX;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  undefined4 uVar8;
  wchar_t *pwVar9;
  
  uVar6 = 0;
  uVar4 = 0x400;
  if ((param_1 == (byte *)0x0) ||
     (in_RAX = (undefined8 *)malloc((ulonglong)(param_2 + 4)), in_RAX == (undefined8 *)0x0)) {
    return (ulonglong)in_RAX & 0xffffffffffffff00;
  }
  uVar7 = (uint)((param_2 & 0x3ff) != 0) + (param_2 >> 10);
  if (uVar7 != 0) {
    do {
      if (uVar6 == uVar7 - 1) {
        if ((int)((ulonglong)param_2 % uVar4) == 0) {
          uVar4 = 0x400;
        }
        else {
          uVar4 = (ulonglong)((ushort)param_2 & 0x3ff);
        }
      }
      else {
        uVar4 = 0x400;
      }
      *(char *)((longlong)in_RAX + 2) = (char)uVar4;
      uVar5 = uVar6 << 10;
      bVar2 = (byte)(uVar4 >> 8);
      *(byte *)((longlong)in_RAX + 3) = bVar2;
      if (uVar5 < 0x10000) {
        *(undefined *)in_RAX = 0;
        uVar1 = (undefined)(uVar5 >> 8);
      }
      else {
        *(char *)in_RAX = (char)(uVar6 & 0x3fffff);
        uVar1 = (undefined)((uVar6 & 0x3fffff) >> 8);
        *(byte *)((longlong)in_RAX + 3) = bVar2 | 0x80;
      }
      *(undefined *)((longlong)in_RAX + 1) = uVar1;
      memcpy_FUN_180019c80
                ((undefined8 *)((longlong)in_RAX + 4),(undefined8 *)(param_1 + uVar5),uVar4);
      bVar2 = UsbSendDataToDevice_FUN_180012240
                        (DAT_18004eb00,0xf,0,in_RAX,(int)uVar4 + 4,'\x01',20000);
      if (bVar2 == 0) {
        pwVar9 = L"F0 no response";
        uVar8 = 0x7c8;
        goto LAB_1800181cd;
      }
      DVar3 = WaitForSingleObject(DAT_18004eb30,3000);
      if (DVar3 == 0x102) {
        pwVar9 = L"Write firmware 1K failed";
        uVar8 = 0x7ce;
        goto LAB_1800181cd;
      }
      uVar6 = uVar6 + 1;
    } while (uVar6 < uVar7);
  }
  FUN_180002770();
  DAT_180037440 = 0xffffffff;
  uVar4 = FUN_1800027b4(param_1,param_2);
  *(undefined2 *)in_RAX = 0;
  *(char *)((longlong)in_RAX + 3) = (char)(param_2 >> 8);
  *(char *)((longlong)in_RAX + 2) = (char)param_2;
  *(char *)((longlong)in_RAX + 9) = (char)(param_2 >> 0x10);
  *(int *)((longlong)in_RAX + 4) = (int)uVar4;
  *(undefined *)(in_RAX + 1) = 1;
  *(char *)((longlong)in_RAX + 10) = (char)(param_2 >> 0x18);
  bVar2 = UsbSendDataToDevice_FUN_180012240(DAT_18004eb00,0xf,2,in_RAX,0xb,'\x01',200);
  if (bVar2 == 0) {
    pwVar9 = L"F2 no response";
    uVar8 = 0x7ed;
LAB_1800181cd:
    uVar6 = 9;
  }
  else {
    DVar3 = WaitForSingleObject(DAT_18004eb30,2000);
    if (DVar3 == 0x102) {
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"usbhal.c",
                 (undefined *)L"updatefirmware",0x7f3,0,
                 (undefined *)L"Check firmware crc failed,Do not update firmware!!!!");
      uVar8 = 0x7f4;
    }
    else {
      if (DAT_18004eb53 != '\0') {
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                   (undefined *)L"updatefirmware",0x7fa,0,
                   (undefined *)L"Check firmware crc success,update firmware!!!");
        debug_print_FUN_180001ce4
                  ((longlong)PTR_DAT_180036ca8,9,(undefined *)L"usbhal.c",
                   (undefined *)L"updatefirmware",0x7fb,0,(undefined *)L"Update firmware  success");
        gfresetMCUAndfingerprint_FUN_180017ce4('\x01','\0',0,(int *)0x0);
        goto LAB_180018333;
      }
      debug_print_FUN_180001ce4
                ((longlong)PTR_DAT_180036ca8,4,(undefined *)L"usbhal.c",
                 (undefined *)L"updatefirmware",0x7ff,0,
                 (undefined *)L"Check firmware crc failed,Do not update firmware!!!!");
      uVar8 = 0x800;
    }
    pwVar9 = L"Update firmware  failed";
    uVar6 = 4;
  }
  debug_print_FUN_180001ce4
            ((longlong)PTR_DAT_180036ca8,uVar6,(undefined *)L"usbhal.c",
             (undefined *)L"updatefirmware",uVar8,0,(undefined *)pwVar9);
LAB_180018333:
  free(in_RAX);
  return extraout_RAX & 0xffffffffffffff00 | (ulonglong)bVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulonglong FxDriverEntryUm(uint *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  code *pcVar1;
  uint uVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  char *pcVar5;
  
                    // 0x1835c  1  FxDriverEntryUm
  if ((param_1 == (uint *)0x0) || (*param_1 < 0x38)) {
    return 0xc000000d;
  }
  _DAT_18005ad30 = param_1[0xc] & 1;
  if (_DAT_18005ad30 != 0) {
    DbgPrintEx(0x65,3,"Wudfx2000: ");
    DbgPrintEx(0x65,3,"FxDriverEntrydUm Enter PDRIVER_OBJECT_UM 0x%p\n",param_3);
  }
  _DAT_18005ad18 = *(undefined8 *)(param_1 + 10);
  pcVar1 = *(code **)(param_1 + 2);
  _guard_check_icall();
  uVar2 = (*pcVar1)(param_2,&DAT_180037708,&DAT_18005ad28);
  uVar3 = (ulonglong)uVar2;
  if ((int)uVar2 < 0) {
    if (_DAT_18005ad30 == 0) {
      return uVar3;
    }
    DbgPrintEx(0x65,3,"Wudfx2000: ");
    pcVar5 = "FxDriverEntryUm: VersionBind status %08X\n";
  }
  else {
    if (_DAT_18005ad30 != 0) {
      DbgPrintEx(0x65,3,"Wudfx2000: ");
      DbgPrintEx(0x65,3,
                 "FxDriverEntryUm: PDRIVER_OBJECT_UM 0x%p Successfully bound to version library\n",
                 param_3);
    }
    uVar3 = FUN_180018564((longlong)param_1,param_2,&DAT_180037708);
    if ((int)uVar3 < 0) {
      return uVar3 & 0xffffffff;
    }
    if (_DAT_18005ad30 != 0) {
      DbgPrintEx(0x65,3,"Wudfx2000: ");
      DbgPrintEx(0x65,3,
                 "FxDriverEntryUm: PDRIVER_OBJECT_UM 0x%p Successfully bound to class library if present\n"
                 ,param_3);
    }
    uVar4 = DriverEntry_FUN_180009e8c(param_3,param_4);
    uVar3 = uVar4 & 0xffffffff;
    if (-1 < (int)uVar4) {
      if (_DAT_18005ad30 == 0) {
        return uVar3;
      }
      DbgPrintEx(0x65,3,"Wudfx2000: ");
      DbgPrintEx(0x65,3,
                 "FxDriverEntryUm: PDRIVER_OBJECT_UM 0x%p Successfully returned from driver\'s DriverEntry\n"
                 ,param_3);
      return uVar3;
    }
    if (_DAT_18005ad30 == 0) {
      return uVar3;
    }
    DbgPrintEx(0x65,3,"Wudfx2000: ");
    pcVar5 = "FxDriverEntryUm: DriverEntry status %08X\n";
  }
  DbgPrintEx(0x65,3,pcVar5,uVar3);
  return uVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulonglong FUN_180018364(uint *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  code *pcVar1;
  uint uVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  char *pcVar5;
  
  if ((param_1 == (uint *)0x0) || (*param_1 < 0x38)) {
    return 0xc000000d;
  }
  _DAT_18005ad30 = param_1[0xc] & 1;
  if (_DAT_18005ad30 != 0) {
    DbgPrintEx(0x65,3,"Wudfx2000: ");
    DbgPrintEx(0x65,3,"FxDriverEntrydUm Enter PDRIVER_OBJECT_UM 0x%p\n",param_3);
  }
  _DAT_18005ad18 = *(undefined8 *)(param_1 + 10);
  pcVar1 = *(code **)(param_1 + 2);
  _guard_check_icall();
  uVar2 = (*pcVar1)(param_2,&DAT_180037708,&DAT_18005ad28);
  uVar3 = (ulonglong)uVar2;
  if ((int)uVar2 < 0) {
    if (_DAT_18005ad30 == 0) {
      return uVar3;
    }
    DbgPrintEx(0x65,3,"Wudfx2000: ");
    pcVar5 = "FxDriverEntryUm: VersionBind status %08X\n";
  }
  else {
    if (_DAT_18005ad30 != 0) {
      DbgPrintEx(0x65,3,"Wudfx2000: ");
      DbgPrintEx(0x65,3,
                 "FxDriverEntryUm: PDRIVER_OBJECT_UM 0x%p Successfully bound to version library\n",
                 param_3);
    }
    uVar3 = FUN_180018564((longlong)param_1,param_2,&DAT_180037708);
    if ((int)uVar3 < 0) {
      return uVar3 & 0xffffffff;
    }
    if (_DAT_18005ad30 != 0) {
      DbgPrintEx(0x65,3,"Wudfx2000: ");
      DbgPrintEx(0x65,3,
                 "FxDriverEntryUm: PDRIVER_OBJECT_UM 0x%p Successfully bound to class library if present\n"
                 ,param_3);
    }
    uVar4 = DriverEntry_FUN_180009e8c(param_3,param_4);
    uVar3 = uVar4 & 0xffffffff;
    if (-1 < (int)uVar4) {
      if (_DAT_18005ad30 == 0) {
        return uVar3;
      }
      DbgPrintEx(0x65,3,"Wudfx2000: ");
      DbgPrintEx(0x65,3,
                 "FxDriverEntryUm: PDRIVER_OBJECT_UM 0x%p Successfully returned from driver\'s DriverEntry\n"
                 ,param_3);
      return uVar3;
    }
    if (_DAT_18005ad30 == 0) {
      return uVar3;
    }
    DbgPrintEx(0x65,3,"Wudfx2000: ");
    pcVar5 = "FxDriverEntryUm: DriverEntry status %08X\n";
  }
  DbgPrintEx(0x65,3,pcVar5,uVar3);
  return uVar3;
}



// WARNING: Removing unreachable block (ram,0x00018001859a)

undefined8 FUN_180018564(longlong param_1,undefined8 param_2,undefined8 param_3)

{
  code *pcVar1;
  undefined8 uVar2;
  int *piVar3;
  
  uVar2 = 0;
  piVar3 = &DAT_1800378a0;
  while( true ) {
    if ((int *)0x18003789f < piVar3) {
      return uVar2;
    }
    if (*piVar3 != 0x50) break;
    pcVar1 = *(code **)(piVar3 + 0xe);
    PTR_DAT_1800378a8 = (undefined *)piVar3;
    if (pcVar1 == (code *)0x0) {
      pcVar1 = *(code **)(param_1 + 0x18);
      _guard_check_icall();
      uVar2 = (*pcVar1)(param_2,param_3,DAT_18005ad28,piVar3);
    }
    else {
      _guard_check_icall();
      uVar2 = (*pcVar1)(*(undefined8 *)(param_1 + 0x18),param_2,param_3,DAT_18005ad28,piVar3);
    }
    if ((int)uVar2 < 0) {
      return uVar2;
    }
    piVar3 = piVar3 + 0x14;
  }
  return 0xc0000004;
}



void _guard_check_icall(void)

{
  return;
}



void TraceMessage(void)

{
                    // WARNING: Could not recover jumptable at 0x000180018630. Too many branches
                    // WARNING: Treating indirect jump as call
  TraceMessage();
  return;
}



void WppAutoLogTrace(void)

{
                    // WARNING: Could not recover jumptable at 0x000180018636. Too many branches
                    // WARNING: Treating indirect jump as call
  WppAutoLogTrace();
  return;
}



void WppAutoLogStop(void)

{
                    // WARNING: Could not recover jumptable at 0x000180018642. Too many branches
                    // WARNING: Treating indirect jump as call
  WppAutoLogStop();
  return;
}



void CallNtPowerInformation(void)

{
                    // WARNING: Could not recover jumptable at 0x000180018648. Too many branches
                    // WARNING: Treating indirect jump as call
  CallNtPowerInformation();
  return;
}



void PowerSettingRegisterNotification(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001864e. Too many branches
                    // WARNING: Treating indirect jump as call
  PowerSettingRegisterNotification();
  return;
}



errno_t wcscpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  errno_t eVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001865a. Too many branches
                    // WARNING: Treating indirect jump as call
  eVar1 = wcscpy_s(_Dst,_SizeInWords,_Src);
  return eVar1;
}



errno_t _wfopen_s(FILE **_File,wchar_t *_Filename,wchar_t *_Mode)

{
  errno_t eVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180018660. Too many branches
                    // WARNING: Treating indirect jump as call
  eVar1 = _wfopen_s(_File,_Filename,_Mode);
  return eVar1;
}



void __stdio_common_vswprintf_s(void)

{
                    // WARNING: Could not recover jumptable at 0x000180018666. Too many branches
                    // WARNING: Treating indirect jump as call
  __stdio_common_vswprintf_s();
  return;
}



size_t fread_s(void *_DstBuf,size_t _DstSize,size_t _ElementSize,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001866c. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = fread_s(_DstBuf,_DstSize,_ElementSize,_Count,_File);
  return sVar1;
}



int fclose(FILE *_File)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180018672. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = fclose(_File);
  return iVar1;
}



size_t fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180018678. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = fwrite(_Str,_Size,_Count,_File);
  return sVar1;
}



void __stdio_common_vsprintf_s(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001867e. Too many branches
                    // WARNING: Treating indirect jump as call
  __stdio_common_vsprintf_s();
  return;
}



void __stdio_common_vsnprintf_s(void)

{
                    // WARNING: Could not recover jumptable at 0x000180018684. Too many branches
                    // WARNING: Treating indirect jump as call
  __stdio_common_vsnprintf_s();
  return;
}



void * calloc(size_t _Count,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001868a. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = calloc(_Count,_Size);
  return pvVar1;
}



void free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180018690. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



errno_t _localtime64_s(tm *_Tm,__time64_t *_Time)

{
  errno_t eVar1;
  
                    // WARNING: Could not recover jumptable at 0x000180018696. Too many branches
                    // WARNING: Treating indirect jump as call
  eVar1 = _localtime64_s(_Tm,_Time);
  return eVar1;
}



size_t strftime(char *_Buf,size_t _SizeInBytes,char *_Format,tm *_Tm)

{
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001869c. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = strftime(_Buf,_SizeInBytes,_Format,_Tm);
  return sVar1;
}



__time64_t _time64(__time64_t *_Time)

{
  __time64_t _Var1;
  
                    // WARNING: Could not recover jumptable at 0x0001800186a2. Too many branches
                    // WARNING: Treating indirect jump as call
  _Var1 = _time64(_Time);
  return _Var1;
}



void * memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001800186a8. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



int _wmkdir(wchar_t *_Path)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001800186ae. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _wmkdir(_Path);
  return iVar1;
}



void __stdio_common_vswprintf(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800186b4. Too many branches
                    // WARNING: Treating indirect jump as call
  __stdio_common_vswprintf();
  return;
}



void __acrt_iob_func(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800186ba. Too many branches
                    // WARNING: Treating indirect jump as call
  __acrt_iob_func();
  return;
}



void __stdio_common_vfwprintf(void)

{
                    // WARNING: Could not recover jumptable at 0x0001800186c0. Too many branches
                    // WARNING: Treating indirect jump as call
  __stdio_common_vfwprintf();
  return;
}



void * malloc(size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001800186c6. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = malloc(_Size);
  return pvVar1;
}



uintptr_t _beginthreadex(void *_Security,uint _StackSize,_StartAddress *_StartAddress,void *_ArgList
                        ,uint _InitFlag,uint *_ThrdAddr)

{
  uintptr_t uVar1;
  
                    // WARNING: Could not recover jumptable at 0x0001800186cc. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = _beginthreadex(_Security,_StackSize,_StartAddress,_ArgList,_InitFlag,_ThrdAddr);
  return uVar1;
}



void FUN_1800186e0(void **param_1)

{
  char cVar1;
  longlong *plVar2;
  longlong *_Memory;
  
  cVar1 = *(char *)((longlong)*(longlong **)((longlong)*param_1 + 8) + 0x19);
  _Memory = *(longlong **)((longlong)*param_1 + 8);
  while (cVar1 == '\0') {
    FUN_180018770(param_1,(longlong *)_Memory[2]);
    plVar2 = (longlong *)*_Memory;
    free(_Memory);
    cVar1 = *(char *)((longlong)plVar2 + 0x19);
    _Memory = plVar2;
  }
  *(void **)((longlong)*param_1 + 8) = *param_1;
  *(void **)*param_1 = *param_1;
  *(void **)((longlong)*param_1 + 0x10) = *param_1;
  param_1[1] = (void *)0x0;
  free(*param_1);
  return;
}



void FUN_180018770(undefined8 param_1,longlong *param_2)

{
  char cVar1;
  longlong *plVar2;
  
  cVar1 = *(char *)((longlong)param_2 + 0x19);
  while (cVar1 == '\0') {
    FUN_180018770(param_1,(longlong *)param_2[2]);
    plVar2 = (longlong *)*param_2;
    free(param_2);
    cVar1 = *(char *)((longlong)plVar2 + 0x19);
    param_2 = plVar2;
  }
  return;
}



void FUN_1800187c0(void)

{
  undefined8 *_Memory;
  void **_Memory_00;
  
  if ((DAT_18005ad40 != 0) &&
     (_Memory = *(undefined8 **)(DAT_18005ad40 + 0x10), _Memory != (undefined8 *)0x0)) {
    FUN_1800189b0(_Memory);
    free(_Memory);
    *(undefined8 *)(DAT_18005ad40 + 0x10) = 0;
  }
  _Memory_00 = DAT_18005ad38;
  if (DAT_18005ad38 != (void **)0x0) {
    FUN_1800186e0(DAT_18005ad38);
    free(_Memory_00);
    DAT_18005ad38 = (void **)0x0;
  }
  return;
}



undefined8 FUN_180018840(void)

{
  if ((DAT_18005ad40 != 0) && (*(longlong *)(DAT_18005ad40 + 0x10) != 0)) {
    return 1;
  }
  return 0;
}



void FUN_180018860(undefined8 param_1,undefined8 param_2,int *param_3,undefined8 param_4,
                  undefined8 param_5,undefined8 param_6)

{
  FUN_180018a20(DAT_18005ad40,param_1,param_2,param_3,param_4,param_5,param_6);
  return;
}



undefined8 FUN_1800188a0(undefined8 *param_1,undefined8 param_2,int param_3)

{
  longlong lVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  int *piVar4;
  int local_res20 [2];
  
  puVar3 = (undefined8 *)0x0;
  local_res20[0] = 0;
  lVar1 = FUN_1800189f0(param_3,local_res20);
  if (local_res20[0] != 0) {
    return 0;
  }
  puVar2 = (undefined8 *)FUN_18001921c(0x60);
  if (puVar2 != (undefined8 *)0x0) {
    puVar3 = FUN_180018960(puVar2);
  }
  puVar2 = puVar3 + 4;
  *(int *)(puVar3 + 1) = param_3;
  puVar3[3] = param_2;
  if (puVar2 != (undefined8 *)0x0) {
    if (param_1 != (undefined8 *)0x0) {
      *puVar2 = *param_1;
      goto LAB_180018935;
    }
    *puVar2 = 0;
    puVar3[5] = 0;
    puVar3[6] = 0;
    puVar3[7] = 0;
  }
  piVar4 = _errno();
  *piVar4 = 0x16;
  _invalid_parameter_noinfo();
LAB_180018935:
  *(undefined8 **)(lVar1 + 0x10) = puVar3;
  return 1;
}



undefined8 * FUN_180018960(undefined8 *param_1)

{
  *param_1 = ChainBase::vftable;
  param_1[2] = 0;
  param_1[3] = 0;
  *(undefined2 *)(param_1 + 4) = 0;
  *(undefined8 *)((longlong)param_1 + 0x22) = 0;
  *(undefined8 *)((longlong)param_1 + 0x2a) = 0;
  *(undefined8 *)((longlong)param_1 + 0x32) = 0;
  *(undefined8 *)((longlong)param_1 + 0x3a) = 0;
  *(undefined8 *)((longlong)param_1 + 0x42) = 0;
  *(undefined8 *)((longlong)param_1 + 0x4a) = 0;
  *(undefined8 *)((longlong)param_1 + 0x52) = 0;
  *(undefined4 *)((longlong)param_1 + 0x5a) = 0;
  *(undefined2 *)((longlong)param_1 + 0x5e) = 0;
  *(undefined4 *)(param_1 + 1) = 0xffffffff;
  return param_1;
}



void FUN_1800189b0(undefined8 *param_1)

{
  undefined8 *_Memory;
  
  _Memory = (undefined8 *)param_1[2];
  *param_1 = ChainBase::vftable;
  if (_Memory != (undefined8 *)0x0) {
    FUN_1800189b0(_Memory);
    free(_Memory);
    return;
  }
  return;
}



void FUN_1800189f0(int param_1,undefined4 *param_2)

{
  longlong lVar1;
  
  lVar1 = DAT_18005ad40;
  *param_2 = 0;
  do {
    if (param_1 == *(int *)(lVar1 + 8)) {
      *param_2 = 1;
    }
    lVar1 = *(longlong *)(lVar1 + 0x10);
  } while (lVar1 != 0);
  return;
}



ulonglong FUN_180018a20(undefined **param_1,undefined8 param_2,undefined8 param_3,int *param_4,
                       undefined8 param_5,undefined8 param_6,undefined8 param_7)

{
  int iVar1;
  ulonglong uVar2;
  uint local_res8 [2];
  
  iVar1 = *(int *)(param_1 + 1);
  while (*param_4 != iVar1) {
    param_1 = (undefined **)((code **)param_1)[2];
    if ((code **)param_1 == (code **)0x0) {
      return 0;
    }
    iVar1 = *(int *)((code **)param_1 + 1);
  }
  if (((code **)param_1)[3] != (code *)0x0) {
    local_res8[0] = 1;
    (*((code **)param_1)[3])(param_2,param_3,param_4,param_5,param_6,local_res8,param_7);
    return (ulonglong)local_res8[0];
  }
  uVar2 = (**(code **)*param_1)();
  return uVar2;
}



undefined8 FUN_180018ae0(void)

{
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180018b70(longlong param_1)

{
  code *pcVar1;
  BOOL BVar2;
  undefined *puVar3;
  undefined auStack56 [8];
  undefined auStack48 [48];
  
  if ((param_1 == DAT_180037758) && ((short)((ulonglong)param_1 >> 0x30) == 0)) {
    return;
  }
  puVar3 = auStack56;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(2);
    puVar3 = auStack48;
  }
  *(undefined8 *)(puVar3 + -8) = 0x180018c62;
  capture_previous_context((PCONTEXT)&DAT_18005adf0,puVar3[-8]);
  _DAT_18005ad60 = *(undefined8 *)(puVar3 + 0x38);
  _DAT_18005ae88 = puVar3 + 0x40;
  _DAT_18005ae70 = *(undefined8 *)(puVar3 + 0x40);
  _DAT_18005ad50 = 0xc0000409;
  _DAT_18005ad54 = 1;
  _DAT_18005ad68 = 1;
  DAT_18005ad70 = 2;
  *(longlong *)(puVar3 + 0x20) = DAT_180037758;
  *(undefined8 *)(puVar3 + 0x28) = DAT_180037750;
  *(undefined8 *)(puVar3 + -8) = 0x180018d04;
  DAT_18005aee8 = _DAT_18005ad60;
  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_180032058,puVar3[-8]);
  return;
}



// Library Function - Single Match
// Name: _alloca_probe
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

void _alloca_probe(void)

{
  undefined *in_RAX;
  undefined *puVar1;
  undefined *puVar2;
  longlong in_GS_OFFSET;
  undefined local_res8 [32];
  
  puVar1 = local_res8 + -(longlong)in_RAX;
  if (local_res8 < in_RAX) {
    puVar1 = (undefined *)0x0;
  }
  puVar2 = *(undefined **)(in_GS_OFFSET + 0x10);
  if (puVar1 < puVar2) {
    do {
      puVar2 = puVar2 + -0x1000;
      *puVar2 = 0;
    } while ((undefined *)((ulonglong)puVar1 & 0xfffffffffffff000) != puVar2);
  }
  return;
}



// Library Function - Single Match
// Name: __raise_securityfailure
// Library: Visual Studio 2015 Release

void __raise_securityfailure(_EXCEPTION_POINTERS *param_1)

{
  HANDLE hProcess;
  
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter(param_1);
  hProcess = GetCurrentProcess();
                    // WARNING: Could not recover jumptable at 0x000180018c31. Too many branches
                    // WARNING: Treating indirect jump as call
  TerminateProcess(hProcess,0xc0000409);
  return;
}



// Library Function - Single Match
// Name: __report_rangecheckfailure
// Libraries: Visual Studio 2012 Debug, Visual Studio 2012 Release, Visual Studio 2015 Debug, Visual
// Studio 2015 Release

void __report_rangecheckfailure(void)

{
  __report_securityfailure(8);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
// Name: __report_securityfailure
// Library: Visual Studio 2015 Release

void __report_securityfailure(uint param_1)

{
  code *pcVar1;
  BOOL BVar2;
  undefined *puVar3;
  undefined auStack40 [8];
  undefined auStack32 [32];
  
  puVar3 = auStack40;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(param_1);
    puVar3 = auStack32;
  }
  *(undefined8 *)(puVar3 + -8) = 0x180018d4a;
  capture_current_context((PCONTEXT)&DAT_18005adf0,puVar3[-8]);
  _DAT_18005ad60 = *(undefined8 *)(puVar3 + 0x28);
  _DAT_18005ae88 = puVar3 + 0x30;
  _DAT_18005ad50 = 0xc0000409;
  _DAT_18005ad54 = 1;
  _DAT_18005ad68 = 1;
  DAT_18005ad70 = (ulonglong)*(uint *)(puVar3 + 0x30);
  *(undefined8 *)(puVar3 + -8) = 0x180018db6;
  DAT_18005aee8 = _DAT_18005ad60;
  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_180032058,puVar3[-8]);
  return;
}



// Library Function - Single Match
// Name: capture_current_context
// Library: Visual Studio 2015 Release

void capture_current_context(PCONTEXT param_1)

{
  DWORD64 ControlPc;
  PRUNTIME_FUNCTION FunctionEntry;
  DWORD64 local_res8;
  ulonglong local_res10;
  PVOID local_res18;
  
  RtlCaptureContext();
  ControlPc = param_1->Rip;
  FunctionEntry = RtlLookupFunctionEntry(ControlPc,&local_res8,(PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    RtlVirtualUnwind(0,local_res8,ControlPc,FunctionEntry,param_1,&local_res18,&local_res10,
                     (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
  }
  return;
}



// Library Function - Single Match
// Name: capture_previous_context
// Library: Visual Studio 2015 Release

void capture_previous_context(PCONTEXT param_1)

{
  DWORD64 ControlPc;
  PRUNTIME_FUNCTION FunctionEntry;
  int iVar1;
  DWORD64 local_res8;
  ulonglong local_res10;
  PVOID local_res18 [2];
  
  RtlCaptureContext();
  ControlPc = param_1->Rip;
  iVar1 = 0;
  do {
    FunctionEntry = RtlLookupFunctionEntry(ControlPc,&local_res8,(PUNWIND_HISTORY_TABLE)0x0);
    if (FunctionEntry == (PRUNTIME_FUNCTION)0x0) {
      return;
    }
    RtlVirtualUnwind(0,local_res8,ControlPc,FunctionEntry,param_1,local_res18,&local_res10,
                     (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
    iVar1 = iVar1 + 1;
  } while (iVar1 < 2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulonglong FUN_180018ea0(undefined8 param_1,int param_2,longlong param_3)

{
  code *pcVar1;
  bool bVar2;
  byte bVar3;
  char cVar4;
  char cVar5;
  int iVar6;
  ulonglong uVar7;
  code **ppcVar8;
  
  if (param_2 == 0) {
    if (DAT_18005b2c0 < 1) {
      uVar7 = 0;
    }
    else {
      DAT_18005b2c0 = DAT_18005b2c0 + -1;
      cVar4 = __scrt_acquire_startup_lock();
      if (_DAT_18005b2e8 != 2) {
        FUN_180019718(7);
      }
      FUN_1800194ac();
      FUN_180019350();
      FUN_1800198b0();
      _DAT_18005b2e8 = 0;
      FUN_1800194dc();
      __scrt_release_startup_lock(cVar4);
      cVar4 = __scrt_uninitialize_crt(param_3 != 0,'\0');
      uVar7 = (ulonglong)(cVar4 != '\0');
    }
    return uVar7;
  }
  if (param_2 == 1) {
    uVar7 = __scrt_initialize_crt(0);
    if ((char)uVar7 != '\0') {
      cVar4 = __scrt_acquire_startup_lock();
      bVar2 = true;
      if (_DAT_18005b2e8 != 0) {
        FUN_180019718(7);
      }
      _DAT_18005b2e8 = 1;
      cVar5 = FUN_1800193f0();
      if (cVar5 != '\0') {
        FUN_180019864();
        FUN_180019340();
        FUN_180019364();
        iVar6 = _initterm_e(&DAT_18001d488,&DAT_18001d490);
        if ((iVar6 == 0) && (uVar7 = __scrt_dllmain_after_initialize_c(), (char)uVar7 != '\0')) {
          _initterm(&DAT_18001d470,&DAT_18001d480);
          _DAT_18005b2e8 = 2;
          bVar2 = false;
        }
      }
      __scrt_release_startup_lock(cVar4);
      if (!bVar2) {
        ppcVar8 = (code **)FUN_180019708();
        if ((*ppcVar8 != (code *)0x0) &&
           (uVar7 = __scrt_is_nonwritable_in_current_image((longlong)ppcVar8), (char)uVar7 != '\0'))
        {
          pcVar1 = *ppcVar8;
          _guard_check_icall();
          (*pcVar1)(param_1,2,param_3);
        }
        DAT_18005b2c0 = DAT_18005b2c0 + 1;
        return 1;
      }
    }
    return 0;
  }
  if (param_2 == 2) {
    uVar7 = __scrt_dllmain_crt_thread_attach();
    bVar3 = (byte)uVar7;
  }
  else {
    if (param_2 != 3) {
      return 1;
    }
    bVar3 = FUN_180019430();
  }
  return (ulonglong)bVar3;
}



// WARNING: Removing unreachable block (ram,0x0001800191b5)
// Library Function - Single Match
// Name: ?dllmain_raw@@YAHQEAUHINSTANCE__@@KQEAX@Z
// Library: Visual Studio 2015 Release
// int __cdecl dllmain_raw(struct HINSTANCE__ * __ptr64 const,unsigned long,void * __ptr64 const)

int dllmain_raw(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  return 1;
}



ulonglong entry(HINSTANCE__ *param_1,ulong param_2,void *param_3)

{
  uint uVar1;
  ulonglong uVar2;
  undefined8 uVar3;
  
  if (param_2 == 1) {
    FUN_180019294();
  }
  if ((param_2 == 0) && (DAT_18005b2c0 < 1)) {
    return 0;
  }
  if (param_2 - 1 < 2) {
    uVar1 = dllmain_raw(param_1,param_2,param_3);
    if (uVar1 == 0) goto LAB_18001916d;
    uVar2 = FUN_180018ea0(param_1,param_2,(longlong)param_3);
    uVar1 = (uint)uVar2;
    if (uVar1 == 0) goto LAB_18001916d;
  }
  uVar3 = FUN_180019c50();
  uVar1 = (uint)uVar3;
  if ((param_2 == 1) && (uVar1 == 0)) {
    FUN_180019c50();
    FUN_180018ea0(param_1,0,(longlong)param_3);
    dllmain_raw(param_1,0,param_3);
  }
  if ((param_2 == 0) || (param_2 == 3)) {
    uVar2 = FUN_180018ea0(param_1,param_2,(longlong)param_3);
    uVar1 = (uint)uVar2;
    if (uVar1 != 0) {
      uVar1 = dllmain_raw(param_1,param_2,param_3);
    }
  }
LAB_18001916d:
  return (ulonglong)uVar1;
}



void FUN_18001921c(size_t param_1)

{
  code *pcVar1;
  int iVar2;
  void *pvVar3;
  
  do {
    pvVar3 = malloc(param_1);
    if (pvVar3 != (void *)0x0) {
      return;
    }
    iVar2 = _callnewh(param_1);
  } while (iVar2 != 0);
  if (param_1 != 0xffffffffffffffff) {
    FUN_180019a40();
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  FUN_180019a60();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180018690. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x000180018690. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



// Library Function - Multiple Matches With Same Base Name
// Name: `scalar_deleting_destructor'
// Library: Visual Studio 2015 Release

undefined8 * _scalar_deleting_destructor_(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = type_info::vftable;
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_180019294(void)

{
  DWORD DVar1;
  _FILETIME local_res8;
  _FILETIME local_res10;
  uint local_res18;
  undefined4 uStackX28;
  
  if (DAT_180037758 == 0x2b992ddfa232) {
    local_res10 = (_FILETIME)0x0;
    GetSystemTimeAsFileTime((LPFILETIME)&local_res10);
    local_res8 = local_res10;
    DVar1 = GetCurrentThreadId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    DVar1 = GetCurrentProcessId();
    local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
    QueryPerformanceCounter((LARGE_INTEGER *)&local_res18);
    DAT_180037758 =
         ((ulonglong)local_res18 << 0x20 ^ CONCAT44(uStackX28,local_res18) ^ (ulonglong)local_res8 ^
         (ulonglong)&local_res8) & 0xffffffffffff;
    if (DAT_180037758 == 0x2b992ddfa232) {
      DAT_180037758 = 0x2b992ddfa233;
    }
  }
  DAT_180037750 = ~DAT_180037758;
  return;
}



void FUN_180019340(void)

{
                    // WARNING: Could not recover jumptable at 0x000180019347. Too many branches
                    // WARNING: Treating indirect jump as call
  InitializeSListHead((PSLIST_HEADER)&DAT_18005b2d0);
  return;
}



void FUN_180019350(void)

{
  _SLIST_ENTRY _Var1;
  _SLIST_ENTRY _Var2;
  
  _Var2 = (_SLIST_ENTRY)InterlockedFlushSList((PSLIST_HEADER)&DAT_18005b2d0);
  while (_Var2 != (_SLIST_ENTRY)0x0) {
    _Var1 = *(_SLIST_ENTRY *)_Var2;
    _free_base(_Var2);
    _Var2 = _Var1;
  }
  return;
}



undefined * FUN_18001935c(void)

{
  return &DAT_18005b2e0;
}



void FUN_180019364(void)

{
  ulonglong *puVar1;
  
  puVar1 = (ulonglong *)FUN_1800017f8();
  *puVar1 = *puVar1 | 4;
  puVar1 = (ulonglong *)FUN_18001935c();
  *puVar1 = *puVar1 | 2;
  return;
}



// Library Function - Single Match
// Name: __scrt_acquire_startup_lock
// Library: Visual Studio 2015 Release

ulonglong __scrt_acquire_startup_lock(void)

{
  ulonglong uVar1;
  ulonglong uVar2;
  longlong in_GS_OFFSET;
  bool bVar3;
  
  uVar2 = __scrt_is_ucrt_dll_in_use();
  if ((int)uVar2 == 0) {
LAB_1800193ae:
    uVar2 = uVar2 & 0xffffffffffffff00;
  }
  else {
    uVar1 = *(ulonglong *)(*(longlong *)(in_GS_OFFSET + 0x30) + 8);
    do {
      LOCK();
      bVar3 = DAT_18005b2f0 == 0;
      DAT_18005b2f0 = DAT_18005b2f0 ^ (ulonglong)bVar3 * (DAT_18005b2f0 ^ uVar1);
      uVar2 = !bVar3 * DAT_18005b2f0;
      if (bVar3) goto LAB_1800193ae;
    } while (uVar1 != uVar2);
    uVar2 = CONCAT71((int7)(uVar2 >> 8),1);
  }
  return uVar2;
}



// Library Function - Single Match
// Name: __scrt_dllmain_after_initialize_c
// Library: Visual Studio 2015 Release

ulonglong __scrt_dllmain_after_initialize_c(void)

{
  ulonglong uVar1;
  undefined8 uVar2;
  
  uVar1 = __scrt_is_ucrt_dll_in_use();
  if ((int)uVar1 == 0) {
    uVar1 = FUN_180019c50();
    uVar1 = _configure_narrow_argv(uVar1 & 0xffffffff);
    if ((int)uVar1 != 0) {
      return uVar1 & 0xffffffffffffff00;
    }
    uVar2 = _initialize_narrow_environment();
  }
  else {
    uVar2 = FUN_180019a94();
  }
  return CONCAT71((int7)((ulonglong)uVar2 >> 8),1);
}



bool FUN_1800193f0(void)

{
  char cVar1;
  
  cVar1 = FUN_18001953c(0);
  return cVar1 != '\0';
}



// Library Function - Single Match
// Name: __scrt_dllmain_crt_thread_attach
// Library: Visual Studio 2015 Release

ulonglong __scrt_dllmain_crt_thread_attach(void)

{
  ulonglong uVar1;
  undefined8 uVar2;
  
  uVar1 = __vcrt_thread_attach();
  if ((char)uVar1 != '\0') {
    uVar2 = FUN_18001cac0();
    if ((char)uVar2 != '\0') {
      return CONCAT71((int7)((ulonglong)uVar2 >> 8),1);
    }
    uVar1 = __vcrt_thread_detach();
  }
  return uVar1 & 0xffffffffffffff00;
}



undefined FUN_180019430(void)

{
  FUN_18001cac0();
  __vcrt_thread_detach();
  return 1;
}



void FUN_180019448(undefined8 param_1,int param_2,undefined8 param_3,undefined *param_4,uint param_5
                  ,undefined8 param_6)

{
  ulonglong uVar1;
  
  uVar1 = __scrt_is_ucrt_dll_in_use();
  if (((int)uVar1 == 0) && (param_2 == 1)) {
    _guard_check_icall();
    (*(code *)param_4)(param_1,0,param_3);
  }
                    // WARNING: Could not recover jumptable at 0x00018001c99a. Too many branches
                    // WARNING: Treating indirect jump as call
  _seh_filter_dll(param_5,param_6);
  return;
}



void FUN_1800194ac(void)

{
  ulonglong uVar1;
  undefined8 uVar2;
  
  uVar1 = __scrt_is_ucrt_dll_in_use();
  if ((int)uVar1 != 0) {
                    // WARNING: Could not recover jumptable at 0x00018001c9b2. Too many branches
                    // WARNING: Treating indirect jump as call
    _execute_onexit_table(&DAT_18005b2f8);
    return;
  }
  uVar2 = FUN_180018ae0();
  if ((int)uVar2 == 0) {
    _cexit();
  }
  return;
}



undefined FUN_1800194dc(void)

{
  FUN_18001cac0();
  __vcrt_uninitialize_ptd();
  return 1;
}



// Library Function - Single Match
// Name: __scrt_initialize_crt
// Library: Visual Studio 2015 Release

ulonglong __scrt_initialize_crt(int param_1)

{
  uint uVar1;
  undefined4 extraout_var;
  ulonglong uVar2;
  
  if (param_1 == 0) {
    DAT_18005b328 = 1;
  }
  FUN_180019a94();
  uVar1 = __vcrt_initialize();
  uVar2 = CONCAT44(extraout_var,uVar1);
  if ((char)uVar1 != '\0') {
    uVar2 = FUN_18001cac0();
    if ((char)uVar2 != '\0') {
      return uVar2 & 0xffffffffffffff00 | 1;
    }
    uVar2 = __vcrt_uninitialize('\0');
  }
  return uVar2 & 0xffffffffffffff00;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_18001953c(uint param_1)

{
  code *pcVar1;
  byte bVar2;
  int iVar3;
  ulonglong uVar4;
  undefined8 uVar5;
  undefined4 local_28;
  undefined4 uStack36;
  
  if (DAT_18005b2ec == '\0') {
    if (1 < param_1) {
      FUN_180019718(5);
      pcVar1 = (code *)swi(3);
      uVar5 = (*pcVar1)();
      return uVar5;
    }
    uVar4 = __scrt_is_ucrt_dll_in_use();
    if (((int)uVar4 == 0) || (param_1 != 0)) {
      bVar2 = 0x40 - ((byte)DAT_180037758 & 0x3f) & 0x3f;
      _DAT_18005b308 = (0xffffffffffffffffU >> bVar2 | -1 << 0x40 - bVar2) ^ DAT_180037758;
      local_28 = (undefined4)_DAT_18005b308;
      uStack36 = (undefined4)(_DAT_18005b308 >> 0x20);
      _DAT_18005b2f8 = local_28;
      DAT_18005b2fc = uStack36;
      DAT_18005b300 = local_28;
      DAT_18005b304 = uStack36;
      _DAT_18005b310 = local_28;
      DAT_18005b314 = uStack36;
      DAT_18005b318 = local_28;
      DAT_18005b31c = uStack36;
      _DAT_18005b320 = _DAT_18005b308;
    }
    else {
      iVar3 = _initialize_onexit_table(&DAT_18005b2f8);
      if ((iVar3 != 0) || (iVar3 = _initialize_onexit_table(&DAT_18005b310), iVar3 != 0)) {
        return 0;
      }
    }
    DAT_18005b2ec = '\x01';
  }
  return 1;
}



// WARNING: Removing unreachable block (ram,0x0001800196aa)
// Library Function - Single Match
// Name: __scrt_is_nonwritable_in_current_image
// Library: Visual Studio 2015 Release

ulonglong __scrt_is_nonwritable_in_current_image(longlong param_1)

{
  ulonglong uVar1;
  uint7 uVar2;
  IMAGE_SECTION_HEADER *pIVar3;
  
  pIVar3 = &IMAGE_SECTION_HEADER_180000218;
  uVar1 = 0;
  while (pIVar3 != (IMAGE_SECTION_HEADER *)&DAT_1800002e0) {
    if (((ulonglong)(uint)pIVar3->VirtualAddress <= param_1 - 0x180000000U) &&
       (uVar1 = (ulonglong)(uint)(pIVar3->Misc + pIVar3->VirtualAddress),
       param_1 - 0x180000000U < uVar1)) goto LAB_180019693;
    pIVar3 = pIVar3 + 1;
  }
  pIVar3 = (IMAGE_SECTION_HEADER *)0x0;
LAB_180019693:
  if (pIVar3 == (IMAGE_SECTION_HEADER *)0x0) {
    uVar1 = uVar1 & 0xffffffffffffff00;
  }
  else {
    uVar2 = (uint7)(uVar1 >> 8);
    if ((int)pIVar3->Characteristics < 0) {
      uVar1 = (ulonglong)uVar2 << 8;
    }
    else {
      uVar1 = CONCAT71(uVar2,1);
    }
  }
  return uVar1;
}



// Library Function - Single Match
// Name: __scrt_release_startup_lock
// Library: Visual Studio 2015 Release

void __scrt_release_startup_lock(char param_1)

{
  ulonglong uVar1;
  
  uVar1 = __scrt_is_ucrt_dll_in_use();
  if (((int)uVar1 != 0) && (param_1 == '\0')) {
    DAT_18005b2f0 = 0;
  }
  return;
}



// Library Function - Single Match
// Name: __scrt_uninitialize_crt
// Library: Visual Studio 2015 Release

undefined __scrt_uninitialize_crt(char param_1,char param_2)

{
  if ((DAT_18005b328 == '\0') || (param_2 == '\0')) {
    FUN_18001cac0();
    __vcrt_uninitialize(param_1);
  }
  return 1;
}



undefined * FUN_180019708(void)

{
  return &DAT_18005b5c8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180019710(void)

{
  _DAT_18005b32c = 0;
  return;
}



void FUN_180019718(uint param_1)

{
  code *pcVar1;
  BOOL BVar2;
  LONG LVar3;
  PRUNTIME_FUNCTION FunctionEntry;
  undefined *puVar4;
  undefined8 in_stack_00000000;
  DWORD64 local_res10;
  undefined local_res18 [8];
  undefined local_res20 [8];
  undefined auStack1480 [8];
  undefined auStack1472 [232];
  undefined local_4d8 [152];
  undefined *local_440;
  DWORD64 local_3e0;
  
  puVar4 = auStack1480;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(param_1);
    puVar4 = auStack1472;
  }
  *(undefined8 *)(puVar4 + -8) = 0x18001974b;
  FUN_180019710(puVar4[-8]);
  *(undefined8 *)(puVar4 + -8) = 0x18001975c;
  memset(local_4d8,0,0x4d0,puVar4[-8]);
  *(undefined8 *)(puVar4 + -8) = 0x180019766;
  RtlCaptureContext(local_4d8);
  *(undefined8 *)(puVar4 + -8) = 0x180019780;
  FunctionEntry =
       RtlLookupFunctionEntry(local_3e0,&local_res10,(PUNWIND_HISTORY_TABLE)0x0,puVar4[-8]);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0) {
    *(undefined8 *)(puVar4 + 0x38) = 0;
    *(undefined **)(puVar4 + 0x30) = local_res18;
    *(undefined **)(puVar4 + 0x28) = local_res20;
    *(undefined **)(puVar4 + 0x20) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x1800197c1;
    RtlVirtualUnwind(0,local_res10,local_3e0,FunctionEntry,*(PCONTEXT *)(puVar4 + 0x20),
                     *(PVOID **)(puVar4 + 0x28),*(PDWORD64 *)(puVar4 + 0x30),
                     *(PKNONVOLATILE_CONTEXT_POINTERS *)(puVar4 + 0x38));
  }
  local_440 = &stack0x00000008;
  *(undefined8 *)(puVar4 + -8) = 0x1800197f3;
  memset(puVar4 + 0x50,0,0x98,puVar4[-8]);
  *(undefined8 *)(puVar4 + 0x60) = in_stack_00000000;
  *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
  *(undefined4 *)(puVar4 + 0x54) = 1;
  *(undefined8 *)(puVar4 + -8) = 0x180019815;
  BVar2 = IsDebuggerPresent(puVar4[-8]);
  *(undefined **)(puVar4 + 0x40) = puVar4 + 0x50;
  *(undefined **)(puVar4 + 0x48) = local_4d8;
  *(undefined8 *)(puVar4 + -8) = 0x180019836;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0,puVar4[-8]);
  *(undefined8 *)(puVar4 + -8) = 0x180019841;
  LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40),puVar4[-8]);
  if ((LVar3 == 0) && (BVar2 != 1)) {
    *(undefined8 *)(puVar4 + -8) = 0x180019851;
    FUN_180019710(puVar4[-8]);
  }
  return;
}



void FUN_180019864(void)

{
  code *pcVar1;
  code **ppcVar2;
  
  ppcVar2 = (code **)&DAT_180033460;
  while (ppcVar2 < &DAT_180033460) {
    pcVar1 = *ppcVar2;
    if (pcVar1 != (code *)0x0) {
      _guard_check_icall();
      (*pcVar1)();
    }
    ppcVar2 = ppcVar2 + 1;
  }
  return;
}



void FUN_1800198b0(void)

{
  code *pcVar1;
  code **ppcVar2;
  
  ppcVar2 = (code **)&DAT_180033470;
  while (ppcVar2 < &DAT_180033470) {
    pcVar1 = *ppcVar2;
    if (pcVar1 != (code *)0x0) {
      _guard_check_icall();
      (*pcVar1)();
    }
    ppcVar2 = ppcVar2 + 1;
  }
  return;
}



void _guard_check_icall(void)

{
  return;
}



undefined8 * FUN_180019904(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = (char *)0x0;
  param_1[2] = 0;
  __std_exception_copy((char **)(param_2 + 8),(char **)(param_1 + 1));
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 * FUN_180019944(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad allocation";
  *param_1 = std::bad_alloc::vftable;
  return param_1;
}



undefined8 * FUN_180019964(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = (char *)0x0;
  param_1[2] = 0;
  __std_exception_copy((char **)(param_2 + 8),(char **)(param_1 + 1));
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}



undefined8 * FUN_1800199a4(undefined8 *param_1)

{
  param_1[2] = 0;
  param_1[1] = "bad array new length";
  *param_1 = std::bad_array_new_length::vftable;
  return param_1;
}



// Library Function - Single Match
// Name: ??0exception@std@@QEAA@AEBV01@@Z
// Library: Visual Studio 2015 Release
// public: __cdecl std::exception::exception(class std::exception const & __ptr64) __ptr64

void __thiscall std::exception::exception(exception *this,exception *param_1)

{
  *(undefined ***)this = vftable;
  *(char **)(this + 8) = (char *)0x0;
  *(undefined8 *)(this + 0x10) = 0;
  __std_exception_copy((char **)(param_1 + 8),(char **)(this + 8));
  return;
}



// Library Function - Multiple Matches With Same Base Name
// Name: `scalar_deleting_destructor'
// Library: Visual Studio 2015 Release

undefined8 * _scalar_deleting_destructor_(undefined8 *param_1,ulonglong param_2)

{
  *param_1 = std::exception::vftable;
  __std_exception_destroy((void **)(param_1 + 1));
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}



void FUN_180019a40(void)

{
  code *pcVar1;
  undefined8 local_28 [5];
  
  FUN_180019944(local_28);
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_180034268);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_180019a60(void)

{
  code *pcVar1;
  undefined8 local_28 [5];
  
  FUN_1800199a4(local_28);
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_1800342f0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



char * FUN_180019a80(longlong param_1)

{
  char *pcVar1;
  
  pcVar1 = "Unknown exception";
  if (*(longlong *)(param_1 + 8) != 0) {
    pcVar1 = *(char **)(param_1 + 8);
  }
  return pcVar1;
}



// WARNING: Removing unreachable block (ram,0x000180019b9f)
// WARNING: Removing unreachable block (ram,0x000180019b02)
// WARNING: Removing unreachable block (ram,0x000180019abe)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_180019a94(void)

{
  int *piVar1;
  uint *puVar2;
  longlong lVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  byte in_XCR0;
  
  DAT_18003776c = 2;
  _DAT_180037768 = 1;
  piVar1 = (int *)cpuid_basic_info(0);
  uVar6 = 0;
  puVar2 = (uint *)cpuid_Version_info(1);
  uVar4 = puVar2[3];
  if ((piVar1[3] ^ 0x6c65746eU | piVar1[1] ^ 0x756e6547U | piVar1[2] ^ 0x49656e69U) == 0) {
    _DAT_180037770 = 0xffffffffffffffff;
    uVar5 = *puVar2 & 0xfff3ff0;
    if ((((uVar5 == 0x106c0) || (uVar5 == 0x20660)) || (uVar5 == 0x20670)) ||
       ((uVar5 - 0x30650 < 0x21 &&
        ((0x100010001U >> ((ulonglong)(uVar5 - 0x30650) & 0x3f) & 1) != 0)))) {
      DAT_18005b330 = DAT_18005b330 | 1;
    }
  }
  if (((piVar1[1] ^ 0x68747541U | piVar1[2] ^ 0x69746e65U | piVar1[3] ^ 0x444d4163U) == 0) &&
     (0x6010ff < (*puVar2 & 0xff00f00))) {
    DAT_18005b330 = DAT_18005b330 | 4;
  }
  if (6 < *piVar1) {
    lVar3 = cpuid_Extended_Feature_Enumeration_info(7);
    uVar6 = *(uint *)(lVar3 + 4);
    if ((uVar6 >> 9 & 1) != 0) {
      DAT_18005b330 = DAT_18005b330 | 2;
    }
  }
  if ((uVar4 >> 0x14 & 1) != 0) {
    _DAT_180037768 = 2;
    DAT_18003776c = 6;
    if ((((uVar4 >> 0x1b & 1) != 0) && ((uVar4 >> 0x1c & 1) != 0)) && ((in_XCR0 & 6) == 6)) {
      DAT_18003776c = 0xe;
      _DAT_180037768 = 3;
      if ((uVar6 & 0x20) != 0) {
        _DAT_180037768 = 5;
        DAT_18003776c = 0x2e;
      }
    }
  }
  return 0;
}



undefined8 FUN_180019c50(void)

{
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
// Name: __scrt_is_ucrt_dll_in_use
// Library: Visual Studio 2015 Release

ulonglong __scrt_is_ucrt_dll_in_use(void)

{
  return (ulonglong)(_DAT_180037790 != 0);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 * memcpy_FUN_180019c80(undefined8 *param_1,undefined8 *param_2,ulonglong param_3)

{
  undefined4 *puVar1;
  undefined uVar2;
  undefined2 uVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  longlong lVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  undefined8 *puVar10;
  ulonglong uVar11;
  undefined4 *puVar12;
  ulonglong uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  undefined4 uVar16;
  undefined4 uVar17;
  undefined4 uVar18;
  undefined4 uVar19;
  undefined4 uVar20;
  undefined4 uVar21;
  
  if (param_3 < 0x11) {
    switch(param_3) {
    case 0:
      return param_1;
    case 1:
      *(undefined *)param_1 = *(undefined *)param_2;
      return param_1;
    case 2:
      *(undefined2 *)param_1 = *(undefined2 *)param_2;
      return param_1;
    case 3:
      uVar2 = *(undefined *)((longlong)param_2 + 2);
      *(undefined2 *)param_1 = *(undefined2 *)param_2;
      *(undefined *)((longlong)param_1 + 2) = uVar2;
      return param_1;
    case 4:
      *(undefined4 *)param_1 = *(undefined4 *)param_2;
      return param_1;
    case 5:
      uVar2 = *(undefined *)((longlong)param_2 + 4);
      *(undefined4 *)param_1 = *(undefined4 *)param_2;
      *(undefined *)((longlong)param_1 + 4) = uVar2;
      return param_1;
    case 6:
      uVar3 = *(undefined2 *)((longlong)param_2 + 4);
      *(undefined4 *)param_1 = *(undefined4 *)param_2;
      *(undefined2 *)((longlong)param_1 + 4) = uVar3;
      return param_1;
    case 7:
      uVar3 = *(undefined2 *)((longlong)param_2 + 4);
      uVar2 = *(undefined *)((longlong)param_2 + 6);
      *(undefined4 *)param_1 = *(undefined4 *)param_2;
      *(undefined2 *)((longlong)param_1 + 4) = uVar3;
      *(undefined *)((longlong)param_1 + 6) = uVar2;
      return param_1;
    case 8:
      *param_1 = *param_2;
      return param_1;
    case 9:
      uVar2 = *(undefined *)(param_2 + 1);
      *param_1 = *param_2;
      *(undefined *)(param_1 + 1) = uVar2;
      return param_1;
    case 10:
      uVar3 = *(undefined2 *)(param_2 + 1);
      *param_1 = *param_2;
      *(undefined2 *)(param_1 + 1) = uVar3;
      return param_1;
    case 0xb:
      uVar3 = *(undefined2 *)(param_2 + 1);
      uVar2 = *(undefined *)((longlong)param_2 + 10);
      *param_1 = *param_2;
      *(undefined2 *)(param_1 + 1) = uVar3;
      *(undefined *)((longlong)param_1 + 10) = uVar2;
      return param_1;
    case 0xc:
      uVar18 = *(undefined4 *)(param_2 + 1);
      *param_1 = *param_2;
      *(undefined4 *)(param_1 + 1) = uVar18;
      return param_1;
    case 0xd:
      uVar18 = *(undefined4 *)(param_2 + 1);
      uVar2 = *(undefined *)((longlong)param_2 + 0xc);
      *param_1 = *param_2;
      *(undefined4 *)(param_1 + 1) = uVar18;
      *(undefined *)((longlong)param_1 + 0xc) = uVar2;
      return param_1;
    case 0xe:
      uVar18 = *(undefined4 *)(param_2 + 1);
      uVar3 = *(undefined2 *)((longlong)param_2 + 0xc);
      *param_1 = *param_2;
      *(undefined4 *)(param_1 + 1) = uVar18;
      *(undefined2 *)((longlong)param_1 + 0xc) = uVar3;
      return param_1;
    case 0xf:
      uVar18 = *(undefined4 *)(param_2 + 1);
      uVar3 = *(undefined2 *)((longlong)param_2 + 0xc);
      uVar2 = *(undefined *)((longlong)param_2 + 0xe);
      *param_1 = *param_2;
      *(undefined4 *)(param_1 + 1) = uVar18;
      *(undefined2 *)((longlong)param_1 + 0xc) = uVar3;
      *(undefined *)((longlong)param_1 + 0xe) = uVar2;
      return param_1;
    case 0x10:
      uVar18 = *(undefined4 *)((longlong)param_2 + 4);
      uVar19 = *(undefined4 *)(param_2 + 1);
      uVar20 = *(undefined4 *)((longlong)param_2 + 0xc);
      *(undefined4 *)param_1 = *(undefined4 *)param_2;
      *(undefined4 *)((longlong)param_1 + 4) = uVar18;
      *(undefined4 *)(param_1 + 1) = uVar19;
      *(undefined4 *)((longlong)param_1 + 0xc) = uVar20;
      return param_1;
    }
  }
  if (param_3 < 0x21) {
    uVar18 = *(undefined4 *)((longlong)param_2 + 4);
    uVar19 = *(undefined4 *)(param_2 + 1);
    uVar20 = *(undefined4 *)((longlong)param_2 + 0xc);
    puVar9 = (undefined4 *)((param_3 - 0x10) + (longlong)param_2);
    uVar21 = *puVar9;
    uVar14 = puVar9[1];
    uVar15 = puVar9[2];
    uVar16 = puVar9[3];
    *(undefined4 *)param_1 = *(undefined4 *)param_2;
    *(undefined4 *)((longlong)param_1 + 4) = uVar18;
    *(undefined4 *)(param_1 + 1) = uVar19;
    *(undefined4 *)((longlong)param_1 + 0xc) = uVar20;
    puVar9 = (undefined4 *)((param_3 - 0x10) + (longlong)param_1);
    *puVar9 = uVar21;
    puVar9[1] = uVar14;
    puVar9[2] = uVar15;
    puVar9[3] = uVar16;
    return param_1;
  }
  puVar10 = (undefined8 *)((longlong)param_2 - (longlong)param_1);
  if ((param_2 < param_1) && ((longlong)param_1 < (longlong)((longlong)param_2 + param_3))) {
    lVar6 = (longlong)param_1 + param_3;
    puVar9 = (undefined4 *)((longlong)puVar10 + lVar6 + -0x10);
    uVar18 = puVar9[1];
    uVar19 = puVar9[2];
    uVar20 = puVar9[3];
    puVar7 = (undefined4 *)(lVar6 + -0x10);
    puVar12 = (undefined4 *)(param_3 - 0x10);
    puVar8 = puVar7;
    uVar21 = *puVar9;
    uVar14 = uVar18;
    uVar15 = uVar19;
    uVar16 = uVar20;
    if (((ulonglong)puVar7 & 0xf) != 0) {
      puVar8 = (undefined4 *)((ulonglong)puVar7 & 0xfffffffffffffff0);
      puVar12 = (undefined4 *)((longlong)puVar10 + (longlong)puVar8);
      uVar21 = *puVar12;
      uVar14 = puVar12[1];
      uVar15 = puVar12[2];
      uVar16 = puVar12[3];
      *puVar7 = *puVar9;
      *(undefined4 *)(lVar6 + -0xc) = uVar18;
      *(undefined4 *)(lVar6 + -8) = uVar19;
      *(undefined4 *)(lVar6 + -4) = uVar20;
      puVar12 = (undefined4 *)((longlong)puVar8 - (longlong)param_1);
    }
    uVar11 = (ulonglong)puVar12 >> 7;
    if (uVar11 != 0) {
      *puVar8 = uVar21;
      puVar8[1] = uVar14;
      puVar8[2] = uVar15;
      puVar8[3] = uVar16;
      puVar9 = puVar8;
      while( true ) {
        puVar7 = (undefined4 *)((longlong)((longlong)puVar10 + -0x10) + (longlong)puVar9);
        uVar18 = puVar7[1];
        uVar19 = puVar7[2];
        uVar20 = puVar7[3];
        puVar8 = (undefined4 *)((longlong)((longlong)puVar10 + -0x20) + (longlong)puVar9);
        uVar21 = *puVar8;
        uVar14 = puVar8[1];
        uVar15 = puVar8[2];
        uVar16 = puVar8[3];
        puVar8 = puVar9 + -0x20;
        puVar9[-4] = *puVar7;
        puVar9[-3] = uVar18;
        puVar9[-2] = uVar19;
        puVar9[-1] = uVar20;
        puVar9[-8] = uVar21;
        puVar9[-7] = uVar14;
        puVar9[-6] = uVar15;
        puVar9[-5] = uVar16;
        puVar7 = (undefined4 *)((longlong)((longlong)puVar10 + 0x50) + (longlong)puVar8);
        uVar18 = puVar7[1];
        uVar19 = puVar7[2];
        uVar20 = puVar7[3];
        puVar1 = (undefined4 *)((longlong)((longlong)puVar10 + 0x40) + (longlong)puVar8);
        uVar21 = *puVar1;
        uVar14 = puVar1[1];
        uVar15 = puVar1[2];
        uVar16 = puVar1[3];
        uVar11 = uVar11 - 1;
        puVar9[-0xc] = *puVar7;
        puVar9[-0xb] = uVar18;
        puVar9[-10] = uVar19;
        puVar9[-9] = uVar20;
        puVar9[-0x10] = uVar21;
        puVar9[-0xf] = uVar14;
        puVar9[-0xe] = uVar15;
        puVar9[-0xd] = uVar16;
        puVar7 = (undefined4 *)((longlong)((longlong)puVar10 + 0x30) + (longlong)puVar8);
        uVar18 = puVar7[1];
        uVar19 = puVar7[2];
        uVar20 = puVar7[3];
        puVar1 = (undefined4 *)((longlong)((longlong)puVar10 + 0x20) + (longlong)puVar8);
        uVar21 = *puVar1;
        uVar14 = puVar1[1];
        uVar15 = puVar1[2];
        uVar16 = puVar1[3];
        puVar9[-0x14] = *puVar7;
        puVar9[-0x13] = uVar18;
        puVar9[-0x12] = uVar19;
        puVar9[-0x11] = uVar20;
        puVar9[-0x18] = uVar21;
        puVar9[-0x17] = uVar14;
        puVar9[-0x16] = uVar15;
        puVar9[-0x15] = uVar16;
        puVar1 = (undefined4 *)((longlong)((longlong)puVar10 + 0x10) + (longlong)puVar8);
        uVar18 = puVar1[1];
        uVar19 = puVar1[2];
        uVar20 = puVar1[3];
        puVar7 = (undefined4 *)((longlong)puVar10 + (longlong)puVar8);
        uVar21 = *puVar7;
        uVar14 = puVar7[1];
        uVar15 = puVar7[2];
        uVar16 = puVar7[3];
        if (uVar11 == 0) break;
        puVar9[-0x1c] = *puVar1;
        puVar9[-0x1b] = uVar18;
        puVar9[-0x1a] = uVar19;
        puVar9[-0x19] = uVar20;
        *puVar8 = uVar21;
        puVar9[-0x1f] = uVar14;
        puVar9[-0x1e] = uVar15;
        puVar9[-0x1d] = uVar16;
        puVar9 = puVar8;
      }
      puVar9[-0x1c] = *puVar1;
      puVar9[-0x1b] = uVar18;
      puVar9[-0x1a] = uVar19;
      puVar9[-0x19] = uVar20;
      puVar12 = (undefined4 *)((ulonglong)puVar12 & 0x7f);
    }
    uVar11 = (ulonglong)puVar12 >> 4;
    while (uVar11 != 0) {
      *puVar8 = uVar21;
      puVar8[1] = uVar14;
      puVar8[2] = uVar15;
      puVar8[3] = uVar16;
      puVar8 = puVar8 + -4;
      puVar9 = (undefined4 *)((longlong)puVar10 + (longlong)puVar8);
      uVar21 = *puVar9;
      uVar14 = puVar9[1];
      uVar15 = puVar9[2];
      uVar16 = puVar9[3];
      uVar11 = uVar11 - 1;
    }
    if (((ulonglong)puVar12 & 0xf) != 0) {
      uVar18 = *(undefined4 *)((longlong)param_2 + 4);
      uVar19 = *(undefined4 *)(param_2 + 1);
      uVar20 = *(undefined4 *)((longlong)param_2 + 0xc);
      *(undefined4 *)param_1 = *(undefined4 *)param_2;
      *(undefined4 *)((longlong)param_1 + 4) = uVar18;
      *(undefined4 *)(param_1 + 1) = uVar19;
      *(undefined4 *)((longlong)param_1 + 0xc) = uVar20;
    }
    *puVar8 = uVar21;
    puVar8[1] = uVar14;
    puVar8[2] = uVar15;
    puVar8[3] = uVar16;
    return param_1;
  }
  if (param_3 < 0x81) {
    if ((DAT_18005b330 >> 2 & 1) == 0) {
      puVar9 = (undefined4 *)((longlong)puVar10 + (longlong)param_1);
      uVar18 = *puVar9;
      uVar19 = puVar9[1];
      uVar20 = puVar9[2];
      uVar21 = puVar9[3];
      puVar5 = param_1 + 2;
      uVar11 = param_3 - 0x10;
      goto LAB_180019f3a;
    }
  }
  else {
    if ((DAT_18005b330 >> 1 & 1) == 0) {
      puVar9 = (undefined4 *)((longlong)puVar10 + (longlong)param_1);
      uVar14 = puVar9[1];
      uVar15 = puVar9[2];
      uVar16 = puVar9[3];
      puVar4 = param_1 + 2;
      uVar18 = *puVar9;
      uVar19 = uVar14;
      uVar20 = uVar15;
      uVar21 = uVar16;
      if (((ulonglong)param_1 & 0xf) != 0) {
        puVar8 = (undefined4 *)((longlong)puVar10 + ((ulonglong)puVar4 & 0xfffffffffffffff0));
        uVar18 = *puVar8;
        uVar19 = puVar8[1];
        uVar20 = puVar8[2];
        uVar21 = puVar8[3];
        puVar4 = (undefined8 *)(((ulonglong)puVar4 & 0xfffffffffffffff0) + 0x10);
        *(undefined4 *)param_1 = *puVar9;
        *(undefined4 *)((longlong)param_1 + 4) = uVar14;
        *(undefined4 *)(param_1 + 1) = uVar15;
        *(undefined4 *)((longlong)param_1 + 0xc) = uVar16;
      }
      uVar11 = (longlong)param_1 + (param_3 - (longlong)puVar4);
      uVar13 = uVar11 >> 7;
      puVar5 = puVar4;
      if (uVar13 != 0) {
        *(undefined4 *)(puVar4 + -2) = uVar18;
        *(undefined4 *)((longlong)puVar4 + -0xc) = uVar19;
        *(undefined4 *)(puVar4 + -1) = uVar20;
        *(undefined4 *)((longlong)puVar4 + -4) = uVar21;
        if (_DAT_180037770 < uVar13) {
          while( true ) {
            puVar9 = (undefined4 *)((longlong)puVar10 + (longlong)puVar4);
            uVar18 = puVar9[1];
            uVar19 = puVar9[2];
            uVar20 = puVar9[3];
            puVar8 = (undefined4 *)((longlong)((longlong)puVar10 + 0x10) + (longlong)puVar4);
            uVar21 = *puVar8;
            uVar14 = puVar8[1];
            uVar15 = puVar8[2];
            uVar16 = puVar8[3];
            puVar5 = puVar4 + 0x10;
            *(undefined4 *)puVar4 = *puVar9;
            *(undefined4 *)((longlong)puVar4 + 4) = uVar18;
            *(undefined4 *)(puVar4 + 1) = uVar19;
            *(undefined4 *)((longlong)puVar4 + 0xc) = uVar20;
            *(undefined4 *)(puVar4 + 2) = uVar21;
            *(undefined4 *)((longlong)puVar4 + 0x14) = uVar14;
            *(undefined4 *)(puVar4 + 3) = uVar15;
            *(undefined4 *)((longlong)puVar4 + 0x1c) = uVar16;
            puVar9 = (undefined4 *)((longlong)((longlong)puVar10 + -0x60) + (longlong)puVar5);
            uVar18 = puVar9[1];
            uVar19 = puVar9[2];
            uVar20 = puVar9[3];
            puVar8 = (undefined4 *)((longlong)((longlong)puVar10 + -0x50) + (longlong)puVar5);
            uVar21 = *puVar8;
            uVar14 = puVar8[1];
            uVar15 = puVar8[2];
            uVar16 = puVar8[3];
            uVar13 = uVar13 - 1;
            *(undefined4 *)(puVar4 + 4) = *puVar9;
            *(undefined4 *)((longlong)puVar4 + 0x24) = uVar18;
            *(undefined4 *)(puVar4 + 5) = uVar19;
            *(undefined4 *)((longlong)puVar4 + 0x2c) = uVar20;
            *(undefined4 *)(puVar4 + 6) = uVar21;
            *(undefined4 *)((longlong)puVar4 + 0x34) = uVar14;
            *(undefined4 *)(puVar4 + 7) = uVar15;
            *(undefined4 *)((longlong)puVar4 + 0x3c) = uVar16;
            puVar9 = (undefined4 *)((longlong)((longlong)puVar10 + -0x40) + (longlong)puVar5);
            uVar18 = puVar9[1];
            uVar19 = puVar9[2];
            uVar20 = puVar9[3];
            puVar8 = (undefined4 *)((longlong)((longlong)puVar10 + -0x30) + (longlong)puVar5);
            uVar21 = *puVar8;
            uVar14 = puVar8[1];
            uVar15 = puVar8[2];
            uVar16 = puVar8[3];
            *(undefined4 *)(puVar4 + 8) = *puVar9;
            *(undefined4 *)((longlong)puVar4 + 0x44) = uVar18;
            *(undefined4 *)(puVar4 + 9) = uVar19;
            *(undefined4 *)((longlong)puVar4 + 0x4c) = uVar20;
            *(undefined4 *)(puVar4 + 10) = uVar21;
            *(undefined4 *)((longlong)puVar4 + 0x54) = uVar14;
            *(undefined4 *)(puVar4 + 0xb) = uVar15;
            *(undefined4 *)((longlong)puVar4 + 0x5c) = uVar16;
            puVar9 = (undefined4 *)((longlong)((longlong)puVar10 + -0x20) + (longlong)puVar5);
            uVar14 = *puVar9;
            uVar15 = puVar9[1];
            uVar16 = puVar9[2];
            uVar17 = puVar9[3];
            puVar9 = (undefined4 *)((longlong)((longlong)puVar10 + -0x10) + (longlong)puVar5);
            uVar18 = *puVar9;
            uVar19 = puVar9[1];
            uVar20 = puVar9[2];
            uVar21 = puVar9[3];
            if (uVar13 == 0) break;
            *(undefined4 *)(puVar4 + 0xc) = uVar14;
            *(undefined4 *)((longlong)puVar4 + 100) = uVar15;
            *(undefined4 *)(puVar4 + 0xd) = uVar16;
            *(undefined4 *)((longlong)puVar4 + 0x6c) = uVar17;
            *(undefined4 *)(puVar4 + 0xe) = uVar18;
            *(undefined4 *)((longlong)puVar4 + 0x74) = uVar19;
            *(undefined4 *)(puVar4 + 0xf) = uVar20;
            *(undefined4 *)((longlong)puVar4 + 0x7c) = uVar21;
            puVar4 = puVar5;
          }
        }
        else {
          while( true ) {
            puVar9 = (undefined4 *)((longlong)puVar10 + (longlong)puVar4);
            uVar18 = puVar9[1];
            uVar19 = puVar9[2];
            uVar20 = puVar9[3];
            puVar8 = (undefined4 *)((longlong)((longlong)puVar10 + 0x10) + (longlong)puVar4);
            uVar21 = *puVar8;
            uVar14 = puVar8[1];
            uVar15 = puVar8[2];
            uVar16 = puVar8[3];
            puVar5 = puVar4 + 0x10;
            *(undefined4 *)puVar4 = *puVar9;
            *(undefined4 *)((longlong)puVar4 + 4) = uVar18;
            *(undefined4 *)(puVar4 + 1) = uVar19;
            *(undefined4 *)((longlong)puVar4 + 0xc) = uVar20;
            *(undefined4 *)(puVar4 + 2) = uVar21;
            *(undefined4 *)((longlong)puVar4 + 0x14) = uVar14;
            *(undefined4 *)(puVar4 + 3) = uVar15;
            *(undefined4 *)((longlong)puVar4 + 0x1c) = uVar16;
            puVar9 = (undefined4 *)((longlong)((longlong)puVar10 + -0x60) + (longlong)puVar5);
            uVar18 = puVar9[1];
            uVar19 = puVar9[2];
            uVar20 = puVar9[3];
            puVar8 = (undefined4 *)((longlong)((longlong)puVar10 + -0x50) + (longlong)puVar5);
            uVar21 = *puVar8;
            uVar14 = puVar8[1];
            uVar15 = puVar8[2];
            uVar16 = puVar8[3];
            uVar13 = uVar13 - 1;
            *(undefined4 *)(puVar4 + 4) = *puVar9;
            *(undefined4 *)((longlong)puVar4 + 0x24) = uVar18;
            *(undefined4 *)(puVar4 + 5) = uVar19;
            *(undefined4 *)((longlong)puVar4 + 0x2c) = uVar20;
            *(undefined4 *)(puVar4 + 6) = uVar21;
            *(undefined4 *)((longlong)puVar4 + 0x34) = uVar14;
            *(undefined4 *)(puVar4 + 7) = uVar15;
            *(undefined4 *)((longlong)puVar4 + 0x3c) = uVar16;
            puVar9 = (undefined4 *)((longlong)((longlong)puVar10 + -0x40) + (longlong)puVar5);
            uVar18 = puVar9[1];
            uVar19 = puVar9[2];
            uVar20 = puVar9[3];
            puVar8 = (undefined4 *)((longlong)((longlong)puVar10 + -0x30) + (longlong)puVar5);
            uVar21 = *puVar8;
            uVar14 = puVar8[1];
            uVar15 = puVar8[2];
            uVar16 = puVar8[3];
            *(undefined4 *)(puVar4 + 8) = *puVar9;
            *(undefined4 *)((longlong)puVar4 + 0x44) = uVar18;
            *(undefined4 *)(puVar4 + 9) = uVar19;
            *(undefined4 *)((longlong)puVar4 + 0x4c) = uVar20;
            *(undefined4 *)(puVar4 + 10) = uVar21;
            *(undefined4 *)((longlong)puVar4 + 0x54) = uVar14;
            *(undefined4 *)(puVar4 + 0xb) = uVar15;
            *(undefined4 *)((longlong)puVar4 + 0x5c) = uVar16;
            puVar9 = (undefined4 *)((longlong)((longlong)puVar10 + -0x20) + (longlong)puVar5);
            uVar14 = *puVar9;
            uVar15 = puVar9[1];
            uVar16 = puVar9[2];
            uVar17 = puVar9[3];
            puVar9 = (undefined4 *)((longlong)((longlong)puVar10 + -0x10) + (longlong)puVar5);
            uVar18 = *puVar9;
            uVar19 = puVar9[1];
            uVar20 = puVar9[2];
            uVar21 = puVar9[3];
            if (uVar13 == 0) break;
            *(undefined4 *)(puVar4 + 0xc) = uVar14;
            *(undefined4 *)((longlong)puVar4 + 100) = uVar15;
            *(undefined4 *)(puVar4 + 0xd) = uVar16;
            *(undefined4 *)((longlong)puVar4 + 0x6c) = uVar17;
            *(undefined4 *)(puVar4 + 0xe) = uVar18;
            *(undefined4 *)((longlong)puVar4 + 0x74) = uVar19;
            *(undefined4 *)(puVar4 + 0xf) = uVar20;
            *(undefined4 *)((longlong)puVar4 + 0x7c) = uVar21;
            puVar4 = puVar5;
          }
        }
        *(undefined4 *)(puVar5 + -4) = uVar14;
        *(undefined4 *)((longlong)puVar5 + -0x1c) = uVar15;
        *(undefined4 *)(puVar5 + -3) = uVar16;
        *(undefined4 *)((longlong)puVar5 + -0x14) = uVar17;
        uVar11 = uVar11 & 0x7f;
      }
LAB_180019f3a:
      uVar13 = uVar11 >> 4;
      while (uVar13 != 0) {
        *(undefined4 *)(puVar5 + -2) = uVar18;
        *(undefined4 *)((longlong)puVar5 + -0xc) = uVar19;
        *(undefined4 *)(puVar5 + -1) = uVar20;
        *(undefined4 *)((longlong)puVar5 + -4) = uVar21;
        puVar9 = (undefined4 *)((longlong)puVar10 + (longlong)puVar5);
        uVar18 = *puVar9;
        uVar19 = puVar9[1];
        uVar20 = puVar9[2];
        uVar21 = puVar9[3];
        puVar5 = puVar5 + 2;
        uVar13 = uVar13 - 1;
      }
      if ((uVar11 & 0xf) != 0) {
        lVar6 = (uVar11 & 0xf) + (longlong)puVar5;
        puVar9 = (undefined4 *)((longlong)puVar10 + lVar6 + -0x10);
        uVar14 = puVar9[1];
        uVar15 = puVar9[2];
        uVar16 = puVar9[3];
        *(undefined4 *)(lVar6 + -0x10) = *puVar9;
        *(undefined4 *)(lVar6 + -0xc) = uVar14;
        *(undefined4 *)(lVar6 + -8) = uVar15;
        *(undefined4 *)(lVar6 + -4) = uVar16;
      }
      *(undefined4 *)(puVar5 + -2) = uVar18;
      *(undefined4 *)((longlong)puVar5 + -0xc) = uVar19;
      *(undefined4 *)(puVar5 + -1) = uVar20;
      *(undefined4 *)((longlong)puVar5 + -4) = uVar21;
      return param_1;
    }
  }
  puVar10 = param_1;
  while (param_3 != 0) {
    param_3 = param_3 - 1;
    *(undefined *)puVar10 = *(undefined *)param_2;
    param_2 = (undefined8 *)((longlong)param_2 + 1);
    puVar10 = (undefined8 *)((longlong)puVar10 + 1);
  }
  return param_1;
}



// Library Function - Single Match
// Name: memcmp
// Library: Visual Studio

int memcmp(void *_Buf1,void *_Buf2,size_t _Size)

{
  uint uVar1;
  ulonglong uVar2;
  void *pvVar3;
  ulonglong uVar4;
  bool bVar5;
  
  pvVar3 = (void *)((longlong)_Buf2 - (longlong)_Buf1);
  if (7 < _Size) {
    uVar4 = (ulonglong)_Buf1 & 7;
    while (uVar4 != 0) {
                    // WARNING: Load size is inaccurate
      bVar5 = *_Buf1 < *(byte *)((longlong)pvVar3 + (longlong)_Buf1);
      if (*_Buf1 != *(byte *)((longlong)pvVar3 + (longlong)_Buf1)) goto LAB_18001a123;
      _Buf1 = (void *)((longlong)_Buf1 + 1);
      _Size = _Size - 1;
      uVar4 = (ulonglong)_Buf1 & 7;
    }
    if (_Size >> 3 != 0) {
      uVar4 = _Size >> 5;
      if (uVar4 != 0) {
        do {
                    // WARNING: Load size is inaccurate
          uVar2 = *_Buf1;
          if (uVar2 != *(ulonglong *)((longlong)pvVar3 + (longlong)_Buf1)) goto LAB_18001a194;
          uVar2 = *(ulonglong *)((longlong)_Buf1 + 8);
          if (uVar2 != *(ulonglong *)((longlong)pvVar3 + 8 + (longlong)_Buf1)) {
LAB_18001a190:
            _Buf1 = (void *)((longlong)_Buf1 + 8);
            goto LAB_18001a194;
          }
          uVar2 = *(ulonglong *)((longlong)_Buf1 + 0x10);
          if (uVar2 != *(ulonglong *)((longlong)pvVar3 + 0x10 + (longlong)_Buf1)) {
LAB_18001a18c:
            _Buf1 = (void *)((longlong)_Buf1 + 8);
            goto LAB_18001a190;
          }
          uVar2 = *(ulonglong *)((longlong)_Buf1 + 0x18);
          if (uVar2 != *(ulonglong *)((longlong)pvVar3 + 0x18 + (longlong)_Buf1)) {
            _Buf1 = (void *)((longlong)_Buf1 + 8);
            goto LAB_18001a18c;
          }
          _Buf1 = (void *)((longlong)_Buf1 + 0x20);
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
        _Size = _Size & 0x1f;
      }
      uVar4 = _Size >> 3;
      if (uVar4 != 0) {
        do {
                    // WARNING: Load size is inaccurate
          uVar2 = *_Buf1;
          if (uVar2 != *(ulonglong *)((longlong)pvVar3 + (longlong)_Buf1)) {
LAB_18001a194:
            uVar4 = *(ulonglong *)((longlong)_Buf1 + (longlong)pvVar3);
            uVar1 = (uint)((uVar2 >> 0x38 | (uVar2 & 0xff000000000000) >> 0x28 |
                            (uVar2 & 0xff0000000000) >> 0x18 | (uVar2 & 0xff00000000) >> 8 |
                            (uVar2 & 0xff000000) << 8 | (uVar2 & 0xff0000) << 0x18 |
                            (uVar2 & 0xff00) << 0x28 | uVar2 << 0x38) <
                          (uVar4 >> 0x38 | (uVar4 & 0xff000000000000) >> 0x28 |
                           (uVar4 & 0xff0000000000) >> 0x18 | (uVar4 & 0xff00000000) >> 8 |
                           (uVar4 & 0xff000000) << 8 | (uVar4 & 0xff0000) << 0x18 |
                           (uVar4 & 0xff00) << 0x28 | uVar4 << 0x38));
            return (int)((1 - uVar1) - (uint)(uVar1 != 0));
          }
          _Buf1 = (void *)((longlong)_Buf1 + 8);
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
        _Size = _Size & 7;
      }
    }
  }
  while( true ) {
    if (_Size == 0) {
      return 0;
    }
                    // WARNING: Load size is inaccurate
    bVar5 = *_Buf1 < *(byte *)((longlong)pvVar3 + (longlong)_Buf1);
    if (*_Buf1 != *(byte *)((longlong)pvVar3 + (longlong)_Buf1)) break;
    _Buf1 = (void *)((longlong)_Buf1 + 1);
    _Size = _Size - 1;
  }
LAB_18001a123:
  return (int)((1 - (uint)bVar5) - (uint)(bVar5 != 0));
}



// Library Function - Single Match
// Name: __DestructExceptionObject
// Library: Visual Studio 2015 Release

void __DestructExceptionObject(int *param_1)

{
  byte *pbVar1;
  longlong *plVar2;
  code *pcVar3;
  
  if ((((param_1 != (int *)0x0) && (*param_1 == -0x1f928c9d)) && (param_1[6] == 4)) &&
     ((param_1[8] + 0xe66cfae0U < 3 && (pbVar1 = *(byte **)(param_1 + 0xc), pbVar1 != (byte *)0x0)))
     ) {
    if (*(int *)(pbVar1 + 4) == 0) {
      if (((*pbVar1 & 0x10) != 0) &&
         (plVar2 = **(longlong ***)(param_1 + 10), plVar2 != (longlong *)0x0)) {
        pcVar3 = *(code **)(*plVar2 + 0x10);
        _guard_check_icall();
        (*pcVar3)(plVar2);
      }
    }
    else {
      FUN_18001a230(*(undefined8 *)(param_1 + 10),
                    (undefined *)((longlong)*(int *)(pbVar1 + 4) + *(longlong *)(param_1 + 0xe)));
    }
  }
  return;
}



void FUN_18001a230(undefined8 param_1,undefined *param_2)

{
                    // WARNING: Could not recover jumptable at 0x00018001a230. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)param_2)();
  return;
}



// Library Function - Single Match
// Name: _IsExceptionObjectToBeDestroyed
// Library: Visual Studio 2015 Release

undefined8 _IsExceptionObjectToBeDestroyed(longlong param_1)

{
  longlong lVar1;
  longlong *plVar2;
  
  lVar1 = __vcrt_getptd();
  plVar2 = *(longlong **)(lVar1 + 0x58);
  while( true ) {
    if (plVar2 == (longlong *)0x0) {
      return 1;
    }
    if (*plVar2 == param_1) break;
    plVar2 = (longlong *)plVar2[1];
  }
  return 0;
}



// Library Function - Single Match
// Name: __AdjustPointer
// Library: Visual Studio 2015 Release

longlong __AdjustPointer(longlong param_1,int *param_2)

{
  longlong lVar1;
  
  lVar1 = *param_2 + param_1;
  if (-1 < param_2[1]) {
    lVar1 = lVar1 + (longlong)*(int *)((longlong)param_2[2] + *(longlong *)(param_2[1] + param_1)) +
                    (longlong)param_2[1];
  }
  return lVar1;
}



// Library Function - Single Match
// Name: __FrameUnwindFilter
// Library: Visual Studio 2015 Release

undefined8 __FrameUnwindFilter(int **param_1)

{
  int *piVar1;
  code *pcVar2;
  longlong lVar3;
  undefined8 uVar4;
  
  piVar1 = *param_1;
  if ((*piVar1 == -0x1fbcbcae) || (*piVar1 == -0x1fbcb0b3)) {
    lVar3 = __vcrt_getptd();
    if (0 < *(int *)(lVar3 + 0x30)) {
      lVar3 = __vcrt_getptd();
      *(int *)(lVar3 + 0x30) = *(int *)(lVar3 + 0x30) + -1;
    }
  }
  else {
    if (*piVar1 == -0x1f928c9d) {
      lVar3 = __vcrt_getptd();
      *(undefined4 *)(lVar3 + 0x30) = 0;
      terminate();
      pcVar2 = (code *)swi(3);
      uVar4 = (*pcVar2)();
      return uVar4;
    }
  }
  return 0;
}



void Unwind_18001a2d4(void)

{
  code *pcVar1;
  
  terminate();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
// Name: _CxxThrowException
// Library: Visual Studio 2015 Release

void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
  longlong lVar1;
  longlong lVar2;
  code *pcVar3;
  PVOID local_res8;
  undefined4 local_38;
  undefined4 uStack52;
  void *local_30;
  ThrowInfo *local_28;
  PVOID local_20;
  
  local_38 = 0x19930520;
  uStack52 = 0;
  local_30 = (void *)0x0;
  local_28 = (ThrowInfo *)0x0;
  local_20 = (PVOID)0x0;
  if ((pThrowInfo != (ThrowInfo *)0x0) && ((*(byte *)&pThrowInfo->attributes & 0x10) != 0)) {
                    // WARNING: Load size is inaccurate
    lVar1 = *pExceptionObject;
    lVar2 = *(longlong *)(lVar1 + -8);
    pcVar3 = *(code **)(lVar2 + 0x40);
    pThrowInfo = *(ThrowInfo **)(lVar2 + 0x30);
    _guard_check_icall();
    (*pcVar3)(lVar1 + -8);
  }
  local_30 = pExceptionObject;
  local_28 = pThrowInfo;
  local_res8 = RtlPcToFileHeader(pThrowInfo,&local_res8);
  if (pThrowInfo != (ThrowInfo *)0x0) {
    if ((*(byte *)&pThrowInfo->attributes & 8) == 0) {
      if (local_res8 == (PVOID)0x0) {
        local_38 = 0x1994000;
      }
    }
    else {
      local_38 = 0x1994000;
    }
  }
  local_20 = local_res8;
  RaiseException(0xe06d7363,1,4,(ULONG_PTR *)&local_38);
  return;
}



// Library Function - Single Match
// Name: ?_ExecutionInCatch@@YAHPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z
// Library: Visual Studio 2015 Release
// int __cdecl _ExecutionInCatch(struct _xDISPATCHER_CONTEXT * __ptr64,struct _s_FuncInfo const *
// __ptr64)

int _ExecutionInCatch(_xDISPATCHER_CONTEXT *param_1,_s_FuncInfo *param_2)

{
  int iVar1;
  longlong lVar2;
  ulonglong uVar3;
  
  iVar1 = FUN_18001af78((longlong)param_2,(ulonglong *)param_1);
  uVar3 = (ulonglong)param_2->nTryBlocks;
  do {
    lVar2 = 0;
    if ((int)uVar3 == 0) break;
    uVar3 = (ulonglong)((int)uVar3 - 1);
    lVar2 = __vcrt_getptd();
    lVar2 = (longlong)(int)param_2->dispTryBlockMap + *(longlong *)(lVar2 + 0x60) + uVar3 * 0x14;
  } while ((iVar1 <= *(int *)(lVar2 + 4)) || (*(int *)(lVar2 + 8) < iVar1));
  return (int)(uint)(lVar2 != 0);
}



// Library Function - Single Match
// Name: ?_GetEstablisherFrame@@YAPEA_KPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@0@Z
// Library: Visual Studio 2015 Release
// unsigned __int64 * __ptr64 __cdecl _GetEstablisherFrame(unsigned __int64 * __ptr64,struct
// _xDISPATCHER_CONTEXT * __ptr64,struct _s_FuncInfo const * __ptr64,unsigned __int64 * __ptr64)

__uint64 *
_GetEstablisherFrame
          (__uint64 *param_1,_xDISPATCHER_CONTEXT *param_2,_s_FuncInfo *param_3,__uint64 *param_4)

{
  uint uVar1;
  int iVar2;
  PRUNTIME_FUNCTION p_Var3;
  uint uVar4;
  ulonglong uVar5;
  int *piVar6;
  longlong lVar7;
  ulonglong uVar8;
  longlong lVar9;
  ulonglong local_res8;
  
  uVar8 = (ulonglong)param_3->nTryBlocks;
  iVar2 = FUN_18001af78((longlong)param_3,(ulonglong *)param_2);
  *param_4 = *param_1;
  do {
    do {
      if ((int)uVar8 == 0) {
        return param_4;
      }
      uVar8 = (ulonglong)((int)uVar8 - 1);
      lVar7 = (longlong)(int)param_3->dispTryBlockMap + uVar8 * 0x14 + *(longlong *)(param_2 + 8);
    } while ((iVar2 <= *(int *)(lVar7 + 4)) || (*(int *)(lVar7 + 8) < iVar2));
    p_Var3 = RtlLookupFunctionEntry(*(DWORD64 *)param_2,&local_res8,(PUNWIND_HISTORY_TABLE)0x0);
    uVar5 = 0;
    lVar9 = (longlong)*(int *)(lVar7 + 0x10) + local_res8;
    uVar1 = *(uint *)(lVar7 + 0xc);
    if (uVar1 != 0) {
      piVar6 = (int *)(lVar9 + 0xc);
      do {
        if ((longlong)*piVar6 == (ulonglong)p_Var3->BeginAddress) break;
        uVar4 = (int)uVar5 + 1;
        uVar5 = (ulonglong)uVar4;
        piVar6 = piVar6 + 5;
      } while (uVar4 < uVar1);
    }
    if ((uint)uVar5 < uVar1) {
      *param_4 = *(__uint64 *)((longlong)*(int *)(lVar9 + 0x10 + uVar5 * 0x14) + *param_1);
      return param_4;
    }
  } while( true );
}



// Library Function - Single Match
// Name: 
?_GetRangeOfTrysToCheck@@YAPEBU_s_TryBlockMapEntry@@PEA_KPEBU_s_FuncInfo@@HHPEAI2PEAU_xDISPATCHER_CONTEXT@@@Z
// Library: Visual Studio 2015 Release
// struct _s_TryBlockMapEntry const * __ptr64 __cdecl _GetRangeOfTrysToCheck(unsigned __int64 *
// __ptr64,struct _s_FuncInfo const * __ptr64,int,int,unsigned int * __ptr64,unsigned int *
// __ptr64,struct _xDISPATCHER_CONTEXT * __ptr64)

_s_TryBlockMapEntry *
_GetRangeOfTrysToCheck
          (__uint64 *param_1,_s_FuncInfo *param_2,int param_3,int param_4,uint *param_5,
          uint *param_6,_xDISPATCHER_CONTEXT *param_7)

{
  uint uVar1;
  longlong lVar2;
  uint uVar3;
  code *pcVar4;
  int iVar5;
  _s_TryBlockMapEntry *p_Var6;
  int *piVar7;
  uint uVar8;
  longlong lVar9;
  longlong lVar10;
  
  uVar3 = param_2->nTryBlocks;
  lVar9 = 0;
  iVar5 = FUN_18001af78((longlong)param_2,(ulonglong *)param_7);
  if (uVar3 == 0) {
    terminate();
    pcVar4 = (code *)swi(3);
    p_Var6 = (_s_TryBlockMapEntry *)(*pcVar4)();
    return p_Var6;
  }
  *param_6 = 0xffffffff;
  *param_5 = 0xffffffff;
  lVar10 = (longlong)(int)param_2->dispTryBlockMap;
  uVar8 = uVar3;
  do {
    uVar1 = uVar8 - 1;
    lVar2 = *(longlong *)(param_7 + 8) + (ulonglong)uVar1 * 0x14;
    if ((*(int *)(lVar2 + 4 + lVar10) < iVar5) && (iVar5 <= *(int *)(lVar2 + 8 + lVar10))) break;
    uVar8 = uVar1;
  } while (uVar1 != 0);
  if (uVar8 != 0) {
    lVar9 = lVar10 + (ulonglong)(uVar8 - 1) * 0x14 + *(longlong *)(param_7 + 8);
  }
  uVar8 = 0;
  if (uVar3 != 0) {
    lVar10 = 0;
    do {
      piVar7 = (int *)((longlong)(int)param_2->dispTryBlockMap + *(longlong *)(param_7 + 8) + lVar10
                      );
      if ((((lVar9 == 0) ||
           ((*piVar7 != *(int *)(lVar9 + 4) && *(int *)(lVar9 + 4) <= *piVar7 &&
            (piVar7[1] == *(int *)(lVar9 + 8) || piVar7[1] < *(int *)(lVar9 + 8))))) &&
          (*piVar7 <= param_4)) && (param_4 <= piVar7[1])) {
        if (*param_5 == 0xffffffff) {
          *param_5 = uVar8;
        }
        *param_6 = uVar8 + 1;
      }
      uVar8 = uVar8 + 1;
      lVar10 = lVar10 + 0x14;
    } while (uVar8 < uVar3);
    if (*param_5 != 0xffffffff) {
      return (_s_TryBlockMapEntry *)
             ((longlong)(int)param_2->dispTryBlockMap + (ulonglong)*param_5 * 0x14 +
             *(longlong *)(param_7 + 8));
    }
  }
  *param_5 = 0;
  *param_6 = 0;
  return (_s_TryBlockMapEntry *)0x0;
}



// Library Function - Single Match
// Name: ?__FrameUnwindToEmptyState@@YAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z
// Library: Visual Studio 2015 Release
// void __cdecl __FrameUnwindToEmptyState(unsigned __int64 * __ptr64,struct _xDISPATCHER_CONTEXT *
// __ptr64,struct _s_FuncInfo const * __ptr64)

void __FrameUnwindToEmptyState(__uint64 *param_1,_xDISPATCHER_CONTEXT *param_2,_s_FuncInfo *param_3)

{
  int iVar1;
  __uint64 *p_Var2;
  longlong lVar3;
  ulonglong uVar4;
  __uint64 local_res18 [2];
  
  p_Var2 = _GetEstablisherFrame(param_1,param_2,param_3,local_res18);
  iVar1 = FUN_18001af78((longlong)param_3,(ulonglong *)param_2);
  uVar4 = (ulonglong)param_3->nTryBlocks;
  do {
    if ((int)uVar4 == 0) {
      lVar3 = 0;
      break;
    }
    uVar4 = (ulonglong)((int)uVar4 - 1);
    lVar3 = __vcrt_getptd();
    lVar3 = (longlong)(int)param_3->dispTryBlockMap + *(longlong *)(lVar3 + 0x60) + uVar4 * 0x14;
  } while ((iVar1 <= *(int *)(lVar3 + 4)) || (*(int *)(lVar3 + 8) < iVar1));
  if (lVar3 == 0) {
    iVar1 = -1;
  }
  else {
    iVar1 = *(int *)(lVar3 + 4);
  }
  __FrameUnwindToState(p_Var2,param_2,param_3,iVar1);
  return;
}



// Library Function - Single Match
// Name: _CallSETranslator
// Library: Visual Studio 2015 Release

undefined8 _CallSETranslator(uint *param_1,undefined8 param_2,undefined8 param_3)

{
  code *pcVar1;
  longlong lVar2;
  uint *local_30;
  undefined8 local_28;
  
  local_30 = param_1;
  local_28 = param_3;
  lVar2 = __vcrt_getptd();
  pcVar1 = *(code **)(lVar2 + 0x10);
  _guard_check_icall();
  (*pcVar1)(*param_1,&local_30);
  return 0;
}



// Library Function - Single Match
// Name: _CreateFrameInfo
// Library: Visual Studio 2015 Release

undefined8 * _CreateFrameInfo(undefined8 *param_1,undefined8 param_2)

{
  longlong lVar1;
  undefined8 uVar2;
  
  *param_1 = param_2;
  lVar1 = __vcrt_getptd();
  if (param_1 < *(undefined8 **)(lVar1 + 0x58)) {
    lVar1 = __vcrt_getptd();
    uVar2 = *(undefined8 *)(lVar1 + 0x58);
  }
  else {
    uVar2 = 0;
  }
  param_1[1] = uVar2;
  lVar1 = __vcrt_getptd();
  *(undefined8 **)(lVar1 + 0x58) = param_1;
  return param_1;
}



// Library Function - Single Match
// Name: _FindAndUnlinkFrame
// Library: Visual Studio 2015 Release

void _FindAndUnlinkFrame(longlong param_1)

{
  code *pcVar1;
  longlong lVar2;
  longlong lVar3;
  
  lVar2 = __vcrt_getptd();
  if (param_1 != *(longlong *)(lVar2 + 0x58)) {
    terminate();
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  lVar2 = __vcrt_getptd();
  lVar2 = *(longlong *)(lVar2 + 0x58);
  while( true ) {
    if (lVar2 == 0) {
      terminate();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    if (param_1 == lVar2) break;
    lVar2 = *(longlong *)(lVar2 + 8);
  }
  lVar3 = __vcrt_getptd();
  *(undefined8 *)(lVar3 + 0x58) = *(undefined8 *)(lVar2 + 8);
  return;
}



// Library Function - Single Match
// Name: _GetImageBase
// Library: Visual Studio 2015 Release

undefined8 _GetImageBase(void)

{
  longlong lVar1;
  
  lVar1 = __vcrt_getptd();
  return *(undefined8 *)(lVar1 + 0x60);
}



// Library Function - Single Match
// Name: _GetThrowImageBase
// Library: Visual Studio 2015 Release

undefined8 _GetThrowImageBase(void)

{
  longlong lVar1;
  
  lVar1 = __vcrt_getptd();
  return *(undefined8 *)(lVar1 + 0x68);
}



// Library Function - Single Match
// Name: _SetImageBase
// Library: Visual Studio 2015 Release

void _SetImageBase(undefined8 param_1)

{
  longlong lVar1;
  
  lVar1 = __vcrt_getptd();
  *(undefined8 *)(lVar1 + 0x60) = param_1;
  return;
}



// Library Function - Single Match
// Name: _SetThrowImageBase
// Library: Visual Studio 2015 Release

void _SetThrowImageBase(undefined8 param_1)

{
  longlong lVar1;
  
  lVar1 = __vcrt_getptd();
  *(undefined8 *)(lVar1 + 0x68) = param_1;
  return;
}



// Library Function - Single Match
// Name: _UnwindNestedFrames
// Library: Visual Studio 2015 Release

void _UnwindNestedFrames(PVOID *param_1,ULONG_PTR param_2,ULONG_PTR param_3,ULONG_PTR param_4,
                        ULONG_PTR param_5,int param_6,ULONG_PTR param_7,PVOID *param_8,byte param_9)

{
  undefined local_588 [12];
  undefined4 uStack1404;
  undefined4 local_578;
  undefined4 uStack1396;
  DWORD DStack1392;
  undefined4 uStack1388;
  undefined *local_568;
  ULONG_PTR local_560;
  ULONG_PTR local_558;
  ULONG_PTR local_550;
  ULONG_PTR local_548;
  ULONG_PTR local_540;
  ULONG_PTR local_538;
  ulonglong local_530;
  ULONG_PTR local_528;
  undefined4 uStack1312;
  undefined4 uStack1308;
  undefined4 local_518;
  undefined4 uStack1300;
  undefined4 uStack1296;
  undefined4 uStack1292;
  undefined4 local_508;
  undefined4 uStack1284;
  undefined4 uStack1280;
  undefined4 uStack1276;
  ULONG_PTR local_4f8;
  _CONTEXT local_4e8;
  ulonglong local_18;
  
  local_18 = DAT_180037758 ^ (ulonglong)&stack0xfffffffffffffa48;
  local_588._0_4_ = 0x80000029;
  local_588._4_4_ = 1;
  local_588._8_4_ = 0;
  uStack1404 = 0;
  local_578 = 0;
  uStack1396 = 0;
  DStack1392 = 0xf;
  uStack1388 = 0;
  uStack1312 = 0;
  uStack1308 = 0;
  local_518 = 0;
  uStack1300 = 0;
  uStack1296 = 0;
  uStack1292 = 0;
  local_508 = 0;
  uStack1284 = 0;
  uStack1280 = 0;
  uStack1276 = 0;
  local_4f8 = 0;
  local_568 = &LAB_18001bc7c;
  local_558 = param_5;
  local_550 = SEXT48(param_6);
  local_540 = param_7;
  local_530 = (ulonglong)param_9;
  local_528 = 0x19930520;
  local_560 = param_4;
  local_548 = param_3;
  local_538 = param_2;
  RtlUnwindEx(*param_1,*param_8,(PEXCEPTION_RECORD)local_588,(PVOID)0x0,(PCONTEXT)&local_4e8,
              (PUNWIND_HISTORY_TABLE)param_8[8]);
  FUN_180018b70(local_18 ^ (ulonglong)&stack0xfffffffffffffa48);
  return;
}



void FUN_18001a920(int *param_1,__uint64 param_2,_CONTEXT *param_3,_xDISPATCHER_CONTEXT *param_4)

{
  longlong lVar1;
  __uint64 local_res8;
  
  local_res8 = param_2;
  lVar1 = __vcrt_getptd();
  *(undefined8 *)(lVar1 + 0x60) = *(undefined8 *)(param_4 + 8);
  lVar1 = __vcrt_getptd();
  *(undefined8 *)(lVar1 + 0x68) = *(undefined8 *)(param_1 + 0xe);
  lVar1 = __vcrt_getptd();
  FUN_18001bffc(param_1,&local_res8,param_3,param_4,
                (_s_FuncInfo *)
                ((ulonglong)**(uint **)(param_4 + 0x38) + *(longlong *)(lVar1 + 0x60)),0,
                (__uint64 *)0x0,0);
  return;
}



undefined8
FUN_18001a9a0(PEXCEPTION_RECORD param_1,PVOID param_2,undefined8 param_3,longlong *param_4)

{
  uint uVar1;
  longlong lVar2;
  uint *puVar3;
  int iVar4;
  BOOL BVar5;
  ulonglong uVar6;
  uint uVar7;
  ulonglong uVar8;
  uint uVar9;
  ulonglong uVar10;
  uint uVar11;
  ulonglong uVar12;
  PEXCEPTION_RECORD local_38;
  undefined8 local_30;
  
  FUN_18001c404();
  lVar2 = param_4[1];
  puVar3 = (uint *)param_4[7];
  uVar12 = *param_4 - lVar2;
  if ((*(byte *)&param_1->ExceptionFlags & 0x66) == 0) {
    uVar7 = *(uint *)(param_4 + 9);
    local_38 = param_1;
    local_30 = param_3;
    while (uVar7 < *puVar3) {
      uVar8 = (ulonglong)uVar7;
      if (((puVar3[uVar8 * 4 + 1] <= uVar12) && (uVar12 < puVar3[uVar8 * 4 + 2])) &&
         (puVar3[uVar8 * 4 + 4] != 0)) {
        if (puVar3[uVar8 * 4 + 3] != 1) {
          iVar4 = (*(code *)((ulonglong)puVar3[uVar8 * 4 + 3] + lVar2))(&local_38,param_2);
          if (iVar4 < 0) {
            return 0;
          }
          if (iVar4 < 1) goto LAB_18001aaba;
        }
        if ((param_1->ExceptionCode == 0xe06d7363) &&
           (BVar5 = _IsNonwritableInCurrentImage((PBYTE)&PTR___DestructExceptionObject_180032108),
           BVar5 != 0)) {
          __DestructExceptionObject((int *)param_1);
        }
        FUN_18001c3d0();
        RtlUnwindEx(param_2,(PVOID)((ulonglong)puVar3[uVar8 * 4 + 4] + lVar2),param_1,
                    (PVOID)(ulonglong)param_1->ExceptionCode,(PCONTEXT)param_4[5],
                    (PUNWIND_HISTORY_TABLE)param_4[8]);
        FUN_18001c400();
      }
LAB_18001aaba:
      uVar7 = uVar7 + 1;
    }
  }
  else {
    uVar7 = *(uint *)(param_4 + 9);
    uVar8 = param_4[4] - lVar2;
    while (uVar1 = *puVar3, uVar7 < uVar1) {
      uVar6 = (ulonglong)uVar7;
      if ((puVar3[uVar6 * 4 + 1] <= uVar12) && (uVar12 < puVar3[uVar6 * 4 + 2])) {
        uVar11 = param_1->ExceptionFlags & 0x20;
        if (uVar11 != 0) {
          uVar10 = 0;
          if (uVar1 != 0) {
            do {
              if ((((puVar3[uVar10 * 4 + 1] <= uVar8) && (uVar8 < puVar3[uVar10 * 4 + 2])) &&
                  (puVar3[uVar10 * 4 + 4] == puVar3[uVar6 * 4 + 4])) &&
                 (puVar3[uVar10 * 4 + 3] == puVar3[uVar6 * 4 + 3])) break;
              uVar9 = (int)uVar10 + 1;
              uVar10 = (ulonglong)uVar9;
            } while (uVar9 < uVar1);
          }
          if ((uint)uVar10 != uVar1) {
            return 1;
          }
        }
        if (puVar3[uVar6 * 4 + 4] == 0) {
          *(uint *)(param_4 + 9) = uVar7 + 1;
          (*(code *)((ulonglong)puVar3[uVar6 * 4 + 3] + lVar2))();
        }
        else {
          if ((uVar8 == puVar3[uVar6 * 4 + 4]) && (uVar11 != 0)) {
            return 1;
          }
        }
      }
      uVar7 = uVar7 + 1;
    }
  }
  return 1;
}



// Library Function - Single Match
// Name: __std_type_info_compare
// Library: Visual Studio 2015 Release

ulonglong __std_type_info_compare(longlong param_1,longlong param_2)

{
  byte bVar1;
  byte *pbVar2;
  longlong lVar3;
  
  if (param_1 != param_2) {
    pbVar2 = (byte *)(param_1 + 9);
    lVar3 = (param_2 + 9) - (longlong)pbVar2;
    do {
      bVar1 = *pbVar2;
      if (bVar1 != pbVar2[lVar3]) {
        return (ulonglong)(-(uint)(bVar1 < pbVar2[lVar3]) | 1);
      }
      pbVar2 = pbVar2 + 1;
    } while (bVar1 != 0);
  }
  return 0;
}



// Library Function - Single Match
// Name: __vcrt_initialize
// Library: Visual Studio 2015 Release

uint __vcrt_initialize(void)

{
  uint uVar1;
  
  __vcrt_initialize_pure_virtual_call_handler();
  FUN_18001c870();
  uVar1 = __vcrt_initialize_locks();
  if ((char)uVar1 != '\0') {
    uVar1 = __vcrt_initialize_ptd();
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    uVar1 = __vcrt_uninitialize_locks();
  }
  return uVar1 & 0xffffff00;
}



// Library Function - Single Match
// Name: __vcrt_thread_attach
// Library: Visual Studio 2015 Release

ulonglong __vcrt_thread_attach(void)

{
  LPVOID pvVar1;
  
  pvVar1 = __vcrt_getptd_noexit();
  return (ulonglong)pvVar1 & 0xffffffffffffff00 | (ulonglong)(pvVar1 != (LPVOID)0x0);
}



// Library Function - Single Match
// Name: __vcrt_thread_detach
// Library: Visual Studio 2015 Release

undefined __vcrt_thread_detach(void)

{
  __vcrt_freeptd((undefined *)0x0);
  return 1;
}



// Library Function - Single Match
// Name: __vcrt_uninitialize
// Library: Visual Studio 2015 Release

undefined __vcrt_uninitialize(char param_1)

{
  if (param_1 == '\0') {
    __vcrt_uninitialize_ptd();
    __vcrt_uninitialize_locks();
    __vcrt_uninitialize_winapi_thunks('\0');
  }
  return 1;
}



// Library Function - Single Match
// Name: __std_exception_copy
// Library: Visual Studio 2015 Release

void __std_exception_copy(char **param_1,char **param_2)

{
  longlong lVar1;
  char *_Dst;
  longlong lVar2;
  
  if ((*(char *)(param_1 + 1) == '\0') || (*param_1 == (char *)0x0)) {
    *param_2 = *param_1;
    *(undefined *)(param_2 + 1) = 0;
  }
  else {
    lVar1 = -1;
    do {
      lVar2 = lVar1;
      lVar1 = lVar2 + 1;
    } while ((*param_1)[lVar2 + 1] != '\0');
    _Dst = (char *)malloc(lVar2 + 2);
    if (_Dst != (char *)0x0) {
      strcpy_s(_Dst,lVar2 + 2,*param_1);
      *(undefined *)(param_2 + 1) = 1;
      *param_2 = _Dst;
      _Dst = (char *)0x0;
    }
    free(_Dst);
  }
  return;
}



// Library Function - Single Match
// Name: __std_exception_destroy
// Library: Visual Studio 2015 Release

void __std_exception_destroy(void **param_1)

{
  if (*(char *)(param_1 + 1) != '\0') {
    free(*param_1);
  }
  *(undefined *)(param_1 + 1) = 0;
  *param_1 = (void *)0x0;
  return;
}



void FUN_18001ad34(undefined *param_1)

{
  if ((param_1 != (undefined *)0x0) && (param_1 != &DAT_18005b340)) {
    _free_base();
  }
  return;
}



// Library Function - Single Match
// Name: __vcrt_freeptd
// Library: Visual Studio 2015 Release

void __vcrt_freeptd(undefined *param_1)

{
  if (DAT_180037780 != 0xffffffff) {
    if (param_1 == (undefined *)0x0) {
      param_1 = (undefined *)__vcrt_FlsGetValue(DAT_180037780);
    }
    __vcrt_FlsSetValue(DAT_180037780,(LPVOID)0x0);
    if ((param_1 != (undefined *)0x0) && (param_1 != &DAT_18005b340)) {
      _free_base(param_1);
    }
  }
  return;
}



// Library Function - Single Match
// Name: __vcrt_getptd
// Library: Visual Studio 2015 Release

void __vcrt_getptd(void)

{
  code *pcVar1;
  LPVOID pvVar2;
  
  pvVar2 = __vcrt_getptd_noexit();
  if (pvVar2 != (LPVOID)0x0) {
    return;
  }
  abort();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
// Name: __vcrt_getptd_noexit
// Library: Visual Studio 2015 Release

LPVOID __vcrt_getptd_noexit(void)

{
  DWORD dwErrCode;
  int iVar1;
  LPVOID pvVar2;
  LPVOID pvVar3;
  LPVOID pvVar4;
  
  if (DAT_180037780 == 0xffffffff) {
    pvVar3 = (LPVOID)0x0;
  }
  else {
    dwErrCode = GetLastError();
    pvVar2 = (LPVOID)__vcrt_FlsGetValue(DAT_180037780);
    pvVar4 = (LPVOID)0x0;
    pvVar3 = pvVar4;
    if (((pvVar2 != (LPVOID)0xffffffffffffffff) && (pvVar3 = pvVar2, pvVar2 == (LPVOID)0x0)) &&
       (iVar1 = __vcrt_FlsSetValue(DAT_180037780,(LPVOID)0xffffffffffffffff), pvVar3 = pvVar4,
       iVar1 != 0)) {
      pvVar3 = (LPVOID)_calloc_base();
      if ((pvVar3 == (LPVOID)0x0) ||
         (iVar1 = __vcrt_FlsSetValue(DAT_180037780,pvVar3), pvVar2 = pvVar4, iVar1 == 0)) {
        __vcrt_FlsSetValue(DAT_180037780,(LPVOID)0x0);
        pvVar2 = pvVar3;
        pvVar3 = pvVar4;
      }
      _free_base(pvVar2);
    }
    SetLastError(dwErrCode);
  }
  return pvVar3;
}



// Library Function - Single Match
// Name: __vcrt_initialize_ptd
// Library: Visual Studio 2015 Release

uint __vcrt_initialize_ptd(void)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = FUN_18001c694(FUN_18001ad34);
  DAT_180037780 = uVar1;
  if (uVar1 != 0xffffffff) {
    iVar2 = __vcrt_FlsSetValue(uVar1,&DAT_18005b340);
    if (iVar2 != 0) {
      return CONCAT31((int3)((uint)iVar2 >> 8),1);
    }
    uVar1 = __vcrt_uninitialize_ptd();
  }
  return uVar1 & 0xffffff00;
}



// Library Function - Single Match
// Name: __vcrt_uninitialize_ptd
// Library: Visual Studio 2015 Release

undefined __vcrt_uninitialize_ptd(void)

{
  if (DAT_180037780 != 0xffffffff) {
    __vcrt_FlsFree(DAT_180037780);
    DAT_180037780 = 0xffffffff;
  }
  return 1;
}



// Library Function - Single Match
// Name: ?__GetCurrentState@@YAHPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z
// Library: Visual Studio 2015 Release
// int __cdecl __GetCurrentState(unsigned __int64 * __ptr64,struct _xDISPATCHER_CONTEXT *
// __ptr64,struct _s_FuncInfo const * __ptr64)

int __GetCurrentState(__uint64 *param_1,_xDISPATCHER_CONTEXT *param_2,_s_FuncInfo *param_3)

{
  int iVar1;
  ulonglong uVar2;
  
  iVar1 = *(int *)((longlong)param_3->dispUnwindHelp + *param_1);
  if (iVar1 == -2) {
    uVar2 = FUN_18001af80((longlong)param_3,(longlong)param_2,*(ulonglong *)param_2);
    iVar1 = (int)uVar2;
  }
  return iVar1;
}



// Library Function - Single Match
// Name: ?__GetUnwindTryBlock@@YAHPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@@Z
// Library: Visual Studio 2015 Release
// int __cdecl __GetUnwindTryBlock(unsigned __int64 * __ptr64,struct _xDISPATCHER_CONTEXT *
// __ptr64,struct _s_FuncInfo const * __ptr64)

int __GetUnwindTryBlock(__uint64 *param_1,_xDISPATCHER_CONTEXT *param_2,_s_FuncInfo *param_3)

{
  __uint64 *p_Var1;
  __uint64 local_res18 [2];
  
  p_Var1 = _GetEstablisherFrame(param_1,param_2,param_3,local_res18);
  return *(int *)((longlong)param_3->dispUnwindHelp + 4 + *p_Var1);
}



// Library Function - Single Match
// Name: ?__SetState@@YAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z
// Library: Visual Studio 2015 Release
// void __cdecl __SetState(unsigned __int64 * __ptr64,struct _xDISPATCHER_CONTEXT * __ptr64,struct
// _s_FuncInfo const * __ptr64,int)

void __SetState(__uint64 *param_1,_xDISPATCHER_CONTEXT *param_2,_s_FuncInfo *param_3,int param_4)

{
  *(int *)((longlong)param_3->dispUnwindHelp + *param_1) = param_4;
  return;
}



// Library Function - Single Match
// Name: ?__SetUnwindTryBlock@@YAXPEA_KPEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@H@Z
// Library: Visual Studio 2015 Release
// void __cdecl __SetUnwindTryBlock(unsigned __int64 * __ptr64,struct _xDISPATCHER_CONTEXT *
// __ptr64,struct _s_FuncInfo const * __ptr64,int)

void __SetUnwindTryBlock(__uint64 *param_1,_xDISPATCHER_CONTEXT *param_2,_s_FuncInfo *param_3,
                        int param_4)

{
  __uint64 *p_Var1;
  __uint64 local_res18 [2];
  
  p_Var1 = _GetEstablisherFrame(param_1,param_2,param_3,local_res18);
  if (*(int *)((longlong)param_3->dispUnwindHelp + 4 + *p_Var1) < param_4) {
    *(int *)((longlong)param_3->dispUnwindHelp + 4 + *p_Var1) = param_4;
  }
  return;
}



void FUN_18001af78(longlong param_1,ulonglong *param_2)

{
  FUN_18001af80(param_1,(longlong)param_2,*param_2);
  return;
}



ulonglong FUN_18001af80(longlong param_1,longlong param_2,ulonglong param_3)

{
  longlong lVar1;
  code *pcVar2;
  ulonglong uVar3;
  uint uVar4;
  longlong lVar5;
  
  if (param_1 == 0) {
    terminate();
    pcVar2 = (code *)swi(3);
    uVar3 = (*pcVar2)();
    return uVar3;
  }
  lVar5 = (longlong)*(int *)(param_1 + 0x18);
  lVar1 = *(longlong *)(param_2 + 8);
  if (lVar5 + lVar1 == 0) {
    terminate();
    pcVar2 = (code *)swi(3);
    uVar3 = (*pcVar2)();
    return uVar3;
  }
  uVar3 = 0;
  if (*(uint *)(param_1 + 0x14) != 0) {
    do {
      if (param_3 < (ulonglong)*(uint *)(lVar5 + uVar3 * 8 + lVar1) + lVar1) break;
      uVar4 = (int)uVar3 + 1;
      uVar3 = (ulonglong)uVar4;
    } while (uVar4 < *(uint *)(param_1 + 0x14));
    if ((int)uVar3 != 0) {
      return (ulonglong)*(uint *)(lVar5 + (ulonglong)((int)uVar3 - 1) * 8 + 4 + lVar1);
    }
  }
  return 0xffffffff;
}



undefined8 * FUN_18001afec(undefined8 *param_1,longlong param_2)

{
  *param_1 = std::exception::vftable;
  param_1[1] = (char *)0x0;
  param_1[2] = 0;
  __std_exception_copy((char **)(param_2 + 8),(char **)(param_1 + 1));
  *param_1 = std::bad_exception::vftable;
  return param_1;
}



// Library Function - Single Match
// Name: ??0bad_exception@std@@QEAA@XZ
// Library: Visual Studio 2015 Release
// public: __cdecl std::bad_exception::bad_exception(void) __ptr64

void __thiscall std::bad_exception::bad_exception(bad_exception *this)

{
  *(undefined8 *)(this + 0x10) = 0;
  *(char **)(this + 8) = "bad exception";
  *(undefined ***)this = vftable;
  return;
}



// Library Function - Single Match
// Name: 
?CatchIt@@YAXPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@PEBU_s_HandlerType@@PEBU_s_CatchableType@@PEBU_s_TryBlockMapEntry@@H1EE@Z
// Library: Visual Studio 2015 Release
// void __cdecl CatchIt(struct EHExceptionRecord * __ptr64,unsigned __int64 * __ptr64,struct
// _CONTEXT * __ptr64,struct _xDISPATCHER_CONTEXT * __ptr64,struct _s_FuncInfo const *
// __ptr64,struct _s_HandlerType const * __ptr64,struct _s_CatchableType const * __ptr64,struct
// _s_TryBlockMapEntry const * __ptr64,int,unsigned __int64 * __ptr64,unsigned char,unsigned char)

void CatchIt(EHExceptionRecord *param_1,__uint64 *param_2,_CONTEXT *param_3,
            _xDISPATCHER_CONTEXT *param_4,_s_FuncInfo *param_5,_s_HandlerType *param_6,
            _s_CatchableType *param_7,_s_TryBlockMapEntry *param_8,int param_9,__uint64 *param_10,
            uchar param_11,uchar param_12)

{
  _s_FuncInfo *p_Var1;
  _s_HandlerType *p_Var2;
  __uint64 *p_Var3;
  longlong lVar4;
  __uint64 local_res10;
  
  p_Var1 = param_5;
  p_Var3 = _GetEstablisherFrame(param_2,param_4,param_5,&local_res10);
  p_Var2 = param_6;
  if (param_7 != (_s_CatchableType *)0x0) {
    __BuildCatchObject((longlong)param_1,(longlong *)p_Var3,(uint *)param_6,(byte *)param_7);
  }
  lVar4 = _GetImageBase();
  _UnwindNestedFrames((PVOID *)param_2,(ULONG_PTR)param_1,(ULONG_PTR)param_3,(ULONG_PTR)p_Var3,
                      lVar4 + *(int *)(p_Var2 + 0xc),*(int *)param_8,(ULONG_PTR)p_Var1,
                      (PVOID *)param_4,param_12);
  return;
}



// Library Function - Single Match
// Name: ?ExFilterRethrow@@YAHPEAU_EXCEPTION_POINTERS@@PEAUEHExceptionRecord@@PEAH@Z
// Library: Visual Studio 2015 Release
// int __cdecl ExFilterRethrow(struct _EXCEPTION_POINTERS * __ptr64,struct EHExceptionRecord *
// __ptr64,int * __ptr64)

int ExFilterRethrow(_EXCEPTION_POINTERS *param_1,EHExceptionRecord *param_2,int *param_3)

{
  PEXCEPTION_RECORD pEVar1;
  longlong lVar2;
  int iVar3;
  
  pEVar1 = param_1->ExceptionRecord;
  *param_3 = 0;
  if (pEVar1->ExceptionCode == 0xe06d7363) {
    if ((pEVar1->NumberParameters == 4) && (*(int *)pEVar1->ExceptionInformation + 0xe66cfae0U < 3))
    {
      iVar3 = *param_3;
      if (pEVar1->ExceptionInformation[1] == *(ULONG_PTR *)(param_2 + 0x28)) {
        iVar3 = 1;
      }
      *param_3 = iVar3;
    }
    if ((((pEVar1->ExceptionCode == 0xe06d7363) && (pEVar1->NumberParameters == 4)) &&
        (*(int *)pEVar1->ExceptionInformation + 0xe66cfae0U < 3)) &&
       (pEVar1->ExceptionInformation[2] == 0)) {
      lVar2 = __vcrt_getptd();
      *(undefined4 *)(lVar2 + 0x40) = 1;
      *param_3 = 1;
      return 1;
    }
  }
  return 0;
}



// Library Function - Single Match
// Name: 
?FindHandler@@YAXPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@EH1@Z
// Library: Visual Studio 2015 Release
// void __cdecl FindHandler(struct EHExceptionRecord * __ptr64,unsigned __int64 * __ptr64,struct
// _CONTEXT * __ptr64,struct _xDISPATCHER_CONTEXT * __ptr64,struct _s_FuncInfo const *
// __ptr64,unsigned char,int,unsigned __int64 * __ptr64)

void FindHandler(EHExceptionRecord *param_1,__uint64 *param_2,_CONTEXT *param_3,
                _xDISPATCHER_CONTEXT *param_4,_s_FuncInfo *param_5,uchar param_6,int param_7,
                __uint64 *param_8)

{
  code *pcVar1;
  bool bVar2;
  uchar uVar3;
  int iVar4;
  int iVar5;
  longlong lVar6;
  ulonglong uVar7;
  _s_TryBlockMapEntry *p_Var8;
  undefined8 uVar9;
  _s_ESTypeList *p_Var10;
  __uint64 *p_Var11;
  _s_ESTypeList *p_Var12;
  ulonglong uVar13;
  ulonglong uVar14;
  _s_HandlerType *p_Var15;
  int *piVar16;
  uint uVar17;
  ulonglong uVar18;
  _CONTEXT *local_res18;
  uchar local_78;
  uint local_74;
  int local_70;
  int local_6c;
  uint local_68 [2];
  int *local_60;
  _s_CatchableType *local_58;
  __uint64 local_50;
  bad_exception local_48 [32];
  
  uVar14 = 0;
  local_78 = '\0';
  bVar2 = false;
  iVar4 = FUN_18001af78((longlong)param_5,(ulonglong *)param_4);
  _GetEstablisherFrame(param_2,param_4,param_5,&local_50);
  iVar5 = __GetUnwindTryBlock(param_2,param_4,param_5);
  if (iVar5 < iVar4) {
    __SetState(&local_50,param_4,param_5,iVar4);
    __SetUnwindTryBlock(param_2,param_4,param_5,iVar4);
  }
  else {
    iVar4 = __GetUnwindTryBlock(param_2,param_4,param_5);
  }
  if ((iVar4 < -1) || (param_5->maxState <= iVar4)) {
    terminate();
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  if (*(int *)param_1 == -0x1f928c9d) {
    local_res18 = param_3;
    if (((*(int *)(param_1 + 0x18) == 4) && (*(int *)(param_1 + 0x20) + 0xe66cfae0U < 3)) &&
       (*(longlong *)(param_1 + 0x30) == 0)) {
      lVar6 = __vcrt_getptd();
      if (*(longlong *)(lVar6 + 0x20) == 0) {
        return;
      }
      lVar6 = __vcrt_getptd();
      param_1 = *(EHExceptionRecord **)(lVar6 + 0x20);
      lVar6 = __vcrt_getptd();
      local_78 = '\x01';
      local_res18 = *(_CONTEXT **)(lVar6 + 0x28);
      _SetThrowImageBase(*(undefined8 *)((longlong)param_1 + 0x38));
      if ((int *)param_1 == (int *)0x0) {
        terminate();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      if (((*(int *)param_1 == -0x1f928c9d) && (*(int *)((longlong)param_1 + 0x18) == 4)) &&
         ((*(int *)((longlong)param_1 + 0x20) + 0xe66cfae0U < 3 &&
          (*(longlong *)((longlong)param_1 + 0x30) == 0)))) {
        terminate();
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      lVar6 = __vcrt_getptd();
      if (*(longlong *)(lVar6 + 0x38) != 0) {
        lVar6 = __vcrt_getptd();
        piVar16 = *(int **)(lVar6 + 0x38);
        lVar6 = __vcrt_getptd();
        *(undefined8 *)(lVar6 + 0x38) = 0;
        uVar3 = IsInExceptionSpec(param_1,(_s_ESTypeList *)piVar16);
        if (uVar3 == '\0') {
          uVar13 = uVar14;
          uVar18 = uVar14;
          if (0 < *piVar16) {
            do {
              lVar6 = _GetImageBase();
              uVar7 = uVar14;
              if (*(int *)((longlong)piVar16[1] + 4 + lVar6 + uVar13) != 0) {
                lVar6 = _GetImageBase();
                iVar4 = *(int *)((longlong)piVar16[1] + 4 + lVar6 + uVar13);
                lVar6 = _GetImageBase();
                uVar7 = lVar6 + iVar4;
              }
              uVar7 = __std_type_info_compare(uVar7 + 8,0x180037868);
              if ((int)uVar7 == 0) {
                __DestructExceptionObject((int *)param_1);
                std::bad_exception::bad_exception(local_48);
                _CxxThrowException(local_48,(ThrowInfo *)&DAT_180034358);
                pcVar1 = (code *)swi(3);
                (*pcVar1)();
                return;
              }
              uVar17 = (int)uVar18 + 1;
              uVar13 = uVar13 + 0x14;
              uVar18 = (ulonglong)uVar17;
            } while ((int)uVar17 < *piVar16);
          }
          terminate();
          pcVar1 = (code *)swi(3);
          (*pcVar1)();
          return;
        }
      }
    }
    param_3 = local_res18;
    if (((*(int *)param_1 == -0x1f928c9d) && (*(int *)((longlong)param_1 + 0x18) == 4)) &&
       (*(int *)((longlong)param_1 + 0x20) + 0xe66cfae0U < 3)) {
      if ((param_5->nTryBlocks != 0) &&
         (p_Var8 = _GetRangeOfTrysToCheck(param_2,param_5,param_7,iVar4,&local_74,local_68,param_4),
         local_74 < local_68[0])) {
        piVar16 = (int *)(p_Var8 + 0x10);
        uVar17 = local_68[0];
        do {
          if ((piVar16[-4] == iVar4 || piVar16[-4] < iVar4) && (iVar4 <= piVar16[-3])) {
            lVar6 = _GetImageBase();
            p_Var15 = (_s_HandlerType *)(*piVar16 + lVar6);
            local_6c = piVar16[-1];
            while (uVar17 = local_68[0], 0 < local_6c) {
              lVar6 = _GetThrowImageBase();
              local_60 = (int *)(lVar6 + 4 +
                                (longlong)*(int *)(*(longlong *)((longlong)param_1 + 0x30) + 0xc));
              lVar6 = _GetThrowImageBase();
              local_70 = *(int *)(lVar6 + *(int *)(*(longlong *)((longlong)param_1 + 0x30) + 0xc));
              while (0 < local_70) {
                lVar6 = _GetThrowImageBase();
                local_58 = (_s_CatchableType *)(lVar6 + *local_60);
                uVar9 = __TypeMatch((byte *)p_Var15,(byte *)local_58,
                                    *(byte **)((longlong)param_1 + 0x30));
                if ((int)uVar9 != 0) {
                  bVar2 = true;
                  CatchIt(param_1,param_2,local_res18,param_4,param_5,p_Var15,local_58,
                          (_s_TryBlockMapEntry *)(piVar16 + -4),param_7,param_8,local_78,param_6);
                  uVar17 = local_68[0];
                  goto LAB_18001b4ef;
                }
                local_60 = local_60 + 1;
                local_70 = local_70 + -1;
              }
              local_6c = local_6c + -1;
              p_Var15 = p_Var15 + 0x14;
            }
          }
LAB_18001b4ef:
          local_74 = local_74 + 1;
          piVar16 = piVar16 + 5;
        } while (local_74 < uVar17);
        if (bVar2) goto LAB_18001b5bf;
      }
      p_Var12 = (_s_ESTypeList *)0x0;
      if (0x19930520 < (param_5->magicNumber_and_bbtFlags & 0x1fffffff)) {
        p_Var10 = p_Var12;
        if (param_5->dispESTypeList != 0) {
          lVar6 = _GetImageBase();
          p_Var10 = (_s_ESTypeList *)(lVar6 + (int)param_5->dispESTypeList);
        }
        if ((p_Var10 != (_s_ESTypeList *)0x0) ||
           (((*(byte *)&param_5->EHFlags & 4) != 0 &&
            (iVar4 = _ExecutionInCatch(param_4,param_5), iVar4 == 0)))) {
          if ((*(byte *)&param_5->EHFlags & 4) != 0) {
            terminate();
            pcVar1 = (code *)swi(3);
            (*pcVar1)();
            return;
          }
          if (param_5->dispESTypeList != 0) {
            lVar6 = _GetImageBase();
            p_Var12 = (_s_ESTypeList *)(lVar6 + (int)param_5->dispESTypeList);
          }
          uVar3 = IsInExceptionSpec(param_1,p_Var12);
          if (uVar3 == '\0') {
            p_Var11 = _GetEstablisherFrame(param_2,param_4,param_5,(__uint64 *)&local_58);
            _UnwindNestedFrames((PVOID *)param_2,(ULONG_PTR)param_1,(ULONG_PTR)local_res18,
                                (ULONG_PTR)p_Var11,0,-1,(ULONG_PTR)param_5,(PVOID *)param_4,param_6)
            ;
          }
        }
      }
      goto LAB_18001b5bf;
    }
  }
  if (param_5->nTryBlocks != 0) {
    if (param_6 != '\0') {
      terminate();
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
    FindHandlerForForeignException(param_1,param_2,param_3,param_4,param_5,iVar4,param_7,param_8);
  }
LAB_18001b5bf:
  lVar6 = __vcrt_getptd();
  if (*(longlong *)(lVar6 + 0x38) == 0) {
    return;
  }
  terminate();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
// Name: 
?FindHandlerForForeignException@@YAXPEAUEHExceptionRecord@@PEA_KPEAU_CONTEXT@@PEAU_xDISPATCHER_CONTEXT@@PEBU_s_FuncInfo@@HH1@Z
// Library: Visual Studio 2015 Release
// void __cdecl FindHandlerForForeignException(struct EHExceptionRecord * __ptr64,unsigned __int64 *
// __ptr64,struct _CONTEXT * __ptr64,struct _xDISPATCHER_CONTEXT * __ptr64,struct _s_FuncInfo const
// * __ptr64,int,int,unsigned __int64 * __ptr64)

void FindHandlerForForeignException
               (EHExceptionRecord *param_1,__uint64 *param_2,_CONTEXT *param_3,
               _xDISPATCHER_CONTEXT *param_4,_s_FuncInfo *param_5,int param_6,int param_7,
               __uint64 *param_8)

{
  int iVar1;
  code *pcVar2;
  _s_FuncInfo *p_Var3;
  int iVar4;
  int iVar5;
  longlong lVar6;
  PVOID pvVar7;
  undefined8 uVar8;
  _s_TryBlockMapEntry *p_Var9;
  int *piVar10;
  uint local_res8 [2];
  _CONTEXT *local_res18;
  uint local_48 [4];
  
  if (*(int *)param_1 != -0x7ffffffd) {
    local_res18 = param_3;
    lVar6 = __vcrt_getptd();
    iVar5 = param_7;
    p_Var3 = param_5;
    if (*(longlong *)(lVar6 + 0x10) != 0) {
      pvVar7 = EncodePointer((PVOID)0x0);
      lVar6 = __vcrt_getptd();
      if ((((*(PVOID *)(lVar6 + 0x10) != pvVar7) && (*(int *)param_1 != -0x1fbcb0b3)) &&
          (*(int *)param_1 != -0x1fbcbcae)) &&
         (uVar8 = _CallSETranslator((uint *)param_1,param_2,param_3), (int)uVar8 != 0)) {
        return;
      }
    }
    iVar4 = param_6;
    if (p_Var3->nTryBlocks == 0) {
      terminate();
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
    p_Var9 = _GetRangeOfTrysToCheck(param_2,p_Var3,iVar5,param_6,local_res8,local_48,param_4);
    if (local_res8[0] < local_48[0]) {
      piVar10 = (int *)(p_Var9 + 0xc);
      do {
        if ((piVar10[-3] <= iVar4) && (iVar4 <= piVar10[-2])) {
          lVar6 = _GetImageBase();
          if (*(int *)((longlong)piVar10[1] + 4 + lVar6 + (longlong)(*piVar10 + -1) * 0x14) == 0) {
            lVar6 = 0;
          }
          else {
            lVar6 = _GetImageBase();
            iVar1 = *(int *)((longlong)piVar10[1] + 4 + lVar6 + (longlong)(*piVar10 + -1) * 0x14);
            lVar6 = _GetImageBase();
            lVar6 = lVar6 + iVar1;
          }
          if (lVar6 != 0) {
            lVar6 = _GetImageBase();
            if (*(int *)((longlong)piVar10[1] + 4 + lVar6 + (longlong)(*piVar10 + -1) * 0x14) == 0)
            {
              lVar6 = 0;
            }
            else {
              lVar6 = _GetImageBase();
              iVar1 = *(int *)((longlong)piVar10[1] + 4 + lVar6 + (longlong)(*piVar10 + -1) * 0x14);
              lVar6 = _GetImageBase();
              lVar6 = lVar6 + iVar1;
            }
            if (*(char *)(lVar6 + 0x10) != '\0') goto LAB_18001b8b1;
          }
          lVar6 = _GetImageBase();
          if ((*(byte *)((longlong)piVar10[1] + lVar6 + (longlong)(*piVar10 + -1) * 0x14) & 0x40) ==
              0) {
            lVar6 = _GetImageBase();
            CatchIt(param_1,param_2,local_res18,param_4,p_Var3,
                    (_s_HandlerType *)
                    ((longlong)piVar10[1] + lVar6 + (longlong)(*piVar10 + -1) * 0x14),
                    (_s_CatchableType *)0x0,(_s_TryBlockMapEntry *)(piVar10 + -3),iVar5,param_8,
                    '\x01','\0');
          }
        }
LAB_18001b8b1:
        local_res8[0] = local_res8[0] + 1;
        piVar10 = piVar10 + 5;
      } while (local_res8[0] < local_48[0]);
    }
  }
  return;
}



// Library Function - Single Match
// Name: ?IsInExceptionSpec@@YAEPEAUEHExceptionRecord@@PEBU_s_ESTypeList@@@Z
// Library: Visual Studio 2015 Release
// unsigned char __cdecl IsInExceptionSpec(struct EHExceptionRecord * __ptr64,struct _s_ESTypeList
// const * __ptr64)

uchar IsInExceptionSpec(EHExceptionRecord *param_1,_s_ESTypeList *param_2)

{
  int iVar1;
  code *pcVar2;
  uchar uVar3;
  longlong lVar4;
  longlong lVar5;
  undefined8 uVar6;
  int iVar7;
  int iVar8;
  int *piVar9;
  
  if (param_2 == (_s_ESTypeList *)0x0) {
    terminate();
    pcVar2 = (code *)swi(3);
    uVar3 = (*pcVar2)();
    return uVar3;
  }
  uVar3 = '\0';
  iVar8 = 0;
  if (0 < *(int *)param_2) {
    do {
      lVar4 = _GetThrowImageBase();
      piVar9 = (int *)((longlong)*(int *)(*(longlong *)(param_1 + 0x30) + 0xc) + 4 + lVar4);
      lVar4 = _GetThrowImageBase();
      iVar7 = *(int *)(lVar4 + *(int *)(*(longlong *)(param_1 + 0x30) + 0xc));
      if (0 < iVar7) {
        do {
          lVar4 = _GetThrowImageBase();
          iVar1 = *piVar9;
          lVar5 = _GetImageBase();
          uVar6 = __TypeMatch((byte *)((longlong)*(int *)(param_2 + 4) +
                                      lVar5 + (longlong)iVar8 * 0x14),(byte *)(lVar4 + iVar1),
                              *(byte **)(param_1 + 0x30));
          if ((int)uVar6 != 0) {
            uVar3 = '\x01';
            break;
          }
          iVar7 = iVar7 + -1;
          piVar9 = piVar9 + 1;
        } while (0 < iVar7);
      }
      iVar8 = iVar8 + 1;
    } while (iVar8 < *(int *)param_2);
  }
  return uVar3;
}



void FUN_18001b9bc(undefined8 param_1,undefined *param_2,undefined8 param_3)

{
                    // WARNING: Could not recover jumptable at 0x00018001b9c2. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)param_2)(param_1,param_3);
  return;
}



// Library Function - Single Match
// Name: ?_CallMemberFunction2@@YAXPEAXP6AX0@Z0H@Z
// Library: Visual Studio 2015 Release
// void __cdecl _CallMemberFunction2(void * __ptr64,void (__cdecl*)(void * __ptr64),void *
// __ptr64,int)

void _CallMemberFunction2(void *param_1,FuncDef3 *param_2,void *param_3,int param_4)

{
                    // WARNING: Could not recover jumptable at 0x00018001b9d4. Too many branches
                    // WARNING: Treating indirect jump as call
  (*param_2)(param_1);
  return;
}



// Library Function - Single Match
// Name: __BuildCatchObject
// Library: Visual Studio 2015 Release

void __BuildCatchObject(longlong param_1,longlong *param_2,uint *param_3,byte *param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  void *pvVar3;
  FuncDef3 *pFVar4;
  longlong *plVar5;
  
  pFVar4 = (FuncDef3 *)0x0;
  plVar5 = param_2;
  if (-1 < (int)*param_3) {
    plVar5 = (longlong *)((longlong)(int)param_3[2] + *param_2);
  }
  uVar1 = __BuildCatchObjectHelper(param_1,param_2,param_3,param_4);
  if ((int)uVar1 == 1) {
    if (*(int *)(param_4 + 0x18) != 0) {
      lVar2 = _GetThrowImageBase();
      pFVar4 = (FuncDef3 *)(lVar2 + *(int *)(param_4 + 0x18));
    }
    lVar2 = __AdjustPointer(*(longlong *)(param_1 + 0x28),(int *)(param_4 + 8));
    FUN_18001b9bc(plVar5,pFVar4,lVar2);
  }
  else {
    if ((int)uVar1 == 2) {
      if (*(int *)(param_4 + 0x18) != 0) {
        lVar2 = _GetThrowImageBase();
        pFVar4 = (FuncDef3 *)(lVar2 + *(int *)(param_4 + 0x18));
      }
      pvVar3 = (void *)__AdjustPointer(*(longlong *)(param_1 + 0x28),(int *)(param_4 + 8));
      _CallMemberFunction2(plVar5,pFVar4,pvVar3,1);
    }
  }
  return;
}



// Library Function - Single Match
// Name: __BuildCatchObjectHelper
// Library: Visual Studio 2015 Release

ulonglong __BuildCatchObjectHelper(longlong param_1,longlong *param_2,uint *param_3,byte *param_4)

{
  uint uVar1;
  int iVar2;
  code *pcVar3;
  longlong lVar4;
  undefined8 *puVar5;
  longlong lVar6;
  code *pcVar7;
  
  lVar6 = 0;
  uVar1 = param_3[1];
  lVar4 = lVar6;
  if (uVar1 != 0) {
    lVar4 = _GetImageBase();
    lVar4 = (int)uVar1 + lVar4;
  }
  if (lVar4 != 0) {
    lVar4 = lVar6;
    if (uVar1 != 0) {
      lVar4 = _GetImageBase();
      lVar4 = lVar4 + (int)param_3[1];
    }
    pcVar3 = DAT_18005b338;
    if (*(char *)(lVar4 + 0x10) == '\0') {
      return 0;
    }
    if ((param_3[2] == 0) && (-1 < (int)*param_3)) {
      return 0;
    }
    uVar1 = *param_3;
    pcVar7 = (code *)(ulonglong)uVar1;
    if (-1 < (int)uVar1) {
      param_2 = (longlong *)((longlong)(int)param_3[2] + *param_2);
    }
    if ((((char)uVar1 < '\0') && ((*param_4 & 0x10) != 0)) && (DAT_18005b338 != (code *)0x0)) {
      pcVar7 = DAT_18005b338;
      _guard_check_icall();
      lVar4 = (*pcVar3)();
      if ((lVar4 != 0) && (param_2 != (longlong *)0x0)) {
        *param_2 = lVar4;
        goto LAB_18001bbb1;
      }
      terminate();
    }
    if (((ulonglong)pcVar7 & 8) != 0) {
      lVar4 = *(longlong *)(param_1 + 0x28);
      if ((lVar4 != 0) && (param_2 != (longlong *)0x0)) {
        *param_2 = lVar4;
        goto LAB_18001bbb1;
      }
      terminate();
    }
    if ((*param_4 & 1) != 0) {
      if ((*(undefined8 **)(param_1 + 0x28) != (undefined8 *)0x0) && (param_2 != (longlong *)0x0)) {
        memcpy_FUN_180019c80
                  (param_2,*(undefined8 **)(param_1 + 0x28),(longlong)*(int *)(param_4 + 0x14));
        if (*(int *)(param_4 + 0x14) != 8) {
          return 0;
        }
        if (*param_2 == 0) {
          return 0;
        }
        lVar4 = *param_2;
LAB_18001bbb1:
        lVar4 = __AdjustPointer(lVar4,(int *)(param_4 + 8));
        *param_2 = lVar4;
        return 0;
      }
      terminate();
    }
    iVar2 = *(int *)(param_4 + 0x18);
    lVar4 = lVar6;
    if (iVar2 != 0) {
      lVar4 = _GetThrowImageBase();
      lVar4 = iVar2 + lVar4;
    }
    if (lVar4 == 0) {
      if ((*(longlong *)(param_1 + 0x28) != 0) && (param_2 != (longlong *)0x0)) {
        iVar2 = *(int *)(param_4 + 0x14);
        puVar5 = (undefined8 *)__AdjustPointer(*(longlong *)(param_1 + 0x28),(int *)(param_4 + 8));
        memcpy_FUN_180019c80(param_2,puVar5,(longlong)iVar2);
        return 0;
      }
      terminate();
    }
    if ((*(longlong *)(param_1 + 0x28) != 0) && (param_2 != (longlong *)0x0)) {
      if (iVar2 != 0) {
        lVar6 = _GetThrowImageBase();
        lVar6 = lVar6 + *(int *)(param_4 + 0x18);
      }
      if (lVar6 != 0) {
        return (ulonglong)(((*param_4 & 4) != 0) + 1);
      }
    }
    terminate();
    terminate();
  }
  return 0;
}



// Library Function - Single Match
// Name: __FrameUnwindToState
// Library: Visual Studio 2015 Release

void __FrameUnwindToState
               (__uint64 *param_1,_xDISPATCHER_CONTEXT *param_2,_s_FuncInfo *param_3,int param_4)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  undefined8 uVar4;
  longlong lVar5;
  longlong lVar6;
  
  uVar4 = _GetImageBase();
  iVar3 = __GetCurrentState(param_1,param_2,param_3);
  lVar5 = __vcrt_getptd();
  *(int *)(lVar5 + 0x30) = *(int *)(lVar5 + 0x30) + 1;
  while( true ) {
    if ((iVar3 == -1) || (iVar3 <= param_4)) goto LAB_18001bfb7;
    if ((iVar3 < 0) || (param_3->maxState <= iVar3)) break;
    lVar6 = (longlong)iVar3;
    lVar5 = _GetImageBase();
    iVar3 = *(int *)((longlong)(int)param_3->dispUnwindMap + lVar5 + lVar6 * 8);
    lVar5 = _GetImageBase();
    if (*(int *)((longlong)(int)param_3->dispUnwindMap + 4 + lVar5 + lVar6 * 8) == 0) {
      lVar5 = 0;
    }
    else {
      lVar5 = _GetImageBase();
      iVar1 = *(int *)((longlong)(int)param_3->dispUnwindMap + 4 + lVar5 + lVar6 * 8);
      lVar5 = _GetImageBase();
      lVar5 = lVar5 + iVar1;
    }
    if (lVar5 != 0) {
      __SetState(param_1,param_2,param_3,iVar3);
      lVar5 = _GetImageBase();
      if (*(int *)((longlong)(int)param_3->dispUnwindMap + 4 + lVar5 + lVar6 * 8) != 0) {
        _GetImageBase();
        _GetImageBase();
      }
      _CallSettingFrame();
      _SetImageBase(uVar4);
    }
  }
  terminate();
LAB_18001bfb7:
  lVar5 = __vcrt_getptd();
  if (0 < *(int *)(lVar5 + 0x30)) {
    lVar5 = __vcrt_getptd();
    *(int *)(lVar5 + 0x30) = *(int *)(lVar5 + 0x30) + -1;
  }
  if ((iVar3 != -1) && (param_4 < iVar3)) {
    terminate();
    pcVar2 = (code *)swi(3);
    (*pcVar2)();
    return;
  }
  __SetState(param_1,param_2,param_3,iVar3);
  return;
}



undefined8
FUN_18001bffc(int *param_1,__uint64 *param_2,_CONTEXT *param_3,_xDISPATCHER_CONTEXT *param_4,
             _s_FuncInfo *param_5,int param_6,__uint64 *param_7,byte param_8)

{
  int iVar1;
  longlong lVar2;
  ulonglong uVar3;
  code *pcVar4;
  undefined8 uVar5;
  code *pcVar6;
  undefined8 in_stack_ffffffffffffffd0;
  undefined4 uVar7;
  
  uVar7 = (undefined4)((ulonglong)in_stack_ffffffffffffffd0 >> 0x20);
  FUN_18001c404();
  lVar2 = __vcrt_getptd();
  pcVar6 = (code *)0x0;
  if ((*(int *)(lVar2 + 0x40) == 0) && (*param_1 != -0x1f928c9d)) {
    if (*param_1 == -0x7fffffd7) {
      if (param_1[6] == 0xf) {
        if (*(longlong *)(param_1 + 0x18) == 0x19930520) goto LAB_18001c090;
        goto LAB_18001c079;
      }
    }
    else {
LAB_18001c079:
      if (*param_1 == -0x7fffffda) goto LAB_18001c090;
    }
    if ((0x19930521 < (param_5->magicNumber_and_bbtFlags & 0x1fffffff)) &&
       ((*(byte *)&param_5->EHFlags & 1) != 0)) {
      return 1;
    }
  }
LAB_18001c090:
  if ((*(byte *)(param_1 + 1) & 0x66) != 0) {
    if (param_5->maxState == 0) {
      return 1;
    }
    if (param_6 != 0) {
      return 1;
    }
    if ((*(byte *)(param_1 + 1) & 0x20) != 0) {
      if (*param_1 == -0x7fffffda) {
        uVar3 = FUN_18001af80((longlong)param_5,(longlong)param_4,param_3->Rip);
        iVar1 = (int)uVar3;
        if ((iVar1 < -1) || (param_5->maxState <= iVar1)) {
          terminate();
          pcVar6 = (code *)swi(3);
          uVar5 = (*pcVar6)();
          return uVar5;
        }
      }
      else {
        if (*param_1 != -0x7fffffd7) goto LAB_18001c118;
        iVar1 = param_1[0xe];
        if ((iVar1 < -1) || (param_5->maxState <= iVar1)) {
          terminate();
          pcVar6 = (code *)swi(3);
          uVar5 = (*pcVar6)();
          return uVar5;
        }
        param_2 = *(__uint64 **)(param_1 + 10);
      }
      __FrameUnwindToState(param_2,param_4,param_5,iVar1);
      return 1;
    }
LAB_18001c118:
    __FrameUnwindToEmptyState(param_2,param_4,param_5);
    return 1;
  }
  if (param_5->nTryBlocks == 0) {
    if (0x19930520 < (param_5->magicNumber_and_bbtFlags & 0x1fffffff)) {
      pcVar4 = pcVar6;
      if (param_5->dispESTypeList != 0) {
        lVar2 = _GetImageBase();
        pcVar4 = (code *)(lVar2 + (int)param_5->dispESTypeList);
      }
      if (pcVar4 != (code *)0x0) goto LAB_18001c171;
    }
    if ((param_5->magicNumber_and_bbtFlags & 0x1fffffff) < 0x19930522) {
      return 1;
    }
    if ((*(byte *)&param_5->EHFlags & 4) == 0) {
      return 1;
    }
  }
LAB_18001c171:
  if (((*param_1 == -0x1f928c9d) && (2 < (uint)param_1[6])) && (0x19930522 < (uint)param_1[8])) {
    if (*(int *)(*(longlong *)(param_1 + 0xc) + 8) != 0) {
      lVar2 = _GetThrowImageBase();
      pcVar6 = (code *)(*(int *)(*(longlong *)(param_1 + 0xc) + 8) + lVar2);
    }
    if (pcVar6 != (code *)0x0) {
      _guard_check_icall();
      uVar5 = (*pcVar6)(param_1,param_2,param_3,param_4,param_5,param_6,param_7,
                        CONCAT44(uVar7,(uint)param_8));
      return uVar5;
    }
  }
  FindHandler((EHExceptionRecord *)param_1,param_2,param_3,param_4,param_5,param_8,param_6,param_7);
  return 1;
}



// Library Function - Single Match
// Name: __TypeMatch
// Library: Visual Studio 2015 Release

undefined8 __TypeMatch(byte *param_1,byte *param_2,byte *param_3)

{
  char cVar1;
  char cVar2;
  longlong lVar3;
  longlong lVar4;
  longlong lVar5;
  char *pcVar6;
  int iVar7;
  
  iVar7 = *(int *)(param_1 + 4);
  lVar5 = 0;
  lVar3 = lVar5;
  if (iVar7 != 0) {
    lVar3 = _GetImageBase();
    lVar3 = iVar7 + lVar3;
  }
  if (lVar3 != 0) {
    lVar3 = lVar5;
    if (iVar7 != 0) {
      iVar7 = *(int *)(param_1 + 4);
      lVar3 = _GetImageBase();
      lVar3 = iVar7 + lVar3;
    }
    if ((*(char *)(lVar3 + 0x10) != '\0') && (((*param_1 & 0x80) == 0 || ((*param_2 & 0x10) == 0))))
    {
      lVar3 = lVar5;
      if (iVar7 != 0) {
        lVar3 = _GetImageBase();
        lVar3 = lVar3 + *(int *)(param_1 + 4);
      }
      lVar4 = _GetThrowImageBase();
      if (lVar3 != lVar4 + *(int *)(param_2 + 4)) {
        if (*(int *)(param_1 + 4) != 0) {
          lVar5 = _GetImageBase();
          lVar5 = lVar5 + *(int *)(param_1 + 4);
        }
        lVar3 = _GetThrowImageBase();
        pcVar6 = (char *)(lVar5 + 0x10);
        lVar3 = ((longlong)*(int *)(param_2 + 4) + 0x10 + lVar3) - (longlong)pcVar6;
        do {
          cVar1 = *pcVar6;
          cVar2 = pcVar6[lVar3];
          if (cVar1 != cVar2) break;
          pcVar6 = pcVar6 + 1;
        } while (cVar2 != '\0');
        if (cVar1 != cVar2) {
          return 0;
        }
      }
      if (((*param_2 & 2) != 0) && ((*param_1 & 8) == 0)) {
        return 0;
      }
      if (((*param_3 & 1) != 0) && ((*param_1 & 1) == 0)) {
        return 0;
      }
      if (((*param_3 & 4) != 0) && ((*param_1 & 4) == 0)) {
        return 0;
      }
      if (((*param_3 & 2) != 0) && ((*param_1 & 2) == 0)) {
        return 0;
      }
      return 1;
    }
  }
  return 1;
}



void FUN_18001c3d0(void)

{
  return;
}



void FUN_18001c400(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00018001c417)
// WARNING: Removing unreachable block (ram,0x00018001c42d)
// WARNING: Removing unreachable block (ram,0x00018001c433)

void FUN_18001c404(void)

{
  return;
}



// Library Function - Single Match
// Name: __vcrt_initialize_locks
// Library: Visual Studio 2015 Release

uint __vcrt_initialize_locks(void)

{
  int iVar1;
  uint uVar2;
  ulonglong uVar3;
  
  uVar3 = 0;
  do {
    iVar1 = __vcrt_InitializeCriticalSectionEx
                      ((LPCRITICAL_SECTION)(&DAT_18005b428 + uVar3 * 0x28),4000,0);
    if (iVar1 == 0) {
      uVar2 = __vcrt_uninitialize_locks();
      return uVar2 & 0xffffff00;
    }
    DAT_18005b450 = DAT_18005b450 + 1;
    uVar2 = (int)uVar3 + 1;
    uVar3 = (ulonglong)uVar2;
  } while (uVar2 == 0);
  return CONCAT31((int3)((uint)iVar1 >> 8),1);
}



// Library Function - Single Match
// Name: __vcrt_uninitialize_locks
// Library: Visual Studio 2015 Release

undefined8 __vcrt_uninitialize_locks(void)

{
  ulonglong uVar1;
  
  uVar1 = (ulonglong)DAT_18005b450;
  while ((int)uVar1 != 0) {
    uVar1 = (ulonglong)((int)uVar1 - 1);
    DeleteCriticalSection((LPCRITICAL_SECTION)(&DAT_18005b428 + uVar1 * 0x28));
    DAT_18005b450 = DAT_18005b450 - 1;
  }
  return 1;
}



FARPROC FUN_18001c4bc(uint param_1,LPCSTR param_2,uint *param_3,uint *param_4)

{
  wchar_t *lpLibFileName;
  HMODULE pHVar1;
  byte bVar2;
  DWORD DVar3;
  int iVar4;
  HMODULE hLibModule;
  FARPROC pFVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  
  uVar7 = (ulonglong)param_1;
  bVar2 = (byte)DAT_180037758 & 0x3f;
  pFVar5 = (FARPROC)((DAT_180037758 ^ *(ulonglong *)((longlong)&DAT_18005b470 + uVar7 * 8)) >> bVar2
                    | (DAT_180037758 ^ *(ulonglong *)((longlong)&DAT_18005b470 + uVar7 * 8)) <<
                      0x40 - bVar2);
  if (pFVar5 != (FARPROC)0xffffffffffffffff) {
    if (pFVar5 != (FARPROC)0x0) {
      return pFVar5;
    }
    if (param_3 != param_4) {
      do {
        uVar6 = (ulonglong)*param_3;
        hLibModule = *(HMODULE *)((longlong)&DAT_18005b458 + uVar6 * 8);
        if (hLibModule == (HMODULE)0x0) {
          lpLibFileName = (wchar_t *)(&PTR_u_api_ms_win_core_fibers_l1_1_1_180032ba8)[uVar6];
          hLibModule = LoadLibraryExW(lpLibFileName,(HANDLE)0x0,0x800);
          if (hLibModule == (HMODULE)0x0) {
            DVar3 = GetLastError();
            if (((DVar3 == 0x57) && (iVar4 = wcsncmp(lpLibFileName,L"api-ms-",7), iVar4 != 0)) &&
               (iVar4 = wcsncmp(lpLibFileName,L"ext-ms-",7), iVar4 != 0)) {
              hLibModule = LoadLibraryExW(lpLibFileName,(HANDLE)0x0,0);
            }
            else {
              hLibModule = (HMODULE)0x0;
            }
          }
          if (hLibModule != (HMODULE)0x0) {
            pHVar1 = *(HMODULE *)((longlong)&DAT_18005b458 + uVar6 * 8);
            *(HMODULE *)((longlong)&DAT_18005b458 + uVar6 * 8) = hLibModule;
            if (pHVar1 != (HMODULE)0x0) {
              FreeLibrary(hLibModule);
            }
            goto LAB_18001c5ee;
          }
          *(undefined8 *)((longlong)&DAT_18005b458 + uVar6 * 8) = 0xffffffffffffffff;
        }
        else {
          if (hLibModule != (HMODULE)0xffffffffffffffff) {
LAB_18001c5ee:
            if (hLibModule != (HMODULE)0x0) goto LAB_18001c609;
          }
        }
        param_3 = param_3 + 1;
      } while (param_3 != param_4);
    }
    hLibModule = (HMODULE)0x0;
LAB_18001c609:
    if ((hLibModule != (HMODULE)0x0) &&
       (pFVar5 = GetProcAddress(hLibModule,param_2), pFVar5 != (FARPROC)0x0)) {
      bVar2 = 0x40 - ((byte)DAT_180037758 & 0x3f) & 0x3f;
      *(ulonglong *)((longlong)&DAT_18005b470 + uVar7 * 8) =
           ((ulonglong)pFVar5 >> bVar2 | (longlong)pFVar5 << 0x40 - bVar2) ^ DAT_180037758;
      return pFVar5;
    }
    bVar2 = 0x40 - ((byte)DAT_180037758 & 0x3f) & 0x3f;
    *(ulonglong *)((longlong)&DAT_18005b470 + uVar7 * 8) =
         (0xffffffffffffffffU >> bVar2 | -1 << 0x40 - bVar2) ^ DAT_180037758;
  }
  return (FARPROC)0x0;
}



void FUN_18001c694(undefined8 param_1)

{
  FARPROC pFVar1;
  
  pFVar1 = FUN_18001c4bc(0,"FlsAlloc",(uint *)&DAT_180032c78,(uint *)"FlsAlloc");
  if (pFVar1 == (FARPROC)0x0) {
    TlsAlloc();
  }
  else {
    _guard_check_icall();
    (*pFVar1)(param_1);
  }
  return;
}



// Library Function - Single Match
// Name: __vcrt_FlsFree
// Library: Visual Studio 2015 Release

void __vcrt_FlsFree(uint param_1)

{
  FARPROC pFVar1;
  
  pFVar1 = FUN_18001c4bc(1,"FlsFree",(uint *)&DAT_180032c90,(uint *)"FlsFree");
  if (pFVar1 == (FARPROC)0x0) {
    TlsFree(param_1);
  }
  else {
    _guard_check_icall();
    (*pFVar1)((ulonglong)param_1);
  }
  return;
}



// Library Function - Single Match
// Name: __vcrt_FlsGetValue
// Library: Visual Studio 2015 Release

void __vcrt_FlsGetValue(uint param_1)

{
  FARPROC pFVar1;
  
  pFVar1 = FUN_18001c4bc(2,"FlsGetValue",(uint *)&DAT_180032ca0,(uint *)"FlsGetValue");
  if (pFVar1 == (FARPROC)0x0) {
    TlsGetValue(param_1);
  }
  else {
    _guard_check_icall();
    (*pFVar1)((ulonglong)param_1);
  }
  return;
}



// Library Function - Single Match
// Name: __vcrt_FlsSetValue
// Library: Visual Studio 2015 Release

void __vcrt_FlsSetValue(uint param_1,LPVOID param_2)

{
  FARPROC pFVar1;
  
  pFVar1 = FUN_18001c4bc(3,"FlsSetValue",(uint *)&DAT_180032cb8,(uint *)"FlsSetValue");
  if (pFVar1 == (FARPROC)0x0) {
    TlsSetValue(param_1,param_2);
  }
  else {
    _guard_check_icall();
    (*pFVar1)((ulonglong)param_1,param_2);
  }
  return;
}



// Library Function - Single Match
// Name: __vcrt_InitializeCriticalSectionEx
// Library: Visual Studio 2015 Release

void __vcrt_InitializeCriticalSectionEx(LPCRITICAL_SECTION param_1,uint param_2,uint param_3)

{
  FARPROC pFVar1;
  
  pFVar1 = FUN_18001c4bc(4,"InitializeCriticalSectionEx",(uint *)&DAT_180032cd0,
                         (uint *)"InitializeCriticalSectionEx");
  if (pFVar1 == (FARPROC)0x0) {
    InitializeCriticalSectionAndSpinCount(param_1,param_2);
  }
  else {
    _guard_check_icall();
    (*pFVar1)(param_1,(ulonglong)param_2,param_3);
  }
  return;
}



void FUN_18001c870(void)

{
  byte bVar1;
  ulonglong uVar2;
  longlong lVar3;
  ulonglong *puVar4;
  
  bVar1 = 0x40 - ((byte)DAT_180037758 & 0x3f) & 0x3f;
  uVar2 = ((ulonglong)(0 >> bVar1) | 0 << 0x40 - bVar1) ^ DAT_180037758;
  lVar3 = 5;
  puVar4 = &DAT_18005b470;
  while (lVar3 != 0) {
    lVar3 = lVar3 + -1;
    *puVar4 = uVar2;
    puVar4 = puVar4 + 1;
  }
  return;
}



// Library Function - Single Match
// Name: __vcrt_uninitialize_winapi_thunks
// Library: Visual Studio 2015 Release

void __vcrt_uninitialize_winapi_thunks(char param_1)

{
  HMODULE hLibModule;
  HMODULE *ppHVar1;
  
  if (param_1 == '\0') {
    ppHVar1 = (HMODULE *)&DAT_18005b458;
    do {
      hLibModule = *ppHVar1;
      if (hLibModule != (HMODULE)0x0) {
        if (hLibModule != (HMODULE)0xffffffffffffffff) {
          FreeLibrary(hLibModule);
        }
        *ppHVar1 = (HMODULE)0x0;
      }
      ppHVar1 = ppHVar1 + 1;
    } while (ppHVar1 != (HMODULE *)&DAT_18005b470);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
// Name: __vcrt_initialize_pure_virtual_call_handler
// Library: Visual Studio 2015 Release

void __vcrt_initialize_pure_virtual_call_handler(void)

{
  byte bVar1;
  
  bVar1 = 0x40 - ((byte)DAT_180037758 & 0x3f) & 0x3f;
  _DAT_18005b498 = ((ulonglong)(0 >> bVar1) | 0 << 0x40 - bVar1) ^ DAT_180037758;
  return;
}



// Library Function - Single Match
// Name: _CallSettingFrame
// Library: Visual Studio 2015 Release

void _CallSettingFrame(void)

{
  code *pcVar1;
  
  pcVar1 = (code *)FUN_18001c3d0();
  (*pcVar1)();
  FUN_18001c400();
  FUN_18001c3d0();
  return;
}



BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001c976. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}



void _invalid_parameter_noinfo(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001c97c. Too many branches
                    // WARNING: Treating indirect jump as call
  _invalid_parameter_noinfo();
  return;
}



int * _errno(void)

{
  int *piVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001c982. Too many branches
                    // WARNING: Treating indirect jump as call
  piVar1 = _errno();
  return piVar1;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001c988. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void _initterm_e(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001c98e. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm_e();
  return;
}



int _callnewh(size_t _Size)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001c994. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _callnewh(_Size);
  return iVar1;
}



void _configure_narrow_argv(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001c9a0. Too many branches
                    // WARNING: Treating indirect jump as call
  _configure_narrow_argv();
  return;
}



void _initialize_narrow_environment(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001c9a6. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_narrow_environment();
  return;
}



void _initialize_onexit_table(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001c9ac. Too many branches
                    // WARNING: Treating indirect jump as call
  _initialize_onexit_table();
  return;
}



void _cexit(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001c9b8. Too many branches
                    // WARNING: Treating indirect jump as call
  _cexit();
  return;
}



void terminate(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001c9be. Too many branches
                    // WARNING: Treating indirect jump as call
  terminate();
  return;
}



void _free_base(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001c9c4. Too many branches
                    // WARNING: Treating indirect jump as call
  _free_base();
  return;
}



errno_t strcpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  errno_t eVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001c9ca. Too many branches
                    // WARNING: Treating indirect jump as call
  eVar1 = strcpy_s(_Dst,_SizeInBytes,_Src);
  return eVar1;
}



void abort(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001c9d0. Too many branches
                    // WARNING: Treating indirect jump as call
  abort();
  return;
}



void _calloc_base(void)

{
                    // WARNING: Could not recover jumptable at 0x00018001c9d6. Too many branches
                    // WARNING: Treating indirect jump as call
  _calloc_base();
  return;
}



int wcsncmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00018001c9dc. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = wcsncmp(_Str1,_Str2,_MaxCount);
  return iVar1;
}



// Library Function - Single Match
// Name: _FindPESection
// Library: Visual Studio 2015 Release

PIMAGE_SECTION_HEADER _FindPESection(PBYTE pImageBase,DWORD_PTR rva)

{
  PIMAGE_SECTION_HEADER p_Var1;
  PBYTE pBVar2;
  uint uVar3;
  
  uVar3 = 0;
  pBVar2 = pImageBase + *(int *)(pImageBase + 0x3c);
  p_Var1 = (PIMAGE_SECTION_HEADER)(pBVar2 + (ulonglong)*(ushort *)(pBVar2 + 0x14) + 0x18);
  if (*(ushort *)(pBVar2 + 6) != 0) {
    do {
      if ((p_Var1->VirtualAddress <= rva) && (rva < p_Var1->Misc + p_Var1->VirtualAddress)) {
        return p_Var1;
      }
      uVar3 = uVar3 + 1;
      p_Var1 = p_Var1 + 1;
    } while (uVar3 < *(ushort *)(pBVar2 + 6));
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



// Library Function - Single Match
// Name: _IsNonwritableInCurrentImage
// Library: Visual Studio 2015 Release

BOOL _IsNonwritableInCurrentImage(PBYTE pTarget)

{
  uint uVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  
  uVar1 = _ValidateImageBase((PBYTE)&IMAGE_DOS_HEADER_180000000);
  p_Var2 = (PIMAGE_SECTION_HEADER)(ulonglong)uVar1;
  if (uVar1 != 0) {
    p_Var2 = _FindPESection((PBYTE)&IMAGE_DOS_HEADER_180000000,(DWORD_PTR)(pTarget + -0x180000000));
    if (p_Var2 != (PIMAGE_SECTION_HEADER)0x0) {
      p_Var2 = (PIMAGE_SECTION_HEADER)(ulonglong)(~(p_Var2->Characteristics >> 0x1f) & 1);
    }
  }
  return (BOOL)p_Var2;
}



// Library Function - Single Match
// Name: _ValidateImageBase
// Library: Visual Studio 2015 Release

BOOL _ValidateImageBase(PBYTE pImageBase)

{
  uint uVar1;
  
  if (*(short *)pImageBase != 0x5a4d) {
    return 0;
  }
  uVar1 = 0;
  if (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550) {
    uVar1 = (uint)(*(short *)((longlong)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x20b)
    ;
  }
  return (BOOL)uVar1;
}



undefined FUN_18001cac0(void)

{
  return 1;
}



void FUN_18001cbb0(undefined8 param_1,longlong param_2)

{
  __scrt_release_startup_lock(*(char *)(param_2 + 0x40));
  return;
}



void FUN_18001cbc7(undefined8 param_1,longlong param_2)

{
  FUN_1800194dc();
  __scrt_release_startup_lock(*(char *)(param_2 + 0x38));
  return;
}



void FUN_18001cbe3(uint **param_1,longlong param_2)

{
  FUN_180019448(*(undefined8 *)(param_2 + 0x60),*(int *)(param_2 + 0x68),
                *(undefined8 *)(param_2 + 0x70),FUN_180018ea0,**param_1,param_1);
  return;
}



ulonglong FUN_18001cc31(undefined8 param_1,longlong param_2)

{
  return (ulonglong)(*(char *)(param_2 + 0x38) != '\0');
}



void FUN_18001ccda(_EXCEPTION_POINTERS *param_1,longlong param_2)

{
  *(_EXCEPTION_POINTERS **)(param_2 + 0x58) = param_1;
  ExFilterRethrow(param_1,*(EHExceptionRecord **)(param_2 + 0xb8),(int *)(param_2 + 0x20));
  return;
}



void FUN_18001cd77(int **param_1)

{
  __FrameUnwindFilter(param_1);
  return;
}



// Library Function - Single Match
// Name: __FrameUnwindToState$fin$1
// Library: Visual Studio 2015 Release

void __FrameUnwindToState_fin_1(void)

{
  longlong lVar1;
  
  lVar1 = __vcrt_getptd();
  if (0 < *(int *)(lVar1 + 0x30)) {
    lVar1 = __vcrt_getptd();
    *(int *)(lVar1 + 0x30) = *(int *)(lVar1 + 0x30) + -1;
  }
  return;
}



ulonglong FUN_18001cdb0(int **param_1)

{
  return (ulonglong)(**param_1 == -0x3ffffffb);
}


