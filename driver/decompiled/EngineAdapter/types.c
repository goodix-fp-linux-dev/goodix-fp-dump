#include "funcs.c"
#include "libs.c"
#include "other.c"

typedef unsigned char undefined;

typedef unsigned long long GUID;
typedef unsigned int ImageBaseOffset32;
typedef unsigned char bool;
typedef unsigned char byte;
typedef unsigned int dword;
typedef long long longlong;
typedef unsigned long long qword;
typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned long long ulonglong;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned short ushort;
typedef short wchar_t;
typedef unsigned short word;
typedef struct _com_error _com_error, *P_com_error;

struct _com_error
{ // PlaceHolder Class Structure
};

typedef struct DName DName, *PDName;

struct DName
{ // PlaceHolder Class Structure
};

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

struct _s_HandlerType
{
  uint adjectives;
  ImageBaseOffset32 dispType;
  int dispCatchObj;
  ImageBaseOffset32 dispOfHandler;
  dword dispFrame;
};

typedef struct _s_IPToStateMapEntry _s_IPToStateMapEntry, *P_s_IPToStateMapEntry;

typedef struct _s_IPToStateMapEntry IPToStateMapEntry;

typedef int __ehstate_t;

struct _s_IPToStateMapEntry
{
  ImageBaseOffset32 Ip;
  __ehstate_t state;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct
{
  dword OffsetToDirectory;
  dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion
{
  dword OffsetToData;
  struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry
{
  __ehstate_t tryLow;
  __ehstate_t tryHigh;
  __ehstate_t catchHigh;
  int nCatches;
  ImageBaseOffset32 dispHandlerArray;
};

typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

struct _s__RTTIClassHierarchyDescriptor
{
  dword signature;
  dword attributes;                  // bit flags
  dword numBaseClasses;              // number of base classes (i.e. rtti1Count)
  ImageBaseOffset32 pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef struct<lambda_a2288fdbbd702c8f223b438290af01a4><lambda_a2288fdbbd702c8f223b438290af01a4>, *P<lambda_a2288fdbbd702c8f223b438290af01a4>;

struct<lambda_a2288fdbbd702c8f223b438290af01a4>
{ // PlaceHolder Class Structure
};

typedef struct<lambda_ee59099aa97e0ff6f003b984c1584058><lambda_ee59099aa97e0ff6f003b984c1584058>, *P<lambda_ee59099aa97e0ff6f003b984c1584058>;

struct<lambda_ee59099aa97e0ff6f003b984c1584058>
{ // PlaceHolder Class Structure
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

struct _s_FuncInfo
{
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

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

typedef struct PMD PMD, *PPMD;

struct PMD
{
  int mdisp;
  int pdisp;
  int vdisp;
};

struct _s__RTTIBaseClassDescriptor
{
  ImageBaseOffset32 pTypeDescriptor;           // ref to TypeDescriptor (RTTI 0) for class
  dword numContainedBases;                     // count of extended classes in BaseClassArray (RTTI 2)
  struct PMD where;                            // member displacement structure
  dword attributes;                            // bit flags
  ImageBaseOffset32 pClassHierarchyDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3) for class
};

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

struct _s_UnwindMapEntry
{
  __ehstate_t toState;
  ImageBaseOffset32 action;
};

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator
{
  dword signature;
  dword offset;                       // offset of vbtable within class
  dword cdOffset;                     // constructor displacement offset
  ImageBaseOffset32 pTypeDescriptor;  // ref to TypeDescriptor (RTTI 0) for class
  ImageBaseOffset32 pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef unsigned short wchar16;
typedef struct Replicator Replicator, *PReplicator;

struct Replicator
{ // PlaceHolder Class Structure
};

typedef struct UnDecorator UnDecorator, *PUnDecorator;

struct UnDecorator
{ // PlaceHolder Class Structure
};

typedef struct __crt_seh_guarded_call<void> __crt_seh_guarded_call<void>, *P__crt_seh_guarded_call<void>;

struct __crt_seh_guarded_call<void>
{ // PlaceHolder Class Structure
};

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef struct __acrt_stdio_temporary_buffering_guard __acrt_stdio_temporary_buffering_guard, *P__acrt_stdio_temporary_buffering_guard;

struct __acrt_stdio_temporary_buffering_guard
{ // PlaceHolder Class Structure
};

typedef struct<lambda_2af78c5f5901b1372d98f9ab3177dfa6><lambda_2af78c5f5901b1372d98f9ab3177dfa6>, *P<lambda_2af78c5f5901b1372d98f9ab3177dfa6>;

struct<lambda_2af78c5f5901b1372d98f9ab3177dfa6>
{ // PlaceHolder Class Structure
};

typedef struct __crt_seh_guarded_call<int> __crt_seh_guarded_call<int>, *P__crt_seh_guarded_call<int>;

struct __crt_seh_guarded_call<int>
{ // PlaceHolder Class Structure
};

typedef struct _AfxBindHost _AfxBindHost, *P_AfxBindHost;

struct _AfxBindHost
{ // PlaceHolder Class Structure
};

typedef struct __crt_seh_guarded_call<void_(__cdecl *)(int)> __crt_seh_guarded_call<void_(__cdecl *)(int)>, *P__crt_seh_guarded_call<void_(__cdecl *)(int)>;

struct __crt_seh_guarded_call<void_(__cdecl *)(int)>
{ // PlaceHolder Class Structure
};

typedef struct pcharNode pcharNode, *PpcharNode;

struct pcharNode
{ // PlaceHolder Class Structure
};

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

typedef struct _s_FuncInfo FuncInfo;

typedef ulonglong __uint64;

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor
{
  void *pVFTable;
  void *spare;
  char[0] name;
};

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef struct _variant_t _variant_t, *P_variant_t;

struct _variant_t
{ // PlaceHolder Class Structure
};

typedef struct _s_HandlerType HandlerType;

typedef struct pDNameNode pDNameNode, *PpDNameNode;

struct pDNameNode
{ // PlaceHolder Class Structure
};

typedef struct __crt_strtox __crt_strtox, *P__crt_strtox;

struct __crt_strtox
{ // PlaceHolder Class Structure
};

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uint UINT;

typedef uchar BYTE;

struct _cpinfo
{
  UINT MaxCharSize;
  BYTE DefaultChar[2];
  BYTE LeadByte[12];
};

typedef int BOOL;

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

typedef BOOL (*LOCALE_ENUMPROCW)(LPWSTR);

typedef struct _cpinfo *LPCPINFO;

typedef ulong DWORD;

typedef DWORD LCTYPE;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulonglong ULONG_PTR;

typedef union _union_538 _union_538, *P_union_538;

typedef void *HANDLE;

typedef struct _struct_539 _struct_539, *P_struct_539;

typedef void *PVOID;

struct _struct_539
{
  DWORD Offset;
  DWORD OffsetHigh;
};

union _union_538
{
  struct _struct_539 s;
  PVOID Pointer;
};

struct _OVERLAPPED
{
  ULONG_PTR Internal;
  ULONG_PTR InternalHigh;
  union _union_538 u;
  HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void *LPVOID;

struct _SECURITY_ATTRIBUTES
{
  DWORD nLength;
  LPVOID lpSecurityDescriptor;
  BOOL bInheritHandle;
};

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

typedef struct _SYSTEMTIME SYSTEMTIME;

typedef ushort WORD;

struct _SYSTEMTIME
{
  WORD wYear;
  WORD wMonth;
  WORD wDayOfWeek;
  WORD wDay;
  WORD wHour;
  WORD wMinute;
  WORD wSecond;
  WORD wMilliseconds;
};

typedef enum _FINDEX_INFO_LEVELS
{
  FindExInfoBasic = 1,
  FindExInfoMaxInfoLevel = 2,
  FindExInfoStandard = 0
} _FINDEX_INFO_LEVELS;

typedef struct _TIME_ZONE_INFORMATION _TIME_ZONE_INFORMATION, *P_TIME_ZONE_INFORMATION;

typedef struct _TIME_ZONE_INFORMATION *LPTIME_ZONE_INFORMATION;

typedef long LONG;

struct _TIME_ZONE_INFORMATION
{
  LONG Bias;
  WCHAR StandardName[32];
  SYSTEMTIME StandardDate;
  LONG StandardBias;
  WCHAR DaylightName[32];
  SYSTEMTIME DaylightDate;
  LONG DaylightBias;
};

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef BYTE *LPBYTE;

struct _STARTUPINFOW
{
  DWORD cb;
  LPWSTR lpReserved;
  LPWSTR lpDesktop;
  LPWSTR lpTitle;
  DWORD dwX;
  DWORD dwY;
  DWORD dwXSize;
  DWORD dwYSize;
  DWORD dwXCountChars;
  DWORD dwYCountChars;
  DWORD dwFillAttribute;
  DWORD dwFlags;
  WORD wShowWindow;
  WORD cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
};

typedef struct _STARTUPINFOW *LPSTARTUPINFOW;

typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

typedef char CHAR;

struct _FILETIME
{
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAA
{
  DWORD dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD nFileSizeHigh;
  DWORD nFileSizeLow;
  DWORD dwReserved0;
  DWORD dwReserved1;
  CHAR cFileName[260];
  CHAR cAlternateFileName[14];
};

typedef struct _WIN32_FIND_DATAW _WIN32_FIND_DATAW, *P_WIN32_FIND_DATAW;

typedef struct _WIN32_FIND_DATAW *LPWIN32_FIND_DATAW;

struct _WIN32_FIND_DATAW
{
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

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef enum _FINDEX_SEARCH_OPS
{
  FindExSearchMaxSearchOp = 3,
  FindExSearchLimitToDirectories = 1,
  FindExSearchNameMatch = 0,
  FindExSearchLimitToDevices = 2
} _FINDEX_SEARCH_OPS;

typedef enum _FINDEX_SEARCH_OPS FINDEX_SEARCH_OPS;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _WIN32_FIND_DATAA *LPWIN32_FIND_DATAA;

typedef enum _FINDEX_INFO_LEVELS FINDEX_INFO_LEVELS;

typedef enum _GET_FILEEX_INFO_LEVELS
{
  GetFileExMaxInfoLevel = 1,
  GetFileExInfoStandard = 0
} _GET_FILEEX_INFO_LEVELS;

typedef enum _GET_FILEEX_INFO_LEVELS GET_FILEEX_INFO_LEVELS;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION
{
  PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
  LONG LockCount;
  LONG RecursionCount;
  HANDLE OwningThread;
  HANDLE LockSemaphore;
  ULONG_PTR SpinCount;
};

struct _LIST_ENTRY
{
  struct _LIST_ENTRY *Flink;
  struct _LIST_ENTRY *Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG
{
  WORD Type;
  WORD CreatorBackTraceIndex;
  struct _RTL_CRITICAL_SECTION *CriticalSection;
  LIST_ENTRY ProcessLocksList;
  DWORD EntryCount;
  DWORD ContentionCount;
  DWORD Flags;
  WORD CreatorBackTraceIndexHigh;
  WORD SpareWORD;
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT *PCONTEXT;

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

struct _M128A
{
  ULONGLONG Low;
  LONGLONG High;
};

struct _XSAVE_FORMAT
{
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

struct _struct_53
{
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

union _union_52
{
  XMM_SAVE_AREA32 FltSave;
  struct _struct_53 s;
};

struct _CONTEXT
{
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

struct _EXCEPTION_RECORD
{
  DWORD ExceptionCode;
  DWORD ExceptionFlags;
  struct _EXCEPTION_RECORD *ExceptionRecord;
  PVOID ExceptionAddress;
  DWORD NumberParameters;
  ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS
{
  PEXCEPTION_RECORD ExceptionRecord;
  PCONTEXT ContextRecord;
};

typedef struct _SYSTEMTIME *LPSYSTEMTIME;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct IErrorInfo IErrorInfo, *PIErrorInfo;

typedef struct IErrorInfoVtbl IErrorInfoVtbl, *PIErrorInfoVtbl;

typedef long HRESULT;

// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef GUID IID;

typedef DWORD ULONG;

typedef WCHAR OLECHAR;

typedef OLECHAR *BSTR;

struct IErrorInfo
{
  struct IErrorInfoVtbl *lpVtbl;
};

struct IErrorInfoVtbl
{
  HRESULT(*QueryInterface)
  (struct IErrorInfo *, IID *, void **);
  ULONG(*AddRef)
  (struct IErrorInfo *);
  ULONG(*Release)
  (struct IErrorInfo *);
  HRESULT(*GetGUID)
  (struct IErrorInfo *, GUID *);
  HRESULT(*GetSource)
  (struct IErrorInfo *, BSTR *);
  HRESULT(*GetDescription)
  (struct IErrorInfo *, BSTR *);
  HRESULT(*GetHelpFile)
  (struct IErrorInfo *, BSTR *);
  HRESULT(*GetHelpContext)
  (struct IErrorInfo *, DWORD *);
};

typedef struct ICreateErrorInfo ICreateErrorInfo, *PICreateErrorInfo;

typedef struct ICreateErrorInfoVtbl ICreateErrorInfoVtbl, *PICreateErrorInfoVtbl;

typedef OLECHAR *LPOLESTR;

struct ICreateErrorInfo
{
  struct ICreateErrorInfoVtbl *lpVtbl;
};

struct ICreateErrorInfoVtbl
{
  HRESULT(*QueryInterface)
  (struct ICreateErrorInfo *, IID *, void **);
  ULONG(*AddRef)
  (struct ICreateErrorInfo *);
  ULONG(*Release)
  (struct ICreateErrorInfo *);
  HRESULT(*SetGUID)
  (struct ICreateErrorInfo *, GUID *);
  HRESULT(*SetSource)
  (struct ICreateErrorInfo *, LPOLESTR);
  HRESULT(*SetDescription)
  (struct ICreateErrorInfo *, LPOLESTR);
  HRESULT(*SetHelpFile)
  (struct ICreateErrorInfo *, LPOLESTR);
  HRESULT(*SetHelpContext)
  (struct ICreateErrorInfo *, DWORD);
};

typedef struct tagSOLE_AUTHENTICATION_SERVICE tagSOLE_AUTHENTICATION_SERVICE, *PtagSOLE_AUTHENTICATION_SERVICE;

typedef struct tagSOLE_AUTHENTICATION_SERVICE SOLE_AUTHENTICATION_SERVICE;

struct tagSOLE_AUTHENTICATION_SERVICE
{
  DWORD dwAuthnSvc;
  DWORD dwAuthzSvc;
  OLECHAR *pPrincipalName;
  HRESULT hr;
};

typedef enum _EXCEPTION_DISPOSITION
{
  ExceptionContinueSearch = 1,
  ExceptionNestedException = 2,
  ExceptionCollidedUnwind = 3,
  ExceptionContinueExecution = 0
} _EXCEPTION_DISPOSITION;

typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo
{
  char signature[4];
  GUID guid;
  dword age;
  char pdbname[112];
};

typedef BYTE UCHAR;

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf
{
  char *_ptr;
  int _cnt;
  char *_base;
  int _flag;
  int _file;
  int _charbuf;
  int _bufsiz;
  char *_tmpfname;
};

typedef struct _iobuf FILE;

typedef BOOL (*PHANDLER_ROUTINE)(DWORD);

typedef struct _CONSOLE_READCONSOLE_CONTROL _CONSOLE_READCONSOLE_CONTROL, *P_CONSOLE_READCONSOLE_CONTROL;

// WARNING! conflicting data type names: /WinDef.h/ULONG - /wtypes.h/ULONG

struct _CONSOLE_READCONSOLE_CONTROL
{
  ULONG nLength;
  ULONG nInitialChars;
  ULONG dwCtrlWakeupMask;
  ULONG dwControlKeyState;
};

typedef struct _CONSOLE_READCONSOLE_CONTROL *PCONSOLE_READCONSOLE_CONTROL;

typedef int PMFN;

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

struct _s_ThrowInfo
{
  uint attributes;
  PMFN pmfnUnwind;
  int pForwardCompat;
  int pCatchableTypeArray;
};

typedef struct _s_ThrowInfo ThrowInfo;

typedef char *va_list;

typedef ulonglong uintptr_t;

typedef struct lconv lconv, *Plconv;

struct lconv
{
  char *decimal_point;
  char *thousands_sep;
  char *grouping;
  char *int_curr_symbol;
  char *currency_symbol;
  char *mon_decimal_point;
  char *mon_thousands_sep;
  char *mon_grouping;
  char *positive_sign;
  char *negative_sign;
  char int_frac_digits;
  char frac_digits;
  char p_cs_precedes;
  char p_sep_by_space;
  char n_cs_precedes;
  char n_sep_by_space;
  char p_sign_posn;
  char n_sign_posn;
  wchar_t *_W_decimal_point;
  wchar_t *_W_thousands_sep;
  wchar_t *_W_int_curr_symbol;
  wchar_t *_W_currency_symbol;
  wchar_t *_W_mon_decimal_point;
  wchar_t *_W_mon_thousands_sep;
  wchar_t *_W_positive_sign;
  wchar_t *_W_negative_sign;
};

typedef ulonglong size_t;

typedef ushort wint_t;

typedef struct threadlocaleinfostruct threadlocaleinfostruct, *Pthreadlocaleinfostruct;

typedef struct threadlocaleinfostruct *pthreadlocinfo;

typedef struct localerefcount localerefcount, *Plocalerefcount;

typedef struct localerefcount locrefcount;

typedef struct __lc_time_data __lc_time_data, *P__lc_time_data;

struct localerefcount
{
  char *locale;
  wchar_t *wlocale;
  int *refcount;
  int *wrefcount;
};

struct threadlocaleinfostruct
{
  int refcount;
  uint lc_codepage;
  uint lc_collate_cp;
  uint lc_time_cp;
  locrefcount lc_category[6];
  int lc_clike;
  int mb_cur_max;
  int *lconv_intl_refcount;
  int *lconv_num_refcount;
  int *lconv_mon_refcount;
  struct lconv *lconv;
  int *ctype1_refcount;
  ushort *ctype1;
  ushort *pctype;
  uchar *pclmap;
  uchar *pcumap;
  struct __lc_time_data *lc_time_curr;
  wchar_t *locale_name[6];
};

struct __lc_time_data
{
  char *wday_abbr[7];
  char *wday[7];
  char *month_abbr[12];
  char *month[12];
  char *ampm[2];
  char *ww_sdatefmt;
  char *ww_ldatefmt;
  char *ww_timefmt;
  int ww_caltype;
  int refcount;
  wchar_t *_W_wday_abbr[7];
  wchar_t *_W_wday[7];
  wchar_t *_W_month_abbr[12];
  wchar_t *_W_month[12];
  wchar_t *_W_ampm[2];
  wchar_t *_W_ww_sdatefmt;
  wchar_t *_W_ww_ldatefmt;
  wchar_t *_W_ww_timefmt;
  wchar_t *_W_ww_locale_name;
};

typedef long __time32_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

typedef struct threadmbcinfostruct threadmbcinfostruct, *Pthreadmbcinfostruct;

typedef struct threadmbcinfostruct *pthreadmbcinfo;

struct threadmbcinfostruct
{
  int refcount;
  int mbcodepage;
  int ismbcodepage;
  ushort mbulinfo[6];
  uchar mbctype[257];
  uchar mbcasemap[256];
  wchar_t *mblocalename;
};

struct localeinfo_struct
{
  pthreadlocinfo locinfo;
  pthreadmbcinfo mbcinfo;
};

typedef int errno_t;

typedef longlong intptr_t;

typedef struct localeinfo_struct *_locale_t;

typedef longlong __time64_t;

typedef size_t rsize_t;

typedef struct exception exception, *Pexception;

struct exception
{ // PlaceHolder Class Structure
};

typedef struct _GUID _GUID, *P_GUID;

struct _GUID
{
  ulong Data1;
  ushort Data2;
  ushort Data3;
  uchar Data4[8];
};

typedef GUID *LPCGUID;

typedef void *RPC_AUTH_IDENTITY_HANDLE;

typedef struct _EVENT_DESCRIPTOR _EVENT_DESCRIPTOR, *P_EVENT_DESCRIPTOR;

typedef struct _EVENT_DESCRIPTOR EVENT_DESCRIPTOR;

typedef ushort USHORT;

struct _EVENT_DESCRIPTOR
{
  USHORT Id;
  UCHAR Version;
  UCHAR Channel;
  UCHAR Level;
  UCHAR Opcode;
  USHORT Task;
  ULONGLONG Keyword;
};

typedef struct _EVENT_DATA_DESCRIPTOR _EVENT_DATA_DESCRIPTOR, *P_EVENT_DATA_DESCRIPTOR;

struct _EVENT_DATA_DESCRIPTOR
{
  ULONGLONG Ptr;
  ULONG Size;
  ULONG Reserved;
};

typedef struct _EVENT_FILTER_DESCRIPTOR _EVENT_FILTER_DESCRIPTOR, *P_EVENT_FILTER_DESCRIPTOR;

struct _EVENT_FILTER_DESCRIPTOR
{
  ULONGLONG Ptr;
  ULONG Size;
  ULONG Type;
};

typedef struct _EVENT_FILTER_DESCRIPTOR *PEVENT_FILTER_DESCRIPTOR;

typedef void (*PENABLECALLBACK)(LPCGUID, ULONG, UCHAR, ULONGLONG, ULONGLONG, PEVENT_FILTER_DESCRIPTOR, PVOID);

typedef ULONGLONG REGHANDLE;

typedef struct _EVENT_DATA_DESCRIPTOR *PEVENT_DATA_DESCRIPTOR;

typedef ULONGLONG *PREGHANDLE;

typedef EVENT_DESCRIPTOR *PCEVENT_DESCRIPTOR;

typedef union _ULARGE_INTEGER _ULARGE_INTEGER, *P_ULARGE_INTEGER;

typedef union _ULARGE_INTEGER ULARGE_INTEGER;

typedef struct _struct_22 _struct_22, *P_struct_22;

typedef struct _struct_23 _struct_23, *P_struct_23;

struct _struct_23
{
  DWORD LowPart;
  DWORD HighPart;
};

struct _struct_22
{
  DWORD LowPart;
  DWORD HighPart;
};

union _ULARGE_INTEGER
{
  struct _struct_22 s;
  struct _struct_23 u;
  ULONGLONG QuadPart;
};

typedef PVOID PSECURITY_DESCRIPTOR;

typedef struct _struct_314 _struct_314, *P_struct_314;

struct _struct_314
{
  ULONGLONG Depth : 16;
  ULONGLONG Sequence : 48;
  ULONGLONG HeaderType : 1;
  ULONGLONG Init : 1;
  ULONGLONG Reserved : 2;
  ULONGLONG NextEntry : 60;
};

typedef struct _struct_313 _struct_313, *P_struct_313;

struct _struct_313
{
  ULONGLONG Depth : 16;
  ULONGLONG Sequence : 9;
  ULONGLONG NextEntry : 39;
  ULONGLONG HeaderType : 1;
  ULONGLONG Init : 1;
  ULONGLONG Reserved : 59;
  ULONGLONG Region : 3;
};

typedef struct _struct_312 _struct_312, *P_struct_312;

struct _struct_312
{
  ULONGLONG Alignment;
  ULONGLONG Region;
};

typedef struct _struct_315 _struct_315, *P_struct_315;

struct _struct_315
{
  ULONGLONG Depth : 16;
  ULONGLONG Sequence : 48;
  ULONGLONG HeaderType : 1;
  ULONGLONG Reserved : 3;
  ULONGLONG NextEntry : 60;
};

typedef struct _RUNTIME_FUNCTION _RUNTIME_FUNCTION, *P_RUNTIME_FUNCTION;

struct _RUNTIME_FUNCTION
{
  DWORD BeginAddress;
  DWORD EndAddress;
  DWORD UnwindData;
};

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef union _union_236 _union_236, *P_union_236;

union _union_236
{
  DWORD PhysicalAddress;
  DWORD VirtualSize;
};

struct _IMAGE_SECTION_HEADER
{
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

typedef struct _RUNTIME_FUNCTION *PRUNTIME_FUNCTION;

typedef WCHAR *PCNZWCH;

typedef struct _SLIST_ENTRY _SLIST_ENTRY, *P_SLIST_ENTRY;

typedef struct _SLIST_ENTRY *PSLIST_ENTRY;

struct _SLIST_ENTRY
{
  PSLIST_ENTRY Next;
};

typedef struct _UNWIND_HISTORY_TABLE_ENTRY _UNWIND_HISTORY_TABLE_ENTRY, *P_UNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY UNWIND_HISTORY_TABLE_ENTRY;

struct _UNWIND_HISTORY_TABLE_ENTRY
{
  DWORD64 ImageBase;
  PRUNTIME_FUNCTION FunctionEntry;
};

typedef union _union_61 _union_61, *P_union_61;

typedef ulonglong *PDWORD64;

typedef struct _struct_62 _struct_62, *P_struct_62;

struct _struct_62
{
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

union _union_61
{
  PDWORD64 IntegerContext[16];
  struct _struct_62 s;
};

typedef EXCEPTION_DISPOSITION(EXCEPTION_ROUTINE)(struct _EXCEPTION_RECORD *, PVOID, struct _CONTEXT *, PVOID);

typedef union _SLIST_HEADER _SLIST_HEADER, *P_SLIST_HEADER;

union _SLIST_HEADER
{
  struct _struct_312 s;
  struct _struct_313 Header8;
  struct _struct_314 Header16;
  struct _struct_315 HeaderX64;
};

typedef struct _struct_60 _struct_60, *P_struct_60;

typedef struct _M128A *PM128A;

struct _struct_60
{
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

struct _UNWIND_HISTORY_TABLE
{
  DWORD Count;
  BYTE LocalHint;
  BYTE GlobalHint;
  BYTE Search;
  BYTE Once;
  DWORD64 LowAddress;
  DWORD64 HighAddress;
  UNWIND_HISTORY_TABLE_ENTRY Entry[12];
};

typedef CHAR *LPCSTR;

typedef LONG *PLONG;

typedef ULARGE_INTEGER *PULARGE_INTEGER;

typedef CHAR *LPSTR;

typedef enum _SID_NAME_USE
{
  SidTypeComputer = 9,
  SidTypeUnknown = 8,
  SidTypeInvalid = 7,
  SidTypeLabel = 10,
  SidTypeWellKnownGroup = 5,
  SidTypeUser = 1,
  SidTypeAlias = 4,
  SidTypeDeletedAccount = 6,
  SidTypeDomain = 3,
  SidTypeGroup = 2
} _SID_NAME_USE;

typedef enum _SID_NAME_USE *PSID_NAME_USE;

typedef DWORD ACCESS_MASK;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

typedef union _union_59 _union_59, *P_union_59;

union _union_59
{
  PM128A FloatingContext[16];
  struct _struct_60 s;
};

struct _KNONVOLATILE_CONTEXT_POINTERS
{
  union _union_59 u;
  union _union_61 u2;
};

typedef PVOID PSID;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

struct _struct_20
{
  DWORD LowPart;
  LONG HighPart;
};

struct _struct_19
{
  DWORD LowPart;
  LONG HighPart;
};

union _LARGE_INTEGER
{
  struct _struct_19 s;
  struct _struct_20 u;
  LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER;

typedef WCHAR *LPWCH;

typedef WCHAR *LPCWSTR;

typedef struct _UNWIND_HISTORY_TABLE *PUNWIND_HISTORY_TABLE;

typedef union _SLIST_HEADER *PSLIST_HEADER;

typedef LARGE_INTEGER *PLARGE_INTEGER;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS *PKNONVOLATILE_CONTEXT_POINTERS;

typedef EXCEPTION_ROUTINE *PEXCEPTION_ROUTINE;

typedef DWORD LCID;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER
{
  char e_magic[2];     // Magic number
  word e_cblp;         // Bytes of last page
  word e_cp;           // Pages in file
  word e_crlc;         // Relocations
  word e_cparhdr;      // Size of header in paragraphs
  word e_minalloc;     // Minimum extra paragraphs needed
  word e_maxalloc;     // Maximum extra paragraphs needed
  word e_ss;           // Initial (relative) SS value
  word e_sp;           // Initial SP value
  word e_csum;         // Checksum
  word e_ip;           // Initial IP value
  word e_cs;           // Initial (relative) CS value
  word e_lfarlc;       // File address of relocation table
  word e_ovno;         // Overlay number
  word e_res[4][4];    // Reserved words
  word e_oemid;        // OEM identifier (for e_oeminfo)
  word e_oeminfo;      // OEM information; e_oemid specific
  word e_res2[10][10]; // Reserved words
  dword e_lfanew;      // File address of new exe header
  byte e_program[64];  // Actual DOS program
};

typedef struct tm tm, *Ptm;

struct tm
{
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

typedef longlong INT_PTR;

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct _FILETIME *LPFILETIME;

typedef INT_PTR (*FARPROC)(void);

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__
{
  int unused;
};

typedef DWORD *LPDWORD;

typedef WORD *LPWORD;

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__
{
  int unused;
};

typedef BOOL *LPBOOL;

typedef BYTE *PBYTE;

typedef struct HINSTANCE__ *HINSTANCE;

typedef HINSTANCE HMODULE;

typedef struct _FILETIME *PFILETIME;

typedef void *LPCVOID;

typedef HANDLE HLOCAL;

typedef struct Var Var, *PVar;

struct Var
{
  word wLength;
  word wValueLength;
  word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct
{
  dword NameOffset;
  dword NameIsString;
};

typedef struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY
{
  word Flags;
  word Catalog;
  dword CatalogOffset;
  dword Reserved;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY
{
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

struct IMAGE_FILE_HEADER
{
  word Machine; // 34404
  word NumberOfSections;
  dword TimeDateStamp;
  dword PointerToSymbolTable;
  dword NumberOfSymbols;
  word SizeOfOptionalHeader;
  word Characteristics;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_14 IMAGE_RESOURCE_DIR_STRING_U_14, *PIMAGE_RESOURCE_DIR_STRING_U_14;

struct IMAGE_RESOURCE_DIR_STRING_U_14
{
  word Length;
  wchar16 NameString[7];
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

typedef enum IMAGE_GUARD_FLAGS
{
  IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION = 8192,
  IMAGE_GUARD_CF_INSTRUMENTED = 256,
  IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION = 32768,
  IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT = 16384,
  IMAGE_GUARD_CFW_INSTRUMENTED = 512,
  IMAGE_GUARD_RF_INSTRUMENTED = 131072,
  IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4 = 1073741824,
  IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT = 65536,
  IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2 = 536870912,
  IMAGE_GUARD_PROTECT_DELAYLOAD_IAT = 4096,
  IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1 = 268435456,
  IMAGE_GUARD_SECURITY_COOKIE_UNUSED = 2048,
  IMAGE_GUARD_RF_STRICT = 524288,
  IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT = 1024,
  IMAGE_GUARD_RF_ENABLE = 262144,
  IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8 = 2147483648
} IMAGE_GUARD_FLAGS;

struct IMAGE_LOAD_CONFIG_DIRECTORY64
{
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

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo
{
  word wLength;
  word wValueLength;
  word wType;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion
{
  struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
  dword Name;
  word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY
{
  union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
  union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY
{
  ImageBaseOffset32 VirtualAddress;
  dword Size;
};

struct IMAGE_OPTIONAL_HEADER64
{
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

typedef struct StringTable StringTable, *PStringTable;

struct StringTable
{
  word wLength;
  word wValueLength;
  word wType;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags
{
  IMAGE_SCN_ALIGN_2BYTES = 2097152,
  IMAGE_SCN_ALIGN_128BYTES = 8388608,
  IMAGE_SCN_LNK_INFO = 512,
  IMAGE_SCN_ALIGN_4096BYTES = 13631488,
  IMAGE_SCN_MEM_READ = 1073741824,
  IMAGE_SCN_ALIGN_8BYTES = 4194304,
  IMAGE_SCN_ALIGN_64BYTES = 7340032,
  IMAGE_SCN_ALIGN_256BYTES = 9437184,
  IMAGE_SCN_MEM_WRITE = 2147483648,
  IMAGE_SCN_LNK_COMDAT = 4096,
  IMAGE_SCN_MEM_16BIT = 131072,
  IMAGE_SCN_ALIGN_8192BYTES = 14680064,
  IMAGE_SCN_MEM_PURGEABLE = 131072,
  IMAGE_SCN_GPREL = 32768,
  IMAGE_SCN_MEM_EXECUTE = 536870912,
  IMAGE_SCN_ALIGN_4BYTES = 3145728,
  IMAGE_SCN_LNK_OTHER = 256,
  IMAGE_SCN_MEM_PRELOAD = 524288,
  IMAGE_SCN_ALIGN_1BYTES = 1048576,
  IMAGE_SCN_MEM_NOT_PAGED = 134217728,
  IMAGE_SCN_ALIGN_1024BYTES = 11534336,
  IMAGE_SCN_RESERVED_0001 = 16,
  IMAGE_SCN_MEM_LOCKED = 262144,
  IMAGE_SCN_ALIGN_512BYTES = 10485760,
  IMAGE_SCN_CNT_INITIALIZED_DATA = 64,
  IMAGE_SCN_ALIGN_32BYTES = 6291456,
  IMAGE_SCN_MEM_DISCARDABLE = 33554432,
  IMAGE_SCN_CNT_UNINITIALIZED_DATA = 128,
  IMAGE_SCN_ALIGN_2048BYTES = 12582912,
  IMAGE_SCN_MEM_SHARED = 268435456,
  IMAGE_SCN_CNT_CODE = 32,
  IMAGE_SCN_LNK_REMOVE = 2048,
  IMAGE_SCN_ALIGN_16BYTES = 5242880,
  IMAGE_SCN_TYPE_NO_PAD = 8,
  IMAGE_SCN_LNK_NRELOC_OVFL = 16777216,
  IMAGE_SCN_RESERVED_0040 = 1024,
  IMAGE_SCN_MEM_NOT_CACHED = 67108864
} SectionFlags;

union Misc
{
  dword PhysicalAddress;
  dword VirtualSize;
};

struct IMAGE_SECTION_HEADER
{
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

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

struct IMAGE_NT_HEADERS64
{
  char Signature[4];
  struct IMAGE_FILE_HEADER FileHeader;
  struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO
{
  word StructLength;
  word ValueLength;
  word StructType;
  wchar16 Info[16];
  byte Padding[2];
  dword Signature;
  word StructVersion[2];
  word FileVersion[4];
  word ProductVersion[4];
  dword FileFlagsMask[2];
  dword FileFlags;
  dword FileOS;
  dword FileType;
  dword FileSubtype;
  dword FileTimestamp;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY
{
  dword OffsetToData;
  dword Size;
  dword CodePage;
  dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo
{
  word wLength;
  word wValueLength;
  word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY
{
  dword Characteristics;
  dword TimeDateStamp;
  word MajorVersion;
  word MinorVersion;
  word NumberOfNamedEntries;
  word NumberOfIdEntries;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT
{
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

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo
{
  word wLength;
  word wValueLength;
  word wType;
};

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef struct<lambda_1cffa78e445b1da5fba1a2e0e533226f><lambda_1cffa78e445b1da5fba1a2e0e533226f>, *P<lambda_1cffa78e445b1da5fba1a2e0e533226f>;

struct<lambda_1cffa78e445b1da5fba1a2e0e533226f>
{ // PlaceHolder Structure
};

typedef struct<lambda_8dff2cf36a5417162780cd64fa2883ef><lambda_8dff2cf36a5417162780cd64fa2883ef>, *P<lambda_8dff2cf36a5417162780cd64fa2883ef>;

struct<lambda_8dff2cf36a5417162780cd64fa2883ef>
{ // PlaceHolder Structure
};

typedef struct<lambda_3e16ef9562a7dcce91392c22ab16ea36><lambda_3e16ef9562a7dcce91392c22ab16ea36>, *P<lambda_3e16ef9562a7dcce91392c22ab16ea36>;

struct<lambda_3e16ef9562a7dcce91392c22ab16ea36>
{ // PlaceHolder Structure
};

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord
{ // PlaceHolder Structure
};

typedef enum __acrt_lock_id
{
} __acrt_lock_id;

typedef struct<lambda_c36588078e9f5dfd39652860aa6b3aaf><lambda_c36588078e9f5dfd39652860aa6b3aaf>, *P<lambda_c36588078e9f5dfd39652860aa6b3aaf>;

struct<lambda_c36588078e9f5dfd39652860aa6b3aaf>
{ // PlaceHolder Structure
};

typedef struct<lambda_7777bce6b2f8c936911f934f8298dc43><lambda_7777bce6b2f8c936911f934f8298dc43>, *P<lambda_7777bce6b2f8c936911f934f8298dc43>;

struct<lambda_7777bce6b2f8c936911f934f8298dc43>
{ // PlaceHolder Structure
};

typedef enum __acrt_fp_class
{
} __acrt_fp_class;

typedef struct<lambda_7f2adfce497ff2baa965cd4f576ecfd1><lambda_7f2adfce497ff2baa965cd4f576ecfd1>, *P<lambda_7f2adfce497ff2baa965cd4f576ecfd1>;

struct<lambda_7f2adfce497ff2baa965cd4f576ecfd1>
{ // PlaceHolder Structure
};

typedef struct<lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec><lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec>, *P<lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec>;

struct<lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec>
{ // PlaceHolder Structure
};

typedef struct<lambda_410d79af7f07d98d83a3f525b3859a53><lambda_410d79af7f07d98d83a3f525b3859a53>, *P<lambda_410d79af7f07d98d83a3f525b3859a53>;

struct<lambda_410d79af7f07d98d83a3f525b3859a53>
{ // PlaceHolder Structure
};

typedef struct __crt_locale_data __crt_locale_data, *P__crt_locale_data;

struct __crt_locale_data
{ // PlaceHolder Structure
};

typedef struct<lambda_237c231691f317818eb88cc1d5d642d6><lambda_237c231691f317818eb88cc1d5d642d6>, *P<lambda_237c231691f317818eb88cc1d5d642d6>;

struct<lambda_237c231691f317818eb88cc1d5d642d6>
{ // PlaceHolder Structure
};

typedef struct<lambda_af91936f1d075d609f72d9d8cba980af><lambda_af91936f1d075d609f72d9d8cba980af>, *P<lambda_af91936f1d075d609f72d9d8cba980af>;

struct<lambda_af91936f1d075d609f72d9d8cba980af>
{ // PlaceHolder Structure
};

typedef struct<lambda_c376a267cfb53b6959b3b692ec76b120><lambda_c376a267cfb53b6959b3b692ec76b120>, *P<lambda_c376a267cfb53b6959b3b692ec76b120>;

struct<lambda_c376a267cfb53b6959b3b692ec76b120>
{ // PlaceHolder Structure
};

typedef struct<lambda_38119f0e861e05405d8a144b9b982f0a><lambda_38119f0e861e05405d8a144b9b982f0a>, *P<lambda_38119f0e861e05405d8a144b9b982f0a>;

struct<lambda_38119f0e861e05405d8a144b9b982f0a>
{ // PlaceHolder Structure
};

typedef struct<lambda_572fbb9fa0ab338edf41edfd4b5fcc8d><lambda_572fbb9fa0ab338edf41edfd4b5fcc8d>, *P<lambda_572fbb9fa0ab338edf41edfd4b5fcc8d>;

struct<lambda_572fbb9fa0ab338edf41edfd4b5fcc8d>
{ // PlaceHolder Structure
};

typedef struct DNameNode DNameNode, *PDNameNode;

struct DNameNode
{ // PlaceHolder Structure
};

typedef struct<lambda_b521505b218e5242e90febf6bfebc422><lambda_b521505b218e5242e90febf6bfebc422>, *P<lambda_b521505b218e5242e90febf6bfebc422>;

struct<lambda_b521505b218e5242e90febf6bfebc422>
{ // PlaceHolder Structure
};

typedef enum DNameStatus
{
} DNameStatus;

typedef struct __crt_lc_time_data __crt_lc_time_data, *P__crt_lc_time_data;

struct __crt_lc_time_data
{ // PlaceHolder Structure
};

typedef struct _s_ESTypeList _s_ESTypeList, *P_s_ESTypeList;

struct _s_ESTypeList
{ // PlaceHolder Structure
};

typedef struct<lambda_f03950bc5685219e0bcd2087efbe011e><lambda_f03950bc5685219e0bcd2087efbe011e>, *P<lambda_f03950bc5685219e0bcd2087efbe011e>;

struct<lambda_f03950bc5685219e0bcd2087efbe011e>
{ // PlaceHolder Structure
};

typedef struct<lambda_c5860995281e5c4ce005b3de8f5874ee><lambda_c5860995281e5c4ce005b3de8f5874ee>, *P<lambda_c5860995281e5c4ce005b3de8f5874ee>;

struct<lambda_c5860995281e5c4ce005b3de8f5874ee>
{ // PlaceHolder Structure
};

typedef struct<lambda_842d9ff0dc9ef11c61343bbaebe7f885><lambda_842d9ff0dc9ef11c61343bbaebe7f885>, *P<lambda_842d9ff0dc9ef11c61343bbaebe7f885>;

struct<lambda_842d9ff0dc9ef11c61343bbaebe7f885>
{ // PlaceHolder Structure
};

typedef struct<lambda_77b15b24eaa4cf6d702b2f4e7ca8df95><lambda_77b15b24eaa4cf6d702b2f4e7ca8df95>, *P<lambda_77b15b24eaa4cf6d702b2f4e7ca8df95>;

struct<lambda_77b15b24eaa4cf6d702b2f4e7ca8df95>
{ // PlaceHolder Structure
};

typedef struct<lambda_2a444430fde8c29194d880d93eed5e8f><lambda_2a444430fde8c29194d880d93eed5e8f>, *P<lambda_2a444430fde8c29194d880d93eed5e8f>;

struct<lambda_2a444430fde8c29194d880d93eed5e8f>
{ // PlaceHolder Structure
};

typedef struct<lambda_e82fa975f615b5c7c7b0e4d178fdae67><lambda_e82fa975f615b5c7c7b0e4d178fdae67>, *P<lambda_e82fa975f615b5c7c7b0e4d178fdae67>;

struct<lambda_e82fa975f615b5c7c7b0e4d178fdae67>
{ // PlaceHolder Structure
};

typedef struct _xDISPATCHER_CONTEXT _xDISPATCHER_CONTEXT, *P_xDISPATCHER_CONTEXT;

struct _xDISPATCHER_CONTEXT
{ // PlaceHolder Structure
};

typedef struct<lambda_3883c3dff614d5e0c5f61bb1ac94921c><lambda_3883c3dff614d5e0c5f61bb1ac94921c>, *P<lambda_3883c3dff614d5e0c5f61bb1ac94921c>;

struct<lambda_3883c3dff614d5e0c5f61bb1ac94921c>
{ // PlaceHolder Structure
};

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

struct _s_CatchableType
{ // PlaceHolder Structure
};

typedef struct<lambda_d67e8342c384adda8f857579ab50b2ae><lambda_d67e8342c384adda8f857579ab50b2ae>, *P<lambda_d67e8342c384adda8f857579ab50b2ae>;

struct<lambda_d67e8342c384adda8f857579ab50b2ae>
{ // PlaceHolder Structure
};

typedef struct<lambda_630b2aca97f6d20d5b5ea6529ea6b6af><lambda_630b2aca97f6d20d5b5ea6529ea6b6af>, *P<lambda_630b2aca97f6d20d5b5ea6529ea6b6af>;

struct<lambda_630b2aca97f6d20d5b5ea6529ea6b6af>
{ // PlaceHolder Structure
};

typedef struct<lambda_314360699dd331753a4119843814e9a7><lambda_314360699dd331753a4119843814e9a7>, *P<lambda_314360699dd331753a4119843814e9a7>;

struct<lambda_314360699dd331753a4119843814e9a7>
{ // PlaceHolder Structure
};

typedef struct _timespec32 _timespec32, *P_timespec32;

struct _timespec32
{ // PlaceHolder Structure
};

typedef struct<lambda_702c71755a341b84ce26a812eea27a9e><lambda_702c71755a341b84ce26a812eea27a9e>, *P<lambda_702c71755a341b84ce26a812eea27a9e>;

struct<lambda_702c71755a341b84ce26a812eea27a9e>
{ // PlaceHolder Structure
};

typedef struct __crt_stdio_stream __crt_stdio_stream, *P__crt_stdio_stream;

struct __crt_stdio_stream
{ // PlaceHolder Structure
};

typedef struct<lambda_6978c1fb23f02e42e1d9e99668cc68aa><lambda_6978c1fb23f02e42e1d9e99668cc68aa>, *P<lambda_6978c1fb23f02e42e1d9e99668cc68aa>;

struct<lambda_6978c1fb23f02e42e1d9e99668cc68aa>
{ // PlaceHolder Structure
};

typedef struct __crt_multibyte_data __crt_multibyte_data, *P__crt_multibyte_data;

struct __crt_multibyte_data
{ // PlaceHolder Structure
};

typedef struct tagEXCEPINFO tagEXCEPINFO, *PtagEXCEPINFO;

struct tagEXCEPINFO
{ // PlaceHolder Structure
};

typedef struct<lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0><lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0>, *P<lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0>;

struct<lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0>
{ // PlaceHolder Structure
};

// WARNING! conflicting data type names: /Demangler/wchar_t - /wchar_t

typedef struct __acrt_ptd __acrt_ptd, *P__acrt_ptd;

struct __acrt_ptd
{ // PlaceHolder Structure
};

typedef struct<lambda_dc9d2797ccde5d239b4a0efae8ebd7db><lambda_dc9d2797ccde5d239b4a0efae8ebd7db>, *P<lambda_dc9d2797ccde5d239b4a0efae8ebd7db>;

struct<lambda_dc9d2797ccde5d239b4a0efae8ebd7db>
{ // PlaceHolder Structure
};

typedef struct<lambda_9a32fed5bf61b6b509b2d3f6003082a1><lambda_9a32fed5bf61b6b509b2d3f6003082a1>, *P<lambda_9a32fed5bf61b6b509b2d3f6003082a1>;

struct<lambda_9a32fed5bf61b6b509b2d3f6003082a1>
{ // PlaceHolder Structure
};

typedef struct<lambda_30712929f77e709619002f448b6a9510><lambda_30712929f77e709619002f448b6a9510>, *P<lambda_30712929f77e709619002f448b6a9510>;

struct<lambda_30712929f77e709619002f448b6a9510>
{ // PlaceHolder Structure
};

typedef struct __crt_deferred_errno_cache __crt_deferred_errno_cache, *P__crt_deferred_errno_cache;

struct __crt_deferred_errno_cache
{ // PlaceHolder Structure
};

typedef struct IDispatch IDispatch, *PIDispatch;

struct IDispatch
{ // PlaceHolder Structure
};

typedef struct __crt_locale_pointers __crt_locale_pointers, *P__crt_locale_pointers;

struct __crt_locale_pointers
{ // PlaceHolder Structure
};

typedef struct<lambda_4525336fd7e478d965fb7ca7a337cad8><lambda_4525336fd7e478d965fb7ca7a337cad8>, *P<lambda_4525336fd7e478d965fb7ca7a337cad8>;

struct<lambda_4525336fd7e478d965fb7ca7a337cad8>
{ // PlaceHolder Structure
};

typedef struct<lambda_ec61778202f4f5fc7e7711acc23c3bca><lambda_ec61778202f4f5fc7e7711acc23c3bca>, *P<lambda_ec61778202f4f5fc7e7711acc23c3bca>;

struct<lambda_ec61778202f4f5fc7e7711acc23c3bca>
{ // PlaceHolder Structure
};

typedef struct _timespec64 _timespec64, *P_timespec64;

struct _timespec64
{ // PlaceHolder Structure
};

typedef struct<lambda_d90129c13df834fdcbf8d2b88dafcf2d><lambda_d90129c13df834fdcbf8d2b88dafcf2d>, *P<lambda_d90129c13df834fdcbf8d2b88dafcf2d>;

struct<lambda_d90129c13df834fdcbf8d2b88dafcf2d>
{ // PlaceHolder Structure
};

typedef struct _strflt _strflt, *P_strflt;

struct _strflt
{ // PlaceHolder Structure
};

typedef enum module_id
{
} module_id;

typedef enum length_modifier
{
} length_modifier;

typedef struct string_output_adapter<char> string_output_adapter<char>, *Pstring_output_adapter<char>;

struct string_output_adapter<char>
{ // PlaceHolder Structure
};

typedef struct string_output_adapter<wchar_t> string_output_adapter<wchar_t>, *Pstring_output_adapter<wchar_t>;

struct string_output_adapter<wchar_t>
{ // PlaceHolder Structure
};

typedef enum function_id
{
} function_id;

typedef struct big_integer big_integer, *Pbig_integer;

struct big_integer
{ // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);

typedef struct IUnknownVtbl IUnknownVtbl, *PIUnknownVtbl;

typedef struct IUnknown IUnknown, *PIUnknown;

struct IUnknownVtbl
{
  HRESULT(*QueryInterface)
  (struct IUnknown *, IID *, void **);
  ULONG(*AddRef)
  (struct IUnknown *);
  ULONG(*Release)
  (struct IUnknown *);
};

struct IUnknown
{
  struct IUnknownVtbl *lpVtbl;
};

typedef struct IUnknown *LPUNKNOWN;
