#include "funcs.c"
#include "other.c"
#include "types.c"

// Library Function - Multiple Matches With Different Base Names
//  _snprintf_s
//  _snwprintf_s
//
// Library: Visual Studio 2019 Debug

int FID_conflict__snprintf_s(wchar_t *_DstBuf, size_t _SizeInWords, size_t _MaxCount, wchar_t *_Format, ...)
{
  int iVar1;

  iVar1 = FUN_18000b650((char *)_DstBuf, _SizeInWords, _MaxCount, (char *)_Format,
                        (__crt_locale_pointers *)0x0, &stack0x00000028);
  return iVar1;
}

// Library Function - Multiple Matches With Different Base Names
//  _snprintf_s
//  _snwprintf_s
//
// Library: Visual Studio 2019 Debug

int FID_conflict__snprintf_s(wchar_t *_DstBuf, size_t _SizeInWords, size_t _MaxCount, wchar_t *_Format, ...)
{
  int iVar1;

  iVar1 = _vsnprintf_s_l((char *)_DstBuf, _SizeInWords, _MaxCount, (char *)_Format, (_locale_t)0x0,
                         &stack0x00000028);
  return iVar1;
}

// Library Function - Single Match
//  _vsnprintf_s_l
//
// Library: Visual Studio 2019 Debug

int _vsnprintf_s_l(char *_DstBuf, size_t _DstSize, size_t _MaxCount, char *_Format, _locale_t _Locale,
                   va_list _ArgList)
{
  __uint64 *p_Var1;
  int local_14;

  p_Var1 = (__uint64 *)FUN_180005100();
  local_14 = __stdio_common_vsnwprintf_s(*p_Var1, (undefined2 *)_DstBuf, _DstSize, _MaxCount, (wchar_t *)_Format,
                                         (__crt_locale_pointers *)_Locale, _ArgList);
  if (local_14 < 0)
  {
    local_14 = -1;
  }
  return local_14;
}

// Library Function - Single Match
//  _vsprintf_l
//
// Library: Visual Studio 2019 Release

int _vsprintf_l(char *_DstBuf, char *_Format, _locale_t param_3, va_list _ArgList)
{
  int iVar1;

  iVar1 = FUN_180010ba0((wchar_t *)_DstBuf, 0xffffffffffffffff, (wchar_t *)_Format, param_3, _ArgList);
  return iVar1;
}

// Library Function - Single Match
//  sprintf
//
// Library: Visual Studio 2019 Release

int sprintf(char *_Dest, char *_Format, ...)
{
  int iVar1;
  undefined8 in_R8;
  undefined8 in_R9;
  undefined8 local_res18;
  undefined8 local_res20;

  local_res18 = in_R8;
  local_res20 = in_R9;
  iVar1 = _vsprintf_l(_Dest, _Format, (_locale_t)0x0, (va_list)&local_res18);
  return iVar1;
}

// Library Function - Multiple Matches With Different Base Names
//  _vsprintf_s_l
//  _vswprintf_c_l
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release, Visual Studio 2017 Debug

int FID_conflict__vsprintf_s_l(wchar_t *_DstBuf, size_t _MaxCount, wchar_t *_Format, _locale_t _Locale, va_list _ArgList)
{
  ulonglong *puVar1;
  int local_14;

  puVar1 = (ulonglong *)FUN_180005100();
  local_14 = common_vsprintf__(*puVar1, _DstBuf, _MaxCount, (longlong)_Format, (undefined4 *)_Locale,
                               _ArgList);
  if (local_14 < 0)
  {
    local_14 = -1;
  }
  return local_14;
}

// Library Function - Multiple Matches With Different Base Names
//  _vsprintf_s_l
//  _vswprintf_c_l
//
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

int FID_conflict__vsprintf_s_l(wchar_t *_DstBuf, size_t _MaxCount, wchar_t *_Format, _locale_t _Locale, va_list _ArgList)
{
  __uint64 *p_Var1;
  int local_14;

  p_Var1 = (__uint64 *)FUN_180005100();
  local_14 = __stdio_common_vswprintf_s(*p_Var1, _DstBuf, _MaxCount, (wchar_t *)_Format,
                                        (__crt_locale_pointers *)_Locale, _ArgList);
  if (local_14 < 0)
  {
    local_14 = -1;
  }
  return local_14;
}

// Library Function - Multiple Matches With Different Base Names
//  sprintf_s
//  swprintf
//
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

int FID_conflict_sprintf_s(char *_DstBuf, size_t _SizeInBytes, char *_Format, ...)
{
  int iVar1;
  undefined8 in_R9;
  undefined8 local_res20;

  local_res20 = in_R9;
  iVar1 = FID_conflict__vsprintf_s_l((wchar_t *)_DstBuf, _SizeInBytes, (wchar_t *)_Format, (_locale_t)0x0,
                                     (va_list)&local_res20);
  return iVar1;
}

// Library Function - Single Match
//  _vfwprintf_l
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int _vfwprintf_l(FILE *_File, wchar_t *_Format, _locale_t _Locale, va_list _ArgList)
{
  int iVar1;
  undefined8 *puVar2;

  puVar2 = (undefined8 *)FUN_180005100();
  iVar1 = __stdio_common_vfwprintf(*puVar2, (longlong)_File, (longlong)_Format, _Locale, _ArgList);
  return iVar1;
}

// Library Function - Multiple Matches With Different Base Names
//  _vsnprintf_s
//  _vsnwprintf_s
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2017 Debug, Visual Studio 2019 Debug

int FID_conflict__vsnwprintf_s(char *_DstBuf, size_t _SizeInBytes, size_t _MaxCount, char *_Format, va_list _ArgList)
{
  int iVar1;

  iVar1 = _vsnprintf_s_l(_DstBuf, _SizeInBytes, _MaxCount, _Format, (_locale_t)0x0, _ArgList);
  return iVar1;
}

// Library Function - Single Match
//  printf
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2017 Debug, Visual Studio 2019 Debug

int printf(char *_Format, ...)
{
  int iVar1;
  FILE *_File;
  undefined8 in_RDX;
  undefined8 in_R8;
  undefined8 in_R9;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 local_res20;

  local_res10 = in_RDX;
  local_res18 = in_R8;
  local_res20 = in_R9;
  _File = (FILE *)__acrt_iob_func(1);
  iVar1 = _vfwprintf_l(_File, (wchar_t *)_Format, (_locale_t)0x0, (va_list)&local_res10);
  return iVar1;
}

// Library Function - Single Match
//  HRESULT_FROM_WIN32
//
// Library: Visual Studio

HRESULT HRESULT_FROM_WIN32(ulong x)
{
  ulong local_18;

  local_18 = x;
  if (0 < (int)x)
  {
    local_18 = x & 0xffff | 0x80070000;
  }
  return (HRESULT)local_18;
}

// Library Function - Single Match
//  public: virtual unsigned long __cdecl _AfxBindHost::Release(void) __ptr64
//
// Library: Visual Studio 2010 Debug

ulong __thiscall _AfxBindHost::Release(_AfxBindHost *this)
{
  int iVar1;
  int *piVar2;

  piVar2 = (int *)(this + 0x10);
  LOCK();
  iVar1 = *piVar2;
  *piVar2 = *piVar2 + -1;
  if ((iVar1 - 1U == 0) && (this != (_AfxBindHost *)0x0))
  {
    FUN_1800296d0((longlong *)this, 1);
  }
  return iVar1 - 1U;
}

// Library Function - Multiple Matches With Different Base Names
//  sprintf_s
//  swprintf
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release, Visual Studio 2017 Debug

int FID_conflict_sprintf_s(char *_DstBuf, size_t _SizeInBytes, char *_Format, ...)
{
  int iVar1;
  undefined8 in_R9;
  undefined8 local_res20;

  local_res20 = in_R9;
  FUN_180029440();
  iVar1 = FID_conflict__vsprintf_s_l((wchar_t *)_DstBuf, _SizeInBytes, (wchar_t *)_Format, (_locale_t)0x0,
                                     (va_list)&local_res20);
  return iVar1;
}

// Library Function - Single Match
//  __raise_securityfailure
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __raise_securityfailure(_EXCEPTION_POINTERS *param_1)
{
  HANDLE hProcess;

  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter(param_1);
  hProcess = GetCurrentProcess();
  // WARNING: Could not recover jumptable at 0x0001800348ed. Too many branches
  // WARNING: Treating indirect jump as call
  TerminateProcess(hProcess, 0xc0000409);
  return;
}

// Library Function - Single Match
//  __report_rangecheckfailure
//
// Libraries: Visual Studio 2012, Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

void __report_rangecheckfailure(void)
{
  __report_securityfailure(8);
  return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __report_securityfailure
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __report_securityfailure(undefined4 param_1)
{
  code *pcVar1;
  BOOL BVar2;
  undefined *puVar3;
  undefined auStack40[8];
  undefined auStack32[32];

  puVar3 = auStack40;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0)
  {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(param_1);
    puVar3 = auStack32;
  }
  *(undefined8 *)(puVar3 + -8) = 0x180034a06;
  capture_current_context((PCONTEXT)&DAT_180101250, puVar3[-8]);
  _DAT_1801011c0 = *(undefined8 *)(puVar3 + 0x28);
  _DAT_1801012e8 = puVar3 + 0x30;
  _DAT_1801011b0 = 0xc0000409;
  _DAT_1801011b4 = 1;
  _DAT_1801011c8 = 1;
  DAT_1801011d0 = (ulonglong) * (uint *)(puVar3 + 0x30);
  *(undefined8 *)(puVar3 + -8) = 0x180034a72;
  DAT_180101348 = _DAT_1801011c0;
  __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_1800c8998, puVar3[-8]);
  return;
}

// Library Function - Single Match
//  capture_current_context
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void capture_current_context(PCONTEXT param_1)
{
  DWORD64 ControlPc;
  PRUNTIME_FUNCTION FunctionEntry;
  DWORD64 local_res8;
  ulonglong local_res10;
  PVOID local_res18;

  RtlCaptureContext();
  ControlPc = param_1->Rip;
  FunctionEntry = RtlLookupFunctionEntry(ControlPc, &local_res8, (PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0)
  {
    RtlVirtualUnwind(0, local_res8, ControlPc, FunctionEntry, param_1, &local_res18, &local_res10,
                     (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
  }
  return;
}

// Library Function - Single Match
//  capture_previous_context
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void capture_previous_context(PCONTEXT param_1)
{
  DWORD64 ControlPc;
  PRUNTIME_FUNCTION FunctionEntry;
  int iVar1;
  DWORD64 local_res8;
  ulonglong local_res10;
  PVOID local_res18[2];

  RtlCaptureContext();
  ControlPc = param_1->Rip;
  iVar1 = 0;
  do
  {
    FunctionEntry = RtlLookupFunctionEntry(ControlPc, &local_res8, (PUNWIND_HISTORY_TABLE)0x0);
    if (FunctionEntry == (PRUNTIME_FUNCTION)0x0)
    {
      return;
    }
    RtlVirtualUnwind(0, local_res8, ControlPc, FunctionEntry, param_1, local_res18, &local_res10,
                     (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
    iVar1 = iVar1 + 1;
  } while (iVar1 < 2);
  return;
}

// Library Function - Single Match
//  __GSHandlerCheck
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8
__GSHandlerCheck(undefined8 param_1, ulonglong param_2, undefined8 param_3, longlong param_4)
{
  __GSHandlerCheckCommon(param_2, param_4, *(uint **)(param_4 + 0x38));
  return 1;
}

// Library Function - Single Match
//  __GSHandlerCheckCommon
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __GSHandlerCheckCommon(ulonglong param_1, longlong param_2, uint *param_3)
{
  ulonglong uVar1;
  ulonglong uVar2;

  uVar2 = param_1;
  if ((*(byte *)param_3 & 4) != 0)
  {
    uVar2 = (longlong)(int)param_3[1] + param_1 & (longlong)(int)-param_3[2];
  }
  uVar1 = (ulonglong) * (uint *)(*(longlong *)(param_2 + 0x10) + 8);
  if ((*(byte *)(uVar1 + 3 + *(longlong *)(param_2 + 8)) & 0xf) != 0)
  {
    param_1 = param_1 + (*(byte *)(uVar1 + 3 + *(longlong *)(param_2 + 8)) & 0xfffffff0);
  }
  FUN_180034d00(param_1 ^ *(ulonglong *)((longlong)(int)(*param_3 & 0xfffffff8) + uVar2));
  return;
}

// WARNING: This is an inlined function
// Library Function - Single Match
//  _alloca_probe
//
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

void _alloca_probe(void)
{
  undefined *in_RAX;
  undefined *puVar1;
  undefined *puVar2;
  longlong in_GS_OFFSET;
  undefined local_res8[32];

  puVar1 = local_res8 + -(longlong)in_RAX;
  if (local_res8 < in_RAX)
  {
    puVar1 = (undefined *)0x0;
  }
  puVar2 = *(undefined **)(in_GS_OFFSET + 0x10);
  if (puVar1 < puVar2)
  {
    do
    {
      puVar2 = puVar2 + -0x1000;
      *puVar2 = 0;
    } while ((undefined *)((ulonglong)puVar1 & 0xfffffffffffff000) != puVar2);
  }
  return;
}

// Library Function - Single Match
//  __scrt_acquire_startup_lock
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong __scrt_acquire_startup_lock(void)
{
  ulonglong uVar1;
  bool bVar2;
  undefined7 extraout_var;
  longlong in_GS_OFFSET;
  ulonglong uVar3;

  bVar2 = __scrt_is_ucrt_dll_in_use();
  uVar3 = CONCAT71(extraout_var, bVar2);
  if ((int)uVar3 == 0)
  {
  LAB_180035046:
    uVar3 = uVar3 & 0xffffffffffffff00;
  }
  else
  {
    uVar1 = *(ulonglong *)(*(longlong *)(in_GS_OFFSET + 0x30) + 8);
    do
    {
      LOCK();
      bVar2 = DAT_180101770 == 0;
      DAT_180101770 = DAT_180101770 ^ (ulonglong)bVar2 * (DAT_180101770 ^ uVar1);
      uVar3 = !bVar2 * DAT_180101770;
      if (bVar2)
        goto LAB_180035046;
    } while (uVar1 != uVar3);
    uVar3 = CONCAT71((int7)(uVar3 >> 8), 1);
  }
  return uVar3;
}

// Library Function - Single Match
//  __scrt_dllmain_after_initialize_c
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong __scrt_dllmain_after_initialize_c(void)
{
  bool bVar1;
  int iVar2;
  undefined7 extraout_var;
  undefined8 uVar3;
  undefined4 extraout_var_00;
  undefined4 extraout_var_01;

  bVar1 = __scrt_is_ucrt_dll_in_use();
  if ((int)CONCAT71(extraout_var, bVar1) == 0)
  {
    uVar3 = FUN_180035b60();
    iVar2 = FUN_180063804((int)uVar3);
    if (iVar2 != 0)
    {
      return CONCAT44(extraout_var_00, iVar2) & 0xffffffffffffff00;
    }
    iVar2 = common_initialize_environment_nolock_char_();
    uVar3 = CONCAT44(extraout_var_01, iVar2);
  }
  else
  {
    uVar3 = FUN_1800359a4();
  }
  return CONCAT71((int7)((ulonglong)uVar3 >> 8), 1);
}

// Library Function - Single Match
//  __scrt_dllmain_crt_thread_attach
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong __scrt_dllmain_crt_thread_attach(void)
{
  ulonglong uVar1;

  uVar1 = __vcrt_thread_attach();
  if ((char)uVar1 != '\0')
  {
    uVar1 = FUN_180064dd0();
    if ((char)uVar1 != '\0')
    {
      return CONCAT71((int7)(uVar1 >> 8), 1);
    }
    uVar1 = __vcrt_thread_detach();
  }
  return uVar1 & 0xffffffffffffff00;
}

// Library Function - Single Match
//  __scrt_dllmain_crt_thread_detach
//
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

undefined __scrt_dllmain_crt_thread_detach(void)
{
  __acrt_thread_detach();
  __vcrt_thread_detach();
  return 1;
}

// Library Function - Single Match
//  __scrt_dllmain_uninitialize_c
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __scrt_dllmain_uninitialize_c(void)
{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;

  bVar1 = __scrt_is_ucrt_dll_in_use();
  if (CONCAT31(extraout_var, bVar1) != 0)
  {
    _execute_onexit_table(&DAT_180101738);
    return;
  }
  iVar2 = FUN_180062f14();
  if (iVar2 == 0)
  {
    FUN_180062ef8();
  }
  return;
}

// Library Function - Single Match
//  __scrt_initialize_crt
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

ulonglong __scrt_initialize_crt(int param_1)
{
  ulonglong uVar1;

  if (param_1 == 0)
  {
    DAT_180101778 = 1;
  }
  FUN_1800359a4();
  uVar1 = __vcrt_initialize();
  if ((char)uVar1 != '\0')
  {
    uVar1 = FUN_180064dbc();
    if ((char)uVar1 != '\0')
    {
      return uVar1 & 0xffffffffffffff00 | 1;
    }
    uVar1 = __vcrt_uninitialize('\0');
  }
  return uVar1 & 0xffffffffffffff00;
}

// WARNING: Removing unreachable block (ram,0x000180035342)
// Library Function - Single Match
//  __scrt_is_nonwritable_in_current_image
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

ulonglong __scrt_is_nonwritable_in_current_image(longlong param_1)
{
  ulonglong uVar1;
  uint7 uVar2;
  IMAGE_SECTION_HEADER *pIVar3;

  pIVar3 = &IMAGE_SECTION_HEADER_180000238;
  uVar1 = 0;
  while (pIVar3 != (IMAGE_SECTION_HEADER *)&DAT_180000328)
  {
    if (((ulonglong)(uint)pIVar3->VirtualAddress <= param_1 - 0x180000000U) &&
        (uVar1 = (ulonglong)(uint)(pIVar3->Misc + pIVar3->VirtualAddress),
         param_1 - 0x180000000U < uVar1))
      goto LAB_18003532b;
    pIVar3 = pIVar3 + 1;
  }
  pIVar3 = (IMAGE_SECTION_HEADER *)0x0;
LAB_18003532b:
  if (pIVar3 == (IMAGE_SECTION_HEADER *)0x0)
  {
    uVar1 = uVar1 & 0xffffffffffffff00;
  }
  else
  {
    uVar2 = (uint7)(uVar1 >> 8);
    if ((int)pIVar3->Characteristics < 0)
    {
      uVar1 = (ulonglong)uVar2 << 8;
    }
    else
    {
      uVar1 = CONCAT71(uVar2, 1);
    }
  }
  return uVar1;
}

// Library Function - Single Match
//  __scrt_release_startup_lock
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __scrt_release_startup_lock(char param_1)
{
  bool bVar1;
  undefined3 extraout_var;

  bVar1 = __scrt_is_ucrt_dll_in_use();
  if ((CONCAT31(extraout_var, bVar1) != 0) && (param_1 == '\0'))
  {
    DAT_180101770 = 0;
  }
  return;
}

// Library Function - Single Match
//  __scrt_uninitialize_crt
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

undefined8 __scrt_uninitialize_crt(bool param_1, char param_2)
{
  undefined8 in_RAX;

  if ((DAT_180101778 == '\0') || (param_2 == '\0'))
  {
    FUN_180064df4(param_1);
    in_RAX = __vcrt_uninitialize(param_1);
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _onexit
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

_onexit_t _onexit(_onexit_t _Func)
{
  int iVar1;
  byte bVar2;
  _onexit_t p_Var3;

  bVar2 = (byte)DAT_1800ee160 & 0x3f;
  if (((DAT_1800ee160 ^ _DAT_180101738) >> bVar2 | (DAT_1800ee160 ^ _DAT_180101738) << 0x40 - bVar2) == 0xffffffffffffffff)
  {
    iVar1 = FUN_180064aa8(_Func);
  }
  else
  {
    iVar1 = _register_onexit_function((ulonglong)&DAT_180101738, _Func);
  }
  p_Var3 = (_onexit_t)0x0;
  if (iVar1 == 0)
  {
    p_Var3 = _Func;
  }
  return p_Var3;
}

// Library Function - Single Match
//  __scrt_fastfail
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __scrt_fastfail(undefined4 param_1)
{
  code *pcVar1;
  BOOL BVar2;
  LONG LVar3;
  PRUNTIME_FUNCTION FunctionEntry;
  undefined *puVar4;
  undefined8 in_stack_00000000;
  DWORD64 local_res10;
  undefined local_res18[8];
  undefined local_res20[8];
  undefined auStack1480[8];
  undefined auStack1472[232];
  undefined local_4d8[152];
  undefined *local_440;
  DWORD64 local_3e0;

  puVar4 = auStack1480;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0)
  {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)(param_1);
    puVar4 = auStack1472;
  }
  *(undefined8 *)(puVar4 + -8) = 0x180035483;
  FUN_180035448(puVar4[-8]);
  *(undefined8 *)(puVar4 + -8) = 0x180035494;
  FUN_18003bd40((undefined(*)[16])local_4d8, 0, 0x4d0, puVar4[-8]);
  *(undefined8 *)(puVar4 + -8) = 0x18003549e;
  RtlCaptureContext(local_4d8);
  *(undefined8 *)(puVar4 + -8) = 0x1800354b8;
  FunctionEntry =
      RtlLookupFunctionEntry(local_3e0, &local_res10, (PUNWIND_HISTORY_TABLE)0x0, puVar4[-8]);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0)
  {
    *(undefined8 *)(puVar4 + 0x38) = 0;
    *(undefined **)(puVar4 + 0x30) = local_res18;
    *(undefined **)(puVar4 + 0x28) = local_res20;
    *(undefined **)(puVar4 + 0x20) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x1800354f9;
    RtlVirtualUnwind(0, local_res10, local_3e0, FunctionEntry, *(PCONTEXT *)(puVar4 + 0x20),
                     *(PVOID **)(puVar4 + 0x28), *(PDWORD64 *)(puVar4 + 0x30),
                     *(PKNONVOLATILE_CONTEXT_POINTERS *)(puVar4 + 0x38));
  }
  local_440 = &stack0x00000008;
  *(undefined8 *)(puVar4 + -8) = 0x18003552b;
  FUN_18003bd40((undefined(*)[16])(puVar4 + 0x50), 0, 0x98, puVar4[-8]);
  *(undefined8 *)(puVar4 + 0x60) = in_stack_00000000;
  *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
  *(undefined4 *)(puVar4 + 0x54) = 1;
  *(undefined8 *)(puVar4 + -8) = 0x18003554d;
  BVar2 = IsDebuggerPresent(puVar4[-8]);
  *(undefined **)(puVar4 + 0x40) = puVar4 + 0x50;
  *(undefined **)(puVar4 + 0x48) = local_4d8;
  *(undefined8 *)(puVar4 + -8) = 0x18003556e;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0, puVar4[-8]);
  *(undefined8 *)(puVar4 + -8) = 0x180035579;
  LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40), puVar4[-8]);
  if ((LVar3 == 0) && (BVar2 != 1))
  {
    *(undefined8 *)(puVar4 + -8) = 0x180035589;
    FUN_180035448(puVar4[-8]);
  }
  return;
}

// Library Function - Single Match
//  public: __cdecl std::exception::exception(class std::exception const & __ptr64) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void __thiscall std::exception::exception(exception *this, exception *param_1)
{
  *(undefined ***)this = vftable;
  *(char **)(this + 8) = (char *)0x0;
  *(undefined8 *)(this + 0x10) = 0;
  __std_exception_copy((char **)(param_1 + 8), (char **)(this + 8));
  return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __scrt_is_ucrt_dll_in_use
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

bool __scrt_is_ucrt_dll_in_use(void)
{
  return _DAT_180105338 != 0;
}

void _guard_check_icall(void)
{
  return;
}

// Library Function - Single Match
//  long __cdecl _com_dispatch_method(struct IDispatch * __ptr64,long,unsigned short,unsigned
// short,void * __ptr64,unsigned short const * __ptr64,...)
//
// Library: Visual Studio 2015 Release

long _com_dispatch_method(IDispatch *param_1, long param_2, ushort param_3, ushort param_4, void *param_5,
                          ushort *param_6, ...)
{
  undefined *puVar1;
  int iVar2;
  IErrorInfo *local_28[3];

  iVar2 = FUN_18003af10((longlong *)param_1, param_2, param_3, param_4, (undefined8 *)param_5, param_6,
                        (longlong *)&stack0x00000038, local_28);
  puVar1 = PTR__com_raise_error_1800ee450;
  if (iVar2 < 0)
  {
    _guard_check_icall();
    (*(code *)puVar1)(iVar2, local_28[0]);
  }
  return (long)iVar2;
}

// Library Function - Single Match
//  long __cdecl _com_dispatch_propget(struct IDispatch * __ptr64,long,unsigned short,void *
// __ptr64)
//
// Library: Visual Studio 2015 Release

long _com_dispatch_propget(IDispatch *param_1, long param_2, ushort param_3, void *param_4)
{
  long lVar1;

  lVar1 = _com_dispatch_method(param_1, param_2, 2, param_3, param_4, (ushort *)0x0);
  return lVar1;
}

// Library Function - Single Match
//  long __cdecl _com_dispatch_propput(struct IDispatch * __ptr64,long,unsigned short,...)
//
// Library: Visual Studio 2015 Release

long _com_dispatch_propput(IDispatch *param_1, long param_2, ushort param_3, ...)
{
  undefined *puVar1;
  ushort uVar2;
  int iVar3;
  longlong in_R9;
  longlong local_res20;
  ushort local_28;
  undefined2 local_26;
  IErrorInfo *local_20[2];

  local_26 = 0;
  uVar2 = 8;
  if ((param_3 - 9 & 0xfffb) != 0)
  {
    uVar2 = 4;
  }
  local_res20 = in_R9;
  local_28 = param_3;
  iVar3 = FUN_18003af10((longlong *)param_1, param_2, uVar2, 0, (undefined8 *)0x0, &local_28, &local_res20, local_20);
  puVar1 = PTR__com_raise_error_1800ee450;
  if (iVar3 < 0)
  {
    _guard_check_icall();
    (*(code *)puVar1)(iVar3, local_20[0]);
  }
  return (long)iVar3;
}

// Library Function - Single Match
//  void __cdecl _com_issue_error(long)
//
// Library: Visual Studio 2015 Release

void _com_issue_error(long param_1)
{
  undefined *UNRECOVERED_JUMPTABLE;

  UNRECOVERED_JUMPTABLE = PTR__com_raise_error_1800ee450;
  _guard_check_icall();
  // WARNING: Could not recover jumptable at 0x00018003a7cc. Too many branches
  // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)(param_1, 0);
  return;
}

// Library Function - Single Match
//  public: __cdecl _variant_t::_variant_t(long,unsigned short) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __thiscall _variant_t::_variant_t(_variant_t *this, long param_1, ushort param_2)
{
  code *pcVar1;

  if ((param_2 != 3) && (1 < (ushort)(param_2 - 10)))
  {
    _com_issue_error(-0x7ff8ffa9);
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  if (param_2 == 10)
  {
    *(long *)(this + 8) = param_1;
    *(undefined2 *)this = 10;
    return;
  }
  if (param_2 == 0xb)
  {
    *(undefined2 *)this = 0xb;
    *(ushort *)(this + 8) = -(ushort)(param_1 != 0);
    return;
  }
  *(long *)(this + 8) = param_1;
  *(undefined2 *)this = 3;
  return;
}

// Library Function - Single Match
//  public: __cdecl _com_error::_com_error(long,struct IErrorInfo * __ptr64,bool) __ptr64
//
// Library: Visual Studio 2015 Release

void __thiscall _com_error::_com_error(_com_error *this, long param_1, IErrorInfo *param_2, bool param_3)
{
  _func_6749 *p_Var1;

  *(long *)(this + 8) = param_1;
  *(undefined ***)this = &PTR_FUN_1800c8c88;
  *(IErrorInfo **)(this + 0x10) = param_2;
  *(undefined8 *)(this + 0x18) = 0;
  if ((param_2 != (IErrorInfo *)0x0) && (param_3 != false))
  {
    p_Var1 = param_2->lpVtbl->AddRef;
    _guard_check_icall();
    (*p_Var1)(param_2);
  }
  return;
}

// Library Function - Single Match
//  void __cdecl _com_raise_error(long,struct IErrorInfo * __ptr64)
//
// Library: Visual Studio 2015 Release

void _com_raise_error(long param_1, IErrorInfo *param_2)
{
  code *pcVar1;
  _com_error local_28[40];

  _com_error::_com_error(local_28, param_1, param_2, false);
  _CxxThrowException(local_28, (ThrowInfo *)&DAT_1800de448);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}

// Library Function - Single Match
//  long __cdecl _com_dispatch_raw_method(struct IDispatch * __ptr64,long,unsigned short,unsigned
// short,void * __ptr64,unsigned short const * __ptr64,...)
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

long _com_dispatch_raw_method(IDispatch *param_1, long param_2, ushort param_3, ushort param_4, void *param_5,
                              ushort *param_6, ...)
{
  int iVar1;
  IErrorInfo *local_18[2];

  iVar1 = FUN_18003af10((longlong *)param_1, param_2, param_3, param_4, (undefined8 *)param_5, param_6,
                        (longlong *)&stack0x00000038, local_18);
  if (iVar1 < 0)
  {
    SetErrorInfo(0, local_18[0]);
  }
  return (long)iVar1;
}

// Library Function - Single Match
//  long __cdecl _com_dispatch_raw_propget(struct IDispatch * __ptr64,long,unsigned short,void *
// __ptr64)
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

long _com_dispatch_raw_propget(IDispatch *param_1, long param_2, ushort param_3, void *param_4)
{
  long lVar1;

  lVar1 = _com_dispatch_raw_method(param_1, param_2, 2, param_3, param_4, (ushort *)0x0);
  return lVar1;
}

// Library Function - Single Match
//  long __cdecl _com_handle_excepinfo(struct tagEXCEPINFO & __ptr64,struct IErrorInfo * __ptr64 *
// __ptr64)
//
// Library: Visual Studio 2015 Release

long _com_handle_excepinfo(tagEXCEPINFO *param_1, IErrorInfo **param_2)
{
  ushort uVar1;
  code *pcVar2;
  _func_6759 *p_Var3;
  LPOLESTR pOVar4;
  _func_6760 *p_Var5;
  _func_6761 *p_Var6;
  _func_6762 *p_Var7;
  _func_6763 *p_Var8;
  _func_6756 *p_Var9;
  _func_6758 *p_Var10;
  ICreateErrorInfo *pIVar11;
  HRESULT HVar12;
  ICreateErrorInfo *local_res8;

  pcVar2 = *(code **)(param_1 + 0x30);
  if (pcVar2 != (code *)0x0)
  {
    _guard_check_icall();
    (*pcVar2)(param_1);
  }
  local_res8 = (ICreateErrorInfo *)0x0;
  if (param_2 != (IErrorInfo **)0x0)
  {
    HVar12 = CreateErrorInfo(&local_res8);
    pIVar11 = local_res8;
    if (-1 < HVar12)
    {
      p_Var3 = local_res8->lpVtbl->SetGUID;
      _guard_check_icall();
      (*p_Var3)(pIVar11, (GUID *)&DAT_1800c8ca0);
      pIVar11 = local_res8;
      pOVar4 = *(LPOLESTR *)(param_1 + 8);
      if (pOVar4 != (LPOLESTR)0x0)
      {
        p_Var5 = local_res8->lpVtbl->SetSource;
        _guard_check_icall();
        (*p_Var5)(pIVar11, pOVar4);
      }
      pIVar11 = local_res8;
      pOVar4 = *(LPOLESTR *)(param_1 + 0x10);
      if (pOVar4 != (LPOLESTR)0x0)
      {
        p_Var6 = local_res8->lpVtbl->SetDescription;
        _guard_check_icall();
        (*p_Var6)(pIVar11, pOVar4);
      }
      pIVar11 = local_res8;
      pOVar4 = *(LPOLESTR *)(param_1 + 0x18);
      if (pOVar4 != (LPOLESTR)0x0)
      {
        p_Var7 = local_res8->lpVtbl->SetHelpFile;
        _guard_check_icall();
        (*p_Var7)(pIVar11, pOVar4);
      }
      pIVar11 = local_res8;
      p_Var8 = local_res8->lpVtbl->SetHelpContext;
      _guard_check_icall();
      (*p_Var8)(pIVar11, *(DWORD *)(param_1 + 0x20));
      pIVar11 = local_res8;
      p_Var9 = local_res8->lpVtbl->QueryInterface;
      _guard_check_icall();
      HVar12 = (*p_Var9)(pIVar11, (IID *)&DAT_1800c8cb0, param_2);
      pIVar11 = local_res8;
      if (HVar12 < 0)
      {
        *param_2 = (IErrorInfo *)0x0;
      }
      p_Var10 = local_res8->lpVtbl->Release;
      _guard_check_icall();
      (*p_Var10)(pIVar11);
    }
  }
  if (*(longlong *)(param_1 + 8) != 0)
  {
    Ordinal_6();
  }
  if (*(longlong *)(param_1 + 0x10) != 0)
  {
    Ordinal_6();
  }
  if (*(longlong *)(param_1 + 0x18) != 0)
  {
    Ordinal_6();
  }
  uVar1 = *(ushort *)param_1;
  if (uVar1 != 0)
  {
    if (0xfdff < uVar1)
    {
      return -0x7ffb0001;
    }
    return (long)(uVar1 + 0x80040200);
  }
  return *(long *)(param_1 + 0x38);
}

// Library Function - Single Match
//  memcmp
//
// Library: Visual Studio

int memcmp(void *_Buf1, void *_Buf2, size_t _Size)
{
  uint uVar1;
  ulonglong uVar2;
  void *pvVar3;
  ulonglong uVar4;
  bool bVar5;

  pvVar3 = (void *)((longlong)_Buf2 - (longlong)_Buf1);
  if (7 < _Size)
  {
    uVar4 = (ulonglong)_Buf1 & 7;
    while (uVar4 != 0)
    {
      // WARNING: Load size is inaccurate
      bVar5 = *_Buf1 < *(byte *)((longlong)_Buf1 + (longlong)pvVar3);
      if (*_Buf1 != *(byte *)((longlong)_Buf1 + (longlong)pvVar3))
        goto LAB_18003c143;
      _Buf1 = (void *)((longlong)_Buf1 + 1);
      _Size = _Size - 1;
      uVar4 = (ulonglong)_Buf1 & 7;
    }
    if (_Size >> 3 != 0)
    {
      uVar4 = _Size >> 5;
      if (uVar4 != 0)
      {
        do
        {
          // WARNING: Load size is inaccurate
          uVar2 = *_Buf1;
          if (uVar2 != *(ulonglong *)((longlong)_Buf1 + (longlong)pvVar3))
            goto LAB_18003c1b4;
          uVar2 = *(ulonglong *)((longlong)_Buf1 + 8);
          if (uVar2 != *(ulonglong *)((longlong)((longlong)_Buf1 + 8) + (longlong)pvVar3))
          {
          LAB_18003c1b0:
            _Buf1 = (void *)((longlong)_Buf1 + 8);
            goto LAB_18003c1b4;
          }
          uVar2 = *(ulonglong *)((longlong)_Buf1 + 0x10);
          if (uVar2 != *(ulonglong *)((longlong)((longlong)_Buf1 + 0x10) + (longlong)pvVar3))
          {
          LAB_18003c1ac:
            _Buf1 = (void *)((longlong)_Buf1 + 8);
            goto LAB_18003c1b0;
          }
          uVar2 = *(ulonglong *)((longlong)_Buf1 + 0x18);
          if (uVar2 != *(ulonglong *)((longlong)((longlong)_Buf1 + 0x18) + (longlong)pvVar3))
          {
            _Buf1 = (void *)((longlong)_Buf1 + 8);
            goto LAB_18003c1ac;
          }
          _Buf1 = (void *)((longlong)_Buf1 + 0x20);
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
        _Size = _Size & 0x1f;
      }
      uVar4 = _Size >> 3;
      if (uVar4 != 0)
      {
        do
        {
          // WARNING: Load size is inaccurate
          uVar2 = *_Buf1;
          if (uVar2 != *(ulonglong *)((longlong)_Buf1 + (longlong)pvVar3))
          {
          LAB_18003c1b4:
            uVar4 = *(ulonglong *)((longlong)pvVar3 + (longlong)_Buf1);
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
  while (true)
  {
    if (_Size == 0)
    {
      return 0;
    }
    // WARNING: Load size is inaccurate
    bVar5 = *_Buf1 < *(byte *)((longlong)_Buf1 + (longlong)pvVar3);
    if (*_Buf1 != *(byte *)((longlong)_Buf1 + (longlong)pvVar3))
      break;
    _Buf1 = (void *)((longlong)_Buf1 + 1);
    _Size = _Size - 1;
  }
LAB_18003c143:
  return (int)((1 - (uint)bVar5) - (uint)(bVar5 != 0));
}

// Library Function - Single Match
//  _CxxThrowException
//
// Library: Visual Studio 2015 Release

void _CxxThrowException(void *pExceptionObject, ThrowInfo *pThrowInfo)
{
  longlong lVar1;
  longlong lVar2;
  code *pcVar3;
  PVOID local_res8;
  undefined4 local_38;
  undefined4 uStack52;
  void *pvStack48;
  ThrowInfo *local_28;
  PVOID pvStack32;

  local_38 = 0x19930520;
  uStack52 = 0;
  pvStack48 = (void *)0x0;
  local_28 = (ThrowInfo *)0x0;
  pvStack32 = (PVOID)0x0;
  if ((pThrowInfo != (ThrowInfo *)0x0) && ((*(byte *)&pThrowInfo->attributes & 0x10) != 0))
  {
    // WARNING: Load size is inaccurate
    lVar1 = *pExceptionObject;
    lVar2 = *(longlong *)(lVar1 + -8);
    pcVar3 = *(code **)(lVar2 + 0x40);
    pThrowInfo = *(ThrowInfo **)(lVar2 + 0x30);
    _guard_check_icall();
    (*pcVar3)(lVar1 + -8);
  }
  pvStack48 = pExceptionObject;
  local_28 = pThrowInfo;
  local_res8 = RtlPcToFileHeader(pThrowInfo, &local_res8);
  if (pThrowInfo != (ThrowInfo *)0x0)
  {
    if ((*(byte *)&pThrowInfo->attributes & 8) == 0)
    {
      if (local_res8 == (PVOID)0x0)
      {
        local_38 = 0x1994000;
      }
    }
    else
    {
      local_38 = 0x1994000;
    }
  }
  pvStack32 = local_res8;
  RaiseException(0xe06d7363, 1, 4, (ULONG_PTR *)&local_38);
  return;
}

// Library Function - Single Match
//  int __cdecl _ExecutionInCatch(struct _xDISPATCHER_CONTEXT * __ptr64,struct _s_FuncInfo const *
// __ptr64)
//
// Library: Visual Studio 2015 Release

int _ExecutionInCatch(_xDISPATCHER_CONTEXT *param_1, _s_FuncInfo *param_2)
{
  int iVar1;
  longlong lVar2;
  ulonglong uVar3;

  iVar1 = FUN_18003d340((longlong)param_2, (ulonglong *)param_1);
  uVar3 = (ulonglong)param_2->nTryBlocks;
  do
  {
    lVar2 = 0;
    if ((int)uVar3 == 0)
      break;
    uVar3 = (ulonglong)((int)uVar3 - 1);
    lVar2 = __vcrt_getptd();
    lVar2 = (longlong)(int)param_2->dispTryBlockMap + *(longlong *)(lVar2 + 0x60) + uVar3 * 0x14;
  } while ((iVar1 <= *(int *)(lVar2 + 4)) || (*(int *)(lVar2 + 8) < iVar1));
  return (int)(uint)(lVar2 != 0);
}

// Library Function - Single Match
//  unsigned __int64 * __ptr64 __cdecl _GetEstablisherFrame(unsigned __int64 * __ptr64,struct
// _xDISPATCHER_CONTEXT * __ptr64,struct _s_FuncInfo const * __ptr64,unsigned __int64 * __ptr64)
//
// Library: Visual Studio 2015 Release

__uint64 *
_GetEstablisherFrame(__uint64 *param_1, _xDISPATCHER_CONTEXT *param_2, _s_FuncInfo *param_3, __uint64 *param_4)
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
  iVar2 = FUN_18003d340((longlong)param_3, (ulonglong *)param_2);
  *param_4 = *param_1;
  do
  {
    do
    {
      if ((int)uVar8 == 0)
      {
        return param_4;
      }
      uVar8 = (ulonglong)((int)uVar8 - 1);
      lVar7 = (longlong)(int)param_3->dispTryBlockMap + uVar8 * 0x14 + *(longlong *)(param_2 + 8);
    } while ((iVar2 <= *(int *)(lVar7 + 4)) || (*(int *)(lVar7 + 8) < iVar2));
    p_Var3 = RtlLookupFunctionEntry(*(DWORD64 *)param_2, &local_res8, (PUNWIND_HISTORY_TABLE)0x0);
    uVar5 = 0;
    lVar9 = (longlong) * (int *)(lVar7 + 0x10) + local_res8;
    uVar1 = *(uint *)(lVar7 + 0xc);
    if (uVar1 != 0)
    {
      piVar6 = (int *)(lVar9 + 0xc);
      do
      {
        if ((longlong)*piVar6 == (ulonglong)p_Var3->BeginAddress)
          break;
        uVar4 = (int)uVar5 + 1;
        uVar5 = (ulonglong)uVar4;
        piVar6 = piVar6 + 5;
      } while (uVar4 < uVar1);
    }
    if ((uint)uVar5 < uVar1)
    {
      *param_4 = *(__uint64 *)((longlong) * (int *)(lVar9 + 0x10 + uVar5 * 0x14) + *param_1);
      return param_4;
    }
  } while (true);
}

// Library Function - Single Match
//  struct _s_TryBlockMapEntry const * __ptr64 __cdecl _GetRangeOfTrysToCheck(unsigned __int64 *
// __ptr64,struct _s_FuncInfo const * __ptr64,int,int,unsigned int * __ptr64,unsigned int *
// __ptr64,struct _xDISPATCHER_CONTEXT * __ptr64)
//
// Library: Visual Studio 2015 Release

_s_TryBlockMapEntry *
_GetRangeOfTrysToCheck(__uint64 *param_1, _s_FuncInfo *param_2, int param_3, int param_4, uint *param_5,
                       uint *param_6, _xDISPATCHER_CONTEXT *param_7)
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
  iVar5 = FUN_18003d340((longlong)param_2, (ulonglong *)param_7);
  if (uVar3 == 0)
  {
    FUN_180064ea0();
    pcVar4 = (code *)swi(3);
    p_Var6 = (_s_TryBlockMapEntry *)(*pcVar4)();
    return p_Var6;
  }
  *param_6 = 0xffffffff;
  *param_5 = 0xffffffff;
  lVar10 = (longlong)(int)param_2->dispTryBlockMap;
  uVar8 = uVar3;
  do
  {
    uVar1 = uVar8 - 1;
    lVar2 = *(longlong *)(param_7 + 8) + (ulonglong)uVar1 * 0x14;
    if ((*(int *)(lVar2 + 4 + lVar10) < iVar5) && (iVar5 <= *(int *)(lVar2 + 8 + lVar10)))
      break;
    uVar8 = uVar1;
  } while (uVar1 != 0);
  if (uVar8 != 0)
  {
    lVar9 = lVar10 + (ulonglong)(uVar8 - 1) * 0x14 + *(longlong *)(param_7 + 8);
  }
  uVar8 = 0;
  if (uVar3 != 0)
  {
    lVar10 = 0;
    do
    {
      piVar7 = (int *)((longlong)(int)param_2->dispTryBlockMap + *(longlong *)(param_7 + 8) + lVar10);
      if ((((lVar9 == 0) ||
            ((*piVar7 != *(int *)(lVar9 + 4) && *(int *)(lVar9 + 4) <= *piVar7 &&
              (piVar7[1] == *(int *)(lVar9 + 8) || piVar7[1] < *(int *)(lVar9 + 8))))) &&
           (*piVar7 <= param_4)) &&
          (param_4 <= piVar7[1]))
      {
        if (*param_5 == 0xffffffff)
        {
          *param_5 = uVar8;
        }
        *param_6 = uVar8 + 1;
      }
      uVar8 = uVar8 + 1;
      lVar10 = lVar10 + 0x14;
    } while (uVar8 < uVar3);
    if (*param_5 != 0xffffffff)
    {
      return (_s_TryBlockMapEntry *)((longlong)(int)param_2->dispTryBlockMap + (ulonglong)*param_5 * 0x14 +
                                     *(longlong *)(param_7 + 8));
    }
  }
  *param_5 = 0;
  *param_6 = 0;
  return (_s_TryBlockMapEntry *)0x0;
}

// Library Function - Single Match
//  void __cdecl __FrameUnwindToEmptyState(unsigned __int64 * __ptr64,struct _xDISPATCHER_CONTEXT *
// __ptr64,struct _s_FuncInfo const * __ptr64)
//
// Library: Visual Studio 2015 Release

void __FrameUnwindToEmptyState(__uint64 *param_1, _xDISPATCHER_CONTEXT *param_2, _s_FuncInfo *param_3)
{
  int iVar1;
  __uint64 *p_Var2;
  longlong lVar3;
  ulonglong uVar4;
  __uint64 local_res18[2];

  p_Var2 = _GetEstablisherFrame(param_1, param_2, param_3, local_res18);
  iVar1 = FUN_18003d340((longlong)param_3, (ulonglong *)param_2);
  uVar4 = (ulonglong)param_3->nTryBlocks;
  do
  {
    if ((int)uVar4 == 0)
    {
      lVar3 = 0;
      break;
    }
    uVar4 = (ulonglong)((int)uVar4 - 1);
    lVar3 = __vcrt_getptd();
    lVar3 = (longlong)(int)param_3->dispTryBlockMap + *(longlong *)(lVar3 + 0x60) + uVar4 * 0x14;
  } while ((iVar1 <= *(int *)(lVar3 + 4)) || (*(int *)(lVar3 + 8) < iVar1));
  if (lVar3 == 0)
  {
    iVar1 = -1;
  }
  else
  {
    iVar1 = *(int *)(lVar3 + 4);
  }
  FUN_18003e354((longlong *)p_Var2, (ulonglong *)param_2, (longlong)param_3, iVar1);
  return;
}

// Library Function - Single Match
//  _CallSETranslator
//
// Library: Visual Studio 2015 Release

undefined4 _CallSETranslator(undefined4 *param_1, undefined8 param_2, undefined8 param_3)
{
  code *pcVar1;
  longlong lVar2;
  undefined4 *local_30;
  undefined8 local_28;

  local_30 = param_1;
  local_28 = param_3;
  lVar2 = __vcrt_getptd();
  pcVar1 = *(code **)(lVar2 + 0x10);
  _guard_check_icall();
  (*pcVar1)(*param_1, &local_30);
  return 0;
}

// Library Function - Single Match
//  _CreateFrameInfo
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 *_CreateFrameInfo(undefined8 *param_1, undefined8 param_2)
{
  longlong lVar1;
  undefined8 uVar2;

  *param_1 = param_2;
  lVar1 = __vcrt_getptd();
  if (param_1 < *(undefined8 **)(lVar1 + 0x58))
  {
    lVar1 = __vcrt_getptd();
    uVar2 = *(undefined8 *)(lVar1 + 0x58);
  }
  else
  {
    uVar2 = 0;
  }
  param_1[1] = uVar2;
  lVar1 = __vcrt_getptd();
  *(undefined8 **)(lVar1 + 0x58) = param_1;
  return param_1;
}

// Library Function - Single Match
//  _GetImageBase
//
// Library: Visual Studio 2015 Release

undefined8 _GetImageBase(void)
{
  longlong lVar1;

  lVar1 = __vcrt_getptd();
  return *(undefined8 *)(lVar1 + 0x60);
}

// Library Function - Single Match
//  _GetThrowImageBase
//
// Library: Visual Studio 2015 Release

undefined8 _GetThrowImageBase(void)
{
  longlong lVar1;

  lVar1 = __vcrt_getptd();
  return *(undefined8 *)(lVar1 + 0x68);
}

// Library Function - Single Match
//  _UnwindNestedFrames
//
// Library: Visual Studio 2015 Release

void _UnwindNestedFrames(PVOID *param_1, ULONG_PTR param_2, ULONG_PTR param_3, ULONG_PTR param_4,
                         ULONG_PTR param_5, int param_6, ULONG_PTR param_7, PVOID *param_8, byte param_9)
{
  undefined local_588[12];
  undefined4 uStack1404;
  undefined4 local_578;
  undefined4 uStack1396;
  DWORD DStack1392;
  undefined4 uStack1388;
  undefined *local_568;
  ULONG_PTR UStack1376;
  ULONG_PTR local_558;
  ULONG_PTR UStack1360;
  ULONG_PTR local_548;
  ULONG_PTR UStack1344;
  ULONG_PTR local_538;
  ulonglong uStack1328;
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

  local_18 = DAT_1800ee160 ^ (ulonglong)&stack0xfffffffffffffa48;
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
  local_568 = &LAB_18003e168;
  local_558 = param_5;
  UStack1360 = SEXT48(param_6);
  UStack1344 = param_7;
  uStack1328 = (ulonglong)param_9;
  local_528 = 0x19930520;
  UStack1376 = param_4;
  local_548 = param_3;
  local_538 = param_2;
  RtlUnwindEx(*param_1, *param_8, (PEXCEPTION_RECORD)local_588, (PVOID)0x0, (PCONTEXT)&local_4e8,
              (PUNWIND_HISTORY_TABLE)param_8[8]);
  FUN_180034d00(local_18 ^ (ulonglong)&stack0xfffffffffffffa48);
  return;
}

// Library Function - Single Match
//  __CxxFrameHandler3
//
// Library: Visual Studio 2017 Release

void __CxxFrameHandler3(int *param_1, PVOID param_2, _CONTEXT *param_3, PVOID *param_4)
{
  longlong lVar1;
  PVOID local_res8;

  local_res8 = param_2;
  lVar1 = __vcrt_getptd();
  *(PVOID *)(lVar1 + 0x60) = param_4[1];
  lVar1 = __vcrt_getptd();
  *(undefined8 *)(lVar1 + 0x68) = *(undefined8 *)(param_1 + 0xe);
  lVar1 = __vcrt_getptd();
  // WARNING: Load size is inaccurate
  FUN_18003e4e8(param_1, &local_res8, param_3, param_4,
                (_s_FuncInfo *)((ulonglong)*param_4[7] + *(longlong *)(lVar1 + 0x60)), 0,
                (__uint64 *)0x0, 0);
  return;
}

// Library Function - Single Match
//  __C_specific_handler
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8
__C_specific_handler(PEXCEPTION_RECORD param_1, PVOID param_2, longlong param_3, longlong *param_4)
{
  longlong lVar1;
  uint *puVar2;
  int iVar3;
  BOOL BVar4;
  ulonglong uVar5;
  uint uVar6;
  ulonglong uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  ulonglong uVar11;
  uint uVar12;
  ulonglong uVar13;
  PEXCEPTION_RECORD local_38;
  longlong local_30;

  __except_validate_context_record(param_3);
  lVar1 = param_4[1];
  puVar2 = (uint *)param_4[7];
  uVar13 = *param_4 - lVar1;
  uVar6 = *(uint *)(param_4 + 9);
  local_38 = param_1;
  local_30 = param_3;
  if ((*(byte *)&param_1->ExceptionFlags & 0x66) == 0)
  {
    while (uVar6 < *puVar2)
    {
      uVar7 = (ulonglong)uVar6;
      if (((puVar2[uVar7 * 4 + 1] <= uVar13) && (uVar13 < puVar2[uVar7 * 4 + 2])) &&
          (puVar2[uVar7 * 4 + 4] != 0))
      {
        if (puVar2[uVar7 * 4 + 3] != 1)
        {
          iVar3 = (*(code *)((ulonglong)puVar2[uVar7 * 4 + 3] + lVar1))(&local_38, param_2);
          if (iVar3 < 0)
          {
            return 0;
          }
          if (iVar3 < 1)
            goto LAB_18003caa2;
        }
        if ((param_1->ExceptionCode == 0xe06d7363) &&
            (BVar4 = _IsNonwritableInCurrentImage((PBYTE)&PTR___DestructExceptionObject_1800c9e40),
             BVar4 != 0))
        {
          __DestructExceptionObject((int *)param_1);
        }
        FUN_18003e8d0();
        RtlUnwindEx(param_2, (PVOID)((ulonglong)puVar2[uVar7 * 4 + 4] + lVar1), param_1,
                    (PVOID)(ulonglong)param_1->ExceptionCode, (PCONTEXT)param_4[5],
                    (PUNWIND_HISTORY_TABLE)param_4[8]);
        FUN_18003e900();
      }
    LAB_18003caa2:
      uVar6 = uVar6 + 1;
    }
  }
  else
  {
    uVar8 = *puVar2;
    uVar7 = param_4[4] - lVar1;
    uVar9 = uVar8;
    if (uVar6 < uVar8)
    {
      do
      {
        uVar5 = (ulonglong)uVar6;
        if ((puVar2[uVar5 * 4 + 1] <= uVar13) && (uVar13 < puVar2[uVar5 * 4 + 2]))
        {
          uVar12 = param_1->ExceptionFlags & 0x20;
          if (uVar12 != 0)
          {
            uVar11 = 0;
            if (uVar8 != 0)
            {
              do
              {
                if ((((puVar2[uVar11 * 4 + 1] <= uVar7) && (uVar7 < puVar2[uVar11 * 4 + 2])) &&
                     (puVar2[uVar11 * 4 + 4] == puVar2[uVar5 * 4 + 4])) &&
                    (puVar2[uVar11 * 4 + 3] == puVar2[uVar5 * 4 + 3]))
                  break;
                uVar10 = (int)uVar11 + 1;
                uVar11 = (ulonglong)uVar10;
              } while (uVar10 < uVar8);
            }
            uVar8 = uVar9;
            if ((uint)uVar11 != uVar9)
            {
              return 1;
            }
          }
          if (puVar2[uVar5 * 4 + 4] == 0)
          {
            *(uint *)(param_4 + 9) = uVar6 + 1;
            (*(code *)((ulonglong)puVar2[uVar5 * 4 + 3] + lVar1))();
            uVar8 = *puVar2;
            uVar9 = uVar8;
          }
          else
          {
            if ((uVar7 == puVar2[uVar5 * 4 + 4]) && (uVar12 != 0))
            {
              return 1;
            }
          }
        }
        uVar6 = uVar6 + 1;
      } while (uVar6 < uVar8);
    }
  }
  return 1;
}

// Library Function - Single Match
//  __std_type_info_compare
//
// Library: Visual Studio 2019 Release

uint __std_type_info_compare(longlong param_1, longlong param_2)
{
  byte bVar1;
  byte *pbVar2;
  longlong lVar3;

  if (param_1 != param_2)
  {
    pbVar2 = (byte *)(param_1 + 9);
    lVar3 = (param_2 + 9) - (longlong)pbVar2;
    do
    {
      bVar1 = *pbVar2;
      if (bVar1 != pbVar2[lVar3])
      {
        return -(uint)(bVar1 < pbVar2[lVar3]) | 1;
      }
      pbVar2 = pbVar2 + 1;
    } while (bVar1 != 0);
  }
  return 0;
}

// Library Function - Single Match
//  __vcrt_initialize
//
// Library: Visual Studio 2015 Release

ulonglong __vcrt_initialize(void)
{
  undefined4 uVar1;
  ulonglong uVar2;
  undefined4 extraout_var;

  __vcrt_initialize_pure_virtual_call_handler();
  FUN_1800467bc();
  uVar2 = __vcrt_initialize_locks();
  if ((char)uVar2 != '\0')
  {
    uVar1 = FUN_18003d22c();
    if ((char)uVar1 != '\0')
    {
      return CONCAT71((int7)(CONCAT44(extraout_var, uVar1) >> 8), 1);
    }
    uVar2 = __vcrt_uninitialize_locks();
  }
  return uVar2 & 0xffffffffffffff00;
}

// Library Function - Single Match
//  __vcrt_thread_attach
//
// Library: Visual Studio 2015 Release

ulonglong __vcrt_thread_attach(void)
{
  LPVOID pvVar1;

  pvVar1 = __vcrt_getptd_noexit();
  return (ulonglong)pvVar1 & 0xffffffffffffff00 | (ulonglong)(pvVar1 != (LPVOID)0x0);
}

// Library Function - Single Match
//  __vcrt_thread_detach
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined __vcrt_thread_detach(void)
{
  __vcrt_freeptd((undefined *)0x0);
  return 1;
}

// Library Function - Single Match
//  __vcrt_uninitialize
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

undefined8 __vcrt_uninitialize(char param_1)
{
  undefined8 in_RAX;

  if (param_1 == '\0')
  {
    __vcrt_uninitialize_ptd();
    __vcrt_uninitialize_locks();
    in_RAX = __vcrt_uninitialize_winapi_thunks('\0');
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Single Match
//  __std_exception_copy
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __std_exception_copy(char **param_1, char **param_2)
{
  longlong lVar1;
  char *_Dst;
  longlong lVar2;

  if ((*(char *)(param_1 + 1) == '\0') || (*param_1 == (char *)0x0))
  {
    *param_2 = *param_1;
    *(undefined *)(param_2 + 1) = 0;
  }
  else
  {
    lVar1 = -1;
    do
    {
      lVar2 = lVar1;
      lVar1 = lVar2 + 1;
    } while ((*param_1)[lVar2 + 1] != '\0');
    _Dst = (char *)_malloc_base(lVar2 + 2);
    if (_Dst != (char *)0x0)
    {
      strcpy_s(_Dst, lVar2 + 2, *param_1);
      *(undefined *)(param_2 + 1) = 1;
      *param_2 = _Dst;
      _Dst = (char *)0x0;
    }
    FUN_180060a18(_Dst);
  }
  return;
}

// Library Function - Single Match
//  __std_exception_destroy
//
// Library: Visual Studio 2015 Release

void __std_exception_destroy(LPVOID *param_1)
{
  if (*(char *)(param_1 + 1) != '\0')
  {
    FUN_180060a18(*param_1);
  }
  *(undefined *)(param_1 + 1) = 0;
  *param_1 = (LPVOID)0x0;
  return;
}

// Library Function - Single Match
//  __vcrt_freeptd
//
// Library: Visual Studio 2015 Release

void __vcrt_freeptd(undefined *param_1)
{
  if (DAT_1800ee470 != 0xffffffff)
  {
    if (param_1 == (undefined *)0x0)
    {
      param_1 = (undefined *)__vcrt_FlsGetValue(DAT_1800ee470);
    }
    __vcrt_FlsSetValue(DAT_1800ee470, (LPVOID)0x0);
    if ((param_1 != (undefined *)0x0) && (param_1 != &DAT_1801017d0))
    {
      _free_base(param_1);
    }
  }
  return;
}

// Library Function - Single Match
//  __vcrt_getptd
//
// Library: Visual Studio 2015 Release

void __vcrt_getptd(void)
{
  code *pcVar1;
  LPVOID pvVar2;

  pvVar2 = __vcrt_getptd_noexit();
  if (pvVar2 != (LPVOID)0x0)
  {
    return;
  }
  abort();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}

// Library Function - Single Match
//  __vcrt_getptd_noexit
//
// Library: Visual Studio 2015 Release

LPVOID __vcrt_getptd_noexit(void)
{
  DWORD dwErrCode;
  int iVar1;
  LPVOID pvVar2;
  LPVOID pvVar3;
  LPVOID pvVar4;

  if (DAT_1800ee470 == 0xffffffff)
  {
    pvVar3 = (LPVOID)0x0;
  }
  else
  {
    dwErrCode = GetLastError();
    pvVar2 = (LPVOID)__vcrt_FlsGetValue(DAT_1800ee470);
    pvVar4 = (LPVOID)0x0;
    pvVar3 = pvVar4;
    if (((pvVar2 != (LPVOID)0xffffffffffffffff) && (pvVar3 = pvVar2, pvVar2 == (LPVOID)0x0)) &&
        (iVar1 = __vcrt_FlsSetValue(DAT_1800ee470, (LPVOID)0xffffffffffffffff), pvVar3 = pvVar4,
         iVar1 != 0))
    {
      pvVar3 = _calloc_base(1, 0x78);
      if ((pvVar3 == (LPVOID)0x0) ||
          (iVar1 = __vcrt_FlsSetValue(DAT_1800ee470, pvVar3), pvVar2 = pvVar4, iVar1 == 0))
      {
        __vcrt_FlsSetValue(DAT_1800ee470, (LPVOID)0x0);
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
//  __vcrt_getptd_noinit
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

longlong __vcrt_getptd_noinit(void)
{
  DWORD dwErrCode;
  longlong lVar1;

  if (DAT_1800ee470 == 0xffffffff)
  {
    lVar1 = 0;
  }
  else
  {
    dwErrCode = GetLastError();
    lVar1 = __vcrt_FlsGetValue(DAT_1800ee470);
    SetLastError(dwErrCode);
    if (lVar1 == -1)
    {
      lVar1 = 0;
    }
  }
  return lVar1;
}

// Library Function - Single Match
//  __vcrt_uninitialize_ptd
//
// Library: Visual Studio 2015 Release

undefined __vcrt_uninitialize_ptd(void)
{
  if (DAT_1800ee470 != 0xffffffff)
  {
    __vcrt_FlsFree(DAT_1800ee470);
    DAT_1800ee470 = 0xffffffff;
  }
  return 1;
}

// Library Function - Multiple Matches With Same Base Name
//  public: static int __cdecl __FrameHandler3::GetUnwindTryBlock(unsigned __int64 * __ptr64,struct
// _xDISPATCHER_CONTEXT * __ptr64,struct _s_FuncInfo const * __ptr64)
//  int __cdecl __GetUnwindTryBlock(unsigned __int64 * __ptr64,struct _xDISPATCHER_CONTEXT *
// __ptr64,struct _s_FuncInfo const * __ptr64)
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 GetUnwindTryBlock(__uint64 *param_1, _xDISPATCHER_CONTEXT *param_2, _s_FuncInfo *param_3)
{
  __uint64 *p_Var1;
  __uint64 local_res18[2];

  p_Var1 = _GetEstablisherFrame(param_1, param_2, param_3, local_res18);
  return *(undefined4 *)((longlong)param_3->dispUnwindHelp + 4 + *p_Var1);
}

// Library Function - Multiple Matches With Same Base Name
//  public: static void __cdecl __FrameHandler3::SetUnwindTryBlock(unsigned __int64 * __ptr64,struct
// _xDISPATCHER_CONTEXT * __ptr64,struct _s_FuncInfo const * __ptr64,int)
//  void __cdecl __SetUnwindTryBlock(unsigned __int64 * __ptr64,struct _xDISPATCHER_CONTEXT *
// __ptr64,struct _s_FuncInfo const * __ptr64,int)
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void SetUnwindTryBlock(__uint64 *param_1, _xDISPATCHER_CONTEXT *param_2, _s_FuncInfo *param_3,
                       int param_4)
{
  __uint64 *p_Var1;
  __uint64 local_res18[2];

  p_Var1 = _GetEstablisherFrame(param_1, param_2, param_3, local_res18);
  if (*(int *)((longlong)param_3->dispUnwindHelp + 4 + *p_Var1) < param_4)
  {
    *(int *)((longlong)param_3->dispUnwindHelp + 4 + *p_Var1) = param_4;
  }
  return;
}

// Library Function - Single Match
//  void __cdecl CatchIt(struct EHExceptionRecord * __ptr64,unsigned __int64 * __ptr64,struct
// _CONTEXT * __ptr64,struct _xDISPATCHER_CONTEXT * __ptr64,struct _s_FuncInfo const *
// __ptr64,struct _s_HandlerType const * __ptr64,struct _s_CatchableType const * __ptr64,struct
// _s_TryBlockMapEntry const * __ptr64,int,unsigned __int64 * __ptr64,unsigned char,unsigned char)
//
// Library: Visual Studio 2015 Release

void CatchIt(EHExceptionRecord *param_1, __uint64 *param_2, _CONTEXT *param_3,
             _xDISPATCHER_CONTEXT *param_4, _s_FuncInfo *param_5, _s_HandlerType *param_6,
             _s_CatchableType *param_7, _s_TryBlockMapEntry *param_8, int param_9, __uint64 *param_10,
             uchar param_11, uchar param_12)
{
  _s_FuncInfo *p_Var1;
  _s_HandlerType *p_Var2;
  __uint64 *p_Var3;
  longlong lVar4;
  __uint64 local_res10;

  p_Var1 = param_5;
  p_Var3 = _GetEstablisherFrame(param_2, param_4, param_5, &local_res10);
  p_Var2 = param_6;
  if (param_7 != (_s_CatchableType *)0x0)
  {
    __BuildCatchObject((longlong)param_1, (longlong *)p_Var3, (uint *)param_6, (byte *)param_7);
  }
  lVar4 = _GetImageBase();
  _UnwindNestedFrames((PVOID *)param_2, (ULONG_PTR)param_1, (ULONG_PTR)param_3, (ULONG_PTR)p_Var3,
                      lVar4 + (int)p_Var2->dispOfHandler, param_8->tryLow, (ULONG_PTR)p_Var1,
                      (PVOID *)param_4, param_12);
  return;
}

// Library Function - Single Match
//  int __cdecl ExFilterRethrow(struct _EXCEPTION_POINTERS * __ptr64,struct EHExceptionRecord *
// __ptr64,int * __ptr64)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int ExFilterRethrow(_EXCEPTION_POINTERS *param_1, EHExceptionRecord *param_2, int *param_3)
{
  PEXCEPTION_RECORD pEVar1;
  int iVar2;
  longlong lVar3;

  pEVar1 = param_1->ExceptionRecord;
  *param_3 = 0;
  if (((((pEVar1->ExceptionCode == 0xe06d7363) && (pEVar1->NumberParameters == 4)) &&
        ((2 < *(int *)pEVar1->ExceptionInformation + 0xe66cfae0U ||
          ((pEVar1->ExceptionInformation[1] != *(ULONG_PTR *)(param_2 + 0x28) ||
            (*param_3 = 1, pEVar1->ExceptionCode == 0xe06d7363)))))) &&
       (pEVar1->NumberParameters == 4)) &&
      ((*(int *)pEVar1->ExceptionInformation + 0xe66cfae0U < 3 &&
        (pEVar1->ExceptionInformation[2] == 0))))
  {
    lVar3 = __vcrt_getptd();
    *(undefined4 *)(lVar3 + 0x40) = 1;
    iVar2 = 1;
    *param_3 = 1;
  }
  else
  {
    iVar2 = 0;
  }
  return iVar2;
}

// Library Function - Single Match
//  unsigned char __cdecl IsInExceptionSpec(struct EHExceptionRecord * __ptr64,struct _s_ESTypeList
// const * __ptr64)
//
// Library: Visual Studio 2015 Release

uchar IsInExceptionSpec(EHExceptionRecord *param_1, _s_ESTypeList *param_2)
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

  if (param_2 == (_s_ESTypeList *)0x0)
  {
    FUN_180064ea0();
    pcVar2 = (code *)swi(3);
    uVar3 = (*pcVar2)();
    return uVar3;
  }
  uVar3 = '\0';
  iVar8 = 0;
  if (0 < *(int *)param_2)
  {
    do
    {
      lVar4 = _GetThrowImageBase();
      piVar9 = (int *)((longlong) * (int *)(*(longlong *)(param_1 + 0x30) + 0xc) + 4 + lVar4);
      lVar4 = _GetThrowImageBase();
      iVar7 = *(int *)(lVar4 + *(int *)(*(longlong *)(param_1 + 0x30) + 0xc));
      if (0 < iVar7)
      {
        do
        {
          lVar4 = _GetThrowImageBase();
          iVar1 = *piVar9;
          lVar5 = _GetImageBase();
          uVar6 = TypeMatchHelper__((byte *)((longlong) * (int *)(param_2 + 4) +
                                             lVar5 + (longlong)iVar8 * 0x14),
                                    (byte *)(lVar4 + iVar1),
                                    *(byte **)(param_1 + 0x30));
          if ((int)uVar6 != 0)
          {
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

// Library Function - Single Match
//  unsigned char __cdecl Is_bad_exception_allowed(struct _s_ESTypeList const * __ptr64)
//
// Library: Visual Studio 2019 Release

uchar Is_bad_exception_allowed(_s_ESTypeList *param_1)
{
  int iVar1;
  uint uVar2;
  longlong lVar3;
  int iVar4;
  longlong lVar5;

  iVar4 = 0;
  if (0 < *(int *)param_1)
  {
    lVar5 = 0;
    do
    {
      lVar3 = _GetImageBase();
      if (*(int *)((longlong) * (int *)(param_1 + 4) + 4 + lVar3 + lVar5) == 0)
      {
        lVar3 = 0;
      }
      else
      {
        lVar3 = _GetImageBase();
        iVar1 = *(int *)((longlong) * (int *)(param_1 + 4) + 4 + lVar3 + lVar5);
        lVar3 = _GetImageBase();
        lVar3 = lVar3 + iVar1;
      }
      uVar2 = __std_type_info_compare(lVar3 + 8, 0x1800ef018);
      if (uVar2 == 0)
      {
        return '\x01';
      }
      iVar4 = iVar4 + 1;
      lVar5 = lVar5 + 0x14;
    } while (iVar4 < *(int *)param_1);
  }
  return '\0';
}

// Library Function - Single Match
//  void __cdecl _CallMemberFunction2(void * __ptr64,void (__cdecl*)(void * __ptr64),void *
// __ptr64,int)
//
// Library: Visual Studio 2015 Release

void _CallMemberFunction2(void *param_1, FuncDef11 *param_2, void *param_3, int param_4)
{
  // WARNING: Could not recover jumptable at 0x00018003de70. Too many branches
  // WARNING: Treating indirect jump as call
  (*param_2)(param_1);
  return;
}

// Library Function - Single Match
//  __BuildCatchObject
//
// Library: Visual Studio 2015 Release

void __BuildCatchObject(longlong param_1, longlong *param_2, uint *param_3, byte *param_4)
{
  ulonglong uVar1;
  longlong lVar2;
  void *pvVar3;
  FuncDef11 *UNRECOVERED_JUMPTABLE;
  longlong *plVar4;

  UNRECOVERED_JUMPTABLE = (FuncDef11 *)0x0;
  plVar4 = param_2;
  if (-1 < (int)*param_3)
  {
    plVar4 = (longlong *)((longlong)(int)param_3[2] + *param_2);
  }
  uVar1 = FUN_18003df64(param_1, param_2, param_3, param_4);
  if ((int)uVar1 == 1)
  {
    if (*(int *)(param_4 + 0x18) != 0)
    {
      lVar2 = _GetThrowImageBase();
      UNRECOVERED_JUMPTABLE = (FuncDef11 *)(lVar2 + *(int *)(param_4 + 0x18));
    }
    lVar2 = __AdjustPointer(*(longlong *)(param_1 + 0x28), (int *)(param_4 + 8));
    FUN_18003de58(plVar4, UNRECOVERED_JUMPTABLE, lVar2);
  }
  else
  {
    if ((int)uVar1 == 2)
    {
      if (*(int *)(param_4 + 0x18) != 0)
      {
        lVar2 = _GetThrowImageBase();
        UNRECOVERED_JUMPTABLE = (FuncDef11 *)(lVar2 + *(int *)(param_4 + 0x18));
      }
      pvVar3 = (void *)__AdjustPointer(*(longlong *)(param_1 + 0x28), (int *)(param_4 + 8));
      _CallMemberFunction2(plVar4, UNRECOVERED_JUMPTABLE, pvVar3, 1);
    }
  }
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  int __cdecl TypeMatchHelper<struct _s_HandlerType const >(struct _s_HandlerType const *
// __ptr64,struct _s_CatchableType const * __ptr64,struct _s_ThrowInfo const * __ptr64)
//  int __cdecl TypeMatchHelper<class __FrameHandler3>(struct _s_HandlerType const * __ptr64,struct
// _s_CatchableType const * __ptr64,struct _s_ThrowInfo const * __ptr64)
//
// Library: Visual Studio 2017 Release

undefined8 TypeMatchHelper__(byte *param_1, byte *param_2, byte *param_3)
{
  char cVar1;
  char cVar2;
  longlong lVar3;
  longlong lVar4;
  longlong lVar5;
  char *pcVar6;
  int iVar7;
  int iVar8;

  lVar5 = 0;
  iVar7 = 0;
  lVar3 = lVar5;
  iVar8 = iVar7;
  if (*(int *)(param_1 + 4) != 0)
  {
    iVar8 = *(int *)(param_1 + 4);
    lVar3 = _GetImageBase();
    lVar3 = iVar8 + lVar3;
  }
  if (lVar3 != 0)
  {
    lVar3 = lVar5;
    if (iVar8 != 0)
    {
      iVar7 = *(int *)(param_1 + 4);
      lVar3 = _GetImageBase();
      lVar3 = iVar7 + lVar3;
    }
    if ((*(char *)(lVar3 + 0x10) != '\0') && (((*param_1 & 0x80) == 0 || ((*param_2 & 0x10) == 0))))
    {
      lVar3 = lVar5;
      if (iVar7 != 0)
      {
        lVar3 = _GetImageBase();
        lVar3 = lVar3 + *(int *)(param_1 + 4);
      }
      lVar4 = _GetThrowImageBase();
      if (lVar3 != lVar4 + *(int *)(param_2 + 4))
      {
        if (*(int *)(param_1 + 4) != 0)
        {
          lVar5 = _GetImageBase();
          lVar5 = lVar5 + *(int *)(param_1 + 4);
        }
        lVar3 = _GetThrowImageBase();
        pcVar6 = (char *)(lVar5 + 0x10);
        lVar3 = ((longlong) * (int *)(param_2 + 4) + 0x10 + lVar3) - (longlong)pcVar6;
        do
        {
          cVar1 = *pcVar6;
          cVar2 = pcVar6[lVar3];
          if (cVar1 != cVar2)
            break;
          pcVar6 = pcVar6 + 1;
        } while (cVar2 != '\0');
        if (cVar1 != cVar2)
        {
          return 0;
        }
      }
      if (((*param_2 & 2) != 0) && ((*param_1 & 8) == 0))
      {
        return 0;
      }
      if (((*param_3 & 1) != 0) && ((*param_1 & 1) == 0))
      {
        return 0;
      }
      if (((*param_3 & 4) != 0) && ((*param_1 & 4) == 0))
      {
        return 0;
      }
      if (((*param_3 & 2) != 0) && ((*param_1 & 2) == 0))
      {
        return 0;
      }
      return 1;
    }
  }
  return 1;
}

// WARNING: Removing unreachable block (ram,0x00018003e91f)
// WARNING: Removing unreachable block (ram,0x00018003e935)
// WARNING: Removing unreachable block (ram,0x00018003e93b)
// Library Function - Single Match
//  __except_validate_context_record
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __except_validate_context_record(longlong param_1)
{
  return;
}

// Library Function - Single Match
//  public: __cdecl DName::DName(class DName * __ptr64) __ptr64
//
// Library: Visual Studio 2017 Release

void __thiscall DName::DName(DName *this, DName *param_1)
{
  undefined **ppuVar1;
  undefined **ppuVar2;
  undefined **ppuVar3;

  ppuVar2 = (undefined **)0x0;
  *(undefined4 *)(this + 8) = 0;
  ppuVar3 = ppuVar2;
  if (param_1 != (DName *)0x0)
  {
    ppuVar1 = (undefined **)FUN_180042a6c((undefined **)&DAT_180101888, 0x10, 0);
    if (ppuVar1 != (undefined **)0x0)
    {
      *ppuVar1 = (undefined *)pDNameNode::vftable;
      if ((byte)((char)param_1[8] - 2U) < 2)
      {
        param_1 = (DName *)ppuVar2;
      }
      ppuVar1[1] = param_1;
      ppuVar3 = ppuVar1;
    }
    ppuVar2 = (undefined **)(ulonglong)(~-(ppuVar3 != (undefined **)0x0) & 3);
  }
  *(undefined ***)this = ppuVar3;
  this[8] = SUB81(ppuVar2, 0);
  return;
}

// Library Function - Single Match
//  public: __cdecl DName::DName(char const * __ptr64) __ptr64
//
// Library: Visual Studio 2017 Release

void __thiscall DName::DName(DName *this, char *param_1)
{
  char *pcVar1;
  int iVar2;

  iVar2 = 0;
  *(undefined8 *)this = 0;
  *(undefined4 *)(this + 8) = 0;
  if ((param_1 != (char *)0x0) && (pcVar1 = param_1, *param_1 != '\0'))
  {
    do
    {
      pcVar1 = pcVar1 + 1;
      iVar2 = iVar2 + 1;
    } while (*pcVar1 != '\0');
    if (iVar2 != 0)
    {
      doPchar(this, param_1, iVar2);
    }
  }
  return;
}

// Library Function - Single Match
//  public: __cdecl DName::DName(__int64) __ptr64
//
// Library: Visual Studio 2017 Release

void __thiscall DName::DName(DName *this, __int64 param_1)
{
  ulonglong uVar1;
  ulonglong uVar2;
  char *pcVar3;
  undefined auStack72[51];
  char local_15[5];
  ulonglong local_10;
  char *pcVar4;

  local_10 = DAT_1800ee160 ^ (ulonglong)auStack72;
  *(undefined8 *)this = 0;
  *(undefined4 *)(this + 8) = 0;
  local_15[2] = 0;
  uVar2 = (param_1 ^ param_1 >> 0x3f) - (param_1 >> 0x3f);
  pcVar3 = local_15 + 2;
  do
  {
    pcVar4 = pcVar3;
    pcVar3 = pcVar4 + -1;
    uVar1 = uVar2 / 10;
    *pcVar3 = (char)uVar2 + (char)uVar1 * -10 + '0';
    uVar2 = uVar1;
  } while (uVar1 != 0);
  if (param_1 < 0)
  {
    pcVar3 = pcVar4 + -2;
    *pcVar3 = '-';
  }
  doPchar(this, pcVar3, ((int)register0x00000020 + -0x13) - (int)pcVar3);
  FUN_180034d00(local_10 ^ (ulonglong)auStack72);
  return;
}

// Library Function - Single Match
//  public: __cdecl DName::DName(unsigned __int64) __ptr64
//
// Library: Visual Studio 2017 Release

void __thiscall DName::DName(DName *this, __uint64 param_1)
{
  ulonglong uVar1;
  char *pcVar2;
  undefined auStack72[51];
  char local_15[5];
  ulonglong local_10;

  local_10 = DAT_1800ee160 ^ (ulonglong)auStack72;
  pcVar2 = local_15 + 1;
  *(undefined8 *)this = 0;
  *(undefined4 *)(this + 8) = 0;
  local_15[1] = 0;
  do
  {
    pcVar2 = pcVar2 + -1;
    uVar1 = param_1 / 10;
    *pcVar2 = (char)param_1 + (char)uVar1 * -10 + '0';
    param_1 = uVar1;
  } while (uVar1 != 0);
  doPchar(this, pcVar2, ((int)register0x00000020 + -0x14) - (int)pcVar2);
  FUN_180034d00(local_10 ^ (ulonglong)auStack72);
  return;
}

// Library Function - Single Match
//  public: __cdecl pcharNode::pcharNode(char const * __ptr64,int) __ptr64
//
// Library: Visual Studio 2017 Release

void __thiscall pcharNode::pcharNode(pcharNode *this, char *param_1, int param_2)
{
  longlong lVar1;
  char *pcVar2;
  ulonglong uVar3;

  uVar3 = (ulonglong)(uint)param_2;
  *(undefined ***)this = vftable;
  if ((param_2 == 0) || (param_1 == (char *)0x0))
  {
    *(undefined8 *)(this + 8) = 0;
    *(undefined4 *)(this + 0x10) = 0;
  }
  else
  {
    pcVar2 = FUN_180042a6c((undefined **)&DAT_180101888, (longlong)param_2, 0);
    *(char **)(this + 8) = pcVar2;
    *(int *)(this + 0x10) = param_2;
    if (pcVar2 == (char *)0x0)
    {
      *(undefined4 *)(this + 0x10) = 0;
    }
    else
    {
      if (param_2 != 0)
      {
        lVar1 = -(longlong)pcVar2;
        do
        {
          *pcVar2 = (param_1 + lVar1)[(longlong)pcVar2];
          pcVar2 = pcVar2 + 1;
          uVar3 = uVar3 - 1;
        } while (uVar3 != 0);
      }
    }
  }
  return;
}

// Library Function - Single Match
//  public: class DName & __ptr64 __cdecl DName::operator=(class DName * __ptr64) __ptr64
//
// Library: Visual Studio 2017 Release

DName *__thiscall DName::operator_(DName *this, DName *param_1)
{
  undefined **ppuVar1;
  undefined **ppuVar2;

  ppuVar2 = (undefined **)0x0;
  *(undefined8 *)this = 0;
  *(undefined4 *)(this + 8) = 0;
  if (param_1 == (DName *)0x0)
  {
    this[8] = (DName)0x3;
  }
  else
  {
    ppuVar1 = (undefined **)FUN_180042a6c((undefined **)&DAT_180101888, 0x10, 0);
    if (ppuVar1 != (undefined **)0x0)
    {
      *ppuVar1 = (undefined *)pDNameNode::vftable;
      if ((byte)((char)param_1[8] - 2U) < 2)
      {
        param_1 = (DName *)ppuVar2;
      }
      ppuVar1[1] = param_1;
      ppuVar2 = ppuVar1;
    }
    *(undefined ***)this = ppuVar2;
    if (ppuVar2 == (undefined **)0x0)
    {
      this[8] = (DName)0x3;
    }
  }
  return this;
}

// Library Function - Single Match
//  public: class DName & __ptr64 __cdecl DName::operator=(char const * __ptr64) __ptr64
//
// Library: Visual Studio 2017 Release

DName *__thiscall DName::operator_(DName *this, char *param_1)
{
  char cVar1;
  char *pcVar2;
  int iVar3;

  iVar3 = 0;
  *(undefined8 *)this = 0;
  *(undefined4 *)(this + 8) = 0;
  cVar1 = *param_1;
  pcVar2 = param_1;
  while (cVar1 != '\0')
  {
    pcVar2 = pcVar2 + 1;
    iVar3 = iVar3 + 1;
    cVar1 = *pcVar2;
  }
  doPchar(this, param_1, iVar3);
  return this;
}

// Library Function - Single Match
//  public: class DName __cdecl Replicator::operator[](int)const __ptr64
//
// Library: Visual Studio 2017 Release

DName __thiscall Replicator::operator__(Replicator *this, int param_1)
{
  undefined8 *puVar1;
  undefined4 in_register_00000014;
  uint in_R8D;

  if (in_R8D < 10)
  {
    if ((*(int *)this != -1) && ((int)in_R8D <= *(int *)this))
    {
      puVar1 = *(undefined8 **)(this + (longlong)(int)in_R8D * 8 + 8);
      *(undefined8 *)CONCAT44(in_register_00000014, param_1) = *puVar1;
      *(undefined4 *)(CONCAT44(in_register_00000014, param_1) + 8) = *(undefined4 *)(puVar1 + 1);
      goto LAB_18003f00c;
    }
    *(undefined4 *)(CONCAT44(in_register_00000014, param_1) + 8) = 0;
    *(undefined *)(CONCAT44(in_register_00000014, param_1) + 8) = 2;
  }
  else
  {
    *(undefined4 *)(CONCAT44(in_register_00000014, param_1) + 8) = 0;
    *(undefined *)(CONCAT44(in_register_00000014, param_1) + 8) = 3;
  }
  *(undefined8 *)CONCAT44(in_register_00000014, param_1) = 0;
LAB_18003f00c:
  return SUB41(param_1, 0);
}

// Library Function - Single Match
//  class DName __cdecl operator+(enum DNameStatus,class DName const & __ptr64)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

DName operator_(DNameStatus param_1, DName *param_2)
{
  uint uVar1;
  undefined4 in_register_0000000c;
  undefined **local_18;
  uint local_10;

  uVar1 = (uint)param_2;
  local_10 = uVar1;
  if (1 < uVar1 - 2)
  {
    local_10 = 0;
  }
  local_10 = local_10 & 0xff;
  local_18 = &PTR_vftable_1800c9cc0;
  if (uVar1 != 1)
  {
    local_18 = (undefined **)0x0;
  }
  DName::operator_((DName *)&local_18, (DName *)CONCAT44(in_register_0000000c, param_1));
  return SUB41(param_1, 0);
}

// Library Function - Single Match
//  public: class DName __cdecl DName::operator+(class DName const & __ptr64)const __ptr64
//
// Library: Visual Studio 2017 Release

DName __thiscall DName::operator_(DName *this, DName *param_1)
{
  DName *in_R8;

  *(undefined8 *)param_1 = *(undefined8 *)this;
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(this + 8);
  operator__(param_1, in_R8);
  return SUB81(param_1, 0);
}

// Library Function - Single Match
//  public: class DName __cdecl DName::operator+(char)const __ptr64
//
// Library: Visual Studio 2017 Release

DName __thiscall DName::operator_(DName *this, char param_1)
{
  undefined7 in_register_00000011;
  char in_R8B;

  *(undefined8 *)CONCAT71(in_register_00000011, param_1) = *(undefined8 *)this;
  *(undefined4 *)(CONCAT71(in_register_00000011, param_1) + 8) = *(undefined4 *)(this + 8);
  operator__((DName *)CONCAT71(in_register_00000011, param_1), in_R8B);
  return (DName)param_1;
}

// Library Function - Single Match
//  public: class DName __cdecl DName::operator+(class DName * __ptr64)const __ptr64
//
// Library: Visual Studio 2017 Release

DName __thiscall DName::operator_(DName *this, DName *param_1)
{
  DName *in_R8;

  *(undefined8 *)param_1 = *(undefined8 *)this;
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(this + 8);
  operator__(param_1, in_R8);
  return SUB81(param_1, 0);
}

// Library Function - Single Match
//  public: class DName __cdecl DName::operator+(char const * __ptr64)const __ptr64
//
// Library: Visual Studio 2017 Release

DName __thiscall DName::operator_(DName *this, char *param_1)
{
  char *in_R8;

  *(undefined8 *)param_1 = *(undefined8 *)this;
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(this + 8);
  operator__((DName *)param_1, in_R8);
  return SUB81(param_1, 0);
}

// Library Function - Single Match
//  public: class DName __cdecl DName::operator+(enum DNameStatus)const __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

DName __thiscall DName::operator_(DName *this, DNameStatus param_1)
{
  undefined4 in_register_00000014;
  undefined8 *this_00;
  DNameStatus in_R8D;

  this_00 = (undefined8 *)CONCAT44(in_register_00000014, param_1);
  *this_00 = *(undefined8 *)this;
  *(undefined4 *)(this_00 + 1) = *(undefined4 *)(this + 8);
  operator__((DName *)this_00, in_R8D);
  return SUB41(param_1, 0);
}

// Library Function - Single Match
//  public: class DName & __ptr64 __cdecl DName::operator+=(class DName const & __ptr64) __ptr64
//
// Library: Visual Studio 2017 Release

DName *__thiscall DName::operator__(DName *this, DName *param_1)
{
  DNameNode *pDVar1;

  if ((char)this[8] < '\x02')
  {
    pDVar1 = *(DNameNode **)param_1;
    if (pDVar1 == (DNameNode *)0x0)
    {
      operator__(this, (int)(char)param_1[8]);
    }
    else
    {
      if (*(longlong *)this == 0)
      {
        *(DNameNode **)this = pDVar1;
        *(undefined4 *)(this + 8) = *(undefined4 *)(param_1 + 8);
      }
      else
      {
        append(this, pDVar1);
      }
    }
  }
  return this;
}

// Library Function - Single Match
//  public: class DName & __ptr64 __cdecl DName::operator+=(char) __ptr64
//
// Library: Visual Studio 2017 Release

DName *__thiscall DName::operator__(DName *this, char param_1)
{
  undefined **ppuVar1;
  char local_res8[8];

  if (((char)this[8] < '\x02') && (param_1 != '\0'))
  {
    if (*(longlong *)this == 0)
    {
      *(undefined8 *)this = 0;
      *(undefined4 *)(this + 8) = 0;
      local_res8[0] = param_1;
      doPchar(this, local_res8, 1);
    }
    else
    {
      ppuVar1 = (undefined **)FUN_180042a6c((undefined **)&DAT_180101888, 0x10, 0);
      if (ppuVar1 != (undefined **)0x0)
      {
        *(char *)(ppuVar1 + 1) = param_1;
        *ppuVar1 = (undefined *)charNode::vftable;
      }
      append(this, (DNameNode *)ppuVar1);
    }
  }
  return this;
}

// Library Function - Single Match
//  public: class DName & __ptr64 __cdecl DName::operator+=(class DName * __ptr64) __ptr64
//
// Library: Visual Studio 2017 Release

DName *__thiscall DName::operator__(DName *this, DName *param_1)
{
  undefined **ppuVar1;
  undefined **ppuVar2;

  if (((char)this[8] < '\x02') && (ppuVar2 = (undefined **)0x0, param_1 != (DName *)0x0))
  {
    if (*(longlong *)this == 0)
    {
      operator_(this, param_1);
    }
    else
    {
      if ((byte)param_1[8] < 2)
      {
        ppuVar1 = (undefined **)FUN_180042a6c((undefined **)&DAT_180101888, 0x10, 0);
        if (ppuVar1 != (undefined **)0x0)
        {
          *ppuVar1 = (undefined *)pDNameNode::vftable;
          if ((byte)((char)param_1[8] - 2U) < 2)
          {
            param_1 = (DName *)ppuVar2;
          }
          ppuVar1[1] = param_1;
          ppuVar2 = ppuVar1;
        }
        append(this, (DNameNode *)ppuVar2);
      }
      else
      {
        operator__(this, (int)(char)param_1[8]);
      }
    }
  }
  return this;
}

// Library Function - Single Match
//  public: class DName & __ptr64 __cdecl DName::operator+=(char const * __ptr64) __ptr64
//
// Library: Visual Studio 2017 Release

DName *__thiscall DName::operator__(DName *this, char *param_1)
{
  char cVar1;
  pcharNode *this_00;
  DNameNode *extraout_RAX;
  char *pcVar2;
  DNameNode *pDVar3;
  uint uVar4;

  if ((((char)this[8] < '\x02') && (pDVar3 = (DNameNode *)0x0, param_1 != (char *)0x0)) &&
      (*param_1 != '\0'))
  {
    if (*(longlong *)this == 0)
    {
      operator_(this, param_1);
    }
    else
    {
      this_00 = (pcharNode *)FUN_180042a6c((undefined **)&DAT_180101888, 0x18, 0);
      if (this_00 != (pcharNode *)0x0)
      {
        uVar4 = 0;
        cVar1 = *param_1;
        pcVar2 = param_1;
        while (cVar1 != '\0')
        {
          pcVar2 = pcVar2 + 1;
          uVar4 = (int)pDVar3 + 1;
          pDVar3 = (DNameNode *)(ulonglong)uVar4;
          cVar1 = *pcVar2;
        }
        pcharNode::pcharNode(this_00, param_1, uVar4);
        pDVar3 = extraout_RAX;
      }
      append(this, pDVar3);
    }
  }
  return this;
}

// Library Function - Single Match
//  public: class DName & __ptr64 __cdecl DName::operator+=(enum DNameStatus) __ptr64
//
// Library: Visual Studio 2017 Release

DName *__thiscall DName::operator__(DName *this, DNameStatus param_1)
{
  undefined **ppuVar1;

  if ((char)this[8] < '\x02')
  {
    if ((*(longlong *)this == 0) || (param_1 + 0xfffffffe < 2))
    {
      *(undefined4 *)(this + 8) = 0;
      this[8] = SUB41(param_1, 0);
      ppuVar1 = &PTR_vftable_1800c9cc0;
      if (param_1 != 1)
      {
        ppuVar1 = (undefined **)0x0;
      }
      *(undefined ***)this = ppuVar1;
    }
    else
    {
      if (param_1 != 0)
      {
        if (param_1 < 4)
        {
          ppuVar1 = &PTR_vftable_1800c9cb0 + (longlong)(int)param_1 * 2;
        }
        else
        {
          ppuVar1 = &PTR_vftable_1800c9ce0;
        }
        append(this, (DNameNode *)ppuVar1);
      }
    }
  }
  return this;
}

// Library Function - Single Match
//  public: class Replicator & __ptr64 __cdecl Replicator::operator+=(class DName const & __ptr64)
// __ptr64
//
// Library: Visual Studio 2017 Release

Replicator *__thiscall Replicator::operator__(Replicator *this, DName *param_1)
{
  int iVar1;
  undefined8 *puVar2;

  if ((*(int *)this != 9) && (*(longlong *)param_1 != 0))
  {
    puVar2 = (undefined8 *)FUN_180042a6c((undefined **)&DAT_180101888, 0x10, 0);
    if (puVar2 == (undefined8 *)0x0)
    {
      puVar2 = (undefined8 *)0x0;
    }
    else
    {
      *puVar2 = *(undefined8 *)param_1;
      *(undefined4 *)(puVar2 + 1) = *(undefined4 *)(param_1 + 8);
    }
    if (puVar2 != (undefined8 *)0x0)
    {
      iVar1 = *(int *)this;
      *(int *)this = iVar1 + 1;
      *(undefined8 **)(this + (longlong)iVar1 * 8 + 0x10) = puVar2;
    }
  }
  return this;
}

// Library Function - Single Match
//  private: void __cdecl DName::append(class DNameNode const * __ptr64) __ptr64
//
// Library: Visual Studio 2017 Release

void __thiscall DName::append(DName *this, DNameNode *param_1)
{
  undefined *puVar1;
  undefined **ppuVar2;

  if (param_1 == (DNameNode *)0x0)
  {
    this[8] = (DName)0x3;
  }
  else
  {
    ppuVar2 = (undefined **)FUN_180042a6c((undefined **)&DAT_180101888, 0x20, 0);
    if (ppuVar2 != (undefined **)0x0)
    {
      puVar1 = *(undefined **)this;
      *(undefined4 *)(ppuVar2 + 3) = 0xffffffff;
      *ppuVar2 = (undefined *)pairNode::vftable;
      ppuVar2[1] = puVar1;
      ppuVar2[2] = param_1;
    }
    *(undefined ***)this = ppuVar2;
    if (ppuVar2 == (undefined **)0x0)
    {
      this[8] = (DName)0x3;
    }
  }
  return;
}

// Library Function - Single Match
//  private: void __cdecl DName::doPchar(char const * __ptr64,int) __ptr64
//
// Library: Visual Studio 2017 Release

void __thiscall DName::doPchar(DName *this, char *param_1, int param_2)
{
  char cVar1;
  pcharNode *this_00;
  undefined **extraout_RAX;
  undefined **ppuVar2;

  if (*(longlong *)this != 0)
  {
    *(undefined4 *)(this + 8) = 0;
    *(undefined8 *)this = 0;
    this[8] = (DName)0x3;
    return;
  }
  if ((param_1 == (char *)0x0) || (param_2 == 0))
  {
    this[8] = (DName)0x2;
    return;
  }
  if (param_2 == 1)
  {
    ppuVar2 = (undefined **)FUN_180042a6c((undefined **)&DAT_180101888, 0x10, 0);
    if (ppuVar2 != (undefined **)0x0)
    {
      cVar1 = *param_1;
      *ppuVar2 = (undefined *)charNode::vftable;
      *(char *)(ppuVar2 + 1) = cVar1;
      goto LAB_180040430;
    }
  }
  else
  {
    this_00 = (pcharNode *)FUN_180042a6c((undefined **)&DAT_180101888, 0x18, 0);
    if (this_00 != (pcharNode *)0x0)
    {
      pcharNode::pcharNode(this_00, param_1, param_2);
      ppuVar2 = extraout_RAX;
      goto LAB_180040430;
    }
  }
  ppuVar2 = (undefined **)0x0;
LAB_180040430:
  *(undefined ***)this = ppuVar2;
  if (ppuVar2 == (undefined **)0x0)
  {
    this[8] = (DName)0x3;
  }
  return;
}

// Library Function - Single Match
//  private: static class DName __cdecl UnDecorator::getArgumentList(void)
//
// Library: Visual Studio 2017 Release

DName __thiscall UnDecorator::getArgumentList(UnDecorator *this)
{
  bool bVar1;
  char *pcVar2;
  DName DVar3;
  undefined7 extraout_var;
  undefined *local_38;
  undefined4 local_30;
  undefined *local_28[4];

  *(undefined8 *)this = 0;
  *(undefined4 *)(this + 8) = 0;
  bVar1 = true;
  while (true)
  {
    if ((*DAT_180101860 == '@') || (*DAT_180101860 == 'Z'))
      goto LAB_1800405c8;
    if (bVar1)
    {
      bVar1 = false;
    }
    else
    {
      DName::operator__((DName *)this, ',');
    }
    pcVar2 = DAT_180101860;
    if (*DAT_180101860 == '\0')
      break;
    if ((int)*DAT_180101860 - 0x30U < 10)
    {
      DAT_180101860 = DAT_180101860 + 1;
      DVar3 = Replicator::operator__((Replicator *)DAT_180101848, (int)register0x00000020 + -0x18);
      DName::operator__((DName *)this, (DName *)CONCAT71(extraout_var, DVar3));
    }
    else
    {
      local_38 = (undefined *)0x0;
      local_30 = 0;
      FUN_1800433a4(local_28, &local_38);
      if ((1 < (longlong)(DAT_180101860 + -(longlong)pcVar2)) && (*DAT_180101848 != 9))
      {
        Replicator::operator__((Replicator *)DAT_180101848, (DName *)local_28);
      }
      DName::operator__((DName *)this, (DName *)local_28);
      if (DAT_180101860 == pcVar2)
      {
        *(undefined4 *)(this + 8) = 0;
        *(undefined8 *)this = 0;
        this[8] = (UnDecorator)0x2;
      }
    }
    if (this[8] != (UnDecorator)0x0)
    {
    LAB_1800405c8:
      return SUB81(this, 0);
    }
  }
  DName::operator__((DName *)this, 1);
  goto LAB_1800405c8;
}

// Library Function - Single Match
//  private: static class DName __cdecl UnDecorator::getBasedType(void)
//
// Library: Visual Studio 2017 Release

DName __thiscall UnDecorator::getBasedType(UnDecorator *this)
{
  char cVar1;
  undefined **ppuVar2;
  char *pcVar3;
  undefined8 local_28;
  undefined4 local_20;
  undefined *local_18[2];

  if ((~DAT_180101870 & 1) == 0)
  {
    pcVar3 = "based(";
  }
  else
  {
    pcVar3 = "__based(";
  }
  DName::DName((DName *)&local_28, pcVar3);
  cVar1 = *DAT_180101860;
  if (cVar1 == '\0')
  {
    DName::operator__((DName *)&local_28, 1);
  }
  else
  {
    DAT_180101860 = DAT_180101860 + 1;
    if (cVar1 == '0')
    {
      DName::operator__((DName *)&local_28, "void");
    }
    else
    {
      if (cVar1 == '2')
      {
        ppuVar2 = FUN_180043ea4(local_18);
        DName::operator__((DName *)&local_28, (DName *)ppuVar2);
      }
      else
      {
        if (cVar1 == '5')
        {
          *(undefined4 *)(this + 8) = 0;
          *(undefined8 *)this = 0;
          this[8] = (UnDecorator)0x2;
          goto LAB_1800409f3;
        }
      }
    }
  }
  DName::operator__((DName *)&local_28, ") ");
  *(undefined8 *)this = local_28;
  *(undefined4 *)(this + 8) = local_20;
LAB_1800409f3:
  return SUB81(this, 0);
}

// Library Function - Single Match
//  private: static class DName __cdecl UnDecorator::getDataType(class DName * __ptr64)
//
// Library: Visual Studio 2017 Release

DName __thiscall UnDecorator::getDataType(UnDecorator *this, DName *param_1)
{
  undefined ***extraout_RAX;
  undefined **ppuVar1;
  undefined ***this_00;
  undefined *local_38;
  undefined4 local_30;
  undefined **local_28;
  undefined4 local_20;
  undefined *local_18[2];

  DName::DName((DName *)&local_38, param_1);
  if (*DAT_180101860 == '\0')
  {
    local_20 = 0;
    local_28 = &PTR_vftable_1800c9cc0;
    this_00 = &local_28;
  LAB_18004197c:
    DName::operator_((DName *)this_00, (DName *)this);
  }
  else
  {
    if (*DAT_180101860 == '?')
    {
      DAT_180101860 = DAT_180101860 + 1;
      local_28 = (undefined **)0x0;
      local_20 = 0;
      ppuVar1 = FUN_1800410b8(local_18, &local_38, "", (longlong *)&local_28, 0);
      local_38 = *ppuVar1;
      local_30 = *(undefined4 *)(ppuVar1 + 1);
    }
    else
    {
      if (*DAT_180101860 == 'X')
      {
        DAT_180101860 = DAT_180101860 + 1;
        if (local_38 == (undefined *)0x0)
        {
          DName::DName((DName *)this, "void");
          goto LAB_180041988;
        }
        DName::DName((DName *)&local_28, "void ");
        this_00 = extraout_RAX;
        goto LAB_18004197c;
      }
    }
    FUN_1800433a4((undefined **)this, &local_38);
  }
LAB_180041988:
  return SUB81(this, 0);
}

// Library Function - Single Match
//  private: static class DName __cdecl UnDecorator::getDispatchTarget(void)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

DName __thiscall UnDecorator::getDispatchTarget(UnDecorator *this)
{
  char *pcVar1;

  if ((*DAT_180101860 == '_') && (DAT_180101860[1] == '_'))
  {
    pcVar1 = DAT_180101860 + 2;
    DAT_180101860 = DAT_180101860 + 3;
    if (3 < (int)*pcVar1 - 0x41U)
    {
      *(undefined4 *)(this + 8) = 0;
      *(undefined8 *)this = 0;
      this[8] = (UnDecorator)0x2;
      goto LAB_180041e08;
    }
  }
  *(undefined8 *)this = 0;
  *(undefined4 *)(this + 8) = 0;
LAB_180041e08:
  return SUB81(this, 0);
}

// Library Function - Single Match
//  public: char __cdecl DName::getLastChar(void)const __ptr64
//
// Library: Visual Studio 2015 Release

char __thiscall DName::getLastChar(DName *this)
{
  longlong *plVar1;
  code *pcVar2;
  char cVar3;

  plVar1 = *(longlong **)this;
  if (plVar1 == (longlong *)0x0)
  {
    cVar3 = '\0';
  }
  else
  {
    pcVar2 = *(code **)(*plVar1 + 8);
    _guard_check_icall();
    cVar3 = (*pcVar2)(plVar1);
  }
  return cVar3;
}

// Library Function - Single Match
//  private: static class DName __cdecl UnDecorator::getLexicalFrame(void)
//
// Library: Visual Studio 2017 Release

DName __thiscall UnDecorator::getLexicalFrame(UnDecorator *this)
{
  char local_res8[8];
  undefined8 local_38;
  undefined4 local_30;
  DName local_28[16];
  undefined *local_18[2];

  FUN_180041c50(local_18, '\0');
  local_38 = 0;
  local_30 = 0;
  local_res8[0] = '`';
  DName::doPchar((DName *)&local_38, local_res8, 1);
  DName::operator_((DName *)&local_38, local_28);
  DName::operator_(local_28, (char)SUB81(this, 0));
  return SUB81(this, 0);
}

// Library Function - Single Match
//  private: static class DName __cdecl UnDecorator::getNoexcept(void)
//
// Library: Visual Studio 2017 Release

DName __thiscall UnDecorator::getNoexcept(UnDecorator *this)
{
  if ((*DAT_180101860 == '_') && (DAT_180101860[1] == 'E'))
  {
    DAT_180101860 = DAT_180101860 + 2;
    DName::DName((DName *)this, " noexcept");
  }
  else
  {
    *(undefined8 *)this = 0;
    *(undefined4 *)(this + 8) = 0;
  }
  return SUB81(this, 0);
}

// Library Function - Single Match
//  private: static int __cdecl UnDecorator::getNumberOfDimensions(void)
//
// Library: Visual Studio 2015 Release

int UnDecorator::getNumberOfDimensions(void)
{
  char cVar1;
  int iVar2;

  cVar1 = *DAT_180101860;
  if (cVar1 == '\0')
  {
    return 0;
  }
  if (9 < (byte)(cVar1 - 0x30U))
  {
    iVar2 = 0;
    while (true)
    {
      if (cVar1 == '@')
      {
        if (*DAT_180101860 != '@')
        {
          DAT_180101860 = DAT_180101860 + 1;
          return -1;
        }
        DAT_180101860 = DAT_180101860 + 1;
        return iVar2;
      }
      if (cVar1 == '\0')
        break;
      if (0xf < (byte)(cVar1 + 0xbfU))
      {
        return -1;
      }
      iVar2 = iVar2 * 0x10 + -0x41 + (int)cVar1;
      DAT_180101860 = DAT_180101860 + 1;
      cVar1 = *DAT_180101860;
    }
    return 0;
  }
  DAT_180101860 = DAT_180101860 + 1;
  return cVar1 + -0x2f;
}

// Library Function - Multiple Matches With Different Base Names
//  private: static class DName __cdecl UnDecorator::getPointerType(class DName const &
// __ptr64,class DName const & __ptr64)
//  private: static class DName __cdecl UnDecorator::getPointerTypeArray(class DName const &
// __ptr64,class DName const & __ptr64)
//
// Library: Visual Studio 2017 Release

UnDecorator *FID_conflict_getPointerType(UnDecorator *param_1, DName *param_2, DName *param_3)
{
  UnDecorator::getPtrRefType(param_1, param_2, param_3, "*");
  return param_1;
}

// Library Function - Multiple Matches With Different Base Names
//  private: static class DName __cdecl UnDecorator::getPointerType(class DName const &
// __ptr64,class DName const & __ptr64)
//  private: static class DName __cdecl UnDecorator::getPointerTypeArray(class DName const &
// __ptr64,class DName const & __ptr64)
//
// Library: Visual Studio 2017 Release

UnDecorator *FID_conflict_getPointerType(UnDecorator *param_1, DName *param_2, DName *param_3)
{
  UnDecorator::getPtrRefType(param_1, param_2, param_3, "");
  return param_1;
}

// Library Function - Single Match
//  private: static class DName __cdecl UnDecorator::getPtrRefType(class DName const & __ptr64,class
// DName const & __ptr64,char const * __ptr64)
//
// Library: Visual Studio 2017 Release

DName __thiscall UnDecorator::getPtrRefType(UnDecorator *this, DName *param_1, DName *param_2, char *param_3)
{
  char cVar1;
  undefined **local_28;
  undefined4 local_20;

  cVar1 = *DAT_180101860;
  if (cVar1 == '\0')
  {
    local_20 = 0;
    local_28 = &PTR_vftable_1800c9cc0;
    DName::operator__((DName *)&local_28, param_3);
    if (*(longlong *)param_1 != 0)
    {
      DName::operator__((DName *)&local_28, param_1);
    }
    if (*(longlong *)param_2 != 0)
    {
      if (*(longlong *)param_1 != 0)
      {
        DName::operator__((DName *)&local_28, ' ');
      }
      DName::operator__((DName *)&local_28, param_2);
    }
    *(undefined ***)this = local_28;
    *(undefined4 *)(this + 8) = local_20;
  }
  else
  {
    if (((byte)(cVar1 - 0x36U) < 4) || (cVar1 == '_'))
    {
      DName::DName((DName *)&local_28, param_3);
      if ((*(longlong *)param_1 != 0) &&
          ((*(longlong *)param_2 == 0 || ((*(uint *)(param_2 + 8) & 0x100) == 0))))
      {
        DName::operator__((DName *)&local_28, param_1);
      }
      if (*(longlong *)param_2 != 0)
      {
        DName::operator__((DName *)&local_28, param_2);
      }
      FUN_180042398((undefined8 *)this, (undefined **)&local_28);
    }
    else
    {
      FUN_1800410b8((undefined **)&local_28, (undefined **)param_2, param_3, (longlong *)param_1, 0);
      FUN_1800435fc((undefined **)this, (undefined **)&local_28, (uint)(*param_3 == '*'));
    }
  }
  return SUB81(this, 0);
}

// Library Function - Single Match
//  private: static class DName __cdecl UnDecorator::getReferenceType(class DName const &
// __ptr64,class DName const & __ptr64,char const * __ptr64)
//
// Library: Visual Studio 2017 Release

DName __thiscall UnDecorator::getReferenceType(UnDecorator *this, DName *param_1, DName *param_2, char *param_3)
{
  getPtrRefType(this, param_1, param_2, param_3);
  return SUB81(this, 0);
}

// Library Function - Single Match
//  private: static class DName __cdecl UnDecorator::getReturnType(class DName * __ptr64)
//
// Library: Visual Studio 2017 Release

DName __thiscall UnDecorator::getReturnType(UnDecorator *this, DName *param_1)
{
  if (*DAT_180101860 == '@')
  {
    DAT_180101860 = DAT_180101860 + 1;
    DName::DName((DName *)this, param_1);
  }
  else
  {
    getDataType(this, param_1);
  }
  return SUB81(this, 0);
}

// Library Function - Single Match
//  public: char * __ptr64 __cdecl DName::getString(char * __ptr64,int)const __ptr64
//
// Library: Visual Studio 2015 Release

char *__thiscall DName::getString(DName *this, char *param_1, int param_2)
{
  code **ppcVar1;
  code *pcVar2;
  longlong *plVar3;
  int iVar4;
  char *pcVar5;

  ppcVar1 = *(code ***)this;
  if (ppcVar1 == (code **)0x0)
  {
    if (param_1 != (char *)0x0)
    {
      *param_1 = '\0';
    }
  }
  else
  {
    if (param_1 == (char *)0x0)
    {
      pcVar2 = *(code **)*ppcVar1;
      _guard_check_icall();
      iVar4 = (*pcVar2)(ppcVar1);
      param_2 = iVar4 + 1;
      param_1 = FUN_180042a6c((undefined **)&DAT_180101888, (longlong)param_2, 0);
      if (param_1 == (char *)0x0)
      {
        return (char *)0x0;
      }
    }
    plVar3 = *(longlong **)this;
    pcVar5 = param_1;
    if (plVar3 != (longlong *)0x0)
    {
      pcVar2 = *(code **)(*plVar3 + 0x10);
      _guard_check_icall();
      pcVar5 = (char *)(*pcVar2)(plVar3, param_1, param_1 + (longlong)param_2 + -1);
    }
    *pcVar5 = '\0';
  }
  return param_1;
}

// Library Function - Single Match
//  public: virtual char * __ptr64 __cdecl pDNameNode::getString(char * __ptr64,char * __ptr64)const
// __ptr64
//
// Library: Visual Studio 2015 Release

char *__thiscall pDNameNode::getString(pDNameNode *this, char *param_1, char *param_2)
{
  longlong *plVar1;
  code *pcVar2;

  if ((*(longlong ***)(this + 8) != (longlong **)0x0) &&
      (plVar1 = **(longlong ***)(this + 8), plVar1 != (longlong *)0x0))
  {
    pcVar2 = *(code **)(*plVar1 + 0x10);
    _guard_check_icall();
    param_1 = (char *)(*pcVar2)(plVar1, param_1, param_2);
  }
  return param_1;
}

// Library Function - Single Match
//  private: static class DName __cdecl UnDecorator::getSymbolName(void)
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

DName __thiscall UnDecorator::getSymbolName(UnDecorator *this)
{
  ulonglong in_R8;
  undefined8 in_R9;

  if (*DAT_180101860 == '?')
  {
    if (DAT_180101860[1] == '$')
    {
      FUN_180044b58((longlong **)this, '\x01', in_R8, in_R9);
    }
    else
    {
      DAT_180101860 = DAT_180101860 + 1;
      FUN_180042bdc((longlong **)this, (undefined **)0x0, (undefined *)0x0, in_R9);
    }
  }
  else
  {
    FUN_18004551c((longlong **)this, '\x01', '\0');
  }
  return SUB81(this, 0);
}

// Library Function - Single Match
//  private: static class DName __cdecl UnDecorator::getVdispMapType(class DName const & __ptr64)
//
// Library: Visual Studio 2017 Release

DName __thiscall UnDecorator::getVdispMapType(UnDecorator *this, DName *param_1)
{
  longlong **pplVar1;
  char *pcVar2;
  longlong **in_R8;
  undefined8 in_R9;
  longlong *local_18[2];

  *(undefined8 *)this = *(undefined8 *)param_1;
  pcVar2 = "{for ";
  *(undefined4 *)(this + 8) = *(undefined4 *)(param_1 + 8);
  DName::operator__((DName *)this, "{for ");
  pplVar1 = FUN_180043a2c(local_18, pcVar2, in_R8, in_R9);
  DName::operator__((DName *)this, (DName *)pplVar1);
  DName::operator__((DName *)this, '}');
  if (*DAT_180101860 == '@')
  {
    DAT_180101860 = DAT_180101860 + 1;
  }
  return SUB81(this, 0);
}

// Library Function - Multiple Matches With Different Base Names
//  _snprintf_c
//  _sprintf_p
//  _swprintf_c
//  _swprintf_p
//   7 names - too many to list
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int FID_conflict__sprintf_p(wchar_t *_Dst, size_t _SizeInWords, wchar_t *_Format, ...)
{
  int iVar1;
  __uint64 *p_Var2;
  undefined8 in_R9;
  undefined8 local_res20;

  local_res20 = in_R9;
  p_Var2 = (__uint64 *)FUN_180005100();
  iVar1 = __stdio_common_vsprintf_s(*p_Var2, (char *)_Dst, _SizeInWords, (char *)_Format, (__crt_locale_pointers *)0x0,
                                    (char *)&local_res20);
  if (iVar1 < 0)
  {
    iVar1 = -1;
  }
  return iVar1;
}

// Library Function - Single Match
//  __vcrt_initialize_locks
//
// Library: Visual Studio 2015 Release

ulonglong __vcrt_initialize_locks(void)
{
  undefined8 uVar1;
  ulonglong uVar2;
  uint uVar3;

  uVar2 = 0;
  do
  {
    uVar1 = __vcrt_InitializeCriticalSectionEx((LPCRITICAL_SECTION)(&DAT_1801018b0 + uVar2 * 0x28), 4000, 0);
    if ((int)uVar1 == 0)
    {
      uVar2 = __vcrt_uninitialize_locks();
      return uVar2 & 0xffffffffffffff00;
    }
    DAT_1801018d8 = DAT_1801018d8 + 1;
    uVar3 = (int)uVar2 + 1;
    uVar2 = (ulonglong)uVar3;
  } while (uVar3 == 0);
  return CONCAT71((int7)((ulonglong)uVar1 >> 8), 1);
}

// Library Function - Single Match
//  __vcrt_uninitialize_locks
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

undefined8 __vcrt_uninitialize_locks(void)
{
  undefined8 in_RAX;
  undefined8 extraout_RAX;
  ulonglong uVar1;

  uVar1 = (ulonglong)DAT_1801018d8;
  while ((int)uVar1 != 0)
  {
    uVar1 = (ulonglong)((int)uVar1 - 1);
    DeleteCriticalSection((LPCRITICAL_SECTION)(&DAT_1801018b0 + uVar1 * 0x28));
    DAT_1801018d8 = DAT_1801018d8 - 1;
    in_RAX = extraout_RAX;
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  void * __ptr64 __cdecl try_get_function(enum `anonymous namespace'::function_id,char const *
// __ptr64 const,enum A0x14c33c87::module_id const * __ptr64 const,enum A0x14c33c87::module_id const
// * __ptr64 const)
//  void * __ptr64 __cdecl try_get_function(enum `anonymous namespace'::function_id,char const *
// __ptr64 const,enum A0x391cf84c::module_id const * __ptr64 const,enum A0x391cf84c::module_id const
// * __ptr64 const)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

FARPROC try_get_function(uint param_1, LPCSTR param_2, uint *param_3, uint *param_4)
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
  bVar2 = (byte)DAT_1800ee160 & 0x3f;
  pFVar5 = (FARPROC)((DAT_1800ee160 ^ *(ulonglong *)((longlong)&DAT_1801018f8 + uVar7 * 8)) >> bVar2 | (DAT_1800ee160 ^ *(ulonglong *)((longlong)&DAT_1801018f8 + uVar7 * 8)) << 0x40 - bVar2);
  if (pFVar5 != (FARPROC)0xffffffffffffffff)
  {
    if (pFVar5 != (FARPROC)0x0)
    {
      return pFVar5;
    }
    if (param_3 != param_4)
    {
      do
      {
        uVar6 = (ulonglong)*param_3;
        hLibModule = *(HMODULE *)((longlong)&DAT_1801018e0 + uVar6 * 8);
        if (hLibModule == (HMODULE)0x0)
        {
          lpLibFileName = (wchar_t *)(&PTR_u_api_ms_win_core_fibers_l1_1_1_1800c9cf0)[uVar6];
          hLibModule = LoadLibraryExW(lpLibFileName, (HANDLE)0x0, 0x800);
          if (hLibModule == (HMODULE)0x0)
          {
            DVar3 = GetLastError();
            if (((DVar3 == 0x57) && (iVar4 = wcsncmp(lpLibFileName, L"api-ms-", 7), iVar4 != 0)) &&
                (iVar4 = wcsncmp(lpLibFileName, L"ext-ms-", 7), iVar4 != 0))
            {
              hLibModule = LoadLibraryExW(lpLibFileName, (HANDLE)0x0, 0);
            }
            else
            {
              hLibModule = (HMODULE)0x0;
            }
          }
          if (hLibModule != (HMODULE)0x0)
          {
            pHVar1 = *(HMODULE *)((longlong)&DAT_1801018e0 + uVar6 * 8);
            *(HMODULE *)((longlong)&DAT_1801018e0 + uVar6 * 8) = hLibModule;
            if (pHVar1 != (HMODULE)0x0)
            {
              FreeLibrary(hLibModule);
            }
            goto LAB_18004628e;
          }
          *(undefined8 *)((longlong)&DAT_1801018e0 + uVar6 * 8) = 0xffffffffffffffff;
        }
        else
        {
          if (hLibModule != (HMODULE)0xffffffffffffffff)
          {
          LAB_18004628e:
            if (hLibModule != (HMODULE)0x0)
              goto LAB_1800462a9;
          }
        }
        param_3 = param_3 + 1;
      } while (param_3 != param_4);
    }
    hLibModule = (HMODULE)0x0;
  LAB_1800462a9:
    if ((hLibModule != (HMODULE)0x0) &&
        (pFVar5 = GetProcAddress(hLibModule, param_2), pFVar5 != (FARPROC)0x0))
    {
      bVar2 = 0x40 - ((byte)DAT_1800ee160 & 0x3f) & 0x3f;
      *(ulonglong *)((longlong)&DAT_1801018f8 + uVar7 * 8) =
          ((ulonglong)pFVar5 >> bVar2 | (longlong)pFVar5 << 0x40 - bVar2) ^ DAT_1800ee160;
      return pFVar5;
    }
    bVar2 = 0x40 - ((byte)DAT_1800ee160 & 0x3f) & 0x3f;
    *(ulonglong *)((longlong)&DAT_1801018f8 + uVar7 * 8) =
        (0xffffffffffffffffU >> bVar2 | -1 << 0x40 - bVar2) ^ DAT_1800ee160;
  }
  return (FARPROC)0x0;
}

// Library Function - Single Match
//  __vcrt_FlsFree
//
// Library: Visual Studio 2015 Release

void __vcrt_FlsFree(uint param_1)
{
  FARPROC pFVar1;

  pFVar1 = try_get_function(1, "FlsFree", (uint *)&DAT_1800c9dd8, (uint *)"FlsFree");
  if (pFVar1 == (FARPROC)0x0)
  {
    TlsFree(param_1);
  }
  else
  {
    _guard_check_icall();
    (*pFVar1)((ulonglong)param_1);
  }
  return;
}

// Library Function - Single Match
//  __vcrt_FlsGetValue
//
// Library: Visual Studio 2015 Release

void __vcrt_FlsGetValue(uint param_1)
{
  FARPROC pFVar1;

  pFVar1 = try_get_function(2, "FlsGetValue", (uint *)&DAT_1800c9de8, (uint *)"FlsGetValue");
  if (pFVar1 == (FARPROC)0x0)
  {
    TlsGetValue(param_1);
  }
  else
  {
    _guard_check_icall();
    (*pFVar1)((ulonglong)param_1);
  }
  return;
}

// Library Function - Single Match
//  __vcrt_FlsSetValue
//
// Library: Visual Studio 2015 Release

void __vcrt_FlsSetValue(uint param_1, LPVOID param_2)
{
  FARPROC pFVar1;

  pFVar1 = try_get_function(3, "FlsSetValue", (uint *)&DAT_1800c9e00, (uint *)"FlsSetValue");
  if (pFVar1 == (FARPROC)0x0)
  {
    TlsSetValue(param_1, param_2);
  }
  else
  {
    _guard_check_icall();
    (*pFVar1)((ulonglong)param_1, param_2);
  }
  return;
}

// Library Function - Single Match
//  __vcrt_InitializeCriticalSectionEx
//
// Library: Visual Studio 2015 Release

void __vcrt_InitializeCriticalSectionEx(LPCRITICAL_SECTION param_1, uint param_2, uint param_3)
{
  FARPROC pFVar1;

  pFVar1 = try_get_function(4, "InitializeCriticalSectionEx", (uint *)&DAT_1800c9e18,
                            (uint *)"InitializeCriticalSectionEx");
  if (pFVar1 == (FARPROC)0x0)
  {
    InitializeCriticalSectionAndSpinCount(param_1, param_2);
  }
  else
  {
    _guard_check_icall();
    (*pFVar1)(param_1, (ulonglong)param_2, param_3);
  }
  return;
}

// Library Function - Single Match
//  __vcrt_uninitialize_winapi_thunks
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void __vcrt_uninitialize_winapi_thunks(char param_1)
{
  HMODULE hLibModule;
  HMODULE *ppHVar1;

  if (param_1 == '\0')
  {
    ppHVar1 = (HMODULE *)&DAT_1801018e0;
    do
    {
      hLibModule = *ppHVar1;
      if (hLibModule != (HMODULE)0x0)
      {
        if (hLibModule != (HMODULE)0xffffffffffffffff)
        {
          FreeLibrary(hLibModule);
        }
        *ppHVar1 = (HMODULE)0x0;
      }
      ppHVar1 = ppHVar1 + 1;
    } while (ppHVar1 != (HMODULE *)&DAT_1801018f8);
  }
  return;
}

// Library Function - Single Match
//  __vcrt_initialize_pure_virtual_call_handler
//
// Library: Visual Studio 2015 Release

void __vcrt_initialize_pure_virtual_call_handler(void)
{
  byte bVar1;

  bVar1 = 0x40 - ((byte)DAT_1800ee160 & 0x3f) & 0x3f;
  DAT_180101920 = ((ulonglong)(0 >> bVar1) | 0 << 0x40 - bVar1) ^ DAT_1800ee160;
  return;
}

// Library Function - Single Match
//  _CallSettingFrame
//
// Library: Visual Studio

void _CallSettingFrame(void)
{
  code *pcVar1;

  pcVar1 = (code *)FUN_18003e8d0();
  (*pcVar1)();
  FUN_18003e900();
  FUN_18003e8d0();
  return;
}

// Library Function - Single Match
//  __DestructExceptionObject
//
// Library: Visual Studio 2015 Release

void __DestructExceptionObject(int *param_1)
{
  byte *pbVar1;
  longlong *plVar2;
  code *pcVar3;

  if ((((param_1 != (int *)0x0) && (*param_1 == -0x1f928c9d)) && (param_1[6] == 4)) &&
      ((param_1[8] + 0xe66cfae0U < 3 && (pbVar1 = *(byte **)(param_1 + 0xc), pbVar1 != (byte *)0x0))))
  {
    if (*(int *)(pbVar1 + 4) == 0)
    {
      if (((*pbVar1 & 0x10) != 0) &&
          (plVar2 = **(longlong ***)(param_1 + 10), plVar2 != (longlong *)0x0))
      {
        pcVar3 = *(code **)(*plVar2 + 0x10);
        _guard_check_icall();
        (*pcVar3)(plVar2);
      }
    }
    else
    {
      FUN_180046974(*(undefined8 *)(param_1 + 10),
                    (undefined *)((longlong) * (int *)(pbVar1 + 4) + *(longlong *)(param_1 + 0xe)));
    }
  }
  return;
}

// Library Function - Single Match
//  _IsExceptionObjectToBeDestroyed
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 _IsExceptionObjectToBeDestroyed(longlong param_1)
{
  longlong lVar1;
  longlong *plVar2;

  lVar1 = __vcrt_getptd();
  plVar2 = *(longlong **)(lVar1 + 0x58);
  while (true)
  {
    if (plVar2 == (longlong *)0x0)
    {
      return 1;
    }
    if (*plVar2 == param_1)
      break;
    plVar2 = (longlong *)plVar2[1];
  }
  return 0;
}

// Library Function - Single Match
//  __AdjustPointer
//
// Library: Visual Studio 2015 Release

longlong __AdjustPointer(longlong param_1, int *param_2)
{
  longlong lVar1;

  lVar1 = *param_2 + param_1;
  if (-1 < param_2[1])
  {
    lVar1 = lVar1 + (longlong) * (int *)((longlong)param_2[2] + *(longlong *)(param_2[1] + param_1)) +
            (longlong)param_2[1];
  }
  return lVar1;
}

// Library Function - Single Match
//  __FrameUnwindFilter
//
// Library: Visual Studio 2017 Release

undefined8 __FrameUnwindFilter(int **param_1)
{
  int *piVar1;
  code *pcVar2;
  longlong lVar3;
  undefined8 uVar4;

  piVar1 = *param_1;
  if ((*piVar1 == -0x1fbcbcae) || (*piVar1 == -0x1fbcb0b3))
  {
    lVar3 = __vcrt_getptd();
    if (0 < *(int *)(lVar3 + 0x30))
    {
      lVar3 = __vcrt_getptd();
      *(int *)(lVar3 + 0x30) = *(int *)(lVar3 + 0x30) + -1;
    }
  }
  else
  {
    if (*piVar1 == -0x1f928c9d)
    {
      lVar3 = __vcrt_getptd();
      *(undefined4 *)(lVar3 + 0x30) = 0;
      FUN_180064ea0();
      pcVar2 = (code *)swi(3);
      uVar4 = (*pcVar2)();
      return uVar4;
    }
  }
  return 0;
}

// Library Function - Single Match
//  __GetPlatformExceptionInfo
//
// Library: Visual Studio 2015 Release

undefined8 __GetPlatformExceptionInfo(undefined4 *param_1)
{
  longlong lVar1;
  undefined8 uVar2;
  int *local_18;
  undefined8 local_10;

  *param_1 = 0;
  lVar1 = __vcrt_getptd();
  local_18 = *(int **)(lVar1 + 0x20);
  if ((local_18 != (int *)0x0) && (*(byte **)(local_18 + 0xc) != (byte *)0x0))
  {
    if ((**(byte **)(local_18 + 0xc) & 0x10) != 0)
    {
      return *(undefined8 *)(**(longlong **)(local_18 + 10) + -8);
    }
    local_10 = 0;
    uVar2 = _is_exception_typeof((longlong)&class_std__bad_alloc_RTTI_Type_Descriptor, &local_18);
    *param_1 = (int)uVar2;
  }
  return 0;
}

// Library Function - Single Match
//  _is_exception_typeof
//
// Library: Visual Studio 2015 Release

undefined8 _is_exception_typeof(longlong param_1, int **param_2)
{
  char cVar1;
  char cVar2;
  int *piVar3;
  longlong lVar4;
  code *pcVar5;
  char *pcVar6;
  undefined8 uVar7;
  int iVar8;
  int *piVar9;

  if (param_2 == (int **)0x0)
  {
    FUN_180064ea0();
    pcVar5 = (code *)swi(3);
    uVar7 = (*pcVar5)();
    return uVar7;
  }
  piVar3 = *param_2;
  if (piVar3 == (int *)0x0)
  {
    FUN_180064ea0();
    pcVar5 = (code *)swi(3);
    uVar7 = (*pcVar5)();
    return uVar7;
  }
  if (((*piVar3 != -0x1f928c9d) || (piVar3[6] != 4)) || (2 < piVar3[8] + 0xe66cfae0U))
  {
    FUN_180064ea0();
    pcVar5 = (code *)swi(3);
    uVar7 = (*pcVar5)();
    return uVar7;
  }
  lVar4 = *(longlong *)(piVar3 + 0xe);
  piVar9 = (int *)(lVar4 + 4 + (longlong) * (int *)(*(longlong *)(piVar3 + 0xc) + 0xc));
  iVar8 = *(int *)(*(int *)(*(longlong *)(piVar3 + 0xc) + 0xc) + lVar4);
  if (0 < iVar8)
  {
    do
    {
      pcVar6 = (char *)(param_1 + 0x10);
      do
      {
        cVar1 = *pcVar6;
        cVar2 = pcVar6[(lVar4 + 0x10 + (longlong) * (int *)((longlong)*piVar9 + 4 + lVar4)) -
                       (longlong)(char *)(param_1 + 0x10)];
        if (cVar1 != cVar2)
          break;
        pcVar6 = pcVar6 + 1;
      } while (cVar2 != '\0');
      if (cVar1 == cVar2)
      {
        return 1;
      }
      iVar8 = iVar8 + -1;
      piVar9 = piVar9 + 1;
    } while (0 < iVar8);
  }
  return 0;
}

// Library Function - Single Match
//  wcslen
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

size_t wcslen(wchar_t *_Str)
{
  undefined auVar1[16];
  int iVar2;
  uint uVar3;
  size_t sVar5;
  wchar_t *pwVar6;
  undefined(*pauVar7)[32];
  ulonglong uVar8;
  undefined in_YMM1[32];
  wchar_t *pwVar4;

  pauVar7 = (undefined(*)[32])_Str;
  if (DAT_1800ee178 < 5)
  {
    if (DAT_1800ee178 < 1)
    {
      while (*(short *)*pauVar7 != 0)
      {
        pauVar7 = (undefined(*)[32])(*pauVar7 + 2);
      }
    }
    else
    {
      if (((ulonglong)_Str & 1) == 0)
      {
        uVar8 = (ulonglong)((uint)_Str & 0xf);
        uVar8 = -(ulonglong)(uVar8 != 0) & 0x10 - uVar8;
        pwVar4 = (wchar_t *)((longlong)_Str + (uVar8 & 0xfffffffffffffffe));
        pwVar6 = _Str;
        if (_Str != pwVar4)
        {
          do
          {
            if (*pwVar6 == L'\0')
              break;
            pwVar6 = pwVar6 + 1;
          } while (pwVar6 != pwVar4);
        }
        sVar5 = (longlong)((longlong)pwVar6 - (longlong)_Str) >> 1;
        if (sVar5 != uVar8 >> 1)
        {
          return sVar5;
        }
        pauVar7 = (undefined(*)[32])(_Str + sVar5);
        while (true)
        {
          uVar3 = pmovmskb((int)pwVar4,
                           CONCAT214(-(ushort)(*(short *)(*pauVar7 + 0xe) == 0),
                                     CONCAT212(-(ushort)(*(short *)(*pauVar7 + 0xc) == 0),
                                               CONCAT210(-(ushort)(*(short *)(*pauVar7 + 10) == 0),
                                                         CONCAT28(-(ushort)(*(short *)(*pauVar7 + 8) == 0),
                                                                  CONCAT26(-(ushort)(*(short *)(*pauVar7 + 6) == 0),
                                                                           CONCAT24(-(ushort)(*(short *)(*pauVar7 + 4) == 0),
                                                                                    CONCAT22(-(ushort)(*(short *)(*pauVar7 +
                                                                                                                  2) == 0),
                                                                                             -(ushort)(*(short *)*pauVar7 ==
                                                                                                       0)))))))));
          pwVar4 = (wchar_t *)(ulonglong)uVar3;
          if (uVar3 != 0)
            break;
          pauVar7 = (undefined(*)[32])(*pauVar7 + 0x10);
        }
        while (*(short *)*pauVar7 != 0)
        {
          pauVar7 = (undefined(*)[32])(*pauVar7 + 2);
        }
      }
      else
      {
        while (*(short *)*pauVar7 != 0)
        {
          pauVar7 = (undefined(*)[32])(*pauVar7 + 2);
        }
      }
    }
  }
  else
  {
    if (((ulonglong)_Str & 1) == 0)
    {
      uVar8 = (ulonglong)((uint)_Str & 0x1f);
      uVar8 = -(ulonglong)(uVar8 != 0) & 0x20 - uVar8;
      pwVar4 = (wchar_t *)((longlong)_Str + (uVar8 & 0xfffffffffffffffe));
      pwVar6 = _Str;
      if (_Str != pwVar4)
      {
        do
        {
          if (*pwVar6 == L'\0')
            break;
          pwVar6 = pwVar6 + 1;
        } while (pwVar6 != pwVar4);
      }
      sVar5 = (longlong)((longlong)pwVar6 - (longlong)_Str) >> 1;
      if (sVar5 != uVar8 >> 1)
      {
        return sVar5;
      }
      pauVar7 = (undefined(*)[32])(_Str + sVar5);
      while (true)
      {
        auVar1 = vpxor_avx(SUB3216(in_YMM1, 0), SUB3216(in_YMM1, 0));
        in_YMM1 = vpcmpeqw_avx2(ZEXT1632(auVar1), *pauVar7);
        iVar2 = vpmovmskb_avx2(in_YMM1);
        vzeroupper_avx();
        if (iVar2 != 0)
          break;
        pauVar7 = pauVar7[1];
      }
      while (*(short *)*pauVar7 != 0)
      {
        pauVar7 = (undefined(*)[32])(*pauVar7 + 2);
      }
    }
    else
    {
      while (*(short *)*pauVar7 != 0)
      {
        pauVar7 = (undefined(*)[32])(*pauVar7 + 2);
      }
    }
  }
  return (longlong)((longlong)pauVar7 - (longlong)_Str) >> 1;
}

// Library Function - Single Match
//  strlen
//
// Library: Visual Studio

size_t strlen(char *_Str)
{
  char cVar1;
  ulonglong uVar2;
  ulonglong *puVar3;
  longlong lVar4;

  lVar4 = -(longlong)_Str;
  uVar2 = (ulonglong)_Str & 7;
  while (uVar2 != 0)
  {
    cVar1 = *_Str;
    _Str = (char *)((longlong)_Str + 1);
    if (cVar1 == '\0')
      goto LAB_180047a38;
    uVar2 = (ulonglong)_Str & 7;
  }
  do
  {
    do
    {
      puVar3 = (ulonglong *)_Str;
      _Str = (char *)(puVar3 + 1);
    } while (((~*puVar3 ^ *puVar3 + 0x7efefefefefefeff) & 0x8101010101010100) == 0);
    uVar2 = *puVar3;
    if ((char)uVar2 == '\0')
    {
      return lVar4 + -8 + (longlong)_Str;
    }
    if ((char)(uVar2 >> 8) == '\0')
    {
      return lVar4 + -7 + (longlong)_Str;
    }
    if ((char)(uVar2 >> 0x10) == '\0')
    {
      return lVar4 + -6 + (longlong)_Str;
    }
    if ((char)(uVar2 >> 0x18) == '\0')
    {
      return lVar4 + -5 + (longlong)_Str;
    }
    if ((char)(uVar2 >> 0x20) == '\0')
    {
      return lVar4 + -4 + (longlong)_Str;
    }
    if ((char)(uVar2 >> 0x28) == '\0')
    {
      return lVar4 + -3 + (longlong)_Str;
    }
    if ((char)(uVar2 >> 0x30) == '\0')
    {
      return lVar4 + -2 + (longlong)_Str;
    }
  } while ((char)(uVar2 >> 0x38) != '\0');
LAB_180047a38:
  return lVar4 + -1 + (longlong)_Str;
}

// Library Function - Multiple Matches With Different Base Names
//  protected: __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>><class
// __crt_stdio_output::stream_output_adapter<char> const & __ptr64,unsigned __int64 const &
// __ptr64,char const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::stream_output_adapter<char>
// const & __ptr64,unsigned __int64 const & __ptr64,char const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//  protected: __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>><class
// __crt_stdio_output::string_output_adapter<char> const & __ptr64,unsigned __int64 const &
// __ptr64,char const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::string_output_adapter<char>
// const & __ptr64,unsigned __int64 const & __ptr64,char const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 *

FID_conflict_positional_parameter_base_char_class___crt_stdio_output__stream_output_adapter_char____class___crt_stdio_output__stream_output_adapter_char__const____ptr64_unsigned___int64_const____ptr64_char_const____ptr64_const____ptr64_struct___crt_locale_pointers____ptr64_const____ptr64_char____ptr64_const____ptr64_(undefined8 *param_1, undefined8 *param_2, undefined8 *param_3, undefined8 *param_4,
                                                                                                                                                                                                                                                                                                                               undefined8 *param_5, undefined8 *param_6)
{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;

  uVar1 = *param_4;
  uVar2 = *param_3;
  uVar3 = *param_6;
  uVar4 = *param_5;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *(undefined4 *)(param_1 + 7) = 0;
  *(undefined2 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 10) = 0;
  *(undefined *)((longlong)param_1 + 0x54) = 0;
  param_1[0x8b] = 0;
  param_1[0x8c] = 0;
  param_1[0x8d] = *param_2;
  *(undefined4 *)(param_1 + 0x1bd) = 0xffffffff;
  *(undefined4 *)((longlong)param_1 + 0xdec) = 0xffffffff;
  param_1[3] = uVar1;
  param_1[0x90] = uVar1;
  *param_1 = uVar2;
  param_1[1] = uVar4;
  param_1[4] = uVar3;
  *(undefined4 *)(param_1 + 0x8e) = 0;
  param_1[0x8f] = 0;
  return param_1;
}

// Library Function - Multiple Matches With Different Base Names
//  protected: __cdecl __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>><class
// __crt_stdio_output::stream_output_adapter<wchar_t> const & __ptr64,unsigned __int64 const &
// __ptr64,wchar_t const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::stream_output_adapter<wchar_t>
// const & __ptr64,unsigned __int64 const & __ptr64,wchar_t const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//  protected: __cdecl __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>><class
// __crt_stdio_output::stream_output_adapter<wchar_t> const & __ptr64,unsigned __int64 const &
// __ptr64,wchar_t const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::stream_output_adapter<wchar_t>
// const & __ptr64,unsigned __int64 const & __ptr64,wchar_t const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//  protected: __cdecl __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::format_validation_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>><class
// __crt_stdio_output::string_output_adapter<wchar_t> const & __ptr64,unsigned __int64 const &
// __ptr64,wchar_t const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::string_output_adapter<wchar_t>
// const & __ptr64,unsigned __int64 const & __ptr64,wchar_t const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//  protected: __cdecl __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::standard_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>><class
// __crt_stdio_output::string_output_adapter<wchar_t> const & __ptr64,unsigned __int64 const &
// __ptr64,wchar_t const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::string_output_adapter<wchar_t>
// const & __ptr64,unsigned __int64 const & __ptr64,wchar_t const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 *

FID_conflict_format_validation_base_wchar_t_class___crt_stdio_output__string_output_adapter_wchar_t____class___crt_stdio_output__string_output_adapter_wchar_t__const____ptr64_unsigned___int64_const____ptr64_wchar_t_const____ptr64_const____ptr64_struct___crt_locale_pointers____ptr64_const____ptr64_char____ptr64_const____ptr64_(undefined8 *param_1, undefined8 *param_2, undefined8 *param_3, undefined8 *param_4,
                                                                                                                                                                                                                                                                                                                                        undefined8 *param_5, undefined8 *param_6)
{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;

  uVar1 = *param_4;
  uVar2 = *param_3;
  uVar3 = *param_6;
  uVar4 = *param_5;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *(undefined4 *)(param_1 + 7) = 0;
  *(undefined *)(param_1 + 8) = 0;
  *(undefined2 *)((longlong)param_1 + 0x42) = 0;
  *(undefined4 *)(param_1 + 10) = 0;
  *(undefined *)((longlong)param_1 + 0x54) = 0;
  param_1[0x8b] = 0;
  param_1[0x8c] = 0;
  param_1[0x8d] = *param_2;
  param_1[4] = uVar3;
  *param_1 = uVar2;
  param_1[1] = uVar4;
  param_1[3] = uVar1;
  *(undefined4 *)(param_1 + 0x8e) = 0;
  return param_1;
}

// Library Function - Multiple Matches With Different Base Names
//  protected: __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>><class
// __crt_stdio_output::stream_output_adapter<wchar_t> const & __ptr64,unsigned __int64 const &
// __ptr64,wchar_t const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::stream_output_adapter<wchar_t>
// const & __ptr64,unsigned __int64 const & __ptr64,wchar_t const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//  protected: __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>><class
// __crt_stdio_output::string_output_adapter<wchar_t> const & __ptr64,unsigned __int64 const &
// __ptr64,wchar_t const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::string_output_adapter<wchar_t>
// const & __ptr64,unsigned __int64 const & __ptr64,wchar_t const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 *

FID_conflict_positional_parameter_base_wchar_t_class___crt_stdio_output__string_output_adapter_wchar_t____class___crt_stdio_output__string_output_adapter_wchar_t__const____ptr64_unsigned___int64_const____ptr64_wchar_t_const____ptr64_const____ptr64_struct___crt_locale_pointers____ptr64_const____ptr64_char____ptr64_const____ptr64_(undefined8 *param_1, undefined8 *param_2, undefined8 *param_3, undefined8 *param_4,
                                                                                                                                                                                                                                                                                                                                           undefined8 *param_5, undefined8 *param_6)
{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;

  uVar1 = *param_4;
  uVar2 = *param_3;
  uVar3 = *param_6;
  uVar4 = *param_5;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *(undefined4 *)(param_1 + 7) = 0;
  *(undefined *)(param_1 + 8) = 0;
  *(undefined2 *)((longlong)param_1 + 0x42) = 0;
  *(undefined4 *)(param_1 + 10) = 0;
  *(undefined *)((longlong)param_1 + 0x54) = 0;
  param_1[0x8b] = 0;
  param_1[0x8c] = 0;
  param_1[0x8d] = *param_2;
  *(undefined4 *)(param_1 + 0x1bd) = 0xffffffff;
  *(undefined4 *)((longlong)param_1 + 0xdec) = 0xffffffff;
  param_1[3] = uVar1;
  param_1[0x90] = uVar1;
  *param_1 = uVar2;
  param_1[1] = uVar4;
  param_1[4] = uVar3;
  *(undefined4 *)(param_1 + 0x8e) = 0;
  param_1[0x8f] = 0;
  return param_1;
}

// Library Function - Multiple Matches With Different Base Names
//  protected: __cdecl __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>><class
// __crt_stdio_output::stream_output_adapter<char> const & __ptr64,unsigned __int64 const &
// __ptr64,char const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::stream_output_adapter<char>
// const & __ptr64,unsigned __int64 const & __ptr64,char const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//  protected: __cdecl __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>><class
// __crt_stdio_output::stream_output_adapter<char> const & __ptr64,unsigned __int64 const &
// __ptr64,char const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::stream_output_adapter<char>
// const & __ptr64,unsigned __int64 const & __ptr64,char const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//  protected: __cdecl __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::format_validation_base<char,class
// __crt_stdio_output::string_output_adapter<char>><class
// __crt_stdio_output::string_output_adapter<char> const & __ptr64,unsigned __int64 const &
// __ptr64,char const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::string_output_adapter<char>
// const & __ptr64,unsigned __int64 const & __ptr64,char const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//  protected: __cdecl __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::standard_base<char,class
// __crt_stdio_output::string_output_adapter<char>><class
// __crt_stdio_output::string_output_adapter<char> const & __ptr64,unsigned __int64 const &
// __ptr64,char const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::string_output_adapter<char>
// const & __ptr64,unsigned __int64 const & __ptr64,char const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 *

FID_conflict_standard_base_char_class___crt_stdio_output__stream_output_adapter_char____class___crt_stdio_output__stream_output_adapter_char__const____ptr64_unsigned___int64_const____ptr64_char_const____ptr64_const____ptr64_struct___crt_locale_pointers____ptr64_const____ptr64_char____ptr64_const____ptr64_(undefined8 *param_1, undefined8 *param_2, undefined8 *param_3, undefined8 *param_4,
                                                                                                                                                                                                                                                                                                                   undefined8 *param_5, undefined8 *param_6)
{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;

  uVar1 = *param_4;
  uVar2 = *param_3;
  uVar3 = *param_6;
  uVar4 = *param_5;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *(undefined4 *)(param_1 + 7) = 0;
  *(undefined2 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 10) = 0;
  *(undefined *)((longlong)param_1 + 0x54) = 0;
  param_1[0x8b] = 0;
  param_1[0x8c] = 0;
  param_1[0x8d] = *param_2;
  param_1[4] = uVar3;
  *param_1 = uVar2;
  param_1[1] = uVar4;
  param_1[3] = uVar1;
  *(undefined4 *)(param_1 + 0x8e) = 0;
  return param_1;
}

// Library Function - Multiple Matches With Different Base Names
//  protected: __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>><class
// __crt_stdio_output::stream_output_adapter<char> const & __ptr64,unsigned __int64 const &
// __ptr64,char const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::stream_output_adapter<char>
// const & __ptr64,unsigned __int64 const & __ptr64,char const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//  protected: __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>><class
// __crt_stdio_output::string_output_adapter<char> const & __ptr64,unsigned __int64 const &
// __ptr64,char const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::string_output_adapter<char>
// const & __ptr64,unsigned __int64 const & __ptr64,char const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 *

FID_conflict_positional_parameter_base_char_class___crt_stdio_output__stream_output_adapter_char____class___crt_stdio_output__stream_output_adapter_char__const____ptr64_unsigned___int64_const____ptr64_char_const____ptr64_const____ptr64_struct___crt_locale_pointers____ptr64_const____ptr64_char____ptr64_const____ptr64_(undefined8 *param_1, undefined8 *param_2, undefined8 *param_3, undefined8 *param_4,
                                                                                                                                                                                                                                                                                                                               undefined8 *param_5, undefined8 *param_6)
{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;

  uVar1 = *param_4;
  uVar2 = *param_3;
  uVar3 = *param_6;
  uVar4 = *param_5;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *(undefined4 *)(param_1 + 7) = 0;
  *(undefined2 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 10) = 0;
  *(undefined *)((longlong)param_1 + 0x54) = 0;
  param_1[0x8b] = 0;
  param_1[0x8c] = 0;
  param_1[0x8d] = *param_2;
  *(undefined4 *)(param_1 + 0x1bd) = 0xffffffff;
  *(undefined4 *)((longlong)param_1 + 0xdec) = 0xffffffff;
  param_1[3] = uVar1;
  param_1[0x90] = uVar1;
  *param_1 = uVar2;
  param_1[1] = uVar4;
  param_1[4] = uVar3;
  *(undefined4 *)(param_1 + 0x8e) = 0;
  param_1[0x8f] = 0;
  return param_1;
}

// Library Function - Multiple Matches With Different Base Names
//  protected: __cdecl __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>><class
// __crt_stdio_output::stream_output_adapter<wchar_t> const & __ptr64,unsigned __int64 const &
// __ptr64,wchar_t const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::stream_output_adapter<wchar_t>
// const & __ptr64,unsigned __int64 const & __ptr64,wchar_t const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//  protected: __cdecl __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>><class
// __crt_stdio_output::stream_output_adapter<wchar_t> const & __ptr64,unsigned __int64 const &
// __ptr64,wchar_t const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::stream_output_adapter<wchar_t>
// const & __ptr64,unsigned __int64 const & __ptr64,wchar_t const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//  protected: __cdecl __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::format_validation_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>><class
// __crt_stdio_output::string_output_adapter<wchar_t> const & __ptr64,unsigned __int64 const &
// __ptr64,wchar_t const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::string_output_adapter<wchar_t>
// const & __ptr64,unsigned __int64 const & __ptr64,wchar_t const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//  protected: __cdecl __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::standard_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>><class
// __crt_stdio_output::string_output_adapter<wchar_t> const & __ptr64,unsigned __int64 const &
// __ptr64,wchar_t const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::string_output_adapter<wchar_t>
// const & __ptr64,unsigned __int64 const & __ptr64,wchar_t const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 *

FID_conflict_format_validation_base_wchar_t_class___crt_stdio_output__string_output_adapter_wchar_t____class___crt_stdio_output__string_output_adapter_wchar_t__const____ptr64_unsigned___int64_const____ptr64_wchar_t_const____ptr64_const____ptr64_struct___crt_locale_pointers____ptr64_const____ptr64_char____ptr64_const____ptr64_(undefined8 *param_1, undefined8 *param_2, undefined8 *param_3, undefined8 *param_4,
                                                                                                                                                                                                                                                                                                                                        undefined8 *param_5, undefined8 *param_6)
{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;

  uVar1 = *param_4;
  uVar2 = *param_3;
  uVar3 = *param_6;
  uVar4 = *param_5;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *(undefined4 *)(param_1 + 7) = 0;
  *(undefined *)(param_1 + 8) = 0;
  *(undefined2 *)((longlong)param_1 + 0x42) = 0;
  *(undefined4 *)(param_1 + 10) = 0;
  *(undefined *)((longlong)param_1 + 0x54) = 0;
  param_1[0x8b] = 0;
  param_1[0x8c] = 0;
  param_1[0x8d] = *param_2;
  param_1[4] = uVar3;
  *param_1 = uVar2;
  param_1[1] = uVar4;
  param_1[3] = uVar1;
  *(undefined4 *)(param_1 + 0x8e) = 0;
  return param_1;
}

// Library Function - Multiple Matches With Different Base Names
//  protected: __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>><class
// __crt_stdio_output::stream_output_adapter<wchar_t> const & __ptr64,unsigned __int64 const &
// __ptr64,wchar_t const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::stream_output_adapter<wchar_t>
// const & __ptr64,unsigned __int64 const & __ptr64,wchar_t const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//  protected: __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>><class
// __crt_stdio_output::string_output_adapter<wchar_t> const & __ptr64,unsigned __int64 const &
// __ptr64,wchar_t const * __ptr64 const & __ptr64,struct __crt_locale_pointers * __ptr64 const &
// __ptr64,char * __ptr64 const & __ptr64>(class __crt_stdio_output::string_output_adapter<wchar_t>
// const & __ptr64,unsigned __int64 const & __ptr64,wchar_t const * __ptr64 const & __ptr64,struct
// __crt_locale_pointers * __ptr64 const & __ptr64,char * __ptr64 const & __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 *

FID_conflict_positional_parameter_base_wchar_t_class___crt_stdio_output__string_output_adapter_wchar_t____class___crt_stdio_output__string_output_adapter_wchar_t__const____ptr64_unsigned___int64_const____ptr64_wchar_t_const____ptr64_const____ptr64_struct___crt_locale_pointers____ptr64_const____ptr64_char____ptr64_const____ptr64_(undefined8 *param_1, undefined8 *param_2, undefined8 *param_3, undefined8 *param_4,
                                                                                                                                                                                                                                                                                                                                           undefined8 *param_5, undefined8 *param_6)
{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;

  uVar1 = *param_4;
  uVar2 = *param_3;
  uVar3 = *param_6;
  uVar4 = *param_5;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *(undefined4 *)(param_1 + 7) = 0;
  *(undefined *)(param_1 + 8) = 0;
  *(undefined2 *)((longlong)param_1 + 0x42) = 0;
  *(undefined4 *)(param_1 + 10) = 0;
  *(undefined *)((longlong)param_1 + 0x54) = 0;
  param_1[0x8b] = 0;
  param_1[0x8c] = 0;
  param_1[0x8d] = *param_2;
  *(undefined4 *)(param_1 + 0x1bd) = 0xffffffff;
  *(undefined4 *)((longlong)param_1 + 0xdec) = 0xffffffff;
  param_1[3] = uVar1;
  param_1[0x90] = uVar1;
  *param_1 = uVar2;
  param_1[1] = uVar4;
  param_1[4] = uVar3;
  *(undefined4 *)(param_1 + 0x8e) = 0;
  param_1[0x8f] = 0;
  return param_1;
}

// Library Function - Multiple Matches With Same Base Name
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_0d412022a4b28cc8a401ea49574e8ae6>,class <lambda_a775ed57af18ba8e4d5dc780aa9068fe>&
// __ptr64,class <lambda_975a71a6baa488a08f4e15f6b0339b9e>>(class
// <lambda_0d412022a4b28cc8a401ea49574e8ae6>&& __ptr64,class
// <lambda_a775ed57af18ba8e4d5dc780aa9068fe>& __ptr64,class
// <lambda_975a71a6baa488a08f4e15f6b0339b9e>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_63c71d947f2ce890aa4aac7392f1cbed>,class <lambda_e3269ba96939e7713c73908c0d757d25>&
// __ptr64,class <lambda_3776af017df72547960a8ac98bb265e7>>(class
// <lambda_63c71d947f2ce890aa4aac7392f1cbed>&& __ptr64,class
// <lambda_e3269ba96939e7713c73908c0d757d25>& __ptr64,class
// <lambda_3776af017df72547960a8ac98bb265e7>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_676bd5779251ec186b530f0a904b4b35>,class <lambda_b579ea784fd840951dfbcbdaebf709fd>&
// __ptr64,class <lambda_10027885da78ada7fb00668d7e2e96b5>>(class
// <lambda_676bd5779251ec186b530f0a904b4b35>&& __ptr64,class
// <lambda_b579ea784fd840951dfbcbdaebf709fd>& __ptr64,class
// <lambda_10027885da78ada7fb00668d7e2e96b5>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_e823f95267a816de70ce630183b86bc2>,class <lambda_7e489fec146d5348dbc86d3cce37c1b5>&
// __ptr64,class <lambda_57931389d27d3dce8b0bd13c3d0d8333>>(class
// <lambda_e823f95267a816de70ce630183b86bc2>&& __ptr64,class
// <lambda_7e489fec146d5348dbc86d3cce37c1b5>& __ptr64,class
// <lambda_57931389d27d3dce8b0bd13c3d0d8333>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 operator____(undefined8 param_1, longlong *param_2, FILE **param_3, longlong *param_4)
{
  undefined4 uVar1;

  FUN_1800625f0(*param_2);
  uVar1 = FID_conflict_operator__(param_3);
  FUN_1800625fc(*param_4);
  return uVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_55577cdf4457e05136e8c1bc6549f697>,class <lambda_ee59099aa97e0ff6f003b984c1584058>&
// __ptr64,class <lambda_cd4250c7ac9eb50c05cf8bb6b444cf42>>(class
// <lambda_55577cdf4457e05136e8c1bc6549f697>&& __ptr64,class
// <lambda_ee59099aa97e0ff6f003b984c1584058>& __ptr64,class
// <lambda_cd4250c7ac9eb50c05cf8bb6b444cf42>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_8be82e0ce9ca3860586e20edfb7a650e>,class <lambda_673ffc0dc9412a0afcf2088e0e1b9bdc>&
// __ptr64,class <lambda_c997b1ad71a4c19edf3d1d12a5864641>>(class
// <lambda_8be82e0ce9ca3860586e20edfb7a650e>&& __ptr64,class
// <lambda_673ffc0dc9412a0afcf2088e0e1b9bdc>& __ptr64,class
// <lambda_c997b1ad71a4c19edf3d1d12a5864641>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int operator____(undefined8 param_1, longlong *param_2,
                 _lambda_ee59099aa97e0ff6f003b984c1584058_ *param_3, longlong *param_4)
{
  int iVar1;

  FUN_1800625f0(*param_2);
  iVar1 = <lambda_ee59099aa97e0ff6f003b984c1584058>::operator__(param_3);
  FUN_1800625fc(*param_4);
  return iVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_74b93660f2d9eb3fb15c5de9eff9db7b>,class <lambda_32f117a32e8f8eb613cbf2ca819ed45e>&
// __ptr64,class <lambda_7322894ee7c8a2d41153fedefeab09e3>>(class
// <lambda_74b93660f2d9eb3fb15c5de9eff9db7b>&& __ptr64,class
// <lambda_32f117a32e8f8eb613cbf2ca819ed45e>& __ptr64,class
// <lambda_7322894ee7c8a2d41153fedefeab09e3>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_a62c933ada0517137acf5807a1eeac1f>,class <lambda_a31071773b9a94e445cbd5d04ef99106>&
// __ptr64,class <lambda_56065050dbf3ada7e59a83db45153de3>>(class
// <lambda_a62c933ada0517137acf5807a1eeac1f>&& __ptr64,class
// <lambda_a31071773b9a94e445cbd5d04ef99106>& __ptr64,class
// <lambda_56065050dbf3ada7e59a83db45153de3>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_d1b8e9147f7260ae436300a3cb83e6d4>,class <lambda_e638437c4db75b75056fab6aaf7e4f15>&
// __ptr64,class <lambda_8c9f37a989ed2ac074735e5b535e306a>>(class
// <lambda_d1b8e9147f7260ae436300a3cb83e6d4>&& __ptr64,class
// <lambda_e638437c4db75b75056fab6aaf7e4f15>& __ptr64,class
// <lambda_8c9f37a989ed2ac074735e5b535e306a>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_fe5404e9642edbb7c8ae71e1dcfa4018>,class <lambda_36eeb330e99a4f0bf8a7da86d0894cb9>&
// __ptr64,class <lambda_2fa474834de80dc12f7a3c6eddd7a366>>(class
// <lambda_fe5404e9642edbb7c8ae71e1dcfa4018>&& __ptr64,class
// <lambda_36eeb330e99a4f0bf8a7da86d0894cb9>& __ptr64,class
// <lambda_2fa474834de80dc12f7a3c6eddd7a366>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 operator____(undefined8 param_1, longlong *param_2, FILE **param_3, longlong *param_4)
{
  undefined4 uVar1;

  FUN_1800625f0(*param_2);
  uVar1 = FID_conflict_operator__(param_3);
  FUN_1800625fc(*param_4);
  return uVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_74b93660f2d9eb3fb15c5de9eff9db7b>,class <lambda_32f117a32e8f8eb613cbf2ca819ed45e>&
// __ptr64,class <lambda_7322894ee7c8a2d41153fedefeab09e3>>(class
// <lambda_74b93660f2d9eb3fb15c5de9eff9db7b>&& __ptr64,class
// <lambda_32f117a32e8f8eb613cbf2ca819ed45e>& __ptr64,class
// <lambda_7322894ee7c8a2d41153fedefeab09e3>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_a62c933ada0517137acf5807a1eeac1f>,class <lambda_a31071773b9a94e445cbd5d04ef99106>&
// __ptr64,class <lambda_56065050dbf3ada7e59a83db45153de3>>(class
// <lambda_a62c933ada0517137acf5807a1eeac1f>&& __ptr64,class
// <lambda_a31071773b9a94e445cbd5d04ef99106>& __ptr64,class
// <lambda_56065050dbf3ada7e59a83db45153de3>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_d1b8e9147f7260ae436300a3cb83e6d4>,class <lambda_e638437c4db75b75056fab6aaf7e4f15>&
// __ptr64,class <lambda_8c9f37a989ed2ac074735e5b535e306a>>(class
// <lambda_d1b8e9147f7260ae436300a3cb83e6d4>&& __ptr64,class
// <lambda_e638437c4db75b75056fab6aaf7e4f15>& __ptr64,class
// <lambda_8c9f37a989ed2ac074735e5b535e306a>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_fe5404e9642edbb7c8ae71e1dcfa4018>,class <lambda_36eeb330e99a4f0bf8a7da86d0894cb9>&
// __ptr64,class <lambda_2fa474834de80dc12f7a3c6eddd7a366>>(class
// <lambda_fe5404e9642edbb7c8ae71e1dcfa4018>&& __ptr64,class
// <lambda_36eeb330e99a4f0bf8a7da86d0894cb9>& __ptr64,class
// <lambda_2fa474834de80dc12f7a3c6eddd7a366>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 operator____(undefined8 param_1, longlong *param_2, FILE **param_3, longlong *param_4)
{
  undefined4 uVar1;

  FUN_1800625f0(*param_2);
  uVar1 = FID_conflict_operator__(param_3);
  FUN_1800625fc(*param_4);
  return uVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_d1aaa8c864b24422b55e9201296d78b9>,class <lambda_a2288fdbbd702c8f223b438290af01a4>&
// __ptr64,class <lambda_4f4c57057ae4c2bc431a3fc6ace2791f>>(class
// <lambda_d1aaa8c864b24422b55e9201296d78b9>&& __ptr64,class
// <lambda_a2288fdbbd702c8f223b438290af01a4>& __ptr64,class
// <lambda_4f4c57057ae4c2bc431a3fc6ace2791f>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_e746820a99d01fe878d2dbd7f1018dff>,class <lambda_a993425e72f5bd8b40f5859286f153c4>&
// __ptr64,class <lambda_4dad5d88921143c78c186dc2683775b0>>(class
// <lambda_e746820a99d01fe878d2dbd7f1018dff>&& __ptr64,class
// <lambda_a993425e72f5bd8b40f5859286f153c4>& __ptr64,class
// <lambda_4dad5d88921143c78c186dc2683775b0>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int operator____(undefined8 param_1, longlong *param_2,
                 _lambda_a2288fdbbd702c8f223b438290af01a4_ *param_3, longlong *param_4)
{
  int iVar1;

  FUN_1800625f0(*param_2);
  iVar1 = <lambda_a2288fdbbd702c8f223b438290af01a4>::operator__(param_3);
  FUN_1800625fc(*param_4);
  return iVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_0d412022a4b28cc8a401ea49574e8ae6>,class <lambda_a775ed57af18ba8e4d5dc780aa9068fe>&
// __ptr64,class <lambda_975a71a6baa488a08f4e15f6b0339b9e>>(class
// <lambda_0d412022a4b28cc8a401ea49574e8ae6>&& __ptr64,class
// <lambda_a775ed57af18ba8e4d5dc780aa9068fe>& __ptr64,class
// <lambda_975a71a6baa488a08f4e15f6b0339b9e>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_63c71d947f2ce890aa4aac7392f1cbed>,class <lambda_e3269ba96939e7713c73908c0d757d25>&
// __ptr64,class <lambda_3776af017df72547960a8ac98bb265e7>>(class
// <lambda_63c71d947f2ce890aa4aac7392f1cbed>&& __ptr64,class
// <lambda_e3269ba96939e7713c73908c0d757d25>& __ptr64,class
// <lambda_3776af017df72547960a8ac98bb265e7>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_676bd5779251ec186b530f0a904b4b35>,class <lambda_b579ea784fd840951dfbcbdaebf709fd>&
// __ptr64,class <lambda_10027885da78ada7fb00668d7e2e96b5>>(class
// <lambda_676bd5779251ec186b530f0a904b4b35>&& __ptr64,class
// <lambda_b579ea784fd840951dfbcbdaebf709fd>& __ptr64,class
// <lambda_10027885da78ada7fb00668d7e2e96b5>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_e823f95267a816de70ce630183b86bc2>,class <lambda_7e489fec146d5348dbc86d3cce37c1b5>&
// __ptr64,class <lambda_57931389d27d3dce8b0bd13c3d0d8333>>(class
// <lambda_e823f95267a816de70ce630183b86bc2>&& __ptr64,class
// <lambda_7e489fec146d5348dbc86d3cce37c1b5>& __ptr64,class
// <lambda_57931389d27d3dce8b0bd13c3d0d8333>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 operator____(undefined8 param_1, longlong *param_2, FILE **param_3, longlong *param_4)
{
  undefined4 uVar1;

  FUN_1800625f0(*param_2);
  uVar1 = FID_conflict_operator__(param_3);
  FUN_1800625fc(*param_4);
  return uVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  int __cdecl __acrt_lock_stream_and_call<class <lambda_0a64b6a4deda75c01876f29c44fc5eb3>>(struct
// _iobuf * __ptr64 const,class <lambda_0a64b6a4deda75c01876f29c44fc5eb3>&& __ptr64)
//  int __cdecl __acrt_lock_stream_and_call<class <lambda_3a6204444a8bad05601fdaf7664f6f17>>(struct
// _iobuf * __ptr64 const,class <lambda_3a6204444a8bad05601fdaf7664f6f17>&& __ptr64)
//  int __cdecl __acrt_lock_stream_and_call<class <lambda_55f9cbce55698c0319f95c01c080475b>>(struct
// _iobuf * __ptr64 const,class <lambda_55f9cbce55698c0319f95c01c080475b>&& __ptr64)
//  int __cdecl __acrt_lock_stream_and_call<class <lambda_576477a770bb5ab586b2d9569451c7f7>>(struct
// _iobuf * __ptr64 const,class <lambda_576477a770bb5ab586b2d9569451c7f7>&& __ptr64)
//   12 names - too many to list
//
// Library: Visual Studio 2015 Release

void __acrt_lock_stream_and_call__(longlong param_1, FILE **param_2)
{
  undefined local_res8[16];
  longlong local_res18;
  longlong local_res20;

  local_res18 = param_1;
  local_res20 = param_1;
  operator____(local_res8, &local_res20, param_2, &local_res18);
  return;
}

// Library Function - Single Match
//  int __cdecl common_vsprintf<class __crt_stdio_output::format_validation_base,char>(unsigned
// __int64,char * __ptr64 const,unsigned __int64,char const * __ptr64 const,struct
// __crt_locale_pointers * __ptr64 const,char * __ptr64 const)
//
// Library: Visual Studio 2017 Release

int common_vsprintf_class___crt_stdio_output__format_validation_base_char_(__uint64 param_1, char *param_2, __uint64 param_3, char *param_4,
                                                                           __crt_locale_pointers *param_5, char *param_6)
{
  int iVar1;
  ulong *puVar2;
  undefined auStack1320[32];
  char *local_508;
  __uint64 local_500;
  __uint64 local_4f8;
  undefined local_4f0;
  __acrt_ptd *local_4e8;
  undefined local_4e0[16];
  char local_4d0;
  __uint64 local_4c8;
  undefined *local_4c0;
  undefined8 local_4b8;
  char *local_4b0;
  char *local_4a8;
  undefined8 local_4a0;
  undefined8 local_498;
  undefined4 local_490;
  undefined2 local_488;
  undefined4 local_478;
  undefined local_474;
  undefined8 local_70;
  LPVOID local_68;
  char **local_60;
  undefined4 local_58;
  ulonglong local_48;

  local_48 = DAT_1800ee160 ^ (ulonglong)auStack1320;
  if ((param_4 == (char *)0x0) || ((param_3 != 0 && (param_2 == (char *)0x0))))
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
    goto LAB_180048dfa;
  }
  FUN_18004e538(&local_4e8, (undefined4 *)param_5);
  FUN_18003bd40((undefined(*)[16]) & local_508, 0, 0x20);
  local_4f8 = 0;
  if (((param_1 & 2) != 0) || (local_4f0 = 0, param_2 == (char *)0x0))
  {
    local_4f0 = 1;
  }
  local_60 = &local_508;
  local_4b8 = 0;
  local_4c0 = local_4e0;
  local_4a0 = 0;
  local_4a8 = param_6;
  local_498 = 0;
  local_490 = 0;
  local_488 = 0;
  local_478 = 0;
  local_474 = 0;
  local_70 = 0;
  local_68 = (LPVOID)0x0;
  local_58 = 0;
  local_508 = param_2;
  local_500 = param_3;
  local_4c8 = param_1;
  local_4b0 = param_4;
  iVar1 = FUN_1800510cc(&local_4c8);
  if (param_2 != (char *)0x0)
  {
    if ((param_1 & 1) == 0)
    {
      if ((param_1 & 2) == 0)
      {
        if (param_3 != 0)
        {
          if (local_4f8 != param_3)
            goto LAB_180048dce;
        LAB_180048e34:
          param_2[param_3 - 1] = '\0';
        }
      }
      else
      {
        if (param_3 != 0)
        {
          if (-1 < iVar1)
          {
            if (local_4f8 == param_3)
              goto LAB_180048e34;
            goto LAB_180048dce;
          }
          *param_2 = '\0';
        }
      }
    }
    else
    {
      if (((param_3 != 0) || (iVar1 == 0)) && (local_4f8 != param_3))
      {
      LAB_180048dce:
        param_2[local_4f8] = '\0';
      }
    }
  }
  _free_base(local_68);
  local_68 = (LPVOID)0x0;
  if (local_4d0 != '\0')
  {
    *(uint *)(local_4e8 + 0x3a8) = *(uint *)(local_4e8 + 0x3a8) & 0xfffffffd;
  }
LAB_180048dfa:
  iVar1 = FUN_180034d00(local_48 ^ (ulonglong)auStack1320);
  return iVar1;
}

// Library Function - Single Match
//  int __cdecl common_vsprintf<class __crt_stdio_output::format_validation_base,wchar_t>(unsigned
// __int64,wchar_t * __ptr64 const,unsigned __int64,wchar_t const * __ptr64 const,struct
// __crt_locale_pointers * __ptr64 const,char * __ptr64 const)
//
// Library: Visual Studio 2017 Release

int common_vsprintf_class___crt_stdio_output__format_validation_base_wchar_t_(__uint64 param_1, wchar_t *param_2, __uint64 param_3, wchar_t *param_4,
                                                                              __crt_locale_pointers *param_5, char *param_6)
{
  int iVar1;
  ulong *puVar2;
  undefined auStack1320[32];
  wchar_t *local_508;
  __uint64 local_500;
  __uint64 local_4f8;
  undefined local_4f0;
  __acrt_ptd *local_4e8;
  undefined local_4e0[16];
  char local_4d0;
  __uint64 local_4c8;
  undefined *local_4c0;
  undefined8 local_4b8;
  wchar_t *local_4b0;
  char *local_4a8;
  undefined8 local_4a0;
  undefined8 local_498;
  undefined4 local_490;
  undefined local_488;
  undefined2 local_486;
  undefined4 local_478;
  undefined local_474;
  undefined8 local_70;
  LPVOID local_68;
  wchar_t **local_60;
  undefined4 local_58;
  ulonglong local_48;

  local_48 = DAT_1800ee160 ^ (ulonglong)auStack1320;
  if ((param_4 == (wchar_t *)0x0) || ((param_3 != 0 && (param_2 == (wchar_t *)0x0))))
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
    goto LAB_180048fcc;
  }
  FUN_18004e538(&local_4e8, (undefined4 *)param_5);
  FUN_18003bd40((undefined(*)[16]) & local_508, 0, 0x20);
  local_4f8 = 0;
  if (((param_1 & 2) != 0) || (local_4f0 = 0, param_2 == (wchar_t *)0x0))
  {
    local_4f0 = 1;
  }
  local_60 = &local_508;
  local_4b8 = 0;
  local_4c0 = local_4e0;
  local_4a0 = 0;
  local_4a8 = param_6;
  local_498 = 0;
  local_490 = 0;
  local_488 = 0;
  local_486 = 0;
  local_478 = 0;
  local_474 = 0;
  local_70 = 0;
  local_68 = (LPVOID)0x0;
  local_58 = 0;
  local_508 = param_2;
  local_500 = param_3;
  local_4c8 = param_1;
  local_4b0 = param_4;
  iVar1 = FUN_180051f28(&local_4c8);
  if (param_2 != (wchar_t *)0x0)
  {
    if ((param_1 & 1) == 0)
    {
      if ((param_1 & 2) == 0)
      {
        if (param_3 != 0)
        {
          if (local_4f8 != param_3)
            goto LAB_180048f9f;
        LAB_180049006:
          *(undefined2 *)(param_2 + param_3 * 2 + -2) = 0;
        }
      }
      else
      {
        if (param_3 != 0)
        {
          if (-1 < iVar1)
          {
            if (local_4f8 == param_3)
              goto LAB_180049006;
            goto LAB_180048f9f;
          }
          *(undefined2 *)param_2 = 0;
        }
      }
    }
    else
    {
      if (((param_3 != 0) || (iVar1 == 0)) && (local_4f8 != param_3))
      {
      LAB_180048f9f:
        *(undefined2 *)(param_2 + local_4f8 * 2) = 0;
      }
    }
  }
  _free_base(local_68);
  local_68 = (LPVOID)0x0;
  if (local_4d0 != '\0')
  {
    *(uint *)(local_4e8 + 0x3a8) = *(uint *)(local_4e8 + 0x3a8) & 0xfffffffd;
  }
LAB_180048fcc:
  iVar1 = FUN_180034d00(local_48 ^ (ulonglong)auStack1320);
  return iVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  int __cdecl common_vsprintf<class __crt_stdio_output::format_validation_base,char>(unsigned
// __int64,char * __ptr64 const,unsigned __int64,char const * __ptr64 const,struct
// __crt_locale_pointers * __ptr64 const,char * __ptr64 const)
//  int __cdecl common_vsprintf<class __crt_stdio_output::standard_base,char>(unsigned __int64,char
// * __ptr64 const,unsigned __int64,char const * __ptr64 const,struct __crt_locale_pointers *
// __ptr64 const,char * __ptr64 const)
//
// Library: Visual Studio 2017 Release

void common_vsprintf__(ulonglong param_1, undefined *param_2, longlong param_3, longlong param_4,
                       undefined4 *param_5, undefined8 param_6)
{
  int iVar1;
  ulong *puVar2;
  undefined auStack1320[32];
  undefined *local_508;
  longlong local_500;
  longlong local_4f8;
  undefined local_4f0;
  __acrt_ptd *local_4e8;
  undefined local_4e0[16];
  char local_4d0;
  ulonglong local_4c8;
  undefined *local_4c0;
  undefined8 local_4b8;
  longlong local_4b0;
  undefined8 local_4a8;
  undefined8 local_4a0;
  undefined8 local_498;
  undefined4 local_490;
  undefined2 local_488;
  undefined4 local_478;
  undefined local_474;
  undefined8 local_70;
  LPVOID local_68;
  undefined **local_60;
  undefined4 local_58;
  ulonglong local_48;

  local_48 = DAT_1800ee160 ^ (ulonglong)auStack1320;
  if ((param_4 == 0) || ((param_3 != 0 && (param_2 == (undefined *)0x0))))
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
    goto LAB_180049572;
  }
  FUN_18004e538(&local_4e8, param_5);
  FUN_18003bd40((undefined(*)[16]) & local_508, 0, 0x20);
  local_4f8 = 0;
  if (((param_1 & 2) != 0) || (local_4f0 = 0, param_2 == (undefined *)0x0))
  {
    local_4f0 = 1;
  }
  local_60 = &local_508;
  local_4b8 = 0;
  local_4c0 = local_4e0;
  local_4a0 = 0;
  local_4a8 = param_6;
  local_498 = 0;
  local_490 = 0;
  local_488 = 0;
  local_478 = 0;
  local_474 = 0;
  local_70 = 0;
  local_68 = (LPVOID)0x0;
  local_58 = 0;
  local_508 = param_2;
  local_500 = param_3;
  local_4c8 = param_1;
  local_4b0 = param_4;
  iVar1 = FUN_180051580(&local_4c8);
  if (param_2 != (undefined *)0x0)
  {
    if ((param_1 & 1) == 0)
    {
      if ((param_1 & 2) == 0)
      {
        if (param_3 != 0)
        {
          if (local_4f8 != param_3)
            goto LAB_180049546;
        LAB_1800495ac:
          param_2[param_3 + -1] = 0;
        }
      }
      else
      {
        if (param_3 != 0)
        {
          if (-1 < iVar1)
          {
            if (local_4f8 == param_3)
              goto LAB_1800495ac;
            goto LAB_180049546;
          }
          *param_2 = 0;
        }
      }
    }
    else
    {
      if (((param_3 != 0) || (iVar1 == 0)) && (local_4f8 != param_3))
      {
      LAB_180049546:
        param_2[local_4f8] = 0;
      }
    }
  }
  _free_base(local_68);
  local_68 = (LPVOID)0x0;
  if (local_4d0 != '\0')
  {
    *(uint *)(local_4e8 + 0x3a8) = *(uint *)(local_4e8 + 0x3a8) & 0xfffffffd;
  }
LAB_180049572:
  FUN_180034d00(local_48 ^ (ulonglong)auStack1320);
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  int __cdecl common_vsprintf<class __crt_stdio_output::format_validation_base,wchar_t>(unsigned
// __int64,wchar_t * __ptr64 const,unsigned __int64,wchar_t const * __ptr64 const,struct
// __crt_locale_pointers * __ptr64 const,char * __ptr64 const)
//  int __cdecl common_vsprintf<class __crt_stdio_output::standard_base,wchar_t>(unsigned
// __int64,wchar_t * __ptr64 const,unsigned __int64,wchar_t const * __ptr64 const,struct
// __crt_locale_pointers * __ptr64 const,char * __ptr64 const)
//
// Library: Visual Studio 2017 Release

void common_vsprintf__(ulonglong param_1, undefined2 *param_2, longlong param_3, longlong param_4,
                       undefined4 *param_5, undefined8 param_6)
{
  int iVar1;
  ulong *puVar2;
  undefined auStack1320[32];
  undefined2 *local_508;
  longlong local_500;
  longlong local_4f8;
  undefined local_4f0;
  __acrt_ptd *local_4e8;
  undefined local_4e0[16];
  char local_4d0;
  ulonglong local_4c8;
  undefined *local_4c0;
  undefined8 local_4b8;
  longlong local_4b0;
  undefined8 local_4a8;
  undefined8 local_4a0;
  undefined8 local_498;
  undefined4 local_490;
  undefined local_488;
  undefined2 local_486;
  undefined4 local_478;
  undefined local_474;
  undefined8 local_70;
  LPVOID local_68;
  undefined2 **local_60;
  undefined4 local_58;
  ulonglong local_48;

  local_48 = DAT_1800ee160 ^ (ulonglong)auStack1320;
  if ((param_4 == 0) || ((param_3 != 0 && (param_2 == (undefined2 *)0x0))))
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
    goto LAB_180049744;
  }
  FUN_18004e538(&local_4e8, param_5);
  FUN_18003bd40((undefined(*)[16]) & local_508, 0, 0x20);
  local_4f8 = 0;
  if (((param_1 & 2) != 0) || (local_4f0 = 0, param_2 == (undefined2 *)0x0))
  {
    local_4f0 = 1;
  }
  local_60 = &local_508;
  local_4b8 = 0;
  local_4c0 = local_4e0;
  local_4a0 = 0;
  local_4a8 = param_6;
  local_498 = 0;
  local_490 = 0;
  local_488 = 0;
  local_486 = 0;
  local_478 = 0;
  local_474 = 0;
  local_70 = 0;
  local_68 = (LPVOID)0x0;
  local_58 = 0;
  local_508 = param_2;
  local_500 = param_3;
  local_4c8 = param_1;
  local_4b0 = param_4;
  iVar1 = FUN_180052454(&local_4c8);
  if (param_2 != (undefined2 *)0x0)
  {
    if ((param_1 & 1) == 0)
    {
      if ((param_1 & 2) == 0)
      {
        if (param_3 != 0)
        {
          if (local_4f8 != param_3)
            goto LAB_180049717;
        LAB_18004977e:
          param_2[param_3 + -1] = 0;
        }
      }
      else
      {
        if (param_3 != 0)
        {
          if (-1 < iVar1)
          {
            if (local_4f8 == param_3)
              goto LAB_18004977e;
            goto LAB_180049717;
          }
          *param_2 = 0;
        }
      }
    }
    else
    {
      if (((param_3 != 0) || (iVar1 == 0)) && (local_4f8 != param_3))
      {
      LAB_180049717:
        param_2[local_4f8] = 0;
      }
    }
  }
  _free_base(local_68);
  local_68 = (LPVOID)0x0;
  if (local_4d0 != '\0')
  {
    *(uint *)(local_4e8 + 0x3a8) = *(uint *)(local_4e8 + 0x3a8) & 0xfffffffd;
  }
LAB_180049744:
  FUN_180034d00(local_48 ^ (ulonglong)auStack1320);
  return;
}

// Library Function - Single Match
//  __stdio_common_vsprintf_s
//
// Library: Visual Studio 2017 Release

int __stdio_common_vsprintf_s(__uint64 param_1, char *param_2, __uint64 param_3, char *param_4,
                              __crt_locale_pointers *param_5, char *param_6)
{
  int iVar1;
  ulong *puVar2;

  if (((param_4 == (char *)0x0) || (param_2 == (char *)0x0)) || (param_3 == 0))
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
  }
  else
  {
    iVar1 = common_vsprintf_class___crt_stdio_output__format_validation_base_char_(param_1, param_2, param_3, param_4, param_5, param_6);
    if (iVar1 < 0)
    {
      *param_2 = '\0';
    }
    if (iVar1 != -2)
    {
      return iVar1;
    }
    puVar2 = __doserrno();
    *puVar2 = 0x22;
  }
  FUN_18006738c();
  return -1;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<signed
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<signed
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<signed
// char,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(longlong param_1, longlong *param_2, undefined8 param_3, uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  char *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = (longlong) * (char *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_180049ac3:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(char **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = (longlong)*in_RAX;
    goto LAB_180049ac3;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_180049a86;
    }
  }
  uVar6 = 1;
LAB_180049a86:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<signed
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<signed
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<signed
// char,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(longlong param_1, longlong *param_2, undefined8 param_3, uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  char *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = (longlong) * (char *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_180049b87:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(char **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = (longlong)*in_RAX;
    goto LAB_180049b87;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004fbac(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_180049b4a;
    }
  }
  uVar6 = 1;
LAB_180049b4a:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<signed
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<signed
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<signed
// char,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1, longlong *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  char *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = (longlong) * (char *)(param_1[4] - 8);
  LAB_180049c4d:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (char *)param_1[uVar4 * 3 + 0x92];
    *param_2 = (longlong)*in_RAX;
    goto LAB_180049c4d;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004fddc(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_180049c10;
    }
  }
  uVar6 = 1;
LAB_180049c10:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<signed
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<signed
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<signed
// char,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1, longlong *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  char *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = (longlong) * (char *)(param_1[4] - 8);
  LAB_180049d15:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (char *)param_1[uVar4 * 3 + 0x92];
    *param_2 = (longlong)*in_RAX;
    goto LAB_180049d15;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004ffd4(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_180049cd8;
    }
  }
  uVar6 = 1;
LAB_180049cd8:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<unsigned
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<unsigned
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<unsigned
// char,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(longlong param_1, ulonglong *param_2, undefined8 param_3, uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  byte *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = (ulonglong) * (byte *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_180049e2a:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(byte **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = (ulonglong)*in_RAX;
    goto LAB_180049e2a;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_180049dee;
    }
  }
  uVar6 = 1;
LAB_180049dee:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<unsigned
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<unsigned
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<unsigned
// char,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(longlong param_1, ulonglong *param_2, undefined8 param_3, uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  byte *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = (ulonglong) * (byte *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_180049eee:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(byte **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = (ulonglong)*in_RAX;
    goto LAB_180049eee;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004fbac(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_180049eb2;
    }
  }
  uVar6 = 1;
LAB_180049eb2:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// char,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1, ulonglong *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  byte *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = (ulonglong) * (byte *)(param_1[4] - 8);
  LAB_180049fb4:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (byte *)param_1[uVar4 * 3 + 0x92];
    *param_2 = (ulonglong)*in_RAX;
    goto LAB_180049fb4;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004fddc(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_180049f78;
    }
  }
  uVar6 = 1;
LAB_180049f78:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// char,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// char,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1, ulonglong *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  byte *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = (ulonglong) * (byte *)(param_1[4] - 8);
  LAB_18004a078:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (byte *)param_1[uVar4 * 3 + 0x92];
    *param_2 = (ulonglong)*in_RAX;
    goto LAB_18004a078;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004ffd4(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004a03c;
    }
  }
  uVar6 = 1;
LAB_18004a03c:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<short,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<short,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<short,__int64>(__int64
// & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,longlong *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  short *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = (longlong) * (short *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004a18b:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(short **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = (longlong)*in_RAX;
    goto LAB_18004a18b;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004a14e;
    }
  }
  uVar6 = 1;
LAB_18004a14e:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<short,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<short,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<short,__int64>(__int64
// & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,longlong *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  short *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = (longlong) * (short *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004a24f:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(short **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = (longlong)*in_RAX;
    goto LAB_18004a24f;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004fbac(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004a212;
    }
  }
  uVar6 = 1;
LAB_18004a212:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<short,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<short,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<short,__int64>(__int64
// & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,longlong *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  short *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = (longlong) * (short *)(param_1[4] - 8);
  LAB_18004a315:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (short *)param_1[uVar4 * 3 + 0x92];
    *param_2 = (longlong)*in_RAX;
    goto LAB_18004a315;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004fddc(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004a2d8;
    }
  }
  uVar6 = 1;
LAB_18004a2d8:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<short,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<short,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<short,__int64>(__int64
// & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,longlong *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  short *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = (longlong) * (short *)(param_1[4] - 8);
  LAB_18004a3dd:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (short *)param_1[uVar4 * 3 + 0x92];
    *param_2 = (longlong)*in_RAX;
    goto LAB_18004a3dd;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004ffd4(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004a3a0;
    }
  }
  uVar6 = 1;
LAB_18004a3a0:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<unsigned
// short,char>(char & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<unsigned
// short,char>(char & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<unsigned
// short,char>(char & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004a4ef:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004a4ef;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004a4b5;
    }
  }
  uVar6 = 1;
LAB_18004a4b5:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<unsigned
// short,char>(char & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<unsigned
// short,char>(char & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<unsigned
// short,char>(char & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004a5af:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004a5af;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004fbac(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004a575;
    }
  }
  uVar6 = 1;
LAB_18004a575:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<unsigned
// short,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<unsigned
// short,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<unsigned
// short,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,ulonglong *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  ushort *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = (ulonglong) * (ushort *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004a69a:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(ushort **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = (ulonglong)*in_RAX;
    goto LAB_18004a69a;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004a65e;
    }
  }
  uVar6 = 1;
LAB_18004a65e:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<unsigned
// short,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<unsigned
// short,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<unsigned
// short,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,ulonglong *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  ushort *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = (ulonglong) * (ushort *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004a75e:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(ushort **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = (ulonglong)*in_RAX;
    goto LAB_18004a75e;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004fbac(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004a722;
    }
  }
  uVar6 = 1;
LAB_18004a722:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// short,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// short,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// short,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,ulonglong *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  ushort *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = (ulonglong) * (ushort *)(param_1[4] - 8);
  LAB_18004a824:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (ushort *)param_1[uVar4 * 3 + 0x92];
    *param_2 = (ulonglong)*in_RAX;
    goto LAB_18004a824;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004fddc(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004a7e8;
    }
  }
  uVar6 = 1;
LAB_18004a7e8:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// short,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// short,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// short,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,ulonglong *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  ushort *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = (ulonglong) * (ushort *)(param_1[4] - 8);
  LAB_18004a8e8:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (ushort *)param_1[uVar4 * 3 + 0x92];
    *param_2 = (ulonglong)*in_RAX;
    goto LAB_18004a8e8;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004ffd4(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004a8ac;
    }
  }
  uVar6 = 1;
LAB_18004a8ac:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<int,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<int,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<int,__int64>(__int64
// & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,longlong *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  int *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = (longlong) * (int *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004a9f9:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(int **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = (longlong)*in_RAX;
    goto LAB_18004a9f9;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004a9bd;
    }
  }
  uVar6 = 1;
LAB_18004a9bd:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<int,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<int,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<int,__int64>(__int64
// & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,longlong *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  int *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = (longlong) * (int *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004aabd:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(int **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = (longlong)*in_RAX;
    goto LAB_18004aabd;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004fbac(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004aa81;
    }
  }
  uVar6 = 1;
LAB_18004aa81:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<int,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<int,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<int,__int64>(__int64
// & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,longlong *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  int *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = (longlong) * (int *)(param_1[4] - 8);
  LAB_18004ab83:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (int *)param_1[uVar4 * 3 + 0x92];
    *param_2 = (longlong)*in_RAX;
    goto LAB_18004ab83;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004fddc(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004ab47;
    }
  }
  uVar6 = 1;
LAB_18004ab47:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<int,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<int,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<int,__int64>(__int64
// & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,longlong *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  int *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = (longlong) * (int *)(param_1[4] - 8);
  LAB_18004ac47:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (int *)param_1[uVar4 * 3 + 0x92];
    *param_2 = (longlong)*in_RAX;
    goto LAB_18004ac47;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004ffd4(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004ac0b;
    }
  }
  uVar6 = 1;
LAB_18004ac0b:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<unsigned
// int,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<unsigned
// int,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<unsigned
// int,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,ulonglong *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  uint *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = (ulonglong) * (uint *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004ad58:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(uint **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = (ulonglong)*in_RAX;
    goto LAB_18004ad58;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004ad1d;
    }
  }
  uVar6 = 1;
LAB_18004ad1d:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// int,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// int,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// int,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,ulonglong *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  uint *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = (ulonglong) * (uint *)(param_1[4] - 8);
  LAB_18004aeda:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (uint *)param_1[uVar4 * 3 + 0x92];
    *param_2 = (ulonglong)*in_RAX;
    goto LAB_18004aeda;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004fddc(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004ae9f;
    }
  }
  uVar6 = 1;
LAB_18004ae9f:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// int,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// int,__int64>(__int64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// int,__int64>(__int64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,ulonglong *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  uint *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = (ulonglong) * (uint *)(param_1[4] - 8);
  LAB_18004af9e:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (uint *)param_1[uVar4 * 3 + 0x92];
    *param_2 = (ulonglong)*in_RAX;
    goto LAB_18004af9e;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004ffd4(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004af63;
    }
  }
  uVar6 = 1;
LAB_18004af63:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<struct `private:
// bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64,struct `private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64>(struct `private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64 & __ptr64) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined8 *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined8 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004b0b1:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined8 **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004b0b1;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 3;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 3, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004b075;
    }
  }
  uVar6 = 1;
LAB_18004b075:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<struct `private:
// bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64,struct `private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64>(struct `private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64 & __ptr64) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined8 *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined8 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004b175:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined8 **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004b175;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 3;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004fbac(param_1, piVar1, 3, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004b139;
    }
  }
  uVar6 = 1;
LAB_18004b139:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<struct
// `private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void)
// __ptr64'::`2'::ansi_string * __ptr64,struct `private: bool __cdecl
// __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void)
// __ptr64'::`2'::ansi_string * __ptr64>(struct `private: bool __cdecl
// __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void)
// __ptr64'::`2'::ansi_string * __ptr64 & __ptr64) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,undefined8 *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = *(undefined8 *)(param_1[4] - 8);
  LAB_18004b23b:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined8 *)param_1[uVar4 * 3 + 0x92];
    *param_2 = *in_RAX;
    goto LAB_18004b23b;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 3;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004fddc(param_1, (int *)p_Var1, 3, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004b1ff;
    }
  }
  uVar6 = 1;
LAB_18004b1ff:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<struct
// `private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void)
// __ptr64'::`2'::ansi_string * __ptr64,struct `private: bool __cdecl
// __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void)
// __ptr64'::`2'::ansi_string * __ptr64>(struct `private: bool __cdecl
// __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void)
// __ptr64'::`2'::ansi_string * __ptr64 & __ptr64) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,undefined8 *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = *(undefined8 *)(param_1[4] - 8);
  LAB_18004b2ff:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined8 *)param_1[uVar4 * 3 + 0x92];
    *param_2 = *in_RAX;
    goto LAB_18004b2ff;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 3;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004ffd4(param_1, (int *)p_Var1, 3, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004b2c3;
    }
  }
  uVar6 = 1;
LAB_18004b2c3:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<struct `private:
// bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64,struct `private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64>(struct `private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64 & __ptr64) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined8 *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined8 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004b425:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined8 **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004b425;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 3;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 3, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004b3e9;
    }
  }
  uVar6 = 1;
LAB_18004b3e9:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<struct `private:
// bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64,struct `private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64>(struct `private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64 & __ptr64) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined8 *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined8 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004b525:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined8 **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004b525;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 3;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004fbac(param_1, piVar1, 3, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004b4e9;
    }
  }
  uVar6 = 1;
LAB_18004b4e9:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<struct
// `private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void)
// __ptr64'::`2'::ansi_string * __ptr64,struct `private: bool __cdecl
// __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void)
// __ptr64'::`2'::ansi_string * __ptr64>(struct `private: bool __cdecl
// __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void)
// __ptr64'::`2'::ansi_string * __ptr64 & __ptr64) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,undefined8 *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = *(undefined8 *)(param_1[4] - 8);
  LAB_18004b627:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined8 *)param_1[uVar4 * 3 + 0x92];
    *param_2 = *in_RAX;
    goto LAB_18004b627;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 3;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004fddc(param_1, (int *)p_Var1, 3, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004b5eb;
    }
  }
  uVar6 = 1;
LAB_18004b5eb:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<struct
// `private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void)
// __ptr64'::`2'::ansi_string * __ptr64,struct `private: bool __cdecl
// __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void)
// __ptr64'::`2'::ansi_string * __ptr64>(struct `private: bool __cdecl
// __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void)
// __ptr64'::`2'::ansi_string * __ptr64 & __ptr64) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,undefined8 *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = *(undefined8 *)(param_1[4] - 8);
  LAB_18004b727:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined8 *)param_1[uVar4 * 3 + 0x92];
    *param_2 = *in_RAX;
    goto LAB_18004b727;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 3;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004ffd4(param_1, (int *)p_Var1, 3, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004b6eb;
    }
  }
  uVar6 = 1;
LAB_18004b6eb:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<void *
// __ptr64,void * __ptr64>(void * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<void *
// __ptr64,void * __ptr64>(void * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<void *
// __ptr64,void * __ptr64>(void * __ptr64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined8 *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined8 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004b811:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined8 **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004b811;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 3;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 3, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004b7d5;
    }
  }
  uVar6 = 1;
LAB_18004b7d5:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<char *
// __ptr64,char * __ptr64>(char * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<struct `private:
// bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64,struct `private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64>(struct `private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_Z(void) __ptr64'::`2'::ansi_string
// * __ptr64 & __ptr64) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined8 *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined8 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004b8d5:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined8 **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004b8d5;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 3;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004fbac(param_1, piVar1, 3, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004b899;
    }
  }
  uVar6 = 1;
LAB_18004b899:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<void *
// __ptr64,void * __ptr64>(void * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<void *
// __ptr64,void * __ptr64>(void * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<void *
// __ptr64,void * __ptr64>(void * __ptr64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,undefined8 *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = *(undefined8 *)(param_1[4] - 8);
  LAB_18004b99b:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined8 *)param_1[uVar4 * 3 + 0x92];
    *param_2 = *in_RAX;
    goto LAB_18004b99b;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 3;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004fddc(param_1, (int *)p_Var1, 3, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004b95f;
    }
  }
  uVar6 = 1;
LAB_18004b95f:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<void *
// __ptr64,void * __ptr64>(void * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<void *
// __ptr64,void * __ptr64>(void * __ptr64 & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<void *
// __ptr64,void * __ptr64>(void * __ptr64 & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,undefined8 *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = *(undefined8 *)(param_1[4] - 8);
  LAB_18004ba5f:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined8 *)param_1[uVar4 * 3 + 0x92];
    *param_2 = *in_RAX;
    goto LAB_18004ba5f;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 3;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004ffd4(param_1, (int *)p_Var1, 3, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004ba23;
    }
  }
  uVar6 = 1;
LAB_18004ba23:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<unsigned
// __int64,__int64>(__int64 & __ptr64) __ptr64
//   6 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined8 *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined8 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004bee1:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined8 **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004bee1;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 2;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 2, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004bea5;
    }
  }
  uVar6 = 1;
LAB_18004bea5:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<unsigned
// __int64,__int64>(__int64 & __ptr64) __ptr64
//   6 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined8 *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined8 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004bfa5:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined8 **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004bfa5;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 2;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004fbac(param_1, piVar1, 2, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004bf69;
    }
  }
  uVar6 = 1;
LAB_18004bf69:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// __int64,__int64>(__int64 & __ptr64) __ptr64
//   6 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,undefined8 *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = *(undefined8 *)(param_1[4] - 8);
  LAB_18004c06b:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined8 *)param_1[uVar4 * 3 + 0x92];
    *param_2 = *in_RAX;
    goto LAB_18004c06b;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 2;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004fddc(param_1, (int *)p_Var1, 2, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004c02f;
    }
  }
  uVar6 = 1;
LAB_18004c02f:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// __int64,__int64>(__int64 & __ptr64) __ptr64
//   6 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,undefined8 *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = *(undefined8 *)(param_1[4] - 8);
  LAB_18004c12f:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined8 *)param_1[uVar4 * 3 + 0x92];
    *param_2 = *in_RAX;
    goto LAB_18004c12f;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 2;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004ffd4(param_1, (int *)p_Var1, 2, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004c0f3;
    }
  }
  uVar6 = 1;
LAB_18004c0f3:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<unsigned
// __int64,__int64>(__int64 & __ptr64) __ptr64
//   6 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined8 *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined8 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004c241:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined8 **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004c241;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 2;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 2, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004c205;
    }
  }
  uVar6 = 1;
LAB_18004c205:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<unsigned
// __int64,__int64>(__int64 & __ptr64) __ptr64
//   6 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined8 *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined8 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004c305:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined8 **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004c305;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 2;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004fbac(param_1, piVar1, 2, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004c2c9;
    }
  }
  uVar6 = 1;
LAB_18004c2c9:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// __int64,__int64>(__int64 & __ptr64) __ptr64
//   6 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,undefined8 *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = *(undefined8 *)(param_1[4] - 8);
  LAB_18004c3cb:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined8 *)param_1[uVar4 * 3 + 0x92];
    *param_2 = *in_RAX;
    goto LAB_18004c3cb;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 2;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004fddc(param_1, (int *)p_Var1, 2, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004c38f;
    }
  }
  uVar6 = 1;
LAB_18004c38f:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<__int64,__int64>(__int64
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<unsigned
// __int64,__int64>(__int64 & __ptr64) __ptr64
//   6 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,undefined8 *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined8 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = *(undefined8 *)(param_1[4] - 8);
  LAB_18004c48f:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined8 *)param_1[uVar4 * 3 + 0x92];
    *param_2 = *in_RAX;
    goto LAB_18004c48f;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 2;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004ffd4(param_1, (int *)p_Var1, 2, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004c453;
    }
  }
  uVar6 = 1;
LAB_18004c453:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<wchar_t,wchar_t>(wchar_t
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<wchar_t,wchar_t>(wchar_t
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<wchar_t,wchar_t>(wchar_t
// & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined2 *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined2 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined2 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004c5a3:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined2 **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004c5a3;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004c567;
    }
  }
  uVar6 = 1;
LAB_18004c567:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::console_output_adapter<char>>::extract_argument_from_va_list<wchar_t,wchar_t>(wchar_t
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::stream_output_adapter<char>>::extract_argument_from_va_list<wchar_t,wchar_t>(wchar_t
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::string_output_adapter<char>>::extract_argument_from_va_list<wchar_t,wchar_t>(wchar_t
// & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__
                    (longlong param_1,undefined2 *param_2,undefined8 param_3,uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined2 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *param_2 = *(undefined2 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18004c667:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined2 **)(param_1 + 0x490 + uVar4 * 0x18);
    *param_2 = *in_RAX;
    goto LAB_18004c667;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004fbac(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004c62b;
    }
  }
  uVar6 = 1;
LAB_18004c62b:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<wchar_t,wchar_t>(wchar_t
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<wchar_t,wchar_t>(wchar_t
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<wchar_t,wchar_t>(wchar_t
// & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,undefined2 *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined2 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = *(undefined2 *)(param_1[4] - 8);
  LAB_18004c72d:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined2 *)param_1[uVar4 * 3 + 0x92];
    *param_2 = *in_RAX;
    goto LAB_18004c72d;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004fddc(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004c6f1;
    }
  }
  uVar6 = 1;
LAB_18004c6f1:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::console_output_adapter<wchar_t>>::extract_argument_from_va_list<wchar_t,wchar_t>(wchar_t
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t>>::extract_argument_from_va_list<wchar_t,wchar_t>(wchar_t
// & __ptr64) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::string_output_adapter<wchar_t>>::extract_argument_from_va_list<wchar_t,wchar_t>(wchar_t
// & __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong extract_argument_from_va_list__(__uint64 *param_1,undefined2 *param_2)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined2 *in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *param_2 = *(undefined2 *)(param_1[4] - 8);
  LAB_18004c7f5:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined2 *)param_1[uVar4 * 3 + 0x92];
    *param_2 = *in_RAX;
    goto LAB_18004c7f5;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004ffd4(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18004c7b9;
    }
  }
  uVar6 = 1;
LAB_18004c7b9:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Single Match
//  bool __cdecl __crt_stdio_output::is_wide_character_specifier<wchar_t>(unsigned
// __int64,wchar_t,enum __crt_stdio_output::length_modifier)
//
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

bool __crt_stdio_output::is_wide_character_specifier_wchar_t_
               (__uint64 param_1,wchar_t param_2,length_modifier param_3)
{
  undefined in_DH;
  bool bVar1;

  if (param_3 == 2)
  {
    bVar1 = false;
  }
  else
  {
    if (((param_3 == 3) || (param_3 == 0xc)) || (param_3 == 0xd))
    {
      return true;
    }
    bVar1 = (param_1 & 4) != 0;
    if ((CONCAT11(in_DH, param_2) - 99U & 0xffef) != 0)
    {
      return (param_1 & 4) == 0;
    }
  }
  return bVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//   9 names - too many to list
//
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

void type_case_integer_parse_into_buffer__
               (longlong param_1,ulonglong param_2,uint param_3,byte param_4)
{
  ulonglong uVar1;
  char cVar2;
  longlong lVar3;

  lVar3 = *(longlong *)(param_1 + 0x460);
  if (lVar3 == 0)
  {
    uVar1 = 0x200;
    lVar3 = param_1 + 0x58;
  }
  else
  {
    uVar1 = *(ulonglong *)(param_1 + 0x458) >> 1;
  }
  lVar3 = lVar3 + -1 + uVar1;
  *(longlong *)(param_1 + 0x48) = lVar3;
  uVar1 = param_2 & 0xffffffff;
  while (true)
  {
    if ((*(int *)(param_1 + 0x38) < 1) && ((int)uVar1 == 0))
      break;
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -1;
    cVar2 = (char)(uVar1 % (ulonglong)param_3) + '0';
    if ('9' < cVar2)
    {
      cVar2 = cVar2 + (param_4 ^ 1) * ' ' + '\a';
    }
    **(char **)(param_1 + 0x48) = cVar2;
    *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + -1;
    uVar1 = uVar1 / param_3;
  }
  *(int *)(param_1 + 0x50) = (int)lVar3 - *(int *)(param_1 + 0x48);
  *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + 1;
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//   9 names - too many to list
//
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

void type_case_integer_parse_into_buffer__
               (longlong param_1,ulonglong param_2,uint param_3,byte param_4)
{
  ulonglong uVar1;
  char cVar2;
  longlong lVar3;

  lVar3 = *(longlong *)(param_1 + 0x460);
  if (lVar3 == 0)
  {
    uVar1 = 0x200;
    lVar3 = param_1 + 0x58;
  }
  else
  {
    uVar1 = *(ulonglong *)(param_1 + 0x458) >> 1;
  }
  lVar3 = lVar3 + -1 + uVar1;
  *(longlong *)(param_1 + 0x48) = lVar3;
  uVar1 = param_2 & 0xffffffff;
  while (true)
  {
    if ((*(int *)(param_1 + 0x38) < 1) && ((int)uVar1 == 0))
      break;
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -1;
    cVar2 = (char)(uVar1 % (ulonglong)param_3) + '0';
    if ('9' < cVar2)
    {
      cVar2 = cVar2 + (param_4 ^ 1) * ' ' + '\a';
    }
    **(char **)(param_1 + 0x48) = cVar2;
    *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + -1;
    uVar1 = uVar1 / param_3;
  }
  *(int *)(param_1 + 0x50) = (int)lVar3 - *(int *)(param_1 + 0x48);
  *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + 1;
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//   9 names - too many to list
//
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

void type_case_integer_parse_into_buffer__
               (longlong param_1,ulonglong param_2,uint param_3,byte param_4)
{
  ulonglong uVar1;
  char cVar2;
  longlong lVar3;

  lVar3 = *(longlong *)(param_1 + 0x460);
  if (lVar3 == 0)
  {
    uVar1 = 0x200;
    lVar3 = param_1 + 0x58;
  }
  else
  {
    uVar1 = *(ulonglong *)(param_1 + 0x458) >> 1;
  }
  lVar3 = lVar3 + -1 + uVar1;
  *(longlong *)(param_1 + 0x48) = lVar3;
  uVar1 = param_2 & 0xffffffff;
  while (true)
  {
    if ((*(int *)(param_1 + 0x38) < 1) && ((int)uVar1 == 0))
      break;
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -1;
    cVar2 = (char)(uVar1 % (ulonglong)param_3) + '0';
    if ('9' < cVar2)
    {
      cVar2 = cVar2 + (param_4 ^ 1) * ' ' + '\a';
    }
    **(char **)(param_1 + 0x48) = cVar2;
    *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + -1;
    uVar1 = uVar1 / param_3;
  }
  *(int *)(param_1 + 0x50) = (int)lVar3 - *(int *)(param_1 + 0x48);
  *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + 1;
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//   9 names - too many to list
//
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

void type_case_integer_parse_into_buffer__
               (longlong param_1,ulonglong param_2,uint param_3,byte param_4)
{
  ulonglong uVar1;
  char cVar2;
  longlong lVar3;

  lVar3 = *(longlong *)(param_1 + 0x460);
  if (lVar3 == 0)
  {
    uVar1 = 0x200;
    lVar3 = param_1 + 0x58;
  }
  else
  {
    uVar1 = *(ulonglong *)(param_1 + 0x458) >> 1;
  }
  lVar3 = lVar3 + -1 + uVar1;
  *(longlong *)(param_1 + 0x48) = lVar3;
  uVar1 = param_2 & 0xffffffff;
  while (true)
  {
    if ((*(int *)(param_1 + 0x38) < 1) && ((int)uVar1 == 0))
      break;
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -1;
    cVar2 = (char)(uVar1 % (ulonglong)param_3) + '0';
    if ('9' < cVar2)
    {
      cVar2 = cVar2 + (param_4 ^ 1) * ' ' + '\a';
    }
    **(char **)(param_1 + 0x48) = cVar2;
    *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + -1;
    uVar1 = uVar1 / param_3;
  }
  *(int *)(param_1 + 0x50) = (int)lVar3 - *(int *)(param_1 + 0x48);
  *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + 1;
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// int>(unsigned int,unsigned int,bool) __ptr64
//   9 names - too many to list
//
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

void type_case_integer_parse_into_buffer__
               (longlong param_1,ulonglong param_2,uint param_3,byte param_4)
{
  ulonglong uVar1;
  char cVar2;
  longlong lVar3;

  lVar3 = *(longlong *)(param_1 + 0x460);
  if (lVar3 == 0)
  {
    uVar1 = 0x200;
    lVar3 = param_1 + 0x58;
  }
  else
  {
    uVar1 = *(ulonglong *)(param_1 + 0x458) >> 1;
  }
  lVar3 = lVar3 + -1 + uVar1;
  *(longlong *)(param_1 + 0x48) = lVar3;
  uVar1 = param_2 & 0xffffffff;
  while (true)
  {
    if ((*(int *)(param_1 + 0x38) < 1) && ((int)uVar1 == 0))
      break;
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -1;
    cVar2 = (char)(uVar1 % (ulonglong)param_3) + '0';
    if ('9' < cVar2)
    {
      cVar2 = cVar2 + (param_4 ^ 1) * ' ' + '\a';
    }
    **(char **)(param_1 + 0x48) = cVar2;
    *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + -1;
    uVar1 = uVar1 / param_3;
  }
  *(int *)(param_1 + 0x50) = (int)lVar3 - *(int *)(param_1 + 0x48);
  *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + 1;
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//   9 names - too many to list
//
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

void type_case_integer_parse_into_buffer__
               (longlong param_1,ulonglong param_2,ulonglong param_3,byte param_4)
{
  ulonglong uVar1;
  char cVar2;
  longlong lVar3;

  lVar3 = *(longlong *)(param_1 + 0x460);
  if (lVar3 == 0)
  {
    uVar1 = 0x200;
    lVar3 = param_1 + 0x58;
  }
  else
  {
    uVar1 = *(ulonglong *)(param_1 + 0x458) >> 1;
  }
  lVar3 = lVar3 + -1 + uVar1;
  *(longlong *)(param_1 + 0x48) = lVar3;
  while ((0 < *(int *)(param_1 + 0x38) || (param_2 != 0)))
  {
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -1;
    cVar2 = (char)(param_2 % (param_3 & 0xffffffff)) + '0';
    if ('9' < cVar2)
    {
      cVar2 = cVar2 + (param_4 ^ 1) * ' ' + '\a';
    }
    **(char **)(param_1 + 0x48) = cVar2;
    *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + -1;
    param_2 = param_2 / (param_3 & 0xffffffff);
  }
  *(int *)(param_1 + 0x50) = (int)lVar3 - *(int *)(param_1 + 0x48);
  *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + 1;
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//   9 names - too many to list
//
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

void type_case_integer_parse_into_buffer__
               (longlong param_1,ulonglong param_2,ulonglong param_3,byte param_4)
{
  ulonglong uVar1;
  char cVar2;
  longlong lVar3;

  lVar3 = *(longlong *)(param_1 + 0x460);
  if (lVar3 == 0)
  {
    uVar1 = 0x200;
    lVar3 = param_1 + 0x58;
  }
  else
  {
    uVar1 = *(ulonglong *)(param_1 + 0x458) >> 1;
  }
  lVar3 = lVar3 + -1 + uVar1;
  *(longlong *)(param_1 + 0x48) = lVar3;
  while ((0 < *(int *)(param_1 + 0x38) || (param_2 != 0)))
  {
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -1;
    cVar2 = (char)(param_2 % (param_3 & 0xffffffff)) + '0';
    if ('9' < cVar2)
    {
      cVar2 = cVar2 + (param_4 ^ 1) * ' ' + '\a';
    }
    **(char **)(param_1 + 0x48) = cVar2;
    *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + -1;
    param_2 = param_2 / (param_3 & 0xffffffff);
  }
  *(int *)(param_1 + 0x50) = (int)lVar3 - *(int *)(param_1 + 0x48);
  *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + 1;
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//   9 names - too many to list
//
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

void type_case_integer_parse_into_buffer__
               (longlong param_1,ulonglong param_2,ulonglong param_3,byte param_4)
{
  ulonglong uVar1;
  char cVar2;
  longlong lVar3;

  lVar3 = *(longlong *)(param_1 + 0x460);
  if (lVar3 == 0)
  {
    uVar1 = 0x200;
    lVar3 = param_1 + 0x58;
  }
  else
  {
    uVar1 = *(ulonglong *)(param_1 + 0x458) >> 1;
  }
  lVar3 = lVar3 + -1 + uVar1;
  *(longlong *)(param_1 + 0x48) = lVar3;
  while ((0 < *(int *)(param_1 + 0x38) || (param_2 != 0)))
  {
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -1;
    cVar2 = (char)(param_2 % (param_3 & 0xffffffff)) + '0';
    if ('9' < cVar2)
    {
      cVar2 = cVar2 + (param_4 ^ 1) * ' ' + '\a';
    }
    **(char **)(param_1 + 0x48) = cVar2;
    *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + -1;
    param_2 = param_2 / (param_3 & 0xffffffff);
  }
  *(int *)(param_1 + 0x50) = (int)lVar3 - *(int *)(param_1 + 0x48);
  *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + 1;
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//   9 names - too many to list
//
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

void type_case_integer_parse_into_buffer__
               (longlong param_1,ulonglong param_2,ulonglong param_3,byte param_4)
{
  ulonglong uVar1;
  char cVar2;
  longlong lVar3;

  lVar3 = *(longlong *)(param_1 + 0x460);
  if (lVar3 == 0)
  {
    uVar1 = 0x200;
    lVar3 = param_1 + 0x58;
  }
  else
  {
    uVar1 = *(ulonglong *)(param_1 + 0x458) >> 1;
  }
  lVar3 = lVar3 + -1 + uVar1;
  *(longlong *)(param_1 + 0x48) = lVar3;
  while ((0 < *(int *)(param_1 + 0x38) || (param_2 != 0)))
  {
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -1;
    cVar2 = (char)(param_2 % (param_3 & 0xffffffff)) + '0';
    if ('9' < cVar2)
    {
      cVar2 = cVar2 + (param_4 ^ 1) * ' ' + '\a';
    }
    **(char **)(param_1 + 0x48) = cVar2;
    *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + -1;
    param_2 = param_2 / (param_3 & 0xffffffff);
  }
  *(int *)(param_1 + 0x50) = (int)lVar3 - *(int *)(param_1 + 0x48);
  *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + 1;
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//   9 names - too many to list
//
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

void type_case_integer_parse_into_buffer__
               (longlong param_1,ulonglong param_2,ulonglong param_3,byte param_4)
{
  ulonglong uVar1;
  char cVar2;
  longlong lVar3;

  lVar3 = *(longlong *)(param_1 + 0x460);
  if (lVar3 == 0)
  {
    uVar1 = 0x200;
    lVar3 = param_1 + 0x58;
  }
  else
  {
    uVar1 = *(ulonglong *)(param_1 + 0x458) >> 1;
  }
  lVar3 = lVar3 + -1 + uVar1;
  *(longlong *)(param_1 + 0x48) = lVar3;
  while ((0 < *(int *)(param_1 + 0x38) || (param_2 != 0)))
  {
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -1;
    cVar2 = (char)(param_2 % (param_3 & 0xffffffff)) + '0';
    if ('9' < cVar2)
    {
      cVar2 = cVar2 + (param_4 ^ 1) * ' ' + '\a';
    }
    **(char **)(param_1 + 0x48) = cVar2;
    *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + -1;
    param_2 = param_2 / (param_3 & 0xffffffff);
  }
  *(int *)(param_1 + 0x50) = (int)lVar3 - *(int *)(param_1 + 0x48);
  *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + 1;
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//  private: void __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_integer_parse_into_buffer<unsigned
// __int64>(unsigned __int64,unsigned int,bool) __ptr64
//   9 names - too many to list
//
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

void type_case_integer_parse_into_buffer__
               (longlong param_1,ulonglong param_2,ulonglong param_3,byte param_4)
{
  ulonglong uVar1;
  char cVar2;
  longlong lVar3;

  lVar3 = *(longlong *)(param_1 + 0x460);
  if (lVar3 == 0)
  {
    uVar1 = 0x200;
    lVar3 = param_1 + 0x58;
  }
  else
  {
    uVar1 = *(ulonglong *)(param_1 + 0x458) >> 1;
  }
  lVar3 = lVar3 + -1 + uVar1;
  *(longlong *)(param_1 + 0x48) = lVar3;
  while ((0 < *(int *)(param_1 + 0x38) || (param_2 != 0)))
  {
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + -1;
    cVar2 = (char)(param_2 % (param_3 & 0xffffffff)) + '0';
    if ('9' < cVar2)
    {
      cVar2 = cVar2 + (param_4 ^ 1) * ' ' + '\a';
    }
    **(char **)(param_1 + 0x48) = cVar2;
    *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + -1;
    param_2 = param_2 / (param_3 & 0xffffffff);
  }
  *(int *)(param_1 + 0x50) = (int)lVar3 - *(int *)(param_1 + 0x48);
  *(longlong *)(param_1 + 0x48) = *(longlong *)(param_1 + 0x48) + 1;
  return;
}

// Library Function - Single Match
//  void __cdecl __crt_stdio_output::write_multiple_characters<class
// __crt_stdio_output::string_output_adapter<char>,char>(class
// __crt_stdio_output::string_output_adapter<char> const & __ptr64,char,int,int * __ptr64 const)
//
// Library: Visual Studio 2015 Release

void __crt_stdio_output::
     write_multiple_characters_class___crt_stdio_output__string_output_adapter_char__char_
               (string_output_adapter_char_ *param_1,char param_2,int param_3,int *param_4)
{
  longlong lVar1;
  int iVar2;

  iVar2 = 0;
  if (0 < param_3)
  {
    do
    {
      lVar1 = *(longlong *)param_1;
      if (*(longlong *)(lVar1 + 0x10) == *(longlong *)(lVar1 + 8))
      {
        if (*(char *)(lVar1 + 0x18) == '\0')
        {
          *param_4 = -1;
        }
        else
        {
          *param_4 = *param_4 + 1;
        }
      }
      else
      {
        *param_4 = *param_4 + 1;
        *(longlong *)(*(longlong *)param_1 + 0x10) = *(longlong *)(*(longlong *)param_1 + 0x10) + 1;
        ***(char ***)param_1 = param_2;
        **(longlong **)param_1 = **(longlong **)param_1 + 1;
      }
    } while ((*param_4 != -1) && (iVar2 = iVar2 + 1, iVar2 < param_3));
  }
  return;
}

// Library Function - Single Match
//  void __cdecl __crt_stdio_output::write_multiple_characters<class
// __crt_stdio_output::string_output_adapter<wchar_t>,char>(class
// __crt_stdio_output::string_output_adapter<wchar_t> const & __ptr64,char,int,int * __ptr64 const)
//
// Library: Visual Studio 2015 Release

void __crt_stdio_output::
     write_multiple_characters_class___crt_stdio_output__string_output_adapter_wchar_t__char_
               (string_output_adapter_wchar_t_ *param_1,char param_2,int param_3,int *param_4)
{
  longlong lVar1;
  int iVar2;

  if (0 < param_3)
  {
    iVar2 = 0;
    do
    {
      lVar1 = *(longlong *)param_1;
      if (*(longlong *)(lVar1 + 0x10) == *(longlong *)(lVar1 + 8))
      {
        if (*(char *)(lVar1 + 0x18) == '\0')
        {
          *param_4 = -1;
        }
        else
        {
          *param_4 = *param_4 + 1;
        }
      }
      else
      {
        *param_4 = *param_4 + 1;
        *(longlong *)(*(longlong *)param_1 + 0x10) = *(longlong *)(*(longlong *)param_1 + 0x10) + 1;
        ***(short ***)param_1 = (short)param_2;
        **(longlong **)param_1 = **(longlong **)param_1 + 2;
      }
    } while ((*param_4 != -1) && (iVar2 = iVar2 + 1, iVar2 < param_3));
  }
  return;
}

// Library Function - Single Match
//  public: __cdecl
// __acrt_stdio_temporary_buffering_guard::__acrt_stdio_temporary_buffering_guard(struct _iobuf *
// __ptr64 const) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __thiscall
__acrt_stdio_temporary_buffering_guard::__acrt_stdio_temporary_buffering_guard
          (__acrt_stdio_temporary_buffering_guard *this,_iobuf *param_1)
{
  ulonglong uVar1;

  *(_iobuf **)this = param_1;
  uVar1 = __acrt_stdio_begin_temporary_buffering_nolock((FILE *)param_1);
  this[8] = SUB81(uVar1, 0);
  return;
}

// Library Function - Multiple Matches With Different Base Names
//  public: int __cdecl <lambda_32f117a32e8f8eb613cbf2ca819ed45e>::operator()(void)const __ptr64
//  public: int __cdecl <lambda_a31071773b9a94e445cbd5d04ef99106>::operator()(void)const __ptr64
//
// Library: Visual Studio 2017 Release

void FID_conflict_operator__(FILE **param_1)
{
  FILE *pFVar1;
  ulonglong uVar2;
  undefined auStack1256[32];
  __acrt_ptd *local_4c8;
  undefined local_4c0[16];
  char local_4b0;
  char *local_4a8;
  undefined *local_4a0;
  undefined8 local_498;
  char *local_490;
  char *local_488;
  undefined8 local_480;
  undefined8 local_478;
  undefined4 local_470;
  undefined2 local_468;
  undefined4 local_458;
  undefined local_454;
  undefined8 local_50;
  LPVOID local_48;
  char *local_40;
  undefined4 local_38;
  ulonglong local_28;

  local_28 = DAT_1800ee160 ^ (ulonglong)auStack1256;
  pFVar1 = (FILE *)(*param_1)->_ptr;
  uVar2 = __acrt_stdio_begin_temporary_buffering_nolock(pFVar1);
  FUN_18004e538(&local_4c8, (undefined4 *)param_1[1]->_ptr);
  local_4a0 = local_4c0;
  local_488 = param_1[4]->_ptr;
  local_40 = (*param_1)->_ptr;
  local_490 = param_1[3]->_ptr;
  local_4a8 = param_1[2]->_ptr;
  local_498 = 0;
  local_480 = 0;
  local_478 = 0;
  local_470 = 0;
  local_468 = 0;
  local_458 = 0;
  local_454 = 0;
  local_50 = 0;
  local_48 = (LPVOID)0x0;
  local_38 = 0;
  FUN_1800509e8((ulonglong *)&local_4a8);
  _free_base(local_48);
  local_48 = (LPVOID)0x0;
  if (local_4b0 != '\0')
  {
    *(uint *)(local_4c8 + 0x3a8) = *(uint *)(local_4c8 + 0x3a8) & 0xfffffffd;
  }
  __acrt_stdio_end_temporary_buffering_nolock((char)uVar2, pFVar1);
  FUN_180034d00(local_28 ^ (ulonglong)auStack1256);
  return;
}

// Library Function - Multiple Matches With Different Base Names
//  public: int __cdecl <lambda_7e489fec146d5348dbc86d3cce37c1b5>::operator()(void)const __ptr64
//  public: int __cdecl <lambda_a775ed57af18ba8e4d5dc780aa9068fe>::operator()(void)const __ptr64
//
// Library: Visual Studio 2017 Release

void FID_conflict_operator__(FILE **param_1)
{
  FILE *pFVar1;
  ulonglong uVar2;
  undefined auStack1256[32];
  __acrt_ptd *local_4c8;
  undefined local_4c0[16];
  char local_4b0;
  char *local_4a8;
  undefined *local_4a0;
  undefined8 local_498;
  char *local_490;
  char *local_488;
  undefined8 local_480;
  undefined8 local_478;
  undefined4 local_470;
  undefined local_468;
  undefined2 local_466;
  undefined4 local_458;
  undefined local_454;
  undefined8 local_50;
  LPVOID local_48;
  char *local_40;
  undefined4 local_38;
  ulonglong local_28;

  local_28 = DAT_1800ee160 ^ (ulonglong)auStack1256;
  pFVar1 = (FILE *)(*param_1)->_ptr;
  uVar2 = __acrt_stdio_begin_temporary_buffering_nolock(pFVar1);
  FUN_18004e538(&local_4c8, (undefined4 *)param_1[1]->_ptr);
  local_4a0 = local_4c0;
  local_488 = param_1[4]->_ptr;
  local_40 = (*param_1)->_ptr;
  local_490 = param_1[3]->_ptr;
  local_4a8 = param_1[2]->_ptr;
  local_498 = 0;
  local_480 = 0;
  local_478 = 0;
  local_470 = 0;
  local_468 = 0;
  local_466 = 0;
  local_458 = 0;
  local_454 = 0;
  local_50 = 0;
  local_48 = (LPVOID)0x0;
  local_38 = 0;
  FUN_180051788((__uint64 *)&local_4a8);
  _free_base(local_48);
  local_48 = (LPVOID)0x0;
  if (local_4b0 != '\0')
  {
    *(uint *)(local_4c8 + 0x3a8) = *(uint *)(local_4c8 + 0x3a8) & 0xfffffffd;
  }
  __acrt_stdio_end_temporary_buffering_nolock((char)uVar2, pFVar1);
  FUN_180034d00(local_28 ^ (ulonglong)auStack1256);
  return;
}

// Library Function - Single Match
//  public: int __cdecl <lambda_a2288fdbbd702c8f223b438290af01a4>::operator()(void)const __ptr64
//
// Library: Visual Studio 2017 Release

int __thiscall<lambda_a2288fdbbd702c8f223b438290af01a4>::operator__(_lambda_a2288fdbbd702c8f223b438290af01a4_ *this)
{
  FILE *pFVar1;
  int iVar2;
  ulonglong uVar3;
  undefined auStack3672[32];
  __acrt_ptd *local_e38;
  undefined local_e30[16];
  char local_e20;
  ulonglong local_e18;
  undefined *local_e10;
  undefined8 local_e08;
  undefined8 local_e00;
  undefined8 local_df8;
  undefined8 local_df0;
  undefined8 local_de8;
  undefined4 local_de0;
  undefined2 local_dd8;
  undefined4 local_dc8;
  undefined local_dc4;
  undefined8 local_9c0;
  LPVOID local_9b8;
  undefined8 local_9b0;
  undefined4 local_9a8;
  undefined8 local_9a0;
  undefined8 local_998;
  undefined4 local_30;
  undefined4 local_2c;
  ulonglong local_28;

  local_28 = DAT_1800ee160 ^ (ulonglong)auStack3672;
  pFVar1 = **(FILE ***)this;
  uVar3 = __acrt_stdio_begin_temporary_buffering_nolock(pFVar1);
  FUN_18004e538(&local_e38, (undefined4 *)**(undefined8 **)(this + 8));
  local_e10 = local_e30;
  local_df8 = **(undefined8 **)(this + 0x20);
  local_9b0 = **(undefined8 **)this;
  local_e00 = **(undefined8 **)(this + 0x18);
  local_e18 = **(ulonglong **)(this + 0x10);
  local_30 = 0xffffffff;
  local_2c = 0xffffffff;
  local_e08 = 0;
  local_df0 = 0;
  local_de8 = 0;
  local_de0 = 0;
  local_dd8 = 0;
  local_dc8 = 0;
  local_dc4 = 0;
  local_9c0 = 0;
  local_9b8 = (LPVOID)0x0;
  local_9a8 = 0;
  local_9a0 = 0;
  local_998 = local_e00;
  FUN_180050c14(&local_e18, *(ulonglong **)(this + 0x10), local_e18, (uint)local_df8);
  _free_base(local_9b8);
  local_9b8 = (LPVOID)0x0;
  if (local_e20 != '\0')
  {
    *(uint *)(local_e38 + 0x3a8) = *(uint *)(local_e38 + 0x3a8) & 0xfffffffd;
  }
  __acrt_stdio_end_temporary_buffering_nolock((char)uVar3, pFVar1);
  iVar2 = FUN_180034d00(local_28 ^ (ulonglong)auStack3672);
  return iVar2;
}

// Library Function - Multiple Matches With Different Base Names
//  public: int __cdecl <lambda_32f117a32e8f8eb613cbf2ca819ed45e>::operator()(void)const __ptr64
//  public: int __cdecl <lambda_a31071773b9a94e445cbd5d04ef99106>::operator()(void)const __ptr64
//
// Library: Visual Studio 2017 Release

void FID_conflict_operator__(FILE **param_1)
{
  FILE *pFVar1;
  ulonglong uVar2;
  undefined auStack1256[32];
  __acrt_ptd *local_4c8;
  undefined local_4c0[16];
  char local_4b0;
  char *local_4a8;
  undefined *local_4a0;
  undefined8 local_498;
  char *local_490;
  char *local_488;
  undefined8 local_480;
  undefined8 local_478;
  undefined4 local_470;
  undefined2 local_468;
  undefined4 local_458;
  undefined local_454;
  undefined8 local_50;
  LPVOID local_48;
  char *local_40;
  undefined4 local_38;
  ulonglong local_28;

  local_28 = DAT_1800ee160 ^ (ulonglong)auStack1256;
  pFVar1 = (FILE *)(*param_1)->_ptr;
  uVar2 = __acrt_stdio_begin_temporary_buffering_nolock(pFVar1);
  FUN_18004e538(&local_4c8, (undefined4 *)param_1[1]->_ptr);
  local_4a0 = local_4c0;
  local_488 = param_1[4]->_ptr;
  local_40 = (*param_1)->_ptr;
  local_490 = param_1[3]->_ptr;
  local_4a8 = param_1[2]->_ptr;
  local_498 = 0;
  local_480 = 0;
  local_478 = 0;
  local_470 = 0;
  local_468 = 0;
  local_458 = 0;
  local_454 = 0;
  local_50 = 0;
  local_48 = (LPVOID)0x0;
  local_38 = 0;
  FUN_180050eb8((ulonglong *)&local_4a8);
  _free_base(local_48);
  local_48 = (LPVOID)0x0;
  if (local_4b0 != '\0')
  {
    *(uint *)(local_4c8 + 0x3a8) = *(uint *)(local_4c8 + 0x3a8) & 0xfffffffd;
  }
  __acrt_stdio_end_temporary_buffering_nolock((char)uVar2, pFVar1);
  FUN_180034d00(local_28 ^ (ulonglong)auStack1256);
  return;
}

// Library Function - Multiple Matches With Different Base Names
//  public: int __cdecl <lambda_7e489fec146d5348dbc86d3cce37c1b5>::operator()(void)const __ptr64
//  public: int __cdecl <lambda_a775ed57af18ba8e4d5dc780aa9068fe>::operator()(void)const __ptr64
//
// Library: Visual Studio 2017 Release

void FID_conflict_operator__(FILE **param_1)
{
  FILE *pFVar1;
  ulonglong uVar2;
  undefined auStack1256[32];
  __acrt_ptd *local_4c8;
  undefined local_4c0[16];
  char local_4b0;
  char *local_4a8;
  undefined *local_4a0;
  undefined8 local_498;
  char *local_490;
  char *local_488;
  undefined8 local_480;
  undefined8 local_478;
  undefined4 local_470;
  undefined local_468;
  undefined2 local_466;
  undefined4 local_458;
  undefined local_454;
  undefined8 local_50;
  LPVOID local_48;
  char *local_40;
  undefined4 local_38;
  ulonglong local_28;

  local_28 = DAT_1800ee160 ^ (ulonglong)auStack1256;
  pFVar1 = (FILE *)(*param_1)->_ptr;
  uVar2 = __acrt_stdio_begin_temporary_buffering_nolock(pFVar1);
  FUN_18004e538(&local_4c8, (undefined4 *)param_1[1]->_ptr);
  local_4a0 = local_4c0;
  local_488 = param_1[4]->_ptr;
  local_40 = (*param_1)->_ptr;
  local_490 = param_1[3]->_ptr;
  local_4a8 = param_1[2]->_ptr;
  local_498 = 0;
  local_480 = 0;
  local_478 = 0;
  local_470 = 0;
  local_468 = 0;
  local_466 = 0;
  local_458 = 0;
  local_454 = 0;
  local_50 = 0;
  local_48 = (LPVOID)0x0;
  local_38 = 0;
  FUN_180051cb8((__uint64 *)&local_4a8);
  _free_base(local_48);
  local_48 = (LPVOID)0x0;
  if (local_4b0 != '\0')
  {
    *(uint *)(local_4c8 + 0x3a8) = *(uint *)(local_4c8 + 0x3a8) & 0xfffffffd;
  }
  __acrt_stdio_end_temporary_buffering_nolock((char)uVar2, pFVar1);
  FUN_180034d00(local_28 ^ (ulonglong)auStack1256);
  return;
}

// Library Function - Single Match
//  public: int __cdecl <lambda_ee59099aa97e0ff6f003b984c1584058>::operator()(void)const __ptr64
//
// Library: Visual Studio 2017 Release

int __thiscall<lambda_ee59099aa97e0ff6f003b984c1584058>::operator__(_lambda_ee59099aa97e0ff6f003b984c1584058_ *this)
{
  FILE *pFVar1;
  int iVar2;
  ulonglong uVar3;
  undefined auStack3672[32];
  __acrt_ptd *local_e38;
  undefined local_e30[16];
  char local_e20;
  __uint64 local_e18;
  undefined *local_e10;
  undefined8 local_e08;
  undefined8 local_e00;
  undefined8 local_df8;
  undefined8 local_df0;
  undefined8 local_de8;
  undefined4 local_de0;
  undefined local_dd8;
  undefined2 local_dd6;
  undefined4 local_dc8;
  undefined local_dc4;
  undefined8 local_9c0;
  LPVOID local_9b8;
  undefined8 local_9b0;
  undefined4 local_9a8;
  undefined8 local_9a0;
  undefined8 local_998;
  undefined4 local_30;
  undefined4 local_2c;
  ulonglong local_28;

  local_28 = DAT_1800ee160 ^ (ulonglong)auStack3672;
  pFVar1 = **(FILE ***)this;
  uVar3 = __acrt_stdio_begin_temporary_buffering_nolock(pFVar1);
  FUN_18004e538(&local_e38, (undefined4 *)**(undefined8 **)(this + 8));
  local_e10 = local_e30;
  local_df8 = **(undefined8 **)(this + 0x20);
  local_9b0 = **(undefined8 **)this;
  local_e00 = **(undefined8 **)(this + 0x18);
  local_e18 = **(__uint64 **)(this + 0x10);
  local_30 = 0xffffffff;
  local_2c = 0xffffffff;
  local_e08 = 0;
  local_df0 = 0;
  local_de8 = 0;
  local_de0 = 0;
  local_dd8 = 0;
  local_dd6 = 0;
  local_dc8 = 0;
  local_dc4 = 0;
  local_9c0 = 0;
  local_9b8 = (LPVOID)0x0;
  local_9a8 = 0;
  local_9a0 = 0;
  local_998 = local_e00;
  process(&local_e18);
  _free_base(local_9b8);
  local_9b8 = (LPVOID)0x0;
  if (local_e20 != '\0')
  {
    *(uint *)(local_e38 + 0x3a8) = *(uint *)(local_e38 + 0x3a8) & 0xfffffffd;
  }
  __acrt_stdio_end_temporary_buffering_nolock((char)uVar3, pFVar1);
  iVar2 = FUN_180034d00(local_28 ^ (ulonglong)auStack3672);
  return iVar2;
}

// Library Function - Single Match
//  void __cdecl __crt_stdio_output::force_decimal_point(char * __ptr64,struct __crt_locale_pointers
// * __ptr64 const)
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

void __crt_stdio_output::force_decimal_point(char *param_1, __crt_locale_pointers *param_2)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  byte bVar4;

  iVar2 = tolower((int)*param_1);
  if (iVar2 != 0x65)
  {
    do
    {
      param_1 = (char *)((byte *)param_1 + 1);
      uVar3 = FUN_180068934((uint)(byte)*param_1);
    } while (uVar3 != 0);
  }
  iVar2 = tolower((int)*param_1);
  if (iVar2 == 0x78)
  {
    param_1 = (char *)((byte *)param_1 + 2);
  }
  bVar4 = *param_1;
  *param_1 = ***(byte ***)(*(longlong *)param_2 + 0xf8);
  do
  {
    param_1 = (char *)((byte *)param_1 + 1);
    bVar1 = *param_1;
    *param_1 = bVar4;
    bVar4 = bVar1;
  } while (*param_1 != 0);
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  public: int __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::process(void) __ptr64
//  public: int __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>>::process(void) __ptr64
//
// Library: Visual Studio 2015 Release

undefined4 process(__uint64 *param_1)
{
  __uint64 *p_Var1;
  __uint64 *p_Var2;
  short sVar3;
  int iVar4;
  char cVar5;
  ulong *puVar6;
  undefined8 uVar7;
  uint uVar8;
  __uint64 *p_Var9;

  if ((param_1[0x8d] == 0) || (param_1[3] == 0))
  {
    puVar6 = __doserrno();
    *puVar6 = 0x16;
    FUN_18006738c();
  }
  else
  {
    do
    {
      *(int *)(param_1 + 0x8f) = *(int *)(param_1 + 0x8f) + 1;
      if ((*(int *)(param_1 + 0x8f) == 3) ||
          ((*(int *)(param_1 + 0x8f) == 2 && (*(int *)((longlong)param_1 + 0x47c) == 1))))
      {
        return *(undefined4 *)(param_1 + 5);
      }
      p_Var1 = (__uint64 *)((longlong)param_1 + 0x34);
      p_Var2 = param_1 + 7;
      *(undefined4 *)((longlong)param_1 + 0x47c) = 0;
      *(undefined4 *)(param_1 + 0x1bd) = 0xffffffff;
      *(undefined4 *)((longlong)param_1 + 0xdec) = 0xffffffff;
      *(int *)p_Var1 = 0;
      *(int *)p_Var2 = 0;
      param_1[3] = (__uint64)(short *)param_1[0x90];
      *(undefined4 *)(param_1 + 10) = 0;
      *(undefined4 *)((longlong)param_1 + 0x2c) = 0;
      sVar3 = *(short *)param_1[0x90];
      *(short *)((longlong)param_1 + 0x42) = sVar3;
      while (sVar3 != 0)
      {
        param_1[3] = param_1[3] + 2;
        if (*(int *)(param_1 + 5) < 0)
          goto LAB_180051c6f;
        uVar8 = 0;
        if ((ushort)(*(short *)((longlong)param_1 + 0x42) - 0x20U) < 0x5b)
        {
          uVar8 = (byte)(&DAT_1800c9e90)[*(ushort *)((longlong)param_1 + 0x42)] & 0xf;
        }
        *(uint *)((longlong)param_1 + 0x2c) =
            (uint)((byte)(&DAT_1800c9eb0)[*(int *)((longlong)param_1 + 0x2c) + uVar8 * 9] >> 4);
        uVar7 = validate_and_update_state_at_beginning_of_format_character((longlong)param_1);
        if ((char)uVar7 == '\0')
        {
          return 0xffffffff;
        }
        iVar4 = *(int *)((longlong)param_1 + 0x2c);
        if (iVar4 == 8)
        {
          puVar6 = __doserrno();
          *puVar6 = 0x16;
          FUN_18006738c();
          return 0xffffffff;
        }
        if (iVar4 == 0)
        {
          uVar7 = FUN_180052ef0((longlong)param_1);
          cVar5 = (char)uVar7;
          goto LAB_180051c52;
        }
        if (iVar4 == 1)
        {
          *(int *)p_Var1 = 0;
          *(undefined *)(param_1 + 8) = 0;
          *(undefined4 *)(param_1 + 6) = 0;
          *(int *)p_Var2 = -1;
          *(undefined4 *)((longlong)param_1 + 0x3c) = 0;
          *(undefined *)((longlong)param_1 + 0x54) = 0;
        }
        else
        {
          if (iVar4 == 2)
          {
            sVar3 = *(short *)((longlong)param_1 + 0x42);
            if (sVar3 == 0x20)
            {
              *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 2;
            }
            else
            {
              if (sVar3 == 0x23)
              {
                *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 0x20;
              }
              else
              {
                if (sVar3 == 0x2b)
                {
                  *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 1;
                }
                else
                {
                  if (sVar3 == 0x2d)
                  {
                    *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 4;
                  }
                  else
                  {
                    if (sVar3 == 0x30)
                    {
                      *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 8;
                    }
                  }
                }
              }
            }
          }
          else
          {
            if (iVar4 == 3)
            {
              p_Var9 = p_Var1;
              if (*(short *)((longlong)param_1 + 0x42) == 0x2a)
              {
                uVar7 = update_field_width(param_1);
                if ((char)uVar7 == '\0')
                {
                  return 0xffffffff;
                }
                if ((*(int *)(param_1 + 0x8f) == 1) && (*(int *)((longlong)param_1 + 0x47c) != 1))
                  goto LAB_180051c56;
                if (*(int *)p_Var1 < 0)
                {
                  *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 4;
                  *(int *)p_Var1 = -*(int *)p_Var1;
                }
              LAB_180051bf6:
                cVar5 = '\x01';
              }
              else
              {
              LAB_180051b7c:
                uVar7 = FUN_1800506b4((longlong)param_1, (undefined4 *)p_Var9);
                cVar5 = (char)uVar7;
              }
            LAB_180051c52:
              if (cVar5 == '\0')
              {
                return 0xffffffff;
              }
            }
            else
            {
              if (iVar4 == 4)
              {
                *(int *)p_Var2 = 0;
              }
              else
              {
                if (iVar4 != 5)
                {
                  if (iVar4 == 6)
                  {
                    uVar7 = state_case_size(param_1);
                    cVar5 = (char)uVar7;
                  }
                  else
                  {
                    if (iVar4 != 7)
                    {
                      return 0xffffffff;
                    }
                    cVar5 = FUN_1800561b0(param_1);
                  }
                  goto LAB_180051c52;
                }
                p_Var9 = p_Var2;
                if (*(short *)((longlong)param_1 + 0x42) != 0x2a)
                  goto LAB_180051b7c;
                uVar7 = update_precision(param_1);
                if ((char)uVar7 == '\0')
                {
                  return 0xffffffff;
                }
                if ((*(int *)(param_1 + 0x8f) != 1) || (*(int *)((longlong)param_1 + 0x47c) == 1))
                {
                  if (*(int *)p_Var2 < 0)
                  {
                    *(int *)p_Var2 = -1;
                  }
                  goto LAB_180051bf6;
                }
              }
            }
          }
        }
      LAB_180051c56:
        sVar3 = *(short *)param_1[3];
        *(short *)((longlong)param_1 + 0x42) = sVar3;
      }
      param_1[3] = param_1[3] + 2;
    LAB_180051c6f:
      uVar7 = validate_and_update_state_at_end_of_format_string((longlong)param_1);
    } while ((char)uVar7 != '\0');
  }
  return 0xffffffff;
}

// Library Function - Multiple Matches With Same Base Name
//  public: int __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::process(void) __ptr64
//  public: int __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>>::process(void) __ptr64
//
// Library: Visual Studio 2015 Release

undefined4 process(__uint64 *param_1)
{
  __uint64 *p_Var1;
  __uint64 *p_Var2;
  short sVar3;
  int iVar4;
  char cVar5;
  ulong *puVar6;
  undefined8 uVar7;
  uint uVar8;
  __uint64 *p_Var9;

  if ((param_1[0x8d] == 0) || (param_1[3] == 0))
  {
    puVar6 = __doserrno();
    *puVar6 = 0x16;
    FUN_18006738c();
  }
  else
  {
    do
    {
      *(int *)(param_1 + 0x8f) = *(int *)(param_1 + 0x8f) + 1;
      if ((*(int *)(param_1 + 0x8f) == 3) ||
          ((*(int *)(param_1 + 0x8f) == 2 && (*(int *)((longlong)param_1 + 0x47c) == 1))))
      {
        return *(undefined4 *)(param_1 + 5);
      }
      p_Var1 = (__uint64 *)((longlong)param_1 + 0x34);
      p_Var2 = param_1 + 7;
      *(undefined4 *)((longlong)param_1 + 0x47c) = 0;
      *(undefined4 *)(param_1 + 0x1bd) = 0xffffffff;
      *(undefined4 *)((longlong)param_1 + 0xdec) = 0xffffffff;
      *(int *)p_Var1 = 0;
      *(int *)p_Var2 = 0;
      param_1[3] = (__uint64)(short *)param_1[0x90];
      *(undefined4 *)(param_1 + 10) = 0;
      *(undefined4 *)((longlong)param_1 + 0x2c) = 0;
      sVar3 = *(short *)param_1[0x90];
      *(short *)((longlong)param_1 + 0x42) = sVar3;
      while (sVar3 != 0)
      {
        param_1[3] = param_1[3] + 2;
        if (*(int *)(param_1 + 5) < 0)
          goto LAB_18005240b;
        uVar8 = 0;
        if ((ushort)(*(short *)((longlong)param_1 + 0x42) - 0x20U) < 0x5b)
        {
          uVar8 = (byte)(&DAT_1800c9e90)[*(ushort *)((longlong)param_1 + 0x42)] & 0xf;
        }
        *(uint *)((longlong)param_1 + 0x2c) =
            (uint)((byte)(&DAT_1800c9eb0)[*(int *)((longlong)param_1 + 0x2c) + uVar8 * 9] >> 4);
        uVar7 = validate_and_update_state_at_beginning_of_format_character((longlong)param_1);
        if ((char)uVar7 == '\0')
        {
          return 0xffffffff;
        }
        iVar4 = *(int *)((longlong)param_1 + 0x2c);
        if (iVar4 == 8)
        {
          puVar6 = __doserrno();
          *puVar6 = 0x16;
          FUN_18006738c();
          return 0xffffffff;
        }
        if (iVar4 == 0)
        {
          uVar7 = FUN_180053018((longlong)param_1);
          cVar5 = (char)uVar7;
          goto LAB_1800523ee;
        }
        if (iVar4 == 1)
        {
          *(int *)p_Var1 = 0;
          *(undefined *)(param_1 + 8) = 0;
          *(undefined4 *)(param_1 + 6) = 0;
          *(int *)p_Var2 = -1;
          *(undefined4 *)((longlong)param_1 + 0x3c) = 0;
          *(undefined *)((longlong)param_1 + 0x54) = 0;
        }
        else
        {
          if (iVar4 == 2)
          {
            sVar3 = *(short *)((longlong)param_1 + 0x42);
            if (sVar3 == 0x20)
            {
              *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 2;
            }
            else
            {
              if (sVar3 == 0x23)
              {
                *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 0x20;
              }
              else
              {
                if (sVar3 == 0x2b)
                {
                  *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 1;
                }
                else
                {
                  if (sVar3 == 0x2d)
                  {
                    *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 4;
                  }
                  else
                  {
                    if (sVar3 == 0x30)
                    {
                      *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 8;
                    }
                  }
                }
              }
            }
          }
          else
          {
            if (iVar4 == 3)
            {
              p_Var9 = p_Var1;
              if (*(short *)((longlong)param_1 + 0x42) == 0x2a)
              {
                uVar7 = update_field_width(param_1);
                if ((char)uVar7 == '\0')
                {
                  return 0xffffffff;
                }
                if ((*(int *)(param_1 + 0x8f) == 1) && (*(int *)((longlong)param_1 + 0x47c) != 1))
                  goto LAB_1800523f2;
                if (*(int *)p_Var1 < 0)
                {
                  *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 4;
                  *(int *)p_Var1 = -*(int *)p_Var1;
                }
              LAB_180052392:
                cVar5 = '\x01';
              }
              else
              {
              LAB_180052318:
                uVar7 = FUN_1800508a0((longlong)param_1, (undefined4 *)p_Var9);
                cVar5 = (char)uVar7;
              }
            LAB_1800523ee:
              if (cVar5 == '\0')
              {
                return 0xffffffff;
              }
            }
            else
            {
              if (iVar4 == 4)
              {
                *(int *)p_Var2 = 0;
              }
              else
              {
                if (iVar4 != 5)
                {
                  if (iVar4 == 6)
                  {
                    uVar7 = state_case_size(param_1);
                    cVar5 = (char)uVar7;
                  }
                  else
                  {
                    if (iVar4 != 7)
                    {
                      return 0xffffffff;
                    }
                    cVar5 = FUN_180056a74(param_1);
                  }
                  goto LAB_1800523ee;
                }
                p_Var9 = p_Var2;
                if (*(short *)((longlong)param_1 + 0x42) != 0x2a)
                  goto LAB_180052318;
                uVar7 = update_precision(param_1);
                if ((char)uVar7 == '\0')
                {
                  return 0xffffffff;
                }
                if ((*(int *)(param_1 + 0x8f) != 1) || (*(int *)((longlong)param_1 + 0x47c) == 1))
                {
                  if (*(int *)p_Var2 < 0)
                  {
                    *(int *)p_Var2 = -1;
                  }
                  goto LAB_180052392;
                }
              }
            }
          }
        }
      LAB_1800523f2:
        sVar3 = *(short *)param_1[3];
        *(short *)((longlong)param_1 + 0x42) = sVar3;
      }
      param_1[3] = param_1[3] + 2;
    LAB_18005240b:
      uVar7 = validate_and_update_state_at_end_of_format_string((longlong)param_1);
    } while ((char)uVar7 != '\0');
  }
  return 0xffffffff;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::state_case_normal(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::state_case_normal(void) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong state_case_normal(longlong param_1)
{
  ulonglong uVar1;
  ulong *puVar2;

  uVar1 = FUN_180053518(param_1);
  if ((char)uVar1 != '\0')
  {
    if ((((*(uint *)(*(longlong *)(param_1 + 0x468) + 0x14) >> 0xc & 1) == 0) ||
         (uVar1 = *(ulonglong *)(param_1 + 0x468), *(longlong *)(uVar1 + 8) != 0)) &&
        (uVar1 = _fputc_nolock(*(byte *)(param_1 + 0x41), *(FILE **)(param_1 + 0x468)),
         (int)uVar1 == -1))
    {
      *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
    }
    else
    {
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
    }
    return CONCAT71((int7)(uVar1 >> 8), 1);
  }
  puVar2 = __doserrno();
  *puVar2 = 0x16;
  uVar1 = FUN_18006738c();
  return uVar1 & 0xffffffffffffff00;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::state_case_normal(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::state_case_normal(void) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong state_case_normal(longlong param_1)
{
  ulonglong uVar1;
  ulong *puVar2;

  uVar1 = FUN_180053650(param_1);
  if ((char)uVar1 != '\0')
  {
    if ((((*(uint *)(*(longlong *)(param_1 + 0x468) + 0x14) >> 0xc & 1) == 0) ||
         (uVar1 = *(ulonglong *)(param_1 + 0x468), *(longlong *)(uVar1 + 8) != 0)) &&
        (uVar1 = _fputc_nolock(*(byte *)(param_1 + 0x41), *(FILE **)(param_1 + 0x468)),
         (int)uVar1 == -1))
    {
      *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
    }
    else
    {
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
    }
    return CONCAT71((int7)(uVar1 >> 8), 1);
  }
  puVar2 = __doserrno();
  *puVar2 = 0x16;
  uVar1 = FUN_18006738c();
  return uVar1 & 0xffffffffffffff00;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::state_case_normal(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::state_case_normal(void) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong state_case_normal(longlong param_1)
{
  undefined uVar1;
  longlong lVar2;
  longlong lVar3;
  ulonglong uVar4;
  ulong *puVar5;

  uVar4 = FUN_1800536ec(param_1);
  if ((char)uVar4 == '\0')
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  else
  {
    lVar2 = *(longlong *)(param_1 + 0x468);
    uVar1 = *(undefined *)(param_1 + 0x41);
    lVar3 = *(longlong *)(lVar2 + 8);
    if (*(longlong *)(lVar2 + 0x10) == lVar3)
    {
      if (*(char *)(lVar2 + 0x18) == '\0')
      {
        *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
      }
      else
      {
        *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
      }
    }
    else
    {
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
      *(longlong *)(lVar2 + 0x10) = *(longlong *)(lVar2 + 0x10) + 1;
      *(undefined *)**(undefined8 **)(param_1 + 0x468) = uVar1;
      **(longlong **)(param_1 + 0x468) = **(longlong **)(param_1 + 0x468) + 1;
    }
    uVar4 = CONCAT71((int7)((ulonglong)lVar3 >> 8), 1);
  }
  return uVar4;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::state_case_normal(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::state_case_normal(void) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong state_case_normal(longlong param_1)
{
  undefined uVar1;
  longlong lVar2;
  longlong lVar3;
  ulonglong uVar4;
  ulong *puVar5;

  uVar4 = FUN_18005381c(param_1);
  if ((char)uVar4 == '\0')
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  else
  {
    lVar2 = *(longlong *)(param_1 + 0x468);
    uVar1 = *(undefined *)(param_1 + 0x41);
    lVar3 = *(longlong *)(lVar2 + 8);
    if (*(longlong *)(lVar2 + 0x10) == lVar3)
    {
      if (*(char *)(lVar2 + 0x18) == '\0')
      {
        *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
      }
      else
      {
        *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
      }
    }
    else
    {
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
      *(longlong *)(lVar2 + 0x10) = *(longlong *)(lVar2 + 0x10) + 1;
      *(undefined *)**(undefined8 **)(param_1 + 0x468) = uVar1;
      **(longlong **)(param_1 + 0x468) = **(longlong **)(param_1 + 0x468) + 1;
    }
    uVar4 = CONCAT71((int7)((ulonglong)lVar3 >> 8), 1);
  }
  return uVar4;
}

// Library Function - Multiple Matches With Different Base Names
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_normal(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_normal(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_normal_common(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_normal_common(void) __ptr64
//   5 names - too many to list
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 FID_conflict_state_case_normal_common(longlong param_1)
{
  longlong lVar1;

  *(undefined *)(param_1 + 0x54) = 1;
  if (((*(uint *)(*(longlong *)(param_1 + 0x468) + 0x14) >> 0xc & 1) == 0) ||
      (lVar1 = *(longlong *)(param_1 + 0x468), *(longlong *)(lVar1 + 8) != 0))
  {
    lVar1 = FUN_18006b814(*(WCHAR *)(param_1 + 0x42), *(FILE **)(param_1 + 0x468));
    if ((short)lVar1 == -1)
    {
      *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
      goto LAB_180052fbc;
    }
  }
  *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
LAB_180052fbc:
  return CONCAT71((int7)((ulonglong)lVar1 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_precision(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::state_case_precision(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::state_case_precision(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong state_case_precision(longlong param_1, undefined8 param_2, undefined8 param_3, uint param_4)
{
  ulonglong uVar1;

  if (*(char *)(param_1 + 0x41) != '*')
  {
    uVar1 = FUN_1800502dc(param_1, (undefined4 *)(param_1 + 0x38));
    return uVar1;
  }
  uVar1 = update_precision(param_1, param_2, param_3, param_4);
  if ((char)uVar1 != '\0')
  {
    if (((*(int *)(param_1 + 0x478) != 1) || (*(int *)(param_1 + 0x47c) == 1)) &&
        (*(int *)(param_1 + 0x38) < 0))
    {
      *(undefined4 *)(param_1 + 0x38) = 0xffffffff;
    }
    uVar1 = CONCAT71((int7)(uVar1 >> 8), 1);
  }
  return uVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_precision(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_precision(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>>::state_case_precision(void) __ptr64
//
// Library: Visual Studio 2015 Release

undefined8 state_case_precision(__uint64 *param_1)
{
  undefined8 uVar1;

  if (*(short *)((longlong)param_1 + 0x42) != 0x2a)
  {
    uVar1 = FUN_1800506b4((longlong)param_1, (undefined4 *)(param_1 + 7));
    return uVar1;
  }
  uVar1 = update_precision(param_1);
  if ((char)uVar1 != '\0')
  {
    if (((*(int *)(param_1 + 0x8f) != 1) || (*(int *)((longlong)param_1 + 0x47c) == 1)) &&
        (*(int *)(param_1 + 7) < 0))
    {
      *(undefined4 *)(param_1 + 7) = 0xffffffff;
    }
    uVar1 = CONCAT71((int7)((ulonglong)uVar1 >> 8), 1);
  }
  return uVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_precision(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_precision(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>>::state_case_precision(void) __ptr64
//
// Library: Visual Studio 2015 Release

undefined8 state_case_precision(__uint64 *param_1)
{
  undefined8 uVar1;

  if (*(short *)((longlong)param_1 + 0x42) != 0x2a)
  {
    uVar1 = FUN_1800508a0((longlong)param_1, (undefined4 *)(param_1 + 7));
    return uVar1;
  }
  uVar1 = update_precision(param_1);
  if ((char)uVar1 != '\0')
  {
    if (((*(int *)(param_1 + 0x8f) != 1) || (*(int *)((longlong)param_1 + 0x47c) == 1)) &&
        (*(int *)(param_1 + 7) < 0))
    {
      *(undefined4 *)(param_1 + 7) = 0xffffffff;
    }
    uVar1 = CONCAT71((int7)((ulonglong)uVar1 >> 8), 1);
  }
  return uVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::state_case_size(void) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong state_case_size(ulonglong *param_1)
{
  char cVar1;
  char *pcVar2;
  ulonglong in_RAX;
  ulonglong uVar3;
  ulong *puVar4;
  char *pcVar5;

  cVar1 = *(char *)((longlong)param_1 + 0x41);
  pcVar5 = (char *)(in_RAX & 0xffffffffffffff00);
  if (cVar1 == 'F')
  {
    if ((*(byte *)param_1 & 8) == 0)
    {
      *(undefined4 *)((longlong)param_1 + 0x2c) = 7;
      uVar3 = FUN_180054f74(param_1);
      return uVar3;
    }
  }
  else
  {
    if (cVar1 == 'N')
    {
      if ((*(byte *)param_1 & 8) == 0)
      {
        *(undefined4 *)((longlong)param_1 + 0x2c) = 8;
      LAB_180053cec:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        uVar3 = FUN_18006738c();
        return uVar3 & 0xffffffffffffff00;
      }
    }
    else
    {
      if (*(int *)((longlong)param_1 + 0x3c) != 0)
        goto LAB_180053cec;
      if (cVar1 == 'I')
      {
        pcVar2 = (char *)param_1[3];
        cVar1 = *pcVar2;
        if (cVar1 == '3')
        {
          if (pcVar2[1] == '2')
          {
            pcVar5 = pcVar2 + 2;
            *(undefined4 *)((longlong)param_1 + 0x3c) = 10;
            param_1[3] = (ulonglong)pcVar5;
          }
        }
        else
        {
          if (cVar1 == '6')
          {
            if (pcVar2[1] == '4')
            {
              pcVar5 = pcVar2 + 2;
              *(undefined4 *)((longlong)param_1 + 0x3c) = 0xb;
              param_1[3] = (ulonglong)pcVar5;
            }
          }
          else
          {
            if (((byte)(cVar1 + 0xa8U) < 0x21) &&
                (pcVar5 = (char *)(longlong)(char)(cVar1 + 0xa8U),
                 (0x120821001U >> ((ulonglong)pcVar5 & 0x3f) & 1) != 0))
            {
              *(undefined4 *)((longlong)param_1 + 0x3c) = 9;
            }
          }
        }
      }
      else
      {
        if (cVar1 == 'L')
        {
          *(undefined4 *)((longlong)param_1 + 0x3c) = 8;
        }
        else
        {
          if (cVar1 == 'T')
          {
            *(undefined4 *)((longlong)param_1 + 0x3c) = 0xd;
          }
          else
          {
            if (cVar1 == 'h')
            {
              pcVar5 = (char *)param_1[3];
              if (*pcVar5 == 'h')
              {
                pcVar5 = pcVar5 + 1;
                *(undefined4 *)((longlong)param_1 + 0x3c) = 1;
                param_1[3] = (ulonglong)pcVar5;
              }
              else
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 2;
              }
            }
            else
            {
              if (cVar1 == 'j')
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 5;
              }
              else
              {
                if (cVar1 == 'l')
                {
                  pcVar5 = (char *)param_1[3];
                  if (*pcVar5 == 'l')
                  {
                    pcVar5 = pcVar5 + 1;
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 4;
                    param_1[3] = (ulonglong)pcVar5;
                  }
                  else
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 3;
                  }
                }
                else
                {
                  if (cVar1 == 't')
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 7;
                  }
                  else
                  {
                    if (cVar1 != 'w')
                    {
                      uVar3 = CONCAT71((int7)((ulonglong)pcVar5 >> 8), 1);
                      if (cVar1 != 'z')
                      {
                        return uVar3;
                      }
                      *(undefined4 *)((longlong)param_1 + 0x3c) = 6;
                      return uVar3;
                    }
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 0xc;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)pcVar5 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::state_case_size(void) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong state_case_size(ulonglong *param_1, undefined8 param_2, ulonglong param_3, uint param_4)
{
  char cVar1;
  char *pcVar2;
  ulonglong in_RAX;
  ulonglong uVar3;
  ulong *puVar4;
  char *pcVar5;

  cVar1 = *(char *)((longlong)param_1 + 0x41);
  pcVar5 = (char *)(in_RAX & 0xffffffffffffff00);
  if (cVar1 == 'F')
  {
    if ((*(byte *)param_1 & 8) == 0)
    {
      *(undefined4 *)((longlong)param_1 + 0x2c) = 7;
      uVar3 = FUN_18005520c(param_1, param_2, param_3, param_4);
      return uVar3;
    }
  }
  else
  {
    if (cVar1 == 'N')
    {
      if ((*(byte *)param_1 & 8) == 0)
      {
        *(undefined4 *)((longlong)param_1 + 0x2c) = 8;
      LAB_180053e68:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        uVar3 = FUN_18006738c();
        return uVar3 & 0xffffffffffffff00;
      }
    }
    else
    {
      if (*(int *)((longlong)param_1 + 0x3c) != 0)
        goto LAB_180053e68;
      if (cVar1 == 'I')
      {
        pcVar2 = (char *)param_1[3];
        cVar1 = *pcVar2;
        if (cVar1 == '3')
        {
          if (pcVar2[1] == '2')
          {
            pcVar5 = pcVar2 + 2;
            *(undefined4 *)((longlong)param_1 + 0x3c) = 10;
            param_1[3] = (ulonglong)pcVar5;
          }
        }
        else
        {
          if (cVar1 == '6')
          {
            if (pcVar2[1] == '4')
            {
              pcVar5 = pcVar2 + 2;
              *(undefined4 *)((longlong)param_1 + 0x3c) = 0xb;
              param_1[3] = (ulonglong)pcVar5;
            }
          }
          else
          {
            if (((byte)(cVar1 + 0xa8U) < 0x21) &&
                (pcVar5 = (char *)(longlong)(char)(cVar1 + 0xa8U),
                 (0x120821001U >> ((ulonglong)pcVar5 & 0x3f) & 1) != 0))
            {
              *(undefined4 *)((longlong)param_1 + 0x3c) = 9;
            }
          }
        }
      }
      else
      {
        if (cVar1 == 'L')
        {
          *(undefined4 *)((longlong)param_1 + 0x3c) = 8;
        }
        else
        {
          if (cVar1 == 'T')
          {
            *(undefined4 *)((longlong)param_1 + 0x3c) = 0xd;
          }
          else
          {
            if (cVar1 == 'h')
            {
              pcVar5 = (char *)param_1[3];
              if (*pcVar5 == 'h')
              {
                pcVar5 = pcVar5 + 1;
                *(undefined4 *)((longlong)param_1 + 0x3c) = 1;
                param_1[3] = (ulonglong)pcVar5;
              }
              else
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 2;
              }
            }
            else
            {
              if (cVar1 == 'j')
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 5;
              }
              else
              {
                if (cVar1 == 'l')
                {
                  pcVar5 = (char *)param_1[3];
                  if (*pcVar5 == 'l')
                  {
                    pcVar5 = pcVar5 + 1;
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 4;
                    param_1[3] = (ulonglong)pcVar5;
                  }
                  else
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 3;
                  }
                }
                else
                {
                  if (cVar1 == 't')
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 7;
                  }
                  else
                  {
                    if (cVar1 != 'w')
                    {
                      uVar3 = CONCAT71((int7)((ulonglong)pcVar5 >> 8), 1);
                      if (cVar1 != 'z')
                      {
                        return uVar3;
                      }
                      *(undefined4 *)((longlong)param_1 + 0x3c) = 6;
                      return uVar3;
                    }
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 0xc;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)pcVar5 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::state_case_size(void) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong state_case_size(ulonglong *param_1)
{
  char cVar1;
  char *pcVar2;
  ulonglong in_RAX;
  ulonglong uVar3;
  ulong *puVar4;
  char *pcVar5;

  cVar1 = *(char *)((longlong)param_1 + 0x41);
  pcVar5 = (char *)(in_RAX & 0xffffffffffffff00);
  if (cVar1 == 'F')
  {
    if ((*(byte *)param_1 & 8) == 0)
    {
      *(undefined4 *)((longlong)param_1 + 0x2c) = 7;
      uVar3 = FUN_1800554b8(param_1);
      return uVar3;
    }
  }
  else
  {
    if (cVar1 == 'N')
    {
      if ((*(byte *)param_1 & 8) == 0)
      {
        *(undefined4 *)((longlong)param_1 + 0x2c) = 8;
      LAB_180053fe4:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        uVar3 = FUN_18006738c();
        return uVar3 & 0xffffffffffffff00;
      }
    }
    else
    {
      if (*(int *)((longlong)param_1 + 0x3c) != 0)
        goto LAB_180053fe4;
      if (cVar1 == 'I')
      {
        pcVar2 = (char *)param_1[3];
        cVar1 = *pcVar2;
        if (cVar1 == '3')
        {
          if (pcVar2[1] == '2')
          {
            pcVar5 = pcVar2 + 2;
            *(undefined4 *)((longlong)param_1 + 0x3c) = 10;
            param_1[3] = (ulonglong)pcVar5;
          }
        }
        else
        {
          if (cVar1 == '6')
          {
            if (pcVar2[1] == '4')
            {
              pcVar5 = pcVar2 + 2;
              *(undefined4 *)((longlong)param_1 + 0x3c) = 0xb;
              param_1[3] = (ulonglong)pcVar5;
            }
          }
          else
          {
            if (((byte)(cVar1 + 0xa8U) < 0x21) &&
                (pcVar5 = (char *)(longlong)(char)(cVar1 + 0xa8U),
                 (0x120821001U >> ((ulonglong)pcVar5 & 0x3f) & 1) != 0))
            {
              *(undefined4 *)((longlong)param_1 + 0x3c) = 9;
            }
          }
        }
      }
      else
      {
        if (cVar1 == 'L')
        {
          *(undefined4 *)((longlong)param_1 + 0x3c) = 8;
        }
        else
        {
          if (cVar1 == 'T')
          {
            *(undefined4 *)((longlong)param_1 + 0x3c) = 0xd;
          }
          else
          {
            if (cVar1 == 'h')
            {
              pcVar5 = (char *)param_1[3];
              if (*pcVar5 == 'h')
              {
                pcVar5 = pcVar5 + 1;
                *(undefined4 *)((longlong)param_1 + 0x3c) = 1;
                param_1[3] = (ulonglong)pcVar5;
              }
              else
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 2;
              }
            }
            else
            {
              if (cVar1 == 'j')
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 5;
              }
              else
              {
                if (cVar1 == 'l')
                {
                  pcVar5 = (char *)param_1[3];
                  if (*pcVar5 == 'l')
                  {
                    pcVar5 = pcVar5 + 1;
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 4;
                    param_1[3] = (ulonglong)pcVar5;
                  }
                  else
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 3;
                  }
                }
                else
                {
                  if (cVar1 == 't')
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 7;
                  }
                  else
                  {
                    if (cVar1 != 'w')
                    {
                      uVar3 = CONCAT71((int7)((ulonglong)pcVar5 >> 8), 1);
                      if (cVar1 != 'z')
                      {
                        return uVar3;
                      }
                      *(undefined4 *)((longlong)param_1 + 0x3c) = 6;
                      return uVar3;
                    }
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 0xc;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)pcVar5 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::state_case_size(void) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong state_case_size(ulonglong *param_1)
{
  char cVar1;
  char *pcVar2;
  ulonglong in_RAX;
  ulonglong uVar3;
  ulong *puVar4;
  char *pcVar5;

  cVar1 = *(char *)((longlong)param_1 + 0x41);
  pcVar5 = (char *)(in_RAX & 0xffffffffffffff00);
  if (cVar1 == 'F')
  {
    if ((*(byte *)param_1 & 8) == 0)
    {
      *(undefined4 *)((longlong)param_1 + 0x2c) = 7;
      uVar3 = FUN_180055750(param_1);
      return uVar3;
    }
  }
  else
  {
    if (cVar1 == 'N')
    {
      if ((*(byte *)param_1 & 8) == 0)
      {
        *(undefined4 *)((longlong)param_1 + 0x2c) = 8;
      LAB_180054160:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        uVar3 = FUN_18006738c();
        return uVar3 & 0xffffffffffffff00;
      }
    }
    else
    {
      if (*(int *)((longlong)param_1 + 0x3c) != 0)
        goto LAB_180054160;
      if (cVar1 == 'I')
      {
        pcVar2 = (char *)param_1[3];
        cVar1 = *pcVar2;
        if (cVar1 == '3')
        {
          if (pcVar2[1] == '2')
          {
            pcVar5 = pcVar2 + 2;
            *(undefined4 *)((longlong)param_1 + 0x3c) = 10;
            param_1[3] = (ulonglong)pcVar5;
          }
        }
        else
        {
          if (cVar1 == '6')
          {
            if (pcVar2[1] == '4')
            {
              pcVar5 = pcVar2 + 2;
              *(undefined4 *)((longlong)param_1 + 0x3c) = 0xb;
              param_1[3] = (ulonglong)pcVar5;
            }
          }
          else
          {
            if (((byte)(cVar1 + 0xa8U) < 0x21) &&
                (pcVar5 = (char *)(longlong)(char)(cVar1 + 0xa8U),
                 (0x120821001U >> ((ulonglong)pcVar5 & 0x3f) & 1) != 0))
            {
              *(undefined4 *)((longlong)param_1 + 0x3c) = 9;
            }
          }
        }
      }
      else
      {
        if (cVar1 == 'L')
        {
          *(undefined4 *)((longlong)param_1 + 0x3c) = 8;
        }
        else
        {
          if (cVar1 == 'T')
          {
            *(undefined4 *)((longlong)param_1 + 0x3c) = 0xd;
          }
          else
          {
            if (cVar1 == 'h')
            {
              pcVar5 = (char *)param_1[3];
              if (*pcVar5 == 'h')
              {
                pcVar5 = pcVar5 + 1;
                *(undefined4 *)((longlong)param_1 + 0x3c) = 1;
                param_1[3] = (ulonglong)pcVar5;
              }
              else
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 2;
              }
            }
            else
            {
              if (cVar1 == 'j')
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 5;
              }
              else
              {
                if (cVar1 == 'l')
                {
                  pcVar5 = (char *)param_1[3];
                  if (*pcVar5 == 'l')
                  {
                    pcVar5 = pcVar5 + 1;
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 4;
                    param_1[3] = (ulonglong)pcVar5;
                  }
                  else
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 3;
                  }
                }
                else
                {
                  if (cVar1 == 't')
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 7;
                  }
                  else
                  {
                    if (cVar1 != 'w')
                    {
                      uVar3 = CONCAT71((int7)((ulonglong)pcVar5 >> 8), 1);
                      if (cVar1 != 'z')
                      {
                        return uVar3;
                      }
                      *(undefined4 *)((longlong)param_1 + 0x3c) = 6;
                      return uVar3;
                    }
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 0xc;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)pcVar5 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::state_case_size(void) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong state_case_size(ulonglong *param_1)
{
  char cVar1;
  char *pcVar2;
  ulonglong in_RAX;
  ulonglong uVar3;
  ulong *puVar4;
  char *pcVar5;

  cVar1 = *(char *)((longlong)param_1 + 0x41);
  pcVar5 = (char *)(in_RAX & 0xffffffffffffff00);
  if (cVar1 == 'F')
  {
    if ((*(byte *)param_1 & 8) == 0)
    {
      *(undefined4 *)((longlong)param_1 + 0x2c) = 7;
      uVar3 = FUN_180055c50(param_1);
      return uVar3;
    }
  }
  else
  {
    if (cVar1 == 'N')
    {
      if ((*(byte *)param_1 & 8) == 0)
      {
        *(undefined4 *)((longlong)param_1 + 0x2c) = 8;
      LAB_180054458:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        uVar3 = FUN_18006738c();
        return uVar3 & 0xffffffffffffff00;
      }
    }
    else
    {
      if (*(int *)((longlong)param_1 + 0x3c) != 0)
        goto LAB_180054458;
      if (cVar1 == 'I')
      {
        pcVar2 = (char *)param_1[3];
        cVar1 = *pcVar2;
        if (cVar1 == '3')
        {
          if (pcVar2[1] == '2')
          {
            pcVar5 = pcVar2 + 2;
            *(undefined4 *)((longlong)param_1 + 0x3c) = 10;
            param_1[3] = (ulonglong)pcVar5;
          }
        }
        else
        {
          if (cVar1 == '6')
          {
            if (pcVar2[1] == '4')
            {
              pcVar5 = pcVar2 + 2;
              *(undefined4 *)((longlong)param_1 + 0x3c) = 0xb;
              param_1[3] = (ulonglong)pcVar5;
            }
          }
          else
          {
            if (((byte)(cVar1 + 0xa8U) < 0x21) &&
                (pcVar5 = (char *)(longlong)(char)(cVar1 + 0xa8U),
                 (0x120821001U >> ((ulonglong)pcVar5 & 0x3f) & 1) != 0))
            {
              *(undefined4 *)((longlong)param_1 + 0x3c) = 9;
            }
          }
        }
      }
      else
      {
        if (cVar1 == 'L')
        {
          *(undefined4 *)((longlong)param_1 + 0x3c) = 8;
        }
        else
        {
          if (cVar1 == 'T')
          {
            *(undefined4 *)((longlong)param_1 + 0x3c) = 0xd;
          }
          else
          {
            if (cVar1 == 'h')
            {
              pcVar5 = (char *)param_1[3];
              if (*pcVar5 == 'h')
              {
                pcVar5 = pcVar5 + 1;
                *(undefined4 *)((longlong)param_1 + 0x3c) = 1;
                param_1[3] = (ulonglong)pcVar5;
              }
              else
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 2;
              }
            }
            else
            {
              if (cVar1 == 'j')
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 5;
              }
              else
              {
                if (cVar1 == 'l')
                {
                  pcVar5 = (char *)param_1[3];
                  if (*pcVar5 == 'l')
                  {
                    pcVar5 = pcVar5 + 1;
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 4;
                    param_1[3] = (ulonglong)pcVar5;
                  }
                  else
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 3;
                  }
                }
                else
                {
                  if (cVar1 == 't')
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 7;
                  }
                  else
                  {
                    if (cVar1 != 'w')
                    {
                      uVar3 = CONCAT71((int7)((ulonglong)pcVar5 >> 8), 1);
                      if (cVar1 != 'z')
                      {
                        return uVar3;
                      }
                      *(undefined4 *)((longlong)param_1 + 0x3c) = 6;
                      return uVar3;
                    }
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 0xc;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)pcVar5 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong state_case_size(__uint64 *param_1)
{
  ushort *puVar1;
  ushort uVar2;
  ushort *in_RAX;
  ulonglong uVar3;
  ulong *puVar4;

  if (*(short *)((longlong)param_1 + 0x42) == 0x46)
  {
    if ((*(byte *)param_1 & 8) == 0)
    {
      *(undefined4 *)((longlong)param_1 + 0x2c) = 7;
      uVar3 = FUN_180055ec4(param_1);
      return uVar3;
    }
  }
  else
  {
    if (*(short *)((longlong)param_1 + 0x42) == 0x4e)
    {
      if ((*(byte *)param_1 & 8) == 0)
      {
        *(undefined4 *)((longlong)param_1 + 0x2c) = 8;
      LAB_1800545d7:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        uVar3 = FUN_18006738c();
        return uVar3 & 0xffffffffffffff00;
      }
    }
    else
    {
      if (*(int *)((longlong)param_1 + 0x3c) != 0)
        goto LAB_1800545d7;
      uVar2 = *(ushort *)((longlong)param_1 + 0x42);
      in_RAX = (ushort *)(ulonglong)uVar2;
      if (uVar2 == 0x49)
      {
        puVar1 = (ushort *)param_1[3];
        uVar2 = *puVar1;
        in_RAX = (ushort *)(ulonglong)uVar2;
        if (uVar2 == 0x33)
        {
          if (puVar1[1] == 0x32)
          {
            in_RAX = puVar1 + 2;
            *(undefined4 *)((longlong)param_1 + 0x3c) = 10;
            param_1[3] = (__uint64)in_RAX;
          }
        }
        else
        {
          if (uVar2 == 0x36)
          {
            if (puVar1[1] == 0x34)
            {
              in_RAX = puVar1 + 2;
              *(undefined4 *)((longlong)param_1 + 0x3c) = 0xb;
              param_1[3] = (__uint64)in_RAX;
            }
          }
          else
          {
            uVar2 = uVar2 - 0x58;
            in_RAX = (ushort *)(ulonglong)uVar2;
            if ((uVar2 < 0x21) &&
                (in_RAX = (ushort *)(ulonglong)uVar2,
                 (0x120821001U >> ((ulonglong)in_RAX & 0x3f) & 1) != 0))
            {
              *(undefined4 *)((longlong)param_1 + 0x3c) = 9;
            }
          }
        }
      }
      else
      {
        if (uVar2 == 0x4c)
        {
          *(undefined4 *)((longlong)param_1 + 0x3c) = 8;
        }
        else
        {
          if (uVar2 == 0x54)
          {
            *(undefined4 *)((longlong)param_1 + 0x3c) = 0xd;
          }
          else
          {
            if (uVar2 == 0x68)
            {
              in_RAX = (ushort *)param_1[3];
              if (*in_RAX == 0x68)
              {
                in_RAX = in_RAX + 1;
                *(undefined4 *)((longlong)param_1 + 0x3c) = 1;
                param_1[3] = (__uint64)in_RAX;
              }
              else
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 2;
              }
            }
            else
            {
              if (uVar2 == 0x6a)
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 5;
              }
              else
              {
                if (uVar2 == 0x6c)
                {
                  in_RAX = (ushort *)param_1[3];
                  if (*in_RAX == 0x6c)
                  {
                    in_RAX = in_RAX + 1;
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 4;
                    param_1[3] = (__uint64)in_RAX;
                  }
                  else
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 3;
                  }
                }
                else
                {
                  if (uVar2 == 0x74)
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 7;
                  }
                  else
                  {
                    if (uVar2 != 0x77)
                    {
                      uVar3 = CONCAT71((uint7)(byte)(uVar2 >> 8), 1);
                      if (uVar2 != 0x7a)
                      {
                        return uVar3;
                      }
                      *(undefined4 *)((longlong)param_1 + 0x3c) = 6;
                      return uVar3;
                    }
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 0xc;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong state_case_size(__uint64 *param_1)
{
  ushort *puVar1;
  ushort uVar2;
  ushort *in_RAX;
  ulonglong uVar3;
  ulong *puVar4;

  if (*(short *)((longlong)param_1 + 0x42) == 0x46)
  {
    if ((*(byte *)param_1 & 8) == 0)
    {
      *(undefined4 *)((longlong)param_1 + 0x2c) = 7;
      uVar3 = FUN_1800561b0(param_1);
      return uVar3;
    }
  }
  else
  {
    if (*(short *)((longlong)param_1 + 0x42) == 0x4e)
    {
      if ((*(byte *)param_1 & 8) == 0)
      {
        *(undefined4 *)((longlong)param_1 + 0x2c) = 8;
      LAB_18005477b:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        uVar3 = FUN_18006738c();
        return uVar3 & 0xffffffffffffff00;
      }
    }
    else
    {
      if (*(int *)((longlong)param_1 + 0x3c) != 0)
        goto LAB_18005477b;
      uVar2 = *(ushort *)((longlong)param_1 + 0x42);
      in_RAX = (ushort *)(ulonglong)uVar2;
      if (uVar2 == 0x49)
      {
        puVar1 = (ushort *)param_1[3];
        uVar2 = *puVar1;
        in_RAX = (ushort *)(ulonglong)uVar2;
        if (uVar2 == 0x33)
        {
          if (puVar1[1] == 0x32)
          {
            in_RAX = puVar1 + 2;
            *(undefined4 *)((longlong)param_1 + 0x3c) = 10;
            param_1[3] = (__uint64)in_RAX;
          }
        }
        else
        {
          if (uVar2 == 0x36)
          {
            if (puVar1[1] == 0x34)
            {
              in_RAX = puVar1 + 2;
              *(undefined4 *)((longlong)param_1 + 0x3c) = 0xb;
              param_1[3] = (__uint64)in_RAX;
            }
          }
          else
          {
            uVar2 = uVar2 - 0x58;
            in_RAX = (ushort *)(ulonglong)uVar2;
            if ((uVar2 < 0x21) &&
                (in_RAX = (ushort *)(ulonglong)uVar2,
                 (0x120821001U >> ((ulonglong)in_RAX & 0x3f) & 1) != 0))
            {
              *(undefined4 *)((longlong)param_1 + 0x3c) = 9;
            }
          }
        }
      }
      else
      {
        if (uVar2 == 0x4c)
        {
          *(undefined4 *)((longlong)param_1 + 0x3c) = 8;
        }
        else
        {
          if (uVar2 == 0x54)
          {
            *(undefined4 *)((longlong)param_1 + 0x3c) = 0xd;
          }
          else
          {
            if (uVar2 == 0x68)
            {
              in_RAX = (ushort *)param_1[3];
              if (*in_RAX == 0x68)
              {
                in_RAX = in_RAX + 1;
                *(undefined4 *)((longlong)param_1 + 0x3c) = 1;
                param_1[3] = (__uint64)in_RAX;
              }
              else
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 2;
              }
            }
            else
            {
              if (uVar2 == 0x6a)
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 5;
              }
              else
              {
                if (uVar2 == 0x6c)
                {
                  in_RAX = (ushort *)param_1[3];
                  if (*in_RAX == 0x6c)
                  {
                    in_RAX = in_RAX + 1;
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 4;
                    param_1[3] = (__uint64)in_RAX;
                  }
                  else
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 3;
                  }
                }
                else
                {
                  if (uVar2 == 0x74)
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 7;
                  }
                  else
                  {
                    if (uVar2 != 0x77)
                    {
                      uVar3 = CONCAT71((uint7)(byte)(uVar2 >> 8), 1);
                      if (uVar2 != 0x7a)
                      {
                        return uVar3;
                      }
                      *(undefined4 *)((longlong)param_1 + 0x3c) = 6;
                      return uVar3;
                    }
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 0xc;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong state_case_size(__uint64 *param_1)
{
  ushort *puVar1;
  ushort uVar2;
  ushort *in_RAX;
  ulonglong uVar3;
  ulong *puVar4;

  if (*(short *)((longlong)param_1 + 0x42) == 0x46)
  {
    if ((*(byte *)param_1 & 8) == 0)
    {
      *(undefined4 *)((longlong)param_1 + 0x2c) = 7;
      uVar3 = FUN_1800564ac(param_1);
      return uVar3;
    }
  }
  else
  {
    if (*(short *)((longlong)param_1 + 0x42) == 0x4e)
    {
      if ((*(byte *)param_1 & 8) == 0)
      {
        *(undefined4 *)((longlong)param_1 + 0x2c) = 8;
      LAB_18005491f:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        uVar3 = FUN_18006738c();
        return uVar3 & 0xffffffffffffff00;
      }
    }
    else
    {
      if (*(int *)((longlong)param_1 + 0x3c) != 0)
        goto LAB_18005491f;
      uVar2 = *(ushort *)((longlong)param_1 + 0x42);
      in_RAX = (ushort *)(ulonglong)uVar2;
      if (uVar2 == 0x49)
      {
        puVar1 = (ushort *)param_1[3];
        uVar2 = *puVar1;
        in_RAX = (ushort *)(ulonglong)uVar2;
        if (uVar2 == 0x33)
        {
          if (puVar1[1] == 0x32)
          {
            in_RAX = puVar1 + 2;
            *(undefined4 *)((longlong)param_1 + 0x3c) = 10;
            param_1[3] = (__uint64)in_RAX;
          }
        }
        else
        {
          if (uVar2 == 0x36)
          {
            if (puVar1[1] == 0x34)
            {
              in_RAX = puVar1 + 2;
              *(undefined4 *)((longlong)param_1 + 0x3c) = 0xb;
              param_1[3] = (__uint64)in_RAX;
            }
          }
          else
          {
            uVar2 = uVar2 - 0x58;
            in_RAX = (ushort *)(ulonglong)uVar2;
            if ((uVar2 < 0x21) &&
                (in_RAX = (ushort *)(ulonglong)uVar2,
                 (0x120821001U >> ((ulonglong)in_RAX & 0x3f) & 1) != 0))
            {
              *(undefined4 *)((longlong)param_1 + 0x3c) = 9;
            }
          }
        }
      }
      else
      {
        if (uVar2 == 0x4c)
        {
          *(undefined4 *)((longlong)param_1 + 0x3c) = 8;
        }
        else
        {
          if (uVar2 == 0x54)
          {
            *(undefined4 *)((longlong)param_1 + 0x3c) = 0xd;
          }
          else
          {
            if (uVar2 == 0x68)
            {
              in_RAX = (ushort *)param_1[3];
              if (*in_RAX == 0x68)
              {
                in_RAX = in_RAX + 1;
                *(undefined4 *)((longlong)param_1 + 0x3c) = 1;
                param_1[3] = (__uint64)in_RAX;
              }
              else
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 2;
              }
            }
            else
            {
              if (uVar2 == 0x6a)
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 5;
              }
              else
              {
                if (uVar2 == 0x6c)
                {
                  in_RAX = (ushort *)param_1[3];
                  if (*in_RAX == 0x6c)
                  {
                    in_RAX = in_RAX + 1;
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 4;
                    param_1[3] = (__uint64)in_RAX;
                  }
                  else
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 3;
                  }
                }
                else
                {
                  if (uVar2 == 0x74)
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 7;
                  }
                  else
                  {
                    if (uVar2 != 0x77)
                    {
                      uVar3 = CONCAT71((uint7)(byte)(uVar2 >> 8), 1);
                      if (uVar2 != 0x7a)
                      {
                        return uVar3;
                      }
                      *(undefined4 *)((longlong)param_1 + 0x3c) = 6;
                      return uVar3;
                    }
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 0xc;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong state_case_size(__uint64 *param_1)
{
  ushort *puVar1;
  ushort uVar2;
  ushort *in_RAX;
  ulonglong uVar3;
  ulong *puVar4;

  if (*(short *)((longlong)param_1 + 0x42) == 0x46)
  {
    if ((*(byte *)param_1 & 8) == 0)
    {
      *(undefined4 *)((longlong)param_1 + 0x2c) = 7;
      uVar3 = FUN_180056798(param_1);
      return uVar3;
    }
  }
  else
  {
    if (*(short *)((longlong)param_1 + 0x42) == 0x4e)
    {
      if ((*(byte *)param_1 & 8) == 0)
      {
        *(undefined4 *)((longlong)param_1 + 0x2c) = 8;
      LAB_180054ac3:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        uVar3 = FUN_18006738c();
        return uVar3 & 0xffffffffffffff00;
      }
    }
    else
    {
      if (*(int *)((longlong)param_1 + 0x3c) != 0)
        goto LAB_180054ac3;
      uVar2 = *(ushort *)((longlong)param_1 + 0x42);
      in_RAX = (ushort *)(ulonglong)uVar2;
      if (uVar2 == 0x49)
      {
        puVar1 = (ushort *)param_1[3];
        uVar2 = *puVar1;
        in_RAX = (ushort *)(ulonglong)uVar2;
        if (uVar2 == 0x33)
        {
          if (puVar1[1] == 0x32)
          {
            in_RAX = puVar1 + 2;
            *(undefined4 *)((longlong)param_1 + 0x3c) = 10;
            param_1[3] = (__uint64)in_RAX;
          }
        }
        else
        {
          if (uVar2 == 0x36)
          {
            if (puVar1[1] == 0x34)
            {
              in_RAX = puVar1 + 2;
              *(undefined4 *)((longlong)param_1 + 0x3c) = 0xb;
              param_1[3] = (__uint64)in_RAX;
            }
          }
          else
          {
            uVar2 = uVar2 - 0x58;
            in_RAX = (ushort *)(ulonglong)uVar2;
            if ((uVar2 < 0x21) &&
                (in_RAX = (ushort *)(ulonglong)uVar2,
                 (0x120821001U >> ((ulonglong)in_RAX & 0x3f) & 1) != 0))
            {
              *(undefined4 *)((longlong)param_1 + 0x3c) = 9;
            }
          }
        }
      }
      else
      {
        if (uVar2 == 0x4c)
        {
          *(undefined4 *)((longlong)param_1 + 0x3c) = 8;
        }
        else
        {
          if (uVar2 == 0x54)
          {
            *(undefined4 *)((longlong)param_1 + 0x3c) = 0xd;
          }
          else
          {
            if (uVar2 == 0x68)
            {
              in_RAX = (ushort *)param_1[3];
              if (*in_RAX == 0x68)
              {
                in_RAX = in_RAX + 1;
                *(undefined4 *)((longlong)param_1 + 0x3c) = 1;
                param_1[3] = (__uint64)in_RAX;
              }
              else
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 2;
              }
            }
            else
            {
              if (uVar2 == 0x6a)
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 5;
              }
              else
              {
                if (uVar2 == 0x6c)
                {
                  in_RAX = (ushort *)param_1[3];
                  if (*in_RAX == 0x6c)
                  {
                    in_RAX = in_RAX + 1;
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 4;
                    param_1[3] = (__uint64)in_RAX;
                  }
                  else
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 3;
                  }
                }
                else
                {
                  if (uVar2 == 0x74)
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 7;
                  }
                  else
                  {
                    if (uVar2 != 0x77)
                    {
                      uVar3 = CONCAT71((uint7)(byte)(uVar2 >> 8), 1);
                      if (uVar2 != 0x7a)
                      {
                        return uVar3;
                      }
                      *(undefined4 *)((longlong)param_1 + 0x3c) = 6;
                      return uVar3;
                    }
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 0xc;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong state_case_size(__uint64 *param_1)
{
  ushort *puVar1;
  ushort uVar2;
  ushort *in_RAX;
  ulonglong uVar3;
  ulong *puVar4;

  if (*(short *)((longlong)param_1 + 0x42) == 0x46)
  {
    if ((*(byte *)param_1 & 8) == 0)
    {
      *(undefined4 *)((longlong)param_1 + 0x2c) = 7;
      uVar3 = FUN_180056a74(param_1);
      return uVar3;
    }
  }
  else
  {
    if (*(short *)((longlong)param_1 + 0x42) == 0x4e)
    {
      if ((*(byte *)param_1 & 8) == 0)
      {
        *(undefined4 *)((longlong)param_1 + 0x2c) = 8;
      LAB_180054c67:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        uVar3 = FUN_18006738c();
        return uVar3 & 0xffffffffffffff00;
      }
    }
    else
    {
      if (*(int *)((longlong)param_1 + 0x3c) != 0)
        goto LAB_180054c67;
      uVar2 = *(ushort *)((longlong)param_1 + 0x42);
      in_RAX = (ushort *)(ulonglong)uVar2;
      if (uVar2 == 0x49)
      {
        puVar1 = (ushort *)param_1[3];
        uVar2 = *puVar1;
        in_RAX = (ushort *)(ulonglong)uVar2;
        if (uVar2 == 0x33)
        {
          if (puVar1[1] == 0x32)
          {
            in_RAX = puVar1 + 2;
            *(undefined4 *)((longlong)param_1 + 0x3c) = 10;
            param_1[3] = (__uint64)in_RAX;
          }
        }
        else
        {
          if (uVar2 == 0x36)
          {
            if (puVar1[1] == 0x34)
            {
              in_RAX = puVar1 + 2;
              *(undefined4 *)((longlong)param_1 + 0x3c) = 0xb;
              param_1[3] = (__uint64)in_RAX;
            }
          }
          else
          {
            uVar2 = uVar2 - 0x58;
            in_RAX = (ushort *)(ulonglong)uVar2;
            if ((uVar2 < 0x21) &&
                (in_RAX = (ushort *)(ulonglong)uVar2,
                 (0x120821001U >> ((ulonglong)in_RAX & 0x3f) & 1) != 0))
            {
              *(undefined4 *)((longlong)param_1 + 0x3c) = 9;
            }
          }
        }
      }
      else
      {
        if (uVar2 == 0x4c)
        {
          *(undefined4 *)((longlong)param_1 + 0x3c) = 8;
        }
        else
        {
          if (uVar2 == 0x54)
          {
            *(undefined4 *)((longlong)param_1 + 0x3c) = 0xd;
          }
          else
          {
            if (uVar2 == 0x68)
            {
              in_RAX = (ushort *)param_1[3];
              if (*in_RAX == 0x68)
              {
                in_RAX = in_RAX + 1;
                *(undefined4 *)((longlong)param_1 + 0x3c) = 1;
                param_1[3] = (__uint64)in_RAX;
              }
              else
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 2;
              }
            }
            else
            {
              if (uVar2 == 0x6a)
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 5;
              }
              else
              {
                if (uVar2 == 0x6c)
                {
                  in_RAX = (ushort *)param_1[3];
                  if (*in_RAX == 0x6c)
                  {
                    in_RAX = in_RAX + 1;
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 4;
                    param_1[3] = (__uint64)in_RAX;
                  }
                  else
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 3;
                  }
                }
                else
                {
                  if (uVar2 == 0x74)
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 7;
                  }
                  else
                  {
                    if (uVar2 != 0x77)
                    {
                      uVar3 = CONCAT71((uint7)(byte)(uVar2 >> 8), 1);
                      if (uVar2 != 0x7a)
                      {
                        return uVar3;
                      }
                      *(undefined4 *)((longlong)param_1 + 0x3c) = 6;
                      return uVar3;
                    }
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 0xc;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_size(void) __ptr64
//   9 names - too many to list
//
// Library: Visual Studio 2015 Release

ulonglong state_case_size(__uint64 *param_1)
{
  ushort *puVar1;
  ushort uVar2;
  ushort *in_RAX;
  ulonglong uVar3;
  ulong *puVar4;

  if (*(short *)((longlong)param_1 + 0x42) == 0x46)
  {
    if ((*(byte *)param_1 & 8) == 0)
    {
      *(undefined4 *)((longlong)param_1 + 0x2c) = 7;
      uVar3 = FUN_180056d60(param_1);
      return uVar3;
    }
  }
  else
  {
    if (*(short *)((longlong)param_1 + 0x42) == 0x4e)
    {
      if ((*(byte *)param_1 & 8) == 0)
      {
        *(undefined4 *)((longlong)param_1 + 0x2c) = 8;
      LAB_180054e0b:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        uVar3 = FUN_18006738c();
        return uVar3 & 0xffffffffffffff00;
      }
    }
    else
    {
      if (*(int *)((longlong)param_1 + 0x3c) != 0)
        goto LAB_180054e0b;
      uVar2 = *(ushort *)((longlong)param_1 + 0x42);
      in_RAX = (ushort *)(ulonglong)uVar2;
      if (uVar2 == 0x49)
      {
        puVar1 = (ushort *)param_1[3];
        uVar2 = *puVar1;
        in_RAX = (ushort *)(ulonglong)uVar2;
        if (uVar2 == 0x33)
        {
          if (puVar1[1] == 0x32)
          {
            in_RAX = puVar1 + 2;
            *(undefined4 *)((longlong)param_1 + 0x3c) = 10;
            param_1[3] = (__uint64)in_RAX;
          }
        }
        else
        {
          if (uVar2 == 0x36)
          {
            if (puVar1[1] == 0x34)
            {
              in_RAX = puVar1 + 2;
              *(undefined4 *)((longlong)param_1 + 0x3c) = 0xb;
              param_1[3] = (__uint64)in_RAX;
            }
          }
          else
          {
            uVar2 = uVar2 - 0x58;
            in_RAX = (ushort *)(ulonglong)uVar2;
            if ((uVar2 < 0x21) &&
                (in_RAX = (ushort *)(ulonglong)uVar2,
                 (0x120821001U >> ((ulonglong)in_RAX & 0x3f) & 1) != 0))
            {
              *(undefined4 *)((longlong)param_1 + 0x3c) = 9;
            }
          }
        }
      }
      else
      {
        if (uVar2 == 0x4c)
        {
          *(undefined4 *)((longlong)param_1 + 0x3c) = 8;
        }
        else
        {
          if (uVar2 == 0x54)
          {
            *(undefined4 *)((longlong)param_1 + 0x3c) = 0xd;
          }
          else
          {
            if (uVar2 == 0x68)
            {
              in_RAX = (ushort *)param_1[3];
              if (*in_RAX == 0x68)
              {
                in_RAX = in_RAX + 1;
                *(undefined4 *)((longlong)param_1 + 0x3c) = 1;
                param_1[3] = (__uint64)in_RAX;
              }
              else
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 2;
              }
            }
            else
            {
              if (uVar2 == 0x6a)
              {
                *(undefined4 *)((longlong)param_1 + 0x3c) = 5;
              }
              else
              {
                if (uVar2 == 0x6c)
                {
                  in_RAX = (ushort *)param_1[3];
                  if (*in_RAX == 0x6c)
                  {
                    in_RAX = in_RAX + 1;
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 4;
                    param_1[3] = (__uint64)in_RAX;
                  }
                  else
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 3;
                  }
                }
                else
                {
                  if (uVar2 == 0x74)
                  {
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 7;
                  }
                  else
                  {
                    if (uVar2 != 0x77)
                    {
                      uVar3 = CONCAT71((uint7)(byte)(uVar2 >> 8), 1);
                      if (uVar2 != 0x7a)
                      {
                        return uVar3;
                      }
                      *(undefined4 *)((longlong)param_1 + 0x3c) = 6;
                      return uVar3;
                    }
                    *(undefined4 *)((longlong)param_1 + 0x3c) = 0xc;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_width(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::state_case_width(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::state_case_width(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong state_case_width(longlong param_1, undefined8 param_2, undefined8 param_3, uint param_4)
{
  uint uVar1;
  ulonglong uVar2;

  if (*(char *)(param_1 + 0x41) != '*')
  {
    uVar2 = FUN_1800502dc(param_1, (undefined4 *)(param_1 + 0x34));
    return uVar2;
  }
  uVar2 = update_field_width(param_1, param_2, param_3, param_4);
  if ((char)uVar2 != '\0')
  {
    if ((*(int *)(param_1 + 0x478) != 1) || (*(int *)(param_1 + 0x47c) == 1))
    {
      uVar1 = *(uint *)(param_1 + 0x34);
      uVar2 = (ulonglong)uVar1;
      if ((int)uVar1 < 0)
      {
        *(uint *)(param_1 + 0x30) = *(uint *)(param_1 + 0x30) | 4;
        uVar2 = (ulonglong)-uVar1;
        *(uint *)(param_1 + 0x34) = -uVar1;
      }
    }
    uVar2 = CONCAT71((int7)(uVar2 >> 8), 1);
  }
  return uVar2;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::state_case_width(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::state_case_width(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::state_case_width(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong state_case_width(longlong param_1, undefined8 param_2, undefined8 param_3, uint param_4)
{
  int iVar1;
  uint uVar2;
  int *piVar3;
  undefined4 uVar4;
  ulong *puVar5;
  int *piVar6;
  ulonglong uVar7;
  int *apiStackX8[2];

  if (*(char *)(param_1 + 0x41) != '*')
  {
    if (*(longlong *)(param_1 + 0x10) == 0)
    {
      puVar5 = __doserrno();
      *(ulong **)(param_1 + 0x10) = puVar5;
    }
    piVar3 = *(int **)(param_1 + 0x10);
    uVar7 = 1;
    iVar1 = *piVar3;
    *piVar3 = 0;
    apiStackX8[0] = (int *)0x0;
    uVar4 = FUN_180069880((byte *)(*(longlong *)(param_1 + 0x18) + -1), (byte **)apiStackX8, 10);
    *(undefined4 *)(param_1 + 0x34) = uVar4;
    if (*(longlong *)(param_1 + 0x10) == 0)
    {
      puVar5 = __doserrno();
      *(ulong **)(param_1 + 0x10) = puVar5;
    }
    piVar6 = *(int **)(param_1 + 0x10);
    if ((**(int **)(param_1 + 0x10) == 0x22) ||
        (piVar6 = apiStackX8[0], apiStackX8[0] < *(int **)(param_1 + 0x18)))
    {
      uVar7 = 0;
    }
    else
    {
      *(int **)(param_1 + 0x18) = apiStackX8[0];
    }
    if ((*piVar3 == 0) && (iVar1 != 0))
    {
      *piVar3 = iVar1;
    }
    return (ulonglong)piVar6 & 0xffffffffffffff00 | uVar7;
  }
  uVar7 = update_field_width(param_1, param_2, param_3, param_4);
  if ((char)uVar7 != '\0')
  {
    if ((*(int *)(param_1 + 0x478) != 1) || (*(int *)(param_1 + 0x47c) == 1))
    {
      uVar2 = *(uint *)(param_1 + 0x34);
      uVar7 = (ulonglong)uVar2;
      if ((int)uVar2 < 0)
      {
        *(uint *)(param_1 + 0x30) = *(uint *)(param_1 + 0x30) | 4;
        uVar7 = (ulonglong)-uVar2;
        *(uint *)(param_1 + 0x34) = -uVar2;
      }
    }
    uVar7 = CONCAT71((int7)(uVar7 >> 8), 1);
  }
  return uVar7;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_width(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_width(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>>::state_case_width(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong state_case_width(__uint64 *param_1)
{
  uint uVar1;
  ulonglong uVar2;

  if (*(short *)((longlong)param_1 + 0x42) != 0x2a)
  {
    uVar2 = FUN_1800506b4((longlong)param_1, (undefined4 *)((longlong)param_1 + 0x34));
    return uVar2;
  }
  uVar2 = update_field_width(param_1);
  if ((char)uVar2 != '\0')
  {
    if ((*(int *)(param_1 + 0x8f) != 1) || (*(int *)((longlong)param_1 + 0x47c) == 1))
    {
      uVar1 = *(uint *)((longlong)param_1 + 0x34);
      uVar2 = (ulonglong)uVar1;
      if ((int)uVar1 < 0)
      {
        *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 4;
        uVar2 = (ulonglong)-uVar1;
        *(uint *)((longlong)param_1 + 0x34) = -uVar1;
      }
    }
    uVar2 = CONCAT71((int7)(uVar2 >> 8), 1);
  }
  return uVar2;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::state_case_width(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::state_case_width(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>>::state_case_width(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong state_case_width(__uint64 *param_1)
{
  uint uVar1;
  ulonglong uVar2;

  if (*(short *)((longlong)param_1 + 0x42) != 0x2a)
  {
    uVar2 = FUN_1800508a0((longlong)param_1, (undefined4 *)((longlong)param_1 + 0x34));
    return uVar2;
  }
  uVar2 = update_field_width(param_1);
  if ((char)uVar2 != '\0')
  {
    if ((*(int *)(param_1 + 0x8f) != 1) || (*(int *)((longlong)param_1 + 0x47c) == 1))
    {
      uVar1 = *(uint *)((longlong)param_1 + 0x34);
      uVar2 = (ulonglong)uVar1;
      if ((int)uVar1 < 0)
      {
        *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 4;
        uVar2 = (ulonglong)-uVar1;
        *(uint *)((longlong)param_1 + 0x34) = -uVar1;
      }
    }
    uVar2 = CONCAT71((int7)(uVar2 >> 8), 1);
  }
  return uVar2;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//   6 names - too many to list
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

undefined8 type_case_Z(__uint64 *param_1)
{
  ushort uVar1;
  ushort *puVar2;
  __uint64 _Var3;
  bool bVar4;
  ulonglong uVar5;

  param_1[4] = param_1[4] + 8;
  uVar5 = param_1[4];
  puVar2 = *(ushort **)(uVar5 - 8);
  if ((puVar2 == (ushort *)0x0) || (_Var3 = *(__uint64 *)(puVar2 + 4), _Var3 == 0))
  {
    *(undefined4 *)(param_1 + 10) = 6;
    param_1[9] = (__uint64) "(null)";
  }
  else
  {
    bVar4 = __crt_stdio_output::is_wide_character_specifier_wchar_t_(*param_1, SUB21(*(undefined2 *)((longlong)param_1 + 0x42), 0),
                                                                     *(length_modifier *)((longlong)param_1 + 0x3c));
    param_1[9] = _Var3;
    uVar1 = *puVar2;
    uVar5 = (ulonglong)uVar1;
    if (bVar4 != false)
    {
      uVar5 = (ulonglong)(uint)(uVar1 >> 1);
      *(uint *)(param_1 + 10) = (uint)(uVar1 >> 1);
      *(undefined *)((longlong)param_1 + 0x54) = 1;
      goto LAB_1800579ee;
    }
    *(uint *)(param_1 + 10) = (uint)uVar1;
  }
  *(undefined *)((longlong)param_1 + 0x54) = 0;
LAB_1800579ee:
  return CONCAT71((int7)(uVar5 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//   6 names - too many to list
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

undefined8 type_case_Z(__uint64 *param_1)
{
  ushort uVar1;
  ushort *puVar2;
  __uint64 _Var3;
  bool bVar4;
  ulonglong uVar5;

  param_1[4] = param_1[4] + 8;
  uVar5 = param_1[4];
  puVar2 = *(ushort **)(uVar5 - 8);
  if ((puVar2 == (ushort *)0x0) || (_Var3 = *(__uint64 *)(puVar2 + 4), _Var3 == 0))
  {
    *(undefined4 *)(param_1 + 10) = 6;
    param_1[9] = (__uint64) "(null)";
  }
  else
  {
    bVar4 = __crt_stdio_output::is_wide_character_specifier_wchar_t_(*param_1, SUB21(*(undefined2 *)((longlong)param_1 + 0x42), 0),
                                                                     *(length_modifier *)((longlong)param_1 + 0x3c));
    param_1[9] = _Var3;
    uVar1 = *puVar2;
    uVar5 = (ulonglong)uVar1;
    if (bVar4 != false)
    {
      uVar5 = (ulonglong)(uint)(uVar1 >> 1);
      *(uint *)(param_1 + 10) = (uint)(uVar1 >> 1);
      *(undefined *)((longlong)param_1 + 0x54) = 1;
      goto LAB_180057bba;
    }
    *(uint *)(param_1 + 10) = (uint)uVar1;
  }
  *(undefined *)((longlong)param_1 + 0x54) = 0;
LAB_180057bba:
  return CONCAT71((int7)(uVar5 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//   6 names - too many to list
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

undefined8 type_case_Z(__uint64 *param_1)
{
  ushort uVar1;
  ushort *puVar2;
  __uint64 _Var3;
  bool bVar4;
  ulonglong uVar5;

  param_1[4] = param_1[4] + 8;
  uVar5 = param_1[4];
  puVar2 = *(ushort **)(uVar5 - 8);
  if ((puVar2 == (ushort *)0x0) || (_Var3 = *(__uint64 *)(puVar2 + 4), _Var3 == 0))
  {
    *(undefined4 *)(param_1 + 10) = 6;
    param_1[9] = (__uint64) "(null)";
  }
  else
  {
    bVar4 = __crt_stdio_output::is_wide_character_specifier_wchar_t_(*param_1, SUB21(*(undefined2 *)((longlong)param_1 + 0x42), 0),
                                                                     *(length_modifier *)((longlong)param_1 + 0x3c));
    param_1[9] = _Var3;
    uVar1 = *puVar2;
    uVar5 = (ulonglong)uVar1;
    if (bVar4 != false)
    {
      uVar5 = (ulonglong)(uint)(uVar1 >> 1);
      *(uint *)(param_1 + 10) = (uint)(uVar1 >> 1);
      *(undefined *)((longlong)param_1 + 0x54) = 1;
      goto LAB_180057c3a;
    }
    *(uint *)(param_1 + 10) = (uint)uVar1;
  }
  *(undefined *)((longlong)param_1 + 0x54) = 0;
LAB_180057c3a:
  return CONCAT71((int7)(uVar5 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_Z(void) __ptr64
//   6 names - too many to list
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

undefined8 type_case_Z(__uint64 *param_1)
{
  ushort uVar1;
  ushort *puVar2;
  __uint64 _Var3;
  bool bVar4;
  ulonglong uVar5;

  param_1[4] = param_1[4] + 8;
  uVar5 = param_1[4];
  puVar2 = *(ushort **)(uVar5 - 8);
  if ((puVar2 == (ushort *)0x0) || (_Var3 = *(__uint64 *)(puVar2 + 4), _Var3 == 0))
  {
    *(undefined4 *)(param_1 + 10) = 6;
    param_1[9] = (__uint64) "(null)";
  }
  else
  {
    bVar4 = __crt_stdio_output::is_wide_character_specifier_wchar_t_(*param_1, SUB21(*(undefined2 *)((longlong)param_1 + 0x42), 0),
                                                                     *(length_modifier *)((longlong)param_1 + 0x3c));
    param_1[9] = _Var3;
    uVar1 = *puVar2;
    uVar5 = (ulonglong)uVar1;
    if (bVar4 != false)
    {
      uVar5 = (ulonglong)(uint)(uVar1 >> 1);
      *(uint *)(param_1 + 10) = (uint)(uVar1 >> 1);
      *(undefined *)((longlong)param_1 + 0x54) = 1;
      goto LAB_180057e06;
    }
    *(uint *)(param_1 + 10) = (uint)uVar1;
  }
  *(undefined *)((longlong)param_1 + 0x54) = 0;
LAB_180057e06:
  return CONCAT71((int7)(uVar5 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//   6 names - too many to list
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

undefined8 type_case_c_tchar(__uint64 *param_1)
{
  __uint64 *p_Var1;
  undefined2 uVar2;
  int iVar3;
  undefined8 uVar4;
  undefined4 extraout_var_00;
  __uint64 *p_Var5;
  byte local_res8;
  undefined local_res9;
  undefined7 extraout_var;

  *(undefined *)((longlong)param_1 + 0x54) = 1;
  param_1[4] = param_1[4] + 8;
  uVar2 = *(undefined2 *)(param_1[4] - 8);
  local_res9 = __crt_stdio_output::is_wide_character_specifier_wchar_t_(*param_1, SUB21(*(undefined2 *)((longlong)param_1 + 0x42), 0),
                                                                        *(length_modifier *)((longlong)param_1 + 0x3c));
  uVar4 = CONCAT71(extraout_var, local_res9);
  p_Var1 = param_1 + 0xb;
  p_Var5 = (__uint64 *)param_1[0x8c];
  if ((bool)local_res9 == false)
  {
    local_res8 = (byte)uVar2;
    if (p_Var5 == (__uint64 *)0x0)
    {
      p_Var5 = p_Var1;
    }
    iVar3 = FUN_180069a64((ushort *)p_Var5, &local_res8,
                          (longlong) * (int *)(*(longlong *)param_1[1] + 8),
                          (undefined4 *)(longlong *)param_1[1]);
    uVar4 = CONCAT44(extraout_var_00, iVar3);
    if (iVar3 < 0)
    {
      *(undefined *)(param_1 + 8) = 1;
    }
  }
  else
  {
    if (p_Var5 == (__uint64 *)0x0)
    {
      p_Var5 = p_Var1;
    }
    *(undefined2 *)p_Var5 = uVar2;
  }
  *(undefined4 *)(param_1 + 10) = 1;
  p_Var5 = (__uint64 *)param_1[0x8c];
  if ((__uint64 *)param_1[0x8c] == (__uint64 *)0x0)
  {
    p_Var5 = p_Var1;
  }
  param_1[9] = (__uint64)p_Var5;
  return CONCAT71((int7)((ulonglong)uVar4 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//
// Library: Visual Studio 2015 Release

__uint64 *type_case_c_tchar(__uint64 *param_1)
{
  __uint64 *p_Var1;
  bool bVar2;
  int iVar3;
  __uint64 *p_Var4;
  ushort local_res8[4];

  *(undefined *)((longlong)param_1 + 0x54) = 1;
  local_res8[0] = 0;
  p_Var4 = (__uint64 *)extract_argument_from_va_list__(param_1, local_res8);
  if ((char)p_Var4 != '\0')
  {
    if ((*(int *)(param_1 + 0x8f) != 1) || (*(int *)((longlong)param_1 + 0x47c) == 1))
    {
      bVar2 = __crt_stdio_output::is_wide_character_specifier_wchar_t_(*param_1, SUB21(*(undefined2 *)((longlong)param_1 + 0x42), 0),
                                                                       *(length_modifier *)((longlong)param_1 + 0x3c));
      p_Var1 = param_1 + 0xb;
      p_Var4 = (__uint64 *)param_1[0x8c];
      if (bVar2 == false)
      {
        local_res8[0] = local_res8[0] & 0xff;
        if (p_Var4 == (__uint64 *)0x0)
        {
          p_Var4 = p_Var1;
        }
        iVar3 = FUN_180069a64((ushort *)p_Var4, (byte *)local_res8,
                              (longlong) * (int *)(*(longlong *)param_1[1] + 8),
                              (undefined4 *)(longlong *)param_1[1]);
        if (iVar3 < 0)
        {
          *(undefined *)(param_1 + 8) = 1;
        }
      }
      else
      {
        if (p_Var4 == (__uint64 *)0x0)
        {
          p_Var4 = p_Var1;
        }
        *(ushort *)p_Var4 = local_res8[0];
      }
      *(undefined4 *)(param_1 + 10) = 1;
      p_Var4 = (__uint64 *)param_1[0x8c];
      if ((__uint64 *)param_1[0x8c] == (__uint64 *)0x0)
      {
        p_Var4 = p_Var1;
      }
      param_1[9] = (__uint64)p_Var4;
    }
    p_Var4 = (__uint64 *)CONCAT71((int7)((ulonglong)p_Var4 >> 8), 1);
  }
  return p_Var4;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//   6 names - too many to list
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

undefined8 type_case_c_tchar(__uint64 *param_1)
{
  __uint64 *p_Var1;
  undefined2 uVar2;
  int iVar3;
  undefined8 uVar4;
  undefined4 extraout_var_00;
  __uint64 *p_Var5;
  byte local_res8;
  undefined local_res9;
  undefined7 extraout_var;

  *(undefined *)((longlong)param_1 + 0x54) = 1;
  param_1[4] = param_1[4] + 8;
  uVar2 = *(undefined2 *)(param_1[4] - 8);
  local_res9 = __crt_stdio_output::is_wide_character_specifier_wchar_t_(*param_1, SUB21(*(undefined2 *)((longlong)param_1 + 0x42), 0),
                                                                        *(length_modifier *)((longlong)param_1 + 0x3c));
  uVar4 = CONCAT71(extraout_var, local_res9);
  p_Var1 = param_1 + 0xb;
  p_Var5 = (__uint64 *)param_1[0x8c];
  if ((bool)local_res9 == false)
  {
    local_res8 = (byte)uVar2;
    if (p_Var5 == (__uint64 *)0x0)
    {
      p_Var5 = p_Var1;
    }
    iVar3 = FUN_180069a64((ushort *)p_Var5, &local_res8,
                          (longlong) * (int *)(*(longlong *)param_1[1] + 8),
                          (undefined4 *)(longlong *)param_1[1]);
    uVar4 = CONCAT44(extraout_var_00, iVar3);
    if (iVar3 < 0)
    {
      *(undefined *)(param_1 + 8) = 1;
    }
  }
  else
  {
    if (p_Var5 == (__uint64 *)0x0)
    {
      p_Var5 = p_Var1;
    }
    *(undefined2 *)p_Var5 = uVar2;
  }
  *(undefined4 *)(param_1 + 10) = 1;
  p_Var5 = (__uint64 *)param_1[0x8c];
  if ((__uint64 *)param_1[0x8c] == (__uint64 *)0x0)
  {
    p_Var5 = p_Var1;
  }
  param_1[9] = (__uint64)p_Var5;
  return CONCAT71((int7)((ulonglong)uVar4 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//   6 names - too many to list
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

undefined8 type_case_c_tchar(__uint64 *param_1)
{
  __uint64 *p_Var1;
  undefined2 uVar2;
  int iVar3;
  undefined8 uVar4;
  undefined4 extraout_var_00;
  __uint64 *p_Var5;
  byte local_res8;
  undefined local_res9;
  undefined7 extraout_var;

  *(undefined *)((longlong)param_1 + 0x54) = 1;
  param_1[4] = param_1[4] + 8;
  uVar2 = *(undefined2 *)(param_1[4] - 8);
  local_res9 = __crt_stdio_output::is_wide_character_specifier_wchar_t_(*param_1, SUB21(*(undefined2 *)((longlong)param_1 + 0x42), 0),
                                                                        *(length_modifier *)((longlong)param_1 + 0x3c));
  uVar4 = CONCAT71(extraout_var, local_res9);
  p_Var1 = param_1 + 0xb;
  p_Var5 = (__uint64 *)param_1[0x8c];
  if ((bool)local_res9 == false)
  {
    local_res8 = (byte)uVar2;
    if (p_Var5 == (__uint64 *)0x0)
    {
      p_Var5 = p_Var1;
    }
    iVar3 = FUN_180069a64((ushort *)p_Var5, &local_res8,
                          (longlong) * (int *)(*(longlong *)param_1[1] + 8),
                          (undefined4 *)(longlong *)param_1[1]);
    uVar4 = CONCAT44(extraout_var_00, iVar3);
    if (iVar3 < 0)
    {
      *(undefined *)(param_1 + 8) = 1;
    }
  }
  else
  {
    if (p_Var5 == (__uint64 *)0x0)
    {
      p_Var5 = p_Var1;
    }
    *(undefined2 *)p_Var5 = uVar2;
  }
  *(undefined4 *)(param_1 + 10) = 1;
  p_Var5 = (__uint64 *)param_1[0x8c];
  if ((__uint64 *)param_1[0x8c] == (__uint64 *)0x0)
  {
    p_Var5 = p_Var1;
  }
  param_1[9] = (__uint64)p_Var5;
  return CONCAT71((int7)((ulonglong)uVar4 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//
// Library: Visual Studio 2015 Release

__uint64 *type_case_c_tchar(__uint64 *param_1)
{
  __uint64 *p_Var1;
  bool bVar2;
  int iVar3;
  __uint64 *p_Var4;
  ushort local_res8[4];

  *(undefined *)((longlong)param_1 + 0x54) = 1;
  local_res8[0] = 0;
  p_Var4 = (__uint64 *)extract_argument_from_va_list__(param_1, local_res8);
  if ((char)p_Var4 != '\0')
  {
    if ((*(int *)(param_1 + 0x8f) != 1) || (*(int *)((longlong)param_1 + 0x47c) == 1))
    {
      bVar2 = __crt_stdio_output::is_wide_character_specifier_wchar_t_(*param_1, SUB21(*(undefined2 *)((longlong)param_1 + 0x42), 0),
                                                                       *(length_modifier *)((longlong)param_1 + 0x3c));
      p_Var1 = param_1 + 0xb;
      p_Var4 = (__uint64 *)param_1[0x8c];
      if (bVar2 == false)
      {
        local_res8[0] = local_res8[0] & 0xff;
        if (p_Var4 == (__uint64 *)0x0)
        {
          p_Var4 = p_Var1;
        }
        iVar3 = FUN_180069a64((ushort *)p_Var4, (byte *)local_res8,
                              (longlong) * (int *)(*(longlong *)param_1[1] + 8),
                              (undefined4 *)(longlong *)param_1[1]);
        if (iVar3 < 0)
        {
          *(undefined *)(param_1 + 8) = 1;
        }
      }
      else
      {
        if (p_Var4 == (__uint64 *)0x0)
        {
          p_Var4 = p_Var1;
        }
        *(ushort *)p_Var4 = local_res8[0];
      }
      *(undefined4 *)(param_1 + 10) = 1;
      p_Var4 = (__uint64 *)param_1[0x8c];
      if ((__uint64 *)param_1[0x8c] == (__uint64 *)0x0)
      {
        p_Var4 = p_Var1;
      }
      param_1[9] = (__uint64)p_Var4;
    }
    p_Var4 = (__uint64 *)CONCAT71((int7)((ulonglong)p_Var4 >> 8), 1);
  }
  return p_Var4;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_c_tchar(wchar_t) __ptr64
//   6 names - too many to list
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

undefined8 type_case_c_tchar(__uint64 *param_1)
{
  __uint64 *p_Var1;
  undefined2 uVar2;
  int iVar3;
  undefined8 uVar4;
  undefined4 extraout_var_00;
  __uint64 *p_Var5;
  byte local_res8;
  undefined local_res9;
  undefined7 extraout_var;

  *(undefined *)((longlong)param_1 + 0x54) = 1;
  param_1[4] = param_1[4] + 8;
  uVar2 = *(undefined2 *)(param_1[4] - 8);
  local_res9 = __crt_stdio_output::is_wide_character_specifier_wchar_t_(*param_1, SUB21(*(undefined2 *)((longlong)param_1 + 0x42), 0),
                                                                        *(length_modifier *)((longlong)param_1 + 0x3c));
  uVar4 = CONCAT71(extraout_var, local_res9);
  p_Var1 = param_1 + 0xb;
  p_Var5 = (__uint64 *)param_1[0x8c];
  if ((bool)local_res9 == false)
  {
    local_res8 = (byte)uVar2;
    if (p_Var5 == (__uint64 *)0x0)
    {
      p_Var5 = p_Var1;
    }
    iVar3 = FUN_180069a64((ushort *)p_Var5, &local_res8,
                          (longlong) * (int *)(*(longlong *)param_1[1] + 8),
                          (undefined4 *)(longlong *)param_1[1]);
    uVar4 = CONCAT44(extraout_var_00, iVar3);
    if (iVar3 < 0)
    {
      *(undefined *)(param_1 + 8) = 1;
    }
  }
  else
  {
    if (p_Var5 == (__uint64 *)0x0)
    {
      p_Var5 = p_Var1;
    }
    *(undefined2 *)p_Var5 = uVar2;
  }
  *(undefined4 *)(param_1 + 10) = 1;
  p_Var5 = (__uint64 *)param_1[0x8c];
  if ((__uint64 *)param_1[0x8c] == (__uint64 *)0x0)
  {
    p_Var5 = p_Var1;
  }
  param_1[9] = (__uint64)p_Var5;
  return CONCAT71((int7)((ulonglong)uVar4 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//   12 names - too many to list
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong type_case_n(longlong param_1)
{
  ulonglong *puVar1;
  int iVar2;
  undefined4 extraout_var;
  ulong *puVar3;
  ulonglong uVar4;
  longlong lVar5;

  lVar5 = 8;
  *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
  puVar1 = *(ulonglong **)(*(longlong *)(param_1 + 0x20) + -8);
  iVar2 = _get_printf_count_output();
  uVar4 = CONCAT44(extraout_var, iVar2);
  if (iVar2 == 0)
  {
  LAB_18005ba24:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  else
  {
    iVar2 = *(int *)(param_1 + 0x3c);
    if (iVar2 < 6)
    {
      if (iVar2 != 5)
      {
        if (iVar2 == 0)
          goto LAB_18005ba85;
        if (iVar2 == 1)
        {
          lVar5 = 1;
        }
        else
        {
          iVar2 = iVar2 + -2;
          if (iVar2 != 0)
            goto LAB_18005ba58;
          lVar5 = 2;
        }
      }
    }
    else
    {
      if (((iVar2 != 6) && (iVar2 != 7)) && (iVar2 = iVar2 + -9, iVar2 != 0))
      {
      LAB_18005ba58:
        if (iVar2 == 1)
        {
        LAB_18005ba85:
          lVar5 = 4;
        }
        else
        {
          if (iVar2 != 2)
          {
            lVar5 = 0;
          }
        }
      }
    }
    if (lVar5 == 1)
    {
      *(undefined *)puVar1 = *(undefined *)(param_1 + 0x28);
    }
    else
    {
      if (lVar5 == 2)
      {
        uVar4 = (ulonglong) * (ushort *)(param_1 + 0x28);
        *(ushort *)puVar1 = *(ushort *)(param_1 + 0x28);
      }
      else
      {
        if (lVar5 == 4)
        {
          uVar4 = (ulonglong) * (uint *)(param_1 + 0x28);
          *(uint *)puVar1 = *(uint *)(param_1 + 0x28);
        }
        else
        {
          if (lVar5 != 8)
            goto LAB_18005ba24;
          uVar4 = SEXT48(*(int *)(param_1 + 0x28));
          *puVar1 = uVar4;
        }
      }
    }
    *(undefined *)(param_1 + 0x40) = 1;
    uVar4 = CONCAT71((int7)(uVar4 >> 8), 1);
  }
  return uVar4;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::type_case_n(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong type_case_n(longlong param_1, undefined8 param_2, undefined8 param_3, uint param_4)
{
  int iVar1;
  longlong *plVar2;
  ulonglong uVar3;
  ulong *puVar4;
  longlong lVar5;
  longlong *local_res10[3];

  lVar5 = 0;
  local_res10[0] = (longlong *)0x0;
  plVar2 = (longlong *)extract_argument_from_va_list__(param_1, local_res10, param_3, param_4);
  if ((char)plVar2 == '\0')
  {
  LAB_18005baf6:
    uVar3 = (ulonglong)plVar2 & 0xffffffffffffff00;
  }
  else
  {
    if ((*(int *)(param_1 + 0x478) != 1) || (*(int *)(param_1 + 0x47c) == 1))
    {
      iVar1 = _get_printf_count_output();
      if (iVar1 == 0)
      {
      LAB_18005bb1c:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        plVar2 = (longlong *)FUN_18006738c();
        goto LAB_18005baf6;
      }
      iVar1 = *(int *)(param_1 + 0x3c);
      if (iVar1 < 6)
      {
        if (iVar1 == 5)
          goto LAB_18005bb79;
        if (iVar1 == 0)
          goto LAB_18005bb57;
        if (iVar1 == 1)
        {
          lVar5 = 1;
        }
        else
        {
          iVar1 = iVar1 + -2;
          if (iVar1 != 0)
            goto LAB_18005bb4b;
          lVar5 = 2;
        }
      }
      else
      {
        if (((iVar1 != 6) && (iVar1 != 7)) && (iVar1 = iVar1 + -9, iVar1 != 0))
        {
        LAB_18005bb4b:
          if (iVar1 == 1)
          {
          LAB_18005bb57:
            lVar5 = 4;
            goto LAB_18005bb7e;
          }
          if (iVar1 != 2)
            goto LAB_18005bb7e;
        }
      LAB_18005bb79:
        lVar5 = 8;
      }
    LAB_18005bb7e:
      if (lVar5 == 1)
      {
        *(undefined *)local_res10[0] = *(undefined *)(param_1 + 0x28);
      }
      else
      {
        if (lVar5 == 2)
        {
          *(undefined2 *)local_res10[0] = *(undefined2 *)(param_1 + 0x28);
        }
        else
        {
          if (lVar5 == 4)
          {
            *(undefined4 *)local_res10[0] = *(undefined4 *)(param_1 + 0x28);
          }
          else
          {
            if (lVar5 != 8)
              goto LAB_18005bb1c;
            *local_res10[0] = (longlong) * (int *)(param_1 + 0x28);
          }
        }
      }
      *(undefined *)(param_1 + 0x40) = 1;
      plVar2 = local_res10[0];
    }
    uVar3 = CONCAT71((int7)((ulonglong)plVar2 >> 8), 1);
  }
  return uVar3;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//   12 names - too many to list
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong type_case_n(longlong param_1)
{
  ulonglong *puVar1;
  int iVar2;
  undefined4 extraout_var;
  ulong *puVar3;
  ulonglong uVar4;
  longlong lVar5;

  lVar5 = 8;
  *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
  puVar1 = *(ulonglong **)(*(longlong *)(param_1 + 0x20) + -8);
  iVar2 = _get_printf_count_output();
  uVar4 = CONCAT44(extraout_var, iVar2);
  if (iVar2 == 0)
  {
  LAB_18005bc04:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  else
  {
    iVar2 = *(int *)(param_1 + 0x3c);
    if (iVar2 < 6)
    {
      if (iVar2 != 5)
      {
        if (iVar2 == 0)
          goto LAB_18005bc65;
        if (iVar2 == 1)
        {
          lVar5 = 1;
        }
        else
        {
          iVar2 = iVar2 + -2;
          if (iVar2 != 0)
            goto LAB_18005bc38;
          lVar5 = 2;
        }
      }
    }
    else
    {
      if (((iVar2 != 6) && (iVar2 != 7)) && (iVar2 = iVar2 + -9, iVar2 != 0))
      {
      LAB_18005bc38:
        if (iVar2 == 1)
        {
        LAB_18005bc65:
          lVar5 = 4;
        }
        else
        {
          if (iVar2 != 2)
          {
            lVar5 = 0;
          }
        }
      }
    }
    if (lVar5 == 1)
    {
      *(undefined *)puVar1 = *(undefined *)(param_1 + 0x28);
    }
    else
    {
      if (lVar5 == 2)
      {
        uVar4 = (ulonglong) * (ushort *)(param_1 + 0x28);
        *(ushort *)puVar1 = *(ushort *)(param_1 + 0x28);
      }
      else
      {
        if (lVar5 == 4)
        {
          uVar4 = (ulonglong) * (uint *)(param_1 + 0x28);
          *(uint *)puVar1 = *(uint *)(param_1 + 0x28);
        }
        else
        {
          if (lVar5 != 8)
            goto LAB_18005bc04;
          uVar4 = SEXT48(*(int *)(param_1 + 0x28));
          *puVar1 = uVar4;
        }
      }
    }
    *(undefined *)(param_1 + 0x40) = 1;
    uVar4 = CONCAT71((int7)(uVar4 >> 8), 1);
  }
  return uVar4;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//   12 names - too many to list
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong type_case_n(longlong param_1)
{
  ulonglong *puVar1;
  int iVar2;
  undefined4 extraout_var;
  ulong *puVar3;
  ulonglong uVar4;
  longlong lVar5;

  lVar5 = 8;
  *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
  puVar1 = *(ulonglong **)(*(longlong *)(param_1 + 0x20) + -8);
  iVar2 = _get_printf_count_output();
  uVar4 = CONCAT44(extraout_var, iVar2);
  if (iVar2 == 0)
  {
  LAB_18005bce0:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  else
  {
    iVar2 = *(int *)(param_1 + 0x3c);
    if (iVar2 < 6)
    {
      if (iVar2 != 5)
      {
        if (iVar2 == 0)
          goto LAB_18005bd41;
        if (iVar2 == 1)
        {
          lVar5 = 1;
        }
        else
        {
          iVar2 = iVar2 + -2;
          if (iVar2 != 0)
            goto LAB_18005bd14;
          lVar5 = 2;
        }
      }
    }
    else
    {
      if (((iVar2 != 6) && (iVar2 != 7)) && (iVar2 = iVar2 + -9, iVar2 != 0))
      {
      LAB_18005bd14:
        if (iVar2 == 1)
        {
        LAB_18005bd41:
          lVar5 = 4;
        }
        else
        {
          if (iVar2 != 2)
          {
            lVar5 = 0;
          }
        }
      }
    }
    if (lVar5 == 1)
    {
      *(undefined *)puVar1 = *(undefined *)(param_1 + 0x28);
    }
    else
    {
      if (lVar5 == 2)
      {
        uVar4 = (ulonglong) * (ushort *)(param_1 + 0x28);
        *(ushort *)puVar1 = *(ushort *)(param_1 + 0x28);
      }
      else
      {
        if (lVar5 == 4)
        {
          uVar4 = (ulonglong) * (uint *)(param_1 + 0x28);
          *(uint *)puVar1 = *(uint *)(param_1 + 0x28);
        }
        else
        {
          if (lVar5 != 8)
            goto LAB_18005bce0;
          uVar4 = SEXT48(*(int *)(param_1 + 0x28));
          *puVar1 = uVar4;
        }
      }
    }
    *(undefined *)(param_1 + 0x40) = 1;
    uVar4 = CONCAT71((int7)(uVar4 >> 8), 1);
  }
  return uVar4;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//   12 names - too many to list
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong type_case_n(longlong param_1)
{
  ulonglong *puVar1;
  int iVar2;
  undefined4 extraout_var;
  ulong *puVar3;
  ulonglong uVar4;
  longlong lVar5;

  lVar5 = 8;
  *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
  puVar1 = *(ulonglong **)(*(longlong *)(param_1 + 0x20) + -8);
  iVar2 = _get_printf_count_output();
  uVar4 = CONCAT44(extraout_var, iVar2);
  if (iVar2 == 0)
  {
  LAB_18005bec0:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  else
  {
    iVar2 = *(int *)(param_1 + 0x3c);
    if (iVar2 < 6)
    {
      if (iVar2 != 5)
      {
        if (iVar2 == 0)
          goto LAB_18005bf21;
        if (iVar2 == 1)
        {
          lVar5 = 1;
        }
        else
        {
          iVar2 = iVar2 + -2;
          if (iVar2 != 0)
            goto LAB_18005bef4;
          lVar5 = 2;
        }
      }
    }
    else
    {
      if (((iVar2 != 6) && (iVar2 != 7)) && (iVar2 = iVar2 + -9, iVar2 != 0))
      {
      LAB_18005bef4:
        if (iVar2 == 1)
        {
        LAB_18005bf21:
          lVar5 = 4;
        }
        else
        {
          if (iVar2 != 2)
          {
            lVar5 = 0;
          }
        }
      }
    }
    if (lVar5 == 1)
    {
      *(undefined *)puVar1 = *(undefined *)(param_1 + 0x28);
    }
    else
    {
      if (lVar5 == 2)
      {
        uVar4 = (ulonglong) * (ushort *)(param_1 + 0x28);
        *(ushort *)puVar1 = *(ushort *)(param_1 + 0x28);
      }
      else
      {
        if (lVar5 == 4)
        {
          uVar4 = (ulonglong) * (uint *)(param_1 + 0x28);
          *(uint *)puVar1 = *(uint *)(param_1 + 0x28);
        }
        else
        {
          if (lVar5 != 8)
            goto LAB_18005bec0;
          uVar4 = SEXT48(*(int *)(param_1 + 0x28));
          *puVar1 = uVar4;
        }
      }
    }
    *(undefined *)(param_1 + 0x40) = 1;
    uVar4 = CONCAT71((int7)(uVar4 >> 8), 1);
  }
  return uVar4;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//   12 names - too many to list
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong type_case_n(longlong param_1)
{
  ulonglong *puVar1;
  int iVar2;
  undefined4 extraout_var;
  ulong *puVar3;
  ulonglong uVar4;
  longlong lVar5;

  lVar5 = 8;
  *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
  puVar1 = *(ulonglong **)(*(longlong *)(param_1 + 0x20) + -8);
  iVar2 = _get_printf_count_output();
  uVar4 = CONCAT44(extraout_var, iVar2);
  if (iVar2 == 0)
  {
  LAB_18005bf9c:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  else
  {
    iVar2 = *(int *)(param_1 + 0x3c);
    if (iVar2 < 6)
    {
      if (iVar2 != 5)
      {
        if (iVar2 == 0)
          goto LAB_18005bffd;
        if (iVar2 == 1)
        {
          lVar5 = 1;
        }
        else
        {
          iVar2 = iVar2 + -2;
          if (iVar2 != 0)
            goto LAB_18005bfd0;
          lVar5 = 2;
        }
      }
    }
    else
    {
      if (((iVar2 != 6) && (iVar2 != 7)) && (iVar2 = iVar2 + -9, iVar2 != 0))
      {
      LAB_18005bfd0:
        if (iVar2 == 1)
        {
        LAB_18005bffd:
          lVar5 = 4;
        }
        else
        {
          if (iVar2 != 2)
          {
            lVar5 = 0;
          }
        }
      }
    }
    if (lVar5 == 1)
    {
      *(undefined *)puVar1 = *(undefined *)(param_1 + 0x28);
    }
    else
    {
      if (lVar5 == 2)
      {
        uVar4 = (ulonglong) * (ushort *)(param_1 + 0x28);
        *(ushort *)puVar1 = *(ushort *)(param_1 + 0x28);
      }
      else
      {
        if (lVar5 == 4)
        {
          uVar4 = (ulonglong) * (uint *)(param_1 + 0x28);
          *(uint *)puVar1 = *(uint *)(param_1 + 0x28);
        }
        else
        {
          if (lVar5 != 8)
            goto LAB_18005bf9c;
          uVar4 = SEXT48(*(int *)(param_1 + 0x28));
          *puVar1 = uVar4;
        }
      }
    }
    *(undefined *)(param_1 + 0x40) = 1;
    uVar4 = CONCAT71((int7)(uVar4 >> 8), 1);
  }
  return uVar4;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>>::type_case_n(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong type_case_n(__uint64 *param_1)
{
  int iVar1;
  longlong *plVar2;
  ulonglong uVar3;
  ulong *puVar4;
  longlong lVar5;
  longlong *local_res10[3];

  lVar5 = 0;
  local_res10[0] = (longlong *)0x0;
  plVar2 = (longlong *)extract_argument_from_va_list__(param_1, local_res10);
  if ((char)plVar2 == '\0')
  {
  LAB_18005c06e:
    uVar3 = (ulonglong)plVar2 & 0xffffffffffffff00;
  }
  else
  {
    if ((*(int *)(param_1 + 0x8f) != 1) || (*(int *)((longlong)param_1 + 0x47c) == 1))
    {
      iVar1 = _get_printf_count_output();
      if (iVar1 == 0)
      {
      LAB_18005c094:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        plVar2 = (longlong *)FUN_18006738c();
        goto LAB_18005c06e;
      }
      iVar1 = *(int *)((longlong)param_1 + 0x3c);
      if (iVar1 < 6)
      {
        if (iVar1 == 5)
          goto LAB_18005c0f1;
        if (iVar1 == 0)
          goto LAB_18005c0cf;
        if (iVar1 == 1)
        {
          lVar5 = 1;
        }
        else
        {
          iVar1 = iVar1 + -2;
          if (iVar1 != 0)
            goto LAB_18005c0c3;
          lVar5 = 2;
        }
      }
      else
      {
        if (((iVar1 != 6) && (iVar1 != 7)) && (iVar1 = iVar1 + -9, iVar1 != 0))
        {
        LAB_18005c0c3:
          if (iVar1 == 1)
          {
          LAB_18005c0cf:
            lVar5 = 4;
            goto LAB_18005c0f6;
          }
          if (iVar1 != 2)
            goto LAB_18005c0f6;
        }
      LAB_18005c0f1:
        lVar5 = 8;
      }
    LAB_18005c0f6:
      if (lVar5 == 1)
      {
        *(undefined *)local_res10[0] = *(undefined *)(param_1 + 5);
      }
      else
      {
        if (lVar5 == 2)
        {
          *(undefined2 *)local_res10[0] = *(undefined2 *)(param_1 + 5);
        }
        else
        {
          if (lVar5 == 4)
          {
            *(undefined4 *)local_res10[0] = *(undefined4 *)(param_1 + 5);
          }
          else
          {
            if (lVar5 != 8)
              goto LAB_18005c094;
            *local_res10[0] = (longlong) * (int *)(param_1 + 5);
          }
        }
      }
      *(undefined *)(param_1 + 8) = 1;
      plVar2 = local_res10[0];
    }
    uVar3 = CONCAT71((int7)((ulonglong)plVar2 >> 8), 1);
  }
  return uVar3;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//   12 names - too many to list
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong type_case_n(longlong param_1)
{
  ulonglong *puVar1;
  int iVar2;
  undefined4 extraout_var;
  ulong *puVar3;
  ulonglong uVar4;
  longlong lVar5;

  lVar5 = 8;
  *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
  puVar1 = *(ulonglong **)(*(longlong *)(param_1 + 0x20) + -8);
  iVar2 = _get_printf_count_output();
  uVar4 = CONCAT44(extraout_var, iVar2);
  if (iVar2 == 0)
  {
  LAB_18005c17c:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  else
  {
    iVar2 = *(int *)(param_1 + 0x3c);
    if (iVar2 < 6)
    {
      if (iVar2 != 5)
      {
        if (iVar2 == 0)
          goto LAB_18005c1dd;
        if (iVar2 == 1)
        {
          lVar5 = 1;
        }
        else
        {
          iVar2 = iVar2 + -2;
          if (iVar2 != 0)
            goto LAB_18005c1b0;
          lVar5 = 2;
        }
      }
    }
    else
    {
      if (((iVar2 != 6) && (iVar2 != 7)) && (iVar2 = iVar2 + -9, iVar2 != 0))
      {
      LAB_18005c1b0:
        if (iVar2 == 1)
        {
        LAB_18005c1dd:
          lVar5 = 4;
        }
        else
        {
          if (iVar2 != 2)
          {
            lVar5 = 0;
          }
        }
      }
    }
    if (lVar5 == 1)
    {
      *(undefined *)puVar1 = *(undefined *)(param_1 + 0x28);
    }
    else
    {
      if (lVar5 == 2)
      {
        uVar4 = (ulonglong) * (ushort *)(param_1 + 0x28);
        *(ushort *)puVar1 = *(ushort *)(param_1 + 0x28);
      }
      else
      {
        if (lVar5 == 4)
        {
          uVar4 = (ulonglong) * (uint *)(param_1 + 0x28);
          *(uint *)puVar1 = *(uint *)(param_1 + 0x28);
        }
        else
        {
          if (lVar5 != 8)
            goto LAB_18005c17c;
          uVar4 = SEXT48(*(int *)(param_1 + 0x28));
          *puVar1 = uVar4;
        }
      }
    }
    *(undefined *)(param_1 + 0x40) = 1;
    uVar4 = CONCAT71((int7)(uVar4 >> 8), 1);
  }
  return uVar4;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//   12 names - too many to list
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong type_case_n(longlong param_1)
{
  ulonglong *puVar1;
  int iVar2;
  undefined4 extraout_var;
  ulong *puVar3;
  ulonglong uVar4;
  longlong lVar5;

  lVar5 = 8;
  *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
  puVar1 = *(ulonglong **)(*(longlong *)(param_1 + 0x20) + -8);
  iVar2 = _get_printf_count_output();
  uVar4 = CONCAT44(extraout_var, iVar2);
  if (iVar2 == 0)
  {
  LAB_18005c258:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  else
  {
    iVar2 = *(int *)(param_1 + 0x3c);
    if (iVar2 < 6)
    {
      if (iVar2 != 5)
      {
        if (iVar2 == 0)
          goto LAB_18005c2b9;
        if (iVar2 == 1)
        {
          lVar5 = 1;
        }
        else
        {
          iVar2 = iVar2 + -2;
          if (iVar2 != 0)
            goto LAB_18005c28c;
          lVar5 = 2;
        }
      }
    }
    else
    {
      if (((iVar2 != 6) && (iVar2 != 7)) && (iVar2 = iVar2 + -9, iVar2 != 0))
      {
      LAB_18005c28c:
        if (iVar2 == 1)
        {
        LAB_18005c2b9:
          lVar5 = 4;
        }
        else
        {
          if (iVar2 != 2)
          {
            lVar5 = 0;
          }
        }
      }
    }
    if (lVar5 == 1)
    {
      *(undefined *)puVar1 = *(undefined *)(param_1 + 0x28);
    }
    else
    {
      if (lVar5 == 2)
      {
        uVar4 = (ulonglong) * (ushort *)(param_1 + 0x28);
        *(ushort *)puVar1 = *(ushort *)(param_1 + 0x28);
      }
      else
      {
        if (lVar5 == 4)
        {
          uVar4 = (ulonglong) * (uint *)(param_1 + 0x28);
          *(uint *)puVar1 = *(uint *)(param_1 + 0x28);
        }
        else
        {
          if (lVar5 != 8)
            goto LAB_18005c258;
          uVar4 = SEXT48(*(int *)(param_1 + 0x28));
          *puVar1 = uVar4;
        }
      }
    }
    *(undefined *)(param_1 + 0x40) = 1;
    uVar4 = CONCAT71((int7)(uVar4 >> 8), 1);
  }
  return uVar4;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>>::type_case_n(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong type_case_n(__uint64 *param_1)
{
  int iVar1;
  longlong *plVar2;
  ulonglong uVar3;
  ulong *puVar4;
  longlong lVar5;
  longlong *local_res10[3];

  lVar5 = 0;
  local_res10[0] = (longlong *)0x0;
  plVar2 = (longlong *)extract_argument_from_va_list__(param_1, local_res10);
  if ((char)plVar2 == '\0')
  {
  LAB_18005c32a:
    uVar3 = (ulonglong)plVar2 & 0xffffffffffffff00;
  }
  else
  {
    if ((*(int *)(param_1 + 0x8f) != 1) || (*(int *)((longlong)param_1 + 0x47c) == 1))
    {
      iVar1 = _get_printf_count_output();
      if (iVar1 == 0)
      {
      LAB_18005c350:
        puVar4 = __doserrno();
        *puVar4 = 0x16;
        plVar2 = (longlong *)FUN_18006738c();
        goto LAB_18005c32a;
      }
      iVar1 = *(int *)((longlong)param_1 + 0x3c);
      if (iVar1 < 6)
      {
        if (iVar1 == 5)
          goto LAB_18005c3ad;
        if (iVar1 == 0)
          goto LAB_18005c38b;
        if (iVar1 == 1)
        {
          lVar5 = 1;
        }
        else
        {
          iVar1 = iVar1 + -2;
          if (iVar1 != 0)
            goto LAB_18005c37f;
          lVar5 = 2;
        }
      }
      else
      {
        if (((iVar1 != 6) && (iVar1 != 7)) && (iVar1 = iVar1 + -9, iVar1 != 0))
        {
        LAB_18005c37f:
          if (iVar1 == 1)
          {
          LAB_18005c38b:
            lVar5 = 4;
            goto LAB_18005c3b2;
          }
          if (iVar1 != 2)
            goto LAB_18005c3b2;
        }
      LAB_18005c3ad:
        lVar5 = 8;
      }
    LAB_18005c3b2:
      if (lVar5 == 1)
      {
        *(undefined *)local_res10[0] = *(undefined *)(param_1 + 5);
      }
      else
      {
        if (lVar5 == 2)
        {
          *(undefined2 *)local_res10[0] = *(undefined2 *)(param_1 + 5);
        }
        else
        {
          if (lVar5 == 4)
          {
            *(undefined4 *)local_res10[0] = *(undefined4 *)(param_1 + 5);
          }
          else
          {
            if (lVar5 != 8)
              goto LAB_18005c350;
            *local_res10[0] = (longlong) * (int *)(param_1 + 5);
          }
        }
      }
      *(undefined *)(param_1 + 8) = 1;
      plVar2 = local_res10[0];
    }
    uVar3 = CONCAT71((int7)((ulonglong)plVar2 >> 8), 1);
  }
  return uVar3;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::console_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::console_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::type_case_n(void) __ptr64
//   12 names - too many to list
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong type_case_n(longlong param_1)
{
  ulonglong *puVar1;
  int iVar2;
  undefined4 extraout_var;
  ulong *puVar3;
  ulonglong uVar4;
  longlong lVar5;

  lVar5 = 8;
  *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
  puVar1 = *(ulonglong **)(*(longlong *)(param_1 + 0x20) + -8);
  iVar2 = _get_printf_count_output();
  uVar4 = CONCAT44(extraout_var, iVar2);
  if (iVar2 == 0)
  {
  LAB_18005c438:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  else
  {
    iVar2 = *(int *)(param_1 + 0x3c);
    if (iVar2 < 6)
    {
      if (iVar2 != 5)
      {
        if (iVar2 == 0)
          goto LAB_18005c499;
        if (iVar2 == 1)
        {
          lVar5 = 1;
        }
        else
        {
          iVar2 = iVar2 + -2;
          if (iVar2 != 0)
            goto LAB_18005c46c;
          lVar5 = 2;
        }
      }
    }
    else
    {
      if (((iVar2 != 6) && (iVar2 != 7)) && (iVar2 = iVar2 + -9, iVar2 != 0))
      {
      LAB_18005c46c:
        if (iVar2 == 1)
        {
        LAB_18005c499:
          lVar5 = 4;
        }
        else
        {
          if (iVar2 != 2)
          {
            lVar5 = 0;
          }
        }
      }
    }
    if (lVar5 == 1)
    {
      *(undefined *)puVar1 = *(undefined *)(param_1 + 0x28);
    }
    else
    {
      if (lVar5 == 2)
      {
        uVar4 = (ulonglong) * (ushort *)(param_1 + 0x28);
        *(ushort *)puVar1 = *(ushort *)(param_1 + 0x28);
      }
      else
      {
        if (lVar5 == 4)
        {
          uVar4 = (ulonglong) * (uint *)(param_1 + 0x28);
          *(uint *)puVar1 = *(uint *)(param_1 + 0x28);
        }
        else
        {
          if (lVar5 != 8)
            goto LAB_18005c438;
          uVar4 = SEXT48(*(int *)(param_1 + 0x28));
          *puVar1 = uVar4;
        }
      }
    }
    *(undefined *)(param_1 + 0x40) = 1;
    uVar4 = CONCAT71((int7)(uVar4 >> 8), 1);
  }
  return uVar4;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::update_field_width(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::update_field_width(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::update_field_width(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong update_field_width(longlong param_1, undefined8 param_2, undefined8 param_3, uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *in_RAX;
  ulonglong uVar6;
  ulong *puVar7;
  ulonglong uVar8;
  byte *local_res8;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *(undefined4 *)(param_1 + 0x34) = *(undefined4 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18005d4ee:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar8 = 0;
  local_res8 = (byte *)0x0;
  iVar4 = FUN_180069880(*(byte **)(param_1 + 0x18), &local_res8, 10);
  iVar4 = iVar4 + -1;
  *(byte **)(param_1 + 0x18) = local_res8 + 1;
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined4 **)(param_1 + 0x490 + (longlong)iVar4 * 0x18);
    *(undefined4 *)(param_1 + 0x34) = *in_RAX;
    goto LAB_18005d4ee;
  }
  if (((iVar4 < 0) || (*local_res8 != 0x24)) || (99 < iVar4))
  {
    puVar7 = __doserrno();
    *puVar7 = 0x16;
    uVar8 = FUN_18006738c();
    return uVar8 & 0xffffffffffffff00;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  iVar5 = *(int *)(param_1 + 0xde8);
  if (*(int *)(param_1 + 0xde8) < iVar4)
  {
    iVar5 = iVar4;
  }
  *(int *)(param_1 + 0xde8) = iVar5;
  uVar6 = SEXT48(iVar4);
  piVar1 = (int *)(param_1 + (uVar6 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar6 = FUN_18004f97c(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar6 == '\0')
    {
      puVar7 = __doserrno();
      *puVar7 = 0x16;
      uVar6 = FUN_18006738c();
      goto LAB_18005d498;
    }
  }
  uVar8 = 1;
LAB_18005d498:
  return uVar6 & 0xffffffffffffff00 | uVar8;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::update_field_width(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::update_field_width(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::update_field_width(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong update_field_width(longlong param_1, undefined8 param_2, undefined8 param_3, uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *in_RAX;
  ulonglong uVar6;
  ulong *puVar7;
  ulonglong uVar8;
  byte *local_res8;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *(undefined4 *)(param_1 + 0x34) = *(undefined4 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18005d602:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar8 = 0;
  local_res8 = (byte *)0x0;
  iVar4 = FUN_180069880(*(byte **)(param_1 + 0x18), &local_res8, 10);
  iVar4 = iVar4 + -1;
  *(byte **)(param_1 + 0x18) = local_res8 + 1;
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined4 **)(param_1 + 0x490 + (longlong)iVar4 * 0x18);
    *(undefined4 *)(param_1 + 0x34) = *in_RAX;
    goto LAB_18005d602;
  }
  if (((iVar4 < 0) || (*local_res8 != 0x24)) || (99 < iVar4))
  {
    puVar7 = __doserrno();
    *puVar7 = 0x16;
    uVar8 = FUN_18006738c();
    return uVar8 & 0xffffffffffffff00;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  iVar5 = *(int *)(param_1 + 0xde8);
  if (*(int *)(param_1 + 0xde8) < iVar4)
  {
    iVar5 = iVar4;
  }
  *(int *)(param_1 + 0xde8) = iVar5;
  uVar6 = SEXT48(iVar4);
  piVar1 = (int *)(param_1 + (uVar6 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar6 = FUN_18004fbac(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar6 == '\0')
    {
      puVar7 = __doserrno();
      *puVar7 = 0x16;
      uVar6 = FUN_18006738c();
      goto LAB_18005d5ac;
    }
  }
  uVar8 = 1;
LAB_18005d5ac:
  return uVar6 & 0xffffffffffffff00 | uVar8;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::update_field_width(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::update_field_width(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong update_field_width(__uint64 *param_1)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  int iVar4;
  int iVar5;
  undefined4 *in_RAX;
  ulonglong uVar6;
  ulong *puVar7;
  ulonglong uVar8;
  ushort *local_res8;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *(undefined4 *)((longlong)param_1 + 0x34) = *(undefined4 *)(param_1[4] - 8);
  LAB_18005d719:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar8 = 0;
  local_res8 = (ushort *)0x0;
  iVar4 = FUN_180069988((ushort *)param_1[3], &local_res8, 10);
  iVar4 = iVar4 + -1;
  param_1[3] = (__uint64)(local_res8 + 1);
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined4 *)param_1[(longlong)iVar4 * 3 + 0x92];
    *(undefined4 *)((longlong)param_1 + 0x34) = *in_RAX;
    goto LAB_18005d719;
  }
  if (((iVar4 < 0) || (*local_res8 != 0x24)) || (99 < iVar4))
  {
    puVar7 = __doserrno();
    *puVar7 = 0x16;
    uVar8 = FUN_18006738c();
    return uVar8 & 0xffffffffffffff00;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  iVar5 = *(int *)(param_1 + 0x1bd);
  if (*(int *)(param_1 + 0x1bd) < iVar4)
  {
    iVar5 = iVar4;
  }
  *(int *)(param_1 + 0x1bd) = iVar5;
  uVar6 = SEXT48(iVar4);
  p_Var1 = param_1 + uVar6 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar6 = FUN_18004fddc(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar6 == '\0')
    {
      puVar7 = __doserrno();
      *puVar7 = 0x16;
      uVar6 = FUN_18006738c();
      goto LAB_18005d6c3;
    }
  }
  uVar8 = 1;
LAB_18005d6c3:
  return uVar6 & 0xffffffffffffff00 | uVar8;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::update_field_width(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::update_field_width(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong update_field_width(__uint64 *param_1)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  int iVar4;
  int iVar5;
  undefined4 *in_RAX;
  ulonglong uVar6;
  ulong *puVar7;
  ulonglong uVar8;
  ushort *local_res8;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *(undefined4 *)((longlong)param_1 + 0x34) = *(undefined4 *)(param_1[4] - 8);
  LAB_18005d831:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar8 = 0;
  local_res8 = (ushort *)0x0;
  iVar4 = FUN_180069988((ushort *)param_1[3], &local_res8, 10);
  iVar4 = iVar4 + -1;
  param_1[3] = (__uint64)(local_res8 + 1);
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined4 *)param_1[(longlong)iVar4 * 3 + 0x92];
    *(undefined4 *)((longlong)param_1 + 0x34) = *in_RAX;
    goto LAB_18005d831;
  }
  if (((iVar4 < 0) || (*local_res8 != 0x24)) || (99 < iVar4))
  {
    puVar7 = __doserrno();
    *puVar7 = 0x16;
    uVar8 = FUN_18006738c();
    return uVar8 & 0xffffffffffffff00;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  iVar5 = *(int *)(param_1 + 0x1bd);
  if (*(int *)(param_1 + 0x1bd) < iVar4)
  {
    iVar5 = iVar4;
  }
  *(int *)(param_1 + 0x1bd) = iVar5;
  uVar6 = SEXT48(iVar4);
  p_Var1 = param_1 + uVar6 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar6 = FUN_18004ffd4(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar6 == '\0')
    {
      puVar7 = __doserrno();
      *puVar7 = 0x16;
      uVar6 = FUN_18006738c();
      goto LAB_18005d7db;
    }
  }
  uVar8 = 1;
LAB_18005d7db:
  return uVar6 & 0xffffffffffffff00 | uVar8;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::update_precision(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::update_precision(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::update_precision(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong update_precision(longlong param_1, undefined8 param_2, undefined8 param_3, uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *in_RAX;
  ulonglong uVar6;
  ulong *puVar7;
  ulonglong uVar8;
  byte *local_res8;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *(undefined4 *)(param_1 + 0x38) = *(undefined4 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18005d996:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar8 = 0;
  local_res8 = (byte *)0x0;
  iVar4 = FUN_180069880(*(byte **)(param_1 + 0x18), &local_res8, 10);
  iVar4 = iVar4 + -1;
  *(byte **)(param_1 + 0x18) = local_res8 + 1;
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined4 **)(param_1 + 0x490 + (longlong)iVar4 * 0x18);
    *(undefined4 *)(param_1 + 0x38) = *in_RAX;
    goto LAB_18005d996;
  }
  if (((iVar4 < 0) || (*local_res8 != 0x24)) || (99 < iVar4))
  {
    puVar7 = __doserrno();
    *puVar7 = 0x16;
    uVar8 = FUN_18006738c();
    return uVar8 & 0xffffffffffffff00;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  iVar5 = *(int *)(param_1 + 0xde8);
  if (*(int *)(param_1 + 0xde8) < iVar4)
  {
    iVar5 = iVar4;
  }
  *(int *)(param_1 + 0xde8) = iVar5;
  uVar6 = SEXT48(iVar4);
  piVar1 = (int *)(param_1 + (uVar6 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar6 = FUN_18004f97c(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar6 == '\0')
    {
      puVar7 = __doserrno();
      *puVar7 = 0x16;
      uVar6 = FUN_18006738c();
      goto LAB_18005d940;
    }
  }
  uVar8 = 1;
LAB_18005d940:
  return uVar6 & 0xffffffffffffff00 | uVar8;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::update_precision(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::update_precision(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::update_precision(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong update_precision(longlong param_1, undefined8 param_2, undefined8 param_3, uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *in_RAX;
  ulonglong uVar6;
  ulong *puVar7;
  ulonglong uVar8;
  byte *local_res8;

  if (*(int *)(param_1 + 0x47c) == 1)
  {
    *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
    *(undefined4 *)(param_1 + 0x38) = *(undefined4 *)(*(longlong *)(param_1 + 0x20) + -8);
  LAB_18005daaa:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar8 = 0;
  local_res8 = (byte *)0x0;
  iVar4 = FUN_180069880(*(byte **)(param_1 + 0x18), &local_res8, 10);
  iVar4 = iVar4 + -1;
  *(byte **)(param_1 + 0x18) = local_res8 + 1;
  if (*(int *)(param_1 + 0x478) != 1)
  {
    in_RAX = *(undefined4 **)(param_1 + 0x490 + (longlong)iVar4 * 0x18);
    *(undefined4 *)(param_1 + 0x38) = *in_RAX;
    goto LAB_18005daaa;
  }
  if (((iVar4 < 0) || (*local_res8 != 0x24)) || (99 < iVar4))
  {
    puVar7 = __doserrno();
    *puVar7 = 0x16;
    uVar8 = FUN_18006738c();
    return uVar8 & 0xffffffffffffff00;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  iVar5 = *(int *)(param_1 + 0xde8);
  if (*(int *)(param_1 + 0xde8) < iVar4)
  {
    iVar5 = iVar4;
  }
  *(int *)(param_1 + 0xde8) = iVar5;
  uVar6 = SEXT48(iVar4);
  piVar1 = (int *)(param_1 + (uVar6 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 1;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar6 = FUN_18004fbac(param_1, piVar1, 1, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar6 == '\0')
    {
      puVar7 = __doserrno();
      *puVar7 = 0x16;
      uVar6 = FUN_18006738c();
      goto LAB_18005da54;
    }
  }
  uVar8 = 1;
LAB_18005da54:
  return uVar6 & 0xffffffffffffff00 | uVar8;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::update_precision(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::update_precision(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong update_precision(__uint64 *param_1)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  int iVar4;
  int iVar5;
  undefined4 *in_RAX;
  ulonglong uVar6;
  ulong *puVar7;
  ulonglong uVar8;
  ushort *local_res8;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *(undefined4 *)(param_1 + 7) = *(undefined4 *)(param_1[4] - 8);
  LAB_18005dbc1:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar8 = 0;
  local_res8 = (ushort *)0x0;
  iVar4 = FUN_180069988((ushort *)param_1[3], &local_res8, 10);
  iVar4 = iVar4 + -1;
  param_1[3] = (__uint64)(local_res8 + 1);
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined4 *)param_1[(longlong)iVar4 * 3 + 0x92];
    *(undefined4 *)(param_1 + 7) = *in_RAX;
    goto LAB_18005dbc1;
  }
  if (((iVar4 < 0) || (*local_res8 != 0x24)) || (99 < iVar4))
  {
    puVar7 = __doserrno();
    *puVar7 = 0x16;
    uVar8 = FUN_18006738c();
    return uVar8 & 0xffffffffffffff00;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  iVar5 = *(int *)(param_1 + 0x1bd);
  if (*(int *)(param_1 + 0x1bd) < iVar4)
  {
    iVar5 = iVar4;
  }
  *(int *)(param_1 + 0x1bd) = iVar5;
  uVar6 = SEXT48(iVar4);
  p_Var1 = param_1 + uVar6 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar6 = FUN_18004fddc(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar6 == '\0')
    {
      puVar7 = __doserrno();
      *puVar7 = 0x16;
      uVar6 = FUN_18006738c();
      goto LAB_18005db6b;
    }
  }
  uVar8 = 1;
LAB_18005db6b:
  return uVar6 & 0xffffffffffffff00 | uVar8;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::update_precision(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::update_precision(void) __ptr64
//
// Library: Visual Studio 2015 Release

ulonglong update_precision(__uint64 *param_1)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  int iVar4;
  int iVar5;
  undefined4 *in_RAX;
  ulonglong uVar6;
  ulong *puVar7;
  ulonglong uVar8;
  ushort *local_res8;

  if (*(int *)((longlong)param_1 + 0x47c) == 1)
  {
    param_1[4] = param_1[4] + 8;
    *(undefined4 *)(param_1 + 7) = *(undefined4 *)(param_1[4] - 8);
  LAB_18005dcd9:
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar8 = 0;
  local_res8 = (ushort *)0x0;
  iVar4 = FUN_180069988((ushort *)param_1[3], &local_res8, 10);
  iVar4 = iVar4 + -1;
  param_1[3] = (__uint64)(local_res8 + 1);
  if (*(int *)(param_1 + 0x8f) != 1)
  {
    in_RAX = (undefined4 *)param_1[(longlong)iVar4 * 3 + 0x92];
    *(undefined4 *)(param_1 + 7) = *in_RAX;
    goto LAB_18005dcd9;
  }
  if (((iVar4 < 0) || (*local_res8 != 0x24)) || (99 < iVar4))
  {
    puVar7 = __doserrno();
    *puVar7 = 0x16;
    uVar8 = FUN_18006738c();
    return uVar8 & 0xffffffffffffff00;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  iVar5 = *(int *)(param_1 + 0x1bd);
  if (*(int *)(param_1 + 0x1bd) < iVar4)
  {
    iVar5 = iVar4;
  }
  *(int *)(param_1 + 0x1bd) = iVar5;
  uVar6 = SEXT48(iVar4);
  p_Var1 = param_1 + uVar6 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 1;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar6 = FUN_18004ffd4(param_1, (int *)p_Var1, 1, uVar2, lVar3);
    if ((char)uVar6 == '\0')
    {
      puVar7 = __doserrno();
      *puVar7 = 0x16;
      uVar6 = FUN_18006738c();
      goto LAB_18005dc83;
    }
  }
  uVar8 = 1;
LAB_18005dc83:
  return uVar6 & 0xffffffffffffff00 | uVar8;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::validate_and_store_parameter_data(struct
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::parameter_data & __ptr64,enum
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::parameter_type,char,enum
// __crt_stdio_output::length_modifier) __ptr64
//  private: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::validate_and_store_parameter_data(struct
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::parameter_data & __ptr64,enum
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::parameter_type,char,enum
// __crt_stdio_output::length_modifier) __ptr64
//  private: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::validate_and_store_parameter_data(struct
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::parameter_data & __ptr64,enum
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::parameter_type,char,enum
// __crt_stdio_output::length_modifier) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong validate_and_store_parameter_data(undefined8 param_1, int *param_2, int param_3, uint param_4, int param_5)
{
  ulonglong uVar1;
  ulong *puVar2;

  uVar1 = (ulonglong)(uint)param_5;
  if (*param_2 == 0)
  {
    *param_2 = param_3;
    *(char *)(param_2 + 1) = (char)param_4;
    param_2[4] = param_5;
  }
  else
  {
    uVar1 = FUN_18004f97c(param_1, param_2, param_3, param_4, param_5);
    if ((char)uVar1 == '\0')
    {
      puVar2 = __doserrno();
      *puVar2 = 0x16;
      uVar1 = FUN_18006738c();
      return uVar1 & 0xffffffffffffff00;
    }
  }
  return CONCAT71((int7)(uVar1 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::console_output_adapter<char> > ::validate_and_update_state_at_beginning_of_format_character(void)
    // __ptr64
    //  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
    //
    __crt_stdio_output::stream_output_adapter<char> > ::validate_and_update_state_at_beginning_of_format_character(void)
    // __ptr64
    //  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
    //
    __crt_stdio_output::string_output_adapter<char> > ::validate_and_update_state_at_beginning_of_format_character(void)
    // __ptr64
    //
    // Library: Visual Studio 2015 Release

    ulonglong validate_and_update_state_at_beginning_of_format_character(longlong param_1)
{
  byte bVar1;
  uint uVar2;
  int iVar3;
  undefined(*in_RAX)[16];
  ulong *puVar4;
  ulonglong uVar5;
  uint uVar6;
  undefined(*local_res8)[16];
  byte *local_res10[3];

  if (*(int *)(param_1 + 0x2c) == 1)
  {
    bVar1 = **(byte **)(param_1 + 0x18);
    in_RAX = (undefined(*)[16])((ulonglong)in_RAX & 0xffffffffffffff00);
    if (bVar1 != 0x25)
    {
      if (*(int *)(param_1 + 0x47c) == 0)
      {
        local_res8 = (undefined(*)[16])0x0;
        if ((((byte)(bVar1 - 0x30) < 10) &&
             (in_RAX = (undefined(*)[16])
                  FUN_180069880(*(byte **)(param_1 + 0x18), (byte **)&local_res8, 10),
              0 < (int)in_RAX)) &&
            (in_RAX = local_res8, (*local_res8)[0] == '$'))
        {
          if (*(int *)(param_1 + 0x478) == 1)
          {
            in_RAX = FUN_18003bd40((undefined(*)[16])(param_1 + 0x488), 0, 0x960);
          }
          *(undefined4 *)(param_1 + 0x47c) = 2;
        }
        else
        {
          *(undefined4 *)(param_1 + 0x47c) = 1;
        }
      }
      if (*(int *)(param_1 + 0x47c) == 2)
      {
        local_res10[0] = (byte *)0x0;
        iVar3 = FUN_180069880(*(byte **)(param_1 + 0x18), local_res10, 10);
        uVar6 = iVar3 - 1;
        *(uint *)(param_1 + 0xdec) = uVar6;
        in_RAX = (undefined(*)[16])(local_res10[0] + 1);
        *(undefined(**)[16])(param_1 + 0x18) = in_RAX;
        if (*(int *)(param_1 + 0x478) == 1)
        {
          if ((((int)uVar6 < 0) || (*local_res10[0] != 0x24)) || (99 < (int)uVar6))
          {
            puVar4 = __doserrno();
            *puVar4 = 0x16;
            uVar5 = FUN_18006738c();
            return uVar5 & 0xffffffffffffff00;
          }
          uVar2 = *(uint *)(param_1 + 0xde8);
          if ((int)*(uint *)(param_1 + 0xde8) < (int)uVar6)
          {
            uVar2 = uVar6;
          }
          in_RAX = (undefined(*)[16])(ulonglong)uVar2;
          *(uint *)(param_1 + 0xde8) = uVar2;
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t> > ::validate_and_update_state_at_beginning_of_format_character(void)
    // __ptr64
    //  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
    //
    __crt_stdio_output::string_output_adapter<wchar_t> > ::validate_and_update_state_at_beginning_of_format_character(void)
    // __ptr64
    //
    // Library: Visual Studio 2015 Release

    ulonglong validate_and_update_state_at_beginning_of_format_character(longlong param_1)
{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  undefined(*in_RAX)[16];
  ulong *puVar4;
  ulonglong uVar5;
  uint uVar6;
  undefined(*local_res8)[16];
  ushort *local_res10[3];

  if (*(int *)(param_1 + 0x2c) == 1)
  {
    uVar1 = **(ushort **)(param_1 + 0x18);
    in_RAX = (undefined(*)[16])(ulonglong)uVar1;
    if (uVar1 != 0x25)
    {
      if (*(int *)(param_1 + 0x47c) == 0)
      {
        local_res8 = (undefined(*)[16])0x0;
        in_RAX = (undefined(*)[16])(ulonglong)(ushort)(uVar1 - 0x30);
        if ((((ushort)(uVar1 - 0x30) < 10) &&
             (in_RAX = (undefined(*)[16])
                  FUN_180069988(*(ushort **)(param_1 + 0x18), (ushort **)&local_res8, 10),
              0 < (int)in_RAX)) &&
            (in_RAX = local_res8, *(short *)*local_res8 == 0x24))
        {
          if (*(int *)(param_1 + 0x478) == 1)
          {
            in_RAX = FUN_18003bd40((undefined(*)[16])(param_1 + 0x488), 0, 0x960);
          }
          *(undefined4 *)(param_1 + 0x47c) = 2;
        }
        else
        {
          *(undefined4 *)(param_1 + 0x47c) = 1;
        }
      }
      if (*(int *)(param_1 + 0x47c) == 2)
      {
        local_res10[0] = (ushort *)0x0;
        iVar3 = FUN_180069988(*(ushort **)(param_1 + 0x18), local_res10, 10);
        uVar6 = iVar3 - 1;
        *(uint *)(param_1 + 0xdec) = uVar6;
        in_RAX = (undefined(*)[16])(local_res10[0] + 1);
        *(undefined(**)[16])(param_1 + 0x18) = in_RAX;
        if (*(int *)(param_1 + 0x478) == 1)
        {
          if ((((int)uVar6 < 0) || (*local_res10[0] != 0x24)) || (99 < (int)uVar6))
          {
            puVar4 = __doserrno();
            *puVar4 = 0x16;
            uVar5 = FUN_18006738c();
            return uVar5 & 0xffffffffffffff00;
          }
          uVar2 = *(uint *)(param_1 + 0xde8);
          if ((int)*(uint *)(param_1 + 0xde8) < (int)uVar6)
          {
            uVar2 = uVar6;
          }
          in_RAX = (undefined(*)[16])(ulonglong)uVar2;
          *(uint *)(param_1 + 0xde8) = uVar2;
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t> > ::validate_and_update_state_at_beginning_of_format_character(void)
    // __ptr64
    //  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
    //
    __crt_stdio_output::string_output_adapter<wchar_t> > ::validate_and_update_state_at_beginning_of_format_character(void)
    // __ptr64
    //
    // Library: Visual Studio 2015 Release

    ulonglong validate_and_update_state_at_beginning_of_format_character(longlong param_1)
{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  undefined(*in_RAX)[16];
  ulong *puVar4;
  ulonglong uVar5;
  uint uVar6;
  undefined(*local_res8)[16];
  ushort *local_res10[3];

  if (*(int *)(param_1 + 0x2c) == 1)
  {
    uVar1 = **(ushort **)(param_1 + 0x18);
    in_RAX = (undefined(*)[16])(ulonglong)uVar1;
    if (uVar1 != 0x25)
    {
      if (*(int *)(param_1 + 0x47c) == 0)
      {
        local_res8 = (undefined(*)[16])0x0;
        in_RAX = (undefined(*)[16])(ulonglong)(ushort)(uVar1 - 0x30);
        if ((((ushort)(uVar1 - 0x30) < 10) &&
             (in_RAX = (undefined(*)[16])
                  FUN_180069988(*(ushort **)(param_1 + 0x18), (ushort **)&local_res8, 10),
              0 < (int)in_RAX)) &&
            (in_RAX = local_res8, *(short *)*local_res8 == 0x24))
        {
          if (*(int *)(param_1 + 0x478) == 1)
          {
            in_RAX = FUN_18003bd40((undefined(*)[16])(param_1 + 0x488), 0, 0x960);
          }
          *(undefined4 *)(param_1 + 0x47c) = 2;
        }
        else
        {
          *(undefined4 *)(param_1 + 0x47c) = 1;
        }
      }
      if (*(int *)(param_1 + 0x47c) == 2)
      {
        local_res10[0] = (ushort *)0x0;
        iVar3 = FUN_180069988(*(ushort **)(param_1 + 0x18), local_res10, 10);
        uVar6 = iVar3 - 1;
        *(uint *)(param_1 + 0xdec) = uVar6;
        in_RAX = (undefined(*)[16])(local_res10[0] + 1);
        *(undefined(**)[16])(param_1 + 0x18) = in_RAX;
        if (*(int *)(param_1 + 0x478) == 1)
        {
          if ((((int)uVar6 < 0) || (*local_res10[0] != 0x24)) || (99 < (int)uVar6))
          {
            puVar4 = __doserrno();
            *puVar4 = 0x16;
            uVar5 = FUN_18006738c();
            return uVar5 & 0xffffffffffffff00;
          }
          uVar2 = *(uint *)(param_1 + 0xde8);
          if ((int)*(uint *)(param_1 + 0xde8) < (int)uVar6)
          {
            uVar2 = uVar6;
          }
          in_RAX = (undefined(*)[16])(ulonglong)uVar2;
          *(uint *)(param_1 + 0xde8) = uVar2;
        }
      }
    }
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::console_output_adapter<char> > ::validate_and_update_state_at_end_of_format_string(void)
    // __ptr64
    //  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
    //
    __crt_stdio_output::stream_output_adapter<char> > ::validate_and_update_state_at_end_of_format_string(void)
    // __ptr64
    //  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
    //
    __crt_stdio_output::string_output_adapter<char> > ::validate_and_update_state_at_end_of_format_string(void)
    // __ptr64
    //  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
    //
    __crt_stdio_output::console_output_adapter<wchar_t> > ::validate_and_update_state_at_end_of_format_string(void)
    // __ptr64
    //   6 names - too many to list
    //
    // Library: Visual Studio 2015 Release

    ulonglong validate_and_update_state_at_end_of_format_string(longlong param_1)
{
  int iVar1;
  longlong lVar2;
  longlong in_RAX;
  ulong *puVar3;
  ulonglong uVar4;
  int *piVar5;

  if ((*(int *)(param_1 + 0x2c) == 0) || (*(int *)(param_1 + 0x2c) == 7))
  {
    if ((*(int *)(param_1 + 0x47c) == 2) && (*(int *)(param_1 + 0x478) == 1))
    {
      in_RAX = (longlong) * (int *)(param_1 + 0xde8);
      piVar5 = (int *)(param_1 + 0x488);
      lVar2 = in_RAX * 0x18;
      while (piVar5 != (int *)(param_1 + lVar2 + 0x4a0))
      {
        iVar1 = *piVar5;
        in_RAX = *(longlong *)(param_1 + 0x20);
        *(longlong *)(piVar5 + 2) = in_RAX;
        if ((((iVar1 != 1) && (iVar1 != 2)) && (iVar1 != 3)) && (iVar1 != 4))
          goto LAB_18005e3d7;
        *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
        piVar5 = piVar5 + 6;
      }
    }
    uVar4 = CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  else
  {
  LAB_18005e3d7:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  return uVar4;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
//
__crt_stdio_output::console_output_adapter<char> > ::validate_and_update_state_at_end_of_format_string(void)
    // __ptr64
    //  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
    //
    __crt_stdio_output::stream_output_adapter<char> > ::validate_and_update_state_at_end_of_format_string(void)
    // __ptr64
    //  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
    //
    __crt_stdio_output::string_output_adapter<char> > ::validate_and_update_state_at_end_of_format_string(void)
    // __ptr64
    //  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
    //
    __crt_stdio_output::console_output_adapter<wchar_t> > ::validate_and_update_state_at_end_of_format_string(void)
    // __ptr64
    //   6 names - too many to list
    //
    // Library: Visual Studio 2015 Release

    ulonglong validate_and_update_state_at_end_of_format_string(longlong param_1)
{
  int iVar1;
  longlong lVar2;
  longlong in_RAX;
  ulong *puVar3;
  ulonglong uVar4;
  int *piVar5;

  if ((*(int *)(param_1 + 0x2c) == 0) || (*(int *)(param_1 + 0x2c) == 7))
  {
    if ((*(int *)(param_1 + 0x47c) == 2) && (*(int *)(param_1 + 0x478) == 1))
    {
      in_RAX = (longlong) * (int *)(param_1 + 0xde8);
      piVar5 = (int *)(param_1 + 0x488);
      lVar2 = in_RAX * 0x18;
      while (piVar5 != (int *)(param_1 + lVar2 + 0x4a0))
      {
        iVar1 = *piVar5;
        in_RAX = *(longlong *)(param_1 + 0x20);
        *(longlong *)(piVar5 + 2) = in_RAX;
        if ((((iVar1 != 1) && (iVar1 != 2)) && (iVar1 != 3)) && (iVar1 != 4))
          goto LAB_18005e463;
        *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
        piVar5 = piVar5 + 6;
      }
    }
    uVar4 = CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  else
  {
  LAB_18005e463:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  return uVar4;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t> > ::validate_and_update_state_at_end_of_format_string(void)
    // __ptr64
    //  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
    //
    __crt_stdio_output::string_output_adapter<wchar_t> > ::validate_and_update_state_at_end_of_format_string(void)
    // __ptr64
    //
    // Library: Visual Studio 2015 Release

    ulonglong validate_and_update_state_at_end_of_format_string(longlong param_1)
{
  int iVar1;
  longlong lVar2;
  longlong in_RAX;
  ulong *puVar3;
  ulonglong uVar4;
  int *piVar5;

  if ((*(int *)(param_1 + 0x2c) == 0) || (*(int *)(param_1 + 0x2c) == 7))
  {
    if ((*(int *)(param_1 + 0x47c) == 2) && (*(int *)(param_1 + 0x478) == 1))
    {
      in_RAX = (longlong) * (int *)(param_1 + 0xde8);
      piVar5 = (int *)(param_1 + 0x488);
      lVar2 = in_RAX * 0x18;
      while (piVar5 != (int *)(param_1 + lVar2 + 0x4a0))
      {
        iVar1 = *piVar5;
        in_RAX = *(longlong *)(param_1 + 0x20);
        *(longlong *)(piVar5 + 2) = in_RAX;
        if ((((iVar1 != 1) && (iVar1 != 2)) && (iVar1 != 3)) && (iVar1 != 4))
          goto LAB_18005e4ef;
        *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
        piVar5 = piVar5 + 6;
      }
    }
    uVar4 = CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  else
  {
  LAB_18005e4ef:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  return uVar4;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
//
__crt_stdio_output::stream_output_adapter<wchar_t> > ::validate_and_update_state_at_end_of_format_string(void)
    // __ptr64
    //  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
    //
    __crt_stdio_output::string_output_adapter<wchar_t> > ::validate_and_update_state_at_end_of_format_string(void)
    // __ptr64
    //
    // Library: Visual Studio 2015 Release

    ulonglong validate_and_update_state_at_end_of_format_string(longlong param_1)
{
  int iVar1;
  longlong lVar2;
  longlong in_RAX;
  ulong *puVar3;
  ulonglong uVar4;
  int *piVar5;

  if ((*(int *)(param_1 + 0x2c) == 0) || (*(int *)(param_1 + 0x2c) == 7))
  {
    if ((*(int *)(param_1 + 0x47c) == 2) && (*(int *)(param_1 + 0x478) == 1))
    {
      in_RAX = (longlong) * (int *)(param_1 + 0xde8);
      piVar5 = (int *)(param_1 + 0x488);
      lVar2 = in_RAX * 0x18;
      while (piVar5 != (int *)(param_1 + lVar2 + 0x4a0))
      {
        iVar1 = *piVar5;
        in_RAX = *(longlong *)(param_1 + 0x20);
        *(longlong *)(piVar5 + 2) = in_RAX;
        if ((((iVar1 != 1) && (iVar1 != 2)) && (iVar1 != 3)) && (iVar1 != 4))
          goto LAB_18005e57b;
        *(longlong *)(param_1 + 0x20) = *(longlong *)(param_1 + 0x20) + 8;
        piVar5 = piVar5 + 6;
      }
    }
    uVar4 = CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  else
  {
  LAB_18005e57b:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    uVar4 = FUN_18006738c();
    uVar4 = uVar4 & 0xffffffffffffff00;
  }
  return uVar4;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::validate_state_for_type_case_a(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::validate_state_for_type_case_a(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::validate_state_for_type_case_a(void) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong validate_state_for_type_case_a(longlong param_1, undefined8 param_2, undefined8 param_3, uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined8 in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if ((*(int *)(param_1 + 0x47c) != 2) || (*(int *)(param_1 + 0x478) != 1))
  {
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 4;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004f97c(param_1, piVar1, 4, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18005e66d;
    }
  }
  uVar6 = 1;
LAB_18005e66d:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::console_output_adapter<char>>::validate_state_for_type_case_a(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>::validate_state_for_type_case_a(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>::validate_state_for_type_case_a(void) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong validate_state_for_type_case_a(longlong param_1, undefined8 param_2, undefined8 param_3, uint param_4)
{
  int *piVar1;
  byte bVar2;
  int iVar3;
  undefined8 in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if ((*(int *)(param_1 + 0x47c) != 2) || (*(int *)(param_1 + 0x478) != 1))
  {
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)(param_1 + 0xdec));
  if (99 < *(uint *)(param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  iVar3 = *(int *)(param_1 + 0x3c);
  bVar2 = *(byte *)(param_1 + 0x41);
  uVar6 = 0;
  piVar1 = (int *)(param_1 + (uVar4 * 3 + 0x91) * 8);
  if (*piVar1 == 0)
  {
    *piVar1 = 4;
    *(byte *)(piVar1 + 1) = bVar2;
    piVar1[4] = iVar3;
  }
  else
  {
    uVar4 = FUN_18004fbac(param_1, piVar1, 4, param_4 & 0xffffff00 | (uint)bVar2, iVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18005e709;
    }
  }
  uVar6 = 1;
LAB_18005e709:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::validate_state_for_type_case_a(void)
// __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::validate_state_for_type_case_a(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::validate_state_for_type_case_a(void) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong validate_state_for_type_case_a(__uint64 *param_1)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined8 in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if ((*(int *)((longlong)param_1 + 0x47c) != 2) || (*(int *)(param_1 + 0x8f) != 1))
  {
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 4;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004fddc(param_1, (int *)p_Var1, 4, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18005e7a7;
    }
  }
  uVar6 = 1;
LAB_18005e7a7:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::console_output_adapter<wchar_t>>::validate_state_for_type_case_a(void)
// __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>::validate_state_for_type_case_a(void) __ptr64
//  protected: bool __cdecl __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::string_output_adapter<wchar_t>>::validate_state_for_type_case_a(void) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong validate_state_for_type_case_a(__uint64 *param_1)
{
  __uint64 *p_Var1;
  ushort uVar2;
  length_modifier lVar3;
  undefined8 in_RAX;
  ulonglong uVar4;
  ulong *puVar5;
  ulonglong uVar6;

  if ((*(int *)((longlong)param_1 + 0x47c) != 2) || (*(int *)(param_1 + 0x8f) != 1))
  {
    return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
  }
  uVar4 = SEXT48((int)*(uint *)((longlong)param_1 + 0xdec));
  if (99 < *(uint *)((longlong)param_1 + 0xdec))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    uVar4 = FUN_18006738c();
    return uVar4 & 0xffffffffffffff00;
  }
  lVar3 = *(length_modifier *)((longlong)param_1 + 0x3c);
  uVar2 = *(ushort *)((longlong)param_1 + 0x42);
  uVar6 = 0;
  p_Var1 = param_1 + uVar4 * 3 + 0x91;
  if (*(int *)p_Var1 == 0)
  {
    *(int *)p_Var1 = 4;
    *(ushort *)((longlong)p_Var1 + 4) = uVar2;
    *(length_modifier *)(p_Var1 + 2) = lVar3;
  }
  else
  {
    uVar4 = FUN_18004ffd4(param_1, (int *)p_Var1, 4, uVar2, lVar3);
    if ((char)uVar4 == '\0')
    {
      puVar5 = __doserrno();
      *puVar5 = 0x16;
      uVar4 = FUN_18006738c();
      goto LAB_18005e847;
    }
  }
  uVar6 = 1;
LAB_18005e847:
  return uVar4 & 0xffffffffffffff00 | uVar6;
}

// Library Function - Single Match
//  public: static bool __cdecl
// __acrt_stdio_char_traits<char>::validate_stream_is_ansi_if_required(struct _iobuf * __ptr64
// const)
//
// Library: Visual Studio 2015 Release

bool __acrt_stdio_char_traits<char>::validate_stream_is_ansi_if_required(_iobuf *param_1)
{
  bool bVar1;
  uint uVar2;
  ulong *puVar3;
  undefined *puVar4;
  undefined *puVar5;

  if ((*(uint *)((longlong)&param_1->_base + 4) >> 0xc & 1) == 0)
  {
    uVar2 = _fileno((FILE *)param_1);
    puVar4 = &DAT_1800ee720;
    if (uVar2 + 2 < 2)
    {
      puVar5 = &DAT_1800ee720;
    }
    else
    {
      puVar5 = (undefined *)((ulonglong)(uVar2 & 0x3f) * 0x40 +
                             *(longlong *)((longlong)&DAT_180101d10 + ((longlong)(int)uVar2 >> 6) * 8));
    }
    if (puVar5[0x39] == '\0')
    {
      if (1 < uVar2 + 2)
      {
        puVar4 = (undefined *)((ulonglong)(uVar2 & 0x3f) * 0x40 +
                               *(longlong *)((longlong)&DAT_180101d10 + ((longlong)(int)uVar2 >> 6) * 8));
      }
      if ((puVar4[0x3d] & 1) == 0)
        goto LAB_18005e911;
    }
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    FUN_18006738c();
    bVar1 = false;
  }
  else
  {
  LAB_18005e911:
    bVar1 = true;
  }
  return bVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void write_stored_string_tchar(longlong param_1)
{
  int *piVar1;
  FILE **ppFVar2;
  wchar_t _WCh;
  errno_t eVar3;
  wchar_t *pwVar4;
  int iVar5;
  int local_28;
  byte local_24[12];
  ulonglong local_18;

  local_18 = DAT_1800ee160 ^ (ulonglong)&stack0xffffffffffffffa8;
  if ((*(char *)(param_1 + 0x54) == '\0') || (*(int *)(param_1 + 0x50) < 1))
  {
    ppFVar2 = (FILE **)(param_1 + 0x468);
    piVar1 = (int *)(param_1 + 0x28);
    if (((*(uint *)((longlong) & (*ppFVar2)->_base + 4) >> 0xc & 1) == 0) ||
        (*(longlong *)&(*ppFVar2)->_cnt != 0))
    {
      FUN_18005f894(ppFVar2, *(byte **)(param_1 + 0x48), *(int *)(param_1 + 0x50), piVar1,
                    (ulong **)(param_1 + 0x10));
    }
    else
    {
      *piVar1 = *piVar1 + *(int *)(param_1 + 0x50);
    }
  }
  else
  {
    pwVar4 = *(wchar_t **)(param_1 + 0x48);
    iVar5 = 0;
    if (*(int *)(param_1 + 0x50) != 0)
    {
      do
      {
        _WCh = *pwVar4;
        local_28 = 0;
        pwVar4 = pwVar4 + 1;
        eVar3 = wctomb_s(&local_28, (char *)local_24, 6, _WCh);
        if ((eVar3 != 0) || (local_28 == 0))
        {
          *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
          break;
        }
        ppFVar2 = (FILE **)(param_1 + 0x468);
        piVar1 = (int *)(param_1 + 0x28);
        if (((*(uint *)((longlong) & (*ppFVar2)->_base + 4) >> 0xc & 1) == 0) ||
            (*(longlong *)&(*ppFVar2)->_cnt != 0))
        {
          FUN_18005f894(ppFVar2, local_24, local_28, piVar1, (ulong **)(param_1 + 0x10));
        }
        else
        {
          *piVar1 = *piVar1 + local_28;
        }
        iVar5 = iVar5 + 1;
      } while (iVar5 != *(int *)(param_1 + 0x50));
    }
  }
  FUN_180034d00(local_18 ^ (ulonglong)&stack0xffffffffffffffa8);
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void write_stored_string_tchar(longlong param_1)
{
  int *piVar1;
  FILE **ppFVar2;
  wchar_t _WCh;
  errno_t eVar3;
  wchar_t *pwVar4;
  int iVar5;
  int local_28;
  byte local_24[12];
  ulonglong local_18;

  local_18 = DAT_1800ee160 ^ (ulonglong)&stack0xffffffffffffffa8;
  if ((*(char *)(param_1 + 0x54) == '\0') || (*(int *)(param_1 + 0x50) < 1))
  {
    ppFVar2 = (FILE **)(param_1 + 0x468);
    piVar1 = (int *)(param_1 + 0x28);
    if (((*(uint *)((longlong) & (*ppFVar2)->_base + 4) >> 0xc & 1) == 0) ||
        (*(longlong *)&(*ppFVar2)->_cnt != 0))
    {
      FUN_18005f894(ppFVar2, *(byte **)(param_1 + 0x48), *(int *)(param_1 + 0x50), piVar1,
                    (ulong **)(param_1 + 0x10));
    }
    else
    {
      *piVar1 = *piVar1 + *(int *)(param_1 + 0x50);
    }
  }
  else
  {
    pwVar4 = *(wchar_t **)(param_1 + 0x48);
    iVar5 = 0;
    if (*(int *)(param_1 + 0x50) != 0)
    {
      do
      {
        _WCh = *pwVar4;
        local_28 = 0;
        pwVar4 = pwVar4 + 1;
        eVar3 = wctomb_s(&local_28, (char *)local_24, 6, _WCh);
        if ((eVar3 != 0) || (local_28 == 0))
        {
          *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
          break;
        }
        ppFVar2 = (FILE **)(param_1 + 0x468);
        piVar1 = (int *)(param_1 + 0x28);
        if (((*(uint *)((longlong) & (*ppFVar2)->_base + 4) >> 0xc & 1) == 0) ||
            (*(longlong *)&(*ppFVar2)->_cnt != 0))
        {
          FUN_18005f894(ppFVar2, local_24, local_28, piVar1, (ulong **)(param_1 + 0x10));
        }
        else
        {
          *piVar1 = *piVar1 + local_28;
        }
        iVar5 = iVar5 + 1;
      } while (iVar5 != *(int *)(param_1 + 0x50));
    }
  }
  FUN_180034d00(local_18 ^ (ulonglong)&stack0xffffffffffffffa8);
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::stream_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::stream_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void write_stored_string_tchar(longlong param_1)
{
  int *piVar1;
  FILE **ppFVar2;
  wchar_t _WCh;
  errno_t eVar3;
  wchar_t *pwVar4;
  int iVar5;
  int local_28;
  byte local_24[12];
  ulonglong local_18;

  local_18 = DAT_1800ee160 ^ (ulonglong)&stack0xffffffffffffffa8;
  if ((*(char *)(param_1 + 0x54) == '\0') || (*(int *)(param_1 + 0x50) < 1))
  {
    ppFVar2 = (FILE **)(param_1 + 0x468);
    piVar1 = (int *)(param_1 + 0x28);
    if (((*(uint *)((longlong) & (*ppFVar2)->_base + 4) >> 0xc & 1) == 0) ||
        (*(longlong *)&(*ppFVar2)->_cnt != 0))
    {
      FUN_18005f894(ppFVar2, *(byte **)(param_1 + 0x48), *(int *)(param_1 + 0x50), piVar1,
                    (ulong **)(param_1 + 0x10));
    }
    else
    {
      *piVar1 = *piVar1 + *(int *)(param_1 + 0x50);
    }
  }
  else
  {
    pwVar4 = *(wchar_t **)(param_1 + 0x48);
    iVar5 = 0;
    if (*(int *)(param_1 + 0x50) != 0)
    {
      do
      {
        _WCh = *pwVar4;
        local_28 = 0;
        pwVar4 = pwVar4 + 1;
        eVar3 = wctomb_s(&local_28, (char *)local_24, 6, _WCh);
        if ((eVar3 != 0) || (local_28 == 0))
        {
          *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
          break;
        }
        ppFVar2 = (FILE **)(param_1 + 0x468);
        piVar1 = (int *)(param_1 + 0x28);
        if (((*(uint *)((longlong) & (*ppFVar2)->_base + 4) >> 0xc & 1) == 0) ||
            (*(longlong *)&(*ppFVar2)->_cnt != 0))
        {
          FUN_18005f894(ppFVar2, local_24, local_28, piVar1, (ulong **)(param_1 + 0x10));
        }
        else
        {
          *piVar1 = *piVar1 + local_28;
        }
        iVar5 = iVar5 + 1;
      } while (iVar5 != *(int *)(param_1 + 0x50));
    }
  }
  FUN_180034d00(local_18 ^ (ulonglong)&stack0xffffffffffffffa8);
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void write_stored_string_tchar(longlong param_1)
{
  wchar_t _WCh;
  errno_t eVar1;
  wchar_t *pwVar2;
  int iVar3;
  int local_28;
  char local_24[12];
  ulonglong local_18;

  local_18 = DAT_1800ee160 ^ (ulonglong)&stack0xffffffffffffffa8;
  if ((*(char *)(param_1 + 0x54) == '\0') || (*(int *)(param_1 + 0x50) < 1))
  {
    __crt_stdio_output::string_output_adapter<char>::write_string((string_output_adapter_char_ *)(param_1 + 0x468), *(char **)(param_1 + 0x48),
                                                                  *(int *)(param_1 + 0x50), (int *)(param_1 + 0x28),
                                                                  (__crt_deferred_errno_cache *)(param_1 + 0x10));
  }
  else
  {
    pwVar2 = *(wchar_t **)(param_1 + 0x48);
    iVar3 = 0;
    if (*(int *)(param_1 + 0x50) != 0)
    {
      do
      {
        _WCh = *pwVar2;
        local_28 = 0;
        pwVar2 = pwVar2 + 1;
        eVar1 = wctomb_s(&local_28, local_24, 6, _WCh);
        if ((eVar1 != 0) || (local_28 == 0))
        {
          *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
          break;
        }
        __crt_stdio_output::string_output_adapter<char>::write_string((string_output_adapter_char_ *)(param_1 + 0x468), local_24, local_28,
                                                                      (int *)(param_1 + 0x28), (__crt_deferred_errno_cache *)(param_1 + 0x10));
        iVar3 = iVar3 + 1;
      } while (iVar3 != *(int *)(param_1 + 0x50));
    }
  }
  FUN_180034d00(local_18 ^ (ulonglong)&stack0xffffffffffffffa8);
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void write_stored_string_tchar(longlong param_1)
{
  wchar_t _WCh;
  errno_t eVar1;
  wchar_t *pwVar2;
  int iVar3;
  int local_28;
  char local_24[12];
  ulonglong local_18;

  local_18 = DAT_1800ee160 ^ (ulonglong)&stack0xffffffffffffffa8;
  if ((*(char *)(param_1 + 0x54) == '\0') || (*(int *)(param_1 + 0x50) < 1))
  {
    __crt_stdio_output::string_output_adapter<char>::write_string((string_output_adapter_char_ *)(param_1 + 0x468), *(char **)(param_1 + 0x48),
                                                                  *(int *)(param_1 + 0x50), (int *)(param_1 + 0x28),
                                                                  (__crt_deferred_errno_cache *)(param_1 + 0x10));
  }
  else
  {
    pwVar2 = *(wchar_t **)(param_1 + 0x48);
    iVar3 = 0;
    if (*(int *)(param_1 + 0x50) != 0)
    {
      do
      {
        _WCh = *pwVar2;
        local_28 = 0;
        pwVar2 = pwVar2 + 1;
        eVar1 = wctomb_s(&local_28, local_24, 6, _WCh);
        if ((eVar1 != 0) || (local_28 == 0))
        {
          *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
          break;
        }
        __crt_stdio_output::string_output_adapter<char>::write_string((string_output_adapter_char_ *)(param_1 + 0x468), local_24, local_28,
                                                                      (int *)(param_1 + 0x28), (__crt_deferred_errno_cache *)(param_1 + 0x10));
        iVar3 = iVar3 + 1;
      } while (iVar3 != *(int *)(param_1 + 0x50));
    }
  }
  FUN_180034d00(local_18 ^ (ulonglong)&stack0xffffffffffffffa8);
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::format_validation_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::positional_parameter_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<char,class
// __crt_stdio_output::string_output_adapter<char>,class
// __crt_stdio_output::standard_base<char,class
// __crt_stdio_output::string_output_adapter<char>>>::write_stored_string_tchar(char) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void write_stored_string_tchar(longlong param_1)
{
  wchar_t _WCh;
  errno_t eVar1;
  wchar_t *pwVar2;
  int iVar3;
  int local_28;
  char local_24[12];
  ulonglong local_18;

  local_18 = DAT_1800ee160 ^ (ulonglong)&stack0xffffffffffffffa8;
  if ((*(char *)(param_1 + 0x54) == '\0') || (*(int *)(param_1 + 0x50) < 1))
  {
    __crt_stdio_output::string_output_adapter<char>::write_string((string_output_adapter_char_ *)(param_1 + 0x468), *(char **)(param_1 + 0x48),
                                                                  *(int *)(param_1 + 0x50), (int *)(param_1 + 0x28),
                                                                  (__crt_deferred_errno_cache *)(param_1 + 0x10));
  }
  else
  {
    pwVar2 = *(wchar_t **)(param_1 + 0x48);
    iVar3 = 0;
    if (*(int *)(param_1 + 0x50) != 0)
    {
      do
      {
        _WCh = *pwVar2;
        local_28 = 0;
        pwVar2 = pwVar2 + 1;
        eVar1 = wctomb_s(&local_28, local_24, 6, _WCh);
        if ((eVar1 != 0) || (local_28 == 0))
        {
          *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
          break;
        }
        __crt_stdio_output::string_output_adapter<char>::write_string((string_output_adapter_char_ *)(param_1 + 0x468), local_24, local_28,
                                                                      (int *)(param_1 + 0x28), (__crt_deferred_errno_cache *)(param_1 + 0x10));
        iVar3 = iVar3 + 1;
      } while (iVar3 != *(int *)(param_1 + 0x50));
    }
  }
  FUN_180034d00(local_18 ^ (ulonglong)&stack0xffffffffffffffa8);
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::write_stored_string_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::write_stored_string_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::write_stored_string_tchar(wchar_t) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 write_stored_string_tchar(longlong param_1)
{
  int *piVar1;
  FILE **ppFVar2;
  short sVar3;
  int iVar4;
  undefined4 extraout_var;
  FILE *pFVar5;
  byte *pbVar6;
  int iVar7;
  ushort local_res8[4];

  iVar7 = 0;
  if ((*(char *)(param_1 + 0x54) == '\0') && (0 < *(int *)(param_1 + 0x50)))
  {
    pbVar6 = *(byte **)(param_1 + 0x48);
    do
    {
      local_res8[0] = 0;
      iVar4 = FUN_180069a64(local_res8, pbVar6, (longlong) * (int *)(**(longlong **)(param_1 + 8) + 8),
                            (undefined4 *)*(longlong **)(param_1 + 8));
      pFVar5 = (FILE *)(longlong)iVar4;
      if (iVar4 < 1)
      {
        *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
        pFVar5 = (FILE *)CONCAT44(extraout_var, iVar4);
        break;
      }
      if ((((*(uint *)(*(longlong *)(param_1 + 0x468) + 0x14) >> 0xc & 1) == 0) ||
           (*(longlong *)(*(longlong *)(param_1 + 0x468) + 8) != 0)) &&
          (sVar3 = FUN_18006b814(local_res8[0], *(FILE **)(param_1 + 0x468)), sVar3 == -1))
      {
        *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
      }
      else
      {
        *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
      }
      pbVar6 = pbVar6 + (longlong)pFVar5;
      iVar7 = iVar7 + 1;
    } while (iVar7 != *(int *)(param_1 + 0x50));
  }
  else
  {
    ppFVar2 = (FILE **)(param_1 + 0x468);
    piVar1 = (int *)(param_1 + 0x28);
    if (((*(uint *)((longlong) & (*ppFVar2)->_base + 4) >> 0xc & 1) == 0) ||
        (pFVar5 = *ppFVar2, *(longlong *)&pFVar5->_cnt != 0))
    {
      pFVar5 = (FILE *)FUN_18005f98c(ppFVar2, *(WCHAR **)(param_1 + 0x48), *(int *)(param_1 + 0x50),
                                     piVar1, (ulong **)(param_1 + 0x10));
    }
    else
    {
      *piVar1 = *piVar1 + *(int *)(param_1 + 0x50);
    }
  }
  return CONCAT71((int7)((ulonglong)pFVar5 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::write_stored_string_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::write_stored_string_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::write_stored_string_tchar(wchar_t) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 write_stored_string_tchar(longlong param_1)
{
  int *piVar1;
  FILE **ppFVar2;
  short sVar3;
  int iVar4;
  undefined4 extraout_var;
  FILE *pFVar5;
  byte *pbVar6;
  int iVar7;
  ushort local_res8[4];

  iVar7 = 0;
  if ((*(char *)(param_1 + 0x54) == '\0') && (0 < *(int *)(param_1 + 0x50)))
  {
    pbVar6 = *(byte **)(param_1 + 0x48);
    do
    {
      local_res8[0] = 0;
      iVar4 = FUN_180069a64(local_res8, pbVar6, (longlong) * (int *)(**(longlong **)(param_1 + 8) + 8),
                            (undefined4 *)*(longlong **)(param_1 + 8));
      pFVar5 = (FILE *)(longlong)iVar4;
      if (iVar4 < 1)
      {
        *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
        pFVar5 = (FILE *)CONCAT44(extraout_var, iVar4);
        break;
      }
      if ((((*(uint *)(*(longlong *)(param_1 + 0x468) + 0x14) >> 0xc & 1) == 0) ||
           (*(longlong *)(*(longlong *)(param_1 + 0x468) + 8) != 0)) &&
          (sVar3 = FUN_18006b814(local_res8[0], *(FILE **)(param_1 + 0x468)), sVar3 == -1))
      {
        *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
      }
      else
      {
        *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
      }
      pbVar6 = pbVar6 + (longlong)pFVar5;
      iVar7 = iVar7 + 1;
    } while (iVar7 != *(int *)(param_1 + 0x50));
  }
  else
  {
    ppFVar2 = (FILE **)(param_1 + 0x468);
    piVar1 = (int *)(param_1 + 0x28);
    if (((*(uint *)((longlong) & (*ppFVar2)->_base + 4) >> 0xc & 1) == 0) ||
        (pFVar5 = *ppFVar2, *(longlong *)&pFVar5->_cnt != 0))
    {
      pFVar5 = (FILE *)FUN_18005f98c(ppFVar2, *(WCHAR **)(param_1 + 0x48), *(int *)(param_1 + 0x50),
                                     piVar1, (ulong **)(param_1 + 0x10));
    }
    else
    {
      *piVar1 = *piVar1 + *(int *)(param_1 + 0x50);
    }
  }
  return CONCAT71((int7)((ulonglong)pFVar5 >> 8), 1);
}

// Library Function - Multiple Matches With Same Base Name
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::format_validation_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::write_stored_string_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::positional_parameter_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::write_stored_string_tchar(wchar_t) __ptr64
//  private: bool __cdecl __crt_stdio_output::output_processor<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>,class
// __crt_stdio_output::standard_base<wchar_t,class
// __crt_stdio_output::stream_output_adapter<wchar_t>>>::write_stored_string_tchar(wchar_t) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 write_stored_string_tchar(longlong param_1)
{
  int *piVar1;
  FILE **ppFVar2;
  short sVar3;
  int iVar4;
  undefined4 extraout_var;
  FILE *pFVar5;
  byte *pbVar6;
  int iVar7;
  ushort local_res8[4];

  iVar7 = 0;
  if ((*(char *)(param_1 + 0x54) == '\0') && (0 < *(int *)(param_1 + 0x50)))
  {
    pbVar6 = *(byte **)(param_1 + 0x48);
    do
    {
      local_res8[0] = 0;
      iVar4 = FUN_180069a64(local_res8, pbVar6, (longlong) * (int *)(**(longlong **)(param_1 + 8) + 8),
                            (undefined4 *)*(longlong **)(param_1 + 8));
      pFVar5 = (FILE *)(longlong)iVar4;
      if (iVar4 < 1)
      {
        *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
        pFVar5 = (FILE *)CONCAT44(extraout_var, iVar4);
        break;
      }
      if ((((*(uint *)(*(longlong *)(param_1 + 0x468) + 0x14) >> 0xc & 1) == 0) ||
           (*(longlong *)(*(longlong *)(param_1 + 0x468) + 8) != 0)) &&
          (sVar3 = FUN_18006b814(local_res8[0], *(FILE **)(param_1 + 0x468)), sVar3 == -1))
      {
        *(undefined4 *)(param_1 + 0x28) = 0xffffffff;
      }
      else
      {
        *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
      }
      pbVar6 = pbVar6 + (longlong)pFVar5;
      iVar7 = iVar7 + 1;
    } while (iVar7 != *(int *)(param_1 + 0x50));
  }
  else
  {
    ppFVar2 = (FILE **)(param_1 + 0x468);
    piVar1 = (int *)(param_1 + 0x28);
    if (((*(uint *)((longlong) & (*ppFVar2)->_base + 4) >> 0xc & 1) == 0) ||
        (pFVar5 = *ppFVar2, *(longlong *)&pFVar5->_cnt != 0))
    {
      pFVar5 = (FILE *)FUN_18005f98c(ppFVar2, *(WCHAR **)(param_1 + 0x48), *(int *)(param_1 + 0x50),
                                     piVar1, (ulong **)(param_1 + 0x10));
    }
    else
    {
      *piVar1 = *piVar1 + *(int *)(param_1 + 0x50);
    }
  }
  return CONCAT71((int7)((ulonglong)pFVar5 >> 8), 1);
}

// Library Function - Single Match
//  public: void __cdecl __crt_stdio_output::string_output_adapter<char>::write_string(char const *
// __ptr64 const,int,int * __ptr64 const,class __crt_deferred_errno_cache & __ptr64)const __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __thiscall __crt_stdio_output::string_output_adapter<char>::write_string(string_output_adapter_char_ *this, char *param_1, int param_2, int *param_3,
                                                                              __crt_deferred_errno_cache *param_4)
{
  undefined8 *puVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  ulonglong uVar4;

  if (param_2 != 0)
  {
    uVar4 = SEXT48(param_2);
    puVar1 = *(undefined8 **)this;
    if (puVar1[2] == puVar1[1])
    {
      if (*(char *)(puVar1 + 3) == '\0')
      {
        *param_3 = -1;
      }
      else
      {
        *param_3 = *param_3 + param_2;
      }
    }
    else
    {
      uVar2 = puVar1[1] - puVar1[2];
      uVar3 = uVar4;
      if (uVar2 < uVar4)
      {
        uVar3 = uVar2;
      }
      FUN_18003b8e0((undefined8 *)*puVar1, (undefined8 *)param_1, uVar3);
      **(longlong **)this = **(longlong **)this + uVar3;
      *(longlong *)(*(longlong *)this + 0x10) = *(longlong *)(*(longlong *)this + 0x10) + uVar3;
      if (*(char *)(*(longlong *)this + 0x18) == '\0')
      {
        if (uVar3 == uVar4)
        {
          *param_3 = *param_3 + (int)uVar3;
        }
        else
        {
          *param_3 = -1;
        }
      }
      else
      {
        *param_3 = *param_3 + param_2;
      }
    }
  }
  return;
}

// Library Function - Single Match
//  public: void __cdecl __crt_stdio_output::string_output_adapter<wchar_t>::write_string(wchar_t
// const * __ptr64 const,int,int * __ptr64 const,class __crt_deferred_errno_cache & __ptr64)const
// __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __thiscall __crt_stdio_output::string_output_adapter<wchar_t>::write_string(string_output_adapter_wchar_t_ *this, wchar_t *param_1, int param_2, int *param_3,
                                                                                 __crt_deferred_errno_cache *param_4)
{
  undefined8 *puVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  ulonglong uVar4;

  if (param_2 != 0)
  {
    uVar3 = SEXT48(param_2);
    puVar1 = *(undefined8 **)this;
    if (puVar1[2] == puVar1[1])
    {
      if (*(char *)(puVar1 + 3) == '\0')
      {
        *param_3 = -1;
      }
      else
      {
        *param_3 = *param_3 + param_2;
      }
    }
    else
    {
      uVar2 = puVar1[1] - puVar1[2];
      uVar4 = uVar3;
      if (uVar2 < uVar3)
      {
        uVar4 = uVar2;
      }
      FUN_18003b8e0((undefined8 *)*puVar1, (undefined8 *)param_1, uVar4 * 2);
      **(longlong **)this = **(longlong **)this + uVar4 * 2;
      *(longlong *)(*(longlong *)this + 0x10) = *(longlong *)(*(longlong *)this + 0x10) + uVar4;
      if (*(char *)(*(longlong *)this + 0x18) == '\0')
      {
        if (uVar4 == uVar3)
        {
          *param_3 = *param_3 + (int)uVar4;
        }
        else
        {
          *param_3 = -1;
        }
      }
      else
      {
        *param_3 = *param_3 + param_2;
      }
    }
  }
  return;
}

// Library Function - Single Match
//  __stdio_common_vfwprintf
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4
__stdio_common_vfwprintf(undefined8 param_1, longlong param_2, longlong param_3, undefined8 param_4,
                         undefined8 param_5)
{
  undefined4 uVar1;
  ulong *puVar2;
  longlong local_res8;
  undefined8 local_res10;
  undefined8 local_res18;
  longlong local_res20;
  undefined8 local_48;
  longlong local_40;
  longlong local_38;
  FILE *local_30;
  undefined8 *local_28;
  undefined8 *local_20;
  longlong *local_18;
  undefined8 *local_10;

  local_48 = param_5;
  local_res8 = param_2;
  local_res10 = param_4;
  local_res18 = param_1;
  local_res20 = param_3;
  if ((param_2 == 0) || (param_3 == 0))
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
    uVar1 = 0xffffffff;
  }
  else
  {
    local_30 = (FILE *)&local_res8;
    local_28 = &local_res10;
    local_20 = &local_res18;
    local_18 = &local_res20;
    local_10 = &local_48;
    local_40 = param_2;
    local_38 = param_2;
    uVar1 = operator____(&param_5, &local_38, &local_30, &local_40);
  }
  return uVar1;
}

// Library Function - Single Match
//  __stdio_common_vsnprintf_s
//
// Library: Visual Studio 2019 Release

int __stdio_common_vsnprintf_s(__uint64 param_1, char *param_2, ulonglong param_3, ulonglong param_4, char *param_5,
                               __crt_locale_pointers *param_6, char *param_7)
{
  ulong uVar1;
  int iVar2;
  ulong *puVar3;

  if (param_5 == (char *)0x0)
  {
  LAB_18005ff16:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    FUN_18006738c();
    return -1;
  }
  if (param_4 == 0)
  {
    if (param_2 == (char *)0x0)
    {
      if (param_3 == 0)
      {
        return 0;
      }
      goto LAB_18005ff16;
    }
  }
  else
  {
    if (param_2 == (char *)0x0)
      goto LAB_18005ff16;
  }
  if (param_3 == 0)
    goto LAB_18005ff16;
  puVar3 = __doserrno();
  if (param_4 < param_3)
  {
    uVar1 = *puVar3;
    iVar2 = common_vsprintf_class___crt_stdio_output__format_validation_base_char_(param_1, param_2, param_4 + 1, param_5, param_6, param_7);
    if (iVar2 == -2)
    {
      puVar3 = __doserrno();
      if (*puVar3 != 0x22)
      {
        return -1;
      }
      puVar3 = __doserrno();
      *puVar3 = uVar1;
      return -1;
    }
  }
  else
  {
    uVar1 = *puVar3;
    iVar2 = common_vsprintf_class___crt_stdio_output__format_validation_base_char_(param_1, param_2, param_3, param_5, param_6, param_7);
    param_2[param_3 - 1] = '\0';
    if (iVar2 == -2)
    {
      if (param_4 == 0xffffffffffffffff)
      {
        puVar3 = __doserrno();
        if (*puVar3 == 0x22)
        {
          puVar3 = __doserrno();
          *puVar3 = uVar1;
          return -1;
        }
        return -1;
      }
      goto LAB_18005fef8;
    }
  }
  if (-1 < iVar2)
  {
    return iVar2;
  }
LAB_18005fef8:
  *param_2 = '\0';
  if (iVar2 == -2)
  {
    puVar3 = __doserrno();
    *puVar3 = 0x22;
    FUN_18006738c();
    return -1;
  }
  return -1;
}

// Library Function - Single Match
//  __stdio_common_vsnwprintf_s
//
// Library: Visual Studio 2019 Release

int __stdio_common_vsnwprintf_s(__uint64 param_1, undefined2 *param_2, ulonglong param_3, ulonglong param_4,
                                wchar_t *param_5, __crt_locale_pointers *param_6, char *param_7)
{
  ulong uVar1;
  int iVar2;
  ulong *puVar3;

  if (param_5 == (wchar_t *)0x0)
  {
  LAB_18006006c:
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    FUN_18006738c();
    return -1;
  }
  if (param_4 == 0)
  {
    if (param_2 == (undefined2 *)0x0)
    {
      if (param_3 == 0)
      {
        return 0;
      }
      goto LAB_18006006c;
    }
  }
  else
  {
    if (param_2 == (undefined2 *)0x0)
      goto LAB_18006006c;
  }
  if (param_3 == 0)
    goto LAB_18006006c;
  puVar3 = __doserrno();
  if (param_4 < param_3)
  {
    uVar1 = *puVar3;
    iVar2 = common_vsprintf_class___crt_stdio_output__format_validation_base_wchar_t_(param_1, (wchar_t *)param_2, param_4 + 1, param_5, param_6, param_7);
    if (iVar2 == -2)
    {
      puVar3 = __doserrno();
      if (*puVar3 != 0x22)
      {
        return -1;
      }
      puVar3 = __doserrno();
      *puVar3 = uVar1;
      return -1;
    }
  }
  else
  {
    uVar1 = *puVar3;
    iVar2 = common_vsprintf_class___crt_stdio_output__format_validation_base_wchar_t_(param_1, (wchar_t *)param_2, param_3, param_5, param_6, param_7);
    param_2[param_3 - 1] = 0;
    if (iVar2 == -2)
    {
      if (param_4 == 0xffffffffffffffff)
      {
        puVar3 = __doserrno();
        if (*puVar3 == 0x22)
        {
          puVar3 = __doserrno();
          *puVar3 = uVar1;
          return -1;
        }
        return -1;
      }
      goto LAB_18006004d;
    }
  }
  if (-1 < iVar2)
  {
    return iVar2;
  }
LAB_18006004d:
  *param_2 = 0;
  if (iVar2 == -2)
  {
    puVar3 = __doserrno();
    *puVar3 = 0x22;
    FUN_18006738c();
    return -1;
  }
  return -1;
}

void common_vsprintf__(ulonglong param_1, undefined *param_2, longlong param_3, longlong param_4,
                       undefined4 *param_5, undefined8 param_6)
{
  int iVar1;
  ulong *puVar2;
  undefined auStack1320[32];
  undefined *puStack1288;
  longlong lStack1280;
  longlong lStack1272;
  undefined uStack1264;
  __acrt_ptd *p_Stack1256;
  undefined auStack1248[16];
  char cStack1232;
  ulonglong uStack1224;
  undefined *puStack1216;
  undefined8 uStack1208;
  longlong lStack1200;
  undefined8 uStack1192;
  undefined8 uStack1184;
  undefined8 uStack1176;
  undefined4 uStack1168;
  undefined2 uStack1160;
  undefined4 uStack1144;
  undefined uStack1140;
  undefined8 uStack112;
  LPVOID pvStack104;
  undefined **ppuStack96;
  undefined4 uStack88;
  ulonglong uStack72;

  uStack72 = DAT_1800ee160 ^ (ulonglong)auStack1320;
  if ((param_4 == 0) || ((param_3 != 0 && (param_2 == (undefined *)0x0))))
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
    goto LAB_180049572;
  }
  FUN_18004e538(&p_Stack1256, param_5);
  FUN_18003bd40((undefined(*)[16]) & puStack1288, 0, 0x20);
  lStack1272 = 0;
  if (((param_1 & 2) != 0) || (uStack1264 = 0, param_2 == (undefined *)0x0))
  {
    uStack1264 = 1;
  }
  ppuStack96 = &puStack1288;
  uStack1208 = 0;
  puStack1216 = auStack1248;
  uStack1184 = 0;
  uStack1192 = param_6;
  uStack1176 = 0;
  uStack1168 = 0;
  uStack1160 = 0;
  uStack1144 = 0;
  uStack1140 = 0;
  uStack112 = 0;
  pvStack104 = (LPVOID)0x0;
  uStack88 = 0;
  puStack1288 = param_2;
  lStack1280 = param_3;
  uStack1224 = param_1;
  lStack1200 = param_4;
  iVar1 = FUN_180051580(&uStack1224);
  if (param_2 != (undefined *)0x0)
  {
    if ((param_1 & 1) == 0)
    {
      if ((param_1 & 2) == 0)
      {
        if (param_3 != 0)
        {
          if (lStack1272 != param_3)
            goto LAB_180049546;
        LAB_1800495ac:
          param_2[param_3 + -1] = 0;
        }
      }
      else
      {
        if (param_3 != 0)
        {
          if (-1 < iVar1)
          {
            if (lStack1272 == param_3)
              goto LAB_1800495ac;
            goto LAB_180049546;
          }
          *param_2 = 0;
        }
      }
    }
    else
    {
      if (((param_3 != 0) || (iVar1 == 0)) && (lStack1272 != param_3))
      {
      LAB_180049546:
        param_2[lStack1272] = 0;
      }
    }
  }
  _free_base(pvStack104);
  pvStack104 = (LPVOID)0x0;
  if (cStack1232 != '\0')
  {
    *(uint *)(p_Stack1256 + 0x3a8) = *(uint *)(p_Stack1256 + 0x3a8) & 0xfffffffd;
  }
LAB_180049572:
  FUN_180034d00(uStack72 ^ (ulonglong)auStack1320);
  return;
}

// Library Function - Single Match
//  __stdio_common_vsprintf_s
//
// Library: Visual Studio 2017 Release

int __stdio_common_vsprintf_s(__uint64 param_1, char *param_2, __uint64 param_3, char *param_4,
                              __crt_locale_pointers *param_5, char *param_6)
{
  int iVar1;
  ulong *puVar2;

  if (((param_4 == (char *)0x0) || (param_2 == (char *)0x0)) || (param_3 == 0))
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
  }
  else
  {
    iVar1 = common_vsprintf_class___crt_stdio_output__format_validation_base_char_(param_1, param_2, param_3, param_4, param_5, param_6);
    if (iVar1 < 0)
    {
      *param_2 = '\0';
    }
    if (iVar1 != -2)
    {
      return iVar1;
    }
    puVar2 = __doserrno();
    *puVar2 = 0x22;
  }
  FUN_18006738c();
  return -1;
}

void common_vsprintf__(ulonglong param_1, undefined2 *param_2, longlong param_3, longlong param_4,
                       undefined4 *param_5, undefined8 param_6)
{
  int iVar1;
  ulong *puVar2;
  undefined auStack1320[32];
  undefined2 *puStack1288;
  longlong lStack1280;
  longlong lStack1272;
  undefined uStack1264;
  __acrt_ptd *p_Stack1256;
  undefined auStack1248[16];
  char cStack1232;
  ulonglong uStack1224;
  undefined *puStack1216;
  undefined8 uStack1208;
  longlong lStack1200;
  undefined8 uStack1192;
  undefined8 uStack1184;
  undefined8 uStack1176;
  undefined4 uStack1168;
  undefined uStack1160;
  undefined2 uStack1158;
  undefined4 uStack1144;
  undefined uStack1140;
  undefined8 uStack112;
  LPVOID pvStack104;
  undefined2 **ppuStack96;
  undefined4 uStack88;
  ulonglong uStack72;

  uStack72 = DAT_1800ee160 ^ (ulonglong)auStack1320;
  if ((param_4 == 0) || ((param_3 != 0 && (param_2 == (undefined2 *)0x0))))
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
    goto LAB_180049744;
  }
  FUN_18004e538(&p_Stack1256, param_5);
  FUN_18003bd40((undefined(*)[16]) & puStack1288, 0, 0x20);
  lStack1272 = 0;
  if (((param_1 & 2) != 0) || (uStack1264 = 0, param_2 == (undefined2 *)0x0))
  {
    uStack1264 = 1;
  }
  ppuStack96 = &puStack1288;
  uStack1208 = 0;
  puStack1216 = auStack1248;
  uStack1184 = 0;
  uStack1192 = param_6;
  uStack1176 = 0;
  uStack1168 = 0;
  uStack1160 = 0;
  uStack1158 = 0;
  uStack1144 = 0;
  uStack1140 = 0;
  uStack112 = 0;
  pvStack104 = (LPVOID)0x0;
  uStack88 = 0;
  puStack1288 = param_2;
  lStack1280 = param_3;
  uStack1224 = param_1;
  lStack1200 = param_4;
  iVar1 = FUN_180052454(&uStack1224);
  if (param_2 != (undefined2 *)0x0)
  {
    if ((param_1 & 1) == 0)
    {
      if ((param_1 & 2) == 0)
      {
        if (param_3 != 0)
        {
          if (lStack1272 != param_3)
            goto LAB_180049717;
        LAB_18004977e:
          param_2[param_3 + -1] = 0;
        }
      }
      else
      {
        if (param_3 != 0)
        {
          if (-1 < iVar1)
          {
            if (lStack1272 == param_3)
              goto LAB_18004977e;
            goto LAB_180049717;
          }
          *param_2 = 0;
        }
      }
    }
    else
    {
      if (((param_3 != 0) || (iVar1 == 0)) && (lStack1272 != param_3))
      {
      LAB_180049717:
        param_2[lStack1272] = 0;
      }
    }
  }
  _free_base(pvStack104);
  pvStack104 = (LPVOID)0x0;
  if (cStack1232 != '\0')
  {
    *(uint *)(p_Stack1256 + 0x3a8) = *(uint *)(p_Stack1256 + 0x3a8) & 0xfffffffd;
  }
LAB_180049744:
  FUN_180034d00(uStack72 ^ (ulonglong)auStack1320);
  return;
}

// Library Function - Single Match
//  __stdio_common_vswprintf_s
//
// Library: Visual Studio 2017 Release

int __stdio_common_vswprintf_s(__uint64 param_1, undefined2 *param_2, __uint64 param_3, wchar_t *param_4,
                               __crt_locale_pointers *param_5, char *param_6)
{
  int iVar1;
  ulong *puVar2;

  if (((param_4 == (wchar_t *)0x0) || (param_2 == (undefined2 *)0x0)) || (param_3 == 0))
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
  }
  else
  {
    iVar1 = common_vsprintf_class___crt_stdio_output__format_validation_base_wchar_t_(param_1, (wchar_t *)param_2, param_3, param_4, param_5, param_6);
    if (iVar1 < 0)
    {
      *param_2 = 0;
    }
    if (iVar1 != -2)
    {
      return iVar1;
    }
    puVar2 = __doserrno();
    *puVar2 = 0x22;
  }
  FUN_18006738c();
  return -1;
}

// Library Function - Single Match
//  fread_s
//
// Libraries: Visual Studio 2012 Release, Visual Studio 2015 Release

size_t fread_s(void *_DstBuf, size_t _DstSize, size_t _ElementSize, size_t _Count, FILE *_File)
{
  ulong *puVar1;
  ulonglong uVar2;

  if ((_ElementSize != 0) && (_Count != 0))
  {
    if (_File != (FILE *)0x0)
    {
      FUN_1800625f0((longlong)_File);
      uVar2 = FUN_180060200((undefined(*)[16])_DstBuf, _DstSize, _ElementSize, _Count, _File);
      FUN_1800625fc((longlong)_File);
      return uVar2;
    }
    if (_DstSize != 0xffffffffffffffff)
    {
      FUN_18003bd40((undefined(*)[16])_DstBuf, 0, _DstSize);
    }
    puVar1 = __doserrno();
    *puVar1 = 0x16;
    FUN_18006738c();
  }
  return 0;
}

// Library Function - Single Match
//  _fclose_nolock
//
// Library: Visual Studio 2017 Release

int _fclose_nolock(FILE *_File)
{
  int iVar1;
  int iVar2;
  ulong *puVar3;
  undefined8 uVar4;

  if (_File == (FILE *)0x0)
  {
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    FUN_18006738c();
    iVar1 = -1;
  }
  else
  {
    iVar1 = -1;
    if ((*(uint *)((longlong)&_File->_base + 4) >> 0xd & 1) != 0)
    {
      uVar4 = __acrt_stdio_flush_nolock(_File);
      iVar1 = (int)uVar4;
      __acrt_stdio_free_buffer_nolock((undefined8 *)_File);
      iVar2 = _fileno(_File);
      iVar2 = _close(iVar2);
      if (iVar2 < 0)
      {
        iVar1 = -1;
      }
      else
      {
        if (_File->_tmpfname != (char *)0x0)
        {
          _free_base(_File->_tmpfname);
          _File->_tmpfname = (char *)0x0;
        }
      }
    }
    __acrt_stdio_free_stream(SUB81(_File, 0));
  }
  return iVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  public: unsigned __int64 __cdecl __crt_seh_guarded_call<unsigned __int64>::operator()<class
// <lambda_2831f20263db5b546e098b45503eb778>,class <lambda_5856287d7ecd2be6c9197bb4007c3f6e>&
// __ptr64,class <lambda_0838d7e100fbcbd261b69cfea6abb102>>(class
// <lambda_2831f20263db5b546e098b45503eb778>&& __ptr64,class
// <lambda_5856287d7ecd2be6c9197bb4007c3f6e>& __ptr64,class
// <lambda_0838d7e100fbcbd261b69cfea6abb102>&& __ptr64) __ptr64
//  public: unsigned __int64 __cdecl __crt_seh_guarded_call<unsigned __int64>::operator()<class
// <lambda_5d4c3fee44080f75d5d9762853974fe0>,class <lambda_532e024f4337e6fc7ad266c2bef9f4ed>&
// __ptr64,class <lambda_c87bdc10097eb2402edb8ba9bdf0697b>>(class
// <lambda_5d4c3fee44080f75d5d9762853974fe0>&& __ptr64,class
// <lambda_532e024f4337e6fc7ad266c2bef9f4ed>& __ptr64,class
// <lambda_c87bdc10097eb2402edb8ba9bdf0697b>&& __ptr64) __ptr64
//  public: unsigned __int64 __cdecl __crt_seh_guarded_call<unsigned __int64>::operator()<class
// <lambda_bdbcead8b570fa3d5ec6d9679862a6e5>,class <lambda_96f4279ff90247a4c5c5d9824f56f8c1>&
// __ptr64,class <lambda_4606be27f17b5e5579e09050fab91818>>(class
// <lambda_bdbcead8b570fa3d5ec6d9679862a6e5>&& __ptr64,class
// <lambda_96f4279ff90247a4c5c5d9824f56f8c1>& __ptr64,class
// <lambda_4606be27f17b5e5579e09050fab91818>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong operator____(undefined8 param_1, longlong *param_2, FILE **param_3, longlong *param_4)
{
  ulonglong uVar1;

  FUN_1800625f0(*param_2);
  uVar1 = FID_conflict_operator__(param_3);
  FUN_1800625fc(*param_4);
  return uVar1;
}

// Library Function - Multiple Matches With Different Base Names
//  public: unsigned __int64 __cdecl
// <lambda_532e024f4337e6fc7ad266c2bef9f4ed>::operator()(void)const __ptr64
//  public: unsigned __int64 __cdecl
// <lambda_96f4279ff90247a4c5c5d9824f56f8c1>::operator()(void)const __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

ulonglong FID_conflict_operator__(FILE **param_1)
{
  FILE *pFVar1;
  ulonglong uVar2;
  ulonglong uVar3;

  pFVar1 = (FILE *)(*param_1)->_ptr;
  uVar2 = __acrt_stdio_begin_temporary_buffering_nolock(pFVar1);
  uVar3 = FUN_1800607f4((undefined8 *)param_1[1]->_ptr, (ulonglong)param_1[2]->_ptr,
                        (ulonglong)param_1[3]->_ptr, (FILE *)(*param_1)->_ptr);
  __acrt_stdio_end_temporary_buffering_nolock((char)uVar2, pFVar1);
  return uVar3;
}

// Library Function - Single Match
//  fwrite
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

size_t fwrite(void *_Str, size_t _Size, size_t _Count, FILE *_File)
{
  ulong *puVar1;
  ulonglong uVar2;
  void *local_res8;
  size_t local_res10;
  size_t local_res18;
  FILE *local_res20;
  undefined local_48[8];
  FILE *local_40;
  FILE *local_38;
  FILE *local_30;
  void **local_28;
  size_t *local_20;
  size_t *local_18;

  if ((_Size != 0) && (_Count != 0))
  {
    local_res8 = _Str;
    local_res10 = _Size;
    local_res18 = _Count;
    local_res20 = _File;
    if (_File != (FILE *)0x0)
    {
      local_30 = (FILE *)&local_res20;
      local_28 = &local_res8;
      local_20 = &local_res10;
      local_18 = &local_res18;
      local_40 = _File;
      local_38 = _File;
      uVar2 = operator____(local_48, (longlong *)&local_38, &local_30, (longlong *)&local_40);
      return uVar2;
    }
    puVar1 = __doserrno();
    *puVar1 = 0x16;
    FUN_18006738c();
  }
  return 0;
}

LPVOID _calloc_base(ulonglong param_1, ulonglong param_2)
{
  int iVar1;
  LPVOID pvVar2;
  ulong *puVar3;
  size_t dwBytes;

  if ((param_1 == 0) || (param_2 <= 0xffffffffffffffe0 / param_1))
  {
    dwBytes = param_1 * param_2;
    if (dwBytes == 0)
    {
      dwBytes = 1;
    }
    do
    {
      pvVar2 = HeapAlloc(DAT_180102658, 8, dwBytes);
      if (pvVar2 != (LPVOID)0x0)
      {
        return pvVar2;
      }
      iVar1 = FUN_180079e3c();
    } while ((iVar1 != 0) && (iVar1 = _callnewh(dwBytes), iVar1 != 0));
  }
  puVar3 = __doserrno();
  *puVar3 = 0xc;
  return (LPVOID)0x0;
}

// Library Function - Single Match
//  int __cdecl common_localtime_s<long>(struct tm * __ptr64 const,long const * __ptr64 const)
//
// Library: Visual Studio 2015 Release

int common_localtime_s_long_(tm *param_1, long *param_2)
{
  code *pcVar1;
  errno_t eVar2;
  int iVar3;
  int iVar4;
  ulong *puVar5;
  undefined8 uVar6;
  int local_res8[4];
  int local_res18[2];
  int local_res20[2];
  int local_28[4];

  if ((param_1 == (tm *)0x0) ||
      (FUN_18003bd40((undefined(*)[16])param_1, 0xff, 0x24), param_2 == (long *)0x0))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    FUN_18006738c();
    return 0x16;
  }
  if ((*param_2 < 0) || (0x7fffd27f < *param_2))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    return 0x16;
  }
  __tzset();
  local_res20[0] = 0;
  local_28[0] = 0;
  local_res18[0] = 0;
  eVar2 = FID_conflict__get_daylight(local_res20);
  if (eVar2 != 0)
  {
    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
    pcVar1 = (code *)swi(3);
    iVar3 = (*pcVar1)();
    return iVar3;
  }
  eVar2 = FID_conflict__get_daylight(local_28);
  if (eVar2 != 0)
  {
    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
    pcVar1 = (code *)swi(3);
    iVar3 = (*pcVar1)();
    return iVar3;
  }
  eVar2 = FID_conflict__get_daylight(local_res18);
  if (eVar2 != 0)
  {
    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
    pcVar1 = (code *)swi(3);
    iVar3 = (*pcVar1)();
    return iVar3;
  }
  if (0x7ff7e97d < *param_2 - 0x3f481U)
  {
    uVar6 = thunk_FUN_1800705c8((undefined(*)[16])param_1, param_2);
    if ((int)uVar6 != 0)
    {
      return (int)uVar6;
    }
    iVar3 = param_1->tm_sec;
    if ((local_res20[0] != 0) && (iVar4 = _isindst(param_1), iVar4 != 0))
    {
      local_res18[0] = local_28[0] + local_res18[0];
      param_1->tm_isdst = 1;
    }
    iVar3 = iVar3 - local_res18[0];
    iVar4 = iVar3 % 0x3c;
    param_1->tm_sec = iVar4;
    if (iVar4 < 0)
    {
      iVar3 = iVar3 + -0x3c;
      param_1->tm_sec = iVar4 + 0x3c;
    }
    iVar4 = iVar3 / 0x3c + param_1->tm_min;
    iVar3 = iVar4 % 0x3c;
    param_1->tm_min = iVar3;
    if (iVar3 < 0)
    {
      iVar4 = iVar4 + -0x3c;
      param_1->tm_min = iVar3 + 0x3c;
    }
    iVar4 = iVar4 / 0x3c + param_1->tm_hour;
    iVar3 = iVar4 / 6 + (iVar4 >> 0x1f);
    iVar3 = iVar4 + ((iVar3 >> 2) - (iVar3 >> 0x1f)) * -0x18;
    param_1->tm_hour = iVar3;
    if (iVar3 < 0)
    {
      iVar4 = iVar4 + -0x18;
      param_1->tm_hour = iVar3 + 0x18;
    }
    iVar3 = iVar4 / 6 + (iVar4 >> 0x1f);
    iVar3 = (iVar3 >> 2) - (iVar3 >> 0x1f);
    if (iVar3 < 1)
    {
      if (-1 < iVar3)
      {
        return 0;
      }
      param_1->tm_mday = param_1->tm_mday + iVar3;
      param_1->tm_wday = (param_1->tm_wday + 7 + iVar3) % 7;
      if (param_1->tm_mday < 1)
      {
        param_1->tm_mon = 0xb;
        param_1->tm_mday = param_1->tm_mday + 0x1f;
        param_1->tm_yday = param_1->tm_yday + iVar3 + 0x16d;
        param_1->tm_year = param_1->tm_year + -1;
        return 0;
      }
    }
    else
    {
      param_1->tm_mday = param_1->tm_mday + iVar3;
      param_1->tm_wday = (param_1->tm_wday + iVar3) % 7;
    }
    param_1->tm_yday = param_1->tm_yday + iVar3;
    return 0;
  }
  local_res8[0] = *param_2 - local_res18[0];
  uVar6 = thunk_FUN_1800705c8((undefined(*)[16])param_1, local_res8);
  if ((int)uVar6 != 0)
  {
    return (int)uVar6;
  }
  if (local_res20[0] == 0)
  {
    return 0;
  }
  iVar3 = _isindst(param_1);
  if (iVar3 == 0)
  {
    return 0;
  }
  local_res8[0] = local_res8[0] - local_28[0];
  uVar6 = thunk_FUN_1800705c8((undefined(*)[16])param_1, local_res8);
  if ((int)uVar6 == 0)
  {
    param_1->tm_isdst = 1;
    return 0;
  }
  return (int)uVar6;
}

// Library Function - Single Match
//  int __cdecl common_localtime_s<__int64>(struct tm * __ptr64 const,__int64 const * __ptr64 const)
//
// Library: Visual Studio 2015 Release

int common_localtime_s___int64_(tm *param_1, __int64 *param_2)
{
  code *pcVar1;
  errno_t eVar2;
  int iVar3;
  int iVar4;
  ulong *puVar5;
  longlong lVar6;
  longlong lVar7;
  int local_res8[4];
  int local_res18[2];
  int local_res20[2];
  longlong local_28[2];

  if ((param_1 == (tm *)0x0) ||
      (FUN_18003bd40((undefined(*)[16])param_1, 0xff, 0x24), param_2 == (__int64 *)0x0))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    FUN_18006738c();
    return 0x16;
  }
  if ((*param_2 < 0) || (0x793582aff < *param_2))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    return 0x16;
  }
  __tzset();
  local_res18[0] = 0;
  local_res20[0] = 0;
  local_res8[0] = 0;
  eVar2 = FID_conflict__get_daylight(local_res18);
  if (eVar2 != 0)
  {
    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
    pcVar1 = (code *)swi(3);
    iVar3 = (*pcVar1)();
    return iVar3;
  }
  eVar2 = FID_conflict__get_daylight(local_res20);
  if (eVar2 != 0)
  {
    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
    pcVar1 = (code *)swi(3);
    iVar3 = (*pcVar1)();
    return iVar3;
  }
  eVar2 = FID_conflict__get_daylight(local_res8);
  if (eVar2 != 0)
  {
    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
    pcVar1 = (code *)swi(3);
    iVar3 = (*pcVar1)();
    return iVar3;
  }
  if (0x7935041fd < *param_2 - 0x3f481U)
  {
    iVar3 = common_gmtime_s___int64_(param_1, param_2);
    if (iVar3 != 0)
    {
      return iVar3;
    }
    iVar3 = param_1->tm_sec;
    if ((local_res18[0] != 0) && (iVar4 = _isindst(param_1), iVar4 != 0))
    {
      local_res8[0] = local_res8[0] + local_res20[0];
      param_1->tm_isdst = 1;
    }
    lVar7 = (longlong)iVar3 - (longlong)local_res8[0];
    lVar6 = SUB168(SEXT816(-0x7777777777777777) * SEXT816(lVar7) >> 0x40, 0) + lVar7;
    iVar3 = (int)lVar7 + ((int)(lVar6 >> 5) - (int)(lVar6 >> 0x3f)) * -0x3c;
    param_1->tm_sec = iVar3;
    if (iVar3 < 0)
    {
      lVar7 = lVar7 + -0x3c;
      param_1->tm_sec = iVar3 + 0x3c;
    }
    lVar7 = lVar7 + SUB168(SEXT816(-0x7777777777777777) * SEXT816(lVar7) >> 0x40, 0);
    lVar7 = ((lVar7 >> 5) - (lVar7 >> 0x3f)) + (longlong)param_1->tm_min;
    lVar6 = SUB168(SEXT816(-0x7777777777777777) * SEXT816(lVar7) >> 0x40, 0) + lVar7;
    iVar3 = (int)lVar7 + ((int)(lVar6 >> 5) - (int)(lVar6 >> 0x3f)) * -0x3c;
    param_1->tm_min = iVar3;
    if (iVar3 < 0)
    {
      lVar7 = lVar7 + -0x3c;
      param_1->tm_min = iVar3 + 0x3c;
    }
    lVar7 = lVar7 + SUB168(SEXT816(-0x7777777777777777) * SEXT816(lVar7) >> 0x40, 0);
    lVar7 = ((lVar7 >> 5) - (lVar7 >> 0x3f)) + (longlong)param_1->tm_hour;
    iVar3 = (int)lVar7 + (int)(lVar7 / 0x18) * -0x18;
    param_1->tm_hour = iVar3;
    if (iVar3 < 0)
    {
      lVar7 = lVar7 + -0x18;
      param_1->tm_hour = iVar3 + 0x18;
    }
    lVar7 = lVar7 / 6 + (lVar7 >> 0x3f);
    lVar7 = (lVar7 >> 2) - (lVar7 >> 0x3f);
    iVar3 = (int)lVar7;
    if (lVar7 < 1)
    {
      if (-1 < lVar7)
      {
        return 0;
      }
      param_1->tm_mday = param_1->tm_mday + iVar3;
      param_1->tm_wday = (param_1->tm_wday + 7 + iVar3) % 7;
      if (param_1->tm_mday < 1)
      {
        param_1->tm_mon = 0xb;
        param_1->tm_mday = param_1->tm_mday + 0x1f;
        param_1->tm_yday = param_1->tm_yday + iVar3 + 0x16d;
        param_1->tm_year = param_1->tm_year + -1;
        return 0;
      }
    }
    else
    {
      param_1->tm_mday = param_1->tm_mday + iVar3;
      param_1->tm_wday = (param_1->tm_wday + iVar3) % 7;
    }
    param_1->tm_yday = param_1->tm_yday + iVar3;
    return 0;
  }
  local_28[0] = *param_2 - (longlong)local_res8[0];
  iVar3 = common_gmtime_s___int64_(param_1, local_28);
  if (iVar3 != 0)
  {
    return iVar3;
  }
  if (local_res18[0] == 0)
  {
    return 0;
  }
  iVar3 = _isindst(param_1);
  if (iVar3 == 0)
  {
    return 0;
  }
  local_28[0] = local_28[0] - local_res20[0];
  iVar3 = common_gmtime_s___int64_(param_1, local_28);
  if (iVar3 == 0)
  {
    param_1->tm_isdst = 1;
    return 0;
  }
  return iVar3;
}

// Library Function - Single Match
//  _localtime32
//
// Library: Visual Studio 2015 Release

tm *_localtime32(__time32_t *_Time)
{
  int iVar1;
  tm *ptVar2;
  tm *ptVar3;

  ptVar2 = __getgmtimebuf();
  ptVar3 = (tm *)0x0;
  if ((ptVar2 != (tm *)0x0) &&
      (iVar1 = common_localtime_s_long_(ptVar2, _Time), ptVar3 = ptVar2, iVar1 != 0))
  {
    ptVar3 = (tm *)0x0;
  }
  return ptVar3;
}

// Library Function - Single Match
//  _localtime64
//
// Library: Visual Studio 2015 Release

tm *_localtime64(__time64_t *_Time)
{
  int iVar1;
  tm *ptVar2;
  tm *ptVar3;

  ptVar2 = __getgmtimebuf();
  ptVar3 = (tm *)0x0;
  if ((ptVar2 != (tm *)0x0) &&
      (iVar1 = common_localtime_s___int64_(ptVar2, _Time), ptVar3 = ptVar2, iVar1 != 0))
  {
    ptVar3 = (tm *)0x0;
  }
  return ptVar3;
}

int common_localtime_s___int64_(tm *param_1, __int64 *param_2)
{
  code *pcVar1;
  errno_t eVar2;
  int iVar3;
  int iVar4;
  ulong *puVar5;
  longlong lVar6;
  longlong lVar7;
  int aiStackX8[4];
  int aiStackX24[2];
  int aiStackX32[2];
  longlong alStack40[2];

  if ((param_1 == (tm *)0x0) ||
      (FUN_18003bd40((undefined(*)[16])param_1, 0xff, 0x24), param_2 == (__int64 *)0x0))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    FUN_18006738c();
    return 0x16;
  }
  if ((*param_2 < 0) || (0x793582aff < *param_2))
  {
    puVar5 = __doserrno();
    *puVar5 = 0x16;
    return 0x16;
  }
  __tzset();
  aiStackX24[0] = 0;
  aiStackX32[0] = 0;
  aiStackX8[0] = 0;
  eVar2 = FID_conflict__get_daylight(aiStackX24);
  if (eVar2 != 0)
  {
    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
    pcVar1 = (code *)swi(3);
    iVar3 = (*pcVar1)();
    return iVar3;
  }
  eVar2 = FID_conflict__get_daylight(aiStackX32);
  if (eVar2 != 0)
  {
    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
    pcVar1 = (code *)swi(3);
    iVar3 = (*pcVar1)();
    return iVar3;
  }
  eVar2 = FID_conflict__get_daylight(aiStackX8);
  if (eVar2 != 0)
  {
    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
    pcVar1 = (code *)swi(3);
    iVar3 = (*pcVar1)();
    return iVar3;
  }
  if (0x7935041fd < *param_2 - 0x3f481U)
  {
    iVar3 = common_gmtime_s___int64_(param_1, param_2);
    if (iVar3 != 0)
    {
      return iVar3;
    }
    iVar3 = param_1->tm_sec;
    if ((aiStackX24[0] != 0) && (iVar4 = _isindst(param_1), iVar4 != 0))
    {
      aiStackX8[0] = aiStackX8[0] + aiStackX32[0];
      param_1->tm_isdst = 1;
    }
    lVar7 = (longlong)iVar3 - (longlong)aiStackX8[0];
    lVar6 = SUB168(SEXT816(-0x7777777777777777) * SEXT816(lVar7) >> 0x40, 0) + lVar7;
    iVar3 = (int)lVar7 + ((int)(lVar6 >> 5) - (int)(lVar6 >> 0x3f)) * -0x3c;
    param_1->tm_sec = iVar3;
    if (iVar3 < 0)
    {
      lVar7 = lVar7 + -0x3c;
      param_1->tm_sec = iVar3 + 0x3c;
    }
    lVar7 = lVar7 + SUB168(SEXT816(-0x7777777777777777) * SEXT816(lVar7) >> 0x40, 0);
    lVar7 = ((lVar7 >> 5) - (lVar7 >> 0x3f)) + (longlong)param_1->tm_min;
    lVar6 = SUB168(SEXT816(-0x7777777777777777) * SEXT816(lVar7) >> 0x40, 0) + lVar7;
    iVar3 = (int)lVar7 + ((int)(lVar6 >> 5) - (int)(lVar6 >> 0x3f)) * -0x3c;
    param_1->tm_min = iVar3;
    if (iVar3 < 0)
    {
      lVar7 = lVar7 + -0x3c;
      param_1->tm_min = iVar3 + 0x3c;
    }
    lVar7 = lVar7 + SUB168(SEXT816(-0x7777777777777777) * SEXT816(lVar7) >> 0x40, 0);
    lVar7 = ((lVar7 >> 5) - (lVar7 >> 0x3f)) + (longlong)param_1->tm_hour;
    iVar3 = (int)lVar7 + (int)(lVar7 / 0x18) * -0x18;
    param_1->tm_hour = iVar3;
    if (iVar3 < 0)
    {
      lVar7 = lVar7 + -0x18;
      param_1->tm_hour = iVar3 + 0x18;
    }
    lVar7 = lVar7 / 6 + (lVar7 >> 0x3f);
    lVar7 = (lVar7 >> 2) - (lVar7 >> 0x3f);
    iVar3 = (int)lVar7;
    if (lVar7 < 1)
    {
      if (-1 < lVar7)
      {
        return 0;
      }
      param_1->tm_mday = param_1->tm_mday + iVar3;
      param_1->tm_wday = (param_1->tm_wday + 7 + iVar3) % 7;
      if (param_1->tm_mday < 1)
      {
        param_1->tm_mon = 0xb;
        param_1->tm_mday = param_1->tm_mday + 0x1f;
        param_1->tm_yday = param_1->tm_yday + iVar3 + 0x16d;
        param_1->tm_year = param_1->tm_year + -1;
        return 0;
      }
    }
    else
    {
      param_1->tm_mday = param_1->tm_mday + iVar3;
      param_1->tm_wday = (param_1->tm_wday + iVar3) % 7;
    }
    param_1->tm_yday = param_1->tm_yday + iVar3;
    return 0;
  }
  alStack40[0] = *param_2 - (longlong)aiStackX8[0];
  iVar3 = common_gmtime_s___int64_(param_1, alStack40);
  if (iVar3 != 0)
  {
    return iVar3;
  }
  if (aiStackX24[0] == 0)
  {
    return 0;
  }
  iVar3 = _isindst(param_1);
  if (iVar3 == 0)
  {
    return 0;
  }
  alStack40[0] = alStack40[0] - aiStackX32[0];
  iVar3 = common_gmtime_s___int64_(param_1, alStack40);
  if (iVar3 == 0)
  {
    param_1->tm_isdst = 1;
    return 0;
  }
  return iVar3;
}

// WARNING: Could not reconcile some variable overlaps
// Library Function - Single Match
//  _time32
//
// Library: Visual Studio 2015 Release

__time32_t _time32(__time32_t *_Time)
{
  int iVar1;
  undefined8 local_res8[4];

  local_res8[0] = 0;
  iVar1 = common_timespec_get_struct__timespec32_((_timespec32 *)local_res8, 1);
  if (iVar1 != 1)
  {
    local_res8[0]._0_4_ = -1;
  }
  if (_Time != (__time32_t *)0x0)
  {
    *_Time = (__time32_t)local_res8[0];
  }
  return (__time32_t)local_res8[0];
}

// Library Function - Single Match
//  _time64
//
// Library: Visual Studio 2015 Release

__time64_t _time64(__time64_t *_Time)
{
  int iVar1;
  __time64_t local_18[2];

  local_18[0] = 0;
  iVar1 = common_timespec_get_struct__timespec64_((_timespec64 *)local_18, 1);
  if (iVar1 != 1)
  {
    local_18[0] = -1;
  }
  if (_Time != (__time64_t *)0x0)
  {
    *_Time = local_18[0];
  }
  return local_18[0];
}

// Library Function - Single Match
//  int __cdecl common_timespec_get<struct _timespec32>(struct _timespec32 * __ptr64 const,int)
//
// Library: Visual Studio 2015 Release

int common_timespec_get_struct__timespec32_(_timespec32 *param_1, int param_2)
{
  ulong *puVar1;
  int iVar2;
  longlong lVar3;
  longlong lVar4;
  _FILETIME local_res8[4];

  if (param_1 == (_timespec32 *)0x0)
  {
    puVar1 = __doserrno();
    *puVar1 = 0x16;
    FUN_18006738c();
  }
  else
  {
    if (param_2 == 1)
    {
      local_res8[0] = (_FILETIME)0x0;
      __acrt_GetSystemTimePreciseAsFileTime((LPFILETIME)local_res8);
      lVar4 = (longlong)local_res8[0] + -0x19db1ded53e8000;
      lVar3 = SUB168(SEXT816(-0x29406b2a1a85bd43) * SEXT816(lVar4) >> 0x40, 0) + lVar4;
      lVar3 = (lVar3 >> 0x17) - (lVar3 >> 0x3f);
      if (lVar3 < 0x7fffd280)
      {
        iVar2 = (int)lVar3;
        *(int *)param_1 = iVar2;
        *(int *)(param_1 + 4) = ((int)lVar4 + iVar2 * -10000000) * 100;
        return 1;
      }
    }
  }
  return 0;
}

// Library Function - Single Match
//  int __cdecl common_timespec_get<struct _timespec64>(struct _timespec64 * __ptr64 const,int)
//
// Library: Visual Studio 2015 Release

int common_timespec_get_struct__timespec64_(_timespec64 *param_1, int param_2)
{
  ulong *puVar1;
  longlong lVar2;
  longlong lVar3;
  _FILETIME local_res8[4];

  if (param_1 == (_timespec64 *)0x0)
  {
    puVar1 = __doserrno();
    *puVar1 = 0x16;
    FUN_18006738c();
  }
  else
  {
    if (param_2 == 1)
    {
      local_res8[0] = (_FILETIME)0x0;
      __acrt_GetSystemTimePreciseAsFileTime((LPFILETIME)local_res8);
      lVar3 = (longlong)local_res8[0] + -0x19db1ded53e8000;
      lVar2 = SUB168(SEXT816(-0x29406b2a1a85bd43) * SEXT816(lVar3) >> 0x40, 0) + lVar3;
      lVar2 = (lVar2 >> 0x17) - (lVar2 >> 0x3f);
      if (lVar2 < 0x793582b00)
      {
        *(longlong *)param_1 = lVar2;
        *(int *)(param_1 + 8) = ((int)lVar3 + (int)lVar2 * -10000000) * 100;
        return 1;
      }
    }
  }
  return 0;
}

// WARNING: Could not reconcile some variable overlaps
// Library Function - Single Match
//  _time32
//
// Library: Visual Studio 2015 Release

__time32_t _time32(__time32_t *_Time)
{
  int iVar1;
  undefined8 local_res8[4];

  local_res8[0] = 0;
  iVar1 = common_timespec_get_struct__timespec32_((_timespec32 *)local_res8, 1);
  if (iVar1 != 1)
  {
    local_res8[0]._0_4_ = -1;
  }
  if (_Time != (__time32_t *)0x0)
  {
    *_Time = (__time32_t)local_res8[0];
  }
  return (__time32_t)local_res8[0];
}

// Library Function - Single Match
//  _time64
//
// Library: Visual Studio 2015 Release

__time64_t _time64(__time64_t *_Time)
{
  int iVar1;
  __time64_t local_18[2];

  local_18[0] = 0;
  iVar1 = common_timespec_get_struct__timespec64_((_timespec64 *)local_18, 1);
  if (iVar1 != 1)
  {
    local_18[0] = -1;
  }
  if (_Time != (__time64_t *)0x0)
  {
    *_Time = local_18[0];
  }
  return local_18[0];
}

// Library Function - Single Match
//  _wmkdir
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int _wmkdir(wchar_t *_Path)
{
  BOOL BVar1;
  DWORD DVar2;
  int iVar3;

  BVar1 = CreateDirectoryW(_Path, (LPSECURITY_ATTRIBUTES)0x0);
  if (BVar1 == 0)
  {
    DVar2 = GetLastError();
    __acrt_errno_map_os_error(DVar2);
    iVar3 = -1;
  }
  else
  {
    iVar3 = 0;
  }
  return iVar3;
}

// Library Function - Single Match
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_842d9ff0dc9ef11c61343bbaebe7f885>,class <lambda_c5860995281e5c4ce005b3de8f5874ee>&
// __ptr64,class <lambda_d90129c13df834fdcbf8d2b88dafcf2d>>(class
// <lambda_842d9ff0dc9ef11c61343bbaebe7f885>&& __ptr64,class
// <lambda_c5860995281e5c4ce005b3de8f5874ee>& __ptr64,class
// <lambda_d90129c13df834fdcbf8d2b88dafcf2d>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __thiscall __crt_seh_guarded_call<void>::

    operator___class__lambda_842d9ff0dc9ef11c61343bbaebe7f885__class__lambda_c5860995281e5c4ce005b3de8f5874ee_____ptr64_class__lambda_d90129c13df834fdcbf8d2b88dafcf2d___(__crt_seh_guarded_call_void_ *this, _lambda_842d9ff0dc9ef11c61343bbaebe7f885_ *param_1,
                                                                                                                                                                          _lambda_c5860995281e5c4ce005b3de8f5874ee_ *param_2,
                                                                                                                                                                          _lambda_d90129c13df834fdcbf8d2b88dafcf2d_ *param_3)
{
  uint uVar1;
  int iVar2;

  FUN_1800625f0(*(longlong *)param_1);
  if ((**(longlong **)param_2 != 0) &&
      (uVar1 = *(uint *)(**(longlong **)param_2 + 0x14), (uVar1 >> 0xd & 1) != 0))
  {
    if (((((byte)uVar1 & 3) == 2) && ((uVar1 & 0xc0) != 0)) || ((uVar1 >> 0xb & 1) != 0))
    {
      if ((**(char **)(param_2 + 0x10) != '\0') ||
          ((*(uint *)(**(longlong **)param_2 + 0x14) >> 1 & 1) != 0))
      {
        iVar2 = _fflush_nolock(**(FILE ***)param_2);
        if (iVar2 == -1)
        {
          **(undefined4 **)(param_2 + 0x18) = 0xffffffff;
        }
        else
        {
          **(int **)(param_2 + 8) = **(int **)(param_2 + 8) + 1;
        }
      }
    }
    else
    {
      **(int **)(param_2 + 8) = **(int **)(param_2 + 8) + 1;
    }
  }
  FUN_1800625fc(*(longlong *)param_3);
  return;
}

// Library Function - Single Match
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_c376a267cfb53b6959b3b692ec76b120>,class <lambda_9a32fed5bf61b6b509b2d3f6003082a1>&
// __ptr64,class <lambda_572fbb9fa0ab338edf41edfd4b5fcc8d>>(class
// <lambda_c376a267cfb53b6959b3b692ec76b120>&& __ptr64,class
// <lambda_9a32fed5bf61b6b509b2d3f6003082a1>& __ptr64,class
// <lambda_572fbb9fa0ab338edf41edfd4b5fcc8d>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int __thiscall __crt_seh_guarded_call<int>::

    operator___class__lambda_c376a267cfb53b6959b3b692ec76b120__class__lambda_9a32fed5bf61b6b509b2d3f6003082a1_____ptr64_class__lambda_572fbb9fa0ab338edf41edfd4b5fcc8d___(__crt_seh_guarded_call_int_ *this, _lambda_c376a267cfb53b6959b3b692ec76b120_ *param_1,
                                                                                                                                                                          _lambda_9a32fed5bf61b6b509b2d3f6003082a1_ *param_2,
                                                                                                                                                                          _lambda_572fbb9fa0ab338edf41edfd4b5fcc8d_ *param_3)
{
  int iVar1;

  FUN_1800625f0(*(longlong *)param_1);
  iVar1 = _fflush_nolock(**(FILE ***)param_2);
  FUN_1800625fc(*(longlong *)param_3);
  return iVar1;
}

// Library Function - Single Match
//  int __cdecl common_flush_all(bool)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int common_flush_all(bool param_1)
{
  char local_res8[8];
  undefined local_res10[8];
  int local_res18[2];
  int local_res20[2];
  int local_28;
  int local_24;
  int *local_20;
  char *local_18;
  int *local_10;

  local_res20[0] = 0;
  local_20 = local_res20;
  local_res18[0] = 0;
  local_18 = local_res8;
  local_10 = local_res18;
  local_28 = 8;
  local_24 = 8;
  local_res8[0] = param_1;
  FUN_180061bc4(local_res10, &local_24, &local_20, &local_28);
  if (local_res8[0] != '\0')
  {
    local_res18[0] = local_res20[0];
  }
  return local_res18[0];
}

// Library Function - Single Match
//  __acrt_stdio_flush_nolock
//
// Library: Visual Studio 2017 Release

undefined8 __acrt_stdio_flush_nolock(FILE *param_1)
{
  uint *puVar1;
  WCHAR *pWVar2;
  uint uVar3;
  uint uVar4;

  uVar4 = *(uint *)((longlong)&param_1->_base + 4);
  if ((((byte)uVar4 & 3) == 2) && ((uVar4 & 0xc0) != 0))
  {
    uVar4 = *(int *)&param_1->_ptr - param_1->_cnt;
    *(undefined4 *)&param_1->_base = 0;
    pWVar2 = *(WCHAR **)&param_1->_cnt;
    param_1->_ptr = (char *)pWVar2;
    if (0 < (int)uVar4)
    {
      uVar3 = _fileno(param_1);
      uVar3 = FUN_18006f8f8(uVar3, pWVar2, uVar4);
      if (uVar4 != uVar3)
      {
        LOCK();
        puVar1 = (uint *)((longlong)&param_1->_base + 4);
        *puVar1 = *puVar1 | 0x10;
        return 0xffffffff;
      }
      if ((*(uint *)((longlong)&param_1->_base + 4) >> 2 & 1) != 0)
      {
        LOCK();
        puVar1 = (uint *)((longlong)&param_1->_base + 4);
        *puVar1 = *puVar1 & 0xfffffffd;
      }
    }
  }
  return 0;
}

// Library Function - Single Match
//  _fflush_nolock
//
// Library: Visual Studio 2015 Release

int _fflush_nolock(FILE *_File)
{
  int iVar1;
  undefined8 uVar2;

  if (_File == (FILE *)0x0)
  {
    iVar1 = common_flush_all(false);
    return iVar1;
  }
  uVar2 = __acrt_stdio_flush_nolock(_File);
  if ((int)uVar2 == 0)
  {
    if ((*(uint *)((longlong)&_File->_base + 4) >> 0xb & 1) != 0)
    {
      iVar1 = _fileno(_File);
      iVar1 = _commit(iVar1);
      if (iVar1 != 0)
        goto LAB_1800620e5;
    }
    iVar1 = 0;
  }
  else
  {
  LAB_1800620e5:
    iVar1 = -1;
  }
  return iVar1;
}

int common_flush_all(bool param_1)
{
  int iVar1;

  iVar1 = common_flush_all(true);
  return iVar1;
}

// Library Function - Single Match
//  fflush
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int fflush(FILE *_File)
{
  uint uVar1;
  int iVar2;
  __crt_seh_guarded_call_int_ local_res8[8];
  FILE *local_res10;
  FILE *local_res18;
  FILE **local_res20;
  FILE *local_18[3];

  local_res10 = _File;
  if (_File == (FILE *)0x0)
  {
    iVar2 = common_flush_all(false);
  }
  else
  {
    uVar1 = *(uint *)((longlong)&_File->_base + 4);
    if (((((byte)uVar1 & 3) == 2) && ((uVar1 & 0xc0) != 0)) || ((uVar1 >> 0xb & 1) != 0))
    {
      local_res20 = &local_res10;
      local_res18 = _File;
      local_18[0] = _File;
      iVar2 = __crt_seh_guarded_call<int>::

          operator___class__lambda_c376a267cfb53b6959b3b692ec76b120__class__lambda_9a32fed5bf61b6b509b2d3f6003082a1_____ptr64_class__lambda_572fbb9fa0ab338edf41edfd4b5fcc8d___(local_res8, (_lambda_c376a267cfb53b6959b3b692ec76b120_ *)local_18,
                                                                                                                                                                                (_lambda_9a32fed5bf61b6b509b2d3f6003082a1_ *)&local_res20,
                                                                                                                                                                                (_lambda_572fbb9fa0ab338edf41edfd4b5fcc8d_ *)&local_res18);
    }
    else
    {
      iVar2 = 0;
    }
  }
  return iVar2;
}

// Library Function - Single Match
//  _waccess
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int _waccess(wchar_t *_Filename, int _AccessMode)
{
  errno_t eVar1;

  eVar1 = _waccess_s(_Filename, _AccessMode);
  return (int)-(uint)(eVar1 != 0);
}

// Library Function - Single Match
//  _waccess_s
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t _waccess_s(wchar_t *_Filename, int _AccessMode)
{
  BOOL BVar1;
  DWORD DVar2;
  errno_t eVar3;
  ulong *puVar4;
  undefined auStack88[32];
  byte local_38[40];
  ulonglong local_10;

  local_10 = DAT_1800ee160 ^ (ulonglong)auStack88;
  if ((_Filename == (wchar_t *)0x0) || ((_AccessMode & 0xfffffff9U) != 0))
  {
    puVar4 = __doserrno();
    *puVar4 = 0;
    puVar4 = __doserrno();
    *puVar4 = 0x16;
    FUN_18006738c();
  }
  else
  {
    BVar1 = GetFileAttributesExW(_Filename, GetFileExInfoStandard, local_38);
    if (BVar1 == 0)
    {
      DVar2 = GetLastError();
      __acrt_errno_map_os_error(DVar2);
    }
    else
    {
      if ((((local_38[0] & 0x10) != 0) || ((local_38[0] & 1) == 0)) ||
          (((uint)_AccessMode >> 1 & 1) == 0))
        goto LAB_1800623b3;
      puVar4 = __doserrno();
      *puVar4 = 5;
      puVar4 = __doserrno();
      *puVar4 = 0xd;
    }
    __doserrno();
  }
LAB_1800623b3:
  eVar3 = FUN_180034d00(local_10 ^ (ulonglong)auStack88);
  return eVar3;
}

// Library Function - Single Match
//  __acrt_iob_func
//
// Library: Visual Studio 2015 Release

undefined *__acrt_iob_func(ulonglong param_1)
{
  return &DAT_1800ee480 + (param_1 & 0xffffffff) * 0x58;
}

// Library Function - Single Match
//  __acrt_uninitialize_stdio
//
// Library: Visual Studio 2015 Release

void __acrt_uninitialize_stdio(bool param_1)
{
  longlong lVar1;

  common_flush_all(param_1);
  _fcloseall();
  lVar1 = 0;
  do
  {
    __acrt_stdio_free_buffer_nolock(*(undefined8 **)(lVar1 + (longlong)DAT_180101938));
    DeleteCriticalSection((LPCRITICAL_SECTION)(*(longlong *)(lVar1 + (longlong)DAT_180101938) + 0x30));
    lVar1 = lVar1 + 8;
  } while (lVar1 != 0x18);
  _free_base(DAT_180101938);
  DAT_180101938 = (LPVOID)0x0;
  return;
}

// Library Function - Single Match
//  wcscmp
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int wcscmp(wchar_t *_Str1, wchar_t *_Str2)
{
  ushort uVar1;
  wchar_t *pwVar2;
  int iVar3;

  uVar1 = *_Str2;
  iVar3 = (uint)(ushort)*_Str1 - (uint)uVar1;
  if (iVar3 == 0)
  {
    pwVar2 = (wchar_t *)((longlong)_Str1 - (longlong)_Str2);
    do
    {
      if (uVar1 == 0)
        break;
      _Str2 = (wchar_t *)((ushort *)_Str2 + 1);
      uVar1 = *_Str2;
      iVar3 = (uint) * (ushort *)((longlong)pwVar2 + (longlong)_Str2) - (uint)uVar1;
    } while (iVar3 == 0);
  }
  return (iVar3 >> 0x1f) - (-iVar3 >> 0x1f);
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  _initterm
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void _initterm(undefined **param_1, undefined **param_2)
{
  ulonglong uVar1;
  ulonglong uVar2;

  uVar1 = 0;
  uVar2 = (ulonglong)((longlong)param_2 + (7 - (longlong)param_1)) >> 3;
  if (param_2 < param_1)
  {
    uVar2 = uVar1;
  }
  if (uVar2 != 0)
  {
    do
    {
      if ((code *)*param_1 != (code *)0x0)
      {
        (*(code *)*param_1)();
      }
      param_1 = (code **)param_1 + 1;
      uVar1 = uVar1 + 1;
    } while (uVar1 != uVar2);
  }
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  _initterm_e
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 _initterm_e(undefined **param_1, undefined **param_2)
{
  undefined8 uVar1;
  bool bVar2;

  bVar2 = param_1 == param_2;
  while (true)
  {
    if (bVar2)
    {
      return 0;
    }
    if (((code *)*param_1 != (code *)0x0) && (uVar1 = (*(code *)*param_1)(), (int)uVar1 != 0))
      break;
    param_1 = (code **)param_1 + 1;
    bVar2 = param_1 == param_2;
  }
  return uVar1;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  _callnewh
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int _callnewh(size_t _Size)
{
  int iVar1;
  code *pcVar2;

  pcVar2 = (code *)_query_new_handler();
  if ((pcVar2 != (code *)0x0) && (iVar1 = (*pcVar2)(), iVar1 != 0))
  {
    return 1;
  }
  return 0;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _query_new_handler
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong _query_new_handler(void)
{
  byte bVar1;
  ulonglong uVar2;

  __acrt_lock(0);
  bVar1 = (byte)DAT_1800ee160 & 0x3f;
  uVar2 = DAT_1800ee160 ^ _DAT_180101948;
  __acrt_unlock(0);
  return uVar2 >> bVar1 | uVar2 << 0x40 - bVar1;
}

LPVOID _malloc_base(ulonglong param_1)
{
  int iVar1;
  LPVOID pvVar2;
  ulong *puVar3;

  if (param_1 < 0xffffffffffffffe1)
  {
    if (param_1 == 0)
    {
      param_1 = 1;
    }
    do
    {
      pvVar2 = HeapAlloc(DAT_180102658, 0, param_1);
      if (pvVar2 != (LPVOID)0x0)
      {
        return pvVar2;
      }
      iVar1 = FUN_180079e3c();
    } while ((iVar1 != 0) && (iVar1 = _callnewh(param_1), iVar1 != 0));
  }
  puVar3 = __doserrno();
  *puVar3 = 0xc;
  return (LPVOID)0x0;
}

// Library Function - Multiple Matches With Same Base Name
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_99476a1ad63dd22509b5d3e65b0ffc95>,class <lambda_ad1ced32f4ac17aa236e5ef05d6b3b7c>&
// __ptr64,class <lambda_f7424dd8d45958661754dc4f2697e9c3>>(class
// <lambda_99476a1ad63dd22509b5d3e65b0ffc95>&& __ptr64,class
// <lambda_ad1ced32f4ac17aa236e5ef05d6b3b7c>& __ptr64,class
// <lambda_f7424dd8d45958661754dc4f2697e9c3>&& __ptr64) __ptr64
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_d80eeec6fff315bfe5c115232f3240e3>,class <lambda_6e4b09c48022b2350581041d5f6b0c4c>&
// __ptr64,class <lambda_2358e3775559c9db80273638284d5e45>>(class
// <lambda_d80eeec6fff315bfe5c115232f3240e3>&& __ptr64,class
// <lambda_6e4b09c48022b2350581041d5f6b0c4c>& __ptr64,class
// <lambda_2358e3775559c9db80273638284d5e45>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void operator____(undefined8 param_1, int *param_2, int **param_3, int *param_4)
{
  __acrt_lock(*param_2);
  FUN_180062bb4(param_3);
  __acrt_unlock(*param_4);
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  void __cdecl try_cor_exit_process(unsigned int)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void try_cor_exit_process(uint param_1)
{
  BOOL BVar1;
  FARPROC pFVar2;
  HMODULE local_res10[3];
  uint extraout_var;

  local_res10[0] = (HMODULE)0x0;
  BVar1 = GetModuleHandleExW(0, L"mscoree.dll", local_res10);
  if (BVar1 != 0)
  {
    pFVar2 = GetProcAddress(local_res10[0], "CorExitProcess");
    extraout_var = (uint)((ulonglong)pFVar2 >> 0x20);
    if (((ulonglong)pFVar2 & 0xffffffff | (ulonglong)extraout_var << 0x20) != 0)
    {
      (*(code *)((ulonglong)pFVar2 & 0xffffffff | (ulonglong)extraout_var << 0x20))();
    }
  }
  if (local_res10[0] != (HMODULE)0x0)
  {
    FreeLibrary(local_res10[0]);
  }
  return;
}

// WARNING: Unknown calling convention yet parameter storage is locked
// Library Function - Single Match
//  int __cdecl common_initialize_environment_nolock<char>(void)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int common_initialize_environment_nolock_char_(void)
{
  char **ppcVar1;
  int iVar2;
  LPSTR pCVar3;
  char **ppcVar4;

  iVar2 = 0;
  if (DAT_180101c90 == (char **)0x0)
  {
    __acrt_initialize_multibyte();
    pCVar3 = __dcrt_get_narrow_environment_from_os();
    if (pCVar3 == (LPSTR)0x0)
    {
      iVar2 = -1;
    }
    else
    {
      ppcVar4 = FUN_180063d8c(pCVar3);
      ppcVar1 = ppcVar4;
      if (ppcVar4 == (char **)0x0)
      {
        iVar2 = -1;
        ppcVar4 = DAT_180101c90;
        ppcVar1 = DAT_180101ca8;
      }
      DAT_180101ca8 = ppcVar1;
      DAT_180101c90 = ppcVar4;
      _free_base((LPVOID)0x0);
    }
    _free_base(pCVar3);
  }
  else
  {
    iVar2 = 0;
  }
  return iVar2;
}

// WARNING: Unknown calling convention yet parameter storage is locked
// Library Function - Single Match
//  int __cdecl common_initialize_environment_nolock<wchar_t>(void)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int common_initialize_environment_nolock_wchar_t_(void)
{
  wchar_t **ppwVar1;
  int iVar2;
  undefined8 *puVar3;
  wchar_t **ppwVar4;

  iVar2 = 0;
  if (DAT_180101c98 == (wchar_t **)0x0)
  {
    puVar3 = __dcrt_get_wide_environment_from_os();
    if (puVar3 == (undefined8 *)0x0)
    {
      iVar2 = -1;
    }
    else
    {
      ppwVar4 = FUN_180063e98((wchar_t *)puVar3);
      ppwVar1 = ppwVar4;
      if (ppwVar4 == (wchar_t **)0x0)
      {
        iVar2 = -1;
        ppwVar4 = DAT_180101c98;
        ppwVar1 = DAT_180101ca0;
      }
      DAT_180101ca0 = ppwVar1;
      DAT_180101c98 = ppwVar4;
      _free_base((LPVOID)0x0);
    }
    _free_base(puVar3);
  }
  else
  {
    iVar2 = 0;
  }
  return iVar2;
}

// Library Function - Multiple Matches With Same Base Name
//  void __cdecl free_environment<char>(char * __ptr64 * __ptr64 const)
//  void __cdecl free_environment<wchar_t>(wchar_t * __ptr64 * __ptr64 const)
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void free_environment__(LPVOID *param_1)
{
  LPVOID pvVar1;
  LPVOID *ppvVar2;

  if (param_1 != (LPVOID *)0x0)
  {
    pvVar1 = *param_1;
    ppvVar2 = param_1;
    while (pvVar1 != (LPVOID)0x0)
    {
      _free_base(pvVar1);
      ppvVar2 = ppvVar2 + 1;
      pvVar1 = *ppvVar2;
    }
    _free_base(param_1);
  }
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  void __cdecl free_environment<char>(char * __ptr64 * __ptr64 const)
//  void __cdecl free_environment<wchar_t>(wchar_t * __ptr64 * __ptr64 const)
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void free_environment__(LPVOID *param_1)
{
  LPVOID pvVar1;
  LPVOID *ppvVar2;

  if (param_1 != (LPVOID *)0x0)
  {
    pvVar1 = *param_1;
    ppvVar2 = param_1;
    while (pvVar1 != (LPVOID)0x0)
    {
      _free_base(pvVar1);
      ppvVar2 = ppvVar2 + 1;
      pvVar1 = *ppvVar2;
    }
    _free_base(param_1);
  }
  return;
}

// WARNING: Unknown calling convention yet parameter storage is locked
// Library Function - Single Match
//  int __cdecl initialize_environment_by_cloning_nolock<char>(void)
//
// Library: Visual Studio 2015 Release

int initialize_environment_by_cloning_nolock_char_(void)
{
  int iVar1;
  char *lpMultiByteStr;
  LPCWSTR *ppWVar2;

  ppWVar2 = DAT_180101c98;
  if (DAT_180101c98 == (LPCWSTR *)0x0)
  {
  LAB_180064067:
    iVar1 = -1;
  }
  else
  {
    while (*ppWVar2 != (LPCWSTR)0x0)
    {
      iVar1 = WideCharToMultiByte(0, 0, *ppWVar2, -1, (LPSTR)0x0, 0, (LPCSTR)0x0, (LPBOOL)0x0);
      if (iVar1 == 0)
        goto LAB_180064067;
      lpMultiByteStr = (char *)_calloc_base((longlong)iVar1, 1);
      if (lpMultiByteStr == (char *)0x0)
      {
      LAB_18006410e:
        _free_base(lpMultiByteStr);
        goto LAB_180064067;
      }
      iVar1 = WideCharToMultiByte(0, 0, *ppWVar2, -1, lpMultiByteStr, iVar1, (LPCSTR)0x0, (LPBOOL)0x0);
      if (iVar1 == 0)
        goto LAB_18006410e;
      thunk_FUN_1800789dc(lpMultiByteStr, 0);
      _free_base((LPVOID)0x0);
      ppWVar2 = ppWVar2 + 1;
    }
    iVar1 = 0;
  }
  return iVar1;
}

// WARNING: Unknown calling convention yet parameter storage is locked
// Library Function - Single Match
//  int __cdecl initialize_environment_by_cloning_nolock<wchar_t>(void)
//
// Library: Visual Studio 2015 Release

int initialize_environment_by_cloning_nolock_wchar_t_(void)
{
  int iVar1;
  undefined(*lpWideCharStr)[32];
  LPCSTR *ppCVar2;

  ppCVar2 = DAT_180101c90;
  if (DAT_180101c90 == (LPCSTR *)0x0)
  {
  LAB_180064137:
    iVar1 = -1;
  }
  else
  {
    while (*ppCVar2 != (LPCSTR)0x0)
    {
      iVar1 = MultiByteToWideChar(0, 0, *ppCVar2, -1, (LPWSTR)0x0, 0);
      if (iVar1 == 0)
        goto LAB_180064137;
      lpWideCharStr = (undefined(*)[32])_calloc_base((longlong)iVar1, 2);
      if (lpWideCharStr == (undefined(*)[32])0x0)
      {
      LAB_1800641bf:
        _free_base(lpWideCharStr);
        goto LAB_180064137;
      }
      iVar1 = MultiByteToWideChar(0, 0, *ppCVar2, -1, (LPWSTR)lpWideCharStr, iVar1);
      if (iVar1 == 0)
        goto LAB_1800641bf;
      thunk_FUN_180078cfc(lpWideCharStr, 0);
      _free_base((LPVOID)0x0);
      ppCVar2 = ppCVar2 + 1;
    }
    iVar1 = 0;
  }
  return iVar1;
}

// Library Function - Single Match
//  unsigned __int64 __cdecl __crt_compute_required_transform_buffer_count(unsigned int,wchar_t
// const * __ptr64 const)
//
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

__uint64 __crt_compute_required_transform_buffer_count(uint param_1, wchar_t *param_2)
{
  int iVar1;

  iVar1 = WideCharToMultiByte(param_1, 0, (LPCWSTR)param_2, -1, (LPSTR)0x0, 0, (LPCSTR)0x0, (LPBOOL)0x0);
  return (longlong)iVar1;
}

// Library Function - Single Match
//  __dcrt_get_or_create_narrow_environment_nolock
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

longlong __dcrt_get_or_create_narrow_environment_nolock(void)
{
  int iVar1;
  longlong lVar2;

  lVar2 = DAT_180101c90;
  if ((DAT_180101c90 == 0) &&
      ((DAT_180101c98 == 0 ||
        ((iVar1 = common_initialize_environment_nolock_char_(), lVar2 = DAT_180101c90, iVar1 != 0 && (iVar1 = initialize_environment_by_cloning_nolock_char_(), lVar2 = DAT_180101c90, iVar1 != 0))))))
  {
    lVar2 = 0;
  }
  return lVar2;
}

// Library Function - Single Match
//  __dcrt_get_or_create_wide_environment_nolock
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

longlong __dcrt_get_or_create_wide_environment_nolock(void)
{
  int iVar1;
  longlong lVar2;

  lVar2 = DAT_180101c98;
  if ((DAT_180101c98 == 0) &&
      ((DAT_180101c90 == 0 ||
        ((iVar1 = common_initialize_environment_nolock_wchar_t_(), lVar2 = DAT_180101c98, iVar1 != 0 && (iVar1 = initialize_environment_by_cloning_nolock_wchar_t_(), lVar2 = DAT_180101c98, iVar1 != 0))))))
  {
    lVar2 = 0;
  }
  return lVar2;
}

// WARNING: Unknown calling convention yet parameter storage is locked

int common_initialize_environment_nolock_char_(void)
{
  char **ppcVar1;
  int iVar2;
  LPSTR pCVar3;
  char **ppcVar4;

  iVar2 = 0;
  if (DAT_180101c90 == (char **)0x0)
  {
    __acrt_initialize_multibyte();
    pCVar3 = __dcrt_get_narrow_environment_from_os();
    if (pCVar3 == (LPSTR)0x0)
    {
      iVar2 = -1;
    }
    else
    {
      ppcVar4 = FUN_180063d8c(pCVar3);
      ppcVar1 = ppcVar4;
      if (ppcVar4 == (char **)0x0)
      {
        iVar2 = -1;
        ppcVar4 = DAT_180101c90;
        ppcVar1 = DAT_180101ca8;
      }
      DAT_180101ca8 = ppcVar1;
      DAT_180101c90 = ppcVar4;
      _free_base((LPVOID)0x0);
    }
    _free_base(pCVar3);
  }
  else
  {
    iVar2 = 0;
  }
  return iVar2;
}

// Library Function - Single Match
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_7777bce6b2f8c936911f934f8298dc43>,class <lambda_f03950bc5685219e0bcd2087efbe011e>&
// __ptr64,class <lambda_3883c3dff614d5e0c5f61bb1ac94921c>>(class
// <lambda_7777bce6b2f8c936911f934f8298dc43>&& __ptr64,class
// <lambda_f03950bc5685219e0bcd2087efbe011e>& __ptr64,class
// <lambda_3883c3dff614d5e0c5f61bb1ac94921c>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int __thiscall __crt_seh_guarded_call<int>::

    operator___class__lambda_7777bce6b2f8c936911f934f8298dc43__class__lambda_f03950bc5685219e0bcd2087efbe011e_____ptr64_class__lambda_3883c3dff614d5e0c5f61bb1ac94921c___(__crt_seh_guarded_call_int_ *this, _lambda_7777bce6b2f8c936911f934f8298dc43_ *param_1,
                                                                                                                                                                          _lambda_f03950bc5685219e0bcd2087efbe011e_ *param_2,
                                                                                                                                                                          _lambda_3883c3dff614d5e0c5f61bb1ac94921c_ *param_3)
{
  undefined8 uVar1;

  __acrt_lock(*(int *)param_1);
  uVar1 = FUN_180064928((ulonglong **)param_2);
  __acrt_unlock(*(int *)param_3);
  return (int)uVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_638799b9deba96c50f710eeac98168cd>,class <lambda_22ebabd17bc4fa466a2aca6d8deb888d>&
// __ptr64,class <lambda_a6f7d7db0129f75315ebf26d50c089f1>>(class
// <lambda_638799b9deba96c50f710eeac98168cd>&& __ptr64,class
// <lambda_22ebabd17bc4fa466a2aca6d8deb888d>& __ptr64,class
// <lambda_a6f7d7db0129f75315ebf26d50c089f1>&& __ptr64) __ptr64
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_b8c45f8f788dd370798f47cfe8ac3a86>,class <lambda_4e60a939b0d047cfe11ddc22648dfba9>&
// __ptr64,class <lambda_332c3edc96d0294ec56c57d38c1cdfd5>>(class
// <lambda_b8c45f8f788dd370798f47cfe8ac3a86>&& __ptr64,class
// <lambda_4e60a939b0d047cfe11ddc22648dfba9>& __ptr64,class
// <lambda_332c3edc96d0294ec56c57d38c1cdfd5>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong operator____(undefined8 param_1, int *param_2, ulonglong **param_3, int *param_4)
{
  ulonglong uVar1;

  __acrt_lock(*param_2);
  uVar1 = FUN_180064764(param_3);
  __acrt_unlock(*param_4);
  return uVar1 & 0xffffffff;
}

// Library Function - Single Match
//  _execute_onexit_table
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void _execute_onexit_table(undefined8 param_1)
{
  undefined8 local_res8;
  __crt_seh_guarded_call_int_ local_res10[8];
  undefined4 local_res18[2];
  undefined4 local_res20[2];
  undefined8 *local_18[3];

  local_18[0] = &local_res8;
  local_res18[0] = 2;
  local_res20[0] = 2;
  local_res8 = param_1;
  __crt_seh_guarded_call<int>::

      operator___class__lambda_7777bce6b2f8c936911f934f8298dc43__class__lambda_f03950bc5685219e0bcd2087efbe011e_____ptr64_class__lambda_3883c3dff614d5e0c5f61bb1ac94921c___(local_res10, (_lambda_7777bce6b2f8c936911f934f8298dc43_ *)local_res20,
                                                                                                                                                                            (_lambda_f03950bc5685219e0bcd2087efbe011e_ *)local_18,
                                                                                                                                                                            (_lambda_3883c3dff614d5e0c5f61bb1ac94921c_ *)local_res18);
  return;
}

// Library Function - Single Match
//  _initialize_onexit_table
//
// Library: Visual Studio 2015 Release

undefined8 _initialize_onexit_table(ulonglong *param_1)
{
  byte bVar1;
  ulonglong uVar2;

  if (param_1 == (ulonglong *)0x0)
  {
    return 0xffffffff;
  }
  if (*param_1 == param_1[2])
  {
    bVar1 = 0x40 - ((byte)DAT_1800ee160 & 0x3f) & 0x3f;
    uVar2 = (0U >> bVar1 | 0 << 0x40 - bVar1) ^ DAT_1800ee160;
    *param_1 = uVar2;
    param_1[1] = uVar2;
    param_1[2] = uVar2;
  }
  return 0;
}

// Library Function - Single Match
//  _register_onexit_function
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void _register_onexit_function(ulonglong param_1, undefined8 param_2)
{
  ulonglong local_res8;
  undefined8 local_res10;
  undefined local_res18[8];
  int local_res20[2];
  int local_28[2];
  ulonglong *local_20;
  undefined8 *local_18;

  local_20 = &local_res8;
  local_18 = &local_res10;
  local_res20[0] = 2;
  local_28[0] = 2;
  local_res8 = param_1;
  local_res10 = param_2;
  operator____(local_res18, local_28, &local_20, local_res20);
  return;
}

// Library Function - Single Match
//  __acrt_thread_detach
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined __acrt_thread_detach(void)
{
  __acrt_freeptd();
  return 1;
}

// Library Function - Single Match
//  set_terminate
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined *set_terminate(undefined8 param_1)
{
  __acrt_ptd *p_Var1;
  code *pcVar2;

  p_Var1 = FUN_18006a750();
  pcVar2 = abort;
  if (*(longlong *)(p_Var1 + 0x18) != 0)
  {
    pcVar2 = *(code **)(p_Var1 + 0x18);
  }
  *(undefined8 *)(p_Var1 + 0x18) = param_1;
  return pcVar2;
}

// Library Function - Single Match
//  _free_base
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void _free_base(LPVOID param_1)
{
  BOOL BVar1;
  DWORD DVar2;
  ulong uVar3;
  ulong *puVar4;

  if ((param_1 != (LPVOID)0x0) && (BVar1 = HeapFree(DAT_180102658, 0, param_1), BVar1 == 0))
  {
    puVar4 = __doserrno();
    DVar2 = GetLastError();
    uVar3 = __acrt_errno_from_os_error(DVar2);
    *puVar4 = uVar3;
  }
  return;
}

// Library Function - Single Match
//  _malloc_base
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

LPVOID _malloc_base(ulonglong param_1)
{
  int iVar1;
  LPVOID pvVar2;
  ulong *puVar3;

  if (param_1 < 0xffffffffffffffe1)
  {
    if (param_1 == 0)
    {
      param_1 = 1;
    }
    do
    {
      pvVar2 = HeapAlloc(DAT_180102658, 0, param_1);
      if (pvVar2 != (LPVOID)0x0)
      {
        return pvVar2;
      }
      iVar1 = FUN_180079e3c();
    } while ((iVar1 != 0) && (iVar1 = _callnewh(param_1), iVar1 != 0));
  }
  puVar3 = __doserrno();
  *puVar3 = 0xc;
  return (LPVOID)0x0;
}

// Library Function - Single Match
//  strcpy_s
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t strcpy_s(char *_Dst, rsize_t _SizeInBytes, char *_Src)
{
  char cVar1;
  ulong *puVar2;
  ulong uVar3;
  char *pcVar4;

  if ((_Dst != (char *)0x0) && (_SizeInBytes != 0))
  {
    if (_Src != (char *)0x0)
    {
      pcVar4 = _Dst;
      do
      {
        cVar1 = (_Src + -(longlong)_Dst)[(longlong)pcVar4];
        *pcVar4 = cVar1;
        pcVar4 = pcVar4 + 1;
        if (cVar1 == '\0')
          break;
        _SizeInBytes = _SizeInBytes - 1;
      } while (_SizeInBytes != 0);
      if (_SizeInBytes != 0)
      {
        return 0;
      }
      *_Dst = '\0';
      puVar2 = __doserrno();
      uVar3 = 0x22;
      goto LAB_180064fef;
    }
    *_Dst = '\0';
  }
  puVar2 = __doserrno();
  uVar3 = 0x16;
LAB_180064fef:
  *puVar2 = uVar3;
  FUN_18006738c();
  return (errno_t)uVar3;
}

// Library Function - Single Match
//  abort
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void abort(void)
{
  code *pcVar1;
  BOOL BVar2;
  longlong lVar3;
  undefined *puVar4;
  undefined auStack40[8];
  undefined auStack32[32];

  puVar4 = auStack40;
  lVar3 = __acrt_get_sigabrt_handler();
  if (lVar3 != 0)
  {
    FUN_180079908(0x16);
  }
  if ((DAT_1800ee588 & 2) != 0)
  {
    BVar2 = IsProcessorFeaturePresent(0x17);
    puVar4 = auStack40;
    if (BVar2 != 0)
    {
      pcVar1 = (code *)swi(0x29);
      (*pcVar1)();
      puVar4 = auStack32;
    }
    *(undefined8 *)(puVar4 + -8) = 0x180065093;
    __acrt_call_reportfault(3, 0x40000015, 1, puVar4[-8]);
  }
  *(undefined8 *)(puVar4 + -8) = 0x18006509d;
  FUN_180062f08(3, puVar4[-8]);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}

// Library Function - Single Match
//  _calloc_base
//
// Library: Visual Studio 2015 Release

LPVOID _calloc_base(ulonglong param_1, ulonglong param_2)
{
  int iVar1;
  LPVOID pvVar2;
  ulong *puVar3;
  size_t dwBytes;

  if ((param_1 == 0) || (param_2 <= 0xffffffffffffffe0 / param_1))
  {
    dwBytes = param_1 * param_2;
    if (dwBytes == 0)
    {
      dwBytes = 1;
    }
    do
    {
      pvVar2 = HeapAlloc(DAT_180102658, 8, dwBytes);
      if (pvVar2 != (LPVOID)0x0)
      {
        return pvVar2;
      }
      iVar1 = FUN_180079e3c();
    } while ((iVar1 != 0) && (iVar1 = _callnewh(dwBytes), iVar1 != 0));
  }
  puVar3 = __doserrno();
  *puVar3 = 0xc;
  return (LPVOID)0x0;
}

// Library Function - Single Match
//  _wtol
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

long _wtol(wchar_t *_Str)
{
  uint uVar1;
  ushort *local_18;
  undefined8 local_10;

  local_10 = 0;
  local_18 = (ushort *)_Str;
  uVar1 = FUN_1800654b4((undefined4 *)0x0, &local_18, 10, 1);
  return uVar1;
}

// Library Function - Single Match
//  strncmp
//
// Libraries: Visual Studio 2012 Debug, Visual Studio 2012 Release, Visual Studio 2015 Debug, Visual
// Studio 2015 Release

int strncmp(char *_Str1, char *_Str2, size_t _MaxCount)
{
  byte bVar1;
  ulonglong uVar2;
  char *pcVar3;
  bool bVar4;

  pcVar3 = _Str2 + -(longlong)_Str1;
  if (_MaxCount != 0)
  {
    uVar2 = (ulonglong)_Str1 & 7;
    while (true)
    {
      if (uVar2 == 0)
      {
        while ((((int)_Str1 + (int)pcVar3 & 0xfffU) < 0xff9 &&
                (uVar2 = *(ulonglong *)_Str1,
                 uVar2 == *(ulonglong *)((longlong)_Str1 + (longlong)pcVar3))))
        {
          _Str1 = (char *)((longlong)_Str1 + 8);
          bVar4 = _MaxCount < 8;
          _MaxCount = _MaxCount - 8;
          if (bVar4 || _MaxCount == 0)
          {
            return 0;
          }
          if ((~uVar2 & uVar2 + 0xfefefefefefefeff & 0x8080808080808080) != 0)
          {
            return 0;
          }
        }
      }
      bVar1 = *_Str1;
      if (bVar1 != *(byte *)((longlong)_Str1 + (longlong)pcVar3))
      {
        return (int)(-(uint)(bVar1 < *(byte *)((longlong)_Str1 + (longlong)pcVar3)) | 1);
      }
      _Str1 = (char *)((longlong)_Str1 + 1);
      _MaxCount = _MaxCount - 1;
      if ((_MaxCount == 0) || (bVar1 == 0))
        break;
      uVar2 = (ulonglong)_Str1 & 7;
    }
  }
  return 0;
}

// Library Function - Single Match
//  wcsncmp
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int wcsncmp(wchar_t *_Str1, wchar_t *_Str2, size_t _MaxCount)
{
  if (_MaxCount == 0)
  {
    return 0;
  }
  while (((_MaxCount = _MaxCount - 1, _MaxCount != 0 && (*_Str1 != 0)) && (*_Str1 == *_Str2)))
  {
    _Str1 = (wchar_t *)((ushort *)_Str1 + 1);
    _Str2 = (wchar_t *)((ushort *)_Str2 + 1);
  }
  return (int)((uint)(ushort)*_Str1 - (uint)(ushort)*_Str2);
}

// Library Function - Single Match
//  __acrt_call_reportfault
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_call_reportfault(int param_1, DWORD param_2, DWORD param_3)
{
  BOOL BVar1;
  LONG LVar2;
  PRUNTIME_FUNCTION FunctionEntry;
  undefined auStackX8[8];
  DWORD64 local_5c8;
  _EXCEPTION_POINTERS local_5c0;
  ulonglong local_5b0;
  PVOID local_5a8[2];
  EXCEPTION_RECORD local_598;
  _CONTEXT local_4f8;
  ulonglong local_28;

  local_28 = DAT_1800ee160 ^ (ulonglong)&stack0xfffffffffffff9f8;
  if (param_1 != -1)
  {
    FUN_180035448();
  }
  FUN_18003bd40((undefined(*)[16]) & local_598, 0, 0x98);
  FUN_18003bd40((undefined(*)[16]) & local_4f8, 0, 0x4d0);
  local_5c0.ExceptionRecord = (PEXCEPTION_RECORD)&local_598;
  local_5c0.ContextRecord = (PCONTEXT)&local_4f8;
  RtlCaptureContext(&local_4f8);
  FunctionEntry = RtlLookupFunctionEntry(local_4f8.Rip, &local_5c8, (PUNWIND_HISTORY_TABLE)0x0);
  if (FunctionEntry != (PRUNTIME_FUNCTION)0x0)
  {
    RtlVirtualUnwind(0, local_5c8, local_4f8.Rip, FunctionEntry, (PCONTEXT)&local_4f8, local_5a8,
                     &local_5b0, (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
  }
  local_4f8.Rsp = (DWORD64)auStackX8;
  local_598.ExceptionCode = param_2;
  local_598.ExceptionFlags = param_3;
  BVar1 = IsDebuggerPresent();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar2 = UnhandledExceptionFilter(&local_5c0);
  if (((LVar2 == 0) && (BVar1 == 0)) && (param_1 != -1))
  {
    FUN_180035448();
  }
  FUN_180034d00(local_28 ^ (ulonglong)&stack0xfffffffffffff9f8);
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _invalid_parameter
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void _invalid_parameter(wchar_t *param_1, wchar_t *param_2, wchar_t *param_3, uint param_4,
                        uintptr_t param_5)
{
  __acrt_ptd *p_Var1;
  byte bVar2;
  code *pcVar3;

  p_Var1 = FUN_18006a8c4();
  if (((p_Var1 == (__acrt_ptd *)0x0) || (pcVar3 = *(code **)(p_Var1 + 0x3b8), pcVar3 == (code *)0x0)) && (bVar2 = (byte)DAT_1800ee160 & 0x3f,
                                                                                                          pcVar3 = (code *)((DAT_1800ee160 ^ _DAT_180101ce0) >> bVar2 |
                                                                                                                            (DAT_1800ee160 ^ _DAT_180101ce0) << 0x40 - bVar2),
                                                                                                          pcVar3 == (code *)0x0))
  {
    _invoke_watson(param_1, param_2, param_3, param_4, param_5);
    pcVar3 = (code *)swi(3);
    (*pcVar3)();
    return;
  }
  (*pcVar3)();
  return;
}

// Library Function - Single Match
//  _invoke_watson
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void _invoke_watson(wchar_t *param_1, wchar_t *param_2, wchar_t *param_3, uint param_4,
                    uintptr_t param_5)
{
  code *pcVar1;
  BOOL BVar2;
  HANDLE hProcess;
  undefined *puVar3;
  undefined auStack40[8];
  undefined auStack32[32];

  puVar3 = auStack40;
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0)
  {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)();
    puVar3 = auStack32;
  }
  *(undefined8 *)(puVar3 + -8) = 0x18006740a;
  __acrt_call_reportfault(2, 0xc0000417, 1, puVar3[-8]);
  *(undefined8 *)(puVar3 + -8) = 0x180067410;
  hProcess = GetCurrentProcess(puVar3[-8]);
  // WARNING: Could not recover jumptable at 0x00018006741c. Too many branches
  // WARNING: Treating indirect jump as call
  TerminateProcess(hProcess, 0xc0000417, puVar3[0x28]);
  return;
}

// Library Function - Single Match
//  __acrt_errno_from_os_error
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __acrt_errno_from_os_error(int param_1)
{
  uint uVar1;
  undefined4 uVar2;
  ulonglong uVar3;
  int *piVar4;

  uVar3 = 0;
  piVar4 = &DAT_1800ca190;
  do
  {
    if (param_1 == *piVar4)
    {
      return *(undefined4 *)((longlong)&DAT_1800ca194 + uVar3 * 8);
    }
    uVar1 = (int)uVar3 + 1;
    uVar3 = (ulonglong)uVar1;
    piVar4 = piVar4 + 2;
  } while (uVar1 < 0x2c);
  if (param_1 - 0x13U < 0x12)
  {
    return 0xd;
  }
  uVar2 = 0x16;
  if (param_1 - 0xbcU < 0xf)
  {
    uVar2 = 8;
  }
  return uVar2;
}

// Library Function - Single Match
//  __acrt_errno_map_os_error
//
// Library: Visual Studio 2015 Release

void __acrt_errno_map_os_error(int param_1)
{
  undefined4 uVar1;
  __acrt_ptd *p_Var2;
  int *piVar3;
  undefined4 *puVar4;

  p_Var2 = FUN_18006a8c4();
  if (p_Var2 == (__acrt_ptd *)0x0)
  {
    piVar3 = &DAT_1800ee594;
  }
  else
  {
    piVar3 = (int *)(p_Var2 + 0x24);
  }
  *piVar3 = param_1;
  p_Var2 = FUN_18006a8c4();
  puVar4 = &DAT_1800ee590;
  if (p_Var2 != (__acrt_ptd *)0x0)
  {
    puVar4 = (undefined4 *)(p_Var2 + 0x20);
  }
  uVar1 = __acrt_errno_from_os_error(param_1);
  *puVar4 = uVar1;
  return;
}

// Library Function - Single Match
//  __doserrno
//
// Library: Visual Studio 2015 Release

ulong *__doserrno(void)
{
  __acrt_ptd *p_Var1;
  ulong *puVar2;

  p_Var1 = FUN_18006a8c4();
  if (p_Var1 == (__acrt_ptd *)0x0)
  {
    puVar2 = &DAT_1800ee594;
  }
  else
  {
    puVar2 = (ulong *)(p_Var1 + 0x24);
  }
  return puVar2;
}

// Library Function - Single Match
//  __doserrno
//
// Library: Visual Studio 2015 Release

ulong *__doserrno(void)
{
  __acrt_ptd *p_Var1;
  ulong *puVar2;

  p_Var1 = FUN_18006a8c4();
  if (p_Var1 == (__acrt_ptd *)0x0)
  {
    puVar2 = &DAT_1800ee590;
  }
  else
  {
    puVar2 = (ulong *)(p_Var1 + 0x20);
  }
  return puVar2;
}

// Library Function - Single Match
//  _get_errno
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t _get_errno(int *_Value)
{
  errno_t eVar1;
  __acrt_ptd *p_Var2;
  int *piVar3;

  if (_Value == (int *)0x0)
  {
    FUN_18006738c();
    eVar1 = 0x16;
  }
  else
  {
    p_Var2 = FUN_18006a8c4();
    if (p_Var2 == (__acrt_ptd *)0x0)
    {
      piVar3 = &DAT_1800ee590;
    }
    else
    {
      piVar3 = (int *)(p_Var2 + 0x20);
    }
    *_Value = *piVar3;
    eVar1 = 0;
  }
  return eVar1;
}

// Library Function - Single Match
//  _set_doserrno
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t _set_doserrno(ulong _Value)
{
  errno_t eVar1;
  __acrt_ptd *p_Var2;
  ulong *puVar3;

  p_Var2 = FUN_18006a8c4();
  if (p_Var2 == (__acrt_ptd *)0x0)
  {
    eVar1 = 0xc;
  }
  else
  {
    p_Var2 = FUN_18006a8c4();
    if (p_Var2 == (__acrt_ptd *)0x0)
    {
      puVar3 = &DAT_1800ee594;
    }
    else
    {
      puVar3 = (ulong *)(p_Var2 + 0x24);
    }
    *puVar3 = _Value;
    eVar1 = 0;
  }
  return eVar1;
}

// Library Function - Single Match
//  _set_errno
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t _set_errno(int _Value)
{
  errno_t eVar1;
  __acrt_ptd *p_Var2;
  int *piVar3;

  p_Var2 = FUN_18006a8c4();
  if (p_Var2 == (__acrt_ptd *)0x0)
  {
    eVar1 = 0xc;
  }
  else
  {
    p_Var2 = FUN_18006a8c4();
    if (p_Var2 == (__acrt_ptd *)0x0)
    {
      piVar3 = &DAT_1800ee590;
    }
    else
    {
      piVar3 = (int *)(p_Var2 + 0x20);
    }
    *piVar3 = _Value;
    eVar1 = 0;
  }
  return eVar1;
}

// WARNING: Unknown calling convention yet parameter storage is locked
// Library Function - Single Match
//  class __crt_stdio_stream __cdecl __acrt_stdio_allocate_stream(void)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

__crt_stdio_stream __acrt_stdio_allocate_stream(void)
{
  undefined8 *puVar1;
  __crt_stdio_stream _Var2;
  undefined7 extraout_var;
  undefined8 *in_RCX;

  *in_RCX = 0;
  __acrt_lock(8);
  _Var2 = find_or_allocate_unused_stream_nolock();
  puVar1 = *(undefined8 **)CONCAT71(extraout_var, _Var2);
  *in_RCX = puVar1;
  if (puVar1 != (undefined8 *)0x0)
  {
    *(undefined4 *)(puVar1 + 2) = 0;
    puVar1[5] = 0;
    *puVar1 = 0;
    puVar1[1] = 0;
    *(undefined4 *)(puVar1 + 3) = 0xffffffff;
  }
  __acrt_unlock(8);
  return SUB81(in_RCX, 0);
}

// Library Function - Single Match
//  void __cdecl __acrt_stdio_free_stream(class __crt_stdio_stream)
//
// Library: Visual Studio 2017 Release

void __acrt_stdio_free_stream(__crt_stdio_stream param_1)
{
  undefined7 in_register_00000009;

  *(undefined4 *)(CONCAT71(in_register_00000009, param_1) + 0x18) = 0xffffffff;
  *(undefined8 *)CONCAT71(in_register_00000009, param_1) = 0;
  *(undefined8 *)(CONCAT71(in_register_00000009, param_1) + 8) = 0;
  *(undefined4 *)(CONCAT71(in_register_00000009, param_1) + 0x10) = 0;
  *(undefined8 *)(CONCAT71(in_register_00000009, param_1) + 0x1c) = 0;
  *(undefined8 *)(CONCAT71(in_register_00000009, param_1) + 0x28) = 0;
  *(undefined4 *)(CONCAT71(in_register_00000009, param_1) + 0x14) = 0;
  return;
}

// WARNING: Unknown calling convention yet parameter storage is locked
// Library Function - Single Match
//  class __crt_stdio_stream __cdecl find_or_allocate_unused_stream_nolock(void)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

__crt_stdio_stream find_or_allocate_unused_stream_nolock(void)
{
  uint *puVar1;
  LPVOID *ppvVar2;
  uint uVar3;
  LPVOID pvVar4;
  LPVOID *in_RCX;
  LPVOID *ppvVar5;

  ppvVar5 = (LPVOID *)(DAT_180101938 + 0x18);
  ppvVar2 = ppvVar5 + (longlong)DAT_180101930 + -3;
  do
  {
    if (ppvVar5 == ppvVar2)
    {
    LAB_1800677d2:
      *in_RCX = (LPVOID)0x0;
    LAB_1800677d6:
      return SUB81(in_RCX, 0);
    }
    pvVar4 = *ppvVar5;
    if (pvVar4 == (LPVOID)0x0)
    {
      pvVar4 = _calloc_base(1, 0x58);
      *ppvVar5 = pvVar4;
      _free_base((LPVOID)0x0);
      if (*ppvVar5 != (LPVOID)0x0)
      {
        *(undefined4 *)((longlong)*ppvVar5 + 0x18) = 0xffffffff;
        __acrt_InitializeCriticalSectionEx((LPCRITICAL_SECTION)((longlong)*ppvVar5 + 0x30), 4000);
        pvVar4 = *ppvVar5;
        LOCK();
        *(uint *)((longlong)pvVar4 + 0x14) = *(uint *)((longlong)pvVar4 + 0x14) | 0x2000;
        FUN_1800625f0((longlong)pvVar4);
      LAB_1800677cd:
        *in_RCX = pvVar4;
        goto LAB_1800677d6;
      }
      goto LAB_1800677d2;
    }
    if ((*(uint *)((longlong)pvVar4 + 0x14) >> 0xd & 1) == 0)
    {
      FUN_1800625f0((longlong)pvVar4);
      uVar3 = *(uint *)((longlong)pvVar4 + 0x14);
      while (true)
      {
        LOCK();
        puVar1 = (uint *)((longlong)pvVar4 + 0x14);
        if (uVar3 == *puVar1)
          break;
        uVar3 = *puVar1;
      }
      *puVar1 = uVar3 | 0x2000;
      if ((~(byte)(uVar3 >> 0xd) & 1) != 0)
        goto LAB_1800677cd;
      FUN_1800625fc((longlong)pvVar4);
    }
    ppvVar5 = ppvVar5 + 1;
  } while (true);
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Multiple Matches With Different Base Names
//  _openfile
//  _wopenfile
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

FILE *FID_conflict__wopenfile(wchar_t *_Filename, wchar_t *_Mode, int _ShFlag, FILE *_File)
{
  uint *puVar1;
  undefined8 uVar2;
  errno_t eVar3;
  undefined8 *puVar4;
  FILE *pFVar5;
  int local_res18[2];
  int local_28;
  uint uStack36;
  undefined8 local_18[2];

  puVar4 = FUN_180067834(local_18, (char *)_Mode);
  uVar2 = *puVar4;
  pFVar5 = (FILE *)0x0;
  if ((char)*(undefined4 *)(puVar4 + 1) != '\0')
  {
    local_28 = (int)uVar2;
    eVar3 = FID_conflict__sopen_s(local_res18, (char *)_Filename, local_28, _ShFlag, 0x180);
    if (eVar3 == 0)
    {
      _DAT_180101940 = _DAT_180101940 + 1;
      uStack36 = (uint)((ulonglong)uVar2 >> 0x20);
      LOCK();
      puVar1 = (uint *)((longlong)&_File->_base + 4);
      *puVar1 = *puVar1 | uStack36;
      *(undefined4 *)&_File->_base = 0;
      _File->_tmpfname = (char *)0x0;
      *(undefined8 *)&_File->_cnt = 0;
      _File->_ptr = (char *)0x0;
      _File->_flag = local_res18[0];
      pFVar5 = _File;
    }
  }
  return pFVar5;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Multiple Matches With Different Base Names
//  _openfile
//  _wopenfile
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

FILE *FID_conflict__wopenfile(wchar_t *_Filename, wchar_t *_Mode, int _ShFlag, FILE *_File)
{
  uint *puVar1;
  undefined8 uVar2;
  errno_t eVar3;
  undefined8 *puVar4;
  FILE *pFVar5;
  int local_res18[2];
  int local_28;
  uint uStack36;
  undefined8 local_18[2];

  puVar4 = FUN_180067ae0(local_18, _Mode);
  uVar2 = *puVar4;
  pFVar5 = (FILE *)0x0;
  if ((char)*(undefined4 *)(puVar4 + 1) != '\0')
  {
    local_28 = (int)uVar2;
    eVar3 = FID_conflict__sopen_s(local_res18, (char *)_Filename, local_28, _ShFlag, 0x180);
    if (eVar3 == 0)
    {
      _DAT_180101940 = _DAT_180101940 + 1;
      uStack36 = (uint)((ulonglong)uVar2 >> 0x20);
      LOCK();
      puVar1 = (uint *)((longlong)&_File->_base + 4);
      *puVar1 = *puVar1 | uStack36;
      *(undefined4 *)&_File->_base = 0;
      _File->_tmpfname = (char *)0x0;
      *(undefined8 *)&_File->_cnt = 0;
      _File->_ptr = (char *)0x0;
      _File->_flag = local_res18[0];
      pFVar5 = _File;
    }
  }
  return pFVar5;
}

// Library Function - Single Match
//  _isalnum_l
//
// Library: Visual Studio 2015 Release

int _isalnum_l(int _C, _locale_t _Locale)
{
  uint uVar1;
  __acrt_ptd *local_28;
  localeinfo_struct local_20;
  char local_10;

  FUN_18004e538(&local_28, (undefined4 *)_Locale);
  if ((int)(local_20.locinfo)->lc_collate_cp < 2)
  {
    uVar1 = *(ushort *)(*(longlong *)local_20.locinfo + (longlong)_C * 2) & 0x107;
  }
  else
  {
    uVar1 = _isctype_l(_C, 0x107, (_locale_t)&local_20);
  }
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return (int)uVar1;
}

// Library Function - Single Match
//  _isalpha_l
//
// Library: Visual Studio 2015 Release

int _isalpha_l(int _C, _locale_t _Locale)
{
  uint uVar1;
  __acrt_ptd *local_28;
  localeinfo_struct local_20;
  char local_10;

  FUN_18004e538(&local_28, (undefined4 *)_Locale);
  if ((int)(local_20.locinfo)->lc_collate_cp < 2)
  {
    uVar1 = *(ushort *)(*(longlong *)local_20.locinfo + (longlong)_C * 2) & 0x103;
  }
  else
  {
    uVar1 = _isctype_l(_C, 0x103, (_locale_t)&local_20);
  }
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return (int)uVar1;
}

// Library Function - Single Match
//  _isblank_l
//
// Library: Visual Studio 2015 Release

uint _isblank_l(int param_1, undefined4 *param_2)
{
  uint uVar1;
  __acrt_ptd *local_28;
  localeinfo_struct local_20;
  char local_10;

  FUN_18004e538(&local_28, param_2);
  if (param_1 == 9)
  {
    uVar1 = 0x40;
  }
  else
  {
    if ((int)(local_20.locinfo)->lc_collate_cp < 2)
    {
      uVar1 = *(ushort *)(*(longlong *)local_20.locinfo + (longlong)param_1 * 2) & 0x40;
    }
    else
    {
      uVar1 = _isctype_l(param_1, 0x40, (_locale_t)&local_20);
    }
  }
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return uVar1;
}

// Library Function - Single Match
//  _iscntrl_l
//
// Library: Visual Studio 2015 Release

int _iscntrl_l(int _C, _locale_t _Locale)
{
  uint uVar1;
  __acrt_ptd *local_28;
  localeinfo_struct local_20;
  char local_10;

  FUN_18004e538(&local_28, (undefined4 *)_Locale);
  if ((int)(local_20.locinfo)->lc_collate_cp < 2)
  {
    uVar1 = *(ushort *)(*(longlong *)local_20.locinfo + (longlong)_C * 2) & 0x20;
  }
  else
  {
    uVar1 = _isctype_l(_C, 0x20, (_locale_t)&local_20);
  }
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return (int)uVar1;
}

// Library Function - Single Match
//  _iscsymf_l
//
// Library: Visual Studio 2015 Release

undefined8 _iscsymf_l(int param_1, undefined4 *param_2)
{
  uint uVar1;
  undefined8 uVar2;
  __acrt_ptd *local_28;
  localeinfo_struct local_20;
  char local_10;

  FUN_18004e538(&local_28, param_2);
  if ((int)(local_20.locinfo)->lc_collate_cp < 2)
  {
    uVar1 = *(ushort *)(*(longlong *)local_20.locinfo + (longlong)param_1 * 2) & 0x103;
  }
  else
  {
    uVar1 = _isctype_l(param_1, 0x103, (_locale_t)&local_20);
  }
  uVar2 = 0;
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  if ((uVar1 != 0) || (param_1 == 0x5f))
  {
    uVar2 = 1;
  }
  return uVar2;
}

// Library Function - Single Match
//  _isdigit_l
//
// Library: Visual Studio 2015 Release

int _isdigit_l(int _C, _locale_t _Locale)
{
  uint uVar1;
  __acrt_ptd *local_28;
  localeinfo_struct local_20;
  char local_10;

  FUN_18004e538(&local_28, (undefined4 *)_Locale);
  if ((int)(local_20.locinfo)->lc_collate_cp < 2)
  {
    uVar1 = *(ushort *)(*(longlong *)local_20.locinfo + (longlong)_C * 2) & 4;
  }
  else
  {
    uVar1 = _isctype_l(_C, 4, (_locale_t)&local_20);
  }
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return (int)uVar1;
}

// Library Function - Single Match
//  _islower_l
//
// Library: Visual Studio 2015 Release

int _islower_l(int _C, _locale_t _Locale)
{
  uint uVar1;
  __acrt_ptd *local_28;
  localeinfo_struct local_20;
  char local_10;

  FUN_18004e538(&local_28, (undefined4 *)_Locale);
  if ((int)(local_20.locinfo)->lc_collate_cp < 2)
  {
    uVar1 = *(ushort *)(*(longlong *)local_20.locinfo + (longlong)_C * 2) & 2;
  }
  else
  {
    uVar1 = _isctype_l(_C, 2, (_locale_t)&local_20);
  }
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return (int)uVar1;
}

// Library Function - Single Match
//  _ispunct_l
//
// Library: Visual Studio 2015 Release

int _ispunct_l(int _C, _locale_t _Locale)
{
  uint uVar1;
  __acrt_ptd *local_28;
  localeinfo_struct local_20;
  char local_10;

  FUN_18004e538(&local_28, (undefined4 *)_Locale);
  if ((int)(local_20.locinfo)->lc_collate_cp < 2)
  {
    uVar1 = *(ushort *)(*(longlong *)local_20.locinfo + (longlong)_C * 2) & 0x10;
  }
  else
  {
    uVar1 = _isctype_l(_C, 0x10, (_locale_t)&local_20);
  }
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return (int)uVar1;
}

// WARNING: Could not reconcile some variable overlaps
// Library Function - Single Match
//  _tolower_l
//
// Library: Visual Studio 2015 Release

int _tolower_l(int _C, _locale_t _Locale)
{
  int iVar1;
  ulonglong uVar2;
  ulong *puVar3;
  ushort local_res8;
  undefined local_resa;
  undefined2 local_res18;
  undefined local_res1a;
  __acrt_ptd *local_28;
  localeinfo_struct local_20;
  char local_10;

  FUN_18004e538(&local_28, (undefined4 *)_Locale);
  if ((uint)_C < 0x100)
  {
    uVar2 = FUN_180068fb0(_C, (_locale_t)&local_20);
    if ((char)uVar2 != '\0')
    {
      _C = ZEXT14((local_20.locinfo)->pclmap[_C]);
    }
  }
  else
  {
    local_res8 = 0;
    local_resa = 0;
    if (((int)(local_20.locinfo)->lc_collate_cp < 2) ||
        (iVar1 = _isleadbyte_l(_C >> 8 & 0xff, (_locale_t)&local_20), iVar1 == 0))
    {
      puVar3 = __doserrno();
      iVar1 = 1;
      *puVar3 = 0x2a;
      local_res8 = (ushort)(byte)_C;
    }
    else
    {
      iVar1 = 2;
      local_res8 = CONCAT11((byte)_C, (char)((uint)_C >> 8));
      local_resa = 0;
    }
    local_res18 = 0;
    local_res1a = 0;
    iVar1 = __acrt_LCMapStringA((undefined4 *)&local_20, (longlong)(local_20.locinfo)->locale_name[2], 0x100, (char *)&local_res8, iVar1, &local_res18, 3,
                                (local_20.locinfo)->lc_time_cp, 1);
    if (iVar1 != 0)
    {
      _C = ZEXT14((byte)local_res18);
      if (iVar1 != 1)
      {
        if (local_10 == '\0')
        {
          return (uint)CONCAT11((byte)local_res18, local_res18._1_1_);
        }
        *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
        return (uint)CONCAT11((byte)local_res18, local_res18._1_1_);
      }
    }
  }
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return _C;
}

// Library Function - Single Match
//  tolower
//
// Library: Visual Studio 2017 Release

int tolower(int _C)
{
  if (DAT_180101d00 == 0)
  {
    if (_C - 0x41U < 0x1a)
    {
      _C = _C + 0x20;
    }
  }
  else
  {
    _C = _tolower_l(_C, (_locale_t)0x0);
  }
  return _C;
}

// Library Function - Single Match
//  wctomb_s
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t wctomb_s(int *_SizeConverted, char *_MbCh, rsize_t _SizeInBytes, wchar_t _WCh)
{
  undefined8 uVar1;

  uVar1 = FUN_180069c28(_SizeConverted, (undefined(*)[16])_MbCh, _SizeInBytes, _WCh, (undefined4 *)0x0);
  return (errno_t)uVar1;
}

// Library Function - Multiple Matches With Same Base Name
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_0ae27a3a962d80f24befdcbee591983d>,class <lambda_8d0ee55de4b1038c4002e0adecdf1839>&
// __ptr64,class <lambda_dc504788e8f1664fe9b84e20bfb512f2>>(class
// <lambda_0ae27a3a962d80f24befdcbee591983d>&& __ptr64,class
// <lambda_8d0ee55de4b1038c4002e0adecdf1839>& __ptr64,class
// <lambda_dc504788e8f1664fe9b84e20bfb512f2>&& __ptr64) __ptr64
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_72d1df2b273a38828b1ce30cbf4cdab5>,class <lambda_876a65b173b8412d3a47c70a915b0cf4>&
// __ptr64,class <lambda_41932305e351933ebe8f8be3ed8bb5dc>>(class
// <lambda_72d1df2b273a38828b1ce30cbf4cdab5>&& __ptr64,class
// <lambda_876a65b173b8412d3a47c70a915b0cf4>& __ptr64,class
// <lambda_41932305e351933ebe8f8be3ed8bb5dc>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void operator____(undefined8 param_1, int *param_2, longlong **param_3, int *param_4)
{
  __acrt_lock(*param_2);
  LOCK();
  **(int **)(**param_3 + 0x88) = **(int **)(**param_3 + 0x88) + 1;
  __acrt_unlock(*param_4);
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_2d41944a1d46af3157314b8a01080d33>,class <lambda_8f455de75cd7d7f24b4096f044d8b9e6>&
// __ptr64,class <lambda_aa500f224e6afead328df44964fe2772>>(class
// <lambda_2d41944a1d46af3157314b8a01080d33>&& __ptr64,class
// <lambda_8f455de75cd7d7f24b4096f044d8b9e6>& __ptr64,class
// <lambda_aa500f224e6afead328df44964fe2772>&& __ptr64) __ptr64
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_fb3a7dec4e47f37f22dae91bb15c9095>,class <lambda_698284760c8add0bfb0756c19673e34b>&
// __ptr64,class <lambda_dfb8eca1e75fef3034a8fb18dd509707>>(class
// <lambda_fb3a7dec4e47f37f22dae91bb15c9095>&& __ptr64,class
// <lambda_698284760c8add0bfb0756c19673e34b>& __ptr64,class
// <lambda_dfb8eca1e75fef3034a8fb18dd509707>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void operator____(undefined8 param_1, int *param_2, __acrt_ptd **param_3, int *param_4)
{
  __acrt_lock(*param_2);
  replace_current_thread_locale_nolock(*(__acrt_ptd **)*param_3, (__crt_locale_data *)0x0);
  __acrt_unlock(*param_4);
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_5e887d1dcbef67a5eb4283622ba103bf>,class <lambda_4466841279450cc726390878d4a41900>&
// __ptr64,class <lambda_341c25c0346d94847f1f3c463c57e077>>(class
// <lambda_5e887d1dcbef67a5eb4283622ba103bf>&& __ptr64,class
// <lambda_4466841279450cc726390878d4a41900>& __ptr64,class
// <lambda_341c25c0346d94847f1f3c463c57e077>&& __ptr64) __ptr64
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_aa87e3671a710a21b5dc78c0bdf72e11>,class <lambda_92619d2358a28f41a33ba319515a20b9>&
// __ptr64,class <lambda_6992ecaafeb10aed2b74cb1fae11a551>>(class
// <lambda_aa87e3671a710a21b5dc78c0bdf72e11>&& __ptr64,class
// <lambda_92619d2358a28f41a33ba319515a20b9>& __ptr64,class
// <lambda_6992ecaafeb10aed2b74cb1fae11a551>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void operator____(undefined8 param_1, int *param_2, __acrt_ptd **param_3, int *param_4)
{
  __acrt_lock(*param_2);
  replace_current_thread_locale_nolock(*(__acrt_ptd **)*param_3, **(__crt_locale_data ***)param_3[1]);
  __acrt_unlock(*param_4);
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_46352004c1216016012b18bd6f87e700>,class <lambda_3bd07e1a1191394380780325891bf33f>&
// __ptr64,class <lambda_334532d3f185bcaa59b5be82d7d22bff>>(class
// <lambda_46352004c1216016012b18bd6f87e700>&& __ptr64,class
// <lambda_3bd07e1a1191394380780325891bf33f>& __ptr64,class
// <lambda_334532d3f185bcaa59b5be82d7d22bff>&& __ptr64) __ptr64
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_f2e299630e499de9f9a165e60fcd3db5>,class <lambda_2ae9d31cdba2644fcbeaf08da7c24588>&
// __ptr64,class <lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>>(class
// <lambda_f2e299630e499de9f9a165e60fcd3db5>&& __ptr64,class
// <lambda_2ae9d31cdba2644fcbeaf08da7c24588>& __ptr64,class
// <lambda_40d01ff24d0e7b3814fdbdcee8eab3c7>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void operator____(undefined8 param_1, int *param_2, longlong **param_3, int *param_4)
{
  int iVar1;
  int *piVar2;

  __acrt_lock(*param_2);
  piVar2 = *(int **)(**param_3 + 0x88);
  if (piVar2 != (int *)0x0)
  {
    LOCK();
    iVar1 = *piVar2;
    *piVar2 = *piVar2 + -1;
    if ((iVar1 == 1) && (piVar2 != (int *)&DAT_1800ee910))
    {
      _free_base(piVar2);
    }
  }
  __acrt_unlock(*param_4);
  return;
}

// Library Function - Single Match
//  void __cdecl construct_ptd_array(struct __acrt_ptd * __ptr64 const)
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void construct_ptd_array(__acrt_ptd *param_1)
{
  undefined local_res10[8];
  int local_res18[2];
  int local_res20[2];
  int local_38;
  int local_34;
  __acrt_ptd *local_30;
  undefined8 *local_28;
  __acrt_ptd **local_20;
  __acrt_ptd **local_18;
  undefined8 **local_10;

  local_20 = &local_30;
  local_res18[0] = 5;
  local_res20[0] = 5;
  local_18 = &local_30;
  local_10 = &local_28;
  local_38 = 4;
  local_34 = 4;
  local_28 = &DAT_180101d08;
  *(undefined4 *)(param_1 + 0x28) = 1;
  *(undefined **)param_1 = &DAT_1800c9f30;
  *(undefined4 *)(param_1 + 0x3a8) = 1;
  *(undefined **)(param_1 + 0x88) = &DAT_1800ee910;
  *(undefined2 *)(param_1 + 0xbc) = 0x43;
  *(undefined2 *)(param_1 + 0x1c2) = 0x43;
  *(undefined8 *)(param_1 + 0x3a0) = 0;
  local_30 = param_1;
  operator____(local_res10, local_res20, (longlong **)&local_20, local_res18);
  operator____(local_res10, &local_34, (__acrt_ptd **)&local_18, &local_38);
  return;
}

// Library Function - Single Match
//  void __cdecl destroy_ptd_array(struct __acrt_ptd * __ptr64 const)
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void destroy_ptd_array(__acrt_ptd *param_1)
{
  undefined local_res10[8];
  int local_res18[2];
  int local_res20[2];
  int local_28;
  int local_24;
  __acrt_ptd *local_20;
  __acrt_ptd **local_18;
  __acrt_ptd **local_10;

  local_18 = &local_20;
  local_res18[0] = 5;
  local_res20[0] = 5;
  local_10 = &local_20;
  local_28 = 4;
  local_24 = 4;
  local_20 = param_1;
  if (*(undefined **)param_1 != &DAT_1800c9f30)
  {
    _free_base(*(undefined **)param_1);
  }
  _free_base(*(LPVOID *)(local_20 + 0x70));
  _free_base(*(LPVOID *)(local_20 + 0x58));
  _free_base(*(LPVOID *)(local_20 + 0x60));
  _free_base(*(LPVOID *)(local_20 + 0x68));
  _free_base(*(LPVOID *)(local_20 + 0x48));
  _free_base(*(LPVOID *)(local_20 + 0x50));
  _free_base(*(LPVOID *)(local_20 + 0x78));
  _free_base(*(LPVOID *)(local_20 + 0x80));
  _free_base(*(LPVOID *)(local_20 + 0x3c0));
  operator____(local_res10, local_res20, (longlong **)&local_18, local_res18);
  operator____(local_res10, &local_24, (__acrt_ptd **)&local_10, &local_28);
  return;
}

// Library Function - Single Match
//  void __cdecl replace_current_thread_locale_nolock(struct __acrt_ptd * __ptr64 const,struct
// __crt_locale_data * __ptr64 const)
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void replace_current_thread_locale_nolock(__acrt_ptd *param_1, __crt_locale_data *param_2)
{
  undefined **ppuVar1;

  if (*(longlong *)(param_1 + 0x90) != 0)
  {
    __acrt_release_locale_ref(*(longlong *)(param_1 + 0x90));
    ppuVar1 = *(undefined ***)(param_1 + 0x90);
    if (((ppuVar1 != DAT_180101d08) && (ppuVar1 != &PTR_DAT_1800ee5b0)) &&
        (*(int *)(ppuVar1 + 2) == 0))
    {
      __acrt_free_locale(ppuVar1);
    }
  }
  *(__crt_locale_data **)(param_1 + 0x90) = param_2;
  if (param_2 != (__crt_locale_data *)0x0)
  {
    FUN_18007c1ec((longlong)param_2);
  }
  return;
}

// Library Function - Single Match
//  __acrt_freeptd
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_freeptd(void)
{
  __acrt_ptd *p_Var1;

  if (DAT_1800ee598 != 0xffffffff)
  {
    p_Var1 = (__acrt_ptd *)__acrt_FlsGetValue(DAT_1800ee598);
    if (p_Var1 != (__acrt_ptd *)0x0)
    {
      __acrt_FlsSetValue(DAT_1800ee598, (LPVOID)0x0);
      destroy_ptd_array(p_Var1);
      _free_base(p_Var1);
    }
  }
  return;
}

// Library Function - Multiple Matches With Different Base Names
//  __acrt_uninitialize_ptd
//  __vcrt_uninitialize_ptd
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined __acrt_uninitialize_ptd(void)
{
  if (DAT_1800ee598 != 0xffffffff)
  {
    __acrt_FlsFree(DAT_1800ee598);
    DAT_1800ee598 = 0xffffffff;
  }
  return 1;
}

// Library Function - Single Match
//  __acrt_update_locale_info
//
// Library: Visual Studio 2015 Release

void __acrt_update_locale_info(longlong param_1, undefined **param_2)
{
  undefined **ppuVar1;

  if ((*param_2 != DAT_180101d08) && ((DAT_1800eee60 & *(uint *)(param_1 + 0x3a8)) == 0))
  {
    ppuVar1 = __acrt_update_thread_locale_data();
    *param_2 = (undefined *)ppuVar1;
  }
  return;
}

// Library Function - Single Match
//  __acrt_update_multibyte_info
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_update_multibyte_info(longlong param_1, longlong *param_2)
{
  longlong lVar1;

  if ((*param_2 != DAT_180102600) && ((DAT_1800eee60 & *(uint *)(param_1 + 0x3a8)) == 0))
  {
    lVar1 = __acrt_update_thread_multibyte_data();
    *param_2 = lVar1;
  }
  return;
}

// Library Function - Single Match
//  int __cdecl fp_format_e(double const * __ptr64 const,char * __ptr64 const,unsigned __int64,char
// * __ptr64 const,unsigned __int64,int,bool,unsigned int,struct __crt_locale_pointers * __ptr64
// const)
//
// Library: Visual Studio 2017 Release

int fp_format_e(double *param_1, char *param_2, __uint64 param_3, char *param_4, __uint64 param_5,
                int param_6, bool param_7, uint param_8, __crt_locale_pointers *param_9)
{
  ulong uVar1;
  ulonglong uVar2;
  int local_18[4];

  uVar2 = (ulonglong)(param_6 + 2) + 1;
  if (uVar2 < param_5)
  {
    param_5 = uVar2;
  }
  FUN_18007eb4c((ulonglong)*param_1, param_6 + 1, local_18, param_4, param_5);
  uVar2 = (param_3 - (0 < param_6)) - (ulonglong)(local_18[0] == 0x2d);
  if (param_3 == 0xffffffffffffffff)
  {
    uVar2 = param_3;
  }
  uVar1 = __acrt_fp_strflt_to_string((undefined8 *)(param_2 + (ulonglong)(local_18[0] == 0x2d) + (ulonglong)(0 < param_6)), uVar2,
                                     param_6 + 1, (longlong)local_18);
  if (uVar1 == 0)
  {
    uVar1 = fp_format_e_internal(param_2, param_3, param_6, param_7, param_8, (_strflt *)local_18, false, param_9);
  }
  else
  {
    *param_2 = '\0';
  }
  return (int)uVar1;
}

// Library Function - Single Match
//  int __cdecl fp_format_e_internal(char * __ptr64 const,unsigned __int64,int,bool,unsigned
// int,struct _strflt * __ptr64 const,bool,struct __crt_locale_pointers * __ptr64 const)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int fp_format_e_internal(char *param_1, __uint64 param_2, int param_3, bool param_4, uint param_5, _strflt *param_6, bool param_7, __crt_locale_pointers *param_8)
{
  code *pcVar1;
  errno_t eVar2;
  ulong *puVar3;
  undefined8 *puVar4;
  char *pcVar5;
  char *_SizeInBytes;
  int iVar6;
  longlong lVar7;
  __acrt_ptd *local_28;
  longlong local_20;
  char local_10;
  longlong lVar8;

  iVar6 = 0;
  if (0 < param_3)
  {
    iVar6 = param_3;
  }
  if ((ulonglong)(longlong)(iVar6 + 9) < param_2)
  {
    FUN_18004e538(&local_28, (undefined4 *)param_8);
    if ((param_7 != false) &&
        (puVar4 = (undefined8 *)(param_1 + (*(int *)param_6 == 0x2d)), 0 < param_3))
    {
      lVar7 = -1;
      do
      {
        lVar8 = lVar7;
        lVar7 = lVar8 + 1;
      } while (*(char *)((longlong)puVar4 + lVar7) != '\0');
      FUN_18003b8e0((undefined8 *)((longlong)puVar4 + 1), puVar4, lVar8 + 2);
    }
    pcVar5 = param_1;
    if (*(int *)param_6 == 0x2d)
    {
      *param_1 = '-';
      pcVar5 = param_1 + 1;
    }
    if (0 < param_3)
    {
      *pcVar5 = pcVar5[1];
      pcVar5 = pcVar5 + 1;
      *pcVar5 = ***(char ***)(local_20 + 0xf8);
    }
    pcVar5 = pcVar5 + ((ulonglong)param_7 ^ 1) + (longlong)param_3;
    _SizeInBytes = param_1 + (param_2 - (longlong)pcVar5);
    if (param_2 == 0xffffffffffffffff)
    {
      _SizeInBytes = (char *)param_2;
    }
    eVar2 = strcpy_s(pcVar5, (rsize_t)_SizeInBytes, "e+000");
    if (eVar2 != 0)
    {
      _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
      pcVar1 = (code *)swi(3);
      iVar6 = (*pcVar1)();
      return iVar6;
    }
    if (param_4 != false)
    {
      *pcVar5 = 'E';
    }
    if (**(char **)(param_6 + 8) != '0')
    {
      iVar6 = *(int *)(param_6 + 4) + -1;
      if (iVar6 < 0)
      {
        iVar6 = -iVar6;
        pcVar5[1] = '-';
      }
      if (99 < iVar6)
      {
        pcVar5[2] = pcVar5[2] + (char)(iVar6 / 100);
        iVar6 = iVar6 % 100;
      }
      if (9 < iVar6)
      {
        pcVar5[3] = pcVar5[3] + (char)(iVar6 / 10);
        iVar6 = iVar6 % 10;
      }
      pcVar5[4] = pcVar5[4] + (char)iVar6;
    }
    if ((param_5 == 2) && (pcVar5[2] == '0'))
    {
      FUN_18003b8e0((undefined8 *)(pcVar5 + 2), (undefined8 *)(pcVar5 + 3), 3);
    }
    if (local_10 != '\0')
    {
      *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
    }
    iVar6 = 0;
  }
  else
  {
    puVar3 = __doserrno();
    iVar6 = 0x22;
    *puVar3 = 0x22;
    FUN_18006738c();
  }
  return iVar6;
}

// WARNING: Could not reconcile some variable overlaps
// Library Function - Single Match
//  int __cdecl fp_format_g(double const * __ptr64 const,char * __ptr64 const,unsigned __int64,char
// * __ptr64 const,unsigned __int64,int,bool,unsigned int,struct __crt_locale_pointers * __ptr64
// const)
//
// Library: Visual Studio 2017 Release

int fp_format_g(double *param_1, char *param_2, __uint64 param_3, char *param_4, __uint64 param_5,
                int param_6, bool param_7, uint param_8, __crt_locale_pointers *param_9)
{
  undefined8 *puVar1;
  ulong uVar2;
  undefined8 uVar3;
  ulonglong uVar4;
  undefined8 *puVar5;
  int iVar6;
  undefined8 local_18;
  undefined8 local_10;

  local_18 = 0;
  local_10 = 0;
  FUN_18007eb4c((ulonglong)*param_1, param_6, (int *)&local_18, param_4, param_5);
  iVar6 = local_18._4_4_ + -1;
  uVar4 = param_3 - ((int)local_18 == 0x2d);
  if (param_3 == 0xffffffffffffffff)
  {
    uVar4 = param_3;
  }
  uVar2 = __acrt_fp_strflt_to_string((undefined8 *)(param_2 + ((int)local_18 == 0x2d)), uVar4, param_6,
                                     (longlong)&local_18);
  if (uVar2 == 0)
  {
    local_18._4_4_ = local_18._4_4_ + -1;
    if ((local_18._4_4_ < -4) || (param_6 <= local_18._4_4_))
    {
      uVar2 = fp_format_e_internal(param_2, param_3, param_6, param_7, param_8, (_strflt *)&local_18, true, param_9);
    }
    else
    {
      puVar1 = (undefined8 *)(param_2 + ((int)local_18 == 0x2d));
      if (iVar6 < local_18._4_4_)
      {
        do
        {
          puVar5 = puVar1;
          puVar1 = (undefined8 *)((longlong)puVar5 + 1);
        } while (*(char *)puVar5 != '\0');
        *(undefined *)((longlong)puVar5 + -1) = 0;
      }
      uVar3 = FUN_18006b180((undefined8 *)param_2, param_3, param_6, (int *)&local_18, '\x01',
                            (undefined4 *)param_9);
      uVar2 = (ulong)uVar3;
    }
  }
  else
  {
    *param_2 = '\0';
  }
  return (int)uVar2;
}

// Library Function - Single Match
//  int __cdecl fp_format_nan_or_infinity(enum __acrt_fp_class,bool,char * __ptr64,unsigned
// __int64,bool)
//
// Library: Visual Studio 2017 Release

int fp_format_nan_or_infinity(__acrt_fp_class param_1, bool param_2, char *param_3, __uint64 param_4, bool param_5)
{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  errno_t eVar4;
  ulonglong uVar5;
  char *_Dst;
  longlong lVar6;
  char *local_98[4];
  undefined *local_78;
  undefined *local_70;
  undefined *local_68;
  undefined *local_60;
  char *local_58;
  undefined *local_50;
  char *local_48;
  undefined *local_40;
  char *local_38;
  undefined *local_30;
  char *local_28;
  undefined *local_20;
  ulonglong local_18;

  local_18 = DAT_1800ee160 ^ (ulonglong)&stack0xffffffffffffff38;
  if (param_4 < (ulonglong)param_2 + 4)
  {
    *param_3 = '\0';
  }
  else
  {
    _Dst = param_3;
    if (param_2 != false)
    {
      _Dst = param_3 + 1;
      *param_3 = '-';
      param_4 = param_4 - 1;
      *_Dst = '\0';
    }
    local_78 = &DAT_1800ca350;
    local_70 = &DAT_1800ca350;
    local_98[0] = "INF";
    local_98[1] = &DAT_1800ca348;
    local_98[2] = &DAT_1800ca34c;
    local_98[3] = &DAT_1800ca34c;
    local_58 = "NAN(SNAN)";
    local_48 = "nan(snan)";
    local_50 = &DAT_1800ca350;
    local_30 = &DAT_1800ca350;
    local_38 = "NAN(IND)";
    lVar6 = (ulonglong)(param_1 + 0xffffffff) * 4;
    local_28 = "nan(ind)";
    uVar2 = (param_5 ^ 1) * 2;
    local_68 = &DAT_1800ca354;
    local_60 = &DAT_1800ca354;
    uVar5 = 0xffffffffffffffff;
    local_40 = &DAT_1800ca354;
    local_20 = &DAT_1800ca354;
    do
    {
      uVar5 = uVar5 + 1;
    } while (local_98[(ulonglong)uVar2 + lVar6][uVar5] != '\0');
    eVar4 = strcpy_s(_Dst, param_4, local_98[(ulonglong)(uVar2 + (param_4 <= uVar5)) + lVar6]);
    if (eVar4 != 0)
    {
      _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
      pcVar1 = (code *)swi(3);
      iVar3 = (*pcVar1)();
      return iVar3;
    }
  }
  iVar3 = FUN_180034d00(local_18 ^ (ulonglong)&stack0xffffffffffffff38);
  return iVar3;
}

// WARNING: Could not reconcile some variable overlaps
// Library Function - Single Match
//  __acrt_fp_format
//
// Library: Visual Studio 2017 Release

ulonglong __acrt_fp_format(double *param_1, undefined8 *param_2, __uint64 param_3, char *param_4,
                           __uint64 param_5, int param_6, uint param_7, ulonglong param_8,
                           undefined4 *param_9)
{
  double dVar1;
  int iVar2;
  ulong uVar3;
  ulong *puVar4;
  undefined4 extraout_var;
  undefined4 extraout_var_00;
  undefined4 extraout_var_01;
  ulonglong uVar5;
  undefined4 extraout_var_02;
  undefined4 extraout_var_03;
  uint uVar6;
  bool bVar7;
  __acrt_fp_class _Var8;
  undefined8 local_18;
  undefined8 local_10;

  if ((((param_2 == (undefined8 *)0x0) || (param_3 == 0)) || (param_4 == (char *)0x0)) ||
      (param_5 == 0))
  {
    puVar4 = __doserrno();
    *puVar4 = 0x16;
    FUN_18006738c();
    return 0x16;
  }
  _Var8 = 1;
  if ((param_6 == 0x41) || (param_6 - 0x45U < 3))
  {
    bVar7 = true;
  }
  else
  {
    bVar7 = false;
  }
  if ((param_8 & 8) == 0)
  {
    dVar1 = *param_1;
    uVar6 = (uint)((ulonglong)dVar1 >> 0x20);
    if ((uVar6 >> 0x14 & 0x7ff) == 0x7ff)
    {
      if (((ulonglong)dVar1 & 0xfffffffffffff) != 0)
      {
        if (((longlong)dVar1 < 0) && (((ulonglong)dVar1 & 0xfffffffffffff) == 0x8000000000000))
        {
          _Var8 = 4;
        }
        else
        {
          _Var8 = ~(uVar6 >> 0x13) & 1 | 2;
        }
      }
      iVar2 = fp_format_nan_or_infinity(_Var8, SUB81((ulonglong)dVar1 >> 0x3f, 0), (char *)param_2, param_3, bVar7);
      return CONCAT44(extraout_var, iVar2);
    }
  }
  uVar6 = (uint)(param_8 >> 4) & 1 | 2;
  if (param_6 == 0x41)
  {
  LAB_18006b7aa:
    iVar2 = FUN_18006aad4(param_1, (char *)param_2, param_3, param_4, param_5, param_7, bVar7, uVar6,
                          param_9);
    uVar5 = CONCAT44(extraout_var_03, iVar2);
  }
  else
  {
    if (param_6 == 0x45)
    {
    LAB_18006b771:
      iVar2 = fp_format_e(param_1, (char *)param_2, param_3, param_4, param_5, param_7, bVar7, uVar6,
                          (__crt_locale_pointers *)param_9);
      return CONCAT44(extraout_var_02, iVar2);
    }
    if (param_6 == 0x46)
    {
    LAB_18006b6e7:
      local_18 = 0;
      local_10 = 0;
      FUN_18007eb4c((ulonglong)*param_1, param_7, (int *)&local_18, param_4, param_5);
      uVar5 = param_3 - ((int)local_18 == 0x2d);
      if (param_3 == 0xffffffffffffffff)
      {
        uVar5 = param_3;
      }
      uVar3 = __acrt_fp_strflt_to_string((undefined8 *)((ulonglong)((int)local_18 == 0x2d) + (longlong)param_2),
                                         uVar5, local_18._4_4_ + param_7, (longlong)&local_18);
      if (uVar3 != 0)
      {
        *(undefined *)param_2 = 0;
        return CONCAT44(extraout_var_01, uVar3);
      }
      uVar5 = FUN_18006b180(param_2, param_3, param_7, (int *)&local_18, '\0', param_9);
      return uVar5;
    }
    if (param_6 != 0x47)
    {
      if (param_6 == 0x61)
        goto LAB_18006b7aa;
      if (param_6 == 0x65)
        goto LAB_18006b771;
      if (param_6 == 0x66)
        goto LAB_18006b6e7;
    }
    iVar2 = fp_format_g(param_1, (char *)param_2, param_3, param_4, param_5, param_7, bVar7, uVar6,
                        (__crt_locale_pointers *)param_9);
    uVar5 = CONCAT44(extraout_var_00, iVar2);
  }
  return uVar5;
}

// Library Function - Single Match
//  _fileno
//
// Library: Visual Studio 2015 Release

int _fileno(FILE *_File)
{
  int iVar1;
  ulong *puVar2;

  if (_File == (FILE *)0x0)
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
    iVar1 = -1;
  }
  else
  {
    iVar1 = _File->_flag;
  }
  return iVar1;
}

// Library Function - Single Match
//  _fputc_nolock
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong _fputc_nolock(byte param_1, FILE *param_2)
{
  char **ppcVar1;
  uint *puVar2;
  bool bVar3;
  int iVar4;
  ulong *puVar5;
  FILE *pFVar6;

  ppcVar1 = &param_2->_base;
  *(int *)ppcVar1 = *(int *)ppcVar1 + -1;
  if (-1 < *(int *)ppcVar1)
  {
    *param_2->_ptr = param_1;
    param_2->_ptr = param_2->_ptr + 1;
    return (ulonglong)param_1;
  }
  iVar4 = _fileno(param_2);
  if ((*(uint *)((longlong)&param_2->_base + 4) & 6) == 0)
  {
    puVar5 = __doserrno();
    *puVar5 = 9;
  }
  else
  {
    if ((*(uint *)((longlong)&param_2->_base + 4) >> 0xc & 1) == 0)
    {
      if ((*(uint *)((longlong)&param_2->_base + 4) & 1) != 0)
      {
        *(undefined4 *)&param_2->_base = 0;
        if ((*(uint *)((longlong)&param_2->_base + 4) >> 3 & 1) == 0)
          goto LAB_1800700ef;
        param_2->_ptr = *(char **)&param_2->_cnt;
        LOCK();
        puVar2 = (uint *)((longlong)&param_2->_base + 4);
        *puVar2 = *puVar2 & 0xfffffffe;
      }
      LOCK();
      puVar2 = (uint *)((longlong)&param_2->_base + 4);
      *puVar2 = *puVar2 | 2;
      LOCK();
      puVar2 = (uint *)((longlong)&param_2->_base + 4);
      *puVar2 = *puVar2 & 0xfffffff7;
      *(undefined4 *)&param_2->_base = 0;
      if (((*(uint *)((longlong)&param_2->_base + 4) & 0x4c0) == 0) &&
          (((pFVar6 = (FILE *)__acrt_iob_func(1), param_2 != pFVar6 &&
                                                      (pFVar6 = (FILE *)__acrt_iob_func(2), param_2 != pFVar6)) ||
            (iVar4 = _isatty(iVar4), iVar4 == 0))))
      {
        __acrt_stdio_allocate_buffer_nolock((undefined8 *)param_2);
      }
      bVar3 = FUN_18006fef8(param_1, param_2);
      if (bVar3 != false)
      {
        return (ulonglong)param_1;
      }
    }
    else
    {
      puVar5 = __doserrno();
      *puVar5 = 0x22;
    }
  }
LAB_1800700ef:
  LOCK();
  puVar2 = (uint *)((longlong)&param_2->_base + 4);
  *puVar2 = *puVar2 | 0x10;
  return 0xffffffff;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _get_printf_count_output
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int _get_printf_count_output(void)
{
  return (int)(uint)(_DAT_180101ce8 == (DAT_1800ee160 | 1));
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __acrt_stdio_begin_temporary_buffering_nolock
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong __acrt_stdio_begin_temporary_buffering_nolock(FILE *param_1)
{
  uint *puVar1;
  uint uVar2;
  int iVar3;
  undefined4 extraout_var;
  FILE *pFVar4;
  char *pcVar5;
  char **ppcVar6;

  iVar3 = _fileno(param_1);
  iVar3 = _isatty(iVar3);
  pFVar4 = (FILE *)CONCAT44(extraout_var, iVar3);
  if (iVar3 == 0)
  {
  LAB_18006bce2:
    return (ulonglong)pFVar4 & 0xffffffffffffff00;
  }
  pFVar4 = (FILE *)__acrt_iob_func(1);
  if (param_1 == pFVar4)
  {
    ppcVar6 = (char **)&DAT_180101cf0;
  }
  else
  {
    pFVar4 = (FILE *)__acrt_iob_func(2);
    if (param_1 != pFVar4)
      goto LAB_18006bce2;
    ppcVar6 = (char **)&DAT_180101cf8;
  }
  _DAT_180101940 = _DAT_180101940 + 1;
  uVar2 = *(uint *)((longlong)&param_1->_base + 4);
  pFVar4 = (FILE *)(ulonglong)uVar2;
  if ((uVar2 & 0x4c0) != 0)
    goto LAB_18006bce2;
  LOCK();
  puVar1 = (uint *)((longlong)&param_1->_base + 4);
  *puVar1 = *puVar1 | 0x282;
  pcVar5 = *ppcVar6;
  if (pcVar5 == (char *)0x0)
  {
    pcVar5 = (char *)_malloc_base(0x1000);
    *ppcVar6 = pcVar5;
    _free_base((LPVOID)0x0);
    pcVar5 = *ppcVar6;
    if (pcVar5 == (char *)0x0)
    {
      *(undefined4 *)&param_1->_base = 2;
      *(int **)&param_1->_cnt = &param_1->_file;
      param_1->_ptr = (char *)&param_1->_file;
      param_1->_charbuf = 2;
      goto LAB_18006bcc4;
    }
  }
  *(char **)&param_1->_cnt = pcVar5;
  pcVar5 = *ppcVar6;
  param_1->_ptr = pcVar5;
  *(undefined4 *)&param_1->_base = 0x1000;
  param_1->_charbuf = 0x1000;
LAB_18006bcc4:
  return CONCAT71((int7)((ulonglong)pcVar5 >> 8), 1);
}

// Library Function - Single Match
//  __acrt_stdio_end_temporary_buffering_nolock
//
// Library: Visual Studio 2017 Release

void __acrt_stdio_end_temporary_buffering_nolock(char param_1, FILE *param_2)
{
  uint *puVar1;

  if ((param_1 != '\0') && ((*(uint *)((longlong)&param_2->_base + 4) >> 9 & 1) != 0))
  {
    __acrt_stdio_flush_nolock(param_2);
    LOCK();
    puVar1 = (uint *)((longlong)&param_2->_base + 4);
    *puVar1 = *puVar1 & 0xfffffd7f;
    param_2->_charbuf = 0;
    *(undefined8 *)&param_2->_cnt = 0;
    param_2->_ptr = (char *)0x0;
  }
  return;
}

// Library Function - Single Match
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_410d79af7f07d98d83a3f525b3859a53>,class <lambda_3e16ef9562a7dcce91392c22ab16ea36>&
// __ptr64,class <lambda_38119f0e861e05405d8a144b9b982f0a>>(class
// <lambda_410d79af7f07d98d83a3f525b3859a53>&& __ptr64,class
// <lambda_3e16ef9562a7dcce91392c22ab16ea36>& __ptr64,class
// <lambda_38119f0e861e05405d8a144b9b982f0a>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __thiscall __crt_seh_guarded_call<void>::

    operator___class__lambda_410d79af7f07d98d83a3f525b3859a53__class__lambda_3e16ef9562a7dcce91392c22ab16ea36_____ptr64_class__lambda_38119f0e861e05405d8a144b9b982f0a___(__crt_seh_guarded_call_void_ *this, _lambda_410d79af7f07d98d83a3f525b3859a53_ *param_1,
                                                                                                                                                                          _lambda_3e16ef9562a7dcce91392c22ab16ea36_ *param_2,
                                                                                                                                                                          _lambda_38119f0e861e05405d8a144b9b982f0a_ *param_3)
{
  undefined **ppuVar1;
  undefined **ppuVar2;

  __acrt_lock(*(int *)param_1);
  ppuVar2 = (undefined **)&DAT_180101d08;
  while (ppuVar2 != (undefined **)&DAT_180101d10)
  {
    if ((undefined **)*ppuVar2 != &PTR_DAT_1800ee5b0)
    {
      ppuVar1 = _updatetlocinfoEx_nolock(ppuVar2, &PTR_DAT_1800ee5b0);
      *ppuVar2 = (undefined *)ppuVar1;
    }
    ppuVar2 = ppuVar2 + 1;
  }
  __acrt_unlock(*(int *)param_3);
  return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_d67e8342c384adda8f857579ab50b2ae>,class <lambda_30712929f77e709619002f448b6a9510>&
// __ptr64,class <lambda_4525336fd7e478d965fb7ca7a337cad8>>(class
// <lambda_d67e8342c384adda8f857579ab50b2ae>&& __ptr64,class
// <lambda_30712929f77e709619002f448b6a9510>& __ptr64,class
// <lambda_4525336fd7e478d965fb7ca7a337cad8>&& __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

void __thiscall __crt_seh_guarded_call<void>::

    operator___class__lambda_d67e8342c384adda8f857579ab50b2ae__class__lambda_30712929f77e709619002f448b6a9510_____ptr64_class__lambda_4525336fd7e478d965fb7ca7a337cad8___(__crt_seh_guarded_call_void_ *this, _lambda_d67e8342c384adda8f857579ab50b2ae_ *param_1,
                                                                                                                                                                          _lambda_30712929f77e709619002f448b6a9510_ *param_2,
                                                                                                                                                                          _lambda_4525336fd7e478d965fb7ca7a337cad8_ *param_3)
{
  short sVar1;
  short sVar2;
  longlong lVar3;
  short *psVar4;
  undefined *puVar5;

  __acrt_lock(*(int *)param_1);
  _copytlocinfo_nolock((undefined4 *)**(undefined8 **)param_2,
                       *(undefined4 **)(**(longlong **)(param_2 + 8) + 0x90));
  lVar3 = FUN_18006d330(**(longlong **)param_2, **(int **)(param_2 + 0x18),
                        **(wchar_t ***)(param_2 + 0x20));
  **(longlong **)(param_2 + 0x10) = lVar3;
  if (lVar3 == 0)
  {
    __acrt_release_locale_ref(**(longlong **)param_2);
    __acrt_free_locale(**(LPVOID **)param_2);
  }
  else
  {
    psVar4 = **(short ***)(param_2 + 0x20);
    if (psVar4 != (short *)0x0)
    {
      puVar5 = (undefined *)((longlong)&DAT_1800ee718 - (longlong)psVar4);
      do
      {
        sVar1 = *psVar4;
        sVar2 = *(short *)((longlong)psVar4 + (longlong)puVar5);
        if (sVar1 != sVar2)
          break;
        psVar4 = psVar4 + 1;
      } while (sVar2 != 0);
      if (sVar1 != sVar2)
      {
        DAT_180101d00 = 1;
      }
    }
    _updatetlocinfoEx_nolock((undefined **)(**(longlong **)(param_2 + 8) + 0x90),
                             (undefined **)**(undefined ***)param_2);
    __acrt_release_locale_ref(**(longlong **)param_2);
    if (((*(byte *)(**(longlong **)(param_2 + 8) + 0x3a8) & 2) == 0) &&
        (((byte)DAT_1800eee60 & 1) == 0))
    {
      _updatetlocinfoEx_nolock((undefined **)&DAT_180101d08, *(undefined ***)(**(longlong **)(param_2 + 8) + 0x90));
      PTR_PTR_DAT_1800eef08 = (undefined *)DAT_180101d08[0x1f];
      PTR_DAT_1800eee50 = (undefined *)*DAT_180101d08;
      _DAT_1800ee5a8 = *(undefined4 *)(DAT_180101d08 + 1);
    }
  }
  __acrt_unlock(*(int *)param_3);
  return;
}

// Library Function - Single Match
//  public: void __cdecl __crt_seh_guarded_call<void>::operator()<class
// <lambda_7f2adfce497ff2baa965cd4f576ecfd1>,class <lambda_2a444430fde8c29194d880d93eed5e8f>&
// __ptr64,class <lambda_8dff2cf36a5417162780cd64fa2883ef>& __ptr64>(class
// <lambda_7f2adfce497ff2baa965cd4f576ecfd1>&& __ptr64,class
// <lambda_2a444430fde8c29194d880d93eed5e8f>& __ptr64,class
// <lambda_8dff2cf36a5417162780cd64fa2883ef>& __ptr64) __ptr64
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __thiscall __crt_seh_guarded_call<void>::

    operator___class__lambda_7f2adfce497ff2baa965cd4f576ecfd1__class__lambda_2a444430fde8c29194d880d93eed5e8f_____ptr64_class__lambda_8dff2cf36a5417162780cd64fa2883ef_____ptr64_(__crt_seh_guarded_call_void_ *this, _lambda_7f2adfce497ff2baa965cd4f576ecfd1_ *param_1,
                                                                                                                                                                                  _lambda_2a444430fde8c29194d880d93eed5e8f_ *param_2,
                                                                                                                                                                                  _lambda_8dff2cf36a5417162780cd64fa2883ef_ *param_3)
{
  <lambda_2af78c5f5901b1372d98f9ab3177dfa6>::operator__((_lambda_2af78c5f5901b1372d98f9ab3177dfa6_ *)param_2);
  *(uint *)(**(longlong **)param_3 + 0x3a8) = *(uint *)(**(longlong **)param_3 + 0x3a8) & 0xffffffef;
  return;
}

// Library Function - Single Match
//  public: void __cdecl <lambda_2af78c5f5901b1372d98f9ab3177dfa6>::operator()(void)const __ptr64
//
// Library: Visual Studio 2015 Release

void __thiscall<lambda_2af78c5f5901b1372d98f9ab3177dfa6>::operator__(_lambda_2af78c5f5901b1372d98f9ab3177dfa6_ *this)
{
  LPVOID pvVar1;
  __crt_seh_guarded_call_void_ local_res8[8];
  undefined4 local_res10[2];
  undefined4 local_res18[2];
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;

  pvVar1 = _calloc_base(1, 0x158);
  **(LPVOID **)this = pvVar1;
  _free_base((LPVOID)0x0);
  if (pvVar1 != (LPVOID)0x0)
  {
    local_38 = *(undefined8 *)this;
    local_30 = *(undefined8 *)(this + 8);
    local_28 = *(undefined8 *)(this + 0x10);
    local_20 = *(undefined8 *)(this + 0x18);
    local_18 = *(undefined8 *)(this + 0x20);
    local_res10[0] = 4;
    local_res18[0] = 4;
    __crt_seh_guarded_call<void>::

        operator___class__lambda_d67e8342c384adda8f857579ab50b2ae__class__lambda_30712929f77e709619002f448b6a9510_____ptr64_class__lambda_4525336fd7e478d965fb7ca7a337cad8___(local_res8, (_lambda_d67e8342c384adda8f857579ab50b2ae_ *)local_res18,
                                                                                                                                                                              (_lambda_30712929f77e709619002f448b6a9510_ *)&local_38,
                                                                                                                                                                              (_lambda_4525336fd7e478d965fb7ca7a337cad8_ *)local_res10);
  }
  return;
}

// Library Function - Single Match
//  __acrt_copy_locale_name
//
// Library: Visual Studio 2015 Release

short *__acrt_copy_locale_name(undefined (*param_1)[32])
{
  code *pcVar1;
  ulong uVar2;
  ulonglong uVar3;
  short *psVar4;

  if (((param_1 == (undefined(*)[32])0x0) || (uVar3 = FUN_1800477e4(param_1, 0x55), 0x54 < uVar3)) || (psVar4 = (short *)_malloc_base(uVar3 * 2 + 2), psVar4 == (short *)0x0))
  {
    psVar4 = (short *)0x0;
  }
  else
  {
    uVar2 = FUN_180061a44(psVar4, uVar3 + 1, (longlong)param_1, uVar3 + 1);
    if (uVar2 != 0)
    {
      _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
      pcVar1 = (code *)swi(3);
      psVar4 = (short *)(*pcVar1)();
      return psVar4;
    }
  }
  return psVar4;
}

// Library Function - Single Match
//  __lc_lctowcs
//
// Library: Visual Studio 2015 Release

void __lc_lctowcs(wchar_t *param_1, rsize_t param_2, wchar_t *param_3)
{
  code *pcVar1;
  errno_t eVar2;

  eVar2 = wcscpy_s(param_1, param_2, param_3);
  if (eVar2 == 0)
  {
    if (param_3[0x40] != L'\0')
    {
      _wcscats(param_1, param_2, 2, &DAT_1800ca550);
    }
    if (param_3[0x80] != L'\0')
    {
      _wcscats(param_1, param_2, 2, &DAT_1800ca554);
    }
    return;
  }
  _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}

// Library Function - Single Match
//  __lc_wcstolc
//
// Library: Visual Studio 2015 Release

undefined8 __lc_wcstolc(undefined (*param_1)[16], wchar_t *param_2)
{
  wchar_t wVar1;
  code *pcVar2;
  ulong uVar3;
  size_t sVar4;
  undefined8 uVar5;
  int iVar6;

  FUN_18003bd40(param_1, 0, 0x1ca);
  iVar6 = 0;
  if (*param_2 != L'\0')
  {
    if ((*param_2 != L'.') || (param_2[1] == L'\0'))
    {
      while (true)
      {
        sVar4 = wcscspn(param_2, L"_.,");
        if (sVar4 == 0)
        {
          return 0xffffffff;
        }
        wVar1 = param_2[sVar4];
        if (iVar6 == 0)
        {
          if (0x3f < sVar4)
          {
            return 0xffffffff;
          }
          if (wVar1 == L'.')
          {
            return 0xffffffff;
          }
          uVar3 = FUN_180061a44((short *)param_1, 0x40, (longlong)param_2, sVar4);
          if (uVar3 != 0)
          {
            _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
            pcVar2 = (code *)swi(3);
            uVar5 = (*pcVar2)();
            return uVar5;
          }
        }
        else
        {
          if (iVar6 == 1)
          {
            if (0x3f < sVar4)
            {
              return 0xffffffff;
            }
            if (wVar1 == L'_')
            {
              return 0xffffffff;
            }
            uVar3 = FUN_180061a44((short *)param_1[8], 0x40, (longlong)param_2, sVar4);
            if (uVar3 != 0)
            {
              _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
              pcVar2 = (code *)swi(3);
              uVar5 = (*pcVar2)();
              return uVar5;
            }
          }
          else
          {
            if (iVar6 != 2)
            {
              return 0xffffffff;
            }
            if (0xf < sVar4)
            {
              return 0xffffffff;
            }
            if ((wVar1 != L'\0') && (wVar1 != L','))
            {
              return 0xffffffff;
            }
            uVar3 = FUN_180061a44((short *)param_1[0x10], 0x10, (longlong)param_2, sVar4);
            if (uVar3 != 0)
            {
              _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
              pcVar2 = (code *)swi(3);
              uVar5 = (*pcVar2)();
              return uVar5;
            }
          }
        }
        if (wVar1 == L',')
        {
          return 0;
        }
        if (wVar1 == L'\0')
          break;
        param_2 = param_2 + sVar4 + 1;
        iVar6 = iVar6 + 1;
      }
      return 0;
    }
    uVar3 = FUN_180061a44((short *)param_1[0x10], 0x10, (longlong)(param_2 + 1), 0xf);
    if (uVar3 != 0)
    {
      _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
      pcVar2 = (code *)swi(3);
      uVar5 = (*pcVar2)();
      return uVar5;
    }
    *(undefined2 *)(param_1[0x11] + 0xe) = 0;
  }
  return 0;
}

// Library Function - Single Match
//  _configthreadlocale
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int _configthreadlocale(int _Flag)
{
  uint uVar1;
  __acrt_ptd *p_Var2;
  ulong *puVar3;
  uint uVar4;

  p_Var2 = FUN_18006a750();
  uVar1 = *(uint *)(p_Var2 + 0x3a8);
  if (_Flag == -1)
  {
    DAT_1800eee60 = 0xffffffff;
  }
  else
  {
    if (_Flag != 0)
    {
      if (_Flag == 1)
      {
        uVar4 = uVar1 | 2;
      }
      else
      {
        if (_Flag != 2)
        {
          puVar3 = __doserrno();
          *puVar3 = 0x16;
          FUN_18006738c();
          return -1;
        }
        uVar4 = uVar1 & 0xfffffffd;
      }
      *(uint *)(p_Var2 + 0x3a8) = uVar4;
    }
  }
  return (int)(2 - (uint)((uVar1 & 2) != 0));
}

// Library Function - Single Match
//  _copytlocinfo_nolock
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void _copytlocinfo_nolock(undefined4 *param_1, undefined4 *param_2)
{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  longlong lVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;

  if (((param_2 != (undefined4 *)0x0) && (param_1 != (undefined4 *)0x0)) && (param_1 != param_2))
  {
    lVar5 = 2;
    puVar4 = param_1;
    do
    {
      puVar7 = puVar4;
      puVar6 = param_2;
      uVar1 = puVar6[1];
      uVar2 = puVar6[2];
      uVar3 = puVar6[3];
      *puVar7 = *puVar6;
      puVar7[1] = uVar1;
      puVar7[2] = uVar2;
      puVar7[3] = uVar3;
      uVar1 = puVar6[5];
      uVar2 = puVar6[6];
      uVar3 = puVar6[7];
      puVar7[4] = puVar6[4];
      puVar7[5] = uVar1;
      puVar7[6] = uVar2;
      puVar7[7] = uVar3;
      uVar1 = puVar6[9];
      uVar2 = puVar6[10];
      uVar3 = puVar6[0xb];
      puVar7[8] = puVar6[8];
      puVar7[9] = uVar1;
      puVar7[10] = uVar2;
      puVar7[0xb] = uVar3;
      uVar1 = puVar6[0xd];
      uVar2 = puVar6[0xe];
      uVar3 = puVar6[0xf];
      puVar7[0xc] = puVar6[0xc];
      puVar7[0xd] = uVar1;
      puVar7[0xe] = uVar2;
      puVar7[0xf] = uVar3;
      uVar1 = puVar6[0x11];
      uVar2 = puVar6[0x12];
      uVar3 = puVar6[0x13];
      puVar7[0x10] = puVar6[0x10];
      puVar7[0x11] = uVar1;
      puVar7[0x12] = uVar2;
      puVar7[0x13] = uVar3;
      uVar1 = puVar6[0x15];
      uVar2 = puVar6[0x16];
      uVar3 = puVar6[0x17];
      puVar7[0x14] = puVar6[0x14];
      puVar7[0x15] = uVar1;
      puVar7[0x16] = uVar2;
      puVar7[0x17] = uVar3;
      uVar1 = puVar6[0x19];
      uVar2 = puVar6[0x1a];
      uVar3 = puVar6[0x1b];
      puVar7[0x18] = puVar6[0x18];
      puVar7[0x19] = uVar1;
      puVar7[0x1a] = uVar2;
      puVar7[0x1b] = uVar3;
      uVar1 = puVar6[0x1d];
      uVar2 = puVar6[0x1e];
      uVar3 = puVar6[0x1f];
      puVar7[0x1c] = puVar6[0x1c];
      puVar7[0x1d] = uVar1;
      puVar7[0x1e] = uVar2;
      puVar7[0x1f] = uVar3;
      lVar5 = lVar5 + -1;
      param_2 = puVar6 + 0x20;
      puVar4 = puVar7 + 0x20;
    } while (lVar5 != 0);
    uVar1 = puVar6[0x21];
    uVar2 = puVar6[0x22];
    uVar3 = puVar6[0x23];
    puVar7[0x20] = puVar6[0x20];
    puVar7[0x21] = uVar1;
    puVar7[0x22] = uVar2;
    puVar7[0x23] = uVar3;
    uVar1 = puVar6[0x25];
    uVar2 = puVar6[0x26];
    uVar3 = puVar6[0x27];
    puVar7[0x24] = puVar6[0x24];
    puVar7[0x25] = uVar1;
    puVar7[0x26] = uVar2;
    puVar7[0x27] = uVar3;
    uVar1 = puVar6[0x29];
    uVar2 = puVar6[0x2a];
    uVar3 = puVar6[0x2b];
    puVar7[0x28] = puVar6[0x28];
    puVar7[0x29] = uVar1;
    puVar7[0x2a] = uVar2;
    puVar7[0x2b] = uVar3;
    uVar1 = puVar6[0x2d];
    uVar2 = puVar6[0x2e];
    uVar3 = puVar6[0x2f];
    puVar7[0x2c] = puVar6[0x2c];
    puVar7[0x2d] = uVar1;
    puVar7[0x2e] = uVar2;
    puVar7[0x2f] = uVar3;
    uVar1 = puVar6[0x31];
    uVar2 = puVar6[0x32];
    uVar3 = puVar6[0x33];
    puVar7[0x30] = puVar6[0x30];
    puVar7[0x31] = uVar1;
    puVar7[0x32] = uVar2;
    puVar7[0x33] = uVar3;
    *(undefined8 *)(puVar7 + 0x34) = *(undefined8 *)(puVar6 + 0x34);
    param_1[4] = 0;
    FUN_18007c1ec((longlong)param_1);
  }
  return;
}

// Library Function - Single Match
//  _expandlocale
//
// Library: Visual Studio 2015 Release

void _expandlocale(wchar_t *param_1, wchar_t *param_2, rsize_t param_3, short *param_4, longlong param_5, UINT *param_6)
{
  wchar_t *_Src;
  wchar_t wVar1;
  wchar_t wVar2;
  short sVar3;
  short sVar4;
  code *pcVar5;
  UINT *pUVar6;
  ulong uVar7;
  errno_t eVar8;
  int iVar9;
  __acrt_ptd *p_Var10;
  wchar_t *pwVar11;
  short *psVar12;
  ulonglong uVar13;
  undefined8 uVar14;
  longlong lVar15;
  ulonglong uVar17;
  UINT local_258[2];
  UINT *local_250;
  short *local_248;
  wchar_t *local_240;
  short *local_238;
  rsize_t local_230;
  wint_t local_228[144];
  short local_108[88];
  ulonglong local_58;
  longlong lVar16;
  ulonglong uVar18;

  local_58 = DAT_1800ee160 ^ (ulonglong)&stack0xfffffffffffffd78;
  local_240 = param_2;
  local_230 = param_3;
  if (param_1 == (wchar_t *)0x0)
    goto LAB_18006c9ef;
  p_Var10 = FUN_18006a750();
  local_258[0] = 0;
  local_250 = (UINT *)(p_Var10 + 0xb8);
  _Src = (wchar_t *)(p_Var10 + 0x1c2);
  local_248 = (short *)(p_Var10 + 0xbc);
  local_238 = (short *)(p_Var10 + 0x2f0);
  uVar7 = FUN_180061a44(param_4, param_5, (longlong)local_238, 0x55);
  if (uVar7 != 0)
  {
    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
    pcVar5 = (code *)swi(3);
    (*pcVar5)();
    return;
  }
  if ((*param_1 == L'C') && (param_1[1] == L'\0'))
  {
    eVar8 = wcscpy_s(param_2, param_3, L"C");
    if (eVar8 != 0)
    {
      _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
      pcVar5 = (code *)swi(3);
      (*pcVar5)();
      return;
    }
    if (param_6 != (UINT *)0x0)
    {
      *param_6 = 0;
    }
    goto LAB_18006c9ef;
  }
  uVar17 = 0xffffffffffffffff;
  do
  {
    uVar18 = uVar17;
    uVar17 = uVar18 + 1;
  } while (param_1[uVar17] != L'\0');
  if (uVar17 < 0x83)
  {
    pwVar11 = _Src;
    do
    {
      wVar1 = *pwVar11;
      wVar2 = *(wchar_t *)((longlong)pwVar11 + (longlong)((longlong)param_1 - (longlong)_Src));
      if (wVar1 != wVar2)
        break;
      pwVar11 = pwVar11 + 1;
    } while (wVar2 != L'\0');
    if (wVar1 != wVar2)
    {
      psVar12 = local_248;
      do
      {
        sVar3 = *psVar12;
        sVar4 = *(short *)((longlong)psVar12 + (longlong)((longlong)param_1 - (longlong)local_248));
        if (sVar3 != sVar4)
          break;
        psVar12 = psVar12 + 1;
      } while (sVar4 != 0);
      if (sVar3 != sVar4)
        goto LAB_18006cb04;
    }
  }
  else
  {
  LAB_18006cb04:
    uVar13 = __acrt_can_use_vista_locale_apis();
    uVar14 = __lc_wcstolc((undefined(*)[16])local_228, param_1);
    pUVar6 = local_250;
    if ((int)uVar14 == 0)
    {
      if ((char)uVar13 == '\0')
      {
        iVar9 = FUN_180082704((longlong)local_228, local_250, (LPWSTR)local_228);
      }
      else
      {
        uVar14 = FUN_180081c48(local_228, local_250, (LPWSTR)local_228);
        iVar9 = (int)uVar14;
      }
      if (iVar9 == 0)
        goto LAB_18006cba7;
      __lc_lctowcs(_Src, 0x83, (wchar_t *)local_228);
      lVar15 = -1;
      if (param_4 != (short *)0x0)
      {
        do
        {
          lVar16 = lVar15;
          lVar15 = lVar16 + 1;
        } while (local_108[lVar15] != 0);
        uVar7 = FUN_180061a44(param_4, param_5, (longlong)local_108, lVar16 + 2);
        if (uVar7 != 0)
        {
          _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
          pcVar5 = (code *)swi(3);
          (*pcVar5)();
          return;
        }
      }
    }
    else
    {
    LAB_18006cba7:
      iVar9 = __acrt_IsValidLocaleName((longlong)param_1);
      lVar15 = -1;
      if (iVar9 == 0)
      {
        do
        {
          lVar16 = lVar15;
          lVar15 = lVar16 + 1;
        } while (param_4[lVar15] != 0);
        uVar7 = FUN_180061a44(local_238, 0x55, (longlong)param_4, lVar16 + 2);
        if (uVar7 != 0)
        {
          _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
          pcVar5 = (code *)swi(3);
          (*pcVar5)();
          return;
        }
        goto LAB_18006c9ef;
      }
      iVar9 = __acrt_GetLocaleInfoEx((longlong)param_1, 0x20001004, (LPWSTR)local_258, 2);
      if ((iVar9 == 0) || (local_258[0] == 0))
      {
        local_258[0] = GetACP();
      }
      lVar15 = uVar18 + 2;
      *pUVar6 = local_258[0] & 0xffff;
      uVar7 = FUN_180061a44(_Src, 0x83, (longlong)param_1, lVar15);
      if (uVar7 != 0)
      {
        _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
        pcVar5 = (code *)swi(3);
        (*pcVar5)();
        return;
      }
      uVar7 = FUN_180061a44(param_4, param_5, (longlong)param_1, lVar15);
      if (uVar7 != 0)
      {
        _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
        pcVar5 = (code *)swi(3);
        (*pcVar5)();
        return;
      }
      uVar7 = FUN_180061a44(local_238, 0x55, (longlong)param_1, lVar15);
      if (uVar7 != 0)
      {
        _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
        pcVar5 = (code *)swi(3);
        (*pcVar5)();
        return;
      }
    }
    if ((*param_1 == L'\0') || (0x82 < uVar17))
    {
      *local_248 = 0;
      param_2 = local_240;
    }
    else
    {
      uVar7 = FUN_180061a44(local_248, 0x83, (longlong)param_1, uVar18 + 2);
      param_2 = local_240;
      if (uVar7 != 0)
      {
        _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
        pcVar5 = (code *)swi(3);
        (*pcVar5)();
        return;
      }
    }
  }
  if (param_6 != (UINT *)0x0)
  {
    *param_6 = *local_250;
  }
  eVar8 = wcscpy_s(param_2, local_230, _Src);
  if (eVar8 != 0)
  {
    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
    pcVar5 = (code *)swi(3);
    (*pcVar5)();
    return;
  }
LAB_18006c9ef:
  FUN_180034d00(local_58 ^ (ulonglong)&stack0xfffffffffffffd78);
  return;
}

// Library Function - Single Match
//  _wcscats
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void _wcscats(wchar_t *param_1, rsize_t param_2, int param_3, undefined8 param_4)
{
  code *pcVar1;
  errno_t eVar2;
  int iVar3;
  wchar_t **ppwVar4;
  int local_res18;
  wchar_t *local_res20;

  if (0 < param_3)
  {
    local_res20 = (wchar_t *)param_4;
    iVar3 = 0;
    ppwVar4 = (wchar_t **)&local_res18;
    local_res18 = param_3;
    do
    {
      ppwVar4 = ppwVar4 + 1;
      eVar2 = wcscat_s(param_1, param_2, *ppwVar4);
      if (eVar2 != 0)
      {
        _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      iVar3 = iVar3 + 1;
    } while (iVar3 < local_res18);
  }
  return;
}

// Library Function - Single Match
//  _wsetlocale
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

wchar_t *_wsetlocale(int _Category, wchar_t *_Locale)
{
  ulong *puVar1;
  int local_res8[2];
  wchar_t *local_res10;
  _lambda_7f2adfce497ff2baa965cd4f576ecfd1_ local_res18[8];
  __acrt_ptd *local_res20;
  wchar_t *local_48;
  undefined8 local_40;
  __acrt_ptd **local_38;
  undefined8 *local_30;
  __acrt_ptd **local_28;
  wchar_t **local_20;
  int *local_18;
  wchar_t **local_10;

  local_48 = (wchar_t *)0x0;
  local_40 = 0;
  local_res8[0] = _Category;
  local_res10 = _Locale;
  if ((uint)_Category < 6)
  {
    local_res20 = FUN_18006a750();
    __acrt_eagerly_load_locale_apis();
    __acrt_update_thread_locale_data();
    *(uint *)(local_res20 + 0x3a8) = *(uint *)(local_res20 + 0x3a8) | 0x10;
    local_38 = &local_res20;
    local_30 = &local_40;
    local_28 = &local_res20;
    local_20 = &local_48;
    local_18 = local_res8;
    local_10 = &local_res10;
    __crt_seh_guarded_call<void>::

        operator___class__lambda_7f2adfce497ff2baa965cd4f576ecfd1__class__lambda_2a444430fde8c29194d880d93eed5e8f_____ptr64_class__lambda_8dff2cf36a5417162780cd64fa2883ef_____ptr64_((__crt_seh_guarded_call_void_ *)local_res18, local_res18,
                                                                                                                                                                                      (_lambda_2a444430fde8c29194d880d93eed5e8f_ *)&local_30,
                                                                                                                                                                                      (_lambda_8dff2cf36a5417162780cd64fa2883ef_ *)&local_38);
  }
  else
  {
    puVar1 = __doserrno();
    *puVar1 = 0x16;
    FUN_18006738c();
    local_48 = (wchar_t *)0x0;
  }
  return local_48;
}

// Library Function - Single Match
//  __p___mb_cur_max
//
// Library: Visual Studio 2015 Release

undefined *__p___mb_cur_max(void)
{
  __acrt_ptd *p_Var1;
  undefined *local_res8[4];

  p_Var1 = FUN_18006a750();
  local_res8[0] = *(undefined **)(p_Var1 + 0x90);
  __acrt_update_locale_info((longlong)p_Var1, local_res8);
  return local_res8[0] + 8;
}

// WARNING: Unknown calling convention yet parameter storage is locked
// Library Function - Single Match
//  void __cdecl initialize_inherited_file_handles_nolock(void)
//
// Library: Visual Studio 2015 Release

void initialize_inherited_file_handles_nolock(void)
{
  DWORD DVar1;
  longlong lVar2;
  HANDLE *ppvVar3;
  longlong lVar4;
  uint *puVar5;
  uint uVar6;
  ulonglong uVar7;
  _STARTUPINFOW local_78;

  GetStartupInfoW((LPSTARTUPINFOW)&local_78);
  lVar4 = 0;
  if ((local_78.cbReserved2 != 0) && ((uint *)local_78.lpReserved2 != (uint *)0x0))
  {
    puVar5 = (uint *)((longlong)local_78.lpReserved2 + 4);
    ppvVar3 = (HANDLE *)((longlong)(int)*(uint *)local_78.lpReserved2 + (longlong)puVar5);
    uVar6 = 0x2000;
    if ((int)*(uint *)local_78.lpReserved2 < 0x2000)
    {
      uVar6 = *(uint *)local_78.lpReserved2;
    }
    FUN_180082b14(uVar6);
    if ((int)DAT_180102110 < (int)uVar6)
    {
      uVar6 = DAT_180102110;
    }
    uVar7 = (ulonglong)uVar6;
    if (uVar6 != 0)
    {
      do
      {
        if ((((*ppvVar3 != (HANDLE)0xffffffffffffffff) && (*ppvVar3 != (HANDLE)0xfffffffffffffffe)) && ((*(byte *)puVar5 & 1) != 0)) &&
            (((*(byte *)puVar5 & 8) != 0 || (DVar1 = GetFileType(*ppvVar3), DVar1 != 0))))
        {
          lVar2 = (ulonglong)((uint)lVar4 & 0x3f) * 0x40 +
                  *(longlong *)((longlong)&DAT_180101d10 + (lVar4 >> 6) * 8);
          *(HANDLE *)(lVar2 + 0x28) = *ppvVar3;
          *(byte *)(lVar2 + 0x38) = *(byte *)puVar5;
        }
        lVar4 = lVar4 + 1;
        puVar5 = (uint *)((longlong)puVar5 + 1);
        ppvVar3 = ppvVar3 + 1;
        uVar7 = uVar7 - 1;
      } while (uVar7 != 0);
    }
  }
  return;
}

// WARNING: Unknown calling convention yet parameter storage is locked
// Library Function - Single Match
//  void __cdecl initialize_stdio_handles_nolock(void)
//
// Library: Visual Studio 2015 Release

void initialize_stdio_handles_nolock(void)
{
  uint uVar1;
  HANDLE hFile;
  DWORD nStdHandle;
  longlong lVar2;
  uint uVar3;
  longlong lVar4;

  uVar3 = 0;
  lVar4 = 0;
  do
  {
    lVar2 = (ulonglong)(uVar3 & 0x3f) * 0x40 +
            *(longlong *)((longlong)&DAT_180101d10 + ((longlong)(int)uVar3 >> 6) * 8);
    if (*(longlong *)(lVar2 + 0x28) + 2U < 2)
    {
      *(undefined *)(lVar2 + 0x38) = 0x81;
      if (uVar3 == 0)
      {
        nStdHandle = 0xfffffff6;
      }
      else
      {
        if (uVar3 == 1)
        {
          nStdHandle = 0xfffffff5;
        }
        else
        {
          nStdHandle = 0xfffffff4;
        }
      }
      hFile = GetStdHandle(nStdHandle);
      if ((longlong)hFile + 1U < 2)
      {
        uVar1 = 0;
      }
      else
      {
        uVar1 = GetFileType(hFile);
      }
      if (uVar1 == 0)
      {
        *(byte *)(lVar2 + 0x38) = *(byte *)(lVar2 + 0x38) | 0x40;
        *(undefined8 *)(lVar2 + 0x28) = 0xfffffffffffffffe;
        if (DAT_180101938 != 0)
        {
          *(undefined4 *)(*(longlong *)(lVar4 + DAT_180101938) + 0x18) = 0xfffffffe;
        }
      }
      else
      {
        *(HANDLE *)(lVar2 + 0x28) = hFile;
        if ((uVar1 & 0xff) == 2)
        {
          *(byte *)(lVar2 + 0x38) = *(byte *)(lVar2 + 0x38) | 0x40;
        }
        else
        {
          if ((uVar1 & 0xff) == 3)
          {
            *(byte *)(lVar2 + 0x38) = *(byte *)(lVar2 + 0x38) | 8;
          }
        }
      }
    }
    else
    {
      *(byte *)(lVar2 + 0x38) = *(byte *)(lVar2 + 0x38) | 0x80;
    }
    uVar3 = uVar3 + 1;
    lVar4 = lVar4 + 8;
  } while (uVar3 != 3);
  return;
}

// Library Function - Single Match
//  __acrt_initialize_lowio
//
// Library: Visual Studio 2015 Release

ulonglong __acrt_initialize_lowio(void)
{
  longlong lVar1;
  ulonglong uVar2;
  bool bVar3;

  __acrt_lock(7);
  lVar1 = FUN_180082b14(0);
  bVar3 = (int)lVar1 == 0;
  if (bVar3)
  {
    initialize_inherited_file_handles_nolock();
    initialize_stdio_handles_nolock();
  }
  uVar2 = __acrt_unlock(7);
  return uVar2 & 0xffffffffffffff00 | (ulonglong)bVar3;
}

// Library Function - Single Match
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0>,class <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec>&
// __ptr64,class <lambda_237c231691f317818eb88cc1d5d642d6>>(class
// <lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0>&& __ptr64,class
// <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec>& __ptr64,class
// <lambda_237c231691f317818eb88cc1d5d642d6>&& __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

int __thiscall __crt_seh_guarded_call<int>::

    operator___class__lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0__class__lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec_____ptr64_class__lambda_237c231691f317818eb88cc1d5d642d6___(__crt_seh_guarded_call_int_ *this, _lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0_ *param_1,
                                                                                                                                                                          _lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec_ *param_2,
                                                                                                                                                                          _lambda_237c231691f317818eb88cc1d5d642d6_ *param_3)
{
  uint _FileHandle;
  int iVar1;
  ulong *puVar2;

  FID_conflict___acrt_lowio_lock_fh(*(uint *)param_1);
  _FileHandle = **(uint **)param_2;
  if ((*(byte *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)(int)_FileHandle >> 6) * 8) +
                 0x38 + (ulonglong)(_FileHandle & 0x3f) * 0x40) &
       1) == 0)
  {
    puVar2 = __doserrno();
    *puVar2 = 9;
    iVar1 = -1;
  }
  else
  {
    iVar1 = _close_nolock(_FileHandle);
  }
  FID_conflict___acrt_lowio_lock_fh(*(uint *)param_3);
  return iVar1;
}

// Library Function - Single Match
//  int __cdecl __acrt_lowio_lock_fh_and_call<class
// <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec>>(int,class <lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec>&&
// __ptr64)
//
// Library: Visual Studio 2015 Release

int __acrt_lowio_lock_fh_and_call_class__lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec___(int param_1, _lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec_ *param_2)
{
  int iVar1;
  __crt_seh_guarded_call_int_ local_res8[16];
  int local_res18[2];
  int local_res20[2];

  local_res18[0] = param_1;
  local_res20[0] = param_1;
  iVar1 = __crt_seh_guarded_call<int>::

      operator___class__lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0__class__lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec_____ptr64_class__lambda_237c231691f317818eb88cc1d5d642d6___(local_res8, (_lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0_ *)local_res20, param_2,
                                                                                                                                                                            (_lambda_237c231691f317818eb88cc1d5d642d6_ *)local_res18);
  return iVar1;
}

// Library Function - Single Match
//  _close
//
// Library: Visual Studio 2015 Release

int _close(int _FileHandle)
{
  int iVar1;
  ulong *puVar2;
  int local_res8[2];
  __crt_seh_guarded_call_int_ local_res10[8];
  int local_res18[2];
  int local_res20[2];
  int *local_18[3];

  local_res8[0] = _FileHandle;
  if (_FileHandle == -2)
  {
    puVar2 = __doserrno();
    *puVar2 = 0;
    puVar2 = __doserrno();
    *puVar2 = 9;
  }
  else
  {
    if (((-1 < _FileHandle) && ((uint)_FileHandle < DAT_180102110)) &&
        ((*(byte *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)_FileHandle >> 6) * 8) + 0x38 + (ulonglong)(_FileHandle & 0x3f) * 0x40) & 1) != 0))
    {
      local_18[0] = local_res8;
      local_res18[0] = _FileHandle;
      local_res20[0] = _FileHandle;
      iVar1 = __crt_seh_guarded_call<int>::

          operator___class__lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0__class__lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec_____ptr64_class__lambda_237c231691f317818eb88cc1d5d642d6___(local_res10, (_lambda_bfedae4ebbf01fab1bb6dcc6a9e276e0_ *)local_res20,
                                                                                                                                                                                (_lambda_2fe9b910cf3cbf4a0ab98a02ba45b3ec_ *)local_18,
                                                                                                                                                                                (_lambda_237c231691f317818eb88cc1d5d642d6_ *)local_res18);
      return iVar1;
    }
    puVar2 = __doserrno();
    *puVar2 = 0;
    puVar2 = __doserrno();
    *puVar2 = 9;
    FUN_18006738c();
  }
  return -1;
}

// Library Function - Single Match
//  _close_nolock
//
// Library: Visual Studio 2015 Release

int _close_nolock(int _FileHandle)
{
  BOOL BVar1;
  DWORD DVar2;
  int iVar3;
  intptr_t iVar4;
  intptr_t iVar5;
  HANDLE hObject;

  iVar4 = _get_osfhandle(_FileHandle);
  if (iVar4 != -1)
  {
    if (((_FileHandle == 1) && ((*(byte *)(DAT_180101d10 + 0xb8) & 1) != 0)) ||
        ((_FileHandle == 2 && ((*(byte *)(DAT_180101d10 + 0x78) & 1) != 0))))
    {
      iVar4 = _get_osfhandle(2);
      iVar5 = _get_osfhandle(1);
      if (iVar5 == iVar4)
        goto LAB_18006f0ca;
    }
    hObject = (HANDLE)_get_osfhandle(_FileHandle);
    BVar1 = CloseHandle(hObject);
    if (BVar1 == 0)
    {
      DVar2 = GetLastError();
      goto LAB_18006f125;
    }
  }
LAB_18006f0ca:
  DVar2 = 0;
LAB_18006f125:
  _free_osfhnd(_FileHandle);
  *(undefined *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)_FileHandle >> 6) * 8) + 0x38 +
                 (ulonglong)(_FileHandle & 0x3f) * 0x40) = 0;
  if (DVar2 == 0)
  {
    iVar3 = 0;
  }
  else
  {
    __acrt_errno_map_os_error(DVar2);
    iVar3 = -1;
  }
  return iVar3;
}

// Library Function - Single Match
//  __acrt_stdio_free_buffer_nolock
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void __acrt_stdio_free_buffer_nolock(undefined8 *param_1)
{
  if (((*(uint *)((longlong)param_1 + 0x14) >> 0xd & 1) != 0) &&
      ((*(uint *)((longlong)param_1 + 0x14) >> 6 & 1) != 0))
  {
    _free_base((LPVOID)param_1[1]);
    LOCK();
    *(uint *)((longlong)param_1 + 0x14) = *(uint *)((longlong)param_1 + 0x14) & 0xfffffebf;
    param_1[1] = 0;
    *param_1 = 0;
    *(undefined4 *)(param_1 + 2) = 0;
  }
  return;
}

// WARNING: Function: _alloca_probe replaced with injection: alloca_probe
// Library Function - Multiple Matches With Same Base Name
//  struct `anonymous namespace'::write_result __cdecl write_text_utf8_nolock(int,char const *
// __ptr64 const,unsigned int)
//  struct `anonymous namespace'::write_result __cdecl write_text_utf8_nolock(int,char const *
// __ptr64 const,unsigned int)
//
// Library: Visual Studio 2015 Release

void write_text_utf8_nolock(DWORD *param_1, uint param_2, WCHAR *param_3, uint param_4)
{
  WCHAR WVar1;
  HANDLE hFile;
  uint uVar2;
  BOOL BVar3;
  DWORD DVar4;
  WCHAR *pWVar5;
  uint uVar6;
  ulonglong uVar7;
  WCHAR *pWVar8;
  WCHAR *pWVar9;
  bool bVar10;
  DWORD local_1460[4];
  WCHAR local_1450[856];
  CHAR local_da0[3424];
  ulonglong local_40;
  undefined8 local_30;

  local_30 = 0x18006f7a0;
  local_40 = DAT_1800ee160 ^ (ulonglong)&stack0xffffffffffffeb60;
  pWVar9 = (WCHAR *)((ulonglong)param_4 + (longlong)param_3);
  hFile = *(HANDLE *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)(int)param_2 >> 6) * 8) + 0x28 +
                      (ulonglong)(param_2 & 0x3f) * 0x40);
  *param_1 = 0;
  *(undefined8 *)(param_1 + 1) = 0;
  bVar10 = param_3 < pWVar9;
  pWVar8 = param_3;
  do
  {
    if (!bVar10)
    {
    LAB_18006f8c7:
      FUN_180034d00(local_40 ^ (ulonglong)&stack0xffffffffffffeb60);
      return;
    }
    pWVar5 = local_1450;
    do
    {
      if (pWVar9 <= pWVar8)
        break;
      WVar1 = *pWVar8;
      pWVar8 = pWVar8 + 1;
      if (WVar1 == L'\n')
      {
        *pWVar5 = L'\r';
        pWVar5 = pWVar5 + 1;
      }
      *pWVar5 = WVar1;
      pWVar5 = pWVar5 + 1;
    } while (pWVar5 < local_1450 + 0x354);
    uVar2 = WideCharToMultiByte(0xfde9, 0, local_1450,
                                (int)((longlong)((longlong)pWVar5 - (longlong)local_1450) >> 1),
                                local_da0, 0xd55, (LPCSTR)0x0, (LPBOOL)0x0);
    if (uVar2 == 0)
    {
    LAB_18006f8bf:
      DVar4 = GetLastError();
      *param_1 = DVar4;
      goto LAB_18006f8c7;
    }
    uVar7 = 0;
    if (uVar2 != 0)
    {
      do
      {
        BVar3 = WriteFile(hFile, local_da0 + uVar7, uVar2 - (int)uVar7, local_1460, (LPOVERLAPPED)0x0);
        if (BVar3 == 0)
          goto LAB_18006f8bf;
        uVar6 = (int)uVar7 + local_1460[0];
        uVar7 = (ulonglong)uVar6;
      } while (uVar6 < uVar2);
    }
    param_1[1] = (int)pWVar8 - (int)param_3;
    bVar10 = pWVar8 < pWVar9;
  } while (true);
}

// Library Function - Single Match
//  __acrt_stdio_flush_and_write_narrow_nolock
//
// Library: Visual Studio 2015 Release

ulonglong __acrt_stdio_flush_and_write_narrow_nolock(byte param_1, FILE *param_2)
{
  uint *puVar1;
  bool bVar2;
  int iVar3;
  ulong *puVar4;
  FILE *pFVar5;

  iVar3 = _fileno(param_2);
  if ((*(uint *)((longlong)&param_2->_base + 4) & 6) == 0)
  {
    puVar4 = __doserrno();
    *puVar4 = 9;
  }
  else
  {
    if ((*(uint *)((longlong)&param_2->_base + 4) >> 0xc & 1) == 0)
    {
      if ((*(uint *)((longlong)&param_2->_base + 4) & 1) != 0)
      {
        *(undefined4 *)&param_2->_base = 0;
        if ((*(uint *)((longlong)&param_2->_base + 4) >> 3 & 1) == 0)
          goto LAB_1800700ef;
        param_2->_ptr = *(char **)&param_2->_cnt;
        LOCK();
        puVar1 = (uint *)((longlong)&param_2->_base + 4);
        *puVar1 = *puVar1 & 0xfffffffe;
      }
      LOCK();
      puVar1 = (uint *)((longlong)&param_2->_base + 4);
      *puVar1 = *puVar1 | 2;
      LOCK();
      puVar1 = (uint *)((longlong)&param_2->_base + 4);
      *puVar1 = *puVar1 & 0xfffffff7;
      *(undefined4 *)&param_2->_base = 0;
      if (((*(uint *)((longlong)&param_2->_base + 4) & 0x4c0) == 0) &&
          (((pFVar5 = (FILE *)__acrt_iob_func(1), param_2 != pFVar5 &&
                                                      (pFVar5 = (FILE *)__acrt_iob_func(2), param_2 != pFVar5)) ||
            (iVar3 = _isatty(iVar3), iVar3 == 0))))
      {
        __acrt_stdio_allocate_buffer_nolock((undefined8 *)param_2);
      }
      bVar2 = FUN_18006fef8(param_1, param_2);
      if (bVar2 != false)
      {
        return (ulonglong)param_1;
      }
    }
    else
    {
      puVar4 = __doserrno();
      *puVar4 = 0x22;
    }
  }
LAB_1800700ef:
  LOCK();
  puVar1 = (uint *)((longlong)&param_2->_base + 4);
  *puVar1 = *puVar1 | 0x10;
  return 0xffffffff;
}

// Library Function - Single Match
//  __acrt_stdio_flush_and_write_wide_nolock
//
// Library: Visual Studio 2015 Release

WCHAR __acrt_stdio_flush_and_write_wide_nolock(WCHAR param_1, FILE *param_2)
{
  uint *puVar1;
  bool bVar2;
  int iVar3;
  ulong *puVar4;
  FILE *pFVar5;

  iVar3 = _fileno(param_2);
  if ((*(uint *)((longlong)&param_2->_base + 4) & 6) == 0)
  {
    puVar4 = __doserrno();
    *puVar4 = 9;
  }
  else
  {
    if ((*(uint *)((longlong)&param_2->_base + 4) >> 0xc & 1) == 0)
    {
      if ((*(uint *)((longlong)&param_2->_base + 4) & 1) != 0)
      {
        *(undefined4 *)&param_2->_base = 0;
        if ((*(uint *)((longlong)&param_2->_base + 4) >> 3 & 1) == 0)
          goto LAB_1800701d7;
        param_2->_ptr = *(char **)&param_2->_cnt;
        LOCK();
        puVar1 = (uint *)((longlong)&param_2->_base + 4);
        *puVar1 = *puVar1 & 0xfffffffe;
      }
      LOCK();
      puVar1 = (uint *)((longlong)&param_2->_base + 4);
      *puVar1 = *puVar1 | 2;
      LOCK();
      puVar1 = (uint *)((longlong)&param_2->_base + 4);
      *puVar1 = *puVar1 & 0xfffffff7;
      *(undefined4 *)&param_2->_base = 0;
      if (((*(uint *)((longlong)&param_2->_base + 4) & 0x4c0) == 0) &&
          (((pFVar5 = (FILE *)__acrt_iob_func(1), param_2 != pFVar5 &&
                                                      (pFVar5 = (FILE *)__acrt_iob_func(2), param_2 != pFVar5)) ||
            (iVar3 = _isatty(iVar3), iVar3 == 0))))
      {
        __acrt_stdio_allocate_buffer_nolock((undefined8 *)param_2);
      }
      bVar2 = FUN_18006ffd8(param_1, param_2);
      if (bVar2 != false)
      {
        return param_1;
      }
    }
    else
    {
      puVar4 = __doserrno();
      *puVar4 = 0x22;
    }
  }
LAB_1800701d7:
  LOCK();
  puVar1 = (uint *)((longlong)&param_2->_base + 4);
  *puVar1 = *puVar1 | 0x10;
  return L'\xffff';
}

// Library Function - Multiple Matches With Different Base Names
//  _get_daylight
//  _get_dstbias
//  _get_timezone
//
// Library: Visual Studio 2015 Release

errno_t FID_conflict__get_daylight(long *_Timezone)
{
  errno_t eVar1;
  ulong *puVar2;

  if (_Timezone == (long *)0x0)
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
    eVar1 = 0x16;
  }
  else
  {
    *_Timezone = DAT_18010211c;
    eVar1 = 0;
  }
  return eVar1;
}

// Library Function - Multiple Matches With Different Base Names
//  _get_daylight
//  _get_dstbias
//  _get_timezone
//
// Library: Visual Studio 2015 Release

errno_t FID_conflict__get_daylight(long *_Timezone)
{
  errno_t eVar1;
  ulong *puVar2;

  if (_Timezone == (long *)0x0)
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
    eVar1 = 0x16;
  }
  else
  {
    *_Timezone = DAT_180102120;
    eVar1 = 0;
  }
  return eVar1;
}

// Library Function - Multiple Matches With Different Base Names
//  _get_daylight
//  _get_dstbias
//  _get_timezone
//
// Library: Visual Studio 2015 Release

errno_t FID_conflict__get_daylight(long *_Timezone)
{
  errno_t eVar1;
  ulong *puVar2;

  if (_Timezone == (long *)0x0)
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
    eVar1 = 0x16;
  }
  else
  {
    *_Timezone = DAT_180102118;
    eVar1 = 0;
  }
  return eVar1;
}

// Library Function - Single Match
//  bool __cdecl __crt_time_is_leap_year<int>(int)
//
// Library: Visual Studio 2015 Release

bool __crt_time_is_leap_year_int_(int param_1)
{
  uint uVar1;

  uVar1 = param_1 & 0x80000003;
  if ((int)uVar1 < 0)
  {
    uVar1 = (uVar1 - 1 | 0xfffffffc) + 1;
  }
  if ((uVar1 == 0) && (param_1 != (param_1 / 100) * 100))
  {
    return true;
  }
  return param_1 + 0x76c == ((param_1 + 0x76c) / 400) * 400;
}

// Library Function - Single Match
//  int __cdecl common_gmtime_s<__int64>(struct tm * __ptr64 const,__int64 const * __ptr64 const)
//
// Library: Visual Studio 2015 Release

int common_gmtime_s___int64_(tm *param_1, __int64 *param_2)
{
  int iVar1;
  ulong *puVar2;
  longlong lVar3;
  int iVar4;
  int *piVar5;
  int *piVar6;
  char local_res8[8];
  longlong local_res18[2];

  if ((param_1 == (tm *)0x0) ||
      (FUN_18003bd40((undefined(*)[16])param_1, 0xff, 0x24), param_2 == (__int64 *)0x0))
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
  }
  else
  {
    local_res18[0] = *param_2;
    if ((-0xa8c1 < local_res18[0]) && (local_res18[0] < 0x79358e1d0))
    {
      local_res8[0] = '\0';
      iVar1 = FUN_180070980(local_res18, local_res8);
      piVar5 = (int *)&DAT_1800cd740;
      param_1->tm_year = iVar1;
      iVar4 = 1;
      iVar1 = (int)(local_res18[0] / 0x15180);
      param_1->tm_yday = iVar1;
      local_res18[0] = local_res18[0] + (longlong)iVar1 * -0x15180;
      piVar6 = piVar5;
      if (local_res8[0] != '\0')
      {
        piVar5 = &DAT_1800cd778;
        piVar6 = piVar5;
      }
      while (piVar5 = piVar5 + 1, *piVar5 < iVar1)
      {
        iVar4 = iVar4 + 1;
      }
      param_1->tm_mon = iVar4 + -1;
      param_1->tm_mday = iVar1 - piVar6[iVar4 + -1];
      lVar3 = *param_2;
      param_1->tm_isdst = 0;
      param_1->tm_wday = ((int)(lVar3 / 0x15180) + 4) % 7;
      iVar1 = (int)(local_res18[0] / 0xe10);
      param_1->tm_hour = iVar1;
      local_res18[0] = local_res18[0] + (longlong)iVar1 * -0xe10;
      lVar3 = SUB168(SEXT816(-0x7777777777777777) * SEXT816(local_res18[0]) >> 0x40, 0) +
              local_res18[0];
      iVar1 = (int)(lVar3 >> 5) - (int)(lVar3 >> 0x3f);
      param_1->tm_min = iVar1;
      param_1->tm_sec = (int)local_res18[0] + iVar1 * -0x3c;
      return 0;
    }
    puVar2 = __doserrno();
    *puVar2 = 0x16;
  }
  return 0x16;
}

// Library Function - Single Match
//  __getgmtimebuf
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

tm *__getgmtimebuf(void)
{
  __acrt_ptd *p_Var1;
  LPVOID pvVar2;
  ulong *puVar3;

  p_Var1 = FUN_18006a8c4();
  if (p_Var1 != (__acrt_ptd *)0x0)
  {
    if (*(tm **)(p_Var1 + 0x68) != (tm *)0x0)
    {
      return *(tm **)(p_Var1 + 0x68);
    }
    pvVar2 = _malloc_base(0x24);
    *(LPVOID *)(p_Var1 + 0x68) = pvVar2;
    _free_base((LPVOID)0x0);
    if (*(tm **)(p_Var1 + 0x68) != (tm *)0x0)
    {
      return *(tm **)(p_Var1 + 0x68);
    }
  }
  puVar3 = __doserrno();
  *puVar3 = 0xc;
  return (tm *)0x0;
}

undefined8 thunk_FUN_1800705c8(undefined (*param_1)[16], int *param_2)
{
  bool bVar1;
  ulong *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  int *piVar8;

  if ((param_1 == (undefined(*)[16])0x0) ||
      (FUN_18003bd40(param_1, 0xff, 0x24), param_2 == (int *)0x0))
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
  }
  else
  {
    iVar4 = *param_2;
    if (-0xa8c1 < iVar4)
    {
      bVar1 = false;
      iVar6 = (iVar4 / 0x7861f80) * 4;
      iVar3 = iVar6 + 0x46;
      iVar4 = iVar4 % 0x7861f80;
      iVar5 = iVar4;
      if (0x1e1337f < iVar4)
      {
        iVar3 = iVar6 + 0x47;
        iVar5 = iVar4 + -0x1e13380;
        if (0x1e1337f < iVar5)
        {
          iVar5 = iVar4 + -0x3c26700;
          iVar3 = iVar6 + 0x48;
          if (iVar5 < 0x1e28500)
          {
            bVar1 = true;
          }
          else
          {
            iVar3 = iVar6 + 0x49;
            iVar5 = iVar4 + -0x5a4ec00;
          }
        }
      }
      *(int *)(param_1[1] + 4) = iVar3;
      piVar7 = (int *)&DAT_1800cd740;
      iVar6 = 1;
      iVar4 = iVar5 / 0x15180;
      *(int *)(param_1[1] + 0xc) = iVar4;
      piVar8 = piVar7;
      if (bVar1)
      {
        piVar7 = &DAT_1800cd778;
        piVar8 = piVar7;
      }
      while (piVar7 = piVar7 + 1, *piVar7 < iVar4)
      {
        iVar6 = iVar6 + 1;
      }
      *(int *)param_1[1] = iVar6 + -1;
      *(int *)(*param_1 + 0xc) = iVar4 - piVar8[iVar6 + -1];
      iVar4 = (int)((ulonglong)((longlong)*param_2 * -0x3dd1baf9) >> 0x20) + *param_2;
      *(undefined4 *)param_1[2] = 0;
      *(int *)(param_1[1] + 8) = (((iVar4 >> 0x10) + 4) - (iVar4 >> 0x1f)) % 7;
      *(int *)(*param_1 + 8) = (iVar5 % 0x15180) / 0xe10;
      iVar4 = (iVar5 % 0x15180) % 0xe10;
      *(int *)(*param_1 + 4) = iVar4 / 0x3c;
      *(int *)*param_1 = iVar4 % 0x3c;
      return 0;
    }
    puVar2 = __doserrno();
    *puVar2 = 0x16;
  }
  return 0x16;
}

// Library Function - Single Match
//  _gmtime64
//
// Library: Visual Studio 2015 Release

tm *_gmtime64(__time64_t *_Time)
{
  int iVar1;
  tm *ptVar2;
  tm *ptVar3;

  ptVar2 = __getgmtimebuf();
  ptVar3 = (tm *)0x0;
  if ((ptVar2 != (tm *)0x0) &&
      (iVar1 = common_gmtime_s___int64_(ptVar2, _Time), ptVar3 = ptVar2, iVar1 != 0))
  {
    ptVar3 = (tm *)0x0;
  }
  return ptVar3;
}

int common_gmtime_s___int64_(tm *param_1, __int64 *param_2)
{
  int iVar1;
  ulong *puVar2;
  longlong lVar3;
  int iVar4;
  int *piVar5;
  int *piVar6;
  char acStackX8[8];
  longlong alStackX24[2];

  if ((param_1 == (tm *)0x0) ||
      (FUN_18003bd40((undefined(*)[16])param_1, 0xff, 0x24), param_2 == (__int64 *)0x0))
  {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_18006738c();
  }
  else
  {
    alStackX24[0] = *param_2;
    if ((-0xa8c1 < alStackX24[0]) && (alStackX24[0] < 0x79358e1d0))
    {
      acStackX8[0] = '\0';
      iVar1 = FUN_180070980(alStackX24, acStackX8);
      piVar5 = (int *)&DAT_1800cd740;
      param_1->tm_year = iVar1;
      iVar4 = 1;
      iVar1 = (int)(alStackX24[0] / 0x15180);
      param_1->tm_yday = iVar1;
      alStackX24[0] = alStackX24[0] + (longlong)iVar1 * -0x15180;
      piVar6 = piVar5;
      if (acStackX8[0] != '\0')
      {
        piVar5 = &DAT_1800cd778;
        piVar6 = piVar5;
      }
      while (piVar5 = piVar5 + 1, *piVar5 < iVar1)
      {
        iVar4 = iVar4 + 1;
      }
      param_1->tm_mon = iVar4 + -1;
      param_1->tm_mday = iVar1 - piVar6[iVar4 + -1];
      lVar3 = *param_2;
      param_1->tm_isdst = 0;
      param_1->tm_wday = ((int)(lVar3 / 0x15180) + 4) % 7;
      iVar1 = (int)(alStackX24[0] / 0xe10);
      param_1->tm_hour = iVar1;
      alStackX24[0] = alStackX24[0] + (longlong)iVar1 * -0xe10;
      lVar3 = SUB168(SEXT816(-0x7777777777777777) * SEXT816(alStackX24[0]) >> 0x40, 0) +
              alStackX24[0];
      iVar1 = (int)(lVar3 >> 5) - (int)(lVar3 >> 0x3f);
      param_1->tm_min = iVar1;
      param_1->tm_sec = (int)alStackX24[0] + iVar1 * -0x3c;
      return 0;
    }
    puVar2 = __doserrno();
    *puVar2 = 0x16;
  }
  return 0x16;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked
// Library Function - Single Match
//  void __cdecl tzset_from_system_nolock(void)
//
// Library: Visual Studio 2015 Release

void tzset_from_system_nolock(void)
{
  code *pcVar1;
  long lVar2;
  errno_t eVar3;
  DWORD DVar4;
  UINT CodePage;
  int iVar5;
  LPSTR *ppCVar6;
  int *piVar7;
  long *plVar8;
  int local_res8[2];
  long local_res10[2];
  int local_res18[2];
  int local_res20[2];

  ppCVar6 = (LPSTR *)FUN_180070350();
  local_res8[0] = 0;
  local_res10[0] = 0;
  local_res18[0] = 0;
  eVar3 = FID_conflict__get_daylight(local_res8);
  if (eVar3 != 0)
  {
    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  eVar3 = FID_conflict__get_daylight(local_res10);
  if (eVar3 == 0)
  {
    eVar3 = FID_conflict__get_daylight(local_res18);
    if (eVar3 == 0)
    {
      _free_base(DAT_180102130);
      DAT_180102130 = (LPVOID)0x0;
      DVar4 = GetTimeZoneInformation((LPTIME_ZONE_INFORMATION)&DAT_180102150);
      if (DVar4 != 0xffffffff)
      {
        local_res8[0] = DAT_180102150 * 0x3c;
        _DAT_180102140 = 1;
        if (DAT_180102196 != 0)
        {
          local_res8[0] = local_res8[0] + DAT_1801021a4 * 0x3c;
        }
        if ((DAT_1801021ea == 0) || (DAT_1801021f8 == 0))
        {
          local_res10[0] = 0;
          local_res18[0] = 0;
        }
        else
        {
          local_res10[0] = 1;
          local_res18[0] = (DAT_1801021f8 - DAT_1801021a4) * 0x3c;
        }
        CodePage = ___lc_codepage_func();
        iVar5 = WideCharToMultiByte(CodePage, 0, (LPCWSTR)&DAT_180102154, -1, *ppCVar6, 0x3f, (LPCSTR)0x0,
                                    local_res20);
        if ((iVar5 == 0) || (local_res20[0] != 0))
        {
          **ppCVar6 = '\0';
        }
        else
        {
          (*ppCVar6)[0x3f] = '\0';
        }
        iVar5 = WideCharToMultiByte(CodePage, 0, (LPCWSTR)&DAT_1801021a8, -1, ppCVar6[1], 0x3f,
                                    (LPCSTR)0x0, local_res20);
        if ((iVar5 == 0) || (local_res20[0] != 0))
        {
          *ppCVar6[1] = '\0';
        }
        else
        {
          ppCVar6[1][0x3f] = '\0';
        }
      }
      iVar5 = local_res8[0];
      piVar7 = (int *)FUN_180070348();
      lVar2 = local_res10[0];
      *piVar7 = iVar5;
      plVar8 = (long *)FUN_180070338();
      iVar5 = local_res18[0];
      *plVar8 = lVar2;
      piVar7 = (int *)FUN_180070340();
      *piVar7 = iVar5;
      return;
    }
    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Unknown calling convention yet parameter storage is locked
// Library Function - Single Match
//  void __cdecl tzset_nolock(void)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void tzset_nolock(void)
{
  int iVar1;
  byte *pbVar2;
  byte *pbVar3;
  byte *pbVar4;
  undefined auStack328[32];
  ulonglong local_128;
  ulonglong local_120;
  byte local_118[256];
  ulonglong local_18;

  local_18 = DAT_1800ee160 ^ (ulonglong)auStack328;
  pbVar4 = (byte *)0x0;
  _DAT_1800ee900 = 0xffffffff;
  _DAT_180102140 = 0;
  _DAT_1800ee8f0 = 0xffffffff;
  iVar1 = thunk_FUN_180083b78(&local_128, (char *)local_118, 0x100, "TZ");
  if (iVar1 == 0)
  {
    pbVar2 = local_118;
  }
  else
  {
    pbVar2 = pbVar4;
    if (iVar1 == 0x22)
    {
      pbVar2 = (byte *)_malloc_base(local_128);
      if (pbVar2 == (byte *)0x0)
      {
        pbVar2 = (byte *)0x0;
      }
      else
      {
        iVar1 = thunk_FUN_180083b78(&local_120, (char *)pbVar2, local_128, "TZ");
        if (iVar1 == 0)
        {
          _free_base((LPVOID)0x0);
          goto LAB_18007164c;
        }
      }
      _free_base(pbVar2);
      pbVar2 = pbVar4;
    }
  }
LAB_18007164c:
  pbVar3 = pbVar2;
  if (pbVar2 == local_118)
  {
    pbVar3 = pbVar4;
  }
  if ((pbVar2 == (byte *)0x0) || (*pbVar2 == 0))
  {
    tzset_from_system_nolock();
  }
  else
  {
    FUN_180071164(pbVar2);
  }
  _free_base(pbVar3);
  FUN_180034d00(local_18 ^ (ulonglong)auStack328);
  return;
}

// Library Function - Single Match
//  __tzset
//
// Library: Visual Studio 2015 Release

void __tzset(void)
{
  if (DAT_1801021fc == 0)
  {
    __acrt_lock(6);
    if (DAT_1801021fc == 0)
    {
      tzset_nolock();
      LOCK();
      DAT_1801021fc = DAT_1801021fc + 1;
    }
    __acrt_unlock(6);
  }
  return;
}

// Library Function - Single Match
//  _isindst
//
// Library: Visual Studio 2015 Release

int _isindst(tm *_Time)
{
  ulonglong uVar1;

  __acrt_lock(6);
  uVar1 = FUN_180070b70((int *)_Time);
  __acrt_unlock(6);
  return (int)uVar1;
}

// Library Function - Single Match
//  int __cdecl compute_iso_week_internal(int,int,int)
//
// Library: Visual Studio 2015 Release

int compute_iso_week_internal(int param_1, int param_2, int param_3)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;

  iVar2 = ((param_3 - (param_2 + 6) % 7) + 7) / 7;
  bVar1 = __crt_time_is_leap_year_int_(param_1);
  iVar5 = param_3 - (uint)bVar1;
  iVar4 = ((param_2 - param_3) + 0x173) % 7;
  iVar3 = (int)(bVar1 + 0x16d + iVar4) % 7;
  if ((((iVar5 < 0x16c) || (iVar3 != 2)) && ((iVar5 < 0x16b || (iVar3 != 3)))) &&
      ((iVar5 < 0x16a || (iVar3 != 4))))
  {
    if (iVar4 - 2U < 3)
    {
      iVar2 = iVar2 + 1;
    }
  }
  else
  {
    iVar2 = -1;
  }
  return iVar2;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_630b2aca97f6d20d5b5ea6529ea6b6af>,class <lambda_af91936f1d075d609f72d9d8cba980af>&
// __ptr64,class <lambda_e82fa975f615b5c7c7b0e4d178fdae67>>(class
// <lambda_630b2aca97f6d20d5b5ea6529ea6b6af>&& __ptr64,class
// <lambda_af91936f1d075d609f72d9d8cba980af>& __ptr64,class
// <lambda_e82fa975f615b5c7c7b0e4d178fdae67>&& __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

int __thiscall __crt_seh_guarded_call<int>::

    operator___class__lambda_630b2aca97f6d20d5b5ea6529ea6b6af__class__lambda_af91936f1d075d609f72d9d8cba980af_____ptr64_class__lambda_e82fa975f615b5c7c7b0e4d178fdae67___(__crt_seh_guarded_call_int_ *this, _lambda_630b2aca97f6d20d5b5ea6529ea6b6af_ *param_1,
                                                                                                                                                                          _lambda_af91936f1d075d609f72d9d8cba980af_ *param_2,
                                                                                                                                                                          _lambda_e82fa975f615b5c7c7b0e4d178fdae67_ *param_3)
{
  byte bVar1;
  BOOL BVar2;

  __acrt_lock(*(int *)param_1);
  bVar1 = -((byte)DAT_1800ee160 & 0x3f) & 0x3f;
  _DAT_1801023b0 =
      (**(ulonglong **)param_2 >> bVar1 | **(ulonglong **)param_2 << 0x40 - bVar1) ^ DAT_1800ee160;
  BVar2 = EnumSystemLocalesW((LOCALE_ENUMPROCW)&LAB_180073e40, 1);
  bVar1 = 0x40 - ((byte)DAT_1800ee160 & 0x3f) & 0x3f;
  _DAT_1801023b0 = ((ulonglong)(0 >> bVar1) | 0 << 0x40 - bVar1) ^ DAT_1800ee160;
  __acrt_unlock(*(int *)param_3);
  return (int)BVar2;
}

// Library Function - Single Match
//  int __cdecl __acrt_lock_and_call<class <lambda_af91936f1d075d609f72d9d8cba980af>>(enum
// __acrt_lock_id,class <lambda_af91936f1d075d609f72d9d8cba980af>&& __ptr64)
//
// Library: Visual Studio 2015 Release

int __acrt_lock_and_call_class__lambda_af91936f1d075d609f72d9d8cba980af___(__acrt_lock_id param_1, _lambda_af91936f1d075d609f72d9d8cba980af_ *param_2)
{
  int iVar1;
  __crt_seh_guarded_call_int_ local_res8[16];
  __acrt_lock_id local_res18[2];
  __acrt_lock_id local_res20[2];

  local_res18[0] = param_1;
  local_res20[0] = param_1;
  iVar1 = __crt_seh_guarded_call<int>::

      operator___class__lambda_630b2aca97f6d20d5b5ea6529ea6b6af__class__lambda_af91936f1d075d609f72d9d8cba980af_____ptr64_class__lambda_e82fa975f615b5c7c7b0e4d178fdae67___(local_res8, (_lambda_630b2aca97f6d20d5b5ea6529ea6b6af_ *)local_res20, param_2,
                                                                                                                                                                            (_lambda_e82fa975f615b5c7c7b0e4d178fdae67_ *)local_res18);
  return iVar1;
}

// Library Function - Single Match
//  void * __ptr64 __cdecl try_get_function(enum `anonymous namespace'::function_id,char const *
// __ptr64 const,enum A0x391cf84c::module_id const * __ptr64 const,enum A0x391cf84c::module_id const
// * __ptr64 const)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void *try_get_function(function_id param_1, char *param_2, module_id *param_3, module_id *param_4)
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
  bVar2 = (byte)DAT_1800ee160 & 0x3f;
  pFVar5 = (FARPROC)((DAT_1800ee160 ^ *(ulonglong *)((longlong)&DAT_1801022a0 + uVar7 * 8)) >> bVar2 | (DAT_1800ee160 ^ *(ulonglong *)((longlong)&DAT_1801022a0 + uVar7 * 8)) << 0x40 - bVar2);
  if (pFVar5 != (FARPROC)0xffffffffffffffff)
  {
    if (pFVar5 != (FARPROC)0x0)
    {
      return pFVar5;
    }
    if (param_3 != param_4)
    {
      do
      {
        uVar6 = (ulonglong)*param_3;
        hLibModule = *(HMODULE *)((longlong)&DAT_180102200 + uVar6 * 8);
        if (hLibModule == (HMODULE)0x0)
        {
          lpLibFileName = (wchar_t *)(&PTR_u_api_ms_win_core_datetime_l1_1_1_1800cac60)[uVar6];
          hLibModule = LoadLibraryExW(lpLibFileName, (HANDLE)0x0, 0x800);
          if (hLibModule == (HMODULE)0x0)
          {
            DVar3 = GetLastError();
            if (((DVar3 == 0x57) && (iVar4 = wcsncmp(lpLibFileName, L"api-ms-", 7), iVar4 != 0)) &&
                (iVar4 = wcsncmp(lpLibFileName, L"ext-ms-", 7), iVar4 != 0))
            {
              hLibModule = LoadLibraryExW(lpLibFileName, (HANDLE)0x0, 0);
            }
            else
            {
              hLibModule = (HMODULE)0x0;
            }
          }
          if (hLibModule != (HMODULE)0x0)
          {
            pHVar1 = *(HMODULE *)((longlong)&DAT_180102200 + uVar6 * 8);
            *(HMODULE *)((longlong)&DAT_180102200 + uVar6 * 8) = hLibModule;
            if (pHVar1 != (HMODULE)0x0)
            {
              FreeLibrary(hLibModule);
            }
            goto LAB_180074732;
          }
          *(undefined8 *)((longlong)&DAT_180102200 + uVar6 * 8) = 0xffffffffffffffff;
        }
        else
        {
          if (hLibModule != (HMODULE)0xffffffffffffffff)
          {
          LAB_180074732:
            if (hLibModule != (HMODULE)0x0)
              goto LAB_18007474d;
          }
        }
        param_3 = param_3 + 1;
      } while (param_3 != param_4);
    }
    hLibModule = (HMODULE)0x0;
  LAB_18007474d:
    if ((hLibModule != (HMODULE)0x0) &&
        (pFVar5 = GetProcAddress(hLibModule, param_2), pFVar5 != (FARPROC)0x0))
    {
      bVar2 = 0x40 - ((byte)DAT_1800ee160 & 0x3f) & 0x3f;
      *(ulonglong *)((longlong)&DAT_1801022a0 + uVar7 * 8) =
          ((ulonglong)pFVar5 >> bVar2 | (longlong)pFVar5 << 0x40 - bVar2) ^ DAT_1800ee160;
      return pFVar5;
    }
    bVar2 = 0x40 - ((byte)DAT_1800ee160 & 0x3f) & 0x3f;
    *(ulonglong *)((longlong)&DAT_1801022a0 + uVar7 * 8) =
        (0xffffffffffffffffU >> bVar2 | -1 << 0x40 - bVar2) ^ DAT_1800ee160;
  }
  return (FARPROC)0x0;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_AppPolicyGetProcessTerminationMethodInternal
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 __acrt_AppPolicyGetProcessTerminationMethodInternal(void)
{
  code *pcVar1;
  undefined8 uVar2;

  pcVar1 = (code *)try_get_function(0x1c, "AppPolicyGetProcessTerminationMethod",
                                    (module_id *)&DAT_1800cb420, (module_id *)&DAT_1800cb424);
  if (pcVar1 != (code *)0x0)
  {
    uVar2 = (*pcVar1)();
    // WARNING: Treating indirect jump as call
    return uVar2;
  }
  return 0xc0000225;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_AppPolicyGetShowDeveloperDiagnosticInternal
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 __acrt_AppPolicyGetShowDeveloperDiagnosticInternal(void)
{
  code *pcVar1;
  undefined8 uVar2;

  pcVar1 = (code *)try_get_function(0x1e, "AppPolicyGetShowDeveloperDiagnostic",
                                    (module_id *)&DAT_1800cb480, (module_id *)&DAT_1800cb484);
  if (pcVar1 != (code *)0x0)
  {
    uVar2 = (*pcVar1)();
    // WARNING: Treating indirect jump as call
    return uVar2;
  }
  return 0xc0000225;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_AppPolicyGetThreadInitializationTypeInternal
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 __acrt_AppPolicyGetThreadInitializationTypeInternal(void)
{
  code *pcVar1;
  undefined8 uVar2;

  pcVar1 = (code *)try_get_function(0x1d, "AppPolicyGetThreadInitializationType",
                                    (module_id *)&DAT_1800cb450, (module_id *)&DAT_1800cb454);
  if (pcVar1 != (code *)0x0)
  {
    uVar2 = (*pcVar1)();
    // WARNING: Treating indirect jump as call
    return uVar2;
  }
  return 0xc0000225;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_AppPolicyGetWindowingModelInternal
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 __acrt_AppPolicyGetWindowingModelInternal(void)
{
  code *pcVar1;
  undefined8 uVar2;

  pcVar1 = (code *)try_get_function(0x1f, "AppPolicyGetWindowingModel", (module_id *)&DAT_1800cb4ac,
                                    (module_id *)"AppPolicyGetWindowingModel");
  if (pcVar1 != (code *)0x0)
  {
    uVar2 = (*pcVar1)();
    // WARNING: Treating indirect jump as call
    return uVar2;
  }
  return 0xc0000225;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_AreFileApisANSI
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 __acrt_AreFileApisANSI(void)
{
  code *pcVar1;
  undefined8 uVar2;

  pcVar1 = (code *)try_get_function(0, "AreFileApisANSI", (module_id *)&DAT_1800cb158,
                                    (module_id *)&DAT_1800cb15c);
  if (pcVar1 != (code *)0x0)
  {
    uVar2 = (*pcVar1)();
    // WARNING: Treating indirect jump as call
    return uVar2;
  }
  return 1;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_CompareStringEx
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_CompareStringEx(longlong param_1, DWORD param_2, PCNZWCH param_3, int param_4, PCNZWCH param_5,
                            int param_6)
{
  LCID Locale;
  code *pcVar1;

  pcVar1 = (code *)try_get_function(1, "CompareStringEx", (module_id *)&DAT_1800cb170,
                                    (module_id *)"CompareStringEx");
  if (pcVar1 == (code *)0x0)
  {
    Locale = __acrt_LocaleNameToLCID(param_1);
    CompareStringW(Locale, param_2, param_3, param_4, param_5, param_6);
  }
  else
  {
    (*pcVar1)();
  }
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_EnumSystemLocalesEx
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_EnumSystemLocalesEx(undefined8 param_1)
{
  code *pcVar1;
  undefined8 local_res8;
  __crt_seh_guarded_call_int_ local_28[4];
  undefined4 local_24;
  undefined4 local_20[2];
  undefined8 *local_18[2];

  local_res8 = param_1;
  pcVar1 = (code *)try_get_function(2, "EnumSystemLocalesEx", (module_id *)&DAT_1800cb188,
                                    (module_id *)"EnumSystemLocalesEx");
  if (pcVar1 == (code *)0x0)
  {
    local_18[0] = &local_res8;
    local_24 = 4;
    local_20[0] = 4;
    __crt_seh_guarded_call<int>::

        operator___class__lambda_630b2aca97f6d20d5b5ea6529ea6b6af__class__lambda_af91936f1d075d609f72d9d8cba980af_____ptr64_class__lambda_e82fa975f615b5c7c7b0e4d178fdae67___(local_28, (_lambda_630b2aca97f6d20d5b5ea6529ea6b6af_ *)local_20,
                                                                                                                                                                              (_lambda_af91936f1d075d609f72d9d8cba980af_ *)local_18,
                                                                                                                                                                              (_lambda_e82fa975f615b5c7c7b0e4d178fdae67_ *)&local_24);
  }
  else
  {
    (*pcVar1)();
  }
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_FlsAlloc
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_FlsAlloc(void)
{
  code *pcVar1;

  pcVar1 = (code *)try_get_function(3, "FlsAlloc", (module_id *)&DAT_1800cb1a8,
                                    (module_id *)&DAT_1800cb1b0);
  if (pcVar1 != (code *)0x0)
  {
    (*pcVar1)();
    // WARNING: Treating indirect jump as call
    return;
  }
  // WARNING: Could not recover jumptable at 0x000180074dbd. Too many branches
  // WARNING: Treating indirect jump as call
  TlsAlloc();
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_FlsFree
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_FlsFree(DWORD param_1)
{
  code *pcVar1;

  pcVar1 = (code *)try_get_function(4, "FlsFree", (module_id *)&DAT_1800cb1b0,
                                    (module_id *)&DAT_1800cb1b8);
  if (pcVar1 != (code *)0x0)
  {
    (*pcVar1)();
    // WARNING: Treating indirect jump as call
    return;
  }
  // WARNING: Could not recover jumptable at 0x000180074e03. Too many branches
  // WARNING: Treating indirect jump as call
  TlsFree(param_1);
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_FlsGetValue
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_FlsGetValue(DWORD param_1)
{
  code *pcVar1;

  pcVar1 = (code *)try_get_function(5, "FlsGetValue", (module_id *)&DAT_1800cb1b8,
                                    (module_id *)&DAT_1800cb1c0);
  if (pcVar1 != (code *)0x0)
  {
    (*pcVar1)();
    // WARNING: Treating indirect jump as call
    return;
  }
  // WARNING: Could not recover jumptable at 0x000180074e4b. Too many branches
  // WARNING: Treating indirect jump as call
  TlsGetValue(param_1);
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_FlsSetValue
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_FlsSetValue(DWORD param_1, LPVOID param_2)
{
  code *pcVar1;

  pcVar1 = (code *)try_get_function(6, "FlsSetValue", (module_id *)&DAT_1800cb1c0,
                                    (module_id *)&DAT_1800cb1c8);
  if (pcVar1 == (code *)0x0)
  {
    TlsSetValue(param_1, param_2);
  }
  else
  {
    (*pcVar1)();
  }
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_GetDateFormatEx
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_GetDateFormatEx(longlong param_1, DWORD param_2, SYSTEMTIME *param_3, LPCWSTR param_4, LPWSTR param_5,
                            int param_6)
{
  LCID Locale;
  code *pcVar1;

  pcVar1 = (code *)try_get_function(8, "GetDateFormatEx", (module_id *)&DAT_1800cb1e0,
                                    (module_id *)"GetDateFormatEx");
  if (pcVar1 == (code *)0x0)
  {
    Locale = __acrt_LocaleNameToLCID(param_1);
    GetDateFormatW(Locale, param_2, param_3, param_4, param_5, param_6);
  }
  else
  {
    (*pcVar1)();
  }
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_GetLocaleInfoEx
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_GetLocaleInfoEx(longlong param_1, LCTYPE param_2, LPWSTR param_3, int param_4)
{
  LCID Locale;
  code *pcVar1;

  pcVar1 = (code *)try_get_function(0xb, "GetLocaleInfoEx", (module_id *)&DAT_1800cb240,
                                    (module_id *)"GetLocaleInfoEx");
  if (pcVar1 == (code *)0x0)
  {
    Locale = __acrt_LocaleNameToLCID(param_1);
    GetLocaleInfoW(Locale, param_2, param_3, param_4);
  }
  else
  {
    (*pcVar1)();
  }
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_GetSystemTimePreciseAsFileTime
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_GetSystemTimePreciseAsFileTime(LPFILETIME param_1)
{
  code *pcVar1;

  pcVar1 = (code *)try_get_function(0xd, "GetSystemTimePreciseAsFileTime", (module_id *)&DAT_1800cb278, (module_id *)&DAT_1800cb27c);
  if (pcVar1 != (code *)0x0)
  {
    (*pcVar1)();
    // WARNING: Treating indirect jump as call
    return;
  }
  // WARNING: Could not recover jumptable at 0x000180075061. Too many branches
  // WARNING: Treating indirect jump as call
  GetSystemTimeAsFileTime(param_1);
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_GetTimeFormatEx
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_GetTimeFormatEx(longlong param_1, DWORD param_2, SYSTEMTIME *param_3, LPCWSTR param_4, LPWSTR param_5,
                            int param_6)
{
  LCID Locale;
  code *pcVar1;

  pcVar1 = (code *)try_get_function(0xe, "GetTimeFormatEx", (module_id *)&DAT_1800cb2a0,
                                    (module_id *)"GetTimeFormatEx");
  if (pcVar1 == (code *)0x0)
  {
    Locale = __acrt_LocaleNameToLCID(param_1);
    GetTimeFormatW(Locale, param_2, param_3, param_4, param_5, param_6);
  }
  else
  {
    (*pcVar1)();
  }
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_GetUserDefaultLocaleName
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_GetUserDefaultLocaleName(wchar_t *param_1, int param_2)
{
  LCID LVar1;
  code *pcVar2;

  pcVar2 = (code *)try_get_function(0xf, "GetUserDefaultLocaleName", (module_id *)&DAT_1800cb2b8,
                                    (module_id *)"GetUserDefaultLocaleName");
  if (pcVar2 == (code *)0x0)
  {
    LVar1 = GetUserDefaultLCID();
    __acrt_LCIDToLocaleName(LVar1, param_1, param_2);
  }
  else
  {
    (*pcVar2)();
  }
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_GetXStateFeaturesMask
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_GetXStateFeaturesMask(void)
{
  code *pcVar1;

  pcVar1 = (code *)try_get_function(0x11, "GetXStateFeaturesMask", (module_id *)&DAT_1800cb308,
                                    (module_id *)"GetXStateFeaturesMask");
  if (pcVar1 != (code *)0x0)
  {
    (*pcVar1)();
    // WARNING: Treating indirect jump as call
    return;
  }
  abort();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_InitializeCriticalSectionEx
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_InitializeCriticalSectionEx(LPCRITICAL_SECTION param_1, DWORD param_2)
{
  code *pcVar1;

  pcVar1 = (code *)try_get_function(0x12, "InitializeCriticalSectionEx", (module_id *)&DAT_1800cb328,
                                    (module_id *)&DAT_1800cb330);
  if (pcVar1 == (code *)0x0)
  {
    InitializeCriticalSectionAndSpinCount(param_1, param_2);
  }
  else
  {
    (*pcVar1)();
  }
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_IsValidLocaleName
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_IsValidLocaleName(longlong param_1)
{
  LCID Locale;
  code *pcVar1;

  pcVar1 = (code *)try_get_function(0x13, "IsValidLocaleName", (module_id *)&DAT_1800cb330,
                                    (module_id *)"IsValidLocaleName");
  if (pcVar1 != (code *)0x0)
  {
    (*pcVar1)();
    // WARNING: Treating indirect jump as call
    return;
  }
  Locale = __acrt_LocaleNameToLCID(param_1);
  // WARNING: Could not recover jumptable at 0x00018007527f. Too many branches
  // WARNING: Treating indirect jump as call
  IsValidLocale(Locale, 1);
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_LCIDToLocaleName
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_LCIDToLocaleName(uint param_1, wchar_t *param_2, int param_3)
{
  code *pcVar1;

  pcVar1 = (code *)try_get_function(0x15, "LCIDToLocaleName", (module_id *)&DAT_1800cb368,
                                    (module_id *)"LCIDToLocaleName");
  if (pcVar1 == (code *)0x0)
  {
    FUN_180084618(param_1, param_2, param_3);
  }
  else
  {
    (*pcVar1)();
  }
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_LCMapStringEx
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_LCMapStringEx(longlong param_1, DWORD param_2, LPCWSTR param_3, int param_4, LPWSTR param_5,
                          int param_6)
{
  LCID Locale;
  code *pcVar1;

  pcVar1 = (code *)try_get_function(0x14, "LCMapStringEx", (module_id *)&DAT_1800cb350,
                                    (module_id *)"LCMapStringEx");
  if (pcVar1 == (code *)0x0)
  {
    Locale = __acrt_LocaleNameToLCID(param_1);
    LCMapStringW(Locale, param_2, param_3, param_4, param_5, param_6);
  }
  else
  {
    (*pcVar1)();
  }
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_LocaleNameToLCID
//
// Library: Visual Studio 2017 Release

void __acrt_LocaleNameToLCID(longlong param_1)
{
  code *pcVar1;

  pcVar1 = (code *)try_get_function(0x16, "LocaleNameToLCID", (module_id *)&DAT_1800cb388,
                                    (module_id *)"LocaleNameToLCID");
  if (pcVar1 == (code *)0x0)
  {
    __acrt_DownlevelLocaleNameToLCID(param_1);
  }
  else
  {
    (*pcVar1)();
  }
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_MessageBoxW
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_MessageBoxW(void)
{
  code *pcVar1;

  pcVar1 = (code *)try_get_function(0x19, "MessageBoxW", (module_id *)&DAT_1800cb3e0,
                                    (module_id *)"MessageBoxW");
  if (pcVar1 != (code *)0x0)
  {
    (*pcVar1)();
    return;
  }
  abort();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_RoInitialize
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_RoInitialize(void)
{
  code *pcVar1;

  pcVar1 = (code *)try_get_function(0x1a, "RoInitialize", (module_id *)&DAT_1800cb3f4,
                                    (module_id *)"RoInitialize");
  if (pcVar1 != (code *)0x0)
  {
    (*pcVar1)();
    // WARNING: Treating indirect jump as call
    return;
  }
  return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Single Match
//  __acrt_SetThreadStackGuarantee
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_SetThreadStackGuarantee(void)
{
  code *pcVar1;

  pcVar1 = (code *)try_get_function(0x20, "SetThreadStackGuarantee", (module_id *)&DAT_1800cb4d0,
                                    (module_id *)"SetThreadStackGuarantee");
  if (pcVar1 != (code *)0x0)
  {
    (*pcVar1)();
    // WARNING: Treating indirect jump as call
    return;
  }
  return;
}

// Library Function - Single Match
//  __acrt_can_use_vista_locale_apis
//
// Library: Visual Studio 2015 Release

ulonglong __acrt_can_use_vista_locale_apis(void)
{
  void *pvVar1;

  pvVar1 = try_get_function(1, "CompareStringEx", (module_id *)&DAT_1800cb170,
                            (module_id *)"CompareStringEx");
  return (ulonglong)pvVar1 & 0xffffffffffffff00 | (ulonglong)(pvVar1 != (void *)0x0);
}

// Library Function - Single Match
//  __acrt_eagerly_load_locale_apis
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_eagerly_load_locale_apis(void)
{
  try_get_function(0, "AreFileApisANSI", (module_id *)&DAT_1800cb158, (module_id *)&DAT_1800cb15c);
  try_get_function(1, "CompareStringEx", (module_id *)&DAT_1800cb170, (module_id *)"CompareStringEx");
  try_get_function(2, "EnumSystemLocalesEx", (module_id *)&DAT_1800cb188,
                   (module_id *)"EnumSystemLocalesEx");
  try_get_function(8, "GetDateFormatEx", (module_id *)&DAT_1800cb1e0, (module_id *)"GetDateFormatEx");
  try_get_function(0xb, "GetLocaleInfoEx", (module_id *)&DAT_1800cb240, (module_id *)"GetLocaleInfoEx");
  try_get_function(0xe, "GetTimeFormatEx", (module_id *)&DAT_1800cb2a0, (module_id *)"GetTimeFormatEx");
  try_get_function(0xf, "GetUserDefaultLocaleName", (module_id *)&DAT_1800cb2b8,
                   (module_id *)"GetUserDefaultLocaleName");
  try_get_function(0x13, "IsValidLocaleName", (module_id *)&DAT_1800cb330,
                   (module_id *)"IsValidLocaleName");
  try_get_function(0x14, "LCMapStringEx", (module_id *)&DAT_1800cb350, (module_id *)"LCMapStringEx");
  try_get_function(0x15, "LCIDToLocaleName", (module_id *)&DAT_1800cb368,
                   (module_id *)"LCIDToLocaleName");
  try_get_function(0x16, "LocaleNameToLCID", (module_id *)&DAT_1800cb388,
                   (module_id *)"LocaleNameToLCID");
  return;
}

// Library Function - Single Match
//  __acrt_uninitialize_winapi_thunks
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 __acrt_uninitialize_winapi_thunks(char param_1)
{
  HMODULE hLibModule;
  undefined *in_RAX;
  HMODULE *ppHVar1;

  if (param_1 == '\0')
  {
    ppHVar1 = (HMODULE *)&DAT_180102200;
    do
    {
      hLibModule = *ppHVar1;
      if (hLibModule != (HMODULE)0x0)
      {
        if (hLibModule != (HMODULE)0xffffffffffffffff)
        {
          FreeLibrary(hLibModule);
        }
        *ppHVar1 = (HMODULE)0x0;
      }
      ppHVar1 = ppHVar1 + 1;
      in_RAX = (undefined *)&DAT_1801022a0;
    } while (ppHVar1 != (HMODULE *)&DAT_1801022a0);
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Single Match
//  __acrt_initialize_locks
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong __acrt_initialize_locks(void)
{
  undefined8 uVar1;
  ulonglong uVar2;
  uint uVar3;

  uVar2 = 0;
  do
  {
    uVar1 = __acrt_InitializeCriticalSectionEx((LPCRITICAL_SECTION)(&DAT_1801023c0 + uVar2 * 0x28), 4000);
    if ((int)uVar1 == 0)
    {
      uVar2 = __acrt_uninitialize_locks();
      return uVar2 & 0xffffffffffffff00;
    }
    DAT_1801025f0 = DAT_1801025f0 + 1;
    uVar3 = (int)uVar2 + 1;
    uVar2 = (ulonglong)uVar3;
  } while (uVar3 < 0xe);
  return CONCAT71((int7)((ulonglong)uVar1 >> 8), 1);
}

// Library Function - Multiple Matches With Different Base Names
//  __acrt_lock
//  __acrt_unlock
//
// Library: Visual Studio 2015 Release

void __acrt_lock(int param_1)
{
  // WARNING: Could not recover jumptable at 0x000180075ada. Too many branches
  // WARNING: Treating indirect jump as call
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_1801023c0 + (longlong)param_1 * 0x28));
  return;
}

// Library Function - Single Match
//  __acrt_uninitialize_locks
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 __acrt_uninitialize_locks(void)
{
  undefined8 in_RAX;
  undefined8 extraout_RAX;
  ulonglong uVar1;

  uVar1 = (ulonglong)DAT_1801025f0;
  while ((int)uVar1 != 0)
  {
    uVar1 = (ulonglong)((int)uVar1 - 1);
    DeleteCriticalSection((LPCRITICAL_SECTION)(&DAT_1801023c0 + uVar1 * 0x28));
    DAT_1801025f0 = DAT_1801025f0 - 1;
    in_RAX = extraout_RAX;
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Single Match
//  __acrt_unlock
//
// Library: Visual Studio 2015 Release

void __acrt_unlock(int param_1)
{
  // WARNING: Could not recover jumptable at 0x000180075b2e. Too many branches
  // WARNING: Treating indirect jump as call
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_1801023c0 + (longlong)param_1 * 0x28));
  return;
}

// Library Function - Single Match
//  _lock_locales
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void _lock_locales(void)
{
  __acrt_eagerly_load_locale_apis();
  // WARNING: Could not recover jumptable at 0x000180075b4c. Too many branches
  // WARNING: Treating indirect jump as call
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_180102460);
  return;
}

// Library Function - Single Match
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_b521505b218e5242e90febf6bfebc422>,class <lambda_6978c1fb23f02e42e1d9e99668cc68aa>&
// __ptr64,class <lambda_314360699dd331753a4119843814e9a7>>(class
// <lambda_b521505b218e5242e90febf6bfebc422>&& __ptr64,class
// <lambda_6978c1fb23f02e42e1d9e99668cc68aa>& __ptr64,class
// <lambda_314360699dd331753a4119843814e9a7>&& __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

int __thiscall __crt_seh_guarded_call<int>::

    operator___class__lambda_b521505b218e5242e90febf6bfebc422__class__lambda_6978c1fb23f02e42e1d9e99668cc68aa_____ptr64_class__lambda_314360699dd331753a4119843814e9a7___(__crt_seh_guarded_call_int_ *this, _lambda_b521505b218e5242e90febf6bfebc422_ *param_1,
                                                                                                                                                                          _lambda_6978c1fb23f02e42e1d9e99668cc68aa_ *param_2,
                                                                                                                                                                          _lambda_314360699dd331753a4119843814e9a7_ *param_3)
{
  uint _FileHandle;
  BOOL BVar1;
  DWORD DVar2;
  HANDLE hFile;
  ulong *puVar3;
  int iVar4;

  FID_conflict___acrt_lowio_lock_fh(*(uint *)param_1);
  _FileHandle = **(uint **)param_2;
  if ((*(byte *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)(int)_FileHandle >> 6) * 8) +
                 0x38 + (ulonglong)(_FileHandle & 0x3f) * 0x40) &
       1) != 0)
  {
    hFile = (HANDLE)_get_osfhandle(_FileHandle);
    BVar1 = FlushFileBuffers(hFile);
    iVar4 = 0;
    if (BVar1 != 0)
      goto LAB_180075bdc;
    puVar3 = __doserrno();
    DVar2 = GetLastError();
    *puVar3 = DVar2;
  }
  puVar3 = __doserrno();
  *puVar3 = 9;
  iVar4 = -1;
LAB_180075bdc:
  FID_conflict___acrt_lowio_lock_fh(*(uint *)param_3);
  return iVar4;
}

// Library Function - Single Match
//  _commit
//
// Library: Visual Studio 2015 Release

int _commit(int _FileHandle)
{
  int iVar1;
  ulong *puVar2;
  int local_res8[2];
  __crt_seh_guarded_call_int_ local_res10[8];
  int local_res18[2];
  int local_res20[2];
  int *local_18[3];

  local_res8[0] = _FileHandle;
  if (_FileHandle == -2)
  {
    puVar2 = __doserrno();
    *puVar2 = 9;
  }
  else
  {
    if (((-1 < _FileHandle) && ((uint)_FileHandle < DAT_180102110)) &&
        ((*(byte *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)_FileHandle >> 6) * 8) + 0x38 + (ulonglong)(_FileHandle & 0x3f) * 0x40) & 1) != 0))
    {
      local_18[0] = local_res8;
      local_res18[0] = _FileHandle;
      local_res20[0] = _FileHandle;
      iVar1 = __crt_seh_guarded_call<int>::

          operator___class__lambda_b521505b218e5242e90febf6bfebc422__class__lambda_6978c1fb23f02e42e1d9e99668cc68aa_____ptr64_class__lambda_314360699dd331753a4119843814e9a7___(local_res10, (_lambda_b521505b218e5242e90febf6bfebc422_ *)local_res20,
                                                                                                                                                                                (_lambda_6978c1fb23f02e42e1d9e99668cc68aa_ *)local_18,
                                                                                                                                                                                (_lambda_314360699dd331753a4119843814e9a7_ *)local_res18);
      return iVar1;
    }
    puVar2 = __doserrno();
    *puVar2 = 9;
    FUN_18006738c();
  }
  return -1;
}

// Library Function - Single Match
//  _towlower_l
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

wint_t _towlower_l(wint_t _C, _locale_t _Locale)
{
  ushort uVar1;
  int iVar2;
  undefined6 extraout_var;
  wint_t local_res8;
  wint_t local_res18[8];
  __acrt_ptd *local_28;
  longlong local_20;
  char local_10;

  local_res8 = 0xffff;
  if (_C != 0xffff)
  {
    local_res8 = _C;
    FUN_18004e538(&local_28, (undefined4 *)_Locale);
    if (*(longlong *)(local_20 + 0x138) == 0)
    {
      if ((ushort)(local_res8 - 0x41) < 0x1a)
      {
        local_res8 = local_res8 + 0x20;
      }
    }
    else
    {
      if (local_res8 < 0x100)
      {
        uVar1 = FUN_180079eb0(local_res8, 1);
        if ((int)CONCAT62(extraout_var, uVar1) != 0)
        {
          local_res8 = (wint_t) * (byte *)(*(longlong *)(local_20 + 0x110) + (ulonglong)local_res8);
        }
      }
      else
      {
        iVar2 = __acrt_LCMapStringW(*(longlong *)(local_20 + 0x138), 0x100,
                                    (undefined(*)[32]) & local_res8, 1, (LPWSTR)local_res18, 1);
        if (iVar2 != 0)
        {
          local_res8 = local_res18[0];
        }
      }
    }
    if (local_10 != '\0')
    {
      *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
    }
  }
  return local_res8;
}

// Library Function - Single Match
//  _fcloseall
//
// Library: Visual Studio 2015 Release

int _fcloseall(void)
{
  longlong lVar1;
  int iVar2;
  int iVar3;
  longlong lVar4;
  int local_18;

  local_18 = 0;
  __acrt_lock(8);
  iVar3 = 3;
  while (iVar3 != DAT_180101930)
  {
    lVar4 = (longlong)iVar3;
    lVar1 = *(longlong *)(DAT_180101938 + lVar4 * 8);
    if (lVar1 != 0)
    {
      if (((*(uint *)(lVar1 + 0x14) >> 0xd & 1) != 0) &&
          (iVar2 = FUN_180060674(*(FILE **)(DAT_180101938 + lVar4 * 8)), iVar2 != -1))
      {
        local_18 = local_18 + 1;
      }
      DeleteCriticalSection((LPCRITICAL_SECTION)(*(longlong *)(DAT_180101938 + lVar4 * 8) + 0x30));
      _free_base(*(LPVOID *)(DAT_180101938 + lVar4 * 8));
      *(undefined8 *)(DAT_180101938 + lVar4 * 8) = 0;
    }
    iVar3 = iVar3 + 1;
  }
  __acrt_unlock(8);
  return local_18;
}

// WARNING: Removing unreachable block (ram,0x0001800762a4)
// Library Function - Single Match
//  __acrt_get_begin_thread_init_policy
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int __acrt_get_begin_thread_init_policy(void)
{
  int iVar1;
  longlong in_GS_OFFSET;

  iVar1 = DAT_1801025f4;
  if ((DAT_1801025f4 == 0) &&
      (iVar1 = 1, -1 < *(int *)(*(longlong *)(*(longlong *)(in_GS_OFFSET + 0x60) + 0x20) + 8)))
  {
    __acrt_AppPolicyGetThreadInitializationTypeInternal();
  }
  DAT_1801025f4 = iVar1;
  return DAT_1801025f4;
}

// Library Function - Single Match
//  __acrt_get_developer_information_policy
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int __acrt_get_developer_information_policy(void)
{
  longlong in_GS_OFFSET;

  if (DAT_1801025f8 == 0)
  {
    if (-1 < *(int *)(*(longlong *)(*(longlong *)(in_GS_OFFSET + 0x60) + 0x20) + 8))
    {
      __acrt_AppPolicyGetShowDeveloperDiagnosticInternal();
    }
    DAT_1801025f8 = 2;
  }
  return DAT_1801025f8;
}

// Library Function - Single Match
//  __acrt_get_process_end_policy
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __acrt_get_process_end_policy(void)
{
  longlong in_GS_OFFSET;

  if (-1 < *(int *)(*(longlong *)(*(longlong *)(in_GS_OFFSET + 0x60) + 0x20) + 8))
  {
    __acrt_AppPolicyGetProcessTerminationMethodInternal();
  }
  return 1;
}

// WARNING: Could not reconcile some variable overlaps
// Library Function - Single Match
//  int __cdecl common_expand_argv_wildcards<char>(char * __ptr64 * __ptr64 const,char * __ptr64 *
// __ptr64 * __ptr64 const)
//
// Library: Visual Studio 2015 Release

int common_expand_argv_wildcards_char_(char **param_1, char ***param_2)
{
  char **ppcVar1;
  code *pcVar2;
  ulong uVar3;
  ulong *puVar4;
  byte *pbVar5;
  undefined8 uVar6;
  longlong lVar7;
  char **ppcVar8;
  ulonglong uVar9;
  LPVOID *ppvVar10;
  int iVar11;
  ulonglong uVar12;
  ulonglong uVar13;
  ulonglong uVar14;
  longlong lVar15;
  ulonglong uVar16;
  undefined8 local_res18;
  char **local_res20;
  undefined local_58[16];
  undefined8 local_48;

  uVar12 = 0;
  if (param_2 == (char ***)0x0)
  {
    puVar4 = __doserrno();
    iVar11 = 0x16;
    *puVar4 = 0x16;
    FUN_18006738c();
  }
  else
  {
    *param_2 = (char **)0x0;
    pbVar5 = (byte *)*param_1;
    local_58 = ZEXT816(0);
    local_48 = 0;
    while (pbVar5 != (byte *)0x0)
    {
      local_res18 = CONCAT53(local_res18._3_5_, 0x3f2a);
      pbVar5 = FUN_180084d00((byte *)*param_1, (byte *)&local_res18);
      if (pbVar5 == (byte *)0x0)
      {
        uVar6 = FUN_18007681c((longlong)*param_1, 0, 0, (LPCVOID *)local_58);
        iVar11 = (int)uVar6;
      }
      else
      {
        iVar11 = FUN_180076b4c((byte *)*param_1, pbVar5, (LPCVOID *)local_58);
      }
      if (iVar11 != 0)
      {
        goto LAB_180076580;
      }
      param_1 = (char **)((byte **)param_1 + 1);
      pbVar5 = (byte *)*param_1;
    }
    local_res18 = 0;
    uVar16 = ((longlong)(LPVOID *)((longlong)local_58._8_8_ - (longlong)local_58._0_8_) >> 3) + 1;
    uVar9 = (longlong)(LPVOID *)((longlong)local_58._8_8_ - (longlong)local_58._0_8_) + 7U >> 3;
    if (local_58._8_8_ < local_58._0_8_)
    {
      uVar9 = uVar12;
    }
    ppvVar10 = local_58._0_8_;
    uVar13 = uVar12;
    uVar14 = uVar12;
    if (uVar9 != 0)
    {
      do
      {
        lVar7 = -1;
        do
        {
          lVar7 = lVar7 + 1;
        } while (*(char *)((longlong)*ppvVar10 + lVar7) != '\0');
        ppvVar10 = ppvVar10 + 1;
        uVar14 = uVar14 + 1 + lVar7;
        uVar13 = uVar13 + 1;
        local_res18 = uVar14;
      } while (uVar13 != uVar9);
    }
    ppcVar8 = (char **)FUN_1800637a4(uVar16, local_res18, 1);
    uVar9 = 0xffffffffffffffff;
    if (ppcVar8 != (char **)0x0)
    {
      ppcVar1 = ppcVar8 + uVar16;
      local_res20 = ppcVar1;
      if (local_58._0_8_ != local_58._8_8_)
      {
        ppvVar10 = local_58._0_8_;
        do
        {
          lVar7 = -1;
          do
          {
            lVar15 = lVar7;
            lVar7 = lVar15 + 1;
          } while (*(char *)((longlong)*ppvVar10 + lVar7) != '\0');
          lVar15 = lVar15 + 2;
          uVar3 = FUN_180084088((char *)local_res20,
                                (longlong)ppcVar1 + (local_res18 - (longlong)local_res20),
                                (longlong)*ppvVar10, lVar15);
          if (uVar3 != 0)
          {
            _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
            pcVar2 = (code *)swi(3);
            iVar11 = (*pcVar2)();
            return iVar11;
          }
          *(char ***)((longlong)((longlong)ppcVar8 - (longlong)local_58._0_8_) + (longlong)ppvVar10) = local_res20;
          local_res20 = (char **)((longlong)local_res20 + lVar15);
          ppvVar10 = ppvVar10 + 1;
        } while (ppvVar10 != local_58._8_8_);
      }
      *param_2 = ppcVar8;
      uVar9 = uVar12;
    }
    iVar11 = (int)uVar9;
    _free_base((LPVOID)0x0);
  LAB_180076580:
    uVar9 = (ulonglong)((longlong)local_58._8_8_ + (7 - (longlong)local_58._0_8_)) >> 3;
    if (local_58._8_8_ < local_58._0_8_)
    {
      uVar9 = uVar12;
    }
    ppvVar10 = local_58._0_8_;
    if (uVar9 != 0)
    {
      do
      {
        _free_base(*ppvVar10);
        uVar12 = uVar12 + 1;
        ppvVar10 = ppvVar10 + 1;
      } while (uVar12 != uVar9);
    }
    _free_base(local_58._0_8_);
  }
  return iVar11;
}

// WARNING: Could not reconcile some variable overlaps
// Library Function - Single Match
//  int __cdecl common_expand_argv_wildcards<wchar_t>(wchar_t * __ptr64 * __ptr64 const,wchar_t *
// __ptr64 * __ptr64 * __ptr64 const)
//
// Library: Visual Studio 2015 Release

int common_expand_argv_wildcards_wchar_t_(wchar_t **param_1, wchar_t ***param_2)
{
  code *pcVar1;
  ulong uVar2;
  int iVar3;
  ulong *puVar4;
  wchar_t *pwVar5;
  undefined8 uVar6;
  longlong lVar7;
  wchar_t **ppwVar8;
  ulonglong uVar9;
  LPVOID *ppvVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  ulonglong uVar13;
  longlong lVar14;
  ulonglong uVar15;
  wchar_t **local_88;
  undefined local_80[16];
  undefined8 local_70;
  wchar_t **local_68;
  wchar_t **local_60;
  wchar_t ***local_58;
  undefined8 local_50;
  ulonglong local_48;

  local_48 = DAT_1800ee160 ^ (ulonglong)&stack0xffffffffffffff48;
  uVar11 = 0;
  local_58 = param_2;
  if (param_2 == (wchar_t ***)0x0)
  {
    puVar4 = __doserrno();
    *puVar4 = 0x16;
    FUN_18006738c();
  }
  else
  {
    *param_2 = (wchar_t **)0x0;
    pwVar5 = (wchar_t *)*param_1;
    local_80 = ZEXT816(0);
    local_70 = 0;
    while (pwVar5 != (wchar_t *)0x0)
    {
      local_50 = CONCAT26(local_50._6_2_, 0x3f002a);
      pwVar5 = wcspbrk((wchar_t *)*param_1, (wchar_t *)&local_50);
      if (pwVar5 == (wchar_t *)0x0)
      {
        uVar6 = FUN_1800769b4((longlong)*param_1, 0, 0, (LPCVOID *)local_80);
        iVar3 = (int)uVar6;
      }
      else
      {
        iVar3 = FUN_180076cf8((LPCWSTR)*param_1, pwVar5, (LPCVOID *)local_80);
      }
      if (iVar3 != 0)
      {
        goto LAB_1800767a3;
      }
      param_1 = (wchar_t **)((wchar_t **)param_1 + 1);
      pwVar5 = (wchar_t *)*param_1;
    }
    local_50 = 0;
    uVar15 = ((longlong)(LPVOID *)((longlong)local_80._8_8_ - (longlong)local_80._0_8_) >> 3) + 1;
    uVar9 = (longlong)(LPVOID *)((longlong)local_80._8_8_ - (longlong)local_80._0_8_) + 7U >> 3;
    if (local_80._8_8_ < local_80._0_8_)
    {
      uVar9 = uVar11;
    }
    ppvVar10 = local_80._0_8_;
    uVar12 = uVar11;
    uVar13 = uVar11;
    if (uVar9 != 0)
    {
      do
      {
        lVar7 = -1;
        do
        {
          lVar7 = lVar7 + 1;
        } while (*(short *)((longlong)*ppvVar10 + lVar7 * 2) != 0);
        ppvVar10 = ppvVar10 + 1;
        uVar13 = uVar13 + 1 + lVar7;
        uVar12 = uVar12 + 1;
        local_50 = uVar13;
      } while (uVar12 != uVar9);
    }
    ppwVar8 = (wchar_t **)FUN_1800637a4(uVar15, local_50, 2);
    if (ppwVar8 != (wchar_t **)0x0)
    {
      local_88 = ppwVar8 + uVar15;
      local_60 = local_88;
      if (local_80._0_8_ != local_80._8_8_)
      {
        local_68 = (wchar_t **)((longlong)ppwVar8 - (longlong)local_80._0_8_);
        ppvVar10 = local_80._0_8_;
        do
        {
          lVar7 = -1;
          do
          {
            lVar14 = lVar7;
            lVar7 = lVar14 + 1;
          } while (*(short *)((longlong)*ppvVar10 + lVar7 * 2) != 0);
          lVar14 = lVar14 + 2;
          uVar2 = FUN_180061a44((short *)local_88,
                                local_50 -
                                    ((longlong)((longlong)local_88 - (longlong)local_60) >> 1),
                                (longlong)*ppvVar10, lVar14);
          if (uVar2 != 0)
          {
            _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
            pcVar1 = (code *)swi(3);
            iVar3 = (*pcVar1)();
            return iVar3;
          }
          *(wchar_t ***)((longlong)local_68 + (longlong)ppvVar10) = local_88;
          ppvVar10 = ppvVar10 + 1;
          local_88 = (wchar_t **)((longlong)local_88 + lVar14 * 2);
        } while (ppvVar10 != local_80._8_8_);
      }
      *local_58 = ppwVar8;
    }
    _free_base((LPVOID)0x0);
  LAB_1800767a3:
    uVar9 = (ulonglong)((longlong)local_80._8_8_ + (7 - (longlong)local_80._0_8_)) >> 3;
    if (local_80._8_8_ < local_80._0_8_)
    {
      uVar9 = uVar11;
    }
    ppvVar10 = local_80._0_8_;
    if (uVar9 != 0)
    {
      do
      {
        _free_base(*ppvVar10);
        uVar11 = uVar11 + 1;
        ppvVar10 = ppvVar10 + 1;
      } while (uVar11 != uVar9);
    }
    _free_base(local_80._0_8_);
  }
  iVar3 = FUN_180034d00(local_48 ^ (ulonglong)&stack0xffffffffffffff48);
  return iVar3;
}

// Library Function - Multiple Matches With Same Base Name
//  private: int __cdecl `anonymous namespace'::argument_list<char>::expand_if_necessary(void)
// __ptr64
//  private: int __cdecl `anonymous namespace'::argument_list<char>::expand_if_necessary(void)
// __ptr64
//  private: int __cdecl `anonymous namespace'::argument_list<wchar_t>::expand_if_necessary(void)
// __ptr64
//  private: int __cdecl `anonymous namespace'::argument_list<wchar_t>::expand_if_necessary(void)
// __ptr64
//
// Library: Visual Studio 2015 Release

undefined4 expand_if_necessary(LPCVOID *param_1)
{
  LPCVOID pvVar1;
  LPVOID pvVar2;
  undefined4 uVar3;
  ulonglong uVar4;

  if (param_1[1] == param_1[2])
  {
    uVar3 = 0;
    if (*param_1 == (LPCVOID)0x0)
    {
      pvVar2 = _calloc_base(4, 8);
      *param_1 = pvVar2;
      _free_base((LPVOID)0x0);
      pvVar1 = *param_1;
      if (pvVar1 != (LPCVOID)0x0)
      {
        param_1[1] = pvVar1;
        param_1[2] = (LPCVOID)((longlong)pvVar1 + 0x20);
        goto LAB_180077349;
      }
    }
    else
    {
      uVar4 = (longlong)((longlong)param_1[2] - (longlong)*param_1) >> 3;
      if (uVar4 < 0x8000000000000000)
      {
        pvVar2 = _recalloc_base(*param_1, uVar4 * 2, 8);
        if (pvVar2 == (LPVOID)0x0)
        {
          uVar3 = 0xc;
        }
        else
        {
          *param_1 = pvVar2;
          param_1[1] = (LPVOID)((longlong)pvVar2 + uVar4 * 8);
          param_1[2] = (LPVOID)((longlong)pvVar2 + uVar4 * 0x10);
        }
        _free_base((LPVOID)0x0);
        return uVar3;
      }
    }
    uVar3 = 0xc;
  }
  else
  {
  LAB_180077349:
    uVar3 = 0;
  }
  return uVar3;
}

// WARNING: Could not reconcile some variable overlaps

int common_expand_argv_wildcards_char_(char **param_1, char ***param_2)
{
  char **ppcVar1;
  code *pcVar2;
  ulong uVar3;
  ulong *puVar4;
  byte *pbVar5;
  undefined8 uVar6;
  longlong lVar7;
  char **ppcVar8;
  ulonglong uVar9;
  LPVOID *ppvVar10;
  int iVar11;
  ulonglong uVar12;
  ulonglong uVar13;
  ulonglong uVar14;
  longlong lVar15;
  ulonglong uVar16;
  undefined8 uStackX24;
  char **ppcStackX32;
  undefined auStack88[16];
  undefined8 uStack72;

  uVar12 = 0;
  if (param_2 == (char ***)0x0)
  {
    puVar4 = __doserrno();
    iVar11 = 0x16;
    *puVar4 = 0x16;
    FUN_18006738c();
  }
  else
  {
    *param_2 = (char **)0x0;
    pbVar5 = (byte *)*param_1;
    auStack88 = ZEXT816(0);
    uStack72 = 0;
    while (pbVar5 != (byte *)0x0)
    {
      uStackX24 = CONCAT53(uStackX24._3_5_, 0x3f2a);
      pbVar5 = FUN_180084d00((byte *)*param_1, (byte *)&uStackX24);
      if (pbVar5 == (byte *)0x0)
      {
        uVar6 = FUN_18007681c((longlong)*param_1, 0, 0, (LPCVOID *)auStack88);
        iVar11 = (int)uVar6;
      }
      else
      {
        iVar11 = FUN_180076b4c((byte *)*param_1, pbVar5, (LPCVOID *)auStack88);
      }
      if (iVar11 != 0)
      {
        goto LAB_180076580;
      }
      param_1 = (char **)((byte **)param_1 + 1);
      pbVar5 = (byte *)*param_1;
    }
    uStackX24 = 0;
    uVar16 = ((longlong)(LPVOID *)((longlong)auStack88._8_8_ - (longlong)auStack88._0_8_) >> 3) + 1;
    uVar9 = (longlong)(LPVOID *)((longlong)auStack88._8_8_ - (longlong)auStack88._0_8_) + 7U >> 3;
    if (auStack88._8_8_ < auStack88._0_8_)
    {
      uVar9 = uVar12;
    }
    ppvVar10 = auStack88._0_8_;
    uVar13 = uVar12;
    uVar14 = uVar12;
    if (uVar9 != 0)
    {
      do
      {
        lVar7 = -1;
        do
        {
          lVar7 = lVar7 + 1;
        } while (*(char *)((longlong)*ppvVar10 + lVar7) != '\0');
        ppvVar10 = ppvVar10 + 1;
        uVar14 = uVar14 + 1 + lVar7;
        uVar13 = uVar13 + 1;
        uStackX24 = uVar14;
      } while (uVar13 != uVar9);
    }
    ppcVar8 = (char **)FUN_1800637a4(uVar16, uStackX24, 1);
    uVar9 = 0xffffffffffffffff;
    if (ppcVar8 != (char **)0x0)
    {
      ppcVar1 = ppcVar8 + uVar16;
      ppcStackX32 = ppcVar1;
      if (auStack88._0_8_ != auStack88._8_8_)
      {
        ppvVar10 = auStack88._0_8_;
        do
        {
          lVar7 = -1;
          do
          {
            lVar15 = lVar7;
            lVar7 = lVar15 + 1;
          } while (*(char *)((longlong)*ppvVar10 + lVar7) != '\0');
          lVar15 = lVar15 + 2;
          uVar3 = FUN_180084088((char *)ppcStackX32,
                                (longlong)ppcVar1 + (uStackX24 - (longlong)ppcStackX32),
                                (longlong)*ppvVar10, lVar15);
          if (uVar3 != 0)
          {
            _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
            pcVar2 = (code *)swi(3);
            iVar11 = (*pcVar2)();
            return iVar11;
          }
          *(char ***)((longlong)((longlong)ppcVar8 - (longlong)auStack88._0_8_) + (longlong)ppvVar10) =
              ppcStackX32;
          ppcStackX32 = (char **)((longlong)ppcStackX32 + lVar15);
          ppvVar10 = ppvVar10 + 1;
        } while (ppvVar10 != auStack88._8_8_);
      }
      *param_2 = ppcVar8;
      uVar9 = uVar12;
    }
    iVar11 = (int)uVar9;
    _free_base((LPVOID)0x0);
  LAB_180076580:
    uVar9 = (ulonglong)((longlong)auStack88._8_8_ + (7 - (longlong)auStack88._0_8_)) >> 3;
    if (auStack88._8_8_ < auStack88._0_8_)
    {
      uVar9 = uVar12;
    }
    ppvVar10 = auStack88._0_8_;
    if (uVar9 != 0)
    {
      do
      {
        _free_base(*ppvVar10);
        uVar12 = uVar12 + 1;
        ppvVar10 = ppvVar10 + 1;
      } while (uVar12 != uVar9);
    }
    _free_base(auStack88._0_8_);
  }
  return iVar11;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  int __cdecl getSystemCP(int)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int getSystemCP(int param_1)
{
  __acrt_ptd *local_28;
  longlong local_20;
  char local_10;

  FUN_18004e538(&local_28, (undefined4 *)0x0);
  _DAT_180102618 = 0;
  if (param_1 == -2)
  {
    _DAT_180102618 = 1;
    param_1 = GetOEMCP();
  }
  else
  {
    if (param_1 == -3)
    {
      _DAT_180102618 = 1;
      param_1 = GetACP();
    }
    else
    {
      if (param_1 == -4)
      {
        _DAT_180102618 = 1;
        param_1 = *(UINT *)(local_20 + 0xc);
      }
    }
  }
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return param_1;
}

// Library Function - Single Match
//  void __cdecl setSBCS(struct __crt_multibyte_data * __ptr64)
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void setSBCS(__crt_multibyte_data *param_1)
{
  longlong lVar1;
  __crt_multibyte_data *p_Var2;
  undefined(*pauVar3)[16];
  longlong lVar4;
  undefined2 *puVar5;

  pauVar3 = (undefined(*)[16])(param_1 + 0x18);
  lVar4 = 0x101;
  FUN_18003bd40(pauVar3, 0, 0x101);
  *(undefined8 *)(param_1 + 4) = 0;
  lVar1 = 6;
  *(undefined8 *)(param_1 + 0x220) = 0;
  puVar5 = (undefined2 *)(param_1 + 0xc);
  while (lVar1 != 0)
  {
    lVar1 = lVar1 + -1;
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  do
  {
    (*pauVar3)[0] = (*pauVar3)[(longlong)(&DAT_1800ee910 + -(longlong)param_1)];
    pauVar3 = (undefined(*)[16])(*pauVar3 + 1);
    lVar4 = lVar4 + -1;
  } while (lVar4 != 0);
  p_Var2 = param_1 + 0x119;
  lVar1 = 0x100;
  do
  {
    *p_Var2 = p_Var2[(longlong)(&DAT_1800ee910 + -(longlong)param_1)];
    p_Var2 = p_Var2 + 1;
    lVar1 = lVar1 + -1;
  } while (lVar1 != 0);
  return;
}

// Library Function - Single Match
//  int __cdecl setmbcp_internal(int,bool,struct __acrt_ptd * __ptr64 const,struct
// __crt_multibyte_data * __ptr64 * __ptr64 const)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int setmbcp_internal(int param_1, bool param_2, __acrt_ptd *param_3, __crt_multibyte_data **param_4)
{
  int iVar1;
  int *piVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  ulong *puVar10;
  undefined4 *puVar11;
  longlong lVar12;
  undefined4 *puVar13;
  __acrt_ptd *local_res18;
  __crt_multibyte_data **local_res20;
  undefined local_38[4];
  int local_34;
  int local_30[2];
  __acrt_ptd **local_28;
  __crt_multibyte_data ***local_20;

  local_res18 = param_3;
  local_res20 = param_4;
  FUN_180077e00((longlong)param_3, (int **)param_4);
  iVar7 = getSystemCP(param_1);
  if (iVar7 == *(int *)(*(longlong *)(local_res18 + 0x88) + 4))
  {
    return 0;
  }
  puVar8 = (undefined4 *)_malloc_base(0x228);
  if (puVar8 != (undefined4 *)0x0)
  {
    lVar12 = 4;
    puVar13 = *(undefined4 **)(local_res18 + 0x88);
    puVar6 = puVar8;
    do
    {
      puVar11 = puVar6;
      puVar9 = puVar13;
      uVar3 = puVar9[1];
      uVar4 = puVar9[2];
      uVar5 = puVar9[3];
      *puVar11 = *puVar9;
      puVar11[1] = uVar3;
      puVar11[2] = uVar4;
      puVar11[3] = uVar5;
      uVar3 = puVar9[5];
      uVar4 = puVar9[6];
      uVar5 = puVar9[7];
      puVar11[4] = puVar9[4];
      puVar11[5] = uVar3;
      puVar11[6] = uVar4;
      puVar11[7] = uVar5;
      uVar3 = puVar9[9];
      uVar4 = puVar9[10];
      uVar5 = puVar9[0xb];
      puVar11[8] = puVar9[8];
      puVar11[9] = uVar3;
      puVar11[10] = uVar4;
      puVar11[0xb] = uVar5;
      uVar3 = puVar9[0xd];
      uVar4 = puVar9[0xe];
      uVar5 = puVar9[0xf];
      puVar11[0xc] = puVar9[0xc];
      puVar11[0xd] = uVar3;
      puVar11[0xe] = uVar4;
      puVar11[0xf] = uVar5;
      uVar3 = puVar9[0x11];
      uVar4 = puVar9[0x12];
      uVar5 = puVar9[0x13];
      puVar11[0x10] = puVar9[0x10];
      puVar11[0x11] = uVar3;
      puVar11[0x12] = uVar4;
      puVar11[0x13] = uVar5;
      uVar3 = puVar9[0x15];
      uVar4 = puVar9[0x16];
      uVar5 = puVar9[0x17];
      puVar11[0x14] = puVar9[0x14];
      puVar11[0x15] = uVar3;
      puVar11[0x16] = uVar4;
      puVar11[0x17] = uVar5;
      uVar3 = puVar9[0x19];
      uVar4 = puVar9[0x1a];
      uVar5 = puVar9[0x1b];
      puVar11[0x18] = puVar9[0x18];
      puVar11[0x19] = uVar3;
      puVar11[0x1a] = uVar4;
      puVar11[0x1b] = uVar5;
      uVar3 = puVar9[0x1d];
      uVar4 = puVar9[0x1e];
      uVar5 = puVar9[0x1f];
      puVar11[0x1c] = puVar9[0x1c];
      puVar11[0x1d] = uVar3;
      puVar11[0x1e] = uVar4;
      puVar11[0x1f] = uVar5;
      lVar12 = lVar12 + -1;
      puVar13 = puVar9 + 0x20;
      puVar6 = puVar11 + 0x20;
    } while (lVar12 != 0);
    uVar3 = puVar9[0x21];
    uVar4 = puVar9[0x22];
    uVar5 = puVar9[0x23];
    puVar11[0x20] = puVar9[0x20];
    puVar11[0x21] = uVar3;
    puVar11[0x22] = uVar4;
    puVar11[0x23] = uVar5;
    uVar3 = puVar9[0x25];
    uVar4 = puVar9[0x26];
    uVar5 = puVar9[0x27];
    puVar11[0x24] = puVar9[0x24];
    puVar11[0x25] = uVar3;
    puVar11[0x26] = uVar4;
    puVar11[0x27] = uVar5;
    *(undefined8 *)(puVar11 + 0x28) = *(undefined8 *)(puVar9 + 0x28);
    *puVar8 = 0;
    iVar7 = FUN_180077fac(iVar7, (__crt_multibyte_data *)puVar8);
    if (iVar7 != -1)
    {
      if (param_2 == false)
      {
        FUN_18006c560();
      }
      piVar2 = *(int **)(local_res18 + 0x88);
      LOCK();
      iVar1 = *piVar2;
      *piVar2 = *piVar2 + -1;
      if ((iVar1 == 1) && (*(undefined **)(local_res18 + 0x88) != &DAT_1800ee910))
      {
        _free_base(*(undefined **)(local_res18 + 0x88));
      }
      *puVar8 = 1;
      puVar13 = (undefined4 *)0x0;
      *(undefined4 **)(local_res18 + 0x88) = puVar8;
      puVar8 = puVar13;
      if ((((byte)local_res18[0x3a8] & 2) == 0) && (((byte)DAT_1800eee60 & 1) == 0))
      {
        local_28 = &local_res18;
        local_20 = &local_res20;
        local_34 = 5;
        local_30[0] = 5;
        FUN_18007750c(local_38, local_30, (longlong **)&local_28, &local_34);
        if (param_2 != false)
        {
          PTR_DAT_1800ee710 = *local_res20;
          puVar8 = (undefined4 *)0x0;
        }
      }
      goto LAB_180077d34;
    }
    puVar10 = __doserrno();
    *puVar10 = 0x16;
  }
  iVar7 = -1;
LAB_180077d34:
  _free_base(puVar8);
  return iVar7;
}

// Library Function - Single Match
//  __acrt_initialize_multibyte
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 __acrt_initialize_multibyte(void)
{
  int iVar1;
  undefined8 in_RAX;
  __acrt_ptd *p_Var2;
  undefined4 extraout_var;

  if (DAT_18010261c == '\0')
  {
    DAT_180102610 = &DAT_1800eec50;
    DAT_180102600 = &DAT_1800ee910;
    DAT_180102608 = &DAT_1800eeb40;
    p_Var2 = FUN_18006a81c();
    iVar1 = setmbcp_internal(-3, true, p_Var2, (__crt_multibyte_data **)&DAT_180102600);
    in_RAX = CONCAT44(extraout_var, iVar1);
    DAT_18010261c = '\x01';
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8), 1);
}

// Library Function - Single Match
//  __acrt_update_thread_multibyte_data
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_update_thread_multibyte_data(void)
{
  __acrt_ptd *p_Var1;

  p_Var1 = FUN_18006a750();
  FUN_180077e00((longlong)p_Var1, (int **)&DAT_180102600);
  return;
}

// Library Function - Single Match
//  _setmbcp
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int _setmbcp(int _CodePage)
{
  int iVar1;
  __acrt_ptd *p_Var2;

  p_Var2 = FUN_18006a750();
  iVar1 = setmbcp_internal(_CodePage, false, p_Var2, (__crt_multibyte_data **)&DAT_180102600);
  return iVar1;
}

// Library Function - Single Match
//  memcpy_s
//
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

errno_t memcpy_s(void *_Dst, rsize_t _DstSize, void *_Src, rsize_t _MaxCount)
{
  ulong *puVar1;
  ulong uVar2;

  if (_MaxCount == 0)
  {
  LAB_180078289:
    uVar2 = 0;
  }
  else
  {
    if (_Dst == (void *)0x0)
    {
    LAB_180078292:
      puVar1 = __doserrno();
      uVar2 = 0x16;
    }
    else
    {
      if ((_Src != (void *)0x0) && (_MaxCount <= _DstSize))
      {
        FUN_18003b8e0((undefined8 *)_Dst, (undefined8 *)_Src, _MaxCount);
        goto LAB_180078289;
      }
      FUN_18003bd40((undefined(*)[16])_Dst, 0, _DstSize);
      if (_Src == (void *)0x0)
        goto LAB_180078292;
      if (_MaxCount <= _DstSize)
      {
        return 0x16;
      }
      puVar1 = __doserrno();
      uVar2 = 0x22;
    }
    *puVar1 = uVar2;
    FUN_18006738c();
  }
  return (errno_t)uVar2;
}

// Library Function - Single Match
//  wcscpy_s
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t wcscpy_s(wchar_t *_Dst, rsize_t _SizeInWords, wchar_t *_Src)
{
  wchar_t wVar1;
  ulong *puVar2;
  ulong uVar3;
  wchar_t *pwVar4;

  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0))
  {
    if (_Src != (wchar_t *)0x0)
    {
      pwVar4 = _Dst;
      do
      {
        wVar1 = *(wchar_t *)((longlong)((longlong)_Src - (longlong)_Dst) + (longlong)pwVar4);
        *pwVar4 = wVar1;
        pwVar4 = pwVar4 + 1;
        if (wVar1 == L'\0')
          break;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0)
      {
        return 0;
      }
      *_Dst = L'\0';
      puVar2 = __doserrno();
      uVar3 = 0x22;
      goto LAB_180078754;
    }
    *_Dst = L'\0';
  }
  puVar2 = __doserrno();
  uVar3 = 0x16;
LAB_180078754:
  *puVar2 = uVar3;
  FUN_18006738c();
  return (errno_t)uVar3;
}

// Library Function - Single Match
//  __dcrt_get_narrow_environment_from_os
//
// Library: Visual Studio 2015 Release

LPSTR __dcrt_get_narrow_environment_from_os(void)
{
  WCHAR WVar1;
  int cbMultiByte;
  int iVar2;
  LPWCH lpWideCharStr;
  longlong lVar3;
  LPSTR lpMultiByteStr;
  WCHAR *pWVar5;
  LPSTR pCVar6;
  LPSTR pCVar7;
  longlong lVar4;

  lpWideCharStr = GetEnvironmentStringsW();
  pCVar7 = (LPSTR)0x0;
  if (lpWideCharStr != (LPWCH)0x0)
  {
    WVar1 = *lpWideCharStr;
    pWVar5 = lpWideCharStr;
    while (WVar1 != L'\0')
    {
      lVar3 = -1;
      do
      {
        lVar4 = lVar3;
        lVar3 = lVar4 + 1;
      } while (pWVar5[lVar3] != L'\0');
      pWVar5 = pWVar5 + lVar4 + 2;
      WVar1 = *pWVar5;
    }
    iVar2 = (int)((longlong)pWVar5 + (2 - (longlong)lpWideCharStr) >> 1);
    cbMultiByte = WideCharToMultiByte(0, 0, lpWideCharStr, iVar2, (LPSTR)0x0, 0, (LPCSTR)0x0, (LPBOOL)0x0);
    if (cbMultiByte != 0)
    {
      lpMultiByteStr = (LPSTR)_malloc_base((longlong)cbMultiByte);
      pCVar6 = pCVar7;
      if ((lpMultiByteStr != (LPSTR)0x0) &&
          (iVar2 = WideCharToMultiByte(0, 0, lpWideCharStr, iVar2, lpMultiByteStr, cbMultiByte, (LPCSTR)0x0, (LPBOOL)0x0), iVar2 != 0))
      {
        pCVar6 = lpMultiByteStr;
        lpMultiByteStr = pCVar7;
      }
      _free_base(lpMultiByteStr);
      pCVar7 = pCVar6;
    }
  }
  if (lpWideCharStr != (LPWCH)0x0)
  {
    FreeEnvironmentStringsW(lpWideCharStr);
  }
  return pCVar7;
}

// Library Function - Single Match
//  __dcrt_get_wide_environment_from_os
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 *__dcrt_get_wide_environment_from_os(void)
{
  short sVar1;
  ulonglong uVar2;
  undefined8 *puVar3;
  longlong lVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;

  puVar3 = (undefined8 *)GetEnvironmentStringsW();
  puVar6 = (undefined8 *)0x0;
  if (puVar3 != (undefined8 *)0x0)
  {
    sVar1 = *(short *)puVar3;
    puVar5 = puVar3;
    while (sVar1 != 0)
    {
      lVar4 = -1;
      do
      {
        lVar4 = lVar4 + 1;
      } while (*(short *)((longlong)puVar5 + lVar4 * 2) != 0);
      puVar5 = (undefined8 *)((longlong)puVar5 + lVar4 * 2 + 2);
      sVar1 = *(short *)puVar5;
    }
    uVar2 = ((longlong)puVar5 + (2 - (longlong)puVar3) >> 1) * 2;
    puVar5 = (undefined8 *)_malloc_base(uVar2);
    if (puVar5 != (undefined8 *)0x0)
    {
      FUN_18003b8e0(puVar5, puVar3, uVar2);
      puVar6 = puVar5;
    }
    _free_base((LPVOID)0x0);
    FreeEnvironmentStringsW((LPWCH)puVar3);
  }
  return puVar6;
}

// Library Function - Single Match
//  char * __ptr64 * __ptr64 __cdecl copy_environment<char>(char * __ptr64 * __ptr64 const)
//
// Library: Visual Studio 2015 Release

char **copy_environment_char_(char **param_1)
{
  char *pcVar1;
  code *pcVar2;
  errno_t eVar3;
  char **ppcVar4;
  LPVOID pvVar5;
  longlong lVar6;
  longlong lVar7;
  char **ppcVar8;

  if (param_1 == (char **)0x0)
  {
    ppcVar4 = (char **)0x0;
  }
  else
  {
    lVar6 = 0;
    pcVar1 = *param_1;
    ppcVar4 = param_1;
    while (pcVar1 != (char *)0x0)
    {
      lVar6 = lVar6 + 1;
      ppcVar4 = ppcVar4 + 1;
      pcVar1 = *ppcVar4;
    }
    ppcVar4 = (char **)_calloc_base(lVar6 + 1, 8);
    if (ppcVar4 == (char **)0x0)
    {
      abort();
      pcVar2 = (code *)swi(3);
      ppcVar4 = (char **)(*pcVar2)();
      return ppcVar4;
    }
    if (*param_1 != (char *)0x0)
    {
      ppcVar8 = (char **)((longlong)ppcVar4 - (longlong)param_1);
      do
      {
        lVar6 = -1;
        do
        {
          lVar7 = lVar6;
          lVar6 = lVar7 + 1;
        } while ((*param_1)[lVar7 + 1] != '\0');
        pvVar5 = _calloc_base(lVar7 + 2, 1);
        *(LPVOID *)((longlong)ppcVar8 + (longlong)param_1) = pvVar5;
        _free_base((LPVOID)0x0);
        pcVar1 = *(char **)((longlong)ppcVar8 + (longlong)param_1);
        if (pcVar1 == (char *)0x0)
        {
          abort();
          pcVar2 = (code *)swi(3);
          ppcVar4 = (char **)(*pcVar2)();
          return ppcVar4;
        }
        eVar3 = strcpy_s(pcVar1, lVar7 + 2, *param_1);
        if (eVar3 != 0)
        {
          _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
          pcVar2 = (code *)swi(3);
          ppcVar4 = (char **)(*pcVar2)();
          return ppcVar4;
        }
        param_1 = param_1 + 1;
      } while (*param_1 != (char *)0x0);
    }
    _free_base((LPVOID)0x0);
  }
  return ppcVar4;
}

// Library Function - Single Match
//  wchar_t * __ptr64 * __ptr64 __cdecl copy_environment<wchar_t>(wchar_t * __ptr64 * __ptr64 const)
//
// Library: Visual Studio 2015 Release

wchar_t **copy_environment_wchar_t_(wchar_t **param_1)
{
  wchar_t *pwVar1;
  wchar_t *_Dst;
  code *pcVar2;
  errno_t eVar3;
  wchar_t **ppwVar4;
  LPVOID pvVar5;
  longlong lVar6;
  longlong lVar7;
  wchar_t **ppwVar8;

  lVar6 = 0;
  if (param_1 == (wchar_t **)0x0)
  {
    ppwVar4 = (wchar_t **)0x0;
  }
  else
  {
    pwVar1 = *param_1;
    ppwVar4 = param_1;
    while (pwVar1 != (wchar_t *)0x0)
    {
      lVar6 = lVar6 + 1;
      ppwVar4 = ppwVar4 + 1;
      pwVar1 = *ppwVar4;
    }
    ppwVar4 = (wchar_t **)_calloc_base(lVar6 + 1, 8);
    if (ppwVar4 == (wchar_t **)0x0)
    {
      abort();
      pcVar2 = (code *)swi(3);
      ppwVar4 = (wchar_t **)(*pcVar2)();
      return ppwVar4;
    }
    if (*param_1 != (wchar_t *)0x0)
    {
      ppwVar8 = (wchar_t **)((longlong)ppwVar4 - (longlong)param_1);
      do
      {
        lVar6 = -1;
        do
        {
          lVar7 = lVar6;
          lVar6 = lVar7 + 1;
        } while (*(wchar_t *)((longlong)*param_1 + (lVar7 + 1) * 2) != L'\0');
        pvVar5 = _calloc_base(lVar7 + 2, 2);
        *(LPVOID *)((longlong)ppwVar8 + (longlong)param_1) = pvVar5;
        _free_base((LPVOID)0x0);
        _Dst = *(wchar_t **)((longlong)ppwVar8 + (longlong)param_1);
        if (_Dst == (wchar_t *)0x0)
        {
          abort();
          pcVar2 = (code *)swi(3);
          ppwVar4 = (wchar_t **)(*pcVar2)();
          return ppwVar4;
        }
        eVar3 = wcscpy_s(_Dst, lVar7 + 2, (wchar_t *)*param_1);
        if (eVar3 != 0)
        {
          _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
          pcVar2 = (code *)swi(3);
          ppwVar4 = (wchar_t **)(*pcVar2)();
          return ppwVar4;
        }
        param_1 = (wchar_t **)((wchar_t **)param_1 + 1);
      } while ((wchar_t *)*param_1 != (wchar_t *)0x0);
    }
    _free_base((LPVOID)0x0);
  }
  return ppwVar4;
}

// Library Function - Single Match
//  _recalloc_base
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

LPVOID _recalloc_base(LPCVOID param_1, ulonglong param_2, ulonglong param_3)
{
  ulong *puVar1;
  SIZE_T SVar2;
  LPVOID pvVar3;
  ulonglong uVar4;

  if ((param_2 == 0) || (param_3 <= 0xffffffffffffffe0 / param_2))
  {
    if (param_1 == (LPCVOID)0x0)
    {
      SVar2 = 0;
    }
    else
    {
      SVar2 = _msize_base(param_1);
    }
    uVar4 = param_2 * param_3;
    pvVar3 = _realloc_base(param_1, uVar4);
    if ((pvVar3 != (LPVOID)0x0) && (SVar2 < uVar4))
    {
      FUN_18003bd40((undefined(*)[16])((longlong)pvVar3 + SVar2), 0, uVar4 - SVar2);
    }
  }
  else
  {
    puVar1 = __doserrno();
    *puVar1 = 0xc;
    pvVar3 = (LPVOID)0x0;
  }
  return pvVar3;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  public: void (__cdecl*__cdecl __crt_seh_guarded_call<void (__cdecl*)(int)>::operator()<class
// <lambda_c36588078e9f5dfd39652860aa6b3aaf>,class <lambda_ec61778202f4f5fc7e7711acc23c3bca>&
// __ptr64,class <lambda_dc9d2797ccde5d239b4a0efae8ebd7db>>(class
// <lambda_c36588078e9f5dfd39652860aa6b3aaf>&& __ptr64,class
// <lambda_ec61778202f4f5fc7e7711acc23c3bca>& __ptr64,class
// <lambda_dc9d2797ccde5d239b4a0efae8ebd7db>&& __ptr64) __ptr64)(int)
//
// Library: Visual Studio 2015 Release

FuncDef12 *__thiscall __crt_seh_guarded_call<void_(__cdecl *)(int)>::

    operator___class__lambda_c36588078e9f5dfd39652860aa6b3aaf__class__lambda_ec61778202f4f5fc7e7711acc23c3bca_____ptr64_class__lambda_dc9d2797ccde5d239b4a0efae8ebd7db___(__crt_seh_guarded_call_void____cdecl___int__ *this,
                                                                                                                                                                          _lambda_c36588078e9f5dfd39652860aa6b3aaf_ *param_1,
                                                                                                                                                                          _lambda_ec61778202f4f5fc7e7711acc23c3bca_ *param_2,
                                                                                                                                                                          _lambda_dc9d2797ccde5d239b4a0efae8ebd7db_ *param_3)
{
  byte bVar1;
  ulonglong uVar2;

  __acrt_lock(*(int *)param_1);
  bVar1 = (byte)DAT_1800ee160 & 0x3f;
  uVar2 = DAT_1800ee160 ^ _DAT_180102678;
  __acrt_unlock(*(int *)param_3);
  return (FuncDef12 *)(uVar2 >> bVar1 | uVar2 << 0x40 - bVar1);
}

// Library Function - Single Match
//  void (__cdecl*__cdecl __acrt_lock_and_call<class <lambda_ec61778202f4f5fc7e7711acc23c3bca>>(enum
// __acrt_lock_id,class <lambda_ec61778202f4f5fc7e7711acc23c3bca>&& __ptr64))(int)
//
// Library: Visual Studio 2015 Release

FuncDef13 *
__acrt_lock_and_call_class__lambda_ec61778202f4f5fc7e7711acc23c3bca___(__acrt_lock_id param_1, _lambda_ec61778202f4f5fc7e7711acc23c3bca_ *param_2)
{
  FuncDef12 *pFVar1;
  __crt_seh_guarded_call_void____cdecl___int__ local_res8[16];
  __acrt_lock_id local_res18[2];
  __acrt_lock_id local_res20[2];

  local_res18[0] = param_1;
  local_res20[0] = param_1;
  pFVar1 = __crt_seh_guarded_call<void_(__cdecl *)(int)>::

      operator___class__lambda_c36588078e9f5dfd39652860aa6b3aaf__class__lambda_ec61778202f4f5fc7e7711acc23c3bca_____ptr64_class__lambda_dc9d2797ccde5d239b4a0efae8ebd7db___(local_res8, (_lambda_c36588078e9f5dfd39652860aa6b3aaf_ *)local_res20, param_2,
                                                                                                                                                                            (_lambda_dc9d2797ccde5d239b4a0efae8ebd7db_ *)local_res18);
  return (FuncDef13 *)pFVar1;
}

// Library Function - Single Match
//  __acrt_get_sigabrt_handler
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_get_sigabrt_handler(void)
{
  _lambda_ec61778202f4f5fc7e7711acc23c3bca_ local_res8[8];
  undefined4 local_res10[2];
  undefined4 local_res18[4];

  local_res10[0] = 3;
  local_res18[0] = 3;
  __crt_seh_guarded_call<void_(__cdecl *)(int)>::

      operator___class__lambda_c36588078e9f5dfd39652860aa6b3aaf__class__lambda_ec61778202f4f5fc7e7711acc23c3bca_____ptr64_class__lambda_dc9d2797ccde5d239b4a0efae8ebd7db___((__crt_seh_guarded_call_void____cdecl___int__ *)local_res8,
                                                                                                                                                                            (_lambda_c36588078e9f5dfd39652860aa6b3aaf_ *)local_res18, local_res8,
                                                                                                                                                                            (_lambda_dc9d2797ccde5d239b4a0efae8ebd7db_ *)local_res10);
  return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __acrt_has_user_matherr
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

bool __acrt_has_user_matherr(void)
{
  byte bVar1;

  bVar1 = (byte)DAT_1800ee160 & 0x3f;
  return ((DAT_1800ee160 ^ _DAT_180102688) >> bVar1 |
          (DAT_1800ee160 ^ _DAT_180102688) << 0x40 - bVar1) != 0;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __acrt_invoke_user_matherr
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 __acrt_invoke_user_matherr(void)
{
  undefined8 uVar1;
  byte bVar2;
  code *pcVar3;

  bVar2 = (byte)DAT_1800ee160 & 0x3f;
  pcVar3 = (code *)((DAT_1800ee160 ^ _DAT_180102688) >> bVar2 |
                    (DAT_1800ee160 ^ _DAT_180102688) << 0x40 - bVar2);
  if (pcVar3 == (code *)0x0)
  {
    return 0;
  }
  uVar1 = (*pcVar3)();
  // WARNING: Treating indirect jump as call
  return uVar1;
}

// Library Function - Single Match
//  __pctype_func
//
// Library: Visual Studio 2015 Release

ushort *__pctype_func(void)
{
  __acrt_ptd *p_Var1;
  ushort **local_res8[4];

  p_Var1 = FUN_18006a750();
  local_res8[0] = *(ushort ***)(p_Var1 + 0x90);
  __acrt_update_locale_info((longlong)p_Var1, (undefined **)local_res8);
  return *local_res8[0];
}

// Library Function - Single Match
//  _isctype_l
//
// Library: Visual Studio 2015 Release

int _isctype_l(int _C, int _Type, _locale_t _Locale)
{
  int iVar1;
  int iVar2;
  CHAR local_48;
  CHAR local_47;
  undefined local_46;
  __acrt_ptd *local_40;
  localeinfo_struct local_38;
  char local_28;
  undefined4 local_20;
  undefined2 local_1c;
  ulonglong local_18;

  local_18 = DAT_1800ee160 ^ (ulonglong)&stack0xffffffffffffff78;
  FUN_18004e538(&local_40, (undefined4 *)_Locale);
  if (0x100 < _C + 1U)
  {
    iVar1 = _isleadbyte_l(_C >> 8 & 0xff, (_locale_t)&local_38);
    iVar2 = 1;
    if (iVar1 == 0)
    {
      local_47 = '\0';
      local_48 = (CHAR)_C;
    }
    else
    {
      iVar2 = 2;
      local_46 = 0;
      local_48 = (CHAR)((uint)_C >> 8);
      local_47 = (CHAR)_C;
    }
    local_20 = 0;
    local_1c = 0;
    iVar1 = FUN_1800811a4((undefined4 *)&local_38, 1, &local_48, iVar2, (LPWORD)&local_20,
                          (local_38.locinfo)->lc_time_cp, 1);
    if (iVar1 == 0)
    {
      if (local_28 != '\0')
      {
        *(uint *)(local_40 + 0x3a8) = *(uint *)(local_40 + 0x3a8) & 0xfffffffd;
      }
      goto LAB_18007a02e;
    }
  }
  if (local_28 != '\0')
  {
    *(uint *)(local_40 + 0x3a8) = *(uint *)(local_40 + 0x3a8) & 0xfffffffd;
  }
LAB_18007a02e:
  iVar1 = FUN_180034d00(local_18 ^ (ulonglong)&stack0xffffffffffffff78);
  return iVar1;
}

// Library Function - Single Match
//  __ascii_strnicmp
//
// Library: Visual Studio 2017 Release

int __ascii_strnicmp(char *_Str1, char *_Str2, size_t _MaxCount)
{
  byte bVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;

  if (_MaxCount == 0)
  {
    iVar4 = 0;
  }
  else
  {
    do
    {
      bVar1 = *_Str1;
      _Str1 = (char *)((byte *)_Str1 + 1);
      bVar2 = *_Str2;
      uVar3 = bVar1 + 0x20;
      if (0x19 < bVar1 - 0x41)
      {
        uVar3 = (uint)bVar1;
      }
      uVar5 = bVar2 + 0x20;
      _Str2 = (char *)((byte *)_Str2 + 1);
      if (0x19 < bVar2 - 0x41)
      {
        uVar5 = (uint)bVar2;
      }
      _MaxCount = _MaxCount - 1;
    } while (((_MaxCount != 0) && (uVar3 != 0)) && (uVar3 == uVar5));
    iVar4 = uVar3 - uVar5;
  }
  return iVar4;
}

// Library Function - Single Match
//  _strnicmp
//
// Library: Visual Studio 2017 Release

int _strnicmp(char *_Str1, char *_Str2, size_t _MaxCount)
{
  int iVar1;
  ulong *puVar2;

  if (DAT_180101d00 != 0)
  {
    iVar1 = _strnicmp_l(_Str1, _Str2, _MaxCount, (_locale_t)0x0);
    return iVar1;
  }
  if (((_Str1 != (char *)0x0) && (_Str2 != (char *)0x0)) && (_MaxCount < 0x80000000))
  {
    iVar1 = __ascii_strnicmp(_Str1, _Str2, _MaxCount);
    return iVar1;
  }
  puVar2 = __doserrno();
  *puVar2 = 0x16;
  FUN_18006738c();
  return 0x7fffffff;
}

// Library Function - Single Match
//  _strnicmp_l
//
// Library: Visual Studio 2017 Release

int _strnicmp_l(char *_Str1, char *_Str2, size_t _MaxCount, _locale_t _Locale)
{
  longlong lVar1;
  int iVar2;
  int iVar3;
  ulong *puVar4;
  __acrt_ptd *local_28;
  localeinfo_struct local_20;
  char local_10;

  if (_MaxCount == 0)
  {
    iVar2 = 0;
  }
  else
  {
    FUN_18004e538(&local_28, (undefined4 *)_Locale);
    iVar2 = 0x7fffffff;
    if (((_Str1 == (char *)0x0) || (_Str2 == (char *)0x0)) || (0x7fffffff < _MaxCount))
    {
      puVar4 = __doserrno();
      *puVar4 = 0x16;
      FUN_18006738c();
    }
    else
    {
      if ((local_20.locinfo)->locale_name[2] == (wchar_t *)0x0)
      {
        iVar2 = __ascii_strnicmp(_Str1, _Str2, _MaxCount);
      }
      else
      {
        lVar1 = -(longlong)_Str2;
        do
        {
          iVar2 = _tolower_l((uint)(byte)(_Str1 + lVar1)[(longlong)_Str2], (_locale_t)&local_20);
          iVar3 = _tolower_l((uint)(byte)*_Str2, (_locale_t)&local_20);
          _Str2 = (char *)((byte *)_Str2 + 1);
          _MaxCount = _MaxCount - 1;
          if ((_MaxCount == 0) || (iVar2 == 0))
            break;
        } while (iVar2 == iVar3);
        iVar2 = iVar2 - iVar3;
      }
    }
    if (local_10 != '\0')
    {
      *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
    }
  }
  return iVar2;
}

// Library Function - Single Match
//  _sopen_nolock
//
// Library: Visual Studio 2015 Release

errno_t _sopen_nolock(int *UnlockFlag, int *_FileHandle, char *_Filename, int _OpenFlag, int _ShareFlag,
                      int _PermissionFlag, int _SecureFlag)
{
  LPCWSTR pWVar1;
  ulong uVar2;
  undefined8 uVar3;
  LPCWSTR local_18[2];

  local_18[0] = (LPCWSTR)0x0;
  uVar3 = FUN_180075ec0(_Filename, local_18);
  pWVar1 = local_18[0];
  if ((int)uVar3 == 0)
  {
    uVar2 = 0xffffffff;
  }
  else
  {
    uVar2 = FUN_18007b020(UnlockFlag, (uint *)_FileHandle, local_18[0], _OpenFlag, _ShareFlag,
                          (byte)_PermissionFlag);
    _free_base(pWVar1);
  }
  return (errno_t)uVar2;
}

// Library Function - Multiple Matches With Different Base Names
//  _sopen_s
//  _wsopen_s
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t FID_conflict__sopen_s(int *_FileHandle, char *_Filename, int _OpenFlag, int _ShareFlag, int _PermissionMode)
{
  errno_t eVar1;

  eVar1 = FUN_18007a4f0(_Filename, _OpenFlag, _ShareFlag, _PermissionMode, (uint *)_FileHandle, 1);
  return eVar1;
}

// Library Function - Multiple Matches With Different Base Names
//  _sopen_s
//  _wsopen_s
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t FID_conflict__sopen_s(int *_FileHandle, char *_Filename, int _OpenFlag, int _ShareFlag, int _PermissionMode)
{
  ulong uVar1;

  uVar1 = FUN_18007a5b4((LPCWSTR)_Filename, _OpenFlag, _ShareFlag, (ulonglong)(uint)_PermissionMode,
                        (uint *)_FileHandle, 1);
  return (errno_t)uVar1;
}

// Library Function - Single Match
//  _isleadbyte_l
//
// Library: Visual Studio 2015 Release

int _isleadbyte_l(int _C, _locale_t _Locale)
{
  ushort uVar1;
  __acrt_ptd *local_28;
  longlong *local_20;
  char local_10;

  FUN_18004e538(&local_28, (undefined4 *)_Locale);
  uVar1 = *(ushort *)(*local_20 + (ulonglong)(_C & 0xff) * 2);
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return (int)(uVar1 & 0x8000);
}

// Library Function - Single Match
//  isleadbyte
//
// Library: Visual Studio 2015 Release

int isleadbyte(int _C)
{
  ushort uVar1;
  __acrt_ptd *local_28;
  longlong *local_20;
  char local_10;

  FUN_18004e538(&local_28, (undefined4 *)0x0);
  uVar1 = *(ushort *)(*local_20 + (ulonglong)(_C & 0xff) * 2);
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return (int)(uVar1 & 0x8000);
}

// Library Function - Single Match
//  __acrt_LCMapStringA
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

void __acrt_LCMapStringA(undefined4 *param_1, longlong param_2, uint param_3, char *param_4, int param_5, undefined8 param_6, int param_7, UINT param_8, int param_9)
{
  __acrt_ptd *local_28;
  longlong local_20[2];
  char local_10;

  FUN_18004e538(&local_28, param_1);
  FUN_18007b6cc(local_20, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return;
}

int MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte,
                        LPWSTR lpWideCharStr, int cchWideChar)
{
  int iVar1;

  // WARNING: Could not recover jumptable at 0x00018007ba7c. Too many branches
  // WARNING: Treating indirect jump as call
  iVar1 = MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
  return iVar1;
}

// Library Function - Single Match
//  ___lc_codepage_func
//
// Library: Visual Studio 2015 Release

UINT ___lc_codepage_func(void)
{
  __acrt_ptd *p_Var1;
  undefined *local_res8[4];

  p_Var1 = FUN_18006a750();
  local_res8[0] = *(undefined **)(p_Var1 + 0x90);
  __acrt_update_locale_info((longlong)p_Var1, local_res8);
  return *(UINT *)(local_res8[0] + 0xc);
}

int WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar,
                        LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar,
                        LPBOOL lpUsedDefaultChar)
{
  int iVar1;

  // WARNING: Could not recover jumptable at 0x00018007c1e4. Too many branches
  // WARNING: Treating indirect jump as call
  iVar1 = WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte,
                              lpDefaultChar, lpUsedDefaultChar);
  return iVar1;
}

// Library Function - Single Match
//  __acrt_free_locale
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_free_locale(LPVOID param_1)
{
  int *piVar1;
  longlong lVar2;
  LPVOID *ppvVar3;
  int **ppiVar4;

  if ((((*(undefined ***)((longlong)param_1 + 0xf8) != (undefined **)0x0) &&
        (*(undefined ***)((longlong)param_1 + 0xf8) != &PTR_DAT_1800eee70)) &&
       (*(int **)((longlong)param_1 + 0xe0) != (int *)0x0)) &&
      (**(int **)((longlong)param_1 + 0xe0) == 0))
  {
    piVar1 = *(int **)((longlong)param_1 + 0xf0);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0))
    {
      _free_base(piVar1);
      __acrt_locale_free_monetary(*(longlong *)((longlong)param_1 + 0xf8));
    }
    piVar1 = *(int **)((longlong)param_1 + 0xe8);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0))
    {
      _free_base(piVar1);
      __acrt_locale_free_numeric(*(LPVOID **)((longlong)param_1 + 0xf8));
    }
    _free_base(*(LPVOID *)((longlong)param_1 + 0xe0));
    _free_base(*(LPVOID *)((longlong)param_1 + 0xf8));
  }
  if ((*(int **)((longlong)param_1 + 0x100) != (int *)0x0) &&
      (**(int **)((longlong)param_1 + 0x100) == 0))
  {
    _free_base((LPVOID)(*(longlong *)((longlong)param_1 + 0x108) + -0xfe));
    _free_base((LPVOID)(*(longlong *)((longlong)param_1 + 0x110) + -0x80));
    _free_base((LPVOID)(*(longlong *)((longlong)param_1 + 0x118) + -0x80));
    _free_base(*(LPVOID *)((longlong)param_1 + 0x100));
  }
  __acrt_locale_free_lc_time_if_unreferenced(*(undefined ***)((longlong)param_1 + 0x120));
  ppvVar3 = (LPVOID *)((longlong)param_1 + 0x128);
  lVar2 = 6;
  ppiVar4 = (int **)((longlong)param_1 + 0x38);
  do
  {
    if (((ppiVar4[-2] != (int *)&DAT_1800ee718) && (piVar1 = *ppiVar4, piVar1 != (int *)0x0)) &&
        (*piVar1 == 0))
    {
      _free_base(piVar1);
      _free_base(*ppvVar3);
    }
    if (((ppiVar4[-3] != (int *)0x0) && (piVar1 = ppiVar4[-1], piVar1 != (int *)0x0)) &&
        (*piVar1 == 0))
    {
      _free_base(piVar1);
    }
    ppvVar3 = ppvVar3 + 1;
    ppiVar4 = ppiVar4 + 4;
    lVar2 = lVar2 + -1;
  } while (lVar2 != 0);
  _free_base(param_1);
  return;
}

// Library Function - Single Match
//  __acrt_locale_free_lc_time_if_unreferenced
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_locale_free_lc_time_if_unreferenced(undefined **param_1)
{
  if (((param_1 != (undefined **)0x0) && (param_1 != &PTR_DAT_1800ca560)) &&
      (*(int *)((longlong)param_1 + 0x15c) == 0))
  {
    __acrt_locale_free_time(param_1);
    _free_base(param_1);
  }
  return;
}

// Library Function - Single Match
//  __acrt_locale_release_lc_time_reference
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __acrt_locale_release_lc_time_reference(undefined **param_1)
{
  int *piVar1;
  int iVar2;

  if ((param_1 != (undefined **)0x0) && (param_1 != &PTR_DAT_1800ca560))
  {
    LOCK();
    piVar1 = (int *)((longlong)param_1 + 0x15c);
    iVar2 = *piVar1;
    *piVar1 = *piVar1 + -1;
    return iVar2 + -1;
  }
  return 0x7fffffff;
}

// Library Function - Single Match
//  __acrt_release_locale_ref
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_release_locale_ref(longlong param_1)
{
  int *piVar1;
  int **ppiVar2;
  longlong lVar3;

  if (param_1 != 0)
  {
    LOCK();
    *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + -1;
    piVar1 = *(int **)(param_1 + 0xe0);
    if (piVar1 != (int *)0x0)
    {
      LOCK();
      *piVar1 = *piVar1 + -1;
    }
    piVar1 = *(int **)(param_1 + 0xf0);
    if (piVar1 != (int *)0x0)
    {
      LOCK();
      *piVar1 = *piVar1 + -1;
    }
    piVar1 = *(int **)(param_1 + 0xe8);
    if (piVar1 != (int *)0x0)
    {
      LOCK();
      *piVar1 = *piVar1 + -1;
    }
    piVar1 = *(int **)(param_1 + 0x100);
    if (piVar1 != (int *)0x0)
    {
      LOCK();
      *piVar1 = *piVar1 + -1;
    }
    ppiVar2 = (int **)(param_1 + 0x38);
    lVar3 = 6;
    do
    {
      if ((ppiVar2[-2] != (int *)&DAT_1800ee718) && (piVar1 = *ppiVar2, piVar1 != (int *)0x0))
      {
        LOCK();
        *piVar1 = *piVar1 + -1;
      }
      if ((ppiVar2[-3] != (int *)0x0) && (piVar1 = ppiVar2[-1], piVar1 != (int *)0x0))
      {
        LOCK();
        *piVar1 = *piVar1 + -1;
      }
      ppiVar2 = ppiVar2 + 4;
      lVar3 = lVar3 + -1;
    } while (lVar3 != 0);
    __acrt_locale_release_lc_time_reference(*(undefined ***)(param_1 + 0x120));
  }
  return;
}

// Library Function - Single Match
//  __acrt_update_thread_locale_data
//
// Library: Visual Studio 2015 Release

undefined **__acrt_update_thread_locale_data(void)
{
  code *pcVar1;
  __acrt_ptd *p_Var2;
  undefined **ppuVar3;

  p_Var2 = FUN_18006a750();
  if (((*(uint *)(p_Var2 + 0x3a8) & DAT_1800eee60) == 0) ||
      (ppuVar3 = *(undefined ***)(p_Var2 + 0x90), ppuVar3 == (undefined **)0x0))
  {
    __acrt_lock(4);
    ppuVar3 = _updatetlocinfoEx_nolock((undefined **)(p_Var2 + 0x90), DAT_180101d08);
    __acrt_unlock(4);
    if (ppuVar3 == (undefined **)0x0)
    {
      abort();
      pcVar1 = (code *)swi(3);
      ppuVar3 = (undefined **)(*pcVar1)();
      return ppuVar3;
    }
  }
  return ppuVar3;
}

// Library Function - Single Match
//  _updatetlocinfoEx_nolock
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined **_updatetlocinfoEx_nolock(undefined **param_1, undefined **param_2)
{
  undefined **ppuVar1;

  if ((param_2 == (undefined **)0x0) || (param_1 == (undefined **)0x0))
  {
    param_2 = (undefined **)0x0;
  }
  else
  {
    ppuVar1 = (undefined **)*param_1;
    if (ppuVar1 != param_2)
    {
      *param_1 = (undefined *)param_2;
      FUN_18007c1ec((longlong)param_2);
      if (((ppuVar1 != (undefined **)0x0) &&
           (__acrt_release_locale_ref((longlong)ppuVar1), *(int *)(ppuVar1 + 2) == 0)) &&
          (ppuVar1 != &PTR_DAT_1800ee5b0))
      {
        __acrt_free_locale(ppuVar1);
      }
    }
  }
  return param_2;
}

// Library Function - Single Match
//  __acrt_fp_strflt_to_string
//
// Library: Visual Studio 2015 Release

ulong __acrt_fp_strflt_to_string(undefined8 *param_1, ulonglong param_2, int param_3, longlong param_4)
{
  longlong lVar1;
  int iVar2;
  ulong *puVar3;
  char *pcVar4;
  char *pcVar5;
  ulong uVar6;
  longlong lVar7;
  char cVar8;

  if ((param_1 != (undefined8 *)0x0) && (param_2 != 0))
  {
    *(undefined *)param_1 = 0;
    iVar2 = 0;
    if (0 < param_3)
    {
      iVar2 = param_3;
    }
    if (param_2 <= (ulonglong)(longlong)(iVar2 + 1))
    {
      puVar3 = __doserrno();
      uVar6 = 0x22;
      goto LAB_18007c60f;
    }
    if (param_4 != 0)
    {
      pcVar5 = *(char **)(param_4 + 8);
      pcVar4 = (char *)((longlong)param_1 + 1);
      *(undefined *)param_1 = 0x30;
      while (0 < param_3)
      {
        cVar8 = *pcVar5;
        if (cVar8 == '\0')
        {
          cVar8 = '0';
        }
        else
        {
          pcVar5 = pcVar5 + 1;
        }
        *pcVar4 = cVar8;
        pcVar4 = pcVar4 + 1;
        param_3 = param_3 + -1;
      }
      *pcVar4 = '\0';
      if ((-1 < param_3) && ('4' < *pcVar5))
      {
        while (pcVar4 = pcVar4 + -1, *pcVar4 == '9')
        {
          *pcVar4 = '0';
        }
        *pcVar4 = *pcVar4 + '\x01';
      }
      if (*(char *)param_1 == '1')
      {
        *(int *)(param_4 + 4) = *(int *)(param_4 + 4) + 1;
      }
      else
      {
        lVar1 = -1;
        do
        {
          lVar7 = lVar1;
          lVar1 = lVar7 + 1;
        } while (*(char *)((longlong)param_1 + lVar7 + 2) != '\0');
        FUN_18003b8e0(param_1, (undefined8 *)((longlong)param_1 + 1), lVar7 + 2);
      }
      return 0;
    }
  }
  puVar3 = __doserrno();
  uVar6 = 0x16;
LAB_18007c60f:
  *puVar3 = uVar6;
  FUN_18006738c();
  return uVar6;
}

// Library Function - Multiple Matches With Same Base Name
//  public: __cdecl `anonymous namespace'::scoped_fp_state_reset::scoped_fp_state_reset(void)
// __ptr64
//  public: __cdecl `anonymous namespace'::scoped_fp_state_reset::scoped_fp_state_reset(void)
// __ptr64
//
// Library: Visual Studio 2015 Release

undefined8 *scoped_fp_state_reset(undefined8 *param_1)
{
  fegetenv((uint *)param_1);
  if (((byte) * (undefined4 *)param_1 & 0x1f) == 0x1f)
  {
    *(undefined *)(param_1 + 1) = 0;
  }
  else
  {
    feholdexcept(param_1);
    *(undefined *)(param_1 + 1) = 1;
  }
  return param_1;
}

// Library Function - Single Match
//  struct __crt_strtox::big_integer __cdecl __crt_strtox::make_big_integer_power_of_two(unsigned
// int)
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

big_integer __thiscall __crt_strtox::make_big_integer_power_of_two(__crt_strtox *this, uint param_1)
{
  ulonglong uVar1;

  uVar1 = (ulonglong)(param_1 >> 5) * 4;
  FUN_18003bd40((undefined(*)[16])(this + 4), 0, uVar1);
  *(int *)(this + uVar1 + 4) = 1 << ((byte)param_1 & 0x1f);
  *(uint *)this = (param_1 >> 5) + 1;
  return SUB81(this, 0);
}

// Library Function - Single Match
//  unsigned int __cdecl __crt_strtox::multiply_core(unsigned int * __ptr64 const,unsigned
// int,unsigned int)
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

uint __crt_strtox::multiply_core(uint *param_1, uint param_2, uint param_3)
{
  uint uVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  uint uVar4;
  ulonglong uVar5;

  uVar2 = 0;
  uVar1 = 0;
  if (param_2 != 0)
  {
    uVar5 = uVar2;
    do
    {
      uVar4 = (int)uVar5 + 1;
      uVar3 = (ulonglong)param_1[uVar5] * (ulonglong)param_3 + uVar2;
      param_1[uVar5] = (uint)uVar3;
      uVar2 = uVar3 >> 0x20;
      uVar1 = (uint)(uVar3 >> 0x20);
      uVar5 = (ulonglong)uVar4;
    } while (uVar4 != param_2);
  }
  return uVar1;
}

// Library Function - Single Match
//  memcpy_s
//
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

errno_t memcpy_s(void *_Dst, rsize_t _DstSize, void *_Src, rsize_t _MaxCount)
{
  ulong *puVar1;
  ulong uVar2;

  if (_MaxCount == 0)
  {
  LAB_18007febd:
    uVar2 = 0;
  }
  else
  {
    if (_Dst == (void *)0x0)
    {
    LAB_18007fec6:
      puVar1 = __doserrno();
      uVar2 = 0x16;
    }
    else
    {
      if ((_Src != (void *)0x0) && (_MaxCount <= _DstSize))
      {
        FUN_18003b8e0((undefined8 *)_Dst, (undefined8 *)_Src, _MaxCount);
        goto LAB_18007febd;
      }
      FUN_18003bd40((undefined(*)[16])_Dst, 0, _DstSize);
      if (_Src == (void *)0x0)
        goto LAB_18007fec6;
      if (_MaxCount <= _DstSize)
      {
        return 0x16;
      }
      puVar1 = __doserrno();
      uVar2 = 0x22;
    }
    *puVar1 = uVar2;
    FUN_18006738c();
  }
  return (errno_t)uVar2;
}

// Library Function - Single Match
//  _isatty
//
// Library: Visual Studio 2015 Release

int _isatty(int _FileHandle)
{
  ulong *puVar1;

  if (_FileHandle == -2)
  {
    puVar1 = __doserrno();
    *puVar1 = 9;
  }
  else
  {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_180102110))
    {
      return *(byte *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)_FileHandle >> 6) * 8) +
                       0x38 + (ulonglong)(_FileHandle & 0x3f) * 0x40) &
             0x40;
    }
    puVar1 = __doserrno();
    *puVar1 = 9;
    FUN_18006738c();
  }
  return (int)0;
}

// Library Function - Single Match
//  __acrt_locale_free_monetary
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_locale_free_monetary(longlong param_1)
{
  if (param_1 != 0)
  {
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_1800eee88)
    {
      _free_base(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_1800eee90)
    {
      _free_base(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x28) != PTR_DAT_1800eee98)
    {
      _free_base(*(undefined **)(param_1 + 0x28));
    }
    if (*(undefined **)(param_1 + 0x30) != PTR_DAT_1800eeea0)
    {
      _free_base(*(undefined **)(param_1 + 0x30));
    }
    if (*(undefined **)(param_1 + 0x38) != PTR_DAT_1800eeea8)
    {
      _free_base(*(undefined **)(param_1 + 0x38));
    }
    if (*(undefined **)(param_1 + 0x40) != PTR_DAT_1800eeeb0)
    {
      _free_base(*(undefined **)(param_1 + 0x40));
    }
    if (*(undefined **)(param_1 + 0x48) != PTR_DAT_1800eeeb8)
    {
      _free_base(*(undefined **)(param_1 + 0x48));
    }
    if (*(undefined **)(param_1 + 0x68) != PTR_DAT_1800eeed8)
    {
      _free_base(*(undefined **)(param_1 + 0x68));
    }
    if (*(undefined **)(param_1 + 0x70) != PTR_DAT_1800eeee0)
    {
      _free_base(*(undefined **)(param_1 + 0x70));
    }
    if (*(undefined **)(param_1 + 0x78) != PTR_DAT_1800eeee8)
    {
      _free_base(*(undefined **)(param_1 + 0x78));
    }
    if (*(undefined **)(param_1 + 0x80) != PTR_DAT_1800eeef0)
    {
      _free_base(*(undefined **)(param_1 + 0x80));
    }
    if (*(undefined **)(param_1 + 0x88) != PTR_DAT_1800eeef8)
    {
      _free_base(*(undefined **)(param_1 + 0x88));
    }
    if (*(undefined **)(param_1 + 0x90) != PTR_DAT_1800eef00)
    {
      _free_base(*(undefined **)(param_1 + 0x90));
    }
  }
  return;
}

// Library Function - Single Match
//  __acrt_locale_free_numeric
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_locale_free_numeric(LPVOID *param_1)
{
  if (param_1 != (LPVOID *)0x0)
  {
    if ((undefined *)*param_1 != PTR_DAT_1800eee70)
    {
      _free_base(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_1800eee78)
    {
      _free_base(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_1800eee80)
    {
      _free_base(param_1[2]);
    }
    if ((undefined *)param_1[0xb] != PTR_DAT_1800eeec8)
    {
      _free_base(param_1[0xb]);
    }
    if ((undefined *)param_1[0xc] != PTR_DAT_1800eeed0)
    {
      _free_base(param_1[0xc]);
    }
  }
  return;
}

// Library Function - Single Match
//  bool __cdecl initialize_lc_time(struct __crt_lc_time_data * __ptr64 const,struct
// __crt_locale_data * __ptr64 const)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool initialize_lc_time(__crt_lc_time_data *param_1, __crt_locale_data *param_2)
{
  undefined(*pauVar1)[32];
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  short *psVar13;
  uint uVar14;
  LPWSTR *ppWVar15;
  longlong lVar16;
  LCTYPE LVar17;
  __crt_locale_data *local_38;
  undefined8 local_30;

  pauVar1 = *(undefined(**)[32])(param_2 + 0x150);
  uVar14 = 0;
  local_30 = 0;
  local_38 = param_2;
  psVar13 = __acrt_copy_locale_name(pauVar1);
  *(short **)(param_1 + 0x2b8) = psVar13;
  LVar17 = 0x31;
  lVar16 = 7;
  do
  {
    ppWVar15 = (LPWSTR *)(param_1 + (ulonglong)((LVar17 - 0x30) % 7) * 8);
    uVar2 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 1, (longlong)pauVar1, LVar17, ppWVar15);
    uVar3 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 1, (longlong)pauVar1, LVar17 - 7, ppWVar15 + 7);
    uVar4 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 2, (longlong)pauVar1, LVar17, ppWVar15 + 0x2c);
    uVar5 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 2, (longlong)pauVar1, LVar17 - 7, ppWVar15 + 0x33);
    uVar14 = uVar14 | uVar2 | uVar3 | uVar4 | uVar5;
    LVar17 = LVar17 + 1;
    lVar16 = lVar16 + -1;
  } while (lVar16 != 0);
  LVar17 = 0x38;
  lVar16 = 0xc;
  ppWVar15 = (LPWSTR *)(param_1 + 0xd0);
  do
  {
    uVar2 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 1, (longlong)pauVar1, LVar17 + 0xc, ppWVar15 + -0xc);
    uVar3 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 1, (longlong)pauVar1, LVar17, ppWVar15);
    uVar4 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 2, (longlong)pauVar1, LVar17 + 0xc, ppWVar15 + 0x20);
    uVar5 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 2, (longlong)pauVar1, LVar17, ppWVar15 + 0x2c);
    uVar14 = uVar14 | uVar2 | uVar3 | uVar4 | uVar5;
    ppWVar15 = ppWVar15 + 1;
    LVar17 = LVar17 + 1;
    lVar16 = lVar16 + -1;
  } while (lVar16 != 0);
  uVar2 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 1, (longlong)pauVar1, 0x28, (LPWSTR *)(param_1 + 0x130));
  uVar3 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 1, (longlong)pauVar1, 0x29, (LPWSTR *)(param_1 + 0x138));
  uVar4 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 2, (longlong)pauVar1, 0x28, (LPWSTR *)(param_1 + 0x290));
  uVar5 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 2, (longlong)pauVar1, 0x29, (LPWSTR *)(param_1 + 0x298));
  uVar6 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 1, (longlong)pauVar1, 0x1f, (LPWSTR *)(param_1 + 0x140));
  uVar7 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 1, (longlong)pauVar1, 0x20, (LPWSTR *)(param_1 + 0x148));
  uVar8 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 1, (longlong)pauVar1, 0x1003, (LPWSTR *)(param_1 + 0x150));
  uVar9 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 0, (longlong)pauVar1, 0x1009, (LPWSTR *)(param_1 + 0x158));
  uVar10 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 2, (longlong)pauVar1, 0x1f, (LPWSTR *)(param_1 + 0x2a0));
  uVar11 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 2, (longlong)pauVar1, 0x20, (LPWSTR *)(param_1 + 0x2a8));
  uVar12 = __acrt_GetLocaleInfoA((undefined4 *)&local_38, 2, (longlong)pauVar1, 0x1003, (LPWSTR *)(param_1 + 0x2b0));
  return (uVar12 | uVar14 | uVar2 | uVar3 | uVar4 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 |
          uVar11) == 0;
}

// Library Function - Single Match
//  __acrt_locale_free_time
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_locale_free_time(LPVOID *param_1)
{
  if (param_1 != (LPVOID *)0x0)
  {
    FUN_180080a54(param_1, 7);
    FUN_180080a54(param_1 + 7, 7);
    FUN_180080a54(param_1 + 0xe, 0xc);
    FUN_180080a54(param_1 + 0x1a, 0xc);
    FUN_180080a54(param_1 + 0x26, 2);
    _free_base(param_1[0x28]);
    _free_base(param_1[0x29]);
    _free_base(param_1[0x2a]);
    FUN_180080a54(param_1 + 0x2c, 7);
    FUN_180080a54(param_1 + 0x33, 7);
    FUN_180080a54(param_1 + 0x3a, 0xc);
    FUN_180080a54(param_1 + 0x46, 0xc);
    FUN_180080a54(param_1 + 0x52, 2);
    _free_base(param_1[0x54]);
    _free_base(param_1[0x55]);
    _free_base(param_1[0x56]);
    _free_base(param_1[0x57]);
  }
  return;
}

// Library Function - Single Match
//  wcscat_s
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t wcscat_s(wchar_t *_Dst, rsize_t _SizeInWords, wchar_t *_Src)
{
  wchar_t wVar1;
  ulong *puVar2;
  wchar_t *pwVar3;
  ulong uVar4;
  wchar_t *pwVar5;

  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0))
  {
    pwVar3 = _Dst;
    if (_Src == (wchar_t *)0x0)
    {
      *_Dst = L'\0';
    }
    else
    {
      do
      {
        if (*pwVar3 == L'\0')
          break;
        pwVar3 = pwVar3 + 1;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0)
      {
        pwVar5 = (wchar_t *)((longlong)_Src - (longlong)pwVar3);
        do
        {
          wVar1 = *(wchar_t *)((longlong)pwVar5 + (longlong)pwVar3);
          *pwVar3 = wVar1;
          pwVar3 = pwVar3 + 1;
          if (wVar1 == L'\0')
            break;
          _SizeInWords = _SizeInWords - 1;
        } while (_SizeInWords != 0);
        if (_SizeInWords != 0)
        {
          return 0;
        }
        *_Dst = L'\0';
        puVar2 = __doserrno();
        uVar4 = 0x22;
        goto LAB_1800810d3;
      }
      *_Dst = L'\0';
    }
  }
  puVar2 = __doserrno();
  uVar4 = 0x16;
LAB_1800810d3:
  *puVar2 = uVar4;
  FUN_18006738c();
  return (errno_t)uVar4;
}

// Library Function - Single Match
//  wcscspn
//
// Library: Visual Studio 2015 Release

size_t wcscspn(wchar_t *_Str, wchar_t *_Control)
{
  wchar_t *pwVar1;
  wchar_t wVar2;
  wchar_t *pwVar3;

  wVar2 = *_Str;
  pwVar1 = _Str;
  while (wVar2 != L'\0')
  {
    if (*_Control != L'\0')
    {
      wVar2 = *_Control;
      pwVar3 = _Control;
      do
      {
        if (*pwVar1 == wVar2)
          goto LAB_180081164;
        pwVar3 = pwVar3 + 1;
        wVar2 = *pwVar3;
      } while (wVar2 != L'\0');
    }
    pwVar1 = pwVar1 + 1;
    wVar2 = *pwVar1;
  }
LAB_180081164:
  return (longlong)((longlong)pwVar1 - (longlong)_Str) >> 1;
}

// Library Function - Single Match
//  wcspbrk
//
// Library: Visual Studio 2015 Release

wchar_t *wcspbrk(wchar_t *_Str, wchar_t *_Control)
{
  wchar_t *pwVar1;
  wchar_t wVar2;

  do
  {
    if (*_Str == L'\0')
    {
      return (wchar_t *)0x0;
    }
    if (*_Control != L'\0')
    {
      wVar2 = *_Control;
      pwVar1 = _Control;
      do
      {
        if (wVar2 == *_Str)
        {
          return _Str;
        }
        pwVar1 = pwVar1 + 1;
        wVar2 = *pwVar1;
      } while (wVar2 != L'\0');
    }
    _Str = _Str + 1;
  } while (true);
}

// Library Function - Single Match
//  GetLocaleNameFromDefault
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void GetLocaleNameFromDefault(longlong param_1)
{
  code *pcVar1;
  int iVar2;
  ulong uVar3;
  longlong lVar4;
  wchar_t local_c8[88];
  ulonglong local_18;
  longlong lVar5;

  local_18 = DAT_1800ee160 ^ (ulonglong)&stack0xffffffffffffff08;
  *(uint *)(param_1 + 0x10) = *(uint *)(param_1 + 0x10) | 0x104;
  iVar2 = __acrt_GetUserDefaultLocaleName(local_c8, 0x55);
  if (1 < iVar2)
  {
    lVar4 = -1;
    do
    {
      lVar5 = lVar4;
      lVar4 = lVar5 + 1;
    } while (local_c8[lVar4] != L'\0');
    uVar3 = FUN_180061a44((short *)(param_1 + 600), 0x55, (longlong)local_c8, lVar5 + 2);
    if (uVar3 != 0)
    {
      _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
      pcVar1 = (code *)swi(3);
      (*pcVar1)();
      return;
    }
  }
  FUN_180034d00(local_18 ^ (ulonglong)&stack0xffffffffffffff08);
  return;
}

// Library Function - Single Match
//  GetLocaleNameFromLangCountry
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void GetLocaleNameFromLangCountry(short **param_1)
{
  short sVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  longlong lVar5;
  short *psVar6;
  longlong lVar7;

  psVar6 = *param_1;
  lVar7 = -1;
  iVar4 = 0;
  lVar5 = -1;
  do
  {
    lVar5 = lVar5 + 1;
  } while (psVar6[lVar5] != 0);
  *(uint *)(param_1 + 3) = (uint)(lVar5 == 3);
  do
  {
    lVar7 = lVar7 + 1;
  } while (param_1[1][lVar7] != 0);
  *(uint *)((longlong)param_1 + 0x1c) = (uint)(lVar7 == 3);
  if (lVar5 == 3)
  {
    iVar4 = 2;
  }
  else
  {
    iVar3 = 0;
    if (psVar6 != (short *)0x0)
    {
      while (true)
      {
        iVar4 = iVar3;
        sVar1 = *psVar6;
        psVar6 = psVar6 + 1;
        if ((0x19 < (ushort)(sVar1 - 0x41U)) && (0x19 < (ushort)(sVar1 - 0x61U)))
          break;
        iVar3 = iVar4 + 1;
      }
    }
  }
  *(int *)((longlong)param_1 + 0x14) = iVar4;
  __acrt_EnumSystemLocalesEx(&LAB_180081578);
  uVar2 = *(uint *)(param_1 + 2);
  if ((uVar2 >> 8 & 1) == 0 || ((uVar2 & 7) == 0 || (uVar2 >> 9 & 1) == 0))
  {
    *(undefined4 *)(param_1 + 2) = 0;
  }
  return;
}

// Library Function - Single Match
//  ProcessCodePage
//
// Library: Visual Studio 2015 Release

UINT ProcessCodePage(wchar_t *param_1, longlong param_2)
{
  int iVar1;
  UINT UVar2;
  UINT local_res8[2];

  if (((param_1 == (wchar_t *)0x0) || (*param_1 == L'\0')) ||
      (iVar1 = wcscmp(param_1, L"ACP"), iVar1 == 0))
  {
    iVar1 = __acrt_GetLocaleInfoEx(param_2 + 600, 0x20001004, (LPWSTR)local_res8, 2);
    if (iVar1 != 0)
    {
      if (local_res8[0] != 0)
      {
        return local_res8[0];
      }
      UVar2 = GetACP();
      return UVar2;
    }
  }
  else
  {
    iVar1 = wcscmp(param_1, L"OCP");
    if (iVar1 != 0)
    {
      UVar2 = _wtol(param_1);
      return UVar2;
    }
    iVar1 = __acrt_GetLocaleInfoEx(param_2 + 600, 0x2000000b, (LPWSTR)local_res8, 2);
    if (iVar1 != 0)
    {
      return local_res8[0];
    }
  }
  return 0;
}

// Library Function - Single Match
//  TestDefaultCountry
//
// Library: Visual Studio 2015 Release

void TestDefaultCountry(wchar_t *param_1)
{
  int iVar1;
  undefined auStack72[32];
  WCHAR local_28[12];
  ulonglong local_10;

  local_10 = DAT_1800ee160 ^ (ulonglong)auStack72;
  iVar1 = __acrt_GetLocaleInfoEx((longlong)param_1, 0x59, local_28, 9);
  if (iVar1 != 0)
  {
    wcsncmp(local_28, param_1, 9);
  }
  FUN_180034d00(local_10 ^ (ulonglong)auStack72);
  return;
}

// Library Function - Single Match
//  TranslateName
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

bool TranslateName(longlong param_1, int param_2, wint_t **param_3)
{
  int iVar1;
  int iVar2;
  int iVar3;

  iVar2 = 1;
  iVar3 = 0;
  if (-1 < param_2)
  {
    do
    {
      if (iVar2 == 0)
      {
        return iVar2 == 0;
      }
      iVar1 = (iVar3 + param_2) / 2;
      iVar2 = FUN_180062194(*param_3, *(wint_t **)((longlong)iVar1 * 0x10 + param_1));
      if (iVar2 == 0)
      {
        *param_3 = (wint_t *)(param_1 + 8 + (longlong)iVar1 * 0x10);
      }
      else
      {
        if (iVar2 < 0)
        {
          param_2 = iVar1 + -1;
        }
        else
        {
          iVar3 = iVar1 + 1;
        }
      }
    } while (iVar3 <= param_2);
  }
  return iVar2 == 0;
}

// Library Function - Single Match
//  GetLcidFromLangCountry
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void GetLcidFromLangCountry(uint *param_1)
{
  short sVar1;
  uint uVar2;
  __acrt_ptd *p_Var3;
  short *psVar4;
  int iVar5;
  longlong lVar6;
  longlong lVar7;
  int iVar8;

  p_Var3 = FUN_18006a750();
  lVar6 = -1;
  lVar7 = -1;
  iVar8 = 0;
  do
  {
    lVar7 = lVar7 + 1;
  } while ((*(short **)(p_Var3 + 0x98))[lVar7] != 0);
  *(uint *)(p_Var3 + 0xb0) = (uint)(lVar7 == 3);
  do
  {
    lVar6 = lVar6 + 1;
  } while (*(short *)(*(longlong *)(p_Var3 + 0xa0) + lVar6 * 2) != 0);
  *(uint *)(p_Var3 + 0xb4) = (uint)(lVar6 == 3);
  param_1[1] = 0;
  iVar5 = 2;
  if (*(int *)(p_Var3 + 0xb0) == 0)
  {
    psVar4 = *(short **)(p_Var3 + 0x98);
    while (true)
    {
      sVar1 = *psVar4;
      psVar4 = psVar4 + 1;
      if ((0x19 < (ushort)(sVar1 - 0x41U)) && (iVar5 = iVar8, 0x19 < (ushort)(sVar1 - 0x61U)))
        break;
      iVar8 = iVar8 + 1;
    }
  }
  *(int *)(p_Var3 + 0xac) = iVar5;
  EnumSystemLocalesW((LOCALE_ENUMPROCW)&LAB_180082178, 1);
  uVar2 = *param_1;
  if ((uVar2 >> 8 & 1) == 0 || ((uVar2 & 7) == 0 || (uVar2 >> 9 & 1) == 0))
  {
    *param_1 = 0;
  }
  return;
}

// Library Function - Single Match
//  LcidFromHexString
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int LcidFromHexString(ushort *param_1)
{
  short sVar1;
  ushort uVar2;
  ushort uVar3;
  int iVar4;

  uVar3 = *param_1;
  iVar4 = 0;
  do
  {
    if (uVar3 == 0)
    {
      return iVar4;
    }
    param_1 = param_1 + 1;
    if ((ushort)(uVar3 - 0x61) < 6)
    {
      sVar1 = -0x27;
    LAB_1800824e4:
      uVar2 = uVar3 + sVar1;
    }
    else
    {
      uVar2 = uVar3;
      if ((ushort)(uVar3 - 0x41) < 6)
      {
        sVar1 = -7;
        goto LAB_1800824e4;
      }
    }
    uVar3 = *param_1;
    iVar4 = iVar4 * 0x10 + -0x30 + (uint)uVar2;
  } while (true);
}

// Library Function - Single Match
//  ProcessCodePage
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

UINT ProcessCodePage(wchar_t *param_1, longlong param_2)
{
  int iVar1;
  UINT UVar2;
  UINT local_res8[2];

  if (((param_1 == (wchar_t *)0x0) || (*param_1 == L'\0')) ||
      (iVar1 = wcscmp(param_1, L"ACP"), iVar1 == 0))
  {
    iVar1 = GetLocaleInfoW(*(LCID *)(param_2 + 8), 0x20001004, (LPWSTR)local_res8, 2);
    if (iVar1 != 0)
    {
      if (local_res8[0] != 0)
      {
        return local_res8[0];
      }
      UVar2 = GetACP();
      return UVar2;
    }
  }
  else
  {
    iVar1 = wcscmp(param_1, L"OCP");
    if (iVar1 != 0)
    {
      UVar2 = _wtol(param_1);
      return UVar2;
    }
    iVar1 = GetLocaleInfoW(*(LCID *)(param_2 + 8), 0x2000000b, (LPWSTR)local_res8, 2);
    if (iVar1 != 0)
    {
      return local_res8[0];
    }
  }
  return 0;
}

// Library Function - Single Match
//  TestDefaultLanguage
//
// Library: Visual Studio 2015 Release

undefined8 TestDefaultLanguage(uint param_1, int param_2)
{
  short sVar1;
  short *psVar2;
  int iVar3;
  __acrt_ptd *p_Var4;
  longlong lVar5;
  undefined8 uVar6;
  short *psVar7;
  uint local_res8[2];

  p_Var4 = FUN_18006a750();
  iVar3 = GetLocaleInfoW(param_1 & 0x3ff | 0x400, 0x20000001, (LPWSTR)local_res8, 2);
  if (iVar3 == 0)
  {
  LAB_18008261c:
    uVar6 = 0;
  }
  else
  {
    if ((param_1 != local_res8[0]) && (param_2 != 0))
    {
      psVar2 = *(short **)(p_Var4 + 0x98);
      iVar3 = 0;
      sVar1 = *psVar2;
      psVar7 = psVar2;
      while ((psVar7 = psVar7 + 1, (ushort)(sVar1 - 0x41U) < 0x1a ||
                                       ((ushort)(sVar1 - 0x61U) < 0x1a)))
      {
        sVar1 = *psVar7;
        iVar3 = iVar3 + 1;
      }
      lVar5 = -1;
      do
      {
        lVar5 = lVar5 + 1;
      } while (psVar2[lVar5] != 0);
      if (iVar3 == (int)lVar5)
        goto LAB_18008261c;
    }
    uVar6 = 1;
  }
  return uVar6;
}

// Library Function - Single Match
//  TranslateName
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong TranslateName(longlong param_1, int param_2, wint_t **param_3)
{
  int iVar1;
  int iVar2;
  ulonglong in_RAX;
  undefined4 extraout_var;
  wint_t *pwVar3;
  int iVar4;

  iVar4 = 0;
  if (-1 < param_2)
  {
    do
    {
      iVar1 = (iVar4 + param_2) / 2;
      iVar2 = FUN_180062194(*param_3, *(wint_t **)((longlong)iVar1 * 0x10 + param_1));
      in_RAX = CONCAT44(extraout_var, iVar2);
      if (iVar2 == 0)
      {
        pwVar3 = (wint_t *)(param_1 + 8 + (longlong)iVar1 * 0x10);
        *param_3 = pwVar3;
        return CONCAT71((int7)((ulonglong)pwVar3 >> 8), 1);
      }
      if (iVar2 < 0)
      {
        param_2 = iVar1 + -1;
      }
      else
      {
        iVar4 = iVar1 + 1;
      }
    } while (iVar4 <= param_2);
  }
  return in_RAX & 0xffffffffffffff00;
}

// Library Function - Single Match
//  localeconv
//
// Library: Visual Studio 2015 Release

lconv *localeconv(void)
{
  __acrt_ptd *p_Var1;
  undefined *local_res8[4];

  p_Var1 = FUN_18006a750();
  local_res8[0] = *(undefined **)(p_Var1 + 0x90);
  __acrt_update_locale_info((longlong)p_Var1, local_res8);
  return *(lconv **)(local_res8[0] + 0xf8);
}

// Library Function - Single Match
//  __acrt_lowio_create_handle_array
//
// Library: Visual Studio 2015 Release

undefined8 *__acrt_lowio_create_handle_array(void)
{
  undefined8 *puVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;

  puVar2 = (undefined8 *)_calloc_base(0x40, 0x40);
  puVar3 = (undefined8 *)0x0;
  if ((puVar2 != (undefined8 *)0x0) && (puVar3 = puVar2, puVar2 != puVar2 + 0x200))
  {
    puVar2 = puVar2 + 6;
    do
    {
      __acrt_InitializeCriticalSectionEx((LPCRITICAL_SECTION)(puVar2 + -6), 4000);
      puVar2[-1] = 0xffffffffffffffff;
      *puVar2 = 0;
      *(undefined4 *)(puVar2 + 1) = 0xa0a0000;
      *(undefined *)((longlong)puVar2 + 0xc) = 10;
      *(byte *)((longlong)puVar2 + 0xd) = *(byte *)((longlong)puVar2 + 0xd) & 0xf8;
      *(undefined *)((longlong)puVar2 + 0xe) = 0;
      puVar1 = puVar2 + 2;
      puVar2 = puVar2 + 8;
    } while (puVar1 != puVar2 + 0x200);
  }
  _free_base((LPVOID)0x0);
  return puVar3;
}

// Library Function - Multiple Matches With Different Base Names
//  __acrt_lowio_lock_fh
//  __acrt_lowio_unlock_fh
//
// Library: Visual Studio 2015 Release

void FID_conflict___acrt_lowio_lock_fh(uint param_1)
{
  // WARNING: Could not recover jumptable at 0x000180082bd8. Too many branches
  // WARNING: Treating indirect jump as call
  EnterCriticalSection((LPCRITICAL_SECTION)((ulonglong)(param_1 & 0x3f) * 0x40 +
                                            *(longlong *)((longlong)&DAT_180101d10 + ((longlong)(int)param_1 >> 6) * 8)));
  return;
}

// Library Function - Single Match
//  __acrt_lowio_set_os_handle
//
// Library: Visual Studio 2015 Release

undefined8 __acrt_lowio_set_os_handle(uint param_1, HANDLE param_2)
{
  int iVar1;
  ulong *puVar2;
  DWORD nStdHandle;
  longlong lVar3;

  if ((-1 < (int)param_1) && (param_1 < DAT_180102110))
  {
    lVar3 = (ulonglong)(param_1 & 0x3f) * 0x40;
    if (*(longlong *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)(int)param_1 >> 6) * 8) + 0x28 + lVar3) == -1)
    {
      iVar1 = FUN_180086f74();
      if (iVar1 == 1)
      {
        if (param_1 == 0)
        {
          nStdHandle = 0xfffffff6;
        }
        else
        {
          if (param_1 == 1)
          {
            nStdHandle = 0xfffffff5;
          }
          else
          {
            if (param_1 != 2)
              goto LAB_180082c61;
            nStdHandle = 0xfffffff4;
          }
        }
        SetStdHandle(nStdHandle, param_2);
      }
    LAB_180082c61:
      *(HANDLE *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)(int)param_1 >> 6) * 8) + 0x28 + lVar3) = param_2;
      return 0;
    }
  }
  puVar2 = __doserrno();
  *puVar2 = 9;
  puVar2 = __doserrno();
  *puVar2 = 0;
  return 0xffffffff;
}

// Library Function - Multiple Matches With Different Base Names
//  __acrt_lowio_lock_fh
//  __acrt_lowio_unlock_fh
//
// Library: Visual Studio 2015 Release

void FID_conflict___acrt_lowio_lock_fh(uint param_1)
{
  // WARNING: Could not recover jumptable at 0x000180082cbc. Too many branches
  // WARNING: Treating indirect jump as call
  LeaveCriticalSection((LPCRITICAL_SECTION)((ulonglong)(param_1 & 0x3f) * 0x40 +
                                            *(longlong *)((longlong)&DAT_180101d10 + ((longlong)(int)param_1 >> 6) * 8)));
  return;
}

// Library Function - Single Match
//  _free_osfhnd
//
// Library: Visual Studio 2015 Release

int _free_osfhnd(int param_1)
{
  int iVar1;
  ulong *puVar2;
  DWORD nStdHandle;
  longlong lVar3;

  if ((-1 < param_1) && ((uint)param_1 < DAT_180102110))
  {
    lVar3 = (ulonglong)(param_1 & 0x3f) * 0x40;
    if (((*(byte *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)param_1 >> 6) * 8) + 0x38 +
                    lVar3) &
          1) != 0) &&
        (*(longlong *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)param_1 >> 6) * 8) + 0x28 + lVar3) !=
         -1))
    {
      iVar1 = FUN_180086f74();
      if (iVar1 == 1)
      {
        if (param_1 == 0)
        {
          nStdHandle = 0xfffffff6;
        }
        else
        {
          if (param_1 == 1)
          {
            nStdHandle = 0xfffffff5;
          }
          else
          {
            if (param_1 != 2)
              goto LAB_180082e68;
            nStdHandle = 0xfffffff4;
          }
        }
        SetStdHandle(nStdHandle, (HANDLE)0x0);
      }
    LAB_180082e68:
      *(undefined8 *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)param_1 >> 6) * 8) + 0x28 + lVar3) =
          0xffffffffffffffff;
      return 0;
    }
  }
  puVar2 = __doserrno();
  *puVar2 = 9;
  puVar2 = __doserrno();
  *puVar2 = 0;
  return -1;
}

// Library Function - Single Match
//  _get_osfhandle
//
// Library: Visual Studio 2015 Release

intptr_t _get_osfhandle(int _FileHandle)
{
  ulong *puVar1;
  longlong lVar2;

  if (_FileHandle == -2)
  {
    puVar1 = __doserrno();
    *puVar1 = 0;
    puVar1 = __doserrno();
    *puVar1 = 9;
  }
  else
  {
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_180102110))
    {
      lVar2 = (ulonglong)(_FileHandle & 0x3f) * 0x40;
      if ((*(byte *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)_FileHandle >> 6) * 8) +
                     0x38 + lVar2) &
           1) != 0)
      {
        return *(intptr_t *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)_FileHandle >> 6) * 8) + 0x28 +
                             lVar2);
      }
    }
    puVar1 = __doserrno();
    *puVar1 = 0;
    puVar1 = __doserrno();
    *puVar1 = 9;
    FUN_18006738c();
  }
  return -1;
}

// Library Function - Single Match
//  __int64 __cdecl common_lseek_nolock<__int64>(int,__int64,int)
//
// Library: Visual Studio 2015 Release

__int64 common_lseek_nolock___int64_(int param_1, __int64 param_2, int param_3)
{
  byte *pbVar1;
  BOOL BVar2;
  DWORD DVar3;
  HANDLE hFile;
  ulong *puVar4;
  longlong local_res20;

  hFile = (HANDLE)_get_osfhandle(param_1);
  if (hFile == (HANDLE)0xffffffffffffffff)
  {
    puVar4 = __doserrno();
    *puVar4 = 9;
  }
  else
  {
    BVar2 = SetFilePointerEx(hFile, param_2, &local_res20, param_3);
    if (BVar2 == 0)
    {
      DVar3 = GetLastError();
      __acrt_errno_map_os_error(DVar3);
    }
    else
    {
      if (local_res20 != -1)
      {
        pbVar1 = (byte *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)param_1 >> 6) * 8) +
                          0x38 + (ulonglong)(param_1 & 0x3f) * 0x40);
        *pbVar1 = *pbVar1 & 0xfd;
        return local_res20;
      }
    }
  }
  return -1;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __acrt_stdio_allocate_buffer_nolock
//
// Library: Visual Studio 2015 Release

void __acrt_stdio_allocate_buffer_nolock(undefined8 *param_1)
{
  LPVOID pvVar1;

  _DAT_180101940 = _DAT_180101940 + 1;
  pvVar1 = _malloc_base(0x1000);
  param_1[1] = pvVar1;
  _free_base((LPVOID)0x0);
  if (param_1[1] == 0)
  {
    LOCK();
    *(uint *)((longlong)param_1 + 0x14) = *(uint *)((longlong)param_1 + 0x14) | 0x400;
    *(undefined4 *)(param_1 + 4) = 2;
    param_1[1] = (longlong)param_1 + 0x1c;
  }
  else
  {
    LOCK();
    *(uint *)((longlong)param_1 + 0x14) = *(uint *)((longlong)param_1 + 0x14) | 0x40;
    *(undefined4 *)(param_1 + 4) = 0x1000;
  }
  *(undefined4 *)(param_1 + 2) = 0;
  *param_1 = param_1[1];
  return;
}

// Library Function - Multiple Matches With Same Base Name
//  public: unsigned short __cdecl __crt_seh_guarded_call<unsigned short>::operator()<class
// <lambda_0384895ae1aa6ccbfe369a30d6ca2ef7>,class <lambda_9e0b6ab72a5b3ae37ad997d08b519f50>&
// __ptr64,class <lambda_7e22f70504d73c22058e5832bde5914f>>(class
// <lambda_0384895ae1aa6ccbfe369a30d6ca2ef7>&& __ptr64,class
// <lambda_9e0b6ab72a5b3ae37ad997d08b519f50>& __ptr64,class
// <lambda_7e22f70504d73c22058e5832bde5914f>&& __ptr64) __ptr64
//  public: unsigned short __cdecl __crt_seh_guarded_call<unsigned short>::operator()<class
// <lambda_9fda798407f8391327e99fec20084266>,class <lambda_6e3e78bb6855d1e4040e022c1b427e22>&
// __ptr64,class <lambda_5d54a80e00f5dcce6acfc22736ebf0cf>>(class
// <lambda_9fda798407f8391327e99fec20084266>&& __ptr64,class
// <lambda_6e3e78bb6855d1e4040e022c1b427e22>& __ptr64,class
// <lambda_5d54a80e00f5dcce6acfc22736ebf0cf>&& __ptr64) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined2 operator____(undefined8 param_1, int *param_2, undefined8 *param_3, int *param_4)
{
  undefined2 uVar1;

  __acrt_lock(*param_2);
  uVar1 = FUN_1800835bc(*(undefined2 *)*param_3);
  __acrt_unlock(*param_4);
  return uVar1;
}

// Library Function - Single Match
//  char * __ptr64 __cdecl common_getenv_nolock<char>(char const * __ptr64 const)
//
// Library: Visual Studio 2015 Release

char *common_getenv_nolock_char_(char *param_1)
{
  char *pcVar1;
  int iVar2;
  char **ppcVar3;
  ulonglong uVar4;
  ulonglong _MaxCount;
  ulonglong uVar5;

  ppcVar3 = (char **)__dcrt_get_or_create_narrow_environment_nolock();
  if ((ppcVar3 != (char **)0x0) && (param_1 != (char *)0x0))
  {
    _MaxCount = 0xffffffffffffffff;
    do
    {
      uVar5 = _MaxCount;
      _MaxCount = uVar5 + 1;
    } while (param_1[_MaxCount] != '\0');
    pcVar1 = *ppcVar3;
    while (pcVar1 != (char *)0x0)
    {
      pcVar1 = *ppcVar3;
      uVar4 = 0xffffffffffffffff;
      do
      {
        uVar4 = uVar4 + 1;
      } while (pcVar1[uVar4] != '\0');
      if (((_MaxCount < uVar4) && (pcVar1[_MaxCount] == '=')) &&
          (iVar2 = _strnicoll(pcVar1, param_1, _MaxCount), iVar2 == 0))
      {
        return *ppcVar3 + uVar5 + 2;
      }
      ppcVar3 = ppcVar3 + 1;
      pcVar1 = *ppcVar3;
    }
  }
  return (char *)0x0;
}

// Library Function - Single Match
//  wchar_t * __ptr64 __cdecl common_getenv_nolock<wchar_t>(wchar_t const * __ptr64 const)
//
// Library: Visual Studio 2015 Release

wchar_t *common_getenv_nolock_wchar_t_(wchar_t *param_1)
{
  undefined(*pauVar1)[32];
  longlong lVar2;
  int iVar3;
  undefined(**ppauVar4)[32];
  ulonglong uVar5;
  ulonglong uVar7;
  ulonglong uVar6;
  ulonglong uVar8;

  ppauVar4 = (undefined(**)[32])__dcrt_get_or_create_wide_environment_nolock();
  if ((ppauVar4 != (undefined(**)[32])0x0) && (param_1 != (wchar_t *)0x0))
  {
    uVar7 = 0xffffffffffffffff;
    do
    {
      uVar8 = uVar7;
      uVar7 = uVar8 + 1;
    } while (*(short *)(param_1 + uVar7 * 2) != 0);
    pauVar1 = *ppauVar4;
    while (pauVar1 != (undefined(*)[32])0x0)
    {
      pauVar1 = *ppauVar4;
      uVar6 = 0xffffffffffffffff;
      do
      {
        uVar5 = uVar6 + 1;
        lVar2 = uVar6 * 2;
        uVar6 = uVar5;
      } while (*(short *)(*pauVar1 + lVar2 + 2) != 0);
      if (((uVar7 < uVar5) && (*(short *)(*pauVar1 + uVar8 * 2 + 2) == 0x3d)) &&
          (iVar3 = FUN_180085190(pauVar1, (undefined(*)[32])param_1, uVar7), iVar3 == 0))
      {
        return (wchar_t *)(**ppauVar4 + uVar8 * 2 + 4);
      }
      ppauVar4 = ppauVar4 + 1;
      pauVar1 = *ppauVar4;
    }
  }
  return (wchar_t *)0x0;
}

// Library Function - Single Match
//  _mbstowcs_s_l
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t _mbstowcs_s_l(size_t *_PtNumOfCharConverted, wchar_t *_DstBuf, size_t _SizeInWords,
                      char *_SrcBuf, size_t _MaxCount, _locale_t _Locale)
{
  ulong *puVar1;
  ulonglong uVar2;
  ulong uVar3;
  size_t sVar4;
  __acrt_ptd *local_38;
  undefined4 local_30[4];
  char local_20;

  uVar3 = 0;
  if (_DstBuf == (wchar_t *)0x0)
  {
    if (_SizeInWords != 0)
    {
    LAB_1800843c1:
      puVar1 = __doserrno();
      *puVar1 = 0x16;
      FUN_18006738c();
      return 0x16;
    }
  }
  else
  {
    if (_SizeInWords == 0)
      goto LAB_1800843c1;
  }
  if (_DstBuf != (wchar_t *)0x0)
  {
    *_DstBuf = L'\0';
  }
  if (_PtNumOfCharConverted != (size_t *)0x0)
  {
    *_PtNumOfCharConverted = 0;
  }
  FUN_18004e538(&local_38, (undefined4 *)_Locale);
  sVar4 = _MaxCount;
  if (_SizeInWords < _MaxCount)
  {
    sVar4 = _SizeInWords;
  }
  if (sVar4 < 0x80000000)
  {
    uVar2 = FUN_18008415c((ushort *)_DstBuf, (byte *)_SrcBuf, sVar4, local_30);
    if (uVar2 == 0xffffffffffffffff)
    {
      if (_DstBuf != (wchar_t *)0x0)
      {
        *_DstBuf = L'\0';
      }
      puVar1 = __doserrno();
      uVar3 = *puVar1;
      goto LAB_180084444;
    }
    uVar2 = uVar2 + 1;
    if (_DstBuf != (wchar_t *)0x0)
    {
      if (_SizeInWords < uVar2)
      {
        if (_MaxCount != 0xffffffffffffffff)
        {
          *_DstBuf = L'\0';
          puVar1 = __doserrno();
          uVar3 = 0x22;
          goto LAB_180084425;
        }
        uVar3 = 0x50;
        uVar2 = _SizeInWords;
      }
      _DstBuf[uVar2 - 1] = L'\0';
    }
    if (_PtNumOfCharConverted != (size_t *)0x0)
    {
      *_PtNumOfCharConverted = uVar2;
    }
  }
  else
  {
    puVar1 = __doserrno();
    uVar3 = 0x16;
  LAB_180084425:
    *puVar1 = uVar3;
    FUN_18006738c();
  }
LAB_180084444:
  if (local_20 != '\0')
  {
    *(uint *)(local_38 + 0x3a8) = *(uint *)(local_38 + 0x3a8) & 0xfffffffd;
  }
  return (errno_t)uVar3;
}

// Library Function - Single Match
//  __acrt_DownlevelLocaleNameToLCID
//
// Library: Visual Studio 2017 Release

undefined4 __acrt_DownlevelLocaleNameToLCID(longlong param_1)
{
  uint uVar1;

  if (((param_1 != 0) && (uVar1 = FUN_1800844f4(param_1), -1 < (int)uVar1)) && (uVar1 < 0xe4))
  {
    return *(undefined4 *)(&DAT_1800cfa30 + (longlong)(int)uVar1 * 0x10);
  }
  return 0;
}

// Library Function - Single Match
//  __acrt_LCMapStringW
//
// Library: Visual Studio 2017 Release

void __acrt_LCMapStringW(longlong param_1, DWORD param_2, undefined (*param_3)[32], int param_4,
                         LPWSTR param_5, int param_6)
{
  int iVar1;
  ulonglong uVar2;
  int iVar3;

  iVar3 = param_4;
  if (0 < param_4)
  {
    uVar2 = FUN_1800477e4(param_3, (longlong)param_4);
    iVar1 = (int)uVar2;
    iVar3 = iVar1 + 1;
    if (param_4 <= iVar1)
    {
      iVar3 = iVar1;
    }
  }
  __acrt_LCMapStringEx(param_1, param_2, (LPCWSTR)param_3, iVar3, param_5, param_6);
  return;
}

// WARNING: Removing unreachable block (ram,0x00018007a2a3)
// Library Function - Single Match
//  _strnicoll
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int _strnicoll(char *_Str1, char *_Str2, size_t _MaxCount)
{
  int iVar1;
  ulong *puVar2;

  if (DAT_180101d00 != 0)
  {
    iVar1 = _strnicoll_l(_Str1, _Str2, _MaxCount, (_locale_t)0x0);
    return iVar1;
  }
  if (((_Str1 != (char *)0x0) && (_Str2 != (char *)0x0)) && (_MaxCount < 0x80000000))
  {
    iVar1 = __ascii_strnicmp(_Str1, _Str2, _MaxCount);
    return iVar1;
  }
  puVar2 = __doserrno();
  *puVar2 = 0x16;
  FUN_18006738c();
  return 0x7fffffff;
}

// Library Function - Single Match
//  _strnicoll_l
//
// Library: Visual Studio 2017 Release

int _strnicoll_l(char *_Str1, char *_Str2, size_t _MaxCount, _locale_t _Locale)
{
  int iVar1;
  int iVar2;
  ulong *puVar3;
  __acrt_ptd *local_28;
  localeinfo_struct local_20;
  char local_10;

  FUN_18004e538(&local_28, (undefined4 *)_Locale);
  if (_MaxCount == 0)
  {
    iVar1 = 0;
  }
  else
  {
    if ((_Str1 == (char *)0x0) || (_Str2 == (char *)0x0))
    {
      puVar3 = __doserrno();
      *puVar3 = 0x16;
      FUN_18006738c();
      iVar1 = 0x7fffffff;
    }
    else
    {
      iVar1 = 0x7fffffff;
      if (_MaxCount < 0x80000000)
      {
        if ((local_20.locinfo)->locale_name[1] == (wchar_t *)0x0)
        {
          iVar1 = _strnicmp_l(_Str1, _Str2, _MaxCount, (_locale_t)&local_20);
        }
        else
        {
          iVar2 = __acrt_CompareStringA((undefined4 *)&local_20, (longlong)(local_20.locinfo)->locale_name[1],
                                        0x1001, (byte *)_Str1, (int)_MaxCount, (byte *)_Str2, (int)_MaxCount,
                                        *(UINT *)((longlong) & (local_20.locinfo)->lc_category[0].locale + 4));
          if (iVar2 == 0)
          {
            puVar3 = __doserrno();
            *puVar3 = 0x16;
          }
          else
          {
            iVar1 = iVar2 + -2;
          }
        }
      }
      else
      {
        puVar3 = __doserrno();
        *puVar3 = 0x16;
        FUN_18006738c();
      }
    }
  }
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return iVar1;
}

SIZE_T _msize_base(LPCVOID param_1)
{
  ulong *puVar1;
  SIZE_T SVar2;

  if (param_1 == (LPCVOID)0x0)
  {
    puVar1 = __doserrno();
    *puVar1 = 0x16;
    FUN_18006738c();
    return 0xffffffffffffffff;
  }
  // WARNING: Could not recover jumptable at 0x0001800854aa. Too many branches
  // WARNING: Treating indirect jump as call
  SVar2 = HeapSize(DAT_180102658, 0, param_1);
  return SVar2;
}

// Library Function - Single Match
//  _msize_base
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

SIZE_T _msize_base(LPCVOID param_1)
{
  ulong *puVar1;
  SIZE_T SVar2;

  if (param_1 == (LPCVOID)0x0)
  {
    puVar1 = __doserrno();
    *puVar1 = 0x16;
    FUN_18006738c();
    return 0xffffffffffffffff;
  }
  // WARNING: Could not recover jumptable at 0x0001800854aa. Too many branches
  // WARNING: Treating indirect jump as call
  SVar2 = HeapSize(DAT_180102658, 0, param_1);
  return SVar2;
}

// Library Function - Single Match
//  _realloc_base
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

LPVOID _realloc_base(LPVOID param_1, ulonglong param_2)
{
  int iVar1;
  LPVOID pvVar2;
  ulong *puVar3;

  if (param_1 == (LPVOID)0x0)
  {
    pvVar2 = _malloc_base(param_2);
  }
  else
  {
    if (param_2 == 0)
    {
      _free_base(param_1);
    }
    else
    {
      if (param_2 < 0xffffffffffffffe1)
      {
        do
        {
          pvVar2 = HeapReAlloc(DAT_180102658, 0, param_1, param_2);
          if (pvVar2 != (LPVOID)0x0)
          {
            return pvVar2;
          }
          iVar1 = FUN_180079e3c();
        } while ((iVar1 != 0) && (iVar1 = _callnewh(param_2), iVar1 != 0));
      }
      puVar3 = __doserrno();
      *puVar3 = 0xc;
    }
    pvVar2 = (LPVOID)0x0;
  }
  return pvVar2;
}

BOOL GetStringTypeW(DWORD dwInfoType, LPCWSTR lpSrcStr, int cchSrc, LPWORD lpCharType)
{
  BOOL BVar1;

  // WARNING: Could not recover jumptable at 0x000180085530. Too many branches
  // WARNING: Treating indirect jump as call
  BVar1 = GetStringTypeW(dwInfoType, lpSrcStr, cchSrc, lpCharType);
  return BVar1;
}

// Library Function - Single Match
//  _setmode_nolock
//
// Library: Visual Studio 2015 Release

int _setmode_nolock(int _FileHandle, int _Mode)
{
  char cVar1;
  byte bVar2;
  longlong lVar3;
  int iVar4;
  longlong lVar5;
  longlong lVar6;

  lVar6 = (longlong)_FileHandle >> 6;
  lVar5 = (ulonglong)(_FileHandle & 0x3f) * 0x40;
  lVar3 = *(longlong *)((longlong)&DAT_180101d10 + lVar6 * 8);
  bVar2 = *(byte *)(lVar3 + 0x38 + lVar5);
  cVar1 = *(char *)(lVar3 + 0x39 + lVar5);
  if (_Mode == 0x4000)
  {
    *(byte *)(lVar3 + 0x38 + lVar5) = bVar2 | 0x80;
    *(undefined *)(*(longlong *)((longlong)&DAT_180101d10 + lVar6 * 8) + 0x39 + lVar5) = 0;
  }
  else
  {
    if (_Mode == 0x8000)
    {
      *(byte *)(lVar3 + 0x38 + lVar5) = bVar2 & 0x7f;
    }
    else
    {
      if ((_Mode - 0x10000U & 0xfffeffff) == 0)
      {
        *(byte *)(lVar3 + 0x38 + lVar5) = bVar2 | 0x80;
        *(undefined *)(*(longlong *)((longlong)&DAT_180101d10 + lVar6 * 8) + 0x39 + lVar5) = 2;
      }
      else
      {
        if (_Mode == 0x40000)
        {
          *(byte *)(lVar3 + 0x38 + lVar5) = bVar2 | 0x80;
          *(undefined *)(*(longlong *)((longlong)&DAT_180101d10 + lVar6 * 8) + 0x39 + lVar5) = 1;
        }
      }
    }
  }
  if ((bVar2 & 0x80) == 0)
  {
    iVar4 = 0x8000;
  }
  else
  {
    if (cVar1 == '\0')
    {
      iVar4 = 0x4000;
    }
    else
    {
      iVar4 = 0x10000;
      if (cVar1 == '\x01')
      {
        iVar4 = 0x40000;
      }
    }
  }
  return iVar4;
}

// Library Function - Single Match
//  public: int __cdecl __crt_seh_guarded_call<int>::operator()<class
// <lambda_702c71755a341b84ce26a812eea27a9e>,class <lambda_1cffa78e445b1da5fba1a2e0e533226f>&
// __ptr64,class <lambda_77b15b24eaa4cf6d702b2f4e7ca8df95>>(class
// <lambda_702c71755a341b84ce26a812eea27a9e>&& __ptr64,class
// <lambda_1cffa78e445b1da5fba1a2e0e533226f>& __ptr64,class
// <lambda_77b15b24eaa4cf6d702b2f4e7ca8df95>&& __ptr64) __ptr64
//
// Library: Visual Studio 2015 Release

int __thiscall __crt_seh_guarded_call<int>::

    operator___class__lambda_702c71755a341b84ce26a812eea27a9e__class__lambda_1cffa78e445b1da5fba1a2e0e533226f_____ptr64_class__lambda_77b15b24eaa4cf6d702b2f4e7ca8df95___(__crt_seh_guarded_call_int_ *this, _lambda_702c71755a341b84ce26a812eea27a9e_ *param_1,
                                                                                                                                                                          _lambda_1cffa78e445b1da5fba1a2e0e533226f_ *param_2,
                                                                                                                                                                          _lambda_77b15b24eaa4cf6d702b2f4e7ca8df95_ *param_3)
{
  uint _FileHandle;
  int iVar1;
  ulong *puVar2;

  FID_conflict___acrt_lowio_lock_fh(*(uint *)param_1);
  _FileHandle = **(uint **)param_2;
  if ((*(byte *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)(int)_FileHandle >> 6) * 8) +
                 0x38 + (ulonglong)(_FileHandle & 0x3f) * 0x40) &
       1) == 0)
  {
    puVar2 = __doserrno();
    iVar1 = 9;
    *puVar2 = 9;
  }
  else
  {
    iVar1 = _chsize_nolock(_FileHandle, **(longlong **)(param_2 + 8));
  }
  FID_conflict___acrt_lowio_lock_fh(*(uint *)param_3);
  return iVar1;
}

// Library Function - Single Match
//  _chsize_nolock
//
// Library: Visual Studio 2015 Release

int _chsize_nolock(int _FileHandle, longlong _Size)
{
  ulong uVar1;
  int _Mode;
  int iVar2;
  BOOL BVar3;
  DWORD DVar4;
  __int64 _Var5;
  ulong *puVar6;
  __int64 _Var7;
  WCHAR *pWVar8;
  HANDLE hFile;
  longlong lVar9;
  uint uVar10;

  _Var5 = common_lseek_nolock___int64_(_FileHandle, 0, 1);
  if ((_Var5 == -1) || (_Var7 = common_lseek_nolock___int64_(_FileHandle, 0, 2), _Var7 == -1))
    goto LAB_1800858fd;
  lVar9 = _Size - _Var7;
  if (lVar9 < 1)
  {
    if (lVar9 < 0)
    {
      _Var7 = common_lseek_nolock___int64_(_FileHandle, _Size, 0);
      if (_Var7 == -1)
        goto LAB_1800858fd;
      hFile = (HANDLE)_get_osfhandle(_FileHandle);
      BVar3 = SetEndOfFile(hFile);
      if (BVar3 == 0)
      {
        puVar6 = __doserrno();
        *puVar6 = 0xd;
        puVar6 = __doserrno();
        DVar4 = GetLastError();
        *puVar6 = DVar4;
        goto LAB_1800858fd;
      }
    }
  }
  else
  {
    pWVar8 = (WCHAR *)_calloc_base(0x1000, 1);
    if (pWVar8 == (WCHAR *)0x0)
    {
      puVar6 = __doserrno();
      *puVar6 = 0xc;
    LAB_1800859dd:
      puVar6 = __doserrno();
      uVar1 = *puVar6;
      _free_base(pWVar8);
      return uVar1;
    }
    _Mode = _setmode_nolock(_FileHandle, 0x8000);
    do
    {
      uVar10 = (uint)lVar9;
      if (0xfff < lVar9)
      {
        uVar10 = 0x1000;
      }
      iVar2 = FUN_18006f9e4(_FileHandle, pWVar8, uVar10);
      if (iVar2 == -1)
      {
        puVar6 = __doserrno();
        if (*puVar6 == 5)
        {
          puVar6 = __doserrno();
          *puVar6 = 0xd;
        }
        goto LAB_1800859dd;
      }
      lVar9 = lVar9 - iVar2;
    } while (0 < lVar9);
    _setmode_nolock(_FileHandle, _Mode);
    _free_base(pWVar8);
  }
  _Var5 = common_lseek_nolock___int64_(_FileHandle, _Var5, 0);
  if (_Var5 != -1)
  {
    return 0;
  }
LAB_1800858fd:
  puVar6 = __doserrno();
  return (int)*puVar6;
}

// Library Function - Single Match
//  _chsize_s
//
// Library: Visual Studio 2015 Release

errno_t _chsize_s(int _FileHandle, longlong _Size)
{
  int iVar1;
  ulong uVar2;
  ulong *puVar3;
  int local_res8[2];
  longlong local_res10;
  __crt_seh_guarded_call_int_ local_res18[8];
  int local_res20[2];
  int local_38[2];
  int *local_30;
  longlong *local_28;

  local_res8[0] = _FileHandle;
  local_res10 = _Size;
  if (_FileHandle == -2)
  {
    puVar3 = __doserrno();
    *puVar3 = 0;
    uVar2 = 9;
  }
  else
  {
    if (((_FileHandle < 0) || (DAT_180102110 <= (uint)_FileHandle)) ||
        ((*(byte *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)_FileHandle >> 6) * 8) + 0x38 + (ulonglong)(_FileHandle & 0x3f) * 0x40) & 1) == 0))
    {
      puVar3 = __doserrno();
      *puVar3 = 0;
      puVar3 = __doserrno();
      uVar2 = 9;
    }
    else
    {
      if (-1 < _Size)
      {
        local_30 = local_res8;
        local_28 = &local_res10;
        local_res20[0] = _FileHandle;
        local_38[0] = _FileHandle;
        iVar1 = __crt_seh_guarded_call<int>::

            operator___class__lambda_702c71755a341b84ce26a812eea27a9e__class__lambda_1cffa78e445b1da5fba1a2e0e533226f_____ptr64_class__lambda_77b15b24eaa4cf6d702b2f4e7ca8df95___(local_res18, (_lambda_702c71755a341b84ce26a812eea27a9e_ *)local_38,
                                                                                                                                                                                  (_lambda_1cffa78e445b1da5fba1a2e0e533226f_ *)&local_30,
                                                                                                                                                                                  (_lambda_77b15b24eaa4cf6d702b2f4e7ca8df95_ *)local_res20);
        return iVar1;
      }
      puVar3 = __doserrno();
      *puVar3 = 0;
      puVar3 = __doserrno();
      uVar2 = 0x16;
    }
    *puVar3 = uVar2;
    FUN_18006738c();
  }
  return (errno_t)uVar2;
}

// Library Function - Single Match
//  __strncnt
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

size_t __strncnt(char *_String, size_t _Cnt)
{
  char cVar1;
  size_t sVar2;

  sVar2 = 0;
  cVar1 = *_String;
  while ((cVar1 != '\0' && (sVar2 != _Cnt)))
  {
    sVar2 = sVar2 + 1;
    cVar1 = _String[sVar2];
  }
  return sVar2;
}

// WARNING: Could not reconcile some variable overlaps
// Library Function - Single Match
//  __acrt_GetLocaleInfoA
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_GetLocaleInfoA(undefined4 *param_1, int param_2, longlong param_3, LCTYPE param_4, LPWSTR *param_5)
{
  code *pcVar1;
  int iVar2;
  ulong uVar3;
  DWORD DVar4;
  LPWSTR pWVar5;
  undefined4 local_d8[4];
  undefined local_c8[128];
  ulonglong local_48;

  local_48 = DAT_1800ee160 ^ (ulonglong)&stack0xfffffffffffffef8;
  *param_5 = (LPWSTR)0x0;
  if (param_2 == 1)
  {
    iVar2 = FUN_180085b78(param_1, param_3, param_4, (ulonglong)local_c8, 0x80);
    if (iVar2 != 0)
    {
      pWVar5 = (LPWSTR)_calloc_base((longlong)iVar2, 1);
      *param_5 = pWVar5;
      _free_base((LPVOID)0x0);
      if ((*param_5 != (LPWSTR)0x0) &&
          (uVar3 = FUN_180084088((char *)*param_5, (longlong)iVar2, (longlong)local_c8,
                                 (longlong)(iVar2 + -1)),
           uVar3 != 0))
      {
        _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
        pcVar1 = (code *)swi(3);
        (*pcVar1)();
        return;
      }
      goto LAB_180085e85;
    }
    DVar4 = GetLastError();
    if (DVar4 != 0x7a)
      goto LAB_180085e85;
    iVar2 = FUN_180085b78(param_1, param_3, param_4, 0, 0);
    if (iVar2 == 0)
      goto LAB_180085e85;
    pWVar5 = (LPWSTR)_calloc_base((longlong)iVar2, 1);
    if (pWVar5 != (LPWSTR)0x0)
    {
      iVar2 = FUN_180085b78(param_1, param_3, param_4, (ulonglong)pWVar5, iVar2);
      goto LAB_180085df3;
    }
  }
  else
  {
    if (param_2 != 2)
    {
      if (param_2 == 0)
      {
        local_d8[0] = 0;
        iVar2 = __acrt_GetLocaleInfoEx(param_3, param_4 | 0x20000000, (LPWSTR)local_d8, 2);
        if (iVar2 != 0)
        {
          *(undefined *)param_5 = (undefined)local_d8[0];
        }
      }
      goto LAB_180085e85;
    }
    iVar2 = __acrt_GetLocaleInfoEx(param_3, param_4, (LPWSTR)0x0, 0);
    if (iVar2 == 0)
      goto LAB_180085e85;
    pWVar5 = (LPWSTR)_calloc_base((longlong)iVar2, 2);
    if (pWVar5 != (LPWSTR)0x0)
    {
      iVar2 = __acrt_GetLocaleInfoEx(param_3, param_4, pWVar5, iVar2);
    LAB_180085df3:
      if (iVar2 != 0)
      {
        *param_5 = pWVar5;
        pWVar5 = (LPWSTR)0x0;
      }
    }
  }
  _free_base(pWVar5);
LAB_180085e85:
  FUN_180034d00(local_48 ^ (ulonglong)&stack0xfffffffffffffef8);
  return;
}

// Library Function - Single Match
//  fegetenv
//
// Library: Visual Studio 2015 Release

undefined8 fegetenv(uint *param_1)
{
  uint uVar1;

  uVar1 = FUN_180087d4c();
  *param_1 = uVar1;
  uVar1 = FUN_180087e58();
  param_1[1] = uVar1;
  return 0;
}

// WARNING: Could not reconcile some variable overlaps
// Library Function - Single Match
//  fesetenv
//
// Library: Visual Studio 2017 Release

undefined8 fesetenv(int *param_1)
{
  undefined8 uVar1;
  undefined8 local_res8;

  __acrt_fenv_set_control();
  __acrt_fenv_set_status();
  local_res8 = 0;
  uVar1 = fegetenv((uint *)&local_res8);
  if ((((int)uVar1 == 0) && (*param_1 == (int)local_res8)) && (param_1[1] == local_res8._4_4_))
  {
    uVar1 = 0;
  }
  else
  {
    uVar1 = 1;
  }
  return uVar1;
}

// Library Function - Single Match
//  feholdexcept
//
// Library: Visual Studio 2015 Release

undefined8 feholdexcept(undefined8 *param_1)
{
  undefined8 uVar1;
  uint local_res10;
  undefined4 uStackX20;

  local_res10 = 0;
  uStackX20 = 0;
  uVar1 = fegetenv(&local_res10);
  if ((int)uVar1 == 0)
  {
    uVar1 = CONCAT44(uStackX20, local_res10);
    local_res10 = local_res10 | 0x1f;
    *param_1 = uVar1;
    uVar1 = fesetenv((int *)&local_res10);
    if ((int)uVar1 == 0)
    {
      _clearfp();
      return 0;
    }
  }
  return 1;
}

// WARNING: Removing unreachable block (ram,0x00018008637d)
// WARNING: Removing unreachable block (ram,0x000180086529)
// WARNING: Removing unreachable block (ram,0x00018008639b)
// WARNING: Removing unreachable block (ram,0x0001800863cf)
// WARNING: Removing unreachable block (ram,0x00018008636f)
// WARNING: Removing unreachable block (ram,0x000180086560)
// WARNING: Removing unreachable block (ram,0x000180086562)
// WARNING: Removing unreachable block (ram,0x000180086480)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  log10
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

double log10(double _X)
{
  ulonglong uVar1;
  ulonglong uVar2;
  undefined8 in_RCX;
  undefined8 in_RDX;
  double dVar3;
  undefined auVar4[16];
  undefined in_register_00001208[24];
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined auVar9[16];
  undefined4 in_XMM6_Da;
  undefined4 in_XMM6_Db;
  double dVar10;
  undefined4 in_XMM6_Dc;
  undefined4 in_XMM6_Dd;

  auVar4 = SUB3216(CONCAT248(in_register_00001208, _X), 0);
  if (_DAT_180102ce0 != 0)
  {
    auVar9 = vpsrlq_avx(auVar4, 0x34);
    uVar1 = vmovq_avx(auVar4);
    auVar9 = vpsubq_avx(auVar9, _DAT_1800d0af0);
    vcvtdq2pd_avx(auVar9);
    vpand_avx(auVar4, _DAT_1800d0ac0);
    vcomisd_avx(ZEXT816(0x7ff0000000000000));
    if (uVar1 != 0x7ff0000000000000)
    {
      if (uVar1 == 0xfff0000000000000)
      {
        _log10_special(_X, 0xfff8000000000000, in_RCX, in_RDX, 2);
        vmovdqa_avx(CONCAT412(in_XMM6_Dd, CONCAT48(in_XMM6_Dc, CONCAT44(in_XMM6_Db, in_XMM6_Da))));
        return _X;
      }
      _log10_special(_X, uVar1 | 0x8000000000000, in_RCX, in_RDX, 3);
    }
    vmovdqa_avx(CONCAT412(in_XMM6_Dd, CONCAT48(in_XMM6_Dc, CONCAT44(in_XMM6_Db, in_XMM6_Da))));
    return _X;
  }
  if ((double)((ulonglong)_X & 0x7ff0000000000000) == INFINITY)
  {
    if (_X == INFINITY)
    {
      return INFINITY;
    }
    if (_X != -INFINITY)
    {
      return (double)((ulonglong)_X | 0x8000000000000);
    }
  }
  else
  {
    dVar10 = (double)((uint)((ulonglong)_X >> 0x34) - 0x3ff);
    if (0.0 < _X)
    {
      dVar3 = _X;
      dVar5 = (double)((ulonglong)_X & 0xfffffffffffff);
      if (dVar10 == -1023.0)
      {
        dVar10 = (double)((ulonglong)_X & 0xfffffffffffff | SUB168(_DAT_1800d0ba0, 0)) - 1.0;
        dVar3 = (double)((ulonglong)dVar10 & SUB168(_DAT_1800d0b10, 0));
        dVar10 = (double)((uint)((ulonglong)dVar10 >> 0x34) - 0x7fd);
        dVar5 = dVar3;
      }
      uVar1 = ((ulonglong)dVar3 & 0xff00000000000) + ((ulonglong)dVar3 & 0x80000000000) * 2;
      if (0.0625 <= (double)((ulonglong)(_X - 1.0) & 0x7fffffffffffffff))
      {
        uVar2 = uVar1 >> 0x2c;
        dVar5 = ((double)(uVar1 | SUB168(_DAT_1800d0bb0, 0)) -
                 (double)((ulonglong)dVar5 | SUB168(_DAT_1800d0bb0, 0))) *
                *(double *)(&DAT_1800d1e00 + uVar2 * 8);
        dVar3 = dVar5 * dVar5;
        return *(double *)(&DAT_1800d0de0 + uVar2 * 8) + dVar10 * 0.3010299950838089 +
               *(double *)(&DAT_1800d15f0 + uVar2 * 8) +
               (dVar10 * 5.801722962879576e-10 -
                ((dVar5 * 0.3333333333333333 + 0.5) * dVar3 + dVar5 +
                 ((dVar5 * 0.1666666666666667 + 0.2) * dVar5 + 0.25) * dVar3 * dVar3) *
                    0.4342944819032518);
      }
      dVar10 = _X - 1.0;
      dVar3 = dVar10 / (dVar10 + 2.0);
      dVar5 = dVar3 + dVar3;
      dVar6 = dVar5 * dVar5;
      dVar7 = dVar6 * dVar5;
      dVar8 = (double)((ulonglong)dVar10 & SUB168(_DAT_1800d0ce0, 0));
      dVar10 = (((dVar6 * 0.01250000000377175 + 0.08333333333333179) * dVar7 +
                 (dVar6 * 0.0004348877777076146 + 0.002232139987919448) * dVar7 * dVar7 * dVar5) -
                dVar10 * dVar3) +
               (dVar10 - dVar8);
      return dVar8 * 7.349550096401511e-07 + dVar10 * 7.349550096401511e-07 +
             dVar10 * 0.4342937469482422 + dVar8 * 0.4342937469482422;
    }
    if (_X == 0.0)
    {
      _log10_special(_X, 0xfff0000000000000, in_RCX, in_RDX, 1);
      return _X;
    }
  }
  _log10_special(_X, 0xfff8000000000000, in_RCX, in_RDX, 2);
  // WARNING: Read-only address (ram,0x0001800d0ac0) is written
  // WARNING: Read-only address (ram,0x0001800d0af0) is written
  // WARNING: Read-only address (ram,0x0001800d0b10) is written
  // WARNING: Read-only address (ram,0x0001800d0ba0) is written
  // WARNING: Read-only address (ram,0x0001800d0bb0) is written
  // WARNING: Read-only address (ram,0x0001800d0ce0) is written
  return _X;
}

// Library Function - Single Match
//  int __cdecl common_xtox_s<unsigned long,char>(unsigned long,char * __ptr64 const,unsigned
// __int64,unsigned int,bool)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int common_xtox_s_unsigned_long_char_(ulong param_1, char *param_2, __uint64 param_3, uint param_4, bool param_5)
{
  ulong *puVar1;
  undefined8 uVar2;
  ulong uVar3;

  if ((param_2 != (char *)0x0) && (param_3 != 0))
  {
    *param_2 = '\0';
    if (param_3 <= (ulonglong)param_5 + 1)
    {
      puVar1 = __doserrno();
      uVar3 = 0x22;
      goto LAB_180086888;
    }
    if (param_4 - 2 < 0x23)
    {
      uVar2 = FUN_1800865ec((ulonglong)param_1, param_2, param_3, param_4, param_5);
      return (int)uVar2;
    }
  }
  puVar1 = __doserrno();
  uVar3 = 0x16;
LAB_180086888:
  *puVar1 = uVar3;
  FUN_18006738c();
  return (int)uVar3;
}

// Library Function - Single Match
//  int __cdecl common_xtox_s<unsigned long,wchar_t>(unsigned long,wchar_t * __ptr64 const,unsigned
// __int64,unsigned int,bool)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int common_xtox_s_unsigned_long_wchar_t_(ulong param_1, wchar_t *param_2, __uint64 param_3, uint param_4, bool param_5)
{
  ulong *puVar1;
  undefined8 uVar2;
  ulong uVar3;

  if ((param_2 != (wchar_t *)0x0) && (param_3 != 0))
  {
    *(undefined2 *)param_2 = 0;
    if (param_3 <= (ulonglong)param_5 + 1)
    {
      puVar1 = __doserrno();
      uVar3 = 0x22;
      goto LAB_1800868f2;
    }
    if (param_4 - 2 < 0x23)
    {
      uVar2 = FUN_180086680(param_1, (short *)param_2, param_3, param_4, param_5);
      return (int)uVar2;
    }
  }
  puVar1 = __doserrno();
  uVar3 = 0x16;
LAB_1800868f2:
  *puVar1 = uVar3;
  FUN_18006738c();
  return (int)uVar3;
}

// Library Function - Single Match
//  int __cdecl common_xtox_s<unsigned __int64,char>(unsigned __int64,char * __ptr64 const,unsigned
// __int64,unsigned int,bool)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int common_xtox_s_unsigned___int64_char_(__uint64 param_1, char *param_2, __uint64 param_3, uint param_4, bool param_5)
{
  ulong *puVar1;
  undefined8 uVar2;
  ulong uVar3;

  if ((param_2 != (char *)0x0) && (param_3 != 0))
  {
    *param_2 = '\0';
    if (param_3 <= (ulonglong)param_5 + 1)
    {
      puVar1 = __doserrno();
      uVar3 = 0x22;
      goto LAB_18008695c;
    }
    if (param_4 - 2 < 0x23)
    {
      uVar2 = FUN_180086728(param_1, param_2, param_3, param_4, param_5);
      return (int)uVar2;
    }
  }
  puVar1 = __doserrno();
  uVar3 = 0x16;
LAB_18008695c:
  *puVar1 = uVar3;
  FUN_18006738c();
  return (int)uVar3;
}

// Library Function - Single Match
//  int __cdecl common_xtox_s<unsigned __int64,wchar_t>(unsigned __int64,wchar_t * __ptr64
// const,unsigned __int64,unsigned int,bool)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int common_xtox_s_unsigned___int64_wchar_t_(__uint64 param_1, wchar_t *param_2, __uint64 param_3, uint param_4, bool param_5)
{
  ulong *puVar1;
  undefined8 uVar2;
  ulong uVar3;

  if ((param_2 != (wchar_t *)0x0) && (param_3 != 0))
  {
    *(undefined2 *)param_2 = 0;
    if (param_3 <= (ulonglong)param_5 + 1)
    {
      puVar1 = __doserrno();
      uVar3 = 0x22;
      goto LAB_1800869c6;
    }
    if (param_4 - 2 < 0x23)
    {
      uVar2 = FUN_1800867c0(param_1, (short *)param_2, param_3, param_4, param_5);
      return (int)uVar2;
    }
  }
  puVar1 = __doserrno();
  uVar3 = 0x16;
LAB_1800869c6:
  *puVar1 = uVar3;
  FUN_18006738c();
  return (int)uVar3;
}

// Library Function - Single Match
//  _i64toa_s
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t _i64toa_s(longlong _Val, char *_DstBuf, size_t _Size, int _Radix)
{
  bool bVar1;
  int iVar2;

  bVar1 = false;
  if ((_Radix == 10) && (_Val < 0))
  {
    bVar1 = true;
  }
  iVar2 = common_xtox_s_unsigned___int64_char_(_Val, _DstBuf, _Size, _Radix, bVar1);
  return (errno_t)iVar2;
}

// Library Function - Single Match
//  _i64tow_s
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t _i64tow_s(longlong _Val, wchar_t *_DstBuf, size_t _SizeInWords, int _Radix)
{
  bool bVar1;
  int iVar2;

  bVar1 = false;
  if ((_Radix == 10) && (_Val < 0))
  {
    bVar1 = true;
  }
  iVar2 = common_xtox_s_unsigned___int64_wchar_t_(_Val, (wchar_t *)_DstBuf, _SizeInWords, _Radix, bVar1);
  return (errno_t)iVar2;
}

// Library Function - Multiple Matches With Different Base Names
//  _itow_s
//  _ltow_s
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t FID_conflict__ltow_s(long _Val, wchar_t *_DstBuf, size_t _SizeInWords, int _Radix)
{
  bool bVar1;
  int iVar2;

  bVar1 = false;
  if ((_Radix == 10) && (_Val < 0))
  {
    bVar1 = true;
  }
  iVar2 = common_xtox_s_unsigned_long_wchar_t_(_Val, (wchar_t *)_DstBuf, _SizeInWords, _Radix, bVar1);
  return (errno_t)iVar2;
}

// Library Function - Single Match
//  __dcrt_lowio_ensure_console_output_initialized
//
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

bool __dcrt_lowio_ensure_console_output_initialized(void)
{
  if (DAT_1800eef20 == (HANDLE)0xfffffffffffffffe)
  {
    DAT_1800eef20 = CreateFileW(L"CONOUT$", 0x40000000, 3, (LPSECURITY_ATTRIBUTES)0x0, 3, 0, (HANDLE)0x0);
  }
  return DAT_1800eef20 != (HANDLE)0xffffffffffffffff;
}

// Library Function - Single Match
//  __dcrt_write_console
//
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

BOOL __dcrt_write_console(void *param_1, DWORD param_2, LPDWORD param_3)
{
  BOOL BVar1;
  DWORD DVar2;

  BVar1 = WriteConsoleW(DAT_1800eef20, param_1, param_2, param_3, (LPVOID)0x0);
  if (BVar1 == 0)
  {
    DVar2 = GetLastError();
    if (DVar2 == 6)
    {
      if (DAT_1800eef20 < (HANDLE)0xfffffffffffffffe)
      {
        CloseHandle(DAT_1800eef20);
      }
      DAT_1800eef20 =
          CreateFileW(L"CONOUT$", 0x40000000, 3, (LPSECURITY_ATTRIBUTES)0x0, 3, 0, (HANDLE)0x0);
      BVar1 = WriteConsoleW(DAT_1800eef20, param_1, param_2, param_3, (LPVOID)0x0);
    }
  }
  return BVar1;
}

// Library Function - Single Match
//  __acrt_CompareStringW
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

ulonglong __acrt_CompareStringW(longlong param_1, DWORD param_2, undefined (*param_3)[32], int param_4,
                                undefined (*param_5)[32], int param_6)
{
  ulonglong uVar1;

  if (0 < param_4)
  {
    uVar1 = FUN_1800477e4(param_3, (longlong)param_4);
    param_4 = (int)uVar1;
  }
  if (0 < param_6)
  {
    uVar1 = FUN_1800477e4(param_5, (longlong)param_6);
    param_6 = (int)uVar1;
  }
  if ((param_4 == 0) || (param_6 == 0))
  {
    uVar1 = (ulonglong)((param_4 - param_6 >> 0x1f & 0xfffffffeU) + 3);
    if (param_4 - param_6 == 0)
    {
      uVar1 = 2;
    }
  }
  else
  {
    uVar1 = __acrt_CompareStringEx(param_1, param_2, (PCNZWCH)param_3, param_4, (PCNZWCH)param_5, param_6);
  }
  return uVar1;
}

// Library Function - Single Match
//  __acrt_CompareStringA
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __acrt_CompareStringA(undefined4 *param_1, longlong param_2, DWORD param_3, byte *param_4, int param_5,
                           byte *param_6, int param_7, UINT param_8)
{
  __acrt_ptd *local_28;
  longlong local_20[2];
  char local_10;

  FUN_18004e538(&local_28, param_1);
  FUN_18008729c(local_20, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
  if (local_10 != '\0')
  {
    *(uint *)(local_28 + 0x3a8) = *(uint *)(local_28 + 0x3a8) & 0xfffffffd;
  }
  return;
}

// Library Function - Single Match
//  __acrt_fenv_set_control
//
// Library: Visual Studio 2017 Release

void __acrt_fenv_set_control(void)
{
  return;
}

// Library Function - Single Match
//  __acrt_fenv_set_status
//
// Library: Visual Studio 2017 Release

void __acrt_fenv_set_status(void)
{
  return;
}

// Library Function - Single Match
//  _clearfp
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

uint _clearfp(void)
{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;

  uVar1 = _get_fpsr();
  _fclrf();
  uVar4 = 0;
  if ((uVar1 & 0x3f) != 0)
  {
    uVar2 = (uVar1 & 1) << 4;
    uVar4 = uVar2 | 8;
    if ((uVar1 & 4) == 0)
    {
      uVar4 = uVar2;
    }
    uVar2 = uVar4 | 4;
    if ((uVar1 & 8) == 0)
    {
      uVar2 = uVar4;
    }
    uVar3 = uVar2 | 2;
    if ((uVar1 & 0x10) == 0)
    {
      uVar3 = uVar2;
    }
    uVar4 = uVar3 | 1;
    if ((uVar1 & 0x20) == 0)
    {
      uVar4 = uVar3;
    }
    if ((uVar1 & 2) != 0)
    {
      uVar4 = uVar4 | 0x80000;
    }
  }
  return uVar4;
}

// Library Function - Single Match
//  _call_matherr
//
// Library: Visual Studio 2019 Release

undefined8
_call_matherr(int param_1, undefined param_2, undefined param_3, undefined param_4, undefined8 param_5,
              undefined8 param_6, undefined8 param_7)
{
  undefined8 uVar1;

  _ctrlfp((uint)param_7, 0xffc0);
  uVar1 = __acrt_invoke_user_matherr();
  if ((int)uVar1 == 0)
  {
    uVar1 = _set_errno_from_matherr(param_1);
  }
  return uVar1;
}

// Library Function - Single Match
//  _exception_enabled
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool _exception_enabled(uint param_1, ulonglong param_2)
{
  uint uVar1;

  uVar1 = param_1 & 0x1f;
  if (((param_1 & 8) == 0) || (-1 < (char)param_2))
  {
    if (((param_1 & 4) == 0) || ((param_2 >> 9 & 1) == 0))
    {
      if (((param_1 & 1) == 0) || ((param_2 >> 10 & 1) == 0))
      {
        if (((param_1 & 2) != 0) && ((param_2 >> 0xb & 1) != 0))
        {
          if ((param_1 & 0x10) != 0)
          {
            _set_statfp();
          }
          uVar1 = param_1 & 0x1d;
        }
      }
      else
      {
        _set_statfp();
        uVar1 = param_1 & 0x1e;
      }
    }
    else
    {
      _set_statfp();
      uVar1 = param_1 & 0x1b;
    }
  }
  else
  {
    _set_statfp();
    uVar1 = param_1 & 0x17;
  }
  if (((param_1 & 0x10) != 0) && ((param_2 >> 0xc & 1) != 0))
  {
    _set_statfp();
    uVar1 = uVar1 & 0xffffffef;
  }
  return uVar1 == 0;
}

// Library Function - Single Match
//  _handle_error
//
// Library: Visual Studio 2019 Release

void _handle_error(undefined8 param_1, uint param_2, undefined8 param_3, int param_4, uint param_5,
                   undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9)
{
  bool bVar1;
  uint uVar2;
  undefined4 extraout_var_00;
  undefined7 extraout_var;
  undefined uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  ulonglong local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  uint local_b8[12];
  undefined8 local_88;
  uint local_78;
  ulonglong local_48;

  uVar3 = (undefined)param_4;
  local_48 = DAT_1800ee160 ^ (ulonglong)&stack0xfffffffffffffee8;
  uVar2 = _ctrlfp(0x1f80, 0xffc0);
  local_d8 = CONCAT44(extraout_var_00, uVar2);
  local_d0 = param_3;
  local_c8 = param_3;
  bVar1 = _exception_enabled(param_5, local_d8);
  uVar4 = (undefined4)param_8;
  uVar5 = (undefined4)((ulonglong)param_8 >> 0x20);
  if ((int)CONCAT71(extraout_var, bVar1) == 0)
  {
    if (param_9 == 2)
    {
      local_88 = param_8;
      local_78 = local_78 & 0xffffffe3 | 3;
    }
    uVar3 = (undefined)param_2;
    _raise_exc(local_b8, &local_d8, (ulonglong)param_5, param_2, &param_7, &local_d0);
  }
  bVar1 = __acrt_has_user_matherr();
  if ((bVar1 == false) || (param_4 == 0))
  {
    _set_errno_from_matherr(param_4);
    _ctrlfp((uint)local_d8, 0xffc0);
  }
  else
  {
    _call_matherr(param_4, (undefined)param_6, (undefined)param_1, uVar3, CONCAT44(uVar5, uVar4), local_d0, local_d8);
  }
  FUN_180034d00(local_48 ^ (ulonglong)&stack0xfffffffffffffee8);
  return;
}

// WARNING: Removing unreachable block (ram,0x000180088a19)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __acrt_initialize_fma3
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined8 __acrt_initialize_fma3(void)
{
  longlong lVar1;
  byte in_XCR0;

  DAT_180102cdc = 0;
  lVar1 = cpuid_Version_info(1);
  if ((*(uint *)(lVar1 + 0xc) & 0x18001000) == 0x18001000)
  {
    DAT_180102cdc = (uint)((in_XCR0 & 6) == 6);
  }
  _DAT_180102ce0 = DAT_180102cdc;
  return 0;
}

// Library Function - Single Match
//  _log10_special
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void _log10_special(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                    int param_5)
{
  undefined in_stack_00000000;
  undefined in_stack_00000008;
  undefined in_stack_00000010;
  undefined in_stack_fffffffffffffff8;

  _log_special_common(param_1, param_2, param_3, param_4, param_5, 0x1b, in_stack_fffffffffffffff8,
                      in_stack_00000000, in_stack_00000008, in_stack_00000010, "log10");
  return;
}

// Library Function - Single Match
//  _log_special_common
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined *
_log_special_common(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                    int param_5, uint param_6, undefined param_7, undefined param_8, undefined param_9,
                    undefined param_10, undefined8 param_11)
{
  undefined *puVar1;
  int iVar2;
  undefined8 local_res10;
  uint uVar3;
  undefined4 uVar4;
  undefined4 in_stack_ffffffffffffffc4;
  int iVar5;

  iVar2 = param_5 + -1;
  if (iVar2 == 0)
  {
    iVar5 = 1;
    iVar2 = 2;
    uVar4 = 0x22;
    uVar3 = 4;
  }
  else
  {
    if (iVar2 != 1)
    {
      return (undefined *)register0x00000020;
    }
    uVar4 = 0x21;
    uVar3 = 8;
    iVar5 = iVar2;
  }
  local_res10 = param_2;
  puVar1 = (undefined *)
      _handle_error(param_11, param_6, param_2, iVar2, uVar3,
                    CONCAT44(in_stack_ffffffffffffffc4, uVar4), param_1, 0, iVar5);
  return puVar1;
}

// Library Function - Single Match
//  _get_fpsr
//
// Library: Visual Studio 2019 Release

undefined4 _get_fpsr(void)
{
  undefined4 in_MXCSR;

  return in_MXCSR;
}

// Library Function - Single Match
//  _fclrf
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void _fclrf(void)
{
  return;
}

// Library Function - Single Match
//  _errcode
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int _errcode(uint param_1)
{
  int iVar1;

  if ((param_1 & 0x20) == 0)
  {
    if ((param_1 & 8) == 0)
    {
      if ((param_1 & 4) == 0)
      {
        if ((param_1 & 1) == 0)
        {
          iVar1 = (param_1 & 2) * 2;
        }
        else
        {
          iVar1 = 3;
        }
      }
      else
      {
        iVar1 = 2;
      }
    }
    else
    {
      iVar1 = 1;
    }
  }
  else
  {
    iVar1 = 5;
  }
  return iVar1;
}

// Library Function - Single Match
//  _except2
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2019 Release

void _except2(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
              uint param_5, uint param_6, undefined8 param_7, ulonglong param_8, double param_9,
              ulonglong param_10)
{
  bool bVar1;
  int iVar2;
  undefined7 extraout_var;
  ulonglong uVar3;
  ulonglong uVar4;
  undefined8 local_c8[2];
  uint local_b8[12];
  undefined8 local_88;
  uint local_78;
  ulonglong local_48;

  uVar3 = param_10;
  local_48 = DAT_1800ee160 ^ (ulonglong)&stack0xfffffffffffffef8;
  uVar4 = param_10;
  local_c8[0] = param_3;
  bVar1 = FUN_180089254(param_5, &param_9, param_10);
  if ((int)CONCAT71(extraout_var, bVar1) == 0)
  {
    local_78 = local_78 & 0xffffffe3 | 3;
    param_8 = (ulonglong)param_6;
    uVar4 = (ulonglong)param_5;
    local_88 = param_4;
    FUN_1800894ec(local_b8, &param_10, uVar4, param_6, local_c8, &param_9, 0);
    uVar3 = param_10;
  }
  iVar2 = _errcode(param_5);
  bVar1 = __acrt_has_user_matherr();
  if ((bVar1 == false) || (iVar2 == 0))
  {
    _set_errno_from_matherr(iVar2);
    _ctrlfp((uint)uVar3, 0xffc0);
  }
  else
  {
    _umatherr(iVar2, param_6, uVar4, param_8, param_9, (uint)uVar3);
  }
  FUN_180034d00(local_48 ^ (ulonglong)&stack0xfffffffffffffef8);
  return;
}

// Library Function - Single Match
//  _raise_exc
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void _raise_exc(uint *param_1, ulonglong *param_2, ulonglong param_3, uint param_4, undefined8 *param_5,
                undefined8 *param_6)
{
  FUN_1800894ec(param_1, param_2, param_3, param_4, param_5, param_6, 0);
  return;
}

// Library Function - Single Match
//  _set_errno_from_matherr
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void _set_errno_from_matherr(int param_1)
{
  ulong *puVar1;

  if (param_1 == 1)
  {
    puVar1 = __doserrno();
    *puVar1 = 0x21;
  }
  else
  {
    if (param_1 - 2U < 2)
    {
      puVar1 = __doserrno();
      *puVar1 = 0x22;
    }
  }
  return;
}

// Library Function - Single Match
//  _umatherr
//
// Library: Visual Studio 2019 Release

undefined8
_umatherr(int param_1, int param_2, undefined8 param_3, undefined8 param_4, undefined8 param_5,
          uint param_6)
{
  int *piVar1;
  undefined *puVar2;
  undefined8 uVar3;
  int iVar4;

  piVar1 = &DAT_1800d2640;
  iVar4 = 0;
  do
  {
    if (*piVar1 == param_2)
    {
      puVar2 = (&PTR_DAT_1800d2648)[(longlong)iVar4 * 2];
      goto LAB_180089896;
    }
    iVar4 = iVar4 + 1;
    piVar1 = piVar1 + 4;
  } while ((longlong)piVar1 < 0x1800d2810);
  puVar2 = (undefined *)0x0;
LAB_180089896:
  if (puVar2 == (undefined *)0x0)
  {
    _ctrlfp(param_6, 0xffc0);
    uVar3 = _set_errno_from_matherr(param_1);
  }
  else
  {
    _ctrlfp(param_6, 0xffc0);
    uVar3 = __acrt_invoke_user_matherr();
    if ((int)uVar3 == 0)
    {
      uVar3 = _set_errno_from_matherr(param_1);
    }
  }
  return uVar3;
}

// Library Function - Single Match
//  _clrfp
//
// Library: Visual Studio

uint _clrfp(void)
{
  uint uVar1;

  uVar1 = _get_fpsr();
  _fclrf();
  return uVar1 & 0x3f;
}

// Library Function - Single Match
//  _ctrlfp
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2019 Release

uint _ctrlfp(uint param_1, uint param_2)
{
  uint uVar1;

  uVar1 = _get_fpsr();
  if ((DAT_1800eef30 == '\0') ||
      ((((~param_2 | 0xffff807f) & uVar1 | param_1 & param_2) & 0x40) == 0))
  {
    FUN_180088fa0();
  }
  else
  {
    FUN_180088fa0();
  }
  return uVar1;
}

// Library Function - Single Match
//  _set_statfp
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void _set_statfp(void)
{
  _get_fpsr();
  FUN_180088fa0();
  return;
}

// WARNING: Could not reconcile some variable overlaps
// Library Function - Single Match
//  _decomp
//
// Library: Visual Studio 2019 Release

double _decomp(double param_1, undefined8 param_2, int *param_3)
{
  bool bVar1;
  int iVar2;
  double dVar3;
  uint uVar4;
  int iVar5;
  double local_res8;
  double local_res10;

  local_res8 = 0.0;
  if (param_1 == 0.0)
  {
    iVar5 = 0;
  }
  else
  {
    if ((((ulonglong)param_1 & 0x7ff0000000000000) == 0) &&
        ((local_res8._0_4_ = SUB84(param_1, 0), ((ulonglong)param_1 >> 0x20 & 0xfffff) != 0 ||
                                                    (local_res8._0_4_ != 0))))
    {
      iVar5 = -0x3fd;
      bVar1 = param_1 < 0.0;
      local_res8 = param_1;
      if (((ulonglong)param_1 >> 0x30 & 0x10) == 0)
      {
        do
        {
          uVar4 = (int)((ulonglong)param_1 >> 0x20) * 2;
          if (SUB84(param_1, 0) < 0)
          {
            uVar4 = uVar4 | 1;
          }
          iVar2 = SUB84(param_1, 0) * 2;
          param_1 = (double)CONCAT44(uVar4, iVar2);
          iVar5 = iVar5 + -1;
        } while ((uVar4 & 0x100000) == 0);
        local_res8 = (double)CONCAT44(uVar4, iVar2);
      }
      dVar3 = local_res8;
      local_res8 = (double)((ulonglong)local_res8 & 0xffefffffffffffff);
      if (bVar1)
      {
        local_res8 = (double)((ulonglong)dVar3 & 0xffefffffffffffff | 0x8000000000000000);
      }
      local_res8 = (double)((ulonglong)local_res8 & 0xbfefffffffffffff | 0x3fe0000000000000);
    }
    else
    {
      local_res10 = (double)((ulonglong)param_1 & 0xbfefffffffffffff | 0x3fe0000000000000);
      iVar5 = ((ushort)((ulonglong)param_1 >> 0x34) & 0x7ff) - 0x3fe;
      local_res8 = local_res10;
    }
  }
  *param_3 = iVar5;
  return local_res8;
}

BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)
{
  BOOL BVar1;

  // WARNING: Could not recover jumptable at 0x000180089c94. Too many branches
  // WARNING: Treating indirect jump as call
  BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
  return BVar1;
}

void RtlUnwindEx(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord,
                 PVOID ReturnValue, PCONTEXT ContextRecord, PUNWIND_HISTORY_TABLE HistoryTable)
{
  // WARNING: Could not recover jumptable at 0x000180089cd6. Too many branches
  // WARNING: Treating indirect jump as call
  RtlUnwindEx(TargetFrame, TargetIp, ExceptionRecord, ReturnValue, ContextRecord, HistoryTable);
  return;
}

void thunk_FUN_180034d24(size_t param_1)
{
  code *pcVar1;
  int iVar2;
  LPVOID pvVar3;

  do
  {
    pvVar3 = _malloc_base(param_1);
    if (pvVar3 != (LPVOID)0x0)
    {
      return;
    }
    iVar2 = _callnewh(param_1);
  } while (iVar2 != 0);
  if (param_1 != 0xffffffffffffffff)
  {
    FUN_180035948();
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  FUN_180035968();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}

// Library Function - Single Match
//  __GSHandlerCheck_SEH
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __GSHandlerCheck_SEH(PEXCEPTION_RECORD param_1, PVOID param_2, longlong param_3, longlong *param_4)
{
  uint *puVar1;

  puVar1 = (uint *)param_4[7] + (ulonglong) * (uint *)param_4[7] * 4;
  __GSHandlerCheckCommon((ulonglong)param_2, (longlong)param_4, puVar1 + 1);
  if ((puVar1[1] & ((param_1->ExceptionFlags & 0x66) != 0) + 1) != 0)
  {
    __C_specific_handler(param_1, param_2, param_3, param_4);
  }
  return;
}

// Library Function - Single Match
//  _FindPESection
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

PIMAGE_SECTION_HEADER _FindPESection(PBYTE pImageBase, DWORD_PTR rva)
{
  PIMAGE_SECTION_HEADER p_Var1;
  PBYTE pBVar2;
  uint uVar3;

  uVar3 = 0;
  pBVar2 = pImageBase + *(int *)(pImageBase + 0x3c);
  p_Var1 = (PIMAGE_SECTION_HEADER)(pBVar2 + (ulonglong) * (ushort *)(pBVar2 + 0x14) + 0x18);
  if (*(ushort *)(pBVar2 + 6) != 0)
  {
    do
    {
      if ((p_Var1->VirtualAddress <= rva) && (rva < p_Var1->Misc + p_Var1->VirtualAddress))
      {
        return p_Var1;
      }
      uVar3 = uVar3 + 1;
      p_Var1 = p_Var1 + 1;
    } while (uVar3 < *(ushort *)(pBVar2 + 6));
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}

// Library Function - Single Match
//  _IsNonwritableInCurrentImage
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

BOOL _IsNonwritableInCurrentImage(PBYTE pTarget)
{
  uint uVar1;
  PIMAGE_SECTION_HEADER p_Var2;

  uVar1 = _ValidateImageBase((PBYTE)&IMAGE_DOS_HEADER_180000000);
  p_Var2 = (PIMAGE_SECTION_HEADER)(ulonglong)uVar1;
  if (uVar1 != 0)
  {
    p_Var2 = _FindPESection((PBYTE)&IMAGE_DOS_HEADER_180000000, (DWORD_PTR)(pTarget + -0x180000000));
    if (p_Var2 != (PIMAGE_SECTION_HEADER)0x0)
    {
      p_Var2 = (PIMAGE_SECTION_HEADER)(ulonglong)(~(p_Var2->Characteristics >> 0x1f) & 1);
    }
  }
  return (BOOL)p_Var2;
}

// Library Function - Single Match
//  _ValidateImageBase
//
// Library: Visual Studio 2015 Release

BOOL _ValidateImageBase(PBYTE pImageBase)
{
  uint uVar1;

  if (*(short *)pImageBase != 0x5a4d)
  {
    return 0;
  }
  uVar1 = 0;
  if (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550)
  {
    uVar1 = (uint)(*(short *)((longlong)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x20b);
  }
  return (BOOL)uVar1;
}

// Library Function - Single Match
//  strrchr
//
// Library: Visual Studio 2017 Release

char *strrchr(char *_Str, int _Ch)
{
  undefined4 in_EAX;
  uint uVar1;
  undefined(*pauVar2)[16];
  uint uVar3;
  int iVar4;
  undefined(*pauVar5)[16];
  char *pcVar6;
  uint uVar7;
  char *pcVar8;
  bool bVar9;
  bool bVar10;
  char cVar11;
  char cVar12;
  char cVar13;
  char cVar14;
  undefined in_XMM1[16];
  undefined auVar15[16];

  pauVar2 = (undefined(*)[16])0x0;
  if (_Ch == 0)
  {
    pcVar6 = (char *)((ulonglong)_Str & 0xfffffffffffffff0);
    auVar15 = in_XMM1 & (undefined[16])0x0;
    cVar11 = SUB161(auVar15 >> 0x40, 0);
    cVar12 = SUB161(auVar15 >> 0x48, 0);
    cVar13 = SUB161(auVar15 >> 0x50, 0);
    cVar14 = SUB161(auVar15 >> 0x58, 0);
    uVar1 = pmovmskb(in_EAX, CONCAT115(-(pcVar6[0xf] == '\0'),
                                       CONCAT114(-(pcVar6[0xe] == '\0'),
                                                 CONCAT113(-(pcVar6[0xd] == '\0'),
                                                           CONCAT112(-(pcVar6[0xc] == '\0'),
                                                                     CONCAT111(-(pcVar6[0xb] ==
                                                                                 cVar14),
                                                                               CONCAT110(-(
                                                                                             pcVar6[10] == cVar13),
                                                                                         CONCAT19(-(pcVar6[9] == cVar12),
                                                                                                  CONCAT18(-(pcVar6[8] == cVar11),
                                                                                                           CONCAT17(-(pcVar6[7] == '\0'),
                                                                                                                    CONCAT16(-(pcVar6[6] ==
                                                                                                                               '\0'),
                                                                                                                             CONCAT15(-(pcVar6[5] == '\0'),
                                                                                                                                      CONCAT14(-(pcVar6[4] == '\0'),
                                                                                                                                               CONCAT13(-(pcVar6[3] == '\0'),
                                                                                                                                                        CONCAT12(-(pcVar6[2] ==
                                                                                                                                                                   '\0'),
                                                                                                                                                                 CONCAT11(-(pcVar6[1] == '\0'), -(*pcVar6 == '\0')))))))))))))))));
    uVar1 = uVar1 & -1 << ((byte)_Str & 0xf);
    while (uVar1 == 0)
    {
      uVar1 = pmovmskb(0, CONCAT115(-(pcVar6[0x1f] == '\0'),
                                    CONCAT114(-(pcVar6[0x1e] == '\0'),
                                              CONCAT113(-(pcVar6[0x1d] == '\0'),
                                                        CONCAT112(-(pcVar6[0x1c] == '\0'),
                                                                  CONCAT111(-(pcVar6[0x1b] == cVar14), CONCAT110(-(pcVar6[0x1a] == cVar13),
                                                                                                                 CONCAT19(-(
                                                                                                                              pcVar6[0x19] == cVar12),
                                                                                                                          CONCAT18(-(pcVar6[0x18] == cVar11),
                                                                                                                                   CONCAT17(-(pcVar6[0x17] == '\0'),
                                                                                                                                            CONCAT16(-(pcVar6[0x16] == '\0'), CONCAT15(-(pcVar6[0x15] == '\0'),
                                                                                                                                                                                       CONCAT14(-(pcVar6[0x14] == '\0'),
                                                                                                                                                                                                CONCAT13(-(pcVar6[0x13] == '\0'),
                                                                                                                                                                                                         CONCAT12(-(pcVar6[0x12] == '\0'), CONCAT11(-(pcVar6[0x11] == '\0'), -(pcVar6[0x10] == '\0')))))))))))))))));
      pcVar6 = pcVar6 + 0x10;
    }
    uVar3 = 0;
    if (uVar1 != 0)
    {
      while ((uVar1 >> uVar3 & 1) == 0)
      {
        uVar3 = uVar3 + 1;
      }
    }
    pauVar2 = (undefined(*)[16])(pcVar6 + uVar3);
  }
  else
  {
    if (DAT_1800ee178 < 2)
    {
      uVar1 = (uint)_Str & 0xf;
      pcVar6 = (char *)((ulonglong)_Str & 0xfffffffffffffff0);
      auVar15 = pshuflw(in_XMM1, ZEXT416((_Ch & 0xffU) << 8 | _Ch & 0xffU), 0);
      uVar7 = -1 << (sbyte)uVar1;
      uVar3 = pmovmskb(uVar1, CONCAT115(-(pcVar6[0xf] == '\0'),
                                        CONCAT114(-(pcVar6[0xe] == '\0'),
                                                  CONCAT113(-(pcVar6[0xd] == '\0'),
                                                            CONCAT112(-(pcVar6[0xc] == '\0'),
                                                                      CONCAT111(-(pcVar6[0xb] == '\0'), CONCAT110(-(pcVar6
                                                                                                                        [10] == '\0'),
                                                                                                                  CONCAT19(-(pcVar6[9] == '\0'),
                                                                                                                           CONCAT18(-(pcVar6[8] == '\0'),
                                                                                                                                    CONCAT17(-(pcVar6[7] == '\0'),
                                                                                                                                             CONCAT16(-(pcVar6[6] ==
                                                                                                                                                        '\0'),
                                                                                                                                                      CONCAT15(-(pcVar6[5] == '\0'),
                                                                                                                                                               CONCAT14(-(pcVar6[4] == '\0'),
                                                                                                                                                                        CONCAT13(-(pcVar6[3] == '\0'),
                                                                                                                                                                                 CONCAT12(-(pcVar6[2] ==
                                                                                                                                                                                            '\0'),
                                                                                                                                                                                          CONCAT11(-(pcVar6[1] == '\0'), -(*pcVar6 == '\0')))))))))))))))));
      cVar11 = SUB161(auVar15, 0);
      cVar12 = SUB161(auVar15 >> 8, 0);
      cVar13 = SUB161(auVar15 >> 0x10, 0);
      cVar14 = SUB161(auVar15 >> 0x18, 0);
      uVar1 = pmovmskb(_Ch, CONCAT115(-(cVar14 == pcVar6[0xf]),
                                      CONCAT114(-(cVar13 == pcVar6[0xe]),
                                                CONCAT113(-(cVar12 == pcVar6[0xd]),
                                                          CONCAT112(-(cVar11 == pcVar6[0xc]),
                                                                    CONCAT111(-(cVar14 == pcVar6[0xb]), CONCAT110(-(cVar13 == pcVar6[10]),
                                                                                                                  CONCAT19(-(cVar12 == pcVar6[9]),
                                                                                                                           CONCAT18(-(cVar11 == pcVar6[8]),
                                                                                                                                    CONCAT17(-(cVar14 == pcVar6[7]),
                                                                                                                                             CONCAT16(-(cVar13 ==
                                                                                                                                                        pcVar6[6]),
                                                                                                                                                      CONCAT15(-(
                                                                                                                                                                   cVar12 == pcVar6[5]),
                                                                                                                                                               CONCAT14(-(cVar11 == pcVar6[4]),
                                                                                                                                                                        CONCAT13(-(cVar14 == pcVar6[3]),
                                                                                                                                                                                 CONCAT12(-(cVar13 == pcVar6[2]),
                                                                                                                                                                                          CONCAT11(-(cVar12 ==
                                                                                                                                                                                                     pcVar6[1]),
                                                                                                                                                                                                   -(cVar11 ==
                                                                                                                                                                                                     *pcVar6)))))))))))))))));
      uVar1 = uVar1 & uVar7;
      uVar3 = uVar3 & uVar7;
      while (uVar3 == 0)
      {
        uVar3 = 0x1f;
        if (uVar1 != 0)
        {
          while (uVar1 >> uVar3 == 0)
          {
            uVar3 = uVar3 - 1;
          }
        }
        if (uVar1 != 0)
        {
          pauVar2 = (undefined(*)[16])(pcVar6 + uVar3);
        }
        pcVar8 = pcVar6 + 0x10;
        uVar3 = pmovmskb((int)(undefined(*)[16])(pcVar6 + uVar3),
                         CONCAT115(-(pcVar6[0x1f] == '\0'),
                                   CONCAT114(-(pcVar6[0x1e] == '\0'),
                                             CONCAT113(-(pcVar6[0x1d] == '\0'),
                                                       CONCAT112(-(pcVar6[0x1c] == '\0'),
                                                                 CONCAT111(-(pcVar6[0x1b] == '\0'),
                                                                           CONCAT110(-(pcVar6[0x1a] == '\0'),
                                                                                     CONCAT19(-(
                                                                                                  pcVar6[0x19] == '\0'),
                                                                                              CONCAT18(-(pcVar6[0x18] == '\0'),
                                                                                                       CONCAT17(-(pcVar6[0x17] == '\0'),
                                                                                                                CONCAT16(-(pcVar6[0x16] == '\0'), CONCAT15(-(pcVar6[0x15] == '\0'),
                                                                                                                                                           CONCAT14(-(pcVar6[0x14] == '\0'),
                                                                                                                                                                    CONCAT13(-(pcVar6[0x13] == '\0'),
                                                                                                                                                                             CONCAT12(-(pcVar6[0x12] == '\0'), CONCAT11(-(pcVar6[0x11] == '\0'), -(*pcVar8 == '\0')))))))))))))))));
        uVar1 = pmovmskb(uVar1, CONCAT115(-(cVar14 == pcVar6[0x1f]),
                                          CONCAT114(-(cVar13 == pcVar6[0x1e]),
                                                    CONCAT113(-(cVar12 == pcVar6[0x1d]),
                                                              CONCAT112(-(cVar11 == pcVar6[0x1c]),
                                                                        CONCAT111(-(cVar14 ==
                                                                                    pcVar6[0x1b]),
                                                                                  CONCAT110(-(cVar13 == pcVar6[0x1a]),
                                                                                            CONCAT19(-(cVar12 == pcVar6[0x19]),
                                                                                                     CONCAT18(-(cVar11 == pcVar6[0x18]),
                                                                                                              CONCAT17(-(cVar14 ==
                                                                                                                         pcVar6[0x17]),
                                                                                                                       CONCAT16(-(cVar13 ==
                                                                                                                                  pcVar6[0x16]),
                                                                                                                                CONCAT15(-(
                                                                                                                                             cVar12 == pcVar6[0x15]),
                                                                                                                                         CONCAT14(-(cVar11 == pcVar6[0x14]),
                                                                                                                                                  CONCAT13(-(cVar14 == pcVar6[0x13]),
                                                                                                                                                           CONCAT12(-(cVar13 ==
                                                                                                                                                                      pcVar6[0x12]),
                                                                                                                                                                    CONCAT11(-(cVar12 ==
                                                                                                                                                                               pcVar6[0x11]),
                                                                                                                                                                             -(cVar11 ==
                                                                                                                                                                               *pcVar8)))))))))))))))));
        pcVar6 = pcVar8;
      }
      uVar1 = uVar1 & (-uVar3 & uVar3) - 1;
      uVar3 = 0x1f;
      if (uVar1 != 0)
      {
        while (uVar1 >> uVar3 == 0)
        {
          uVar3 = uVar3 - 1;
        }
      }
      if (uVar1 != 0)
      {
        pauVar2 = (undefined(*)[16])(pcVar6 + uVar3);
      }
    }
    else
    {
      while (true)
      {
        bVar9 = false;
        bVar10 = ((ulonglong)_Str & 0xf) == 0;
        if (bVar10)
          break;
        pauVar5 = (undefined(*)[16])_Str;
        if (*_Str != _Ch)
        {
          pauVar5 = pauVar2;
        }
        if (*_Str == '\0')
        {
          return (char *)pauVar5;
        }
        _Str = _Str + 1;
        pauVar2 = pauVar5;
      }
      while (true)
      {
        iVar4 = pcmpistri(ZEXT416(_Ch & 0xff), *(undefined(*)[16])_Str, 0x40);
        if (bVar9)
        {
          pauVar2 = (undefined(*)[16])(_Str + iVar4);
          bVar10 = pauVar2 == (undefined(*)[16])0x0;
          pcmpistri(ZEXT416(_Ch & 0xff), *(undefined(*)[16])_Str, 0x40);
        }
        if (bVar10)
          break;
        bVar9 = (undefined(*)[16])0xffffffffffffffef < _Str;
        _Str = (char *)((longlong)_Str + 0x10);
        bVar10 = (undefined(*)[16])_Str == (undefined(*)[16])0x0;
      }
    }
  }
  return (char *)pauVar2;
}

// Library Function - Single Match
//  strchr
//
// Library: Visual Studio 2017 Release

char *strchr(char *_Str, int _Val)
{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  char *pcVar4;
  char *pcVar5;
  char cVar6;
  char cVar8;
  char cVar9;
  char cVar10;
  undefined in_XMM1[16];
  undefined auVar7[16];

  uVar2 = _Val & 0xff;
  pcVar4 = (char *)((ulonglong)_Str & 0xfffffffffffffff0);
  auVar7 = pshuflw(in_XMM1, ZEXT416(uVar2 << 8 | uVar2), 0);
  cVar6 = SUB161(auVar7, 0);
  cVar8 = SUB161(auVar7 >> 8, 0);
  cVar9 = SUB161(auVar7 >> 0x10, 0);
  cVar10 = SUB161(auVar7 >> 0x18, 0);
  uVar3 = pmovmskb(_Val, CONCAT115(-(cVar10 == pcVar4[0xf]),
                                   CONCAT114(-(cVar9 == pcVar4[0xe]),
                                             CONCAT113(-(cVar8 == pcVar4[0xd]),
                                                       CONCAT112(-(cVar6 == pcVar4[0xc]),
                                                                 CONCAT111(-(cVar10 == pcVar4[0xb]),
                                                                           CONCAT110(-(cVar9 ==
                                                                                       pcVar4[10]),
                                                                                     CONCAT19(-(cVar8 == pcVar4[9]),
                                                                                              CONCAT18(-(cVar6 == pcVar4[8]),
                                                                                                       CONCAT17(-(cVar10 == pcVar4[7]),
                                                                                                                CONCAT16(-(cVar9 ==
                                                                                                                           pcVar4[6]),
                                                                                                                         CONCAT15(-(cVar8 == pcVar4[5]),
                                                                                                                                  CONCAT14(-(cVar6 == pcVar4[4]),
                                                                                                                                           CONCAT13(-(cVar10 == pcVar4[3]),
                                                                                                                                                    CONCAT12(-(cVar9 ==
                                                                                                                                                               pcVar4[2]),
                                                                                                                                                             CONCAT11(-(cVar8 == pcVar4[1]), -(cVar6 == *pcVar4)))))))))))))))) |
                             CONCAT115(-(pcVar4[0xf] == '\0'),
                                       CONCAT114(-(pcVar4[0xe] == '\0'),
                                                 CONCAT113(-(pcVar4[0xd] == '\0'),
                                                           CONCAT112(-(pcVar4[0xc] == '\0'),
                                                                     CONCAT111(-(pcVar4[0xb] == '\0'),
                                                                               CONCAT110(-(pcVar4[10] ==
                                                                                           '\0'),
                                                                                         CONCAT19(
                                                                                             -(pcVar4[9] == '\0'),
                                                                                             CONCAT18(-(pcVar4[8] == '\0'),
                                                                                                      CONCAT17(-(pcVar4[7] == '\0'),
                                                                                                               CONCAT16(-(pcVar4[6] == '\0'),
                                                                                                                        CONCAT15(-(pcVar4[5] ==
                                                                                                                                   '\0'),
                                                                                                                                 CONCAT14(-(pcVar4[4] == '\0'),
                                                                                                                                          CONCAT13(-(pcVar4[3] == '\0'),
                                                                                                                                                   CONCAT12(-(pcVar4[2] == '\0'),
                                                                                                                                                            CONCAT11(-(pcVar4[1] ==
                                                                                                                                                                       '\0'),
                                                                                                                                                                     -(*pcVar4 == '\0')))))))))))))))));
  uVar3 = uVar3 & -1 << ((byte)_Str & 0xf);
  while (uVar3 == 0)
  {
    pcVar5 = pcVar4 + 0x10;
    uVar3 = pmovmskb(0, CONCAT115(-(cVar10 == pcVar4[0x1f]),
                                  CONCAT114(-(cVar9 == pcVar4[0x1e]),
                                            CONCAT113(-(cVar8 == pcVar4[0x1d]),
                                                      CONCAT112(-(cVar6 == pcVar4[0x1c]),
                                                                CONCAT111(-(cVar10 == pcVar4[0x1b]),
                                                                          CONCAT110(-(cVar9 == pcVar4
                                                                                                   [0x1a]),
                                                                                    CONCAT19(-(cVar8 == pcVar4[0x19]),
                                                                                             CONCAT18(-(cVar6 == pcVar4[0x18]), CONCAT17(-(cVar10 ==
                                                                                                                                           pcVar4[0x17]),
                                                                                                                                         CONCAT16(-(
                                                                                                                                                      cVar9 == pcVar4[0x16]),
                                                                                                                                                  CONCAT15(-(cVar8 == pcVar4[0x15]),
                                                                                                                                                           CONCAT14(-(cVar6 == pcVar4[0x14]),
                                                                                                                                                                    CONCAT13(-(cVar10 ==
                                                                                                                                                                               pcVar4[0x13]),
                                                                                                                                                                             CONCAT12(-(cVar9 ==
                                                                                                                                                                                        pcVar4[0x12]),
                                                                                                                                                                                      CONCAT11(-(cVar8 == pcVar4[0x11]),
                                                                                                                                                                                               -(cVar6 == *pcVar5)))))))))))))))) |
                            CONCAT115(-(pcVar4[0x1f] == '\0'),
                                      CONCAT114(-(pcVar4[0x1e] == '\0'),
                                                CONCAT113(-(pcVar4[0x1d] == '\0'),
                                                          CONCAT112(-(pcVar4[0x1c] == '\0'),
                                                                    CONCAT111(-(pcVar4[0x1b] == '\0'),
                                                                              CONCAT110(-(pcVar4[0x1a] ==
                                                                                          '\0'),
                                                                                        CONCAT19(-(pcVar4[0x19] == '\0'),
                                                                                                 CONCAT18(-(pcVar4[0x18] == '\0'),
                                                                                                          CONCAT17(-(pcVar4[0x17] == '\0'),
                                                                                                                   CONCAT16(-(pcVar4[0x16] == '\0'), CONCAT15(-(pcVar4[0x15] == '\0'),
                                                                                                                                                              CONCAT14(-(pcVar4[0x14] == '\0'),
                                                                                                                                                                       CONCAT13(-(pcVar4[0x13] == '\0'),
                                                                                                                                                                                CONCAT12(-(pcVar4[0x12] == '\0'), CONCAT11(-(pcVar4[0x11] == '\0'), -(*pcVar5 == '\0')))))))))))))))));
    pcVar4 = pcVar5;
  }
  uVar1 = 0;
  if (uVar3 != 0)
  {
    while ((uVar3 >> uVar1 & 1) == 0)
    {
      uVar1 = uVar1 + 1;
    }
  }
  pcVar5 = (char *)0x0;
  if (pcVar4[uVar1] == (char)uVar2)
  {
    pcVar5 = pcVar4 + uVar1;
  }
  return pcVar5;
}

// Library Function - Single Match
//  wcschr
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

wchar_t *wcschr(wchar_t *_Str, wchar_t _Ch)
{
  uint uVar1;
  uint uVar2;
  longlong lVar3;
  wchar_t *pwVar4;
  undefined in_XMM1[16];
  undefined auVar5[16];
  wchar_t wVar6;
  wchar_t wVar7;

  auVar5 = pshuflw(in_XMM1, ZEXT216((ushort)_Ch), 0);
  do
  {
    uVar2 = (uint)_Str & 0xfff;
    if (uVar2 < 0xff1)
    {
      wVar6 = SUB162(auVar5, 0);
      wVar7 = SUB162(auVar5 >> 0x10, 0);
      uVar2 = pmovmskb(uVar2, CONCAT214(-(ushort)(_Str[7] == L'\0'),
                                        CONCAT212(-(ushort)(_Str[6] == L'\0'),
                                                  CONCAT210(-(ushort)(_Str[5] == L'\0'),
                                                            CONCAT28(-(ushort)(_Str[4] == L'\0'),
                                                                     CONCAT26(-(ushort)(_Str[3] ==
                                                                                        L'\0'),
                                                                              CONCAT24(-(ushort)(_Str
                                                                                                     [2] == L'\0'),
                                                                                       CONCAT22(-(ushort)(_Str[1] == L'\0'),
                                                                                                -(ushort)(*_Str == L'\0')))))))) |
                                  CONCAT214(-(ushort)(_Str[7] == wVar7),
                                            CONCAT212(-(ushort)(_Str[6] == wVar6),
                                                      CONCAT210(-(ushort)(_Str[5] == wVar7),
                                                                CONCAT28(-(ushort)(_Str[4] == wVar6),
                                                                         CONCAT26(-(ushort)(_Str[3] ==
                                                                                            wVar7),
                                                                                  CONCAT24(-(ushort)(_Str
                                                                                                         [2] == wVar6),
                                                                                           CONCAT22(-(ushort)(_Str[1] == wVar7),
                                                                                                    -(ushort)(*_Str == wVar6)))))))));
      if (uVar2 != 0)
      {
        uVar1 = 0;
        if (uVar2 != 0)
        {
          while ((uVar2 >> uVar1 & 1) == 0)
          {
            uVar1 = uVar1 + 1;
          }
        }
        pwVar4 = (wchar_t *)0x0;
        if (*(wchar_t *)((longlong)_Str + (ulonglong)uVar1) == _Ch)
        {
          pwVar4 = (wchar_t *)((longlong)_Str + (ulonglong)uVar1);
        }
        return pwVar4;
      }
      lVar3 = 0x10;
    }
    else
    {
      if (*_Str == _Ch)
      {
        return _Str;
      }
      if (*_Str == L'\0')
      {
        return (wchar_t *)0x0;
      }
      lVar3 = 2;
    }
    _Str = (wchar_t *)((longlong)_Str + lVar3);
  } while (true);
}

// WARNING: This is an inlined function

void _guard_dispatch_icall(void)
{
  code *UNRECOVERED_JUMPTABLE;

  // WARNING: Could not recover jumptable at 0x00018008a200. Too many branches
  // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}

void _guard_check_icall(void)
{
  return;
}

LPVOID _recalloc_base(LPCVOID param_1, ulonglong param_2, ulonglong param_3)
{
  ulong *puVar1;
  SIZE_T SVar2;
  LPVOID pvVar3;
  ulonglong uVar4;

  if ((param_2 == 0) || (param_3 <= 0xffffffffffffffe0 / param_2))
  {
    if (param_1 == (LPCVOID)0x0)
    {
      SVar2 = 0;
    }
    else
    {
      SVar2 = _msize_base(param_1);
    }
    uVar4 = param_2 * param_3;
    pvVar3 = _realloc_base(param_1, uVar4);
    if ((pvVar3 != (LPVOID)0x0) && (SVar2 < uVar4))
    {
      FUN_18003bd40((undefined(*)[16])((longlong)pvVar3 + SVar2), 0, uVar4 - SVar2);
    }
  }
  else
  {
    puVar1 = __doserrno();
    *puVar1 = 0xc;
    pvVar3 = (LPVOID)0x0;
  }
  return pvVar3;
}

__int64 common_lseek_nolock___int64_(int param_1, __int64 param_2, int param_3)
{
  byte *pbVar1;
  BOOL BVar2;
  DWORD DVar3;
  HANDLE hFile;
  ulong *puVar4;
  longlong lStackX32;

  hFile = (HANDLE)_get_osfhandle(param_1);
  if (hFile == (HANDLE)0xffffffffffffffff)
  {
    puVar4 = __doserrno();
    *puVar4 = 9;
  }
  else
  {
    BVar2 = SetFilePointerEx(hFile, param_2, &lStackX32, param_3);
    if (BVar2 == 0)
    {
      DVar3 = GetLastError();
      __acrt_errno_map_os_error(DVar3);
    }
    else
    {
      if (lStackX32 != -1)
      {
        pbVar1 = (byte *)(*(longlong *)((longlong)&DAT_180101d10 + ((longlong)param_1 >> 6) * 8) +
                          0x38 + (ulonglong)(param_1 & 0x3f) * 0x40);
        *pbVar1 = *pbVar1 & 0xfd;
        return lStackX32;
      }
    }
  }
  return -1;
}

// WARNING: Removing unreachable block (ram,0x0001800347ab)
// WARNING: Removing unreachable block (ram,0x00018003472e)
// WARNING: Removing unreachable block (ram,0x0001800347f5)

ulonglong entry(undefined8 param_1, int param_2, longlong param_3)
{
  ulonglong uVar1;
  ulonglong uVar2;

  if (param_2 == 1)
  {
    FUN_180034e40();
  }
  if ((param_2 == 0) && (DAT_1801011a0 < 1))
  {
    uVar2 = 0;
  }
  else
  {
    if (param_2 - 1U < 2)
    {
      uVar1 = FUN_1800344e0(param_1, param_2, param_3);
      if ((int)uVar1 == 0)
      {
        return uVar1 & 0xffffffff;
      }
    }
    uVar1 = FUN_180023880(param_1, param_2);
    uVar2 = uVar1 & 0xffffffff;
    if ((param_2 == 1) && ((int)uVar1 == 0))
    {
      FUN_180023880(param_1, 0);
      FUN_1800344e0(param_1, 0, param_3);
    }
    if ((param_2 == 0) || (param_2 == 3))
    {
      uVar1 = FUN_1800344e0(param_1, param_2, param_3);
      uVar2 = uVar1 & 0xffffffff;
      if ((int)uVar1 != 0)
      {
        uVar2 = 1;
      }
    }
  }
  return uVar2;
}

undefined8 WbioQueryEngineInterface(undefined8 *param_1)
{
  undefined8 uVar1;

  // 0x17790  1  WbioQueryEngineInterface
  FUN_1800147f0((wchar_t *)PTR_DAT_1800ebd68, 9,

                L"f:\\work\\huawei_kepler\\winfpcode\\milan_watt\\milanspi\\adapters\\engine_adapter\\engineadapter.cpp", L"WbioQueryEngineInterface", 0x29c, 0, (char *)L"enter");
  if (param_1 == (undefined8 *)0x0)
  {
    uVar1 = 0x80004003;
  }
  else
  {
    *param_1 = &DAT_1800ec770;
    FUN_1800147f0((wchar_t *)PTR_DAT_1800ebd68, 9,

                  L"f:\\work\\huawei_kepler\\winfpcode\\milan_watt\\milanspi\\adapters\\engine_adapter\\engineadapter.cpp", L"WbioQueryEngineInterface", 0x2a2, 0, (char *)L"Exit");
    uVar1 = 0;
  }
  return uVar1;
}
