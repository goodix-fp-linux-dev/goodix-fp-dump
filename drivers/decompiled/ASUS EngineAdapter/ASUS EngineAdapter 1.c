ulonglong FUN_180001080(void)

{
  code *pcVar1;
  undefined(*pauVar2)[16];
  ulonglong uVar3;
  _onexit_t p_Var4;

  pauVar2 = (undefined(*)[16])FUN_18005f1cc(0x10);
  if (pauVar2 != (undefined(*)[16])0x0)
  {
    DAT_1800b1810 = pauVar2;
    *pauVar2 = ZEXT816(0);
    *(undefined(***)[16]) * DAT_1800b1810 = &DAT_1800b1810;
    p_Var4 = _onexit((_onexit_t)&LAB_18006d2b0);
    return (ulonglong)((p_Var4 != (_onexit_t)0x0) - 1);
  }
  _invalid_parameter_noinfo_noreturn();
  pcVar1 = (code *)swi(3);
  uVar3 = (*pcVar1)();
  return uVar3;
}

void FUN_1800010d0(void)

{
  DAT_1800b18e0 = (undefined **)FUN_18005f1cc(0x60);
  if (DAT_1800b18e0 != (undefined **)0x0)
  {
    *DAT_1800b18e0 = (undefined *)ChainBase::vftable;
    DAT_1800b18e0[2] = (undefined *)0x0;
    DAT_1800b18e0[3] = (undefined *)0x0;
    *(undefined2 *)(DAT_1800b18e0 + 4) = 0;
    *(undefined8 *)((longlong)DAT_1800b18e0 + 0x22) = 0;
    *(undefined8 *)((longlong)DAT_1800b18e0 + 0x2a) = 0;
    *(undefined8 *)((longlong)DAT_1800b18e0 + 0x32) = 0;
    *(undefined8 *)((longlong)DAT_1800b18e0 + 0x3a) = 0;
    *(undefined8 *)((longlong)DAT_1800b18e0 + 0x42) = 0;
    *(undefined8 *)((longlong)DAT_1800b18e0 + 0x4a) = 0;
    *(undefined8 *)((longlong)DAT_1800b18e0 + 0x52) = 0;
    *(undefined4 *)((longlong)DAT_1800b18e0 + 0x5a) = 0;
    *(undefined2 *)((longlong)DAT_1800b18e0 + 0x5e) = 0;
    *(undefined4 *)(DAT_1800b18e0 + 1) = 0xffffffff;
    return;
  }
  DAT_1800b18e0 = (undefined **)0x0;
  return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint **enrolStartEx(uint *param_1)

{
  uint **_Memory;
  uint **_Memory_00;
  uint **_Memory_01;
  undefined8 uVar1;
  uint uVar2;

  // 0x1160  7  enrolStartEx
  if (_DAT_1800b20a0 != 1)
  {
    FUN_1800545f0();
    return (uint **)0x0;
  }
  uVar2 = (((DAT_1800d853c << 9 | DAT_1800d8540) << 0xb | DAT_1800d8538) << 2 | DAT_1800b20ac) * 2 |
          DAT_1800b20a8 | DAT_1800b20a4;
  _Memory = (uint **)malloc(0x20);
  _Memory_00 = (uint **)malloc(8);
  _Memory_01 = (uint **)malloc(8);
  if ((((_Memory != (uint **)0x0) && (_Memory_00 != (uint **)0x0)) && (_Memory_01 != (uint **)0x0)) && (param_1 != (uint *)0x0))
  {
    _Memory[1] = (uint *)0x0;
    _Memory[2] = (uint *)0x0;
    _Memory[3] = (uint *)0x0;
    *(undefined4 *)(_Memory + 1) = 8;
    *_Memory = (uint *)_Memory_00;
    if (0x32 < (int)*param_1)
    {
      *param_1 = 0x32;
    }
    uVar1 = FUN_180003f90(_Memory_01, *param_1, (ulonglong)uVar2);
    if ((*_Memory_01 != (uint *)0x0) && ((int)uVar1 == 0))
    {
      *param_1 = (*_Memory_01)[8];
      FUN_1800545f0();
      *_Memory_00 = (uint *)_Memory_01;
      FUN_1800545f0();
      return _Memory;
    }
  }
  FUN_1800545f0();
  free(_Memory);
  free(_Memory_00);
  free(_Memory_01);
  return (uint **)0x0;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint **enrolStart(void)

{
  uint **_Memory;
  uint **_Memory_00;
  uint **_Memory_01;
  undefined8 uVar1;
  uint uVar2;

  // 0x12d0  6  enrolStart
  if (_DAT_1800b20a0 != 1)
  {
    FUN_1800545f0();
    return (uint **)0x0;
  }
  uVar2 = (((DAT_1800d853c << 9 | DAT_1800d8540) << 0xb | DAT_1800d8538) << 2 | DAT_1800b20ac) * 2 |
          DAT_1800b20a8 | DAT_1800b20a4;
  _Memory = (uint **)malloc(0x20);
  _Memory_00 = (uint **)malloc(8);
  _Memory_01 = (uint **)malloc(8);
  if (((_Memory == (uint **)0x0) || (_Memory_00 == (uint **)0x0)) || (_Memory_01 == (uint **)0x0))
  {
    FUN_1800545f0();
    free(_Memory);
    free(_Memory_00);
    free(_Memory_01);
  }
  else
  {
    _Memory[1] = (uint *)0x0;
    _Memory[2] = (uint *)0x0;
    _Memory[3] = (uint *)0x0;
    *(undefined4 *)(_Memory + 1) = 8;
    *_Memory = (uint *)_Memory_00;
    uVar1 = FUN_180003f90(_Memory_01, 0x32, (ulonglong)uVar2);
    if ((*_Memory_01 != (uint *)0x0) && ((int)uVar1 == 0))
    {
      FUN_1800545f0();
      *_Memory_00 = (uint *)_Memory_01;
      FUN_1800545f0();
      return _Memory;
    }
    FUN_1800545f0();
    free(_Memory);
    free(_Memory_00);
    free(_Memory_01);
  }
  return (uint **)0x0;
}

undefined8 gx_sensorCheck(longlong *param_1, longlong *param_2, int *param_3, byte *param_4)

{
  undefined8 uVar1;

  // 0x1450  10  gx_sensorCheck
  if (((param_1 != (longlong *)0x0) && (param_2 != (longlong *)0x0)) && (param_3 != (int *)0x0))
  {
    if ((((*(char *)((longlong)param_1 + 0xe) == '\x10') &&
          (*(char *)((longlong)param_1 + 0xf) == '\x01')) &&
         ((*(short *)(param_1 + 3) != 0 &&
           ((*(char *)((longlong)param_2 + 0xe) == '\x10' &&
             (*(char *)((longlong)param_2 + 0xf) == '\x01')))))) &&
        (*(short *)(param_2 + 3) != 0))
    {
      if ((*param_1 != 0) && (*param_2 != 0))
      {
        uVar1 = FUN_180015830(*param_1, *param_2, param_4, param_3);
        return uVar1;
      }
      FUN_1800545f0();
      return 0x81;
    }
    FUN_1800545f0();
    FUN_1800545f0();
    FUN_1800545f0();
  }
  return 0x81;
}

// WARNING: Could not reconcile some variable overlaps

undefined8
enrolAddImage(longlong **param_1, longlong *param_2, undefined8 param_3, char param_4, uint *param_5)

{
  void **ppvVar1;
  byte bVar2;
  uint **ppuVar3;
  uint *puVar4;
  uint *puVar5;
  int *_Memory;
  undefined8 *_Memory_00;
  uint uVar6;
  int iVar7;
  int iVar8;
  uint local_res8[2];
  char local_res20;
  int *local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 *local_48;

  // 0x1560  2  enrolAddImage
  puVar5 = param_5;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = (undefined8 *)0x0;
  local_68 = (int *)0x0;
  local_res20 = param_4;
  if ((((param_1 == (longlong **)0x0) || ((uint **)*param_1 == (uint **)0x0)) ||
       (ppuVar3 = (uint **)**param_1, ppuVar3 == (uint **)0x0)) ||
      (((puVar4 = *ppuVar3, puVar4 == (uint *)0x0 || (param_2 == (longlong *)0x0)) ||
        (param_5 == (uint *)0x0))))
  {
    FUN_1800545f0();
    return 0x81;
  }
  if (((*(char *)((longlong)param_2 + 0xe) == '\b') &&
       (*(char *)((longlong)param_2 + 0xf) == '\x01')) &&
      (*(short *)(param_2 + 3) != 0))
  {
    if (*param_2 == 0)
    {
      FUN_1800545f0();
      return 0x81;
    }
    iVar8 = (int)*(short *)((longlong)param_2 + 10);
    uVar6 = iVar8 * *(short *)(param_2 + 1);
    local_60 = CONCAT44(iVar8, (int)*(short *)(param_2 + 1));
    local_50 = 1;
    local_58._0_4_ = 0;
    local_58._4_4_ = uVar6;
    _Memory_00 = (undefined8 *)malloc((ulonglong)uVar6);
    local_48 = _Memory_00;
    if (_Memory_00 == (undefined8 *)0x0)
    {
      FUN_1800545f0();
      return 0x82;
    }
    local_58 = CONCAT44(local_58._4_4_, iVar8);
    memcpy_FUN_180061f90(_Memory_00, (undefined8 *)*param_2, (longlong)(int)uVar6);
    puVar5[1] = (uint) * (byte *)(param_2 + 5);
    bVar2 = *(byte *)((longlong)param_2 + 0x29);
    *puVar5 = (uint)bVar2;
    if (*(short *)((longlong)param_1 + 10) < *(short *)(param_1 + 1))
    {
      local_res8[0] = 0;
      if (((*puVar4 < 9) && ((0x132U >> (*puVar4 & 0x1f) & 1) != 0)) ||
          (iVar8 = FUN_180011ab0(&local_68, (uint *)&local_60, puVar5[1], (uint)bVar2, 0, puVar4),
           _Memory = local_68, _Memory_00 = local_48, iVar8 != 0))
      {
        FUN_1800545f0();
        free(_Memory_00);
        return 0x80000001;
      }
      if (local_res20 != '\0')
      {
        local_68 = (int *)((ulonglong)local_68 & 0xffffffff00000000);
        FUN_1800144b0(_Memory, puVar4, &DAT_1800c52f4);
      }
      iVar8 = FUN_180007bc0((int *)local_res8, _Memory, puVar4);
      if (iVar8 != 0)
      {
        FUN_1800545f0();
        FUN_1800545f0();
        if (_Memory != (int *)0x0)
        {
          ppvVar1 = (void **)(_Memory + 2);
          if (((*(longlong *)(_Memory + 2) != 0) && (ppvVar1 != (void **)0x0)) &&
              (*ppvVar1 != (void *)0x0))
          {
            free(*ppvVar1);
            *ppvVar1 = (void *)0x0;
          }
          *ppvVar1 = (void *)0x0;
          ppvVar1 = (void **)(_Memory + 4);
          if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
          {
            free(*ppvVar1);
            *ppvVar1 = (void *)0x0;
          }
          *ppvVar1 = (void *)0x0;
          ppvVar1 = (void **)(_Memory + 6);
          if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
          {
            free(*ppvVar1);
            *ppvVar1 = (void *)0x0;
          }
          *ppvVar1 = (void *)0x0;
          ppvVar1 = (void **)(_Memory + 8);
          if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
          {
            free(*ppvVar1);
            *ppvVar1 = (void *)0x0;
          }
          *ppvVar1 = (void *)0x0;
          if (*(void **)(_Memory + 0x3e) != (void *)0x0)
          {
            free(*(void **)(_Memory + 0x3e));
          }
          ppvVar1 = (void **)(_Memory + 0x4c);
          *(undefined8 *)(_Memory + 0x3e) = 0;
          if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
          {
            free(*ppvVar1);
            *ppvVar1 = (void *)0x0;
          }
          *ppvVar1 = (void *)0x0;
          free(_Memory);
        }
        free(local_48);
        return 0x83;
      }
      *(short *)((longlong)param_1 + 10) = *(short *)((longlong)param_1 + 10) + 1;
      *(uint *)(param_1 + 2) = 100 - (local_res8[0] >> 0x18);
      *(uint *)((longlong)param_1 + 0x14) = 100 - (local_res8[0] & 0xff);
      _Memory_00 = local_48;
      if (_Memory != (int *)0x0)
      {
        ppvVar1 = (void **)(_Memory + 2);
        if (((*(longlong *)(_Memory + 2) != 0) && (ppvVar1 != (void **)0x0)) &&
            (*ppvVar1 != (void *)0x0))
        {
          free(*ppvVar1);
          *ppvVar1 = (void *)0x0;
        }
        *ppvVar1 = (void *)0x0;
        ppvVar1 = (void **)(_Memory + 4);
        if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
        {
          free(*ppvVar1);
          *ppvVar1 = (void *)0x0;
        }
        *ppvVar1 = (void *)0x0;
        ppvVar1 = (void **)(_Memory + 6);
        if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
        {
          free(*ppvVar1);
          *ppvVar1 = (void *)0x0;
        }
        *ppvVar1 = (void *)0x0;
        ppvVar1 = (void **)(_Memory + 8);
        if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
        {
          free(*ppvVar1);
          *ppvVar1 = (void *)0x0;
        }
        *ppvVar1 = (void *)0x0;
        if (*(void **)(_Memory + 0x3e) != (void *)0x0)
        {
          free(*(void **)(_Memory + 0x3e));
        }
        ppvVar1 = (void **)(_Memory + 0x4c);
        *(undefined8 *)(_Memory + 0x3e) = 0;
        if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
        {
          free(*ppvVar1);
          *ppvVar1 = (void *)0x0;
        }
        *ppvVar1 = (void *)0x0;
        free(_Memory);
        _Memory_00 = local_48;
      }
    }
    free(_Memory_00);
    iVar8 = (*(short *)((longlong)param_1 + 10) * 100) / (int)*(short *)(param_1 + 1);
    iVar7 = 100;
    if (iVar8 < 100)
    {
      iVar7 = iVar8;
    }
    *(int *)((longlong)param_1 + 0xc) = iVar7;
    if (iVar7 == 100)
    {
      FUN_1800545f0();
    }
    return 0;
  }
  FUN_1800545f0();
  FUN_1800545f0();
  return 0x81;
}

undefined8 enrolDeleteImage(int **param_1)

{
  int iVar1;
  int **ppiVar2;
  int *piVar3;
  longlong lVar4;
  short sVar5;
  int iVar6;
  longlong *plVar7;
  int iVar8;
  int *piVar9;
  uint uVar10;
  ulonglong uVar11;

  // 0x1a80  3  enrolDeleteImage
  FUN_1800545f0();
  if ((((param_1 != (int **)0x0) && ((int **)*param_1 != (int **)0x0)) &&
       (ppiVar2 = *(int ***)*param_1, ppiVar2 != (int **)0x0)) &&
      (piVar3 = *ppiVar2, piVar3 != (int *)0x0))
  {
    if (piVar3[7] != 0)
    {
      iVar8 = piVar3[7] + -1;
      iVar6 = *(int *)(*(longlong *)(piVar3 + (longlong)iVar8 * 2 + 10) + 0x104);
      uVar11 = (longlong)iVar6 & 0xffffffff;
      if (iVar6 < piVar3[9])
      {
        piVar9 = piVar3 + (longlong)iVar6 * 7 + 0x6e;
        do
        {
          uVar10 = (int)uVar11 + 1;
          uVar11 = (ulonglong)uVar10;
          *piVar9 = -1;
          piVar9[1] = 0x100;
          piVar9[2] = 0;
          piVar9[3] = 0;
          *(undefined8 *)(piVar9 + 4) = 0x10000000000;
          piVar9[6] = 0;
          piVar9 = piVar9 + 7;
        } while ((int)uVar10 < piVar3[9]);
      }
      iVar1 = piVar3[7];
      piVar3[9] = iVar6;
      piVar3[7] = iVar1 + -1;
      if (iVar8 == piVar3[0x21f6])
      {
        piVar3[0x21f9] = 0;
        iVar8 = 0;
        if (0 < iVar1 + -1)
        {
          plVar7 = (longlong *)(piVar3 + 10);
          do
          {
            lVar4 = *plVar7;
            plVar7 = plVar7 + 1;
            iVar8 = iVar8 + 1;
            *(undefined4 *)(lVar4 + 0x100) = 0;
          } while (iVar8 < piVar3[7]);
        }
      }
      if (1 < *piVar3 - 9U)
      {
        FUN_180017490((longlong)piVar3);
      }
    }
    if (0 < *(short *)((longlong)param_1 + 10))
    {
      sVar5 = *(short *)((longlong)param_1 + 10) + -1;
      *(short *)((longlong)param_1 + 10) = sVar5;
      iVar8 = (sVar5 * 100) / (int)*(short *)(param_1 + 1);
      iVar6 = 100;
      if (iVar8 < 100)
      {
        iVar6 = iVar8;
      }
      *(int *)((longlong)param_1 + 0xc) = iVar6;
    }
    return 0;
  }
  FUN_1800545f0();
  return 0x81;
}

undefined8 enrolGetTemplate(longlong *param_1, undefined8 *param_2)

{
  // 0x1bd0  5  enrolGetTemplate
  FUN_1800545f0();
  if ((param_1 != (longlong *)0x0) && ((undefined8 *)*param_1 != (undefined8 *)0x0))
  {
    *param_2 = *(undefined8 *)*param_1;
    return 0;
  }
  FUN_1800545f0();
  return 0x81;
}

undefined8 enrolFinish(void **param_1)

{
  void **_Memory;

  // 0x1c30  4  enrolFinish
  FUN_1800545f0();
  if (param_1 == (void **)0x0)
  {
    FUN_1800545f0();
    return 0x81;
  }
  // WARNING: Load size is inaccurate
  _Memory = **param_1;
  if (_Memory != (void **)0x0)
  {
    FUN_1800048e0(_Memory);
  }
  free(_Memory);
  free(*param_1);
  *param_1 = (void *)0x0;
  free(param_1);
  return 0;
}

// WARNING: Could not reconcile some variable overlaps

undefined8
identifyImage(longlong *param_1, longlong **param_2, uint param_3, uint *param_4, int *param_5,
              uint *param_6, uint param_7, byte param_8, ulonglong param_9, char param_10)

{
  byte bVar1;
  uint *puVar2;
  undefined8 *_Memory;
  undefined8 uVar3;
  ulonglong uVar4;
  int iVar5;
  uint *puVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  longlong lVar10;
  uint *puVar11;
  int local_68[2];
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 *local_48;

  // 0x1cb0  11  identifyImage
  local_60 = 0;
  local_58 = 0;
  iVar5 = 0;
  local_50 = 0;
  local_48 = (undefined8 *)0x0;
  local_68[0] = 0;
  DAT_1800b2098 = (uint *)0x0;
  if ((((param_1 == (longlong *)0x0) || (param_2 == (longlong **)0x0)) || (param_4 == (uint *)0x0)) || ((param_5 == (int *)0x0 || (param_6 == (uint *)0x0))))
  {
    FUN_1800545f0();
    return 0x81;
  }
  *param_5 = 0;
  *param_4 = 0xffffffff;
  if (*param_1 == 0)
  {
    FUN_1800545f0();
    return 0x81;
  }
  if (((*(char *)((longlong)param_1 + 0xe) != '\b') ||
       (*(char *)((longlong)param_1 + 0xf) != '\x01')) ||
      (*(short *)(param_1 + 3) == 0))
  {
    FUN_1800545f0();
    return 0x81;
  }
  if (*param_2 == (longlong *)0x0)
  {
    FUN_1800545f0();
    return 0x81;
  }
  if (**param_2 == 0)
  {
    FUN_1800545f0();
    return 0x81;
  }
  if (param_3 == 0)
  {
    FUN_1800545f0();
    return 0x81;
  }
  iVar8 = (int)*(short *)((longlong)param_1 + 10);
  local_58._4_4_ = iVar8 * *(short *)(param_1 + 1);
  local_60 = CONCAT44(iVar8, (int)*(short *)(param_1 + 1));
  local_50 = 1;
  local_58._0_4_ = 0;
  _Memory = (undefined8 *)malloc((ulonglong)local_58._4_4_);
  local_48 = _Memory;
  if (_Memory == (undefined8 *)0x0)
  {
    FUN_1800545f0();
    uVar3 = 0x82;
  }
  else
  {
    local_58 = CONCAT44(local_58._4_4_, iVar8);
    memcpy_FUN_180061f90(_Memory, (undefined8 *)*param_1,
                         (longlong)((int)*(short *)((longlong)param_1 + 10) * (int)*(short *)(param_1 + 1)));
    param_6[1] = (uint) * (byte *)(param_1 + 5);
    bVar1 = *(byte *)((longlong)param_1 + 0x29);
    puVar11 = (uint *)(ulonglong)bVar1;
    *param_6 = (uint)bVar1;
    uVar9 = *(uint *)**param_2;
    if (((uVar9 < 9) && ((0x132U >> (uVar9 & 0x1f) & 1) != 0)) ||
        (iVar8 = FUN_180011ab0((int **)&DAT_1800b2090, (uint *)&local_60, param_6[1], (uint)bVar1, 1,
                               (uint *)**param_2),
         _Memory = local_48, iVar8 != 0))
    {
      FUN_1800545f0();
      free(_Memory);
      uVar3 = 0x80000001;
    }
    else
    {
      uVar9 = 0;
      if (param_3 != 0)
      {
        do
        {
          puVar2 = (uint *)**param_2;
          if (puVar2 == (uint *)0x0)
          {
            FUN_1800545f0();
            free(local_48);
            return 0x81;
          }
          if (param_10 != '\0')
          {
            uVar7 = (((DAT_1800d853c << 9 | DAT_1800d8540) << 0xb | DAT_1800d8538) << 2 |
                     DAT_1800b20ac) *
                        2 |
                    DAT_1800b20a8 | DAT_1800b20a4;
            puVar6 = puVar2;
            FUN_1800144b0(DAT_1800b2090);
            uVar4 = FUN_18003b0b0(param_9, (ulonglong)puVar6, (ulonglong)uVar7, (ulonglong)puVar11);
            if ((int)uVar4 == 0)
            {
              return 0x84;
            }
          }
          iVar8 = FUN_1800206e0(local_68, DAT_1800b2090, puVar2, param_7, (uint)param_8,
                                (undefined8 *)&DAT_1800e9750);
          iVar5 = local_68[0];
          if (iVar8 != 0)
          {
            FUN_1800545f0();
            return 0x83;
          }
          puVar11 = (uint *)(ulonglong)puVar2[8];
          FUN_1800545f0();
          if (*puVar2 - 9 < 2)
          {
            if (puVar2[0x2380] == 0)
            {
              puVar11 = (uint *)&DAT_00000004;
              do
              {
                puVar11 = (uint *)((longlong)puVar11 + -1);
              } while (puVar11 != (uint *)0x0);
            }
            else
            {
              puVar11 = puVar2 + 0x236d;
              lVar10 = 4;
              do
              {
                puVar11 = puVar11 + 5;
                lVar10 = lVar10 + -1;
              } while (lVar10 != 0);
            }
          }
          else
          {
            if (puVar2[0x2380] == 0)
            {
              puVar11 = (uint *)&DAT_00000004;
              do
              {
                puVar11 = (uint *)((longlong)puVar11 + -1);
              } while (puVar11 != (uint *)0x0);
            }
          }
          FUN_1800545f0();
          if (0 < iVar5)
          {
            *param_5 = iVar5;
            DAT_1800b2098 = puVar2;
            *param_4 = uVar9;
            free(local_48);
            goto LAB_180002155;
          }
          uVar9 = uVar9 + 1;
          param_2 = param_2 + 1;
        } while (uVar9 < param_3);
      }
      free(local_48);
      *param_5 = iVar5;
      *param_4 = 0xffffffff;
    LAB_180002155:
      uVar3 = 0;
    }
  }
  return uVar3;
}

ulonglong templateStudy(int *param_1)

{
  void **ppvVar1;
  int iVar2;
  ulonglong uVar3;
  int local_res8;
  undefined4 local_resc;

  // 0x2220  27  templateStudy
  if (param_1 == (int *)0x0)
  {
    FUN_1800545f0();
    uRam0000000000000000 = 0;
    if (DAT_1800b2090 != (uint *)0x0)
    {
      ppvVar1 = (void **)(DAT_1800b2090 + 2);
      if (((*(longlong *)(DAT_1800b2090 + 2) != 0) && (ppvVar1 != (void **)0x0)) &&
          (*ppvVar1 != (void *)0x0))
      {
        free(*ppvVar1);
        *ppvVar1 = (void *)0x0;
      }
      *(undefined8 *)(DAT_1800b2090 + 2) = 0;
      ppvVar1 = (void **)(DAT_1800b2090 + 4);
      if (((*(longlong *)(DAT_1800b2090 + 4) != 0) && (ppvVar1 != (void **)0x0)) &&
          (*ppvVar1 != (void *)0x0))
      {
        free(*ppvVar1);
        *ppvVar1 = (void *)0x0;
      }
      *(undefined8 *)(DAT_1800b2090 + 4) = 0;
      ppvVar1 = (void **)(DAT_1800b2090 + 6);
      if (((*(longlong *)(DAT_1800b2090 + 6) != 0) && (ppvVar1 != (void **)0x0)) &&
          (*ppvVar1 != (void *)0x0))
      {
        free(*ppvVar1);
        *ppvVar1 = (void *)0x0;
      }
      *(undefined8 *)(DAT_1800b2090 + 6) = 0;
      ppvVar1 = (void **)(DAT_1800b2090 + 8);
      if (((*(longlong *)(DAT_1800b2090 + 8) != 0) && (ppvVar1 != (void **)0x0)) &&
          (*ppvVar1 != (void *)0x0))
      {
        free(*ppvVar1);
        *ppvVar1 = (void *)0x0;
      }
      *(undefined8 *)(DAT_1800b2090 + 8) = 0;
      if (*(void **)(DAT_1800b2090 + 0x3e) != (void *)0x0)
      {
        free(*(void **)(DAT_1800b2090 + 0x3e));
      }
      *(undefined8 *)(DAT_1800b2090 + 0x3e) = 0;
      ppvVar1 = (void **)(DAT_1800b2090 + 0x4c);
      if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
      {
        free(*ppvVar1);
        *ppvVar1 = (void *)0x0;
      }
      *(undefined8 *)(DAT_1800b2090 + 0x4c) = 0;
      free(DAT_1800b2090);
      DAT_1800b2090 = (uint *)0x0;
    }
    return 0x81;
  }
  local_resc = 0xffffffff;
  local_res8 = 0;
  if (DAT_1800b2098 != (uint *)0x0)
  {
    uVar3 = FUN_180018a70(DAT_1800b2098, DAT_1800b2090, (uint *)&DAT_1800e9750, &local_res8);
    iVar2 = local_res8;
    if ((int)uVar3 != 0)
    {
      FUN_1800545f0();
      *param_1 = iVar2;
      if (DAT_1800b2090 == (uint *)0x0)
      {
        return uVar3 & 0xffffffff;
      }
      ppvVar1 = (void **)(DAT_1800b2090 + 2);
      if (((*(longlong *)(DAT_1800b2090 + 2) != 0) && (ppvVar1 != (void **)0x0)) &&
          (*ppvVar1 != (void *)0x0))
      {
        free(*ppvVar1);
        *ppvVar1 = (void *)0x0;
      }
      *(undefined8 *)(DAT_1800b2090 + 2) = 0;
      ppvVar1 = (void **)(DAT_1800b2090 + 4);
      if (((*(longlong *)(DAT_1800b2090 + 4) != 0) && (ppvVar1 != (void **)0x0)) &&
          (*ppvVar1 != (void *)0x0))
      {
        free(*ppvVar1);
        *ppvVar1 = (void *)0x0;
      }
      *(undefined8 *)(DAT_1800b2090 + 4) = 0;
      ppvVar1 = (void **)(DAT_1800b2090 + 6);
      if (((*(longlong *)(DAT_1800b2090 + 6) != 0) && (ppvVar1 != (void **)0x0)) &&
          (*ppvVar1 != (void *)0x0))
      {
        free(*ppvVar1);
        *ppvVar1 = (void *)0x0;
      }
      *(undefined8 *)(DAT_1800b2090 + 6) = 0;
      ppvVar1 = (void **)(DAT_1800b2090 + 8);
      if (((*(longlong *)(DAT_1800b2090 + 8) != 0) && (ppvVar1 != (void **)0x0)) &&
          (*ppvVar1 != (void *)0x0))
      {
        free(*ppvVar1);
        *ppvVar1 = (void *)0x0;
      }
      *(undefined8 *)(DAT_1800b2090 + 8) = 0;
      if (*(void **)(DAT_1800b2090 + 0x3e) != (void *)0x0)
      {
        free(*(void **)(DAT_1800b2090 + 0x3e));
      }
      *(undefined8 *)(DAT_1800b2090 + 0x3e) = 0;
      ppvVar1 = (void **)(DAT_1800b2090 + 0x4c);
      if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
      {
        free(*ppvVar1);
        *ppvVar1 = (void *)0x0;
      }
      *(undefined8 *)(DAT_1800b2090 + 0x4c) = 0;
      free(DAT_1800b2090);
      DAT_1800b2090 = (uint *)0x0;
      return uVar3 & 0xffffffff;
    }
  }
  *param_1 = local_res8;
  FUN_1800545f0();
  if (DAT_1800b2090 != (uint *)0x0)
  {
    ppvVar1 = (void **)(DAT_1800b2090 + 2);
    if (((*(longlong *)(DAT_1800b2090 + 2) != 0) && (ppvVar1 != (void **)0x0)) &&
        (*ppvVar1 != (void *)0x0))
    {
      free(*ppvVar1);
      *ppvVar1 = (void *)0x0;
    }
    *(undefined8 *)(DAT_1800b2090 + 2) = 0;
    ppvVar1 = (void **)(DAT_1800b2090 + 4);
    if (((*(longlong *)(DAT_1800b2090 + 4) != 0) && (ppvVar1 != (void **)0x0)) &&
        (*ppvVar1 != (void *)0x0))
    {
      free(*ppvVar1);
      *ppvVar1 = (void *)0x0;
    }
    *(undefined8 *)(DAT_1800b2090 + 4) = 0;
    ppvVar1 = (void **)(DAT_1800b2090 + 6);
    if (((*(longlong *)(DAT_1800b2090 + 6) != 0) && (ppvVar1 != (void **)0x0)) &&
        (*ppvVar1 != (void *)0x0))
    {
      free(*ppvVar1);
      *ppvVar1 = (void *)0x0;
    }
    *(undefined8 *)(DAT_1800b2090 + 6) = 0;
    ppvVar1 = (void **)(DAT_1800b2090 + 8);
    if (((*(longlong *)(DAT_1800b2090 + 8) != 0) && (ppvVar1 != (void **)0x0)) &&
        (*ppvVar1 != (void *)0x0))
    {
      free(*ppvVar1);
      *ppvVar1 = (void *)0x0;
    }
    *(undefined8 *)(DAT_1800b2090 + 8) = 0;
    if (*(void **)(DAT_1800b2090 + 0x3e) != (void *)0x0)
    {
      free(*(void **)(DAT_1800b2090 + 0x3e));
    }
    *(undefined8 *)(DAT_1800b2090 + 0x3e) = 0;
    ppvVar1 = (void **)(DAT_1800b2090 + 0x4c);
    if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
    {
      free(*ppvVar1);
      *ppvVar1 = (void *)0x0;
    }
    *(undefined8 *)(DAT_1800b2090 + 0x4c) = 0;
    free(DAT_1800b2090);
    DAT_1800b2090 = (uint *)0x0;
  }
  return 0;
}

undefined8 identifyUpdate(void)

{
  // 0x26d0  12  identifyUpdate
  return 0;
}

undefined8 templatePack(uint **param_1, undefined *param_2)

{
  uint *puVar1;
  int iVar2;
  ulonglong uVar3;
  uint local_res8[2];
  undefined8 local_res18[2];

  // 0x26e0  26  templatePack
  local_res18[0] = 0;
  FUN_1800545f0();
  if (((param_1 != (uint **)0x0) && (param_2 != (undefined *)0x0)) &&
      (puVar1 = *param_1, puVar1 != (uint *)0x0))
  {
    uVar3 = FUN_18000d5a0(puVar1);
    local_res8[0] = (uint)uVar3;
    iVar2 = FUN_18000a3c0(local_res18, param_2, local_res8, puVar1);
    if (iVar2 != 0)
    {
      FUN_1800545f0();
      return 0x80;
    }
    return 0;
  }
  FUN_1800545f0();
  return 0x81;
}

ulonglong templateGetPackedSize(uint **param_1)

{
  ulonglong uVar1;

  // 0x2790  25  templateGetPackedSize
  FUN_1800545f0();
  if ((param_1 != (uint **)0x0) && (*param_1 != (uint *)0x0))
  {
    uVar1 = FUN_18000d5a0(*param_1);
    FUN_1800545f0();
    return uVar1 & 0xffffffff;
  }
  return 0;
}

ulonglong templateUnPack(uint *param_1, uint param_2, uint *param_3, uint **param_4)

{
  uint uVar1;
  uint **_Memory;
  uint *local_res8;
  uint local_res10[2];
  uint *local_28[2];

  // 0x27e0  28  templateUnPack
  local_res8 = (uint *)0x0;
  local_res10[0] = param_2;
  FUN_1800545f0();
  if (((param_1 == (uint *)0x0) || (param_4 == (uint **)0x0)) || (param_2 == 0))
  {
    return 0x81;
  }
  _Memory = (uint **)malloc(8);
  if (_Memory == (uint **)0x0)
  {
    FUN_1800545f0();
    return 0x82;
  }
  local_28[0] = param_1;
  uVar1 = FUN_18000b0e0(local_28, local_res10, &local_res8, param_3);
  if (uVar1 != 0)
  {
    free(_Memory);
    return (ulonglong)uVar1;
  }
  *_Memory = local_res8;
  FUN_1800545f0();
  *param_4 = (uint *)_Memory;
  return 0;
}

void templateDelete(void **param_1)

{
  void *_Memory;
  int iVar1;
  void **ppvVar2;
  longlong lVar3;

  // 0x28d0  24  templateDelete
  FUN_1800545f0();
  if ((param_1 != (void **)0x0) && (_Memory = *param_1, _Memory != (void *)0x0))
  {
    iVar1 = 0;
    if (0 < *(int *)((longlong)_Memory + 0x20))
    {
      do
      {
        FUN_180004ab0((void **)((longlong)_Memory + ((longlong)iVar1 + 5) * 8));
        iVar1 = iVar1 + 1;
      } while (iVar1 < *(int *)((longlong)_Memory + 0x20));
    }
    ppvVar2 = (void **)((longlong)_Memory + 0x8d10);
    lVar3 = 0x14;
    do
    {
      FUN_180004ab0(ppvVar2);
      ppvVar2 = ppvVar2 + 1;
      lVar3 = lVar3 + -1;
    } while (lVar3 != 0);
    free(_Memory);
    // WARNING: Could not recover jumptable at 0x000180002966. Too many branches
    // WARNING: Treating indirect jump as call
    free(param_1);
    return;
  }
  FUN_1800545f0();
  return;
}

undefined8 getAlgorithmVersion(uint *param_1)

{
  char cVar1;
  uint *_Memory;
  uint *puVar2;
  int iVar3;
  void **ppvVar4;
  uint *puVar5;
  longlong lVar6;
  uint *local_res8;

  // 0x2990  8  getAlgorithmVersion
  iVar3 = 0;
  local_res8 = (uint *)0x0;
  if (param_1 == (uint *)0x0)
  {
    return 0x81;
  }
  FUN_180003f90(&local_res8, 0x32,
                (ulonglong)((((DAT_1800d853c << 9 | DAT_1800d8540) << 0xb | DAT_1800d8538) << 2 | DAT_1800b20ac) * 2 | DAT_1800b20a8 | DAT_1800b20a4));
  _Memory = local_res8;
  if (local_res8 != (uint *)0x0)
  {
    puVar2 = local_res8 + 0x222d;
    if ((puVar2 != (uint *)0x0) && (param_1 != puVar2))
    {
      puVar5 = (uint *)((longlong)param_1 - (longlong)puVar2);
      do
      {
        cVar1 = *(char *)puVar2;
        *(char *)((longlong)puVar5 + (longlong)puVar2) = cVar1;
        puVar2 = (uint *)((longlong)puVar2 + 1);
      } while (cVar1 != '\0');
    }
    if (0 < (int)local_res8[8])
    {
      do
      {
        FUN_180004ab0((void **)(_Memory + ((longlong)iVar3 + 5) * 2));
        iVar3 = iVar3 + 1;
      } while (iVar3 < (int)_Memory[8]);
    }
    ppvVar4 = (void **)(_Memory + 0x2344);
    lVar6 = 0x14;
    do
    {
      FUN_180004ab0(ppvVar4);
      ppvVar4 = ppvVar4 + 1;
      lVar6 = lVar6 + -1;
    } while (lVar6 != 0);
    free(_Memory);
    return 0;
  }
  return 0x80;
}

void getQuality(longlong *param_1, int *param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  longlong local_10;

  // 0x2ab0  9  getQuality
  uVar2 = (((DAT_1800d853c << 9 | DAT_1800d8540) << 0xb | DAT_1800d8538) << 2 | DAT_1800b20ac) * 2 |
          DAT_1800b20a8 | DAT_1800b20a4;
  if ((param_1 != (longlong *)0x0) && (local_10 = *param_1, local_10 != 0))
  {
    iVar3 = (int)*(short *)(param_1 + 1);
    iVar1 = (int)*(short *)((longlong)param_1 + 10);
    local_28 = CONCAT44(iVar1, iVar3);
    local_18 = 1;
    local_20 = CONCAT44(iVar1 * iVar3, iVar1);
    if ((DAT_1800d8538 == 1) || (DAT_1800d8538 == 8))
    {
      *param_2 = iVar1 * iVar3;
    }
    else
    {
      *param_2 = 0;
    }
    FUN_180013600((uint *)&local_28, uVar2, param_2 + 1, param_2);
    *(undefined *)(param_1 + 5) = *(undefined *)(param_2 + 1);
    *(undefined *)((longlong)param_1 + 0x29) = *(undefined *)param_2;
  }
  return;
}

void identifytemplate(uint **param_1, undefined8 *param_2, undefined8 param_3, uint *param_4)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  uint *puVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined8 *_Memory;
  undefined8 *puVar7;
  undefined8 *puVar8;
  longlong lVar9;
  uint uVar10;
  uint **ppuVar11;
  int local_6d8[4];
  undefined8 local_6c8[210];
  ulonglong local_38;

  // 0x2b90  13  identifytemplate
  local_38 = DAT_1800b04e8 ^ (ulonglong)&stack0xfffffffffffff8e8;
  local_6d8[0] = 0;
  if ((((param_1 != (uint **)0x0) && (param_2 != (undefined8 *)0x0)) && (param_4 != (uint *)0x0)) &&
      ((puVar3 = *param_1, puVar3 != (uint *)0x0 &&
                               (_Memory = (undefined8 *)malloc(0x8e08), _Memory != (undefined8 *)0x0))))
  {
    lVar9 = 0x11c;
    puVar7 = (undefined8 *)*param_2;
    puVar8 = _Memory;
    do
    {
      puVar1 = puVar8 + 0x10;
      uVar4 = *(undefined4 *)((longlong)puVar7 + 4);
      uVar5 = *(undefined4 *)(puVar7 + 1);
      uVar6 = *(undefined4 *)((longlong)puVar7 + 0xc);
      puVar2 = puVar7 + 0x10;
      *(undefined4 *)puVar8 = *(undefined4 *)puVar7;
      *(undefined4 *)((longlong)puVar8 + 4) = uVar4;
      *(undefined4 *)(puVar8 + 1) = uVar5;
      *(undefined4 *)((longlong)puVar8 + 0xc) = uVar6;
      uVar4 = *(undefined4 *)((longlong)puVar7 + 0x14);
      uVar5 = *(undefined4 *)(puVar7 + 3);
      uVar6 = *(undefined4 *)((longlong)puVar7 + 0x1c);
      *(undefined4 *)(puVar8 + 2) = *(undefined4 *)(puVar7 + 2);
      *(undefined4 *)((longlong)puVar8 + 0x14) = uVar4;
      *(undefined4 *)(puVar8 + 3) = uVar5;
      *(undefined4 *)((longlong)puVar8 + 0x1c) = uVar6;
      uVar4 = *(undefined4 *)((longlong)puVar7 + 0x24);
      uVar5 = *(undefined4 *)(puVar7 + 5);
      uVar6 = *(undefined4 *)((longlong)puVar7 + 0x2c);
      *(undefined4 *)(puVar8 + 4) = *(undefined4 *)(puVar7 + 4);
      *(undefined4 *)((longlong)puVar8 + 0x24) = uVar4;
      *(undefined4 *)(puVar8 + 5) = uVar5;
      *(undefined4 *)((longlong)puVar8 + 0x2c) = uVar6;
      uVar4 = *(undefined4 *)((longlong)puVar7 + 0x34);
      uVar5 = *(undefined4 *)(puVar7 + 7);
      uVar6 = *(undefined4 *)((longlong)puVar7 + 0x3c);
      *(undefined4 *)(puVar8 + 6) = *(undefined4 *)(puVar7 + 6);
      *(undefined4 *)((longlong)puVar8 + 0x34) = uVar4;
      *(undefined4 *)(puVar8 + 7) = uVar5;
      *(undefined4 *)((longlong)puVar8 + 0x3c) = uVar6;
      uVar4 = *(undefined4 *)((longlong)puVar7 + 0x44);
      uVar5 = *(undefined4 *)(puVar7 + 9);
      uVar6 = *(undefined4 *)((longlong)puVar7 + 0x4c);
      *(undefined4 *)(puVar8 + 8) = *(undefined4 *)(puVar7 + 8);
      *(undefined4 *)((longlong)puVar8 + 0x44) = uVar4;
      *(undefined4 *)(puVar8 + 9) = uVar5;
      *(undefined4 *)((longlong)puVar8 + 0x4c) = uVar6;
      uVar4 = *(undefined4 *)((longlong)puVar7 + 0x54);
      uVar5 = *(undefined4 *)(puVar7 + 0xb);
      uVar6 = *(undefined4 *)((longlong)puVar7 + 0x5c);
      *(undefined4 *)(puVar8 + 10) = *(undefined4 *)(puVar7 + 10);
      *(undefined4 *)((longlong)puVar8 + 0x54) = uVar4;
      *(undefined4 *)(puVar8 + 0xb) = uVar5;
      *(undefined4 *)((longlong)puVar8 + 0x5c) = uVar6;
      uVar4 = *(undefined4 *)((longlong)puVar7 + 100);
      uVar5 = *(undefined4 *)(puVar7 + 0xd);
      uVar6 = *(undefined4 *)((longlong)puVar7 + 0x6c);
      *(undefined4 *)(puVar8 + 0xc) = *(undefined4 *)(puVar7 + 0xc);
      *(undefined4 *)((longlong)puVar8 + 100) = uVar4;
      *(undefined4 *)(puVar8 + 0xd) = uVar5;
      *(undefined4 *)((longlong)puVar8 + 0x6c) = uVar6;
      uVar4 = *(undefined4 *)((longlong)puVar7 + 0x74);
      uVar5 = *(undefined4 *)(puVar7 + 0xf);
      uVar6 = *(undefined4 *)((longlong)puVar7 + 0x7c);
      *(undefined4 *)(puVar8 + 0xe) = *(undefined4 *)(puVar7 + 0xe);
      *(undefined4 *)((longlong)puVar8 + 0x74) = uVar4;
      *(undefined4 *)(puVar8 + 0xf) = uVar5;
      *(undefined4 *)((longlong)puVar8 + 0x7c) = uVar6;
      lVar9 = lVar9 + -1;
      puVar7 = puVar2;
      puVar8 = puVar1;
    } while (lVar9 != 0);
    uVar10 = 0;
    *puVar1 = *puVar2;
    if (*(int *)((longlong)_Memory + 0x1c) != 0)
    {
      ppuVar11 = (uint **)(_Memory + 5);
      do
      {
        FUN_1800206e0(local_6d8, *ppuVar11, puVar3, 0, 0, local_6c8);
        if (0 < local_6d8[0])
        {
          *param_4 = uVar10;
          goto LAB_180002ccb;
        }
        uVar10 = uVar10 + 1;
        ppuVar11 = ppuVar11 + 1;
      } while (uVar10 < *(uint *)((longlong)_Memory + 0x1c));
    }
    *param_4 = 0xffffffff;
  LAB_180002ccb:
    free(_Memory);
  }
  FUN_18005f100(local_38 ^ (ulonglong)&stack0xfffffffffffff8e8);
  return;
}

void init_crc_FUN_180002d20(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;

  uVar3 = 0;
  puVar4 = &crc_table_DAT_1800e9de0;
  do
  {
    uVar2 = ((int)(uVar3 << 0x18) >> 0x1f & 0x4c11db7U) * 2;
    if ((int)(uVar3 * 0x2000000) < 0)
    {
      uVar2 = uVar2 ^ 0x4c11db7;
    }
    if ((int)(uVar2 ^ uVar3 * 0x4000000) < 0)
    {
      uVar2 = uVar2 * 2 ^ 0x4c11db7;
    }
    else
    {
      uVar2 = uVar2 * 2;
    }
    if ((int)(uVar2 ^ uVar3 * 0x8000000) < 0)
    {
      uVar2 = uVar2 * 2 ^ 0x4c11db7;
    }
    else
    {
      uVar2 = uVar2 * 2;
    }
    if ((int)(uVar2 ^ uVar3 * 0x10000000) < 0)
    {
      uVar2 = uVar2 * 2 ^ 0x4c11db7;
    }
    else
    {
      uVar2 = uVar2 * 2;
    }
    if ((int)(uVar2 ^ uVar3 * 0x20000000) < 0)
    {
      uVar2 = uVar2 * 2 ^ 0x4c11db7;
    }
    else
    {
      uVar2 = uVar2 * 2;
    }
    uVar1 = uVar2 * 2;
    if ((int)(uVar2 ^ uVar3 * 0x40000000) < 0)
    {
      uVar1 = uVar1 ^ 0x4c11db7;
    }
    if ((int)(uVar3 << 0x1f ^ uVar1) < 0)
    {
      uVar1 = uVar1 * 2 ^ 0x4c11db7;
    }
    else
    {
      uVar1 = uVar1 * 2;
    }
    *puVar4 = uVar1;
    uVar3 = uVar3 + 1;
    puVar4 = puVar4 + 1;
  } while (uVar3 < 0x100);
  return;
}

void calc_crc_FUN_180002de0(byte *buffer, short len)

{
  byte bVar1;

  if (len != 0)
  {
    do
    {
      bVar1 = *buffer;
      buffer = buffer + 1;
      crc_DAT_1800b0550 =
          *(uint *)((longlong)&crc_table_DAT_1800e9de0 +
                    (ulonglong)(byte)((byte)(crc_DAT_1800b0550 >> 0x18) ^ bVar1) * 4) ^
          crc_DAT_1800b0550 << 8;
      len = len + -1;
    } while (len != 0);
  }
  return;
}

void FUN_180002e50(ushort *buffer, short len)

{
  ushort uVar1;
  uint uVar2;

  if (len != 0)
  {
    do
    {
      uVar1 = *buffer;
      buffer = buffer + 1;
      uVar2 = *(uint *)((longlong)&crc_table_DAT_1800e9de0 +
                        ((ulonglong)(crc_DAT_1800b0550 >> 0x18) ^ (ulonglong)(uVar1 >> 8)) * 4) ^
              crc_DAT_1800b0550 << 8;
      crc_DAT_1800b0550 =
          *(uint *)((longlong)&crc_table_DAT_1800e9de0 +
                    ((ulonglong)(uVar2 >> 0x18) ^ (ulonglong)(byte)uVar1) * 4) ^
          uVar2 << 8;
      len = len + -1;
    } while (len != 0);
  }
  return;
}

ulonglong FUN_1800030d0(undefined8 param_1, longlong param_2, int param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  longlong lVar4;

  uVar3 = 0xffffffff;
  if (0 < param_3)
  {
    lVar4 = 0;
    do
    {
      uVar1 = *(byte *)(lVar4 + param_2) ^ uVar3;
      uVar2 = uVar1 & 0xff;
      if ((uVar1 & 1) == 0)
      {
        uVar2 = uVar2 >> 1;
      }
      else
      {
        uVar2 = uVar2 >> 1 ^ 0xedb88320;
      }
      if ((uVar2 & 1) == 0)
      {
        uVar2 = uVar2 >> 1;
      }
      else
      {
        uVar2 = uVar2 >> 1 ^ 0xedb88320;
      }
      if ((uVar2 & 1) == 0)
      {
        uVar2 = uVar2 >> 1;
      }
      else
      {
        uVar2 = uVar2 >> 1 ^ 0xedb88320;
      }
      if ((uVar2 & 1) == 0)
      {
        uVar2 = uVar2 >> 1;
      }
      else
      {
        uVar2 = uVar2 >> 1 ^ 0xedb88320;
      }
      if ((uVar2 & 1) == 0)
      {
        uVar2 = uVar2 >> 1;
      }
      else
      {
        uVar2 = uVar2 >> 1 ^ 0xedb88320;
      }
      if ((uVar2 & 1) == 0)
      {
        uVar2 = uVar2 >> 1;
      }
      else
      {
        uVar2 = uVar2 >> 1 ^ 0xedb88320;
      }
      if ((uVar2 & 1) == 0)
      {
        uVar2 = uVar2 >> 1;
      }
      else
      {
        uVar2 = uVar2 >> 1 ^ 0xedb88320;
      }
      if ((uVar2 & 1) == 0)
      {
        uVar2 = uVar2 >> 1;
      }
      else
      {
        uVar2 = uVar2 >> 1 ^ 0xedb88320;
      }
      lVar4 = lVar4 + 1;
      uVar3 = uVar3 >> 8 ^ uVar2;
    } while (lVar4 < param_3);
  }
  return (ulonglong)uVar3;
}

ulonglong FUN_1800031d0(longlong param_1, uint param_2)

{
  byte *pbVar1;
  uint uVar2;
  ulonglong uVar3;
  ushort uVar4;
  uint uVar5;
  ushort uVar6;
  ushort uVar8;
  uint uVar7;

  uVar6 = 0;
  uVar8 = 0;
  uVar4 = 0;
  uVar5 = 0;
  uVar2 = 0;
  uVar7 = uVar2;
  if (1 < param_2)
  {
    uVar2 = (param_2 - 2 >> 1) + 1;
    uVar3 = (ulonglong)uVar2;
    uVar2 = uVar2 * 2;
    pbVar1 = (byte *)(param_1 + 1);
    do
    {
      uVar6 = uVar6 + pbVar1[-1];
      uVar7 = (uint)uVar6;
      uVar4 = uVar4 + *pbVar1;
      uVar5 = (uint)uVar4;
      uVar3 = uVar3 - 1;
      pbVar1 = pbVar1 + 2;
    } while (uVar3 != 0);
  }
  if (uVar2 < param_2)
  {
    uVar8 = (ushort) * (byte *)((ulonglong)uVar2 + param_1);
  }
  return (ulonglong)(uVar7 + uVar5 & 0xffff0000 | (uint)(ushort)((short)(uVar7 + uVar5) + uVar8));
}

void FUN_180003250(void)

{
  FUN_1800545f0();
  return;
}

void FUN_1800032a0(void)

{
  FUN_1800545f0();
  FUN_1800545f0();
  FUN_1800545f0();
  FUN_1800545f0();
  FUN_1800545f0();
  FUN_1800545f0();
  FUN_1800545f0();
  return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 ppp_param_init(uint param_1)

{
  longlong lVar1;

  // 0x3320  14  ppp_param_init
  if (0xb < param_1)
  {
    FUN_1800545f0();
    return 0x81;
  }
  _DAT_1800b20a0 = 1;
  lVar1 = (longlong)(int)param_1 * 0x20;
  DAT_1800b20a4 = *(undefined4 *)(&DAT_18007c554 + lVar1);
  DAT_1800b20ac = *(undefined4 *)(&DAT_18007c558 + lVar1);
  DAT_1800b20a8 = *(undefined4 *)(&DAT_18007c55c + lVar1);
  DAT_1800d8548 = *(undefined4 *)(&DAT_18007c560 + lVar1);
  DAT_1800d8540 = *(undefined4 *)(&DAT_18007c564 + lVar1);
  DAT_1800d853c = *(undefined4 *)(&DAT_18007c568 + lVar1);
  DAT_1800d8538 = *(undefined4 *)(&DAT_18007c56c + lVar1);
  FUN_1800545f0();
  return 0;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulonglong preprocessor_init(longlong param_1)

{
  ulonglong uVar1;
  ulonglong uVar2;
  uint uVar3;
  ulonglong uVar4;
  uint *local_res8;
  int local_res10;
  int local_res14;
  undefined4 in_stack_ffffffffffffffb0;
  undefined4 in_stack_ffffffffffffffb4;
  undefined4 in_stack_ffffffffffffffb8;
  undefined4 in_stack_ffffffffffffffbc;

  // 0x33c0  23  preprocessor_init
  local_res8 = (uint *)0x0;
  uVar2 = 0xffffffff;
  FUN_1800545f0();
  if (param_1 == 0)
  {
    return 0x81;
  }
  if (_DAT_1800b20a0 != 1)
  {
    FUN_1800545f0();
    return 0x80;
  }
  uVar3 = (((DAT_1800d853c << 9 | DAT_1800d8540) << 0xb | DAT_1800d8538) << 2 | DAT_1800b20ac) * 2 |
          DAT_1800b20a8 | DAT_1800b20a4;
  FUN_1800545f0();
  FUN_1800545f0();
  uVar4 = (ulonglong)DAT_1800b20a8;
  FUN_1800545f0();
  FUN_1800545f0();
  uVar1 = (ulonglong)DAT_1800d853c;
  FUN_1800545f0();
  DAT_1800d8544 = 0;
  if (*(undefined **)(param_1 + 0x18) != (undefined *)0x0)
  {
    uVar3 = FUN_180027640(&local_res8, *(undefined **)(param_1 + 0x18), uVar1, uVar4, uVar3,
                          CONCAT44(in_stack_ffffffffffffffb4, in_stack_ffffffffffffffb0),
                          CONCAT44(in_stack_ffffffffffffffbc, in_stack_ffffffffffffffb8), &local_res14, &local_res10, (int *)0x0);
    uVar2 = (ulonglong)uVar3;
    if (local_res8 != (uint *)0x0)
    {
      free(local_res8);
    }
  }
  FUN_1800545f0();
  uVar1 = 0;
  if (DAT_1800d8544 != 1)
  {
    uVar1 = uVar2;
  }
  return uVar1;
}

undefined8 preprocessor_exit(void)

{
  // 0x3580  21  preprocessor_exit
  FUN_1800545f0();
  DAT_1800d8544 = 0;
  memset(&DAT_1800b20b0, 0, 0x26488);
  return 0;
}

undefined8 preprocessor_get_CalibParam(undefined8 *param_1, undefined4 *param_2)

{
  // 0x35c0  22  preprocessor_get_CalibParam
  FUN_1800545f0();
  if ((param_1 != (undefined8 *)0x0) && (param_2 != (undefined4 *)0x0))
  {
    *param_1 = &DAT_1800b20b0;
    *param_2 = 0x26488;
    return 0;
  }
  return 0x80;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulonglong preprocessor(undefined8 *param_1, int *param_2, longlong *param_3, undefined *param_4)

{
  longlong lVar1;
  uint uVar2;
  uint uVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  uint *local_res8;
  undefined8 in_stack_ffffffffffffffb0;
  undefined8 in_stack_ffffffffffffffb8;

  // 0x3620  20  preprocessor
  uVar4 = 0;
  local_res8 = (uint *)0x0;
  if ((param_1 == (undefined8 *)0x0) || (param_3 == (longlong *)0x0))
  {
    FUN_1800545f0();
    return 0x81;
  }
  if (_DAT_1800b20a0 != 1)
  {
    FUN_1800545f0();
    return 0x80;
  }
  if (DAT_1800d8544 == 1)
  {
    uVar2 = FUN_180027640(&local_res8, (undefined *)*param_1, param_3, param_4,
                          (((DAT_1800d853c << 9 | DAT_1800d8540) << 0xb | DAT_1800d8538) << 2 |
                           DAT_1800b20ac) *
                                  2 |
                              DAT_1800b20a8 | DAT_1800b20a4,
                          in_stack_ffffffffffffffb0, in_stack_ffffffffffffffb8, (int *)(param_4 + 4),
                          (int *)param_4, param_2);
    FUN_1800545f0();
    *(undefined *)(param_3 + 5) = param_4[4];
    *(undefined *)((longlong)param_3 + 0x29) = *param_4;
    if (local_res8 != (uint *)0x0)
    {
      lVar1 = *(longlong *)(local_res8 + 6);
      uVar5 = uVar4;
      if (*(int *)((longlong)param_3 + 0x14) != 0)
      {
        do
        {
          uVar3 = (int)uVar4 + 1;
          uVar4 = (ulonglong)uVar3;
          *(undefined *)(uVar5 + *param_3) = *(undefined *)(uVar5 + lVar1);
          uVar5 = uVar5 + 1;
        } while (uVar3 < *(uint *)((longlong)param_3 + 0x14));
      }
      free(local_res8);
    }
    return (ulonglong)uVar2;
  }
  FUN_1800545f0();
  return 0x80;
}

undefined8 preprocess_get_calidata_len(void)

{
  // 0x3790  15  preprocess_get_calidata_len
  return 0x184ac;
}

undefined8 preprocess_save_calidata(undefined4 *param_1, uint *param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  ulonglong uVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  char *pcVar9;
  longlong lVar10;
  int iVar11;

  // 0x37a0  18  preprocess_save_calidata
  if ((param_1 != (undefined4 *)0x0) && (0x184ab < *param_2))
  {
    uVar6 = (ulonglong)(uint)(DAT_1800d8540 * DAT_1800d853c) * 2;
    memcpy_FUN_180061f90((undefined8 *)(param_1 + 2), (undefined8 *)&DAT_1800b20b4, uVar6);
    memcpy_FUN_180061f90((undefined8 *)(param_1 + 0x264a), (undefined8 *)&DAT_1800bb9d4, uVar6);
    param_1[0x6122] = DAT_1800b20b0;
    lVar10 = 0x10;
    *(undefined8 *)(param_1 + 0x6123) = 0;
    *(undefined8 *)(param_1 + 0x6125) = 0;
    *(undefined8 *)(param_1 + 0x6127) = 0;
    *(undefined8 *)(param_1 + 0x6129) = 0;
    param_1[0x6123] = 0x70657250;
    param_1[0x6124] = 0x65636f72;
    param_1[0x6125] = 0x765f7373;
    param_1[0x6126] = 0x302e315f;
    param_1[0x6127] = 0x31302e31;
    puVar4 = param_1 + 0x4c92;
    puVar7 = &DAT_1800dcf90;
    do
    {
      uVar1 = puVar7[1];
      uVar2 = puVar7[2];
      uVar3 = puVar7[3];
      *puVar4 = *puVar7;
      puVar4[1] = uVar1;
      puVar4[2] = uVar2;
      puVar4[3] = uVar3;
      uVar1 = puVar7[5];
      uVar2 = puVar7[6];
      uVar3 = puVar7[7];
      puVar4[4] = puVar7[4];
      puVar4[5] = uVar1;
      puVar4[6] = uVar2;
      puVar4[7] = uVar3;
      uVar1 = puVar7[9];
      uVar2 = puVar7[10];
      uVar3 = puVar7[0xb];
      puVar4[8] = puVar7[8];
      puVar4[9] = uVar1;
      puVar4[10] = uVar2;
      puVar4[0xb] = uVar3;
      uVar1 = puVar7[0xd];
      uVar2 = puVar7[0xe];
      uVar3 = puVar7[0xf];
      puVar4[0xc] = puVar7[0xc];
      puVar4[0xd] = uVar1;
      puVar4[0xe] = uVar2;
      puVar4[0xf] = uVar3;
      uVar1 = puVar7[0x11];
      uVar2 = puVar7[0x12];
      uVar3 = puVar7[0x13];
      puVar4[0x10] = puVar7[0x10];
      puVar4[0x11] = uVar1;
      puVar4[0x12] = uVar2;
      puVar4[0x13] = uVar3;
      uVar1 = puVar7[0x15];
      uVar2 = puVar7[0x16];
      uVar3 = puVar7[0x17];
      puVar4[0x14] = puVar7[0x14];
      puVar4[0x15] = uVar1;
      puVar4[0x16] = uVar2;
      puVar4[0x17] = uVar3;
      uVar1 = puVar7[0x19];
      uVar2 = puVar7[0x1a];
      uVar3 = puVar7[0x1b];
      puVar4[0x18] = puVar7[0x18];
      puVar4[0x19] = uVar1;
      puVar4[0x1a] = uVar2;
      puVar4[0x1b] = uVar3;
      uVar1 = puVar7[0x1d];
      uVar2 = puVar7[0x1e];
      uVar3 = puVar7[0x1f];
      puVar4[0x1c] = puVar7[0x1c];
      puVar4[0x1d] = uVar1;
      puVar4[0x1e] = uVar2;
      puVar4[0x1f] = uVar3;
      lVar10 = lVar10 + -1;
      puVar4 = puVar4 + 0x20;
      puVar7 = puVar7 + 0x20;
    } while (lVar10 != 0);
    lVar10 = 0x94;
    puVar4 = &DAT_1800d8550;
    puVar7 = param_1 + 0x4e92;
    do
    {
      puVar8 = puVar7;
      puVar5 = puVar4;
      uVar1 = puVar5[1];
      uVar2 = puVar5[2];
      uVar3 = puVar5[3];
      *puVar8 = *puVar5;
      puVar8[1] = uVar1;
      puVar8[2] = uVar2;
      puVar8[3] = uVar3;
      uVar1 = puVar5[5];
      uVar2 = puVar5[6];
      uVar3 = puVar5[7];
      puVar8[4] = puVar5[4];
      puVar8[5] = uVar1;
      puVar8[6] = uVar2;
      puVar8[7] = uVar3;
      uVar1 = puVar5[9];
      uVar2 = puVar5[10];
      uVar3 = puVar5[0xb];
      puVar8[8] = puVar5[8];
      puVar8[9] = uVar1;
      puVar8[10] = uVar2;
      puVar8[0xb] = uVar3;
      uVar1 = puVar5[0xd];
      uVar2 = puVar5[0xe];
      uVar3 = puVar5[0xf];
      puVar8[0xc] = puVar5[0xc];
      puVar8[0xd] = uVar1;
      puVar8[0xe] = uVar2;
      puVar8[0xf] = uVar3;
      uVar1 = puVar5[0x11];
      uVar2 = puVar5[0x12];
      uVar3 = puVar5[0x13];
      puVar8[0x10] = puVar5[0x10];
      puVar8[0x11] = uVar1;
      puVar8[0x12] = uVar2;
      puVar8[0x13] = uVar3;
      uVar1 = puVar5[0x15];
      uVar2 = puVar5[0x16];
      uVar3 = puVar5[0x17];
      puVar8[0x14] = puVar5[0x14];
      puVar8[0x15] = uVar1;
      puVar8[0x16] = uVar2;
      puVar8[0x17] = uVar3;
      uVar1 = puVar5[0x19];
      uVar2 = puVar5[0x1a];
      uVar3 = puVar5[0x1b];
      puVar8[0x18] = puVar5[0x18];
      puVar8[0x19] = uVar1;
      puVar8[0x1a] = uVar2;
      puVar8[0x1b] = uVar3;
      uVar1 = puVar5[0x1d];
      uVar2 = puVar5[0x1e];
      uVar3 = puVar5[0x1f];
      puVar8[0x1c] = puVar5[0x1c];
      puVar8[0x1d] = uVar1;
      puVar8[0x1e] = uVar2;
      puVar8[0x1f] = uVar3;
      lVar10 = lVar10 + -1;
      puVar4 = puVar5 + 0x20;
      puVar7 = puVar8 + 0x20;
    } while (lVar10 != 0);
    uVar1 = puVar5[0x21];
    uVar2 = puVar5[0x22];
    uVar3 = puVar5[0x23];
    puVar8[0x20] = puVar5[0x20];
    puVar8[0x21] = uVar1;
    puVar8[0x22] = uVar2;
    puVar8[0x23] = uVar3;
    uVar1 = puVar5[0x25];
    uVar2 = puVar5[0x26];
    uVar3 = puVar5[0x27];
    puVar8[0x24] = puVar5[0x24];
    puVar8[0x25] = uVar1;
    puVar8[0x26] = uVar2;
    puVar8[0x27] = uVar3;
    uVar1 = puVar5[0x29];
    uVar2 = puVar5[0x2a];
    uVar3 = puVar5[0x2b];
    puVar8[0x28] = puVar5[0x28];
    puVar8[0x29] = uVar1;
    puVar8[0x2a] = uVar2;
    puVar8[0x2b] = uVar3;
    uVar1 = puVar5[0x2d];
    uVar2 = puVar5[0x2e];
    uVar3 = puVar5[0x2f];
    puVar8[0x2c] = puVar5[0x2c];
    puVar8[0x2d] = uVar1;
    puVar8[0x2e] = uVar2;
    puVar8[0x2f] = uVar3;
    FUN_1800545f0();
    pcVar9 = "pCaliData->version: %s";
    FUN_1800545f0();
    iVar11 = DAT_1800d8540 * DAT_1800d853c * 2;
    uVar6 = FUN_1800030d0(pcVar9, (longlong)(param_1 + 2), iVar11);
    *param_1 = (int)uVar6;
    uVar6 = FUN_1800030d0(pcVar9, (longlong)(param_1 + 0x264a), iVar11);
    param_1[1] = (int)uVar6;
    *param_2 = 0x184ac;
    return 0;
  }
  return 0x81;
}

undefined8 preprocess_load_calidata(int *param_1, uint param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  ulonglong uVar6;
  int *piVar7;
  int *piVar8;
  int *piVar9;
  int *piVar10;
  uint uVar11;
  longlong lVar12;
  uint uVar13;
  int iVar14;

  // 0x39d0  17  preprocess_load_calidata
  if ((param_1 == (int *)0x0) || (param_2 < 0x184ac))
  {
    FUN_1800545f0();
    return 0x81;
  }
  if (((*(longlong *)(param_1 + 0x6123) == 0x65636f7270657250) &&
       (*(longlong *)(param_1 + 0x6125) == 0x302e315f765f7373)) &&
      (param_1[0x6127] == 0x31302e31))
  {
    iVar14 = DAT_1800d8540 * DAT_1800d853c * 2;
    piVar7 = param_1;
    uVar6 = FUN_1800030d0(param_1, (longlong)(param_1 + 2), iVar14);
    if ((*param_1 == (int)uVar6) &&
        (uVar6 = FUN_1800030d0(piVar7, (longlong)(param_1 + 0x264a), iVar14), param_1[1] == (int)uVar6))
    {
      FUN_1800545f0();
      uVar5 = DAT_1800d8540;
      uVar4 = DAT_1800d853c;
      uVar13 = 0;
      if (DAT_1800d8540 != 0)
      {
        do
        {
          uVar11 = 0;
          if (uVar4 != 0)
          {
            do
            {
              uVar1 = uVar4 * uVar13 + uVar11;
              uVar11 = uVar11 + 1;
              uVar6 = (ulonglong)uVar1;
              *(undefined2 *)(&DAT_1800b20b4 + uVar6 * 2) =
                  *(undefined2 *)((longlong)param_1 + (ulonglong)uVar1 * 2 + 8);
              *(undefined2 *)((longlong)&DAT_1800bb9d4 + uVar6 * 2) =
                  *(undefined2 *)((longlong)param_1 + uVar6 * 2 + 0x9928);
            } while (uVar11 < uVar4);
          }
          uVar13 = uVar13 + 1;
        } while (uVar13 < uVar5);
      }
      lVar12 = 0x10;
      piVar7 = param_1 + 0x4c92;
      piVar9 = &DAT_1800dcf90;
      do
      {
        iVar14 = piVar7[1];
        iVar2 = piVar7[2];
        iVar3 = piVar7[3];
        *piVar9 = *piVar7;
        piVar9[1] = iVar14;
        piVar9[2] = iVar2;
        piVar9[3] = iVar3;
        iVar14 = piVar7[5];
        iVar2 = piVar7[6];
        iVar3 = piVar7[7];
        piVar9[4] = piVar7[4];
        piVar9[5] = iVar14;
        piVar9[6] = iVar2;
        piVar9[7] = iVar3;
        iVar14 = piVar7[9];
        iVar2 = piVar7[10];
        iVar3 = piVar7[0xb];
        piVar9[8] = piVar7[8];
        piVar9[9] = iVar14;
        piVar9[10] = iVar2;
        piVar9[0xb] = iVar3;
        iVar14 = piVar7[0xd];
        iVar2 = piVar7[0xe];
        iVar3 = piVar7[0xf];
        piVar9[0xc] = piVar7[0xc];
        piVar9[0xd] = iVar14;
        piVar9[0xe] = iVar2;
        piVar9[0xf] = iVar3;
        iVar14 = piVar7[0x11];
        iVar2 = piVar7[0x12];
        iVar3 = piVar7[0x13];
        piVar9[0x10] = piVar7[0x10];
        piVar9[0x11] = iVar14;
        piVar9[0x12] = iVar2;
        piVar9[0x13] = iVar3;
        iVar14 = piVar7[0x15];
        iVar2 = piVar7[0x16];
        iVar3 = piVar7[0x17];
        piVar9[0x14] = piVar7[0x14];
        piVar9[0x15] = iVar14;
        piVar9[0x16] = iVar2;
        piVar9[0x17] = iVar3;
        iVar14 = piVar7[0x19];
        iVar2 = piVar7[0x1a];
        iVar3 = piVar7[0x1b];
        piVar9[0x18] = piVar7[0x18];
        piVar9[0x19] = iVar14;
        piVar9[0x1a] = iVar2;
        piVar9[0x1b] = iVar3;
        iVar14 = piVar7[0x1d];
        iVar2 = piVar7[0x1e];
        iVar3 = piVar7[0x1f];
        piVar9[0x1c] = piVar7[0x1c];
        piVar9[0x1d] = iVar14;
        piVar9[0x1e] = iVar2;
        piVar9[0x1f] = iVar3;
        lVar12 = lVar12 + -1;
        piVar7 = piVar7 + 0x20;
        piVar9 = piVar9 + 0x20;
      } while (lVar12 != 0);
      lVar12 = 0x94;
      piVar7 = &DAT_1800d8550;
      piVar9 = param_1 + 0x4e92;
      do
      {
        piVar10 = piVar9;
        piVar8 = piVar7;
        iVar14 = piVar10[1];
        iVar2 = piVar10[2];
        iVar3 = piVar10[3];
        *piVar8 = *piVar10;
        piVar8[1] = iVar14;
        piVar8[2] = iVar2;
        piVar8[3] = iVar3;
        iVar14 = piVar10[5];
        iVar2 = piVar10[6];
        iVar3 = piVar10[7];
        piVar8[4] = piVar10[4];
        piVar8[5] = iVar14;
        piVar8[6] = iVar2;
        piVar8[7] = iVar3;
        iVar14 = piVar10[9];
        iVar2 = piVar10[10];
        iVar3 = piVar10[0xb];
        piVar8[8] = piVar10[8];
        piVar8[9] = iVar14;
        piVar8[10] = iVar2;
        piVar8[0xb] = iVar3;
        iVar14 = piVar10[0xd];
        iVar2 = piVar10[0xe];
        iVar3 = piVar10[0xf];
        piVar8[0xc] = piVar10[0xc];
        piVar8[0xd] = iVar14;
        piVar8[0xe] = iVar2;
        piVar8[0xf] = iVar3;
        iVar14 = piVar10[0x11];
        iVar2 = piVar10[0x12];
        iVar3 = piVar10[0x13];
        piVar8[0x10] = piVar10[0x10];
        piVar8[0x11] = iVar14;
        piVar8[0x12] = iVar2;
        piVar8[0x13] = iVar3;
        iVar14 = piVar10[0x15];
        iVar2 = piVar10[0x16];
        iVar3 = piVar10[0x17];
        piVar8[0x14] = piVar10[0x14];
        piVar8[0x15] = iVar14;
        piVar8[0x16] = iVar2;
        piVar8[0x17] = iVar3;
        iVar14 = piVar10[0x19];
        iVar2 = piVar10[0x1a];
        iVar3 = piVar10[0x1b];
        piVar8[0x18] = piVar10[0x18];
        piVar8[0x19] = iVar14;
        piVar8[0x1a] = iVar2;
        piVar8[0x1b] = iVar3;
        iVar14 = piVar10[0x1d];
        iVar2 = piVar10[0x1e];
        iVar3 = piVar10[0x1f];
        piVar8[0x1c] = piVar10[0x1c];
        piVar8[0x1d] = iVar14;
        piVar8[0x1e] = iVar2;
        piVar8[0x1f] = iVar3;
        lVar12 = lVar12 + -1;
        piVar7 = piVar8 + 0x20;
        piVar9 = piVar10 + 0x20;
      } while (lVar12 != 0);
      iVar14 = piVar10[0x21];
      iVar2 = piVar10[0x22];
      iVar3 = piVar10[0x23];
      piVar8[0x20] = piVar10[0x20];
      piVar8[0x21] = iVar14;
      piVar8[0x22] = iVar2;
      piVar8[0x23] = iVar3;
      iVar14 = piVar10[0x25];
      iVar2 = piVar10[0x26];
      iVar3 = piVar10[0x27];
      piVar8[0x24] = piVar10[0x24];
      piVar8[0x25] = iVar14;
      piVar8[0x26] = iVar2;
      piVar8[0x27] = iVar3;
      iVar14 = piVar10[0x29];
      iVar2 = piVar10[0x2a];
      iVar3 = piVar10[0x2b];
      piVar8[0x28] = piVar10[0x28];
      piVar8[0x29] = iVar14;
      piVar8[0x2a] = iVar2;
      piVar8[0x2b] = iVar3;
      iVar14 = piVar10[0x2d];
      iVar2 = piVar10[0x2e];
      iVar3 = piVar10[0x2f];
      piVar8[0x2c] = piVar10[0x2c];
      piVar8[0x2d] = iVar14;
      piVar8[0x2e] = iVar2;
      piVar8[0x2f] = iVar3;
      DAT_1800b20b0 = param_1[0x6122];
      return 0;
    }
    FUN_1800545f0();
    return 0x80;
  }
  FUN_1800545f0();
  return 0x80;
}

undefined8 preprocess_init_calidata(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  longlong lVar5;
  ulonglong uVar6;
  uint uVar7;
  undefined2 *puVar8;
  uint uVar9;
  ulonglong uVar10;
  uint uVar11;

  // 0x3c30  16  preprocess_init_calidata
  FUN_1800545f0();
  uVar3 = DAT_1800d8540;
  uVar2 = DAT_1800d853c;
  uVar11 = 0;
  if (DAT_1800d8540 != 0)
  {
    do
    {
      uVar9 = 0;
      if (uVar2 != 0)
      {
        uVar4 = uVar9;
        if (7 < uVar2)
        {
          uVar7 = uVar2 * uVar11;
          lVar5 = (longlong)(int)((uVar2 - 1) + uVar7);
          if ((&DAT_1800b20b4 + lVar5 * 2 <
               (undefined *)((longlong)&DAT_1800bb9d4 + (longlong)(int)uVar7 * 2)) ||
              (uVar4 = 0,
               (undefined *)((longlong)&DAT_1800bb9d4 + lVar5 * 2) <
                   &DAT_1800b20b4 + (longlong)(int)uVar7 * 2))
          {
            uVar4 = uVar2 - (uVar2 & 7);
            do
            {
              uVar9 = uVar9 + 8;
            } while (uVar9 < uVar4);
            iVar1 = uVar4 + 7;
            uVar10 = (longlong)((int)(iVar1 + (iVar1 >> 0x1f & 7U)) >> 3) << 4;
            uVar6 = uVar10 >> 1;
            puVar8 = (undefined2 *)(&DAT_1800b20b4 + (ulonglong)uVar7 * 2);
            while (uVar6 != 0)
            {
              uVar6 = uVar6 - 1;
              *puVar8 = 0x2000;
              puVar8 = puVar8 + 1;
            }
            uVar10 = uVar10 >> 1;
            puVar8 = (undefined2 *)((longlong)&DAT_1800bb9d4 + (ulonglong)uVar7 * 2);
            while (uVar4 = uVar9, uVar10 != 0)
            {
              uVar10 = uVar10 - 1;
              *puVar8 = 0;
              puVar8 = puVar8 + 1;
            }
          }
        }
        if (uVar4 < uVar2)
        {
          do
          {
            uVar6 = (ulonglong)(uVar2 * uVar11 + uVar4);
            uVar4 = uVar4 + 1;
            *(undefined2 *)(&DAT_1800b20b4 + uVar6 * 2) = 0x2000;
            *(undefined2 *)((longlong)&DAT_1800bb9d4 + uVar6 * 2) = 0;
          } while (uVar4 < uVar2);
        }
      }
      uVar11 = uVar11 + 1;
    } while (uVar11 < uVar3);
  }
  DAT_1800b20b0 = 0;
  return 0;
}

undefined8 preprocess_set_mode(undefined4 param_1)

{
  // 0x3da0  19  preprocess_set_mode
  DAT_1800d8544 = param_1;
  return 0;
}

undefined8 FUN_180003f90(uint **param_1, uint param_2, ulonglong param_3)

{
  undefined4 *puVar1;
  char cVar2;
  uint *puVar3;
  int iVar4;
  uint *puVar5;
  undefined8 *puVar6;
  int *piVar7;
  void *pvVar8;
  undefined8 *puVar9;
  int iVar10;
  longlong lVar11;
  longlong lVar12;
  ulonglong uVar13;
  uint uVar14;
  longlong lVar15;
  char *pcVar16;
  uint uVar17;
  longlong *plVar18;
  int iVar19;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  uint uVar23;
  int iVar24;
  int iVar25;
  int iVar26;
  uint local_res18;

  uVar13 = (param_3 & 0xffffffff) >> 0x17;
  uVar17 = (int)param_3 >> 3 & 0x3f;
  uVar20 = (int)param_3 >> 0xe & 0x1ff;
  puVar5 = (uint *)malloc(0x8e08);
  *param_1 = puVar5;
  uVar23 = 0;
  if (uVar17 != 0x14)
  {
    uVar23 = uVar17;
  }
  if (puVar5 == (uint *)0x0)
  {
    return 0x80000004;
  }
  uVar14 = 0x32;
  local_res18 = 0xa0;
  uVar21 = 0;
  uVar22 = 0;
  switch (uVar17)
  {
  default:
    local_res18 = 0x96;
    uVar14 = 0x28;
    uVar21 = 1;
    uVar22 = 1;
    if ((int)uVar13 == 0x6c)
    {
      uVar13 = 0x68;
    }
    break;
  case 1:
  case 5:
  case 8:
  case 0xb:
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
  case 0x20:
  case 0x21:
  case 0x22:
  case 0x23:
  case 0x24:
  case 0x25:
  case 0x26:
  case 0x27:
  case 0x28:
  case 0x29:
  case 0x2a:
  case 0x2b:
  case 0x2c:
  case 0x2d:
  case 0x2e:
  case 0x2f:
  case 0x30:
  case 0x31:
  case 0x32:
  case 0x33:
  case 0x34:
  case 0x35:
  case 0x36:
  case 0x37:
  case 0x38:
  case 0x39:
  case 0x3a:
  case 0x3b:
  case 0x3c:
  case 0x3d:
    break;
  case 2:
    uVar14 = 0x1e;
    local_res18 = 0x96;
    goto LAB_1800040c5;
  case 3:
    uVar14 = 0xf;
    local_res18 = 0x96;
    goto LAB_1800040c5;
  case 4:
    uVar14 = 0x28;
    local_res18 = 0x96;
    uVar21 = 0;
    uVar22 = 0;
    break;
  case 6:
  case 7:
  case 0x3e:
    uVar14 = 0x28;
    local_res18 = 0x96;
    goto LAB_1800040c5;
  case 9:
    uVar14 = 0x2d;
    local_res18 = 0x96;
    uVar21 = 0;
    uVar22 = 1;
    break;
  case 10:
    local_res18 = 0x78;
    uVar21 = 0;
    uVar22 = 1;
    break;
  case 0x3f:
    local_res18 = 0x8c;
    uVar14 = 0x32;
    if ((int)uVar13 == 0x76)
    {
      uVar13 = 0x78;
    }
  LAB_1800040c5:
    uVar21 = 1;
    uVar22 = 1;
  }
  *puVar5 = uVar23;
  if (param_2 < uVar14)
  {
    uVar14 = param_2;
  }
  (*param_1)[1] = (uint)uVar13;
  (*param_1)[2] = uVar20;
  (*param_1)[3] = uVar21;
  (*param_1)[4] = uVar22;
  (*param_1)[5] = local_res18;
  (*param_1)[6] = local_res18;
  (*param_1)[7] = 0;
  (*param_1)[8] = uVar14;
  (*param_1)[9] = 0;
  puVar3 = *param_1;
  plVar18 = (longlong *)(puVar3 + 10);
  if (puVar3[3] != 0)
  {
    uVar13 = (ulonglong)((uint)uVar13 >> 1);
    uVar20 = uVar20 >> 1;
  }
  iVar19 = (int)uVar13;
  iVar26 = 0;
  iVar10 = (int)(uVar13 >> 3);
  iVar24 = iVar10 + 1;
  if (iVar19 == iVar10 * 8)
  {
    iVar24 = iVar10;
  }
  if (0 < (int)puVar3[8])
  {
    uVar17 = uVar20 * iVar19;
    iVar4 = (int)uVar17 >> 3;
    iVar10 = iVar4 + 1;
    if (uVar17 <= (uint)(iVar4 * 8))
    {
      iVar10 = iVar4;
    }
    do
    {
      puVar6 = (undefined8 *)malloc(0x158);
      *plVar18 = (longlong)puVar6;
      if (puVar6 != (undefined8 *)0x0)
      {
        lVar11 = 5;
        do
        {
          puVar9 = puVar6;
          *puVar9 = 0;
          puVar9[1] = 0;
          puVar9[2] = 0;
          puVar9[3] = 0;
          puVar9[4] = 0;
          puVar9[5] = 0;
          puVar9[6] = 0;
          puVar9[7] = 0;
          lVar11 = lVar11 + -1;
          puVar6 = puVar9 + 8;
        } while (lVar11 != 0);
        puVar9[8] = 0;
        puVar9[9] = 0;
        puVar9[10] = 0;
      }
      piVar7 = (int *)malloc((longlong)iVar10 + 0x20);
      if (piVar7 != (int *)0x0)
      {
        piVar7[3] = iVar10;
        *piVar7 = iVar19;
        piVar7[1] = uVar20;
        piVar7[4] = 8;
        piVar7[2] = -1;
        *(int **)(piVar7 + 6) = piVar7 + 8;
      }
      *(int **)(*plVar18 + 8) = piVar7;
      iVar25 = iVar4 + 1;
      if (uVar17 <= (uint)(iVar4 * 8))
      {
        iVar25 = iVar4;
      }
      piVar7 = (int *)malloc((longlong)iVar25 + 0x20);
      if (piVar7 != (int *)0x0)
      {
        piVar7[3] = iVar25;
        *piVar7 = iVar19;
        piVar7[1] = uVar20;
        piVar7[4] = 8;
        piVar7[2] = -1;
        *(int **)(piVar7 + 6) = piVar7 + 8;
      }
      *(int **)(*plVar18 + 0x10) = piVar7;
      if ((ulonglong)uVar23 - 9 < 2)
      {
        *(undefined8 *)(*plVar18 + 0x18) = 0;
      }
      else
      {
        piVar7 = (int *)malloc((longlong)iVar25 + 0x20);
        if (piVar7 == (int *)0x0)
        {
          *(undefined8 *)(*plVar18 + 0x18) = 0;
        }
        else
        {
          piVar7[3] = iVar25;
          *piVar7 = iVar19;
          piVar7[1] = uVar20;
          piVar7[4] = 8;
          piVar7[2] = -1;
          *(int **)(piVar7 + 6) = piVar7 + 8;
          *(int **)(*plVar18 + 0x18) = piVar7;
        }
      }
      pvVar8 = malloc((ulonglong)local_res18 * 0x38);
      *(void **)(*plVar18 + 0xf8) = pvVar8;
      piVar7 = (int *)malloc((ulonglong)(iVar24 * uVar20) + 0x20);
      if (piVar7 != (int *)0x0)
      {
        piVar7[3] = iVar24 * uVar20;
        *(int **)(piVar7 + 6) = piVar7 + 8;
        *piVar7 = iVar24;
        piVar7[1] = uVar20;
        piVar7[4] = 1;
        piVar7[2] = iVar24;
      }
      iVar26 = iVar26 + 1;
      *(int **)(*plVar18 + 0x130) = piVar7;
      *(undefined8 *)(*plVar18 + 0x20) = 0;
      lVar11 = *plVar18;
      plVar18 = plVar18 + 1;
      *(undefined8 *)(lVar11 + 0x140) = 0;
    } while (iVar26 < (int)(*param_1)[8]);
  }
  puVar3 = *param_1;
  plVar18 = (longlong *)(puVar3 + 0x2344);
  if ((undefined8 *)(puVar3 + 0x236c) != (undefined8 *)0x0)
  {
    *(undefined8 *)(puVar3 + 0x236c) = 0xffffffffffffffff;
    *(undefined8 *)(puVar3 + 0x236e) = 0xffffffffffffffff;
    *(undefined8 *)(puVar3 + 0x2370) = 0xffffffffffffffff;
    *(undefined8 *)(puVar3 + 0x2372) = 0xffffffffffffffff;
    *(undefined8 *)(puVar3 + 0x2374) = 0xffffffffffffffff;
    *(undefined8 *)(puVar3 + 0x2376) = 0xffffffffffffffff;
    *(undefined8 *)(puVar3 + 0x2378) = 0xffffffffffffffff;
    *(undefined8 *)(puVar3 + 0x237a) = 0xffffffffffffffff;
    *(undefined8 *)(puVar3 + 0x237c) = 0xffffffffffffffff;
    *(undefined8 *)(puVar3 + 0x237e) = 0xffffffffffffffff;
  }
  if ((undefined8 *)(*param_1 + 0x2380) != (undefined8 *)0x0)
  {
    *(undefined8 *)(*param_1 + 0x2380) = 0;
  }
  lVar11 = 0x14;
  uVar17 = uVar20 * iVar19;
  do
  {
    puVar6 = (undefined8 *)malloc(0x158);
    *plVar18 = (longlong)puVar6;
    if (puVar6 != (undefined8 *)0x0)
    {
      lVar12 = 5;
      do
      {
        puVar9 = puVar6;
        *puVar9 = 0;
        puVar9[1] = 0;
        puVar9[2] = 0;
        puVar9[3] = 0;
        puVar9[4] = 0;
        puVar9[5] = 0;
        puVar9[6] = 0;
        puVar9[7] = 0;
        lVar12 = lVar12 + -1;
        puVar6 = puVar9 + 8;
      } while (lVar12 != 0);
      puVar9[8] = 0;
      puVar9[9] = 0;
      puVar9[10] = 0;
    }
    uVar21 = (uVar17 >> 3) + 1;
    if (uVar17 <= (uVar17 & 0xfffffff8))
    {
      uVar21 = uVar17 >> 3;
    }
    uVar13 = (ulonglong)uVar21;
    piVar7 = (int *)malloc(uVar13 + 0x20);
    if (piVar7 != (int *)0x0)
    {
      piVar7[3] = uVar21;
      *piVar7 = iVar19;
      piVar7[1] = uVar20;
      piVar7[4] = 8;
      piVar7[2] = -1;
      *(int **)(piVar7 + 6) = piVar7 + 8;
    }
    *(int **)(*plVar18 + 8) = piVar7;
    piVar7 = (int *)malloc(uVar13 + 0x20);
    if (piVar7 != (int *)0x0)
    {
      piVar7[3] = uVar21;
      *piVar7 = iVar19;
      piVar7[1] = uVar20;
      piVar7[4] = 8;
      piVar7[2] = -1;
      *(int **)(piVar7 + 6) = piVar7 + 8;
    }
    *(int **)(*plVar18 + 0x10) = piVar7;
    if ((ulonglong)uVar23 - 9 < 2)
    {
      *(undefined8 *)(*plVar18 + 0x18) = 0;
    }
    else
    {
      piVar7 = (int *)malloc(uVar13 + 0x20);
      if (piVar7 == (int *)0x0)
      {
        *(undefined8 *)(*plVar18 + 0x18) = 0;
      }
      else
      {
        piVar7[3] = uVar21;
        *piVar7 = iVar19;
        piVar7[1] = uVar20;
        piVar7[4] = 8;
        piVar7[2] = -1;
        *(int **)(piVar7 + 6) = piVar7 + 8;
        *(int **)(*plVar18 + 0x18) = piVar7;
      }
    }
    pvVar8 = malloc((ulonglong)local_res18 * 0x38);
    *(void **)(*plVar18 + 0xf8) = pvVar8;
    piVar7 = (int *)malloc((ulonglong)(iVar24 * uVar20) + 0x20);
    if (piVar7 == (int *)0x0)
    {
      piVar7 = (int *)0x0;
    }
    else
    {
      piVar7[3] = iVar24 * uVar20;
      *piVar7 = iVar24;
      piVar7[1] = uVar20;
      piVar7[4] = 1;
      piVar7[2] = iVar24;
      *(int **)(piVar7 + 6) = piVar7 + 8;
    }
    lVar15 = 0;
    *(int **)(*plVar18 + 0x130) = piVar7;
    *(undefined8 *)(*plVar18 + 0x20) = 0;
    lVar12 = *plVar18;
    plVar18 = plVar18 + 1;
    *(undefined8 *)(lVar12 + 0x140) = 0;
    lVar11 = lVar11 + -1;
  } while (lVar11 != 0);
  do
  {
    puVar3 = *param_1;
    puVar1 = (undefined4 *)((longlong)puVar3 + lVar15 + 0x1b8);
    *puVar1 = 0xffffffff;
    puVar1[1] = 0x100;
    puVar1[2] = 0;
    puVar1[3] = 0;
    *(undefined8 *)((longlong)puVar3 + lVar15 + 0x1c8) = 0x10000000000;
    *(undefined4 *)((longlong)puVar3 + lVar15 + 0x1d0) = 0;
    puVar3 = *param_1;
    puVar1 = (undefined4 *)((longlong)puVar3 + lVar15 + 0x1d4);
    *puVar1 = 0xffffffff;
    puVar1[1] = 0x100;
    puVar1[2] = 0;
    puVar1[3] = 0;
    *(undefined8 *)((longlong)puVar3 + lVar15 + 0x1e4) = 0x10000000000;
    *(undefined4 *)((longlong)puVar3 + lVar15 + 0x1ec) = 0;
    lVar15 = lVar15 + 0x38;
  } while (lVar15 < 0x8618);
  *(undefined8 *)(puVar5 + 0x21f4) = 0;
  *(undefined8 *)(puVar5 + 0x21f6) = 0xffffffffffffffff;
  puVar5[0x21f8] = 0xffffffff;
  puVar5[0x21f9] = 0;
  if ((undefined8 *)(*param_1 + 0x21fa) != (undefined8 *)0x0)
  {
    lVar11 = 3;
    puVar6 = (undefined8 *)(*param_1 + 0x21fa);
    do
    {
      *puVar6 = 0xffffffffffffffff;
      puVar6[1] = 0xffffffffffffffff;
      puVar6[2] = 0xffffffffffffffff;
      puVar9 = puVar6 + 8;
      puVar6[3] = 0xffffffffffffffff;
      puVar6[4] = 0xffffffffffffffff;
      puVar6[5] = 0xffffffffffffffff;
      puVar6[6] = 0xffffffffffffffff;
      puVar6[7] = 0xffffffffffffffff;
      lVar11 = lVar11 + -1;
      puVar6 = puVar9;
    } while (lVar11 != 0);
    *puVar9 = 0xffffffffffffffff;
  }
  pcVar16 = "Milan_v_3.00.11.02";
  (*param_1)[0x222c] = 0xffffffff;
  puVar5 = *param_1 + 0x222d;
  if ((puVar5 != (uint *)0x0) && (puVar5 != (uint *)"Milan_v_3.00.11.02"))
  {
    do
    {
      cVar2 = *pcVar16;
      pcVar16 = pcVar16 + 1;
      *(char *)puVar5 = cVar2;
      puVar5 = (uint *)((longlong)puVar5 + 1);
    } while (cVar2 != '\0');
  }
  pcVar16 = "";
  puVar5 = *param_1 + 0x223d;
  if ((puVar5 != (uint *)0x0) && (puVar5 != (uint *)&DAT_1800a4143))
  {
    do
    {
      cVar2 = *pcVar16;
      pcVar16 = pcVar16 + 1;
      *(char *)puVar5 = cVar2;
      puVar5 = (uint *)((longlong)puVar5 + 1);
    } while (cVar2 != '\0');
  }
  (*param_1)[0x233d] = 0;
  (*param_1)[0x233e] = 0;
  (*param_1)[0x233f] = 0;
  *(undefined8 *)(*param_1 + 0x2342) = 0;
  return 0;
}

undefined8 FUN_180004800(int *param_1)

{
  int iVar1;
  int iVar2;
  longlong lVar3;
  longlong *plVar4;
  int iVar5;
  int *piVar6;
  uint uVar7;
  ulonglong uVar8;

  if (param_1 == (int *)0x0)
  {
    return 0x80000002;
  }
  if (param_1[7] == 0)
  {
    return 0x80000003;
  }
  iVar5 = param_1[7] + -1;
  iVar1 = *(int *)(*(longlong *)(param_1 + (longlong)iVar5 * 2 + 10) + 0x104);
  uVar8 = (longlong)iVar1 & 0xffffffff;
  if (iVar1 < param_1[9])
  {
    piVar6 = param_1 + (longlong)iVar1 * 7 + 0x6e;
    do
    {
      uVar7 = (int)uVar8 + 1;
      uVar8 = (ulonglong)uVar7;
      *piVar6 = -1;
      piVar6[1] = 0x100;
      piVar6[2] = 0;
      piVar6[3] = 0;
      *(undefined8 *)(piVar6 + 4) = 0x10000000000;
      piVar6[6] = 0;
      piVar6 = piVar6 + 7;
    } while ((int)uVar7 < param_1[9]);
  }
  iVar2 = param_1[7];
  param_1[9] = iVar1;
  param_1[7] = iVar2 + -1;
  if (iVar5 == param_1[0x21f6])
  {
    param_1[0x21f9] = 0;
    iVar5 = 0;
    if (0 < iVar2 + -1)
    {
      plVar4 = (longlong *)(param_1 + 10);
      do
      {
        lVar3 = *plVar4;
        plVar4 = plVar4 + 1;
        iVar5 = iVar5 + 1;
        *(undefined4 *)(lVar3 + 0x100) = 0;
      } while (iVar5 < param_1[7]);
    }
  }
  if (1 < *param_1 - 9U)
  {
    FUN_180017490((longlong)param_1);
  }
  return 0;
}

undefined8 FUN_1800048e0(void **param_1)

{
  void **ppvVar1;
  int iVar2;
  void **ppvVar3;
  longlong lVar4;
  longlong lVar5;

  if (*param_1 != (void *)0x0)
  {
    iVar2 = 0;
    if (0 < *(int *)((longlong)*param_1 + 0x20))
    {
      lVar5 = 0x28;
      do
      {
        ppvVar1 = (void **)((longlong)*param_1 + lVar5);
        if ((ppvVar1 != (void **)0x0) && (*ppvVar1 != (void *)0x0))
        {
          ppvVar3 = (void **)((longlong)*ppvVar1 + 8);
          if ((*ppvVar3 != (void *)0x0) && ((ppvVar3 != (void **)0x0 && (*ppvVar3 != (void *)0x0))))
          {
            free(*ppvVar3);
            *ppvVar3 = (void *)0x0;
          }
          *(undefined8 *)((longlong)*ppvVar1 + 8) = 0;
          ppvVar3 = (void **)((longlong)*ppvVar1 + 0x10);
          if (((*ppvVar3 != (void *)0x0) && (ppvVar3 != (void **)0x0)) && (*ppvVar3 != (void *)0x0))
          {
            free(*ppvVar3);
            *ppvVar3 = (void *)0x0;
          }
          *(undefined8 *)((longlong)*ppvVar1 + 0x10) = 0;
          ppvVar3 = (void **)((longlong)*ppvVar1 + 0x18);
          if (((*ppvVar3 != (void *)0x0) && (ppvVar3 != (void **)0x0)) && (*ppvVar3 != (void *)0x0))
          {
            free(*ppvVar3);
            *ppvVar3 = (void *)0x0;
          }
          *(undefined8 *)((longlong)*ppvVar1 + 0x18) = 0;
          ppvVar3 = (void **)((longlong)*ppvVar1 + 0x20);
          if (((*ppvVar3 != (void *)0x0) && (ppvVar3 != (void **)0x0)) && (*ppvVar3 != (void *)0x0))
          {
            free(*ppvVar3);
            *ppvVar3 = (void *)0x0;
          }
          *(undefined8 *)((longlong)*ppvVar1 + 0x20) = 0;
          if (*(void **)((longlong)*ppvVar1 + 0xf8) != (void *)0x0)
          {
            free(*(void **)((longlong)*ppvVar1 + 0xf8));
          }
          *(undefined8 *)((longlong)*ppvVar1 + 0xf8) = 0;
          ppvVar3 = (void **)((longlong)*ppvVar1 + 0x130);
          if (((*ppvVar3 != (void *)0x0) && (ppvVar3 != (void **)0x0)) && (*ppvVar3 != (void *)0x0))
          {
            free(*ppvVar3);
            *ppvVar3 = (void *)0x0;
          }
          *(undefined8 *)((longlong)*ppvVar1 + 0x130) = 0;
          free(*ppvVar1);
          *ppvVar1 = (void *)0x0;
        }
        iVar2 = iVar2 + 1;
        lVar5 = lVar5 + 8;
      } while (iVar2 < *(int *)((longlong)*param_1 + 0x20));
    }
    lVar5 = 0x8d10;
    lVar4 = 0x14;
    do
    {
      FUN_180004ab0((void **)((longlong)*param_1 + lVar5));
      lVar5 = lVar5 + 8;
      lVar4 = lVar4 + -1;
    } while (lVar4 != 0);
    free(*param_1);
    *param_1 = (void *)0x0;
    return 0;
  }
  return 0x80000002;
}

undefined8 FUN_180004ab0(void **param_1)

{
  void **ppvVar1;

  if ((param_1 != (void **)0x0) && (*param_1 != (void *)0x0))
  {
    ppvVar1 = (void **)((longlong)*param_1 + 8);
    if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
    {
      free(*ppvVar1);
      *ppvVar1 = (void *)0x0;
    }
    *(undefined8 *)((longlong)*param_1 + 8) = 0;
    ppvVar1 = (void **)((longlong)*param_1 + 0x10);
    if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
    {
      free(*ppvVar1);
      *ppvVar1 = (void *)0x0;
    }
    *(undefined8 *)((longlong)*param_1 + 0x10) = 0;
    ppvVar1 = (void **)((longlong)*param_1 + 0x18);
    if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
    {
      free(*ppvVar1);
      *ppvVar1 = (void *)0x0;
    }
    *(undefined8 *)((longlong)*param_1 + 0x18) = 0;
    ppvVar1 = (void **)((longlong)*param_1 + 0x20);
    if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
    {
      free(*ppvVar1);
      *ppvVar1 = (void *)0x0;
    }
    *(undefined8 *)((longlong)*param_1 + 0x20) = 0;
    if (*(void **)((longlong)*param_1 + 0xf8) != (void *)0x0)
    {
      free(*(void **)((longlong)*param_1 + 0xf8));
    }
    *(undefined8 *)((longlong)*param_1 + 0xf8) = 0;
    ppvVar1 = (void **)((longlong)*param_1 + 0x130);
    if (((*ppvVar1 != (void *)0x0) && (ppvVar1 != (void **)0x0)) && (*ppvVar1 != (void *)0x0))
    {
      free(*ppvVar1);
      *ppvVar1 = (void *)0x0;
    }
    *(undefined8 *)((longlong)*param_1 + 0x130) = 0;
    free(*param_1);
    *param_1 = (void *)0x0;
    return 0;
  }
  return 0x80000002;
}

undefined8 FUN_180004c30(longlong param_1)

{
  longlong lVar1;
  longlong lVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  longlong lVar7;
  longlong lVar8;
  longlong lVar9;
  int *piVar10;

  if (param_1 == 0)
  {
    return 0x80000002;
  }
  iVar3 = *(int *)(param_1 + 0x1c);
  if (iVar3 == 0)
  {
    return 0x80000003;
  }
  if (*(int *)(param_1 + 0x87e4) != 0)
  {
    lVar2 = param_1 + 0x1b8;
    iVar4 = *(int *)(param_1 + 0x87d8);
    lVar8 = (longlong)iVar4;
    lVar1 = param_1 + 0x28;
    if (0 < iVar4)
    {
      lVar9 = 0;
      piVar10 = (int *)((longlong) * (int *)(*(longlong *)(lVar1 + lVar8 * 8) + 0x104) * 0x1c + lVar2);
      do
      {
        if ((*piVar10 != -1) && (0 < lVar9))
        {
          lVar7 = lVar9;
          puVar6 = (undefined4 *)((longlong) * (int *)(*(longlong *)(lVar1 + lVar9 * 8) + 0x104) * 0x1c + lVar2);
          do
          {
            *puVar6 = 0xffffffff;
            puVar6[1] = 0x100;
            puVar6[2] = 0;
            puVar6[3] = 0;
            *(undefined8 *)(puVar6 + 4) = 0x10000000000;
            puVar6[6] = 0;
            lVar7 = lVar7 + -1;
            puVar6 = puVar6 + 7;
          } while (lVar7 != 0);
        }
        lVar9 = lVar9 + 1;
        piVar10 = piVar10 + 7;
      } while (lVar9 < lVar8);
    }
    lVar9 = (longlong)(iVar4 + 1);
    while (lVar9 < iVar3)
    {
      iVar5 = *(int *)(*(longlong *)(lVar1 + lVar9 * 8) + 0x104);
      if ((*(int *)((longlong)(iVar5 + iVar4) * 0x1c + lVar2) != -1) && (0 < lVar9))
      {
        lVar7 = 0;
        puVar6 = (undefined4 *)((longlong)iVar5 * 0x1c + lVar2);
        do
        {
          if (lVar7 != lVar8)
          {
            *puVar6 = 0xffffffff;
            puVar6[1] = 0x100;
            puVar6[2] = 0;
            puVar6[3] = 0;
            *(undefined8 *)(puVar6 + 4) = 0x10000000000;
            puVar6[6] = 0;
          }
          lVar7 = lVar7 + 1;
          puVar6 = puVar6 + 7;
        } while (lVar7 < lVar9);
      }
      lVar9 = lVar9 + 1;
    }
  }
  return 0;
}

void FUN_180004ea0(longlong param_1)

{
  byte *pbVar1;
  ulonglong *puVar2;
  undefined(*pauVar3)[16];
  longlong lVar4;
  longlong lVar5;
  ulonglong uVar6;
  ulonglong *puVar7;
  int iVar8;
  ulonglong uVar9;
  int iVar10;
  undefined4 local_48;
  undefined4 uStack68;
  undefined4 uStack64;
  undefined4 uStack60;
  undefined4 local_38;
  undefined4 uStack52;
  undefined4 uStack48;
  undefined4 uStack44;
  undefined4 local_28;
  undefined4 uStack36;
  undefined4 uStack32;
  undefined4 uStack28;
  ulonglong local_18;
  ulonglong local_10;

  local_10 = DAT_1800b04e8 ^ (ulonglong)&local_48;
  uVar6 = 0;
  iVar8 = 0;
  iVar10 = *(int *)(param_1 + 0xf0) + -1;
  if (0 < iVar10)
  {
    lVar4 = (longlong)iVar10;
    uVar9 = uVar6;
  LAB_180004ef2:
    lVar5 = *(longlong *)(param_1 + 0xf8);
    pbVar1 = (byte *)(uVar6 * 0x38 + lVar5);
    do
    {
      if ((*pbVar1 & 3) != 0)
        break;
      uVar9 = (ulonglong)((int)uVar9 + 1);
      uVar6 = uVar6 + 1;
      pbVar1 = pbVar1 + 0x38;
    } while ((longlong)uVar6 < lVar4);
    iVar8 = (int)uVar9;
    if (iVar8 < iVar10)
    {
      pbVar1 = (byte *)(lVar4 * 0x38 + lVar5);
      do
      {
        if ((*pbVar1 & 3) != 1)
          break;
        iVar10 = iVar10 + -1;
        lVar4 = lVar4 + -1;
        pbVar1 = pbVar1 + -0x38;
      } while ((longlong)uVar6 < lVar4);
      if (iVar10 <= iVar8)
        goto LAB_180005014;
      puVar7 = (ulonglong *)((longlong)iVar8 * 0x38 + lVar5);
      if ((puVar7 != (ulonglong *)0x0) && ((puVar7 + 7 <= &local_48 || (&local_10 <= puVar7))))
      {
        local_48 = *(undefined4 *)puVar7;
        uStack68 = *(undefined4 *)((longlong)puVar7 + 4);
        uStack64 = *(undefined4 *)(puVar7 + 1);
        uStack60 = *(undefined4 *)((longlong)puVar7 + 0xc);
        local_38 = *(undefined4 *)(puVar7 + 2);
        uStack52 = *(undefined4 *)((longlong)puVar7 + 0x14);
        uStack48 = *(undefined4 *)(puVar7 + 3);
        uStack44 = *(undefined4 *)((longlong)puVar7 + 0x1c);
        local_28 = *(undefined4 *)(puVar7 + 4);
        uStack36 = *(undefined4 *)((longlong)puVar7 + 0x24);
        uStack32 = *(undefined4 *)(puVar7 + 5);
        uStack28 = *(undefined4 *)((longlong)puVar7 + 0x2c);
        local_18 = puVar7[6];
      }
      puVar2 = (ulonglong *)((longlong)iVar10 * 0x38 + lVar5);
      if (((puVar7 != (ulonglong *)0x0) && (puVar2 != (ulonglong *)0x0)) &&
          ((puVar2 + 7 <= puVar7 || (puVar7 + 7 <= puVar2))))
      {
        puVar7 = (ulonglong *)((longlong)puVar7 - (longlong)puVar2);
        lVar5 = 0x1c;
        do
        {
          *(undefined *)((longlong)puVar7 + (longlong)puVar2) = *(undefined *)puVar2;
          ((undefined *)((longlong)puVar7 + 1))[(longlong)puVar2] =
              *(undefined *)((longlong)puVar2 + 1);
          puVar2 = (ulonglong *)((longlong)puVar2 + 2);
          lVar5 = lVar5 + -1;
        } while (lVar5 != 0);
      }
      pauVar3 = (undefined(*)[16])(*(longlong *)(param_1 + 0xf8) + (longlong)iVar10 * 0x38);
      if ((pauVar3 != (undefined(*)[16])0x0) &&
          (((undefined(*)[16]) & local_10 <= pauVar3 || (pauVar3[3] + 8 <= &local_48))))
      {
        *pauVar3 = CONCAT412(uStack60, CONCAT48(uStack64, CONCAT44(uStack68, local_48)));
        pauVar3[1] = CONCAT412(uStack44, CONCAT48(uStack48, CONCAT44(uStack52, local_38)));
        pauVar3[2] = CONCAT412(uStack28, CONCAT48(uStack32, CONCAT44(uStack36, local_28)));
        *(ulonglong *)pauVar3[3] = local_18;
      }
      goto LAB_180004ef2;
    }
  }
LAB_180005014:
  if ((iVar8 == iVar10) &&
      ((*(byte *)((longlong)iVar8 * 0x38 + *(longlong *)(param_1 + 0xf8)) & 3) == 0))
  {
    iVar8 = iVar8 + 1;
  }
  *(int *)(param_1 + 0x108) = iVar8;
  FUN_18005f100(local_10 ^ (ulonglong)&local_48);
  return;
}

// WARNING: Could not reconcile some variable overlaps

void FUN_180005050(longlong param_1, longlong param_2, int param_3, int param_4)

{
  int iVar1;
  undefined4 uVar2;
  undefined *puVar3;
  void *pvVar4;
  undefined8 *puVar5;
  undefined *puVar6;
  undefined2 *puVar7;
  undefined2 *puVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  undefined2 *puVar11;
  undefined4 *puVar12;
  longlong lVar13;
  uint uVar14;
  longlong lVar15;
  undefined2 *puVar16;
  undefined auStack1544[32];
  undefined8 local_5e8;
  undefined8 uStack1504;
  undefined8 local_5d8;
  undefined8 local_5d0[179];
  ulonglong local_38;

  local_38 = DAT_1800b04e8 ^ (ulonglong)auStack1544;
  if (*(longlong *)(param_2 + 0xf8) == 0)
  {
    pvVar4 = malloc((longlong)(param_3 * 0x38));
    *(void **)(param_2 + 0xf8) = pvVar4;
  }
  iVar1 = *(int *)(param_1 + 0xf0);
  uVar9 = 0;
  if (param_3 < iVar1)
  {
    puVar16 = *(undefined2 **)(param_2 + 0xf8);
    if (0 < iVar1)
    {
      puVar5 = &local_5d8;
      puVar12 = (undefined4 *)(*(longlong *)(param_1 + 0xf8) + 8);
      uVar10 = uVar9;
      do
      {
        uVar2 = *puVar12;
        puVar12 = puVar12 + 0xe;
        *(int *)((longlong)puVar5 + 4) = (int)uVar10;
        uVar14 = (int)uVar10 + 1;
        uVar10 = (ulonglong)uVar14;
        *(undefined4 *)puVar5 = uVar2;
        puVar5 = puVar5 + 1;
      } while ((int)uVar14 < iVar1);
    }
    if (1 < (longlong)iVar1)
    {
      lVar15 = 1;
      do
      {
        local_5e8 = (&local_5d8)[lVar15];
        lVar13 = lVar15;
        if (0 < lVar15)
        {
          local_5e8._4_4_ = (int)((ulonglong)local_5e8 >> 0x20);
          puVar5 = &uStack1504 + lVar15;
          do
          {
            if ((*(int *)puVar5 <= (int)local_5e8) &&
                ((*(int *)puVar5 != (int)local_5e8 ||
                  (*(int *)((longlong)puVar5 + 4) == local_5e8._4_4_ ||
                   *(int *)((longlong)puVar5 + 4) < local_5e8._4_4_))))
              break;
            lVar13 = lVar13 + -1;
            puVar5[1] = *puVar5;
            puVar5 = puVar5 + -1;
          } while (0 < lVar13);
        }
        lVar15 = lVar15 + 1;
        (&local_5d8)[lVar13] = local_5e8;
      } while (lVar15 < iVar1);
    }
    uVar10 = uVar9;
    if (0 < param_3)
    {
      do
      {
        puVar7 = (undefined2 *)((longlong) * (int *)((longlong)local_5d0 + uVar10 * 8 + -4) * 0x38 +
                                *(longlong *)(param_1 + 0xf8));
        puVar11 = puVar7 + 8;
        puVar16[1] = puVar7[1];
        puVar16[2] = puVar7[2];
        puVar16[3] = puVar7[3];
        *puVar16 = *puVar7;
        puVar8 = puVar16 + 8;
        *(undefined4 *)(puVar16 + 4) = *(undefined4 *)(puVar7 + 4);
        if (((puVar8 != (undefined2 *)0x0) && (puVar11 != (undefined2 *)0x0)) &&
            ((puVar7 + 0x14 <= puVar8 || (puVar16 + 0x14 <= puVar11))))
        {
          puVar11 = (undefined2 *)((longlong)puVar11 - (longlong)puVar8);
          lVar15 = 0x18;
          do
          {
            *(undefined *)puVar8 = *(undefined *)((longlong)puVar11 + (longlong)puVar8);
            puVar8 = (undefined2 *)((longlong)puVar8 + 1);
            lVar15 = lVar15 + -1;
          } while (lVar15 != 0);
        }
        uVar10 = uVar10 + 1;
        puVar16 = puVar16 + 0x1c;
      } while ((longlong)uVar10 < (longlong)param_3);
    }
    *(int *)(param_2 + 0xf0) = param_3;
    FUN_180004ea0(param_2);
  }
  else
  {
    puVar6 = *(undefined **)(param_2 + 0xf8);
    *(int *)(param_2 + 0xf0) = iVar1;
    uVar14 = *(int *)(param_1 + 0xf0) * 0x38;
    uVar10 = (ulonglong)uVar14;
    puVar3 = *(undefined **)(param_1 + 0xf8);
    if (((((puVar6 != (undefined *)0x0) && (puVar3 != (undefined *)0x0)) && (uVar14 != 0)) &&
         ((puVar3 + uVar10 <= puVar6 || (puVar6 + uVar10 <= puVar3)))) &&
        (uVar14 != 0))
    {
      lVar15 = -(longlong)puVar6;
      do
      {
        *puVar6 = puVar6[(longlong)(puVar3 + lVar15)];
        puVar6 = puVar6 + 1;
        uVar10 = uVar10 - 1;
      } while (uVar10 != 0);
    }
    *(undefined4 *)(param_2 + 0x108) = *(undefined4 *)(param_1 + 0x108);
  }
  if ((param_4 != 0) && (0 < *(int *)(param_2 + 0xf0)))
  {
    puVar5 = (undefined8 *)(*(longlong *)(param_2 + 0xf8) + 0x30);
    do
    {
      *(undefined4 *)((longlong)puVar5 + -0xc) = 0;
      uVar14 = (int)uVar9 + 1;
      uVar9 = (ulonglong)uVar14;
      *puVar5 = 0;
      puVar5 = puVar5 + 7;
    } while ((int)uVar14 < *(int *)(param_2 + 0xf0));
  }
  FUN_18005f100(local_38 ^ (ulonglong)auStack1544);
  return;
}

undefined8 *FUN_180005350(undefined8 *param_1, undefined8 *param_2, ulonglong param_3)

{
  memcpy_FUN_180061f90(param_1, param_2, param_3);
  return param_1;
}

void *FUN_180005370(void *param_1, undefined8 param_2, size_t param_3)

{
  memset(param_1, 0, param_3);
  return param_1;
}

void FUN_180005390(undefined4 *param_1, undefined4 *param_2, int param_3)

{
  undefined *puVar1;
  int iVar2;
  ulonglong uVar3;
  undefined4 *puVar4;
  undefined *puVar5;
  undefined4 *puVar6;
  longlong lVar7;
  uint uVar8;

  uVar8 = *(uint *)(*(longlong *)(param_1 + 2) + 0xc);
  uVar3 = (ulonglong)uVar8;
  puVar1 = *(undefined **)(*(longlong *)(param_1 + 2) + 0x18);
  puVar5 = *(undefined **)(*(longlong *)(param_2 + 2) + 0x18);
  if ((((puVar5 != (undefined *)0x0) && (puVar1 != (undefined *)0x0)) && (uVar8 != 0)) &&
      (((puVar1 + uVar3 <= puVar5 || (puVar5 + uVar3 <= puVar1)) && (uVar8 != 0))))
  {
    lVar7 = -(longlong)puVar5;
    do
    {
      *puVar5 = puVar5[(longlong)(puVar1 + lVar7)];
      puVar5 = puVar5 + 1;
      uVar3 = uVar3 - 1;
    } while (uVar3 != 0);
  }
  lVar7 = *(longlong *)(param_1 + 4);
  if (lVar7 == 0)
  {
    *(undefined8 *)(param_2 + 4) = 0;
  }
  else
  {
    uVar8 = *(uint *)(lVar7 + 0xc);
    uVar3 = (ulonglong)uVar8;
    puVar1 = *(undefined **)(lVar7 + 0x18);
    puVar5 = *(undefined **)(*(longlong *)(param_2 + 4) + 0x18);
    if (((puVar5 != (undefined *)0x0) && (puVar1 != (undefined *)0x0)) &&
        ((uVar8 != 0 && (((puVar1 + uVar3 <= puVar5 || (puVar5 + uVar3 <= puVar1)) && (uVar8 != 0))))))
    {
      lVar7 = -(longlong)puVar5;
      do
      {
        *puVar5 = puVar5[(longlong)(puVar1 + lVar7)];
        puVar5 = puVar5 + 1;
        uVar3 = uVar3 - 1;
      } while (uVar3 != 0);
    }
  }
  lVar7 = *(longlong *)(param_1 + 6);
  if (lVar7 == 0)
  {
    *(undefined8 *)(param_2 + 6) = 0;
  }
  else
  {
    uVar8 = *(uint *)(lVar7 + 0xc);
    uVar3 = (ulonglong)uVar8;
    puVar1 = *(undefined **)(lVar7 + 0x18);
    puVar5 = *(undefined **)(*(longlong *)(param_2 + 6) + 0x18);
    if ((((puVar5 != (undefined *)0x0) && (puVar1 != (undefined *)0x0)) &&
         ((uVar8 != 0 && ((puVar1 + uVar3 <= puVar5 || (puVar5 + uVar3 <= puVar1)))))) &&
        (uVar8 != 0))
    {
      lVar7 = -(longlong)puVar5;
      do
      {
        *puVar5 = puVar5[(longlong)(puVar1 + lVar7)];
        puVar5 = puVar5 + 1;
        uVar3 = uVar3 - 1;
      } while (uVar3 != 0);
    }
  }
  puVar6 = param_2 + 10;
  puVar4 = param_1 + 10;
  if (((puVar6 != (undefined4 *)0x0) && (puVar4 != (undefined4 *)0x0)) &&
      ((param_1 + 0x3c <= puVar6 || (param_2 + 0x3c <= puVar4))))
  {
    puVar6 = (undefined4 *)((longlong)puVar6 - (longlong)puVar4);
    lVar7 = 100;
    do
    {
      *(undefined *)((longlong)puVar6 + (longlong)puVar4) = *(undefined *)puVar4;
      *(undefined *)((longlong)puVar6 + 1 + (longlong)puVar4) = *(undefined *)((longlong)puVar4 + 1);
      puVar4 = (undefined4 *)((longlong)puVar4 + 2);
      lVar7 = lVar7 + -1;
    } while (lVar7 != 0);
  }
  if (*(int **)(param_1 + 0x4c) != (int *)0x0)
  {
    FUN_1800230e0(*(int **)(param_1 + 0x4c), (int **)(param_2 + 0x4c));
  }
  puVar5 = *(undefined **)(param_2 + 0x3e);
  *(undefined8 *)(param_2 + 8) = 0;
  iVar2 = param_1[0x3c];
  if (param_3 < (int)param_1[0x3c])
  {
    iVar2 = param_3;
  }
  uVar8 = iVar2 * 0x38;
  uVar3 = (ulonglong)uVar8;
  param_2[0x3c] = iVar2;
  puVar1 = *(undefined **)(param_1 + 0x3e);
  if (((((puVar5 != (undefined *)0x0) && (puVar1 != (undefined *)0x0)) && (uVar8 != 0)) &&
       ((puVar1 + uVar3 <= puVar5 || (puVar5 + uVar3 <= puVar1)))) &&
      (uVar8 != 0))
  {
    lVar7 = -(longlong)puVar5;
    do
    {
      *puVar5 = puVar5[(longlong)(puVar1 + lVar7)];
      puVar5 = puVar5 + 1;
      uVar3 = uVar3 - 1;
    } while (uVar3 != 0);
  }
  param_2[0x42] = param_1[0x42];
  param_2[0x41] = param_1[0x41];
  param_2[0x43] = param_1[0x43];
  param_2[0x44] = param_1[0x44];
  param_2[0x40] = param_1[0x40];
  param_2[0x49] = param_1[0x49];
  param_2[0x47] = param_1[0x47];
  param_2[0x48] = param_1[0x48];
  param_2[0x45] = param_1[0x45];
  param_2[0x43] = param_1[0x43];
  param_2[0x44] = param_1[0x44];
  param_2[0x4a] = param_1[0x4a];
  param_2[1] = param_1[1];
  *param_2 = *param_1;
  param_2[0x54] = param_1[0x54];
  param_2[0x53] = param_1[0x53];
  return;
}

void FUN_180005670(longlong param_1, undefined4 *param_2, int *param_3)

{
  undefined4 *puVar1;
  ulonglong *puVar2;
  undefined auStack88[32];
  ulonglong local_38[2];
  ulonglong local_28;
  ulonglong local_20;

  local_20 = DAT_1800b04e8 ^ (ulonglong)auStack88;
  local_28 = 0x100;
  puVar1 = *(undefined4 **)(param_1 + 0x28 + (ulonglong) * (uint *)(param_1 + 0x1c) * 8);
  FUN_180005390(param_2, puVar1, *(int *)(param_1 + 0x14));
  *(undefined4 *)((ulonglong) * (uint *)(param_1 + 0x24) * 0x1c + 0x1b8 + param_1) = 0xffffffff;
  puVar2 = (ulonglong *)(param_1 + 0x1bc + (ulonglong) * (uint *)(param_1 + 0x24) * 0x1c);
  if ((puVar2 != (ulonglong *)0x0) && ((&local_20 <= puVar2 || (puVar2 + 3 <= local_38))))
  {
    *(undefined4 *)puVar2 = 0x100;
    *(undefined4 *)((longlong)puVar2 + 4) = 0;
    *(undefined4 *)(puVar2 + 1) = 0;
    *(undefined4 *)((longlong)puVar2 + 0xc) = 0;
    puVar2[2] = local_28;
  }
  *(int *)(param_1 + 0x24) = *(int *)(param_1 + 0x24) + 1;
  *(undefined4 *)(*(longlong *)(param_1 + 0x28 + (ulonglong) * (uint *)(param_1 + 0x1c) * 8) + 0x108) = puVar1[0x42];
  *(undefined4 *)(*(longlong *)(param_1 + 0x28 + (ulonglong) * (uint *)(param_1 + 0x1c) * 8) + 0x10c) = puVar1[0x43];
  *(undefined4 *)(*(longlong *)(param_1 + 0x28 + (ulonglong) * (uint *)(param_1 + 0x1c) * 8) + 0x114) = 0;
  *(undefined4 *)(*(longlong *)(param_1 + 0x28 + (ulonglong) * (uint *)(param_1 + 0x1c) * 8) + 0x11c) = 0;
  *(undefined4 *)(*(longlong *)(param_1 + 0x28 + (ulonglong) * (uint *)(param_1 + 0x1c) * 8) + 0x120) = 0;
  *(undefined4 *)(*(longlong *)(param_1 + 0x28 + (ulonglong) * (uint *)(param_1 + 0x1c) * 8) + 0x124) = 0;
  *(undefined8 *)(*(longlong *)(param_1 + 0x28 + (ulonglong) * (uint *)(param_1 + 0x1c) * 8) + 0x140) = 0;
  *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + 1;
  *param_3 = *param_3 + 100;
  FUN_18005f100(local_20 ^ (ulonglong)auStack88);
  return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1800057a0(longlong param_1, uint *param_2, int *param_3, longlong param_4, int *param_5)

{
  int iVar1;
  int iVar2;
  uint *puVar3;
  undefined8 *puVar4;
  longlong lVar5;
  longlong lVar6;
  undefined(*pauVar7)[16];
  undefined8 *puVar8;
  ulonglong uVar9;
  int iVar10;
  uint uVar11;
  int *piVar13;
  ulonglong uVar14;
  uint **ppuVar15;
  int iVar16;
  undefined4 uVar17;
  undefined4 uVar18;
  undefined auVar19[16];
  int local_3d8;
  int local_3d4;
  longlong local_3d0;
  uint *local_3c8;
  int *local_3c0;
  longlong local_3b8;
  undefined8 local_3b0;
  undefined4 uStack936;
  undefined4 uStack932;
  undefined8 local_3a0;
  undefined8 local_398;
  undefined8 local_298;
  undefined8 local_198;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined4 local_80;
  undefined2 local_7c;
  undefined local_7a;
  ulonglong local_78;
  ulonglong uVar12;

  auVar19 = _DAT_1800a4170;
  local_78 = DAT_1800b04e8 ^ (ulonglong)&stack0xfffffffffffffbd8;
  lVar6 = *(longlong *)(param_2 + 0x3e);
  ppuVar15 = (uint **)(param_1 + 0x28);
  iVar16 = 0;
  *param_5 = 0;
  local_3a0 = 0x100;
  local_3d0 = lVar6;
  local_3c8 = param_2;
  local_3c0 = param_3;
  local_3b8 = param_4;
  if (0 < *(int *)(param_1 + 0x1c) + -1)
  {
    uVar17 = 0x100;
    uVar18 = 0;
    do
    {
      iVar10 = 0;
      puVar3 = *ppuVar15;
      lVar5 = 3;
      puVar8 = &local_398;
      do
      {
        puVar4 = puVar8;
        *puVar4 = 0xffffffffffffffff;
        puVar4[1] = 0xffffffffffffffff;
        puVar4[2] = 0xffffffffffffffff;
        puVar4[3] = 0xffffffffffffffff;
        puVar4[4] = 0xffffffffffffffff;
        puVar4[5] = 0xffffffffffffffff;
        puVar4[6] = 0xffffffffffffffff;
        puVar4[7] = 0xffffffffffffffff;
        lVar5 = lVar5 + -1;
        puVar8 = puVar4 + 8;
      } while (lVar5 != 0);
      puVar4[8] = 0xffffffffffffffff;
      lVar5 = 3;
      puVar4[9] = 0xffffffffffffffff;
      puVar4[10] = 0xffffffffffffffff;
      puVar4[0xb] = 0xffffffffffffffff;
      puVar4[0xc] = 0xffffffffffffffff;
      puVar4[0xd] = 0xffffffffffffffff;
      puVar4[0xe] = 0xffffffffffffffff;
      puVar8 = &local_298;
      do
      {
        puVar4 = puVar8;
        *puVar4 = 0;
        puVar4[1] = 0;
        puVar4[2] = 0;
        puVar4[3] = 0;
        puVar4[4] = 0;
        puVar4[5] = 0;
        puVar4[6] = 0;
        puVar4[7] = 0;
        lVar5 = lVar5 + -1;
        puVar8 = puVar4 + 8;
      } while (lVar5 != 0);
      puVar4[8] = 0;
      lVar5 = 3;
      puVar4[9] = 0;
      puVar4[10] = 0;
      puVar4[0xb] = 0;
      puVar4[0xc] = 0;
      puVar4[0xd] = 0;
      puVar4[0xe] = 0;
      puVar8 = &local_198;
      do
      {
        puVar4 = puVar8;
        *puVar4 = 0;
        puVar4[1] = 0;
        puVar4[2] = 0;
        puVar4[3] = 0;
        puVar4[4] = 0;
        puVar4[5] = 0;
        puVar4[6] = 0;
        puVar4[7] = 0;
        lVar5 = lVar5 + -1;
        puVar8 = puVar4 + 8;
      } while (lVar5 != 0);
      puVar4[8] = 0;
      puVar4[9] = 0;
      puVar4[10] = 0;
      puVar4[0xb] = 0;
      puVar4[0xc] = 0;
      puVar4[0xd] = 0;
      puVar4[0xe] = 0;
      FUN_1800329f0((longlong)puVar3, (longlong)local_3c8, &local_398);
      uVar9 = 0;
      piVar13 = (int *)((longlong)&local_398 + 4);
      uVar12 = uVar9;
      uVar14 = uVar9;
      do
      {
        iVar1 = *(int *)((longlong)&local_398 + (longlong)((int)uVar12 * 2) * 4);
        if (-1 < iVar1)
        {
          iVar2 = *piVar13;
          iVar10 = iVar10 + 1;
          *(uint *)((longlong)&local_198 + uVar14) =
              (uint) * (ushort *)((longlong)iVar2 * 0x38 + 2 + lVar6);
          *(uint *)((longlong)&local_198 + uVar14 + 4) =
              (uint) * (ushort *)((longlong)iVar2 * 0x38 + 4 + lVar6);
          lVar5 = (longlong)iVar1 * 0x38 + *(longlong *)(puVar3 + 0x3e);
          *(uint *)((longlong)&local_298 + uVar14) = (uint) * (ushort *)(lVar5 + 2);
          *(uint *)((longlong)&local_298 + uVar14 + 4) = (uint) * (ushort *)(lVar5 + 4);
          uVar14 = uVar14 + 8;
        }
        uVar11 = (int)uVar12 + 1;
        uVar12 = (ulonglong)uVar11;
        piVar13 = piVar13 + 2;
      } while ((int)uVar11 < 0x1f);
      if (iVar10 < 5)
      {
        *(undefined4 *)((ulonglong) * (uint *)(param_1 + 0x24) * 0x1c + 0x1b8 + param_1) = 0xffffffff;
        pauVar7 = (undefined(*)[16])(param_1 + 0x1bc + (ulonglong) * (uint *)(param_1 + 0x24) * 0x1c);
        if ((pauVar7 != (undefined(*)[16])0x0) &&
            (((undefined(*)[16]) & local_398 <= pauVar7 || (pauVar7[1] + 8 <= &local_3b0))))
        {
          *pauVar7 = auVar19;
          *(ulonglong *)pauVar7[1] = CONCAT44(uVar18, uVar17);
        }
      }
      else
      {
        local_3a0 = 0x100;
        local_98 = 0;
        local_90 = 0;
        local_88 = 0;
        local_80 = 0;
        local_7c = 0;
        local_7a = 0;
        local_3b0._0_4_ = 0x100;
        local_3b0._4_4_ = 0;
        uStack936 = 0;
        uStack932 = 0;
        local_3d8 = 0;
        FUN_180030800(&local_198, (longlong)&local_298, iVar10, &local_3b0,
                      (undefined1(*)[9]) & local_98, &local_3d8);
        lVar6 = 0;
        do
        {
          uVar11 = (uint)uVar9 + 1;
          if (*(char *)((longlong)&local_98 + lVar6) == '\0')
          {
            uVar11 = (uint)uVar9;
          }
          lVar6 = lVar6 + 1;
          uVar9 = (ulonglong)uVar11;
        } while (lVar6 < 0x1f);
        local_3d4 = 0;
        local_3d8 = 0;
        if (4 < (int)uVar11)
        {
          FUN_18002bd60(local_3c8, puVar3, &local_3b0, local_3c0, (int *)0x0, (int *)0x0, &local_3d4,
                        &local_3d8, 0, (int *)0x0);
        }
        lVar6 = local_3d0;
        if ((((((int)uVar11 < 7) || (local_3d4 < 0xd1)) || (local_3d8 < 0x41)) &&
             ((int)uVar11 < 0xb)) &&
            ((local_3d4 < 0xd8 || ((int)uVar11 < 6))))
        {
          *(undefined4 *)((ulonglong) * (uint *)(param_1 + 0x24) * 0x1c + 0x1b8 + param_1) =
              0xffffffff;
          pauVar7 = (undefined(*)[16])(param_1 + 0x1bc + (ulonglong) * (uint *)(param_1 + 0x24) * 0x1c);
          if ((pauVar7 != (undefined(*)[16])0x0) &&
              (((undefined(*)[16]) & local_398 <= pauVar7 || (pauVar7[1] + 8 <= &local_3b0))))
          {
            *pauVar7 = auVar19;
            *(ulonglong *)pauVar7[1] = CONCAT44(uVar18, uVar17);
          }
        }
        else
        {
          *(uint *)((ulonglong) * (uint *)(param_1 + 0x24) * 0x1c + 0x1b8 + param_1) = uVar11;
          puVar8 = (undefined8 *)(param_1 + 0x1bc + (ulonglong) * (uint *)(param_1 + 0x24) * 0x1c);
          if ((puVar8 != (undefined8 *)0x0) &&
              ((&local_398 <= puVar8 || (puVar8 + 3 <= &local_3b0))))
          {
            *(undefined4 *)puVar8 = (undefined4)local_3b0;
            *(undefined4 *)((longlong)puVar8 + 4) = local_3b0._4_4_;
            *(undefined4 *)(puVar8 + 1) = uStack936;
            *(undefined4 *)((longlong)puVar8 + 0xc) = uStack932;
            puVar8[2] = local_3a0;
          }
          *(int *)(local_3b8 + (longlong)*param_5 * 4) = iVar16;
          *param_5 = *param_5 + 1;
        }
      }
      *(int *)(param_1 + 0x24) = *(int *)(param_1 + 0x24) + 1;
      iVar16 = iVar16 + 1;
      ppuVar15 = ppuVar15 + 1;
    } while (iVar16 < *(int *)(param_1 + 0x1c) + -1);
  }
  FUN_18005f100(local_78 ^ (ulonglong)&stack0xfffffffffffffbd8);
  return;
}

// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180005c80(longlong param_1, longlong param_2, int *param_3, undefined (*param_4)[16])

{
  longlong lVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  byte bVar5;
  longlong lVar6;
  undefined(*pauVar7)[16];
  uint uVar8;
  longlong lVar9;
  longlong lVar10;
  int iVar11;
  longlong lVar12;
  int iVar13;
  uint uVar14;
  longlong lVar15;
  uint uVar16;
  int *piVar17;
  ulonglong uVar18;
  undefined auVar19[16];
  undefined auStack232[32];
  uint local_c8;
  uint local_c4;
  undefined(*local_c0)[16];
  int *local_b8;
  longlong local_b0;
  longlong local_a8;
  int *local_a0;
  undefined local_98[12];
  undefined4 uStack140;
  undefined8 local_88;
  int local_80;
  int iStack124;
  int iStack120;
  int iStack116;
  undefined8 local_70;
  ulonglong local_68;

  local_68 = DAT_1800b04e8 ^ (ulonglong)auStack232;
  local_b8 = (int *)(param_1 + 0x28);
  lVar1 = param_1 + 0x1b8;
  lVar9 = *(longlong *)(param_3 + 2);
  iVar11 = 0;
  iVar2 = *param_3;
  iVar13 = 0;
  local_c8 = *(uint *)(param_1 + 0x87d8);
  local_88 = 0x100;
  _local_98 = _DAT_1800a4170;
  if (0 < (longlong)param_3[1])
  {
    lVar12 = 0;
    lVar10 = 0;
    do
    {
      lVar15 = lVar12 * 4;
      iVar3 = *(int *)((longlong)(*(int *)(lVar15 + lVar9) + iVar2) * 0x1c + lVar1);
      lVar6 = (longlong)(*(int *)(lVar10 + lVar9) + iVar2) * 0x1c;
      if (*(int *)(lVar6 + lVar1) < iVar3)
      {
        iVar11 = iVar13;
      }
      iVar13 = iVar13 + 1;
      lVar12 = lVar12 + 1;
      if (iVar3 <= *(int *)(lVar6 + lVar1))
      {
        lVar15 = lVar10;
      }
      lVar10 = lVar15;
    } while (lVar12 < param_3[1]);
  }
  uVar4 = *(uint *)(lVar9 + (longlong)iVar11 * 4);
  auVar19 = _DAT_1800a4170;
  local_c4 = uVar4;
  local_c0 = param_4;
  local_a8 = param_2;
  local_a0 = param_3;
  if ((int)local_c8 < (int)uVar4)
  {
    piVar17 = (int *)(param_1 + 0x1bc + (longlong)(int)(uVar4 + iVar2) * 0x1c);
    local_b8 = (int *)(param_1 + 0x1bc +
                       (longlong)(int)(*(int *)(*(longlong *)(local_b8 + (longlong)(int)uVar4 * 2) + 0x104) +
                                       local_c8) *
                           0x1c);
    if ((local_b8 != (int *)0x0) && (piVar17 != (int *)0x0))
    {
      lVar9 = (longlong)*local_b8;
      lVar12 = (longlong)local_b8[1];
      lVar15 = (longlong)local_b8[3];
      lVar10 = (longlong)local_b8[4];
      local_b0 = lVar15 * *piVar17;
      uStack140 = SUB164(_DAT_1800a4170 >> 0x60, 0);
      local_98._0_8_ = SUB168(_DAT_1800a4170, 0);
      local_98 = CONCAT48((int)((ulonglong)(piVar17[2] * lVar9 + piVar17[5] * lVar12) >> 8) +
                              local_b8[2],
                          local_98._0_8_);
      bVar5 = 0xf;
      iVar11 = (int)((ulonglong)(local_b0 + lVar10 * piVar17[3]) >> 8) -
                   (int)((ulonglong)(piVar17[1] * lVar9 + piVar17[4] * lVar12) >> 8) >>
               1;
      iVar13 = (int)((ulonglong)(piVar17[1] * lVar15 + lVar10 * piVar17[4]) >> 8) +
                   (int)((ulonglong)(*piVar17 * lVar9 + piVar17[3] * lVar12) >> 8) >>
               1;
      local_88 = (ulonglong)(uint)((int)((ulonglong)(lVar15 * piVar17[2] + lVar10 * piVar17[5]) >> 8) +
                                   local_b8[5])
                 << 0x20;
      uVar14 = 0;
      uVar16 = iVar11 * iVar11 + iVar13 * iVar13;
      uVar4 = 0x8000;
      uVar8 = uVar16;
      if (1 < uVar16)
      {
        do
        {
          uVar8 = uVar4 + uVar14 * 2 << (bVar5 & 0x1f);
          bVar5 = bVar5 - 1;
          if (uVar8 <= uVar16)
          {
            uVar14 = uVar14 + uVar4;
            uVar16 = uVar16 - uVar8;
          }
          uVar4 = uVar4 >> 1;
          uVar8 = uVar14;
        } while (uVar4 != 0);
      }
    LAB_18000601a:
      param_4 = local_c0;
      uVar4 = local_c4;
      if (uVar8 == 0)
      {
        _local_98 = CONCAT88(stack0xffffffffffffff70, 0x100);
        local_88 = CONCAT44(local_88._4_4_, 0x100);
        _local_98 = _local_98 & (undefined[16])0xffffffffffffffff;
        auVar19 = _local_98;
      }
      else
      {
        uVar14 = (((int)uVar8 >> 1) + iVar13 * 0x100) / (int)uVar8;
        local_88 = local_88 | uVar14;
        iVar11 = (((int)uVar8 >> 1) + iVar11 * -0x100) / (int)uVar8;
        local_98._0_8_ = CONCAT44(iVar11, uVar14);
        _local_98 = CONCAT412(-iVar11, local_98);
        auVar19 = _local_98;
      }
    }
  }
  else
  {
    if ((int)local_c8 <= (int)uVar4)
    {
      pauVar7 = (undefined(*)[16])(param_1 + 0x1bc + (longlong)(int)(uVar4 + iVar2) * 0x1c);
      uVar18 = local_88;
      if ((pauVar7 != (undefined(*)[16])0x0) &&
          ((pauVar7[1] + 8 <= local_98 || ((undefined(*)[16]) & local_80 <= pauVar7))))
      {
        uVar18 = *(ulonglong *)pauVar7[1];
        auVar19 = *pauVar7;
      }
      goto LAB_1800060e6;
    }
    iVar11 = 0x100;
    local_80 = 0x100;
    iStack124 = 0;
    iStack120 = 0;
    iStack116 = 0;
    local_70 = 0x100;
    piVar17 = (int *)((longlong)(int)(*(int *)(*(longlong *)(local_b8 + (longlong)(int)local_c8 * 2) + 0x104) + uVar4) * 0x1c + 4 + lVar1);
    if (piVar17 != (int *)0x0)
    {
      FUN_180023cd0(piVar17, &local_80);
      iVar11 = (int)local_70;
    }
    piVar17 = (int *)(param_1 + 0x1bc + (longlong)(int)(uVar4 + iVar2) * 0x1c);
    if (piVar17 != (int *)0x0)
    {
      lVar9 = (longlong)iStack124;
      lVar10 = (longlong)local_80;
      bVar5 = 0xf;
      local_98 = CONCAT48((int)((ulonglong)(lVar10 * piVar17[2] + lVar9 * piVar17[5]) >> 8) +
                              iStack120,
                          local_98._0_8_);
      lVar12 = (longlong)iVar11;
      lVar15 = (longlong)iStack116;
      local_b0 = lVar15 * *piVar17;
      iVar11 = (int)((ulonglong)(local_b0 + lVar12 * piVar17[3]) >> 8) -
                   (int)((ulonglong)(lVar10 * piVar17[1] + lVar9 * piVar17[4]) >> 8) >>
               1;
      iVar13 = (int)((ulonglong)(piVar17[1] * lVar15 + lVar12 * piVar17[4]) >> 8) +
                   (int)((ulonglong)(lVar10 * *piVar17 + lVar9 * piVar17[3]) >> 8) >>
               1;
      local_88 = (ulonglong)(uint)((int)((ulonglong)(lVar15 * piVar17[2] + lVar12 * piVar17[5]) >> 8) +
                                   local_70._4_4_)
                 << 0x20;
      uVar14 = 0;
      uVar16 = iVar13 * iVar13 + iVar11 * iVar11;
      uVar4 = 0x8000;
      uVar8 = uVar16;
      if (1 < uVar16)
      {
        do
        {
          uVar8 = uVar4 + uVar14 * 2 << (bVar5 & 0x1f);
          bVar5 = bVar5 - 1;
          if (uVar8 <= uVar16)
          {
            uVar14 = uVar14 + uVar4;
            uVar16 = uVar16 - uVar8;
          }
          uVar4 = uVar4 >> 1;
          uVar8 = uVar14;
        } while (uVar4 != 0);
      }
      goto LAB_18000601a;
    }
  }
  pauVar7 = (undefined(*)[16])(param_1 + 0x1bc + (longlong)(int)(local_c8 + iVar2) * 0x1c);
  uVar18 = local_88;
  if ((pauVar7 != (undefined(*)[16])0x0) &&
      (((undefined(*)[16]) & local_80 <= pauVar7 || (pauVar7[1] + 8 <= local_98))))
  {
    *pauVar7 = auVar19;
    *(ulonglong *)pauVar7[1] = local_88;
  }
LAB_1800060e6:
  if ((uVar4 != local_c8) &&
      (lVar9 = (longlong)(int)(local_c8 + iVar2) * 0x1c, *(int *)(lVar9 + lVar1) < 0))
  {
    *(undefined4 *)(lVar9 + lVar1) = 0;
  }
  *(undefined4 *)(local_a8 + 0x100) = 1;
  if ((param_4 != (undefined(*)[16])0x0) &&
      (((undefined(*)[16]) & local_80 <= param_4 || (param_4[1] + 8 <= local_98))))
  {
    *param_4 = auVar19;
    *(ulonglong *)param_4[1] = uVar18;
  }
  local_a0[7] = local_a0[7] + (uVar4 & 0xff) * 0x100 + 0x100;
  FUN_18005f100(local_68 ^ (ulonglong)auStack232);
  return;
}

ulonglong FUN_180006180(longlong param_1, uint *param_2, int *param_3, ulonglong *param_4)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  ulonglong uVar6;
  ulonglong *puVar7;
  longlong lVar8;

  iVar2 = *param_3;
  uVar5 = **(uint **)(param_3 + 2);
  if (1 < (longlong)param_3[1])
  {
    lVar8 = 1;
    do
    {
      uVar3 = (*(uint **)(param_3 + 2))[lVar8];
      iVar4 = *(int *)((longlong)(int)(uVar5 + iVar2) * 0x1c + 0x1b8 + param_1);
      piVar1 = (int *)((longlong)(int)(uVar3 + iVar2) * 0x1c + 0x1b8 + param_1);
      if (*piVar1 == iVar4 || *piVar1 < iVar4)
      {
        uVar3 = uVar5;
      }
      uVar5 = uVar3;
      lVar8 = lVar8 + 1;
    } while (lVar8 < param_3[1]);
  }
  uVar6 = (longlong)(int)(uVar5 + iVar2) * 0x1c;
  if (5 < *(int *)(uVar6 + 0x1b8 + param_1))
  {
    puVar7 = (ulonglong *)(param_1 + 0x1bc + uVar6);
    uVar6 = FUN_18002bd60(param_2, *(uint **)((longlong)(int)uVar5 * 8 + 0x28 + param_1), puVar7,
                          *(int **)(param_3 + 4), (int *)0x0, (int *)0x0, (int *)0x0, (int *)0x0, 0,
                          (int *)0x0);
    if (param_3[6] < (int)uVar6)
    {
      *(uint *)(param_1 + 0x87d8) = uVar5;
      param_2[0x40] = 1;
      *(undefined4 *)(*(longlong *)((longlong)(int)uVar5 * 8 + 0x28 + param_1) + 0x100) = 1;
      *(undefined4 *)(param_1 + 0x87e4) = 1;
      if (((param_4 != (ulonglong *)0x0) && (puVar7 != (ulonglong *)0x0)) &&
          ((puVar7 + 3 <= param_4 || (param_4 + 3 <= puVar7))))
      {
        puVar7 = (ulonglong *)((longlong)puVar7 - (longlong)param_4);
        lVar8 = 0x18;
        do
        {
          *(undefined *)param_4 = *(undefined *)((longlong)puVar7 + (longlong)param_4);
          param_4 = (ulonglong *)((longlong)param_4 + 1);
          lVar8 = lVar8 + -1;
        } while (lVar8 != 0);
      }
      uVar5 = (uVar5 & 0xff) * 0x100 + 0x100;
      uVar6 = (ulonglong)uVar5;
      param_3[7] = param_3[7] + uVar5;
    }
  }
  return uVar6;
}

// WARNING: Could not reconcile some variable overlaps

void FUN_180006300(longlong param_1, int *param_2, int param_3, int *param_4, int param_5)

{
  uint **ppuVar1;
  uint *puVar2;
  int iVar3;
  uint uVar4;
  byte bVar5;
  uint uVar6;
  int iVar7;
  longlong lVar8;
  longlong lVar9;
  int iVar10;
  uint uVar11;
  longlong lVar12;
  undefined8 *puVar13;
  longlong lVar14;
  ulonglong *puVar15;
  ulonglong uVar16;
  longlong lVar17;
  uint uVar18;
  uint uVar19;
  longlong lVar20;
  int iVar21;
  int iVar22;
  int iVar23;
  ulonglong uVar24;
  int iVar25;
  ulonglong uVar26;
  uint uVar27;
  ulonglong uVar28;
  int *piVar29;
  uint **ppuVar30;
  longlong lVar31;
  ulonglong local_1b8;
  ulonglong local_1b0;
  int local_1a8;
  uint local_1a4;
  ulonglong local_1a0;
  uint local_198;
  int *local_190;
  ulonglong local_188;
  longlong local_180;
  int *local_178;
  int *local_170;
  uint **local_168;
  int aiStack348[53];
  undefined8 local_88;
  uint uStack128;
  int iStack124;
  ulonglong local_78;
  undefined8 local_70;
  int iStack104;
  int iStack100;
  ulonglong local_60;
  int local_58;
  int local_54;
  int local_50;
  int local_4c;
  ulonglong local_48;
  ulonglong local_40;

  if (param_3 < 1)
  {
    return;
  }
  local_40 = DAT_1800b04e8 ^ (ulonglong)&stack0xfffffffffffffdf8;
  uVar28 = SEXT48(param_3);
  local_178 = aiStack348 + 2;
  uVar26 = 0;
  ppuVar30 = (uint **)(param_1 + 0x28 + uVar28 * 8);
  local_188 = 0;
  local_1a4 = 0;
  aiStack348[1] = param_3;
  uVar16 = uVar26;
  local_190 = param_2;
  local_180 = param_1;
  local_170 = param_4;
LAB_180006390:
  ppuVar1 = ppuVar30 + -1;
  ppuVar30 = ppuVar30 + -1;
  uVar27 = (int)uVar28 - 1;
  uVar28 = (ulonglong)uVar27;
  local_198 = uVar27;
  local_168 = ppuVar30;
  if (((*ppuVar1)[0x40] != 1) && (piVar29 = local_170, -1 < (int)uVar26))
  {
  LAB_1800063c0:
    puVar2 = *(uint **)(param_1 + 0x28 + (longlong)aiStack348[uVar16 + 1] * 8);
    lVar8 = (longlong)(int)(puVar2[0x41] + uVar27) * 0x1c;
    iVar22 = (int)uVar26;
    if (0x7fffffff < *(uint *)(lVar8 + 0x1b8 + param_1))
      goto LAB_180006427;
    puVar15 = (ulonglong *)(lVar8 + 0x1bc + param_1);
    iVar3 = FUN_18002bd60(puVar2, *ppuVar30, puVar15, piVar29, (int *)0x0, (int *)0x0, (int *)0x0,
                          (int *)0x0, 0, (int *)0x0);
    piVar29 = local_170;
    if (iVar3 <= param_5)
      goto LAB_180006427;
    iVar3 = 0x100;
    iVar7 = 0;
    local_1b0 = 0;
    uVar26 = 0x100;
    local_60 = 0x100;
    local_78 = 0x100;
    local_1a0 = 0;
    local_70 = 0x100;
    iStack104 = 0;
    iStack100 = 0;
    local_88 = 0x100;
    local_88._0_4_ = 0x100;
    uStack128 = 0;
    iStack124 = 0;
    if ((puVar15 != (ulonglong *)0x0) && ((puVar15 + 3 <= &local_70 || (&local_58 <= puVar15))))
    {
      iVar3 = *(int *)puVar15;
      iVar7 = *(int *)((longlong)puVar15 + 4);
      local_60 = puVar15[2];
      local_1b0 = local_60 >> 0x20;
      uVar26 = local_60 & 0xffffffff;
      local_70 = *puVar15;
      iStack104 = *(int *)(puVar15 + 1);
      iStack100 = *(int *)((longlong)puVar15 + 0xc);
    }
    iVar25 = (int)uVar26;
    local_1a8 = iVar22 + -1;
    uVar24 = local_70 & 0xffffffff;
    iVar21 = iStack100;
    uVar27 = local_70._4_4_;
    iVar23 = (int)local_70;
    iVar10 = iStack104;
    if (-1 < local_1a8)
    {
      lVar8 = (longlong)iVar22 * 4;
      lVar9 = uVar16 * 4;
      do
      {
        lVar31 = lVar9 + -4;
        lVar9 = (longlong)(*(int *)(*(longlong *)(param_1 + 0x28 + (longlong) * (int *)((longlong)aiStack348 + lVar9) * 8) +
                                    0x104) +
                           *(int *)((longlong)aiStack348 + lVar8 + 4)) *
                0x1c;
        if ((*(uint *)(lVar9 + 0x1b8 + param_1) < 0x80000000) &&
            (piVar29 = (int *)(param_1 + 0x1bc + lVar9), lVar8 = lVar31, piVar29 != (int *)0x0))
        {
          lVar12 = (longlong)*piVar29;
          lVar20 = (longlong)piVar29[1];
          lVar17 = (longlong)piVar29[4];
          lVar14 = (longlong)piVar29[3];
          lVar9 = (longlong)iVar10;
          iVar22 = (int)((ulonglong)((int)uVar27 * lVar14 + (int)uVar26 * lVar17) >> 8) +
                       (int)((ulonglong)((int)uVar24 * lVar12 + iVar21 * lVar20) >> 8) >>
                   1;
          iVar3 = (int)((ulonglong)((int)uVar24 * lVar14 + iVar21 * lVar17) >> 8) -
                      (int)((ulonglong)((int)uVar27 * lVar12 + (int)uVar26 * lVar20) >> 8) >>
                  1;
          iVar10 = (int)((ulonglong)(lVar9 * lVar12 + (int)local_1b0 * lVar20) >> 8) + piVar29[2];
          uVar6 = (int)((ulonglong)(lVar9 * lVar14 + (int)local_1b0 * lVar17) >> 8) + piVar29[5];
          local_1b0 = (ulonglong)uVar6;
          iStack104 = iVar10;
          uVar11 = 0x8000;
          uVar18 = iVar3 * iVar3 + iVar22 * iVar22;
          bVar5 = 0xf;
          uVar27 = uVar18;
          uVar19 = 0;
          if (1 < uVar18)
          {
            do
            {
              uVar4 = uVar11 + uVar19 * 2 << (bVar5 & 0x1f);
              bVar5 = bVar5 - 1;
              uVar27 = uVar19;
              if (uVar4 <= uVar18)
              {
                uVar27 = uVar19 + uVar11;
                uVar18 = uVar18 - uVar4;
              }
              uVar11 = uVar11 >> 1;
              uVar19 = uVar27;
            } while (uVar11 != 0);
          }
          if (uVar27 == 0)
          {
            uVar24 = 0x100;
            uVar27 = 0;
            local_70 = 0x100;
            iVar21 = 0;
          }
          else
          {
            uVar24 = (longlong)(((int)uVar27 >> 1) + iVar22 * 0x100) / (longlong)(int)uVar27 &
                     0xffffffff;
            uVar27 = (((int)uVar27 >> 1) + iVar3 * -0x100) / (int)uVar27;
            local_70 = uVar24 | (ulonglong)uVar27 << 0x20;
            iVar21 = -uVar27;
          }
          iStack100 = iVar21;
          local_60 = uVar24 | (ulonglong)uVar6 << 0x20;
          uVar26 = uVar24;
          param_1 = local_180;
        }
        iVar25 = (int)uVar26;
        local_1a8 = local_1a8 + -1;
        lVar9 = lVar31;
      } while (-1 < local_1a8);
      uVar28 = (ulonglong)local_198;
      iVar23 = (int)uVar24;
      iVar3 = (int)local_70;
      iVar7 = local_70._4_4_;
    }
    iVar22 = iVar23 * iVar25 - uVar27 * iVar21;
    if (iVar22 == 0)
    {
      local_58 = iVar3;
      local_54 = iVar7;
      local_50 = iStack104;
      local_4c = iStack100;
      local_48 = local_60;
      local_1b8 = local_60 >> 0x20;
      local_48._0_4_ = (int)local_60;
      iVar22 = iStack104;
      iVar10 = iStack100;
    }
    else
    {
      lVar8 = (longlong)iVar22;
      iVar3 = (int)(((longlong)iVar25 << 0x10) / lVar8);
      iVar7 = (int)(((longlong)(int)uVar27 * -0x10000) / lVar8);
      local_1b0 = ((longlong)iVar23 << 0x10) / lVar8;
      local_48._0_4_ = (int)local_1b0;
      local_1b8 = (((longlong)iVar21 * (longlong)iVar10 -
                    (longlong)(int)local_1b0 * (longlong)iVar23) *
                   0x100) /
                  lVar8;
      iVar22 = (int)((((longlong)(int)local_1b0 * (longlong)(int)uVar27 -
                       (longlong)iVar25 * (longlong)iVar10) *
                      0x100) /
                     lVar8);
      iVar10 = (int)(((longlong)iVar21 * -0x10000) / lVar8);
    }
    if (local_190 == (int *)0x0)
    {
      uVar27 = 0;
    }
    else
    {
      lVar9 = (longlong)local_190[1];
      lVar31 = (longlong)*local_190;
      uStack128 = (int)((ulonglong)((int)local_1b8 * lVar9 + lVar31 * iVar22) >> 8) + local_190[2];
      local_1b8 = (ulonglong)uStack128;
      lVar12 = (longlong)local_190[3];
      lVar8 = (longlong)local_190[4];
      uVar6 = 0;
      iVar21 = (int)((ulonglong)(lVar8 * iVar10 + lVar12 * iVar3) >> 8) -
                   (int)((ulonglong)((int)local_48 * lVar9 + lVar31 * iVar7) >> 8) >>
               1;
      uVar18 = (int)((ulonglong)(lVar8 * (int)local_1b8 + lVar12 * iVar22) >> 8) + local_190[5];
      local_1a0 = (ulonglong)uVar18;
      uVar11 = 0x8000;
      local_78 = (ulonglong)uVar18 << 0x20;
      bVar5 = 0xf;
      iVar22 = (int)((ulonglong)(lVar8 * (int)local_48 + lVar12 * iVar7) >> 8) +
                   (int)((ulonglong)(iVar10 * lVar9 + lVar31 * iVar3) >> 8) >>
               1;
      uVar27 = iVar21 * iVar21 + iVar22 * iVar22;
      uVar19 = uVar27;
      if (1 < uVar27)
      {
        do
        {
          uVar4 = uVar11 + uVar6 * 2 << (bVar5 & 0x1f);
          bVar5 = bVar5 - 1;
          uVar27 = uVar6;
          if (uVar4 <= uVar19)
          {
            uVar27 = uVar6 + uVar11;
            uVar19 = uVar19 - uVar4;
          }
          uVar11 = uVar11 >> 1;
          uVar6 = uVar27;
        } while (uVar11 != 0);
      }
      if (uVar27 == 0)
      {
        local_88._0_4_ = 0x100;
        uVar27 = 0;
        local_88 = 0x100;
        local_78 = CONCAT44(uVar18, 0x100);
        iStack124 = 0;
      }
      else
      {
        local_88 = (longlong)(((int)uVar27 >> 1) + iVar22 * 0x100) / (longlong)(int)uVar27 &
                   0xffffffff;
        local_78 = local_78 | local_88;
        uVar27 = (((int)uVar27 >> 1) + iVar21 * -0x100) / (int)uVar27;
        local_88 = local_88 | (ulonglong)uVar27 << 0x20;
        iStack124 = -uVar27;
      }
    }
    (*local_168)[0x40] = 1;
    iVar22 = *(int *)(param_1 + 0x87d8);
    iVar3 = (int)uVar28;
    if (iVar3 < iVar22)
    {
      lVar9 = (longlong)iStack124;
      lVar8 = (longlong)(int)uStack128;
      iVar7 = (int)local_88 * (int)local_88 - uVar27 * iStack124;
      if (iVar7 != 0)
      {
        lVar31 = (longlong)iVar7;
        local_88 = ((longlong)(int)local_88 << 0x10) / lVar31 & 0xffffffffU |
                   ((longlong)(int)uVar27 * -0x10000) / lVar31 << 0x20;
        uStack128 = (uint)((((longlong)(int)local_1a0 * (longlong)(int)uVar27 -
                             (int)local_88 * lVar8) *
                            0x100) /
                           lVar31);
        iStack124 = (int)((lVar9 * -0x10000) / lVar31);
        local_78 = ((longlong)(int)local_88 << 0x10) / lVar31 & 0xffffffffU |
                   ((lVar9 * lVar8 - (longlong)(int)local_1a0 * (longlong)(int)local_88) * 0x100) /
                           lVar31
                       << 0x20;
      }
      puVar13 = (undefined8 *)(param_1 + 0x1bc +
                               (longlong)(*(int *)(*(longlong *)(param_1 + 0x28 + (longlong)iVar22 * 8) + 0x104) + iVar3) *
                                   0x1c);
      if ((puVar13 != (undefined8 *)0x0) && ((&local_70 <= puVar13 || (puVar13 + 3 <= &local_88))))
      {
        *(int *)puVar13 = (int)local_88;
        *(undefined4 *)((longlong)puVar13 + 4) = local_88._4_4_;
        *(uint *)(puVar13 + 1) = uStack128;
        *(int *)((longlong)puVar13 + 0xc) = iStack124;
        puVar13[2] = local_78;
      }
      iVar22 = *(int *)(*(longlong *)(param_1 + 0x28 + (longlong) * (int *)(param_1 + 0x87d8) * 8) +
                        0x104) +
               iVar3;
    }
    else
    {
      puVar13 = (undefined8 *)(param_1 + 0x1bc + (longlong)(int)((*local_168)[0x41] + iVar22) * 0x1c);
      if ((puVar13 != (undefined8 *)0x0) && ((&local_70 <= puVar13 || (puVar13 + 3 <= &local_88))))
      {
        *(int *)puVar13 = (int)local_88;
        *(undefined4 *)((longlong)puVar13 + 4) = local_88._4_4_;
        *(uint *)(puVar13 + 1) = uStack128;
        *(int *)((longlong)puVar13 + 0xc) = iStack124;
        puVar13[2] = local_78;
      }
      iVar22 = (*local_168)[0x41] + *(int *)(param_1 + 0x87d8);
    }
    uVar16 = local_188 + 1;
    *local_178 = iVar3;
    *(undefined4 *)((longlong)iVar22 * 0x1c + 0x1b8 + param_1) = 0;
    local_1a4 = local_1a4 + 1;
    uVar26 = (ulonglong)local_1a4;
    local_178 = local_178 + 1;
    ppuVar30 = local_168;
    local_188 = uVar16;
  }
  goto LAB_180006437;
LAB_180006427:
  uVar16 = uVar16 - 1;
  uVar26 = (ulonglong)(iVar22 - 1U);
  if ((int)(iVar22 - 1U) < 0)
    goto code_r0x00018000642f;
  goto LAB_1800063c0;
code_r0x00018000642f:
  uVar26 = (ulonglong)local_1a4;
  uVar16 = local_188;
LAB_180006437:
  if ((int)uVar28 < 1)
  {
    FUN_18005f100(local_40 ^ (ulonglong)&stack0xfffffffffffffdf8);
    return;
  }
  goto LAB_180006390;
}

// WARNING: Could not reconcile some variable overlaps

void FUN_180006be0(longlong param_1, int *param_2, int param_3, int *param_4, int param_5)

{
  uint *puVar1;
  int iVar2;
  uint uVar3;
  ulonglong uVar4;
  byte bVar5;
  int iVar6;
  uint uVar7;
  longlong lVar8;
  longlong lVar9;
  ulonglong *puVar10;
  longlong lVar11;
  longlong lVar12;
  int iVar13;
  int iVar14;
  uint uVar15;
  int *piVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  longlong *plVar20;
  int iVar21;
  int local_98;
  int local_94;
  ulonglong local_90;
  int *local_88;
  longlong local_80;
  int *local_78;
  longlong local_70;
  longlong local_68;
  undefined8 local_60;
  uint uStack88;
  int iStack84;
  ulonglong local_50;
  ulonglong local_48[2];

  local_48[0] = DAT_1800b04e8 ^ (ulonglong)&stack0xffffffffffffff18;
  iVar21 = *(int *)(param_1 + 0x1c) + -2;
  local_98 = param_3;
  local_94 = iVar21;
  local_88 = param_2;
  local_78 = param_4;
  if (param_3 < iVar21)
  {
    lVar11 = (longlong)param_3 * 8;
    plVar20 = (longlong *)(param_1 + 0x28 + lVar11);
    iVar14 = param_3;
    local_80 = lVar11;
    do
    {
      puVar1 = (uint *)plVar20[1];
      plVar20 = plVar20 + 1;
      param_3 = param_3 + 1;
      if ((puVar1[0x40] != 1) &&
          (lVar12 = (longlong)(int)(puVar1[0x41] + iVar14) * 0x1c,
           *(uint *)(lVar12 + 0x1b8 + param_1) < 0x80000000))
      {
        uVar19 = 0;
        iVar2 = FUN_18002bd60(puVar1, *(uint **)(lVar11 + 0x28 + param_1),
                              (ulonglong *)(param_1 + 0x1bc + lVar12), param_4, (int *)0x0, (int *)0x0,
                              (int *)0x0, (int *)0x0, 0, (int *)0x0);
        lVar11 = local_80;
        param_4 = local_78;
        iVar14 = local_98;
        if (param_5 < iVar2)
        {
          piVar16 = (int *)(param_1 + 0x1bc + lVar12);
          iVar2 = 0x100;
          local_50 = 0x100;
          local_60 = 0x100;
          uStack88 = 0;
          iStack84 = 0;
          if ((param_2 == (int *)0x0) || (piVar16 == (int *)0x0))
          {
            uVar18 = 0;
          }
          else
          {
            lVar8 = (longlong)param_2[1];
            lVar12 = (longlong)*param_2;
            uStack88 = (int)((ulonglong)(piVar16[2] * lVar12 + piVar16[5] * lVar8) >> 8) +
                       local_88[2];
            local_90 = (ulonglong)uStack88;
            lVar9 = (longlong)local_88[4];
            local_68 = (longlong)local_88[3];
            local_70 = local_68 * *piVar16;
            iVar13 = (int)((ulonglong)(local_70 + lVar9 * piVar16[3]) >> 8) -
                         (int)((ulonglong)(piVar16[1] * lVar12 + piVar16[4] * lVar8) >> 8) >>
                     1;
            uVar7 = 0x8000;
            uVar19 = (int)((ulonglong)(local_68 * piVar16[2] + lVar9 * piVar16[5]) >> 8) +
                     local_88[5];
            iVar2 = (int)((ulonglong)(local_68 * piVar16[1] + lVar9 * piVar16[4]) >> 8) +
                        (int)((ulonglong)(lVar12 * *piVar16 + lVar8 * piVar16[3]) >> 8) >>
                    1;
            bVar5 = 0xf;
            local_50 = (ulonglong)uVar19 << 0x20;
            uVar15 = iVar13 * iVar13 + iVar2 * iVar2;
            uVar18 = uVar15;
            uVar17 = 0;
            if (1 < uVar15)
            {
              do
              {
                uVar3 = uVar7 + uVar17 * 2 << (bVar5 & 0x1f);
                bVar5 = bVar5 - 1;
                uVar18 = uVar17;
                if (uVar3 <= uVar15)
                {
                  uVar18 = uVar17 + uVar7;
                  uVar15 = uVar15 - uVar3;
                }
                uVar7 = uVar7 >> 1;
                uVar17 = uVar18;
              } while (uVar7 != 0);
            }
            iVar21 = local_94;
            if (uVar18 == 0)
            {
              uVar18 = 0;
              iVar2 = 0x100;
              local_60 = 0x100;
              local_50 = CONCAT44(uVar19, 0x100);
              iStack84 = 0;
            }
            else
            {
              uVar4 = (longlong)(((int)uVar18 >> 1) + iVar2 * 0x100) / (longlong)(int)uVar18 &
                      0xffffffff;
              iVar2 = (int)uVar4;
              uVar18 = (((int)uVar18 >> 1) + iVar13 * -0x100) / (int)uVar18;
              local_60 = uVar4 | (ulonglong)uVar18 << 0x20;
              iStack84 = -uVar18;
              local_50 = local_50 | uVar4;
            }
          }
          *(undefined4 *)(*plVar20 + 0x100) = 1;
          iVar13 = *(int *)(param_1 + 0x87d8);
          if (param_3 < iVar13)
          {
            lVar8 = (longlong)iStack84;
            lVar12 = (longlong)(int)uStack88;
            iVar6 = iVar2 * iVar2 - uVar18 * iStack84;
            if (iVar6 != 0)
            {
              lVar9 = (longlong)iVar6;
              local_60 = ((longlong)iVar2 << 0x10) / lVar9 & 0xffffffffU |
                         ((longlong)(int)uVar18 * -0x10000) / lVar9 << 0x20;
              uStack88 = (uint)((((longlong)(int)uVar19 * (longlong)(int)uVar18 - iVar2 * lVar12) *
                                 0x100) /
                                lVar9);
              iStack84 = (int)((lVar8 * -0x10000) / lVar9);
              local_50 = ((longlong)iVar2 << 0x10) / lVar9 & 0xffffffffU |
                         ((lVar8 * lVar12 - (longlong)(int)uVar19 * (longlong)iVar2) * 0x100) /
                                 lVar9
                             << 0x20;
            }
            puVar10 = (ulonglong *)(param_1 + 0x1bc +
                                    (longlong)(*(int *)(*(longlong *)(param_1 + 0x28 + (longlong)iVar13 * 8) + 0x104) +
                                               param_3) *
                                        0x1c);
            if ((puVar10 != (ulonglong *)0x0) &&
                ((local_48 <= puVar10 || (puVar10 + 3 <= &local_60))))
            {
              *(undefined4 *)puVar10 = (undefined4)local_60;
              *(undefined4 *)((longlong)puVar10 + 4) = local_60._4_4_;
              *(uint *)(puVar10 + 1) = uStack88;
              *(int *)((longlong)puVar10 + 0xc) = iStack84;
              puVar10[2] = local_50;
            }
            iVar2 = *(int *)(*(longlong *)(param_1 + 0x28 + (longlong) * (int *)(param_1 + 0x87d8) * 8) + 0x104) +
                    param_3;
          }
          else
          {
            puVar10 = (ulonglong *)(param_1 + 0x1bc + (longlong)(*(int *)(*plVar20 + 0x104) + iVar13) * 0x1c);
            if ((puVar10 != (ulonglong *)0x0) &&
                ((local_48 <= puVar10 || (puVar10 + 3 <= &local_60))))
            {
              *(undefined4 *)puVar10 = (undefined4)local_60;
              *(undefined4 *)((longlong)puVar10 + 4) = local_60._4_4_;
              *(uint *)(puVar10 + 1) = uStack88;
              *(int *)((longlong)puVar10 + 0xc) = iStack84;
              puVar10[2] = local_50;
            }
            iVar2 = *(int *)(*plVar20 + 0x104) + *(int *)(param_1 + 0x87d8);
          }
          *(undefined4 *)((longlong)iVar2 * 0x1c + 0x1b8 + param_1) = 0;
          param_2 = local_88;
        }
      }
    } while (param_3 < iVar21);
  }
  FUN_18005f100(local_48[0] ^ (ulonglong)&stack0xffffffffffffff18);
  return;
}

// WARNING: Could not reconcile some variable overlaps

void FUN_180007050(longlong param_1, uint *param_2, int *param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  byte bVar4;
  int iVar5;
  longlong lVar6;
  uint uVar7;
  longlong lVar8;
  longlong lVar9;
  longlong *plVar10;
  ulonglong *puVar11;
  uint uVar12;
  int *piVar13;
  uint uVar14;
  int iVar15;
  uint uVar16;
  ulonglong local_c8;
  int local_c0;
  longlong local_b8;
  int *local_b0;
  longlong *local_a8;
  longlong local_a0;
  longlong local_98;
  longlong local_90;
  uint *local_88;
  longlong local_80;
  undefined8 local_78;
  uint uStack112;
  int iStack108;
  ulonglong local_68;
  int local_60;
  int iStack92;
  int iStack88;
  int iStack84;
  undefined8 local_50;
  ulonglong local_48;

  local_48 = DAT_1800b04e8 ^ (ulonglong)&stack0xfffffffffffffee8;
  local_c0 = *param_3;
  local_90 = (longlong)param_3[1];
  local_80 = *(longlong *)(param_3 + 2);
  local_88 = param_2;
  if (0 < local_90)
  {
    local_b8 = 0;
    do
    {
      lVar6 = local_b8;
      iVar1 = *(int *)(local_80 + local_b8 * 4);
      plVar10 = (longlong *)(param_1 + 0x28 + (longlong)iVar1 * 8);
      puVar11 = (ulonglong *)(param_1 + 0x1bc + (longlong)(local_c0 + iVar1) * 0x1c);
      local_a8 = plVar10;
      iVar2 = FUN_18002bd60(local_88, *(uint **)(param_1 + 0x28 + (longlong)iVar1 * 8), puVar11,
                            *(int **)(param_3 + 4), (int *)0x0, (int *)0x0, (int *)0x0, (int *)0x0, 0,
                            (int *)0x0);
      if (0xd0 < iVar2)
      {
        iVar2 = 0x100;
        local_68 = 0x100;
        local_a0 = 0;
        local_50._0_4_ = 0x100;
        local_50 = 0x100;
        local_78 = 0x100;
        uStack112 = 0;
        iStack108 = 0;
        local_60 = 0x100;
        iStack92 = 0;
        iStack88 = 0;
        iStack84 = 0;
        if (puVar11 != (ulonglong *)0x0)
        {
          FUN_180023cd0((int *)puVar11, &local_60);
        }
        uVar16 = (uint)local_a0;
        local_b0 = (int *)(param_1 + 0x1bc +
                           (longlong)(*(int *)(param_1 + 0x87d8) + local_c0) * 0x1c);
        if (local_b0 == (int *)0x0)
        {
          local_c8 = (ulonglong)uStack112;
          iVar15 = (int)local_78;
        }
        else
        {
          lVar6 = (longlong)local_b0[1];
          lVar8 = (longlong)*local_b0;
          uStack112 = (int)((ulonglong)(local_50._4_4_ * lVar6 + lVar8 * iStack88) >> 8) +
                      local_b0[2];
          local_c8 = (ulonglong)uStack112;
          lVar9 = (longlong)local_b0[3];
          local_a0 = (longlong)local_b0[4];
          local_98 = local_a0 * iStack84;
          uVar16 = (int)((ulonglong)(local_a0 * local_50._4_4_ + lVar9 * iStack88) >> 8) +
                   local_b0[5];
          uVar7 = 0x8000;
          iVar2 = (int)((ulonglong)(local_98 + lVar9 * local_60) >> 8) -
                      (int)((ulonglong)((int)local_50 * lVar6 + lVar8 * iStack92) >> 8) >>
                  1;
          iVar15 = (int)((ulonglong)(local_a0 * (int)local_50 + lVar9 * iStack92) >> 8) +
                       (int)((ulonglong)(iStack84 * lVar6 + lVar8 * local_60) >> 8) >>
                   1;
          bVar4 = 0xf;
          local_68 = (ulonglong)uVar16 << 0x20;
          uVar12 = iVar2 * iVar2 + iVar15 * iVar15;
          local_78._4_4_ = uVar12;
          uVar14 = 0;
          if (1 < uVar12)
          {
            do
            {
              uVar3 = uVar7 + uVar14 * 2 << (bVar4 & 0x1f);
              bVar4 = bVar4 - 1;
              local_78._4_4_ = uVar14;
              if (uVar3 <= uVar12)
              {
                local_78._4_4_ = uVar14 + uVar7;
                uVar12 = uVar12 - uVar3;
              }
              uVar7 = uVar7 >> 1;
              uVar14 = local_78._4_4_;
            } while (uVar7 != 0);
          }
          lVar6 = local_b8;
          plVar10 = local_a8;
          if (local_78._4_4_ == 0)
          {
            iVar15 = 0x100;
            local_78._4_4_ = 0;
            local_78 = 0x100;
            local_68 = CONCAT44(uVar16, 0x100);
            iStack108 = 0;
            iVar2 = 0x100;
          }
          else
          {
            local_78 = (longlong)(((int)local_78._4_4_ >> 1) + iVar15 * 0x100) /
                           (longlong)(int)local_78._4_4_ &
                       0xffffffff;
            iVar15 = (int)local_78;
            local_68 = local_68 | local_78;
            local_78._4_4_ = (((int)local_78._4_4_ >> 1) + iVar2 * -0x100) / (int)local_78._4_4_;
            local_78 = local_78 | (ulonglong)local_78._4_4_ << 0x20;
            iStack108 = -local_78._4_4_;
            iVar2 = iVar15;
          }
        }
        *(undefined4 *)(*plVar10 + 0x100) = 1;
        iVar5 = *(int *)(param_1 + 0x87d8);
        if (iVar1 < iVar5)
        {
          piVar13 = (int *)(param_1 + 0x1bc +
                            (longlong)(*(int *)(*(longlong *)(param_1 + 0x28 + (longlong)iVar5 * 8) + 0x104) +
                                       iVar1) *
                                0x1c);
          if (piVar13 != (int *)0x0)
          {
            local_b8 = (longlong)iVar15;
            local_98 = (longlong)(int)local_78._4_4_;
            local_a8 = (longlong *)(longlong)(int)uStack112;
            local_b0 = (int *)(longlong)(int)uVar16;
            iVar5 = iVar15 * iVar2 - local_78._4_4_ * iStack108;
            if (iVar5 == 0)
            {
              piVar13[2] = (int)local_c8;
              *piVar13 = iVar15;
              piVar13[1] = local_78._4_4_;
              piVar13[3] = iStack108;
              piVar13[4] = iVar2;
              piVar13[5] = uVar16;
            }
            else
            {
              lVar8 = (longlong)iVar5;
              *piVar13 = (int)(((longlong)iVar2 << 0x10) / lVar8);
              piVar13[1] = (int)((local_98 * -0x10000) / lVar8);
              piVar13[2] = (int)((((longlong)local_b0 * local_98 -
                                   (longlong)iVar2 * (longlong)local_a8) *
                                  0x100) /
                                 lVar8);
              piVar13[3] = (int)(((longlong)iStack108 * -0x10000) / lVar8);
              piVar13[4] = (int)((local_b8 << 0x10) / lVar8);
              piVar13[5] = (int)((((longlong)iStack108 * (longlong)local_a8 -
                                   (longlong)local_b0 * local_b8) *
                                  0x100) /
                                 lVar8);
            }
          }
          iVar2 = *(int *)(*(longlong *)(param_1 + 0x28 + (longlong) * (int *)(param_1 + 0x87d8) * 8) + 0x104) + iVar1;
        }
        else
        {
          piVar13 = (int *)(param_1 + 0x1bc + (longlong)(*(int *)(*plVar10 + 0x104) + iVar5) * 0x1c);
          if ((piVar13 != (int *)0x0) && ((&local_60 <= piVar13 || (piVar13 + 6 <= &local_78))))
          {
            *piVar13 = (int)local_78;
            piVar13[1] = local_78._4_4_;
            piVar13[2] = uStack112;
            piVar13[3] = iStack108;
            *(ulonglong *)(piVar13 + 4) = local_68;
          }
          iVar2 = *(int *)(*plVar10 + 0x104) + *(int *)(param_1 + 0x87d8);
        }
        *(undefined4 *)((longlong)iVar2 * 0x1c + 0x1b8 + param_1) = 0;
        FUN_180006300(param_1, (int *)&local_78, iVar1, *(int **)(param_3 + 4), param_3[6]);
        FUN_180006be0(param_1, (int *)&local_78, iVar1, *(int **)(param_3 + 4), param_3[6]);
      }
      local_b8 = lVar6 + 1;
    } while (local_b8 < local_90);
  }
  FUN_18005f100(local_48 ^ (ulonglong)&stack0xfffffffffffffee8);
  return;
}

void FUN_1800076d0(longlong param_1, uint *param_2, int *param_3)

{
  int *piVar1;
  int iVar2;
  uint *puVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  longlong *plVar9;
  longlong lVar10;
  ulonglong uVar11;
  uint *puVar12;
  uint uVar13;
  longlong lVar14;
  int iVar15;
  int iVar16;
  ulonglong *puVar17;
  uint *local_a28;
  int local_a20;
  int local_a1c;
  int local_a18[516];
  ulonglong local_208;
  ulonglong uStack512;
  ulonglong local_1f8;
  ulonglong local_1f0;
  uint local_1e8[52];
  uint local_118[52];
  ulonglong local_48;

  local_48 = DAT_1800b04e8 ^ (ulonglong)&stack0xfffffffffffff588;
  lVar10 = (longlong)param_3[1];
  puVar3 = *(uint **)(param_3 + 2);
  uVar7 = 0;
  iVar6 = 0;
  if (0 < lVar10)
  {
    puVar12 = local_118;
    uVar8 = uVar7;
    uVar11 = uVar7;
    do
    {
      if (*(int *)(*(longlong *)(param_1 + 0x28 + (longlong)(int)puVar3[uVar8] * 8) + 0x100) == 1)
      {
        uVar11 = (ulonglong)((int)uVar11 + 1);
        *puVar12 = puVar3[uVar8];
        puVar12 = puVar12 + 1;
      }
      iVar6 = (int)uVar11;
      uVar8 = uVar8 + 1;
    } while ((longlong)uVar8 < lVar10);
  }
  local_1f8 = 0x100;
  local_208 = 0x100;
  uStack512 = 0;
  local_a28 = param_2;
  if (iVar6 < 1)
  {
    if (*(int *)(param_1 + 0x87e4) == 0)
    {
      iVar6 = *param_3;
      uVar13 = *puVar3;
      if (1 < lVar10)
      {
        lVar14 = 1;
        do
        {
          iVar2 = *(int *)((longlong)(int)(uVar13 + iVar6) * 0x1c + 0x1b8 + param_1);
          piVar1 = (int *)((longlong)(int)(iVar6 + puVar3[lVar14]) * 0x1c + 0x1b8 + param_1);
          uVar4 = puVar3[lVar14];
          if (*piVar1 == iVar2 || *piVar1 < iVar2)
          {
            uVar4 = uVar13;
          }
          uVar13 = uVar4;
          lVar14 = lVar14 + 1;
        } while (lVar14 < lVar10);
      }
      lVar14 = (longlong)(int)(uVar13 + iVar6) * 0x1c;
      if (5 < *(int *)(lVar14 + 0x1b8 + param_1))
      {
        puVar17 = (ulonglong *)(param_1 + 0x1bc + lVar14);
        lVar14 = param_1 + (longlong)(int)uVar13 * 8;
        iVar6 = FUN_18002bd60(param_2, *(uint **)(lVar14 + 0x28), puVar17, *(int **)(param_3 + 4),
                              (int *)0x0, (int *)0x0, (int *)0x0, (int *)0x0, 0, (int *)0x0);
        if (param_3[6] < iVar6)
        {
          *(uint *)(param_1 + 0x87d8) = uVar13;
          local_a28[0x40] = 1;
          *(undefined4 *)(*(longlong *)(lVar14 + 0x28) + 0x100) = 1;
          *(undefined4 *)(param_1 + 0x87e4) = 1;
          if ((puVar17 != (ulonglong *)0x0) &&
              ((puVar17 + 3 <= &local_208 || (&local_1f0 <= puVar17))))
          {
            local_208 = *puVar17;
            uStack512 = puVar17[1];
            local_1f8 = puVar17[2];
          }
          param_3[7] = param_3[7] + (uVar13 & 0xff) * 0x100 + 0x100;
        }
      }
    }
  }
  else
  {
    param_3[1] = iVar6;
    *(uint **)(param_3 + 2) = local_118;
    FUN_180005c80(0x100, param_1);
  }
  if (0 < lVar10)
  {
    uVar11 = 0;
    puVar12 = local_1e8;
    uVar13 = 0;
    uVar8 = uVar11;
    do
    {
      if (*(int *)(*(longlong *)(param_1 + 0x28 + (longlong)(int)puVar3[uVar8] * 8) + 0x100) == 0)
      {
        uVar7 = (ulonglong)((int)uVar7 + 1);
        *puVar12 = puVar3[uVar8];
        puVar12 = puVar12 + 1;
      }
      uVar8 = uVar8 + 1;
    } while ((longlong)uVar8 < lVar10);
    iVar6 = (int)uVar7;
    if (0 < iVar6)
    {
      param_3[1] = iVar6;
      *(uint **)(param_3 + 2) = local_1e8;
      if ((*(int *)(param_1 + 0x87e4) == 0) || (local_a28[0x40] == 0))
      {
        local_a1c = *(int *)(param_1 + 8);
        local_a20 = *(int *)(param_1 + 4);
        iVar2 = *param_3;
        iVar15 = local_a1c * local_a20;
        uVar7 = uVar11;
        iVar16 = iVar15;
        if (0 < (longlong)iVar6)
        {
          do
          {
            iVar5 = FUN_18002bd60(local_a28,
                                  *(uint **)(param_1 + 0x28 + (longlong)(int)local_1e8[uVar11] * 8),
                                  (ulonglong *)(param_1 + 0x1bc +
                                                (longlong)(int)(local_1e8[uVar11] + iVar2) * 0x1c),
                                  *(int **)(param_3 + 4), (int *)0x0, (int *)0x0, (int *)0x0, (int *)0x0, 0, (int *)0x0);
            if (param_3[6] < iVar5)
            {
              uVar8 = FUN_18002d430(local_a1c, local_a20, local_a1c, local_a20,
                                    (int *)(param_1 + 0x1bc +
                                            (longlong)(int)(local_1e8[uVar11] + iVar2) * 0x1c),
                                    local_a18);
              iVar5 = iVar15 - (int)uVar8;
              if (iVar5 < iVar16)
              {
                uVar7 = (ulonglong)local_1e8[uVar11];
                iVar16 = iVar5;
              }
            }
            uVar13 = (uint)uVar7;
            uVar11 = uVar11 + 1;
          } while ((longlong)uVar11 < (longlong)iVar6);
        }
        param_3[8] = iVar16;
        param_3[7] = param_3[7] + (uVar13 & 0xff) * 0x100 + 0x100;
      }
      else
      {
        FUN_180007050(param_1, local_a28, param_3);
      }
    }
  }
  if ((*(int *)(param_1 + 0x87e4) == 1) && (local_a28[0x40] != 0))
  {
    iVar6 = FUN_180016b60(param_1, (longlong)local_a28, (int *)&local_208,
                          *(int *)(param_1 + 0x1c) + -1);
    param_3[8] = iVar6;
    if (*(int *)(param_1 + 0xc) != 0)
    {
      param_3[8] = iVar6 * 4;
    }
  }
  iVar6 = *(int *)(param_1 + 0x1c) + -1;
  lVar10 = (longlong)iVar6;
  if (0 < iVar6)
  {
    plVar9 = (longlong *)(param_1 + 0x20 + lVar10 * 8);
    do
    {
      if (*(int *)(*plVar9 + 0x114) != 5)
      {
        if ((-1 < iVar6 + -1) &&
            (lVar10 = (longlong)(*param_3 + iVar6 + -1) * 0x1c,
             5 < *(int *)(lVar10 + param_1 + 0x1b8)))
        {
          iVar6 = *(int *)(param_1 + 8);
          iVar2 = *(int *)(param_1 + 4);
          uVar7 = FUN_18002d430(iVar6, iVar2, iVar6, iVar2, (int *)(lVar10 + 4 + param_1 + 0x1b8),
                                local_a18);
          param_3[7] = ((iVar2 * iVar6 - (int)uVar7) * 100) / (iVar2 * iVar6 + 1) << 0x18 ^
                       param_3[7] & 0xffffffU;
        }
        break;
      }
      iVar6 = iVar6 + -1;
      lVar10 = lVar10 + -1;
      plVar9 = plVar9 + -1;
    } while (0 < lVar10);
  }
  FUN_18005f100(local_48 ^ (ulonglong)&stack0xfffffffffffff588);
  return;
}

void FUN_180007bc0(int *param_1, undefined4 *param_2, uint *param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  longlong lVar4;
  uint uVar5;
  ulonglong uVar6;
  uint *puVar7;
  longlong lVar8;
  int iVar9;
  undefined auStack392[32];
  int *local_168;
  int local_158;
  uint local_154;
  uint local_150;
  undefined8 local_14c;
  uint local_140;
  int local_13c;
  undefined *local_138;
  uint *local_130;
  uint local_128;
  int local_124;
  int local_120;
  undefined local_118[208];
  ulonglong local_48;

  local_48 = DAT_1800b04e8 ^ (ulonglong)auStack392;
  local_150 = param_3[3];
  uVar6 = 0;
  local_14c = 0;
  if ((*param_3 < 9) && ((0x132U >> (*param_3 & 0x1f) & 1) != 0))
  {
    local_14c = 4;
  }
  local_154 = param_3[1];
  uVar1 = param_3[8];
  uVar5 = param_3[2];
  uVar2 = param_3[7];
  if (uVar2 < uVar1)
  {
    if (param_2[0x3c] == 0)
    {
      *param_1 = 0;
    }
    else
    {
      if (uVar2 == 0)
      {
        puVar3 = *(undefined4 **)(param_3 + 10);
        local_130 = (uint *)0x100;
        FUN_180005390(param_2, puVar3, param_3[5]);
        param_3[(ulonglong)param_3[9] * 7 + 0x6e] = 0xffffffff;
        puVar7 = param_3 + (ulonglong)param_3[9] * 7 + 0x6f;
        if ((puVar7 != (uint *)0x0) && ((&local_128 <= puVar7 || (puVar7 + 6 <= &local_140))))
        {
          *puVar7 = 0x100;
          puVar7[1] = 0;
          puVar7[2] = 0;
          puVar7[3] = 0;
          *(uint **)(puVar7 + 4) = local_130;
        }
        param_3[9] = param_3[9] + 1;
        iVar9 = 0x64000064;
        *(undefined4 *)(*(longlong *)(param_3 + (ulonglong)param_3[7] * 2 + 10) + 0x108) =
            puVar3[0x42];
        *(undefined4 *)(*(longlong *)(param_3 + (ulonglong)param_3[7] * 2 + 10) + 0x10c) =
            puVar3[0x43];
        *(undefined4 *)(*(longlong *)(param_3 + (ulonglong)param_3[7] * 2 + 10) + 0x114) = 0;
        *(undefined4 *)(*(longlong *)(param_3 + (ulonglong)param_3[7] * 2 + 10) + 0x11c) = 0;
        *(undefined4 *)(*(longlong *)(param_3 + (ulonglong)param_3[7] * 2 + 10) + 0x120) = 0;
        *(undefined4 *)(*(longlong *)(param_3 + (ulonglong)param_3[7] * 2 + 10) + 0x124) = 0;
        *(undefined8 *)(*(longlong *)(param_3 + (ulonglong)param_3[7] * 2 + 10) + 0x140) = 0;
        param_3[7] = param_3[7] + 1;
      }
      else
      {
        puVar7 = *(uint **)(param_3 + (ulonglong)uVar2 * 2 + 10);
        uVar2 = param_3[9];
        local_158 = 0;
        FUN_180005390(param_2, puVar7, param_3[5]);
        puVar7[0x41] = uVar2;
        puVar7[0x45] = 0;
        puVar7[0x47] = param_3[7];
        local_168 = &local_158;
        *(undefined8 *)(puVar7 + 0x48) = 0;
        *(undefined8 *)(puVar7 + 0x50) = 0;
        param_3[7] = param_3[7] + 1;
        FUN_1800057a0(param_3, puVar7, &local_150, local_118);
        if (local_158 < 1)
        {
          iVar9 = 0x64000064;
        }
        else
        {
          iVar9 = uVar5 * local_154;
          local_13c = local_158;
          local_138 = local_118;
          local_130 = &local_150;
          local_128 = 0xcd;
          local_124 = 0x64000000;
          local_140 = uVar2;
          local_120 = iVar9;
          FUN_1800076d0((longlong)param_3, puVar7, (int *)&local_140);
          iVar9 = (local_120 * 100) / (iVar9 + 1) + local_124;
        }
      }
      if (param_3[7] != 0)
      {
        do
        {
          param_3[uVar6 + 0x21fa] = (uint)uVar6;
          uVar5 = (uint)uVar6 + 1;
          uVar6 = (ulonglong)uVar5;
        } while (uVar5 < param_3[7]);
      }
      lVar8 = (longlong)(int)param_3[7];
      if (lVar8 < (int)uVar1)
      {
        lVar4 = (int)uVar1 - lVar8;
        puVar7 = param_3 + lVar8 + 0x21fa;
        while (lVar4 != 0)
        {
          lVar4 = lVar4 + -1;
          *puVar7 = 0xffffffff;
          puVar7 = puVar7 + 1;
        }
      }
      *param_1 = iVar9;
      if ((param_3[7] == param_3[8]) && (FUN_18002e530((longlong)param_3, 0), 1 < *param_3 - 9))
      {
        FUN_180017490((longlong)param_3);
      }
    }
  }
  else
  {
    *param_1 = 0;
  }
  FUN_18005f100(local_48 ^ (ulonglong)auStack392);
  return;
}

void FUN_180007f10(undefined4 *param_1, int param_2)

{
  undefined4 local_78;
  undefined4 uStack116;
  undefined4 uStack112;
  undefined4 uStack108;
  undefined4 local_68;
  undefined4 uStack100;
  ulonglong local_60[2];
  undefined4 local_50;
  undefined4 uStack76;
  ulonglong local_48[2];
  undefined4 local_38;
  undefined4 uStack52;
  ulonglong local_30[2];
  undefined4 local_20;
  undefined4 uStack28;
  ulonglong local_18[2];

  local_18[0] = DAT_1800b04e8 ^ (ulonglong)&local_78;
  uStack100 = 4;
  local_50 = 0x14;
  uStack76 = 4;
  local_38 = 0x14;
  uStack52 = 6;
  local_20 = 0x14;
  uStack28 = 6;
  uStack108 = 300;
  if (param_2 == 9)
  {
    if ((local_18 <= &local_78) || (local_60 <= local_30))
    {
      uStack108 = 600;
      uStack100 = 6;
    }
  }
  else
  {
    if (param_2 == 10)
    {
      if ((local_30 <= &local_78) || (local_60 <= local_48))
      {
        uStack100 = 6;
        uStack108 = 600;
      }
    }
    else
    {
      uStack100 = 4;
      uStack108 = 300;
    }
  }
  local_68 = 0x14;
  uStack112 = 0x14;
  uStack116 = 0x1e;
  local_78 = 0x14;
  param_1[3] = 0x14;
  param_1[4] = uStack108;
  param_1[5] = 0x14;
  param_1[6] = uStack100;
  *(undefined8 *)(param_1 + 7) = 0;
  *(undefined8 *)(param_1 + 9) = 0;
  param_1[0xb] = 0;
  *(undefined8 *)(param_1 + 0xf) = 0;
  param_1[0x11] = 0;
  param_1[1] = 0x14;
  param_1[2] = 0x1e;
  *param_1 = 0xffff0000;
  param_1[0xd] = 0x14;
  param_1[0xe] = 0x1e;
  FUN_18005f100(local_18[0] ^ (ulonglong)&local_78);
  return;
}

undefined8
FUN_180008060(longlong param_1, longlong param_2, int param_3, int param_4, int param_5, int param_6,
              undefined4 *param_7, undefined4 *param_8)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  int iVar4;

  uVar1 = *(ushort *)(param_1 + 0x1c);
  iVar4 = 100;
  iVar3 = 100;
  if (*(int *)(param_2 + 0x24) < *(int *)(param_2 + 0x18))
  {
    iVar4 = param_6;
    iVar3 = param_5;
  }
  iVar2 = *(int *)(param_2 + 0x44);
  if (*(int *)(param_2 + 0x40) < 9)
  {
    iVar3 = iVar4 + 5;
    if (iVar2 <= *(int *)(param_2 + 4))
    {
      iVar3 = iVar4;
    }
    if ((iVar3 < param_4) && (uVar1 != 0))
    {
      *(undefined4 *)(*(longlong *)(param_1 + 0x20 + (ulonglong)uVar1 * 8) + 0x114) = 5;
      *(int *)(param_2 + 0x44) = *(int *)(param_2 + 0x44) + 1;
      *(int *)(param_2 + 0x3c) = *(int *)(param_2 + 0x3c) + 1;
      *(int *)(param_2 + 0x24) = *(int *)(param_2 + 0x24) + 1;
      *(int *)(param_2 + 0x38) = *(int *)(param_2 + 0x38) + -1;
      *param_8 = 1;
      goto LAB_18000814e;
    }
  }
  else
  {
    if (*(int *)(param_2 + 4) < iVar2)
    {
      iVar4 = iVar4 + 5;
      iVar3 = iVar3 + 5;
    }
    if (((iVar4 < param_4) && (iVar3 < param_3)) && (uVar1 != 0))
    {
      *(undefined4 *)(*(longlong *)(param_1 + 0x20 + (ulonglong)uVar1 * 8) + 0x114) = 5;
      *(int *)(param_2 + 0x44) = *(int *)(param_2 + 0x44) + 1;
      *(int *)(param_2 + 0x3c) = *(int *)(param_2 + 0x3c) + 1;
      *(int *)(param_2 + 0x24) = *(int *)(param_2 + 0x24) + 1;
      *(int *)(param_2 + 0x38) = *(int *)(param_2 + 0x38) + -1;
      *param_8 = 2;
      goto LAB_18000814e;
    }
  }
  *(int *)(param_2 + 0x3c) = *(int *)(param_2 + 0x3c) + 1;
  *(int *)(param_2 + 0x34) = *(int *)(param_2 + 0x34) + -1;
  *(int *)(param_2 + 0x38) = *(int *)(param_2 + 0x38) + -1;
  *(int *)(param_2 + 0x40) = *(int *)(param_2 + 0x40) + 1;
  *(int *)(param_2 + 0x44) = iVar2 + 1;
  *(undefined4 *)(param_2 + 0x24) = 0;
  *param_8 = 0;
LAB_18000814e:
  *param_7 = 3;
  return 0;
}

ulonglong FUN_1800083c0(longlong param_1)

{
  byte *pbVar1;
  uint uVar2;
  ulonglong uVar3;
  byte *pbVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;

  iVar7 = *(int *)(param_1 + 0xc);
  pbVar4 = *(byte **)(param_1 + 0x18);
  iVar5 = 0;
  iVar6 = 0;
  iVar8 = 0;
  if (1 < iVar7)
  {
    uVar2 = (iVar7 - 2U >> 1) + 1;
    uVar3 = (ulonglong)uVar2;
    iVar7 = iVar7 + uVar2 * -2;
    do
    {
      iVar5 = iVar5 + *(int *)(&DAT_18007caf0 + (ulonglong)*pbVar4 * 4);
      pbVar1 = pbVar4 + 1;
      pbVar4 = pbVar4 + 2;
      iVar6 = iVar6 + *(int *)(&DAT_18007caf0 + (ulonglong)*pbVar1 * 4);
      uVar3 = uVar3 - 1;
    } while (uVar3 != 0);
  }
  if (0 < iVar7)
  {
    iVar8 = *(int *)(&DAT_18007caf0 + (ulonglong)*pbVar4 * 4);
  }
  return (ulonglong)(uint)(iVar6 + iVar5 + iVar8);
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180008440(void)

{
  undefined local_28[16];
  undefined8 local_18;
  ulonglong local_10[2];

  local_10[0] = DAT_1800b04e8 ^ (ulonglong)local_28;
  local_18 = 0x100;
  if ((local_10 < (ulonglong *)0x9) || ((undefined *)0x1f < local_28))
  {
    _DAT_00000008 = 0x100;
    _DAT_0000000c = 0;
    _DAT_00000010 = 0;
    _DAT_00000014 = 0;
    _DAT_00000018 = 0x100;
  }
  FUN_18005f100(local_10[0] ^ (ulonglong)local_28);
  uRam0000000000000000 = 0;
  _DAT_00000004 = 0;
  return;
}

undefined8 FUN_1800084b0(int *param_1, undefined4 *param_2)

{
  int iVar1;
  int iVar2;
  short sVar3;
  uint uVar4;
  ulonglong uVar5;
  byte bVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint local_res8[4];
  uint local_res18[4];

  if ((param_1 != (int *)0x0) && (param_2 != (undefined4 *)0x0))
  {
    iVar1 = *param_1;
    uVar10 = 0;
    iVar2 = param_1[3];
    bVar6 = 0xf;
    uVar8 = iVar2 * iVar2 + iVar1 * iVar1;
    uVar4 = 0x8000;
    uVar9 = uVar8;
    if (1 < uVar8)
    {
      do
      {
        uVar7 = uVar4 + uVar10 * 2 << (bVar6 & 0x1f);
        bVar6 = bVar6 - 1;
        uVar8 = uVar10;
        if (uVar7 <= uVar9)
        {
          uVar8 = uVar10 + uVar4;
          uVar9 = uVar9 - uVar7;
        }
        uVar4 = uVar4 >> 1;
        uVar10 = uVar8;
      } while (uVar4 != 0);
    }
    local_res8[0] = (iVar1 << 8) / (int)(uVar8 + 1);
    local_res18[0] = (iVar2 << 8) / (int)(uVar8 + 1);
    uVar5 = FUN_1800350d0(local_res18, local_res8);
    sVar3 = (short)uVar5;
    if (sVar3 < 0)
    {
      sVar3 = sVar3 + 0x6488;
    }
    *param_2 = (int)((ulonglong)((longlong)sVar3 * 0x395) >> 0x10);
    return 0;
  }
  return 0x80000002;
}
