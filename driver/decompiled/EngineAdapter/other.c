#include "funcs.c"
#include "libs.c"
#include "types.c"

undefined8 thunk_FUN_180009cd0(int *param_1, longlong param_2, uint param_3)
{
    undefined8 uVar1;

    uVar1 = FUN_180009cd0(param_1, param_2, param_3);
    return uVar1;
}

void thunk_FUN_180060a18(LPVOID param_1)
{
    thunk_FUN_180060a18(param_1);
    return;
}

void thunk_FUN_180060a18(LPVOID param_1)
{
    _free_base(param_1);
    return;
}

void thunk_FUN_180060a18(LPVOID param_1)
{
    _free_base(param_1);
    return;
}

undefined (*)[32] thunk_FUN_180078cfc(undefined (*param_1)[32], int param_2)
{
    ulonglong uVar1;
    short sVar2;
    code *pcVar3;
    int iVar4;
    errno_t eVar5;
    BOOL BVar6;
    ulong *puVar7;
    undefined(*pauVar8)[32];
    longlong lVar9;
    undefined(**ppauVar10)[32];
    wchar_t *_Dst;
    undefined(*pauVar11)[32];
    undefined(**ppauVar12)[32];
    ulonglong uVar13;
    uint uVar14;
    undefined(*pauVar15)[32];
    ulonglong uVar16;
    longlong lVar17;

    pauVar11 = (undefined(*)[32])0x0;
    uVar14 = 0;
    if (param_1 == (undefined(*)[32])0x0)
    {
        puVar7 = __doserrno();
        *puVar7 = 0x16;
        return (undefined(*)[32])0xffffffffffffffff;
    }
    pauVar8 = (undefined(*)[32])wcschr((wchar_t *)param_1, L'=');
    pauVar15 = param_1;
    if ((pauVar8 == (undefined(*)[32])0x0) || (pauVar8 == param_1))
    {
    LAB_180078fc8:
        puVar7 = __doserrno();
        uVar14 = 0xffffffff;
        *puVar7 = 0x16;
    }
    else
    {
        sVar2 = *(short *)(*pauVar8 + 2);
        if (DAT_180101c98 == DAT_180101ca0)
        {
            DAT_180101c98 = (undefined(**)[32])copy_environment_wchar_t_((wchar_t **)DAT_180101c98);
        }
        if (DAT_180101c98 == (undefined(**)[32])0x0)
        {
            if ((param_2 == 0) || (DAT_180101c90 == (LPVOID)0x0))
            {
                if (sVar2 == 0)
                    goto LAB_180078fdd;
                if (DAT_180101c90 != (LPVOID)0x0)
                {
                LAB_180078e17:
                    DAT_180101c98 = (undefined(**)[32])_calloc_base(1, 8);
                    _free_base((LPVOID)0x0);
                    goto LAB_180078e39;
                }
                DAT_180101c90 = _calloc_base(1, 8);
                _free_base((LPVOID)0x0);
                if (DAT_180101c90 != (LPVOID)0x0)
                {
                    if (DAT_180101c98 != (undefined(**)[32])0x0)
                        goto LAB_180078e3e;
                    goto LAB_180078e17;
                }
            }
            else
            {
                lVar9 = __dcrt_get_or_create_wide_environment_nolock();
                if (lVar9 == 0)
                    goto LAB_180078fc8;
                if (DAT_180101c98 == DAT_180101ca0)
                {
                    DAT_180101c98 = (undefined(**)[32])copy_environment_wchar_t_((wchar_t **)DAT_180101c98);
                }
            LAB_180078e39:
                if (DAT_180101c98 != (undefined(**)[32])0x0)
                    goto LAB_180078e3e;
            }
            uVar14 = 0xffffffff;
        }
        else
        {
        LAB_180078e3e:
            ppauVar10 = DAT_180101c98;
            uVar16 = (longlong)((longlong)pauVar8 - (longlong)param_1) >> 1;
            pauVar8 = *DAT_180101c98;
            ppauVar12 = DAT_180101c98;
            while (pauVar8 != (undefined(*)[32])0x0)
            {
                iVar4 = FUN_180085190(param_1, *ppauVar12, uVar16);
                if ((iVar4 == 0) &&
                    ((*(short *)(**ppauVar12 + uVar16 * 2) == 0x3d ||
                      (*(short *)(**ppauVar12 + uVar16 * 2) == 0))))
                {
                    uVar13 = (longlong)((longlong)ppauVar12 - (longlong)ppauVar10) >> 3;
                    goto LAB_180078e90;
                }
                ppauVar12 = ppauVar12 + 1;
                pauVar8 = *ppauVar12;
            }
            uVar13 = -((longlong)((longlong)ppauVar12 - (longlong)ppauVar10) >> 3);
        LAB_180078e90:
            if ((-1 < (longlong)uVar13) && (*ppauVar10 != (undefined(*)[32])0x0))
            {
                _free_base(ppauVar10[uVar13]);
                if (sVar2 == 0)
                {
                    while (ppauVar10[uVar13] != (undefined(*)[32])0x0)
                    {
                        ppauVar10[uVar13] = ppauVar10[uVar13 + 1];
                        uVar13 = uVar13 + 1;
                    }
                    ppauVar10 = (undefined(**)[32])_recalloc_base(ppauVar10, uVar13, 8);
                    _free_base((LPVOID)0x0);
                    if (ppauVar10 != (undefined(**)[32])0x0)
                    {
                        DAT_180101c98 = ppauVar10;
                    }
                }
                else
                {
                    ppauVar10[uVar13] = param_1;
                    pauVar15 = pauVar11;
                }
            LAB_180078f4b:
                if (param_2 != 0)
                {
                    lVar9 = -1;
                    do
                    {
                        lVar17 = lVar9;
                        lVar9 = lVar17 + 1;
                    } while (*(short *)(*param_1 + lVar17 * 2 + 2) != 0);
                    _Dst = (wchar_t *)_calloc_base(lVar17 + 3U, 2);
                    if (_Dst != (wchar_t *)0x0)
                    {
                        eVar5 = wcscpy_s(_Dst, lVar17 + 3U, (wchar_t *)param_1);
                        if (eVar5 != 0)
                        {
                            _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
                            pcVar3 = (code *)swi(3);
                            pauVar11 = (undefined(*)[32])(*pcVar3)();
                            return pauVar11;
                        }
                        (_Dst + uVar16 + 1)[-1] = L'\0';
                        BVar6 = SetEnvironmentVariableW(_Dst, (LPCWSTR)(-(ulonglong)(sVar2 != 0) &
                                                                        (ulonglong)(_Dst + uVar16 + 1)));
                        if (BVar6 == 0)
                        {
                            puVar7 = __doserrno();
                            pauVar11 = (undefined(*)[32])0xffffffff;
                            *puVar7 = 0x2a;
                        }
                    }
                    _free_base(_Dst);
                }
                goto LAB_180078fdf;
            }
            if (sVar2 != 0)
            {
                uVar1 = -uVar13 + 2;
                if ((-uVar13 <= uVar1) && (uVar1 < 0x1fffffffffffffff))
                {
                    ppauVar10 = (undefined(**)[32])_recalloc_base(ppauVar10, uVar1, 8);
                    _free_base((LPVOID)0x0);
                    if (ppauVar10 != (undefined(**)[32])0x0)
                    {
                        ppauVar10[-uVar13] = param_1;
                        ppauVar10[1 - uVar13] = (undefined(*)[32])0x0;
                        pauVar15 = pauVar11;
                        DAT_180101c98 = ppauVar10;
                        goto LAB_180078f4b;
                    }
                }
                uVar14 = 0xffffffff;
            }
        }
    }
LAB_180078fdd:
    pauVar11 = (undefined(*)[32])(ulonglong)uVar14;
LAB_180078fdf:
    _free_base(pauVar15);
    return pauVar11;
}

void thunk_FUN_180083b78(ulonglong *param_1, char *param_2, ulonglong param_3, char *param_4)
{
    bool bVar1;
    errno_t eVar2;
    ulong *puVar3;
    char *_Src;
    longlong lVar4;
    ulonglong uVar6;
    longlong lVar5;

    __acrt_lock(0xb);
    if (param_1 != (ulonglong *)0x0)
    {
        *param_1 = 0;
        if (param_2 == (char *)0x0)
        {
        LAB_180083bd4:
            if (param_3 == 0)
                goto LAB_180083bd9;
        LAB_180083be0:
            bVar1 = false;
        }
        else
        {
            if (param_3 == 0)
            {
                if (param_2 == (char *)0x0)
                    goto LAB_180083bd4;
                goto LAB_180083be0;
            }
        LAB_180083bd9:
            bVar1 = true;
        }
        if (bVar1)
        {
            if (param_2 != (char *)0x0)
            {
                *param_2 = '\0';
            }
            _Src = common_getenv_nolock_char_(param_4);
            if (_Src != (char *)0x0)
            {
                lVar4 = -1;
                do
                {
                    lVar5 = lVar4;
                    lVar4 = lVar5 + 1;
                } while (_Src[lVar4] != '\0');
                uVar6 = lVar5 + 2;
                *param_1 = uVar6;
                if (((param_3 != 0) && (uVar6 <= param_3)) &&
                    (eVar2 = strcpy_s(param_2, param_3, _Src), eVar2 != 0))
                {
                    _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
                    return;
                }
            }
            goto LAB_180083c30;
        }
    }
    puVar3 = __doserrno();
    *puVar3 = 0x16;
    FUN_18006738c();
LAB_180083c30:
    __acrt_unlock(0xb);
    return;
}

void thunk_FUN_1800095c0(uint *param_1, undefined *param_2)
{
    int iVar1;
    int iVar2;
    uint uVar3;
    ulonglong uVar4;
    ulonglong uVar5;
    undefined8 *puVar6;
    uint uVar7;
    uint uVar8;
    undefined auStack88[32];
    undefined uStack56;
    undefined uStack55;
    undefined uStack54;
    byte bStack53;
    undefined uStack52;
    undefined uStack51;
    undefined uStack50;
    undefined uStack49;
    ulonglong uStack48;

    uStack48 = DAT_1800ee160 ^ (ulonglong)auStack88;
    uVar7 = *param_1;
    iVar1 = uVar7 * 8;
    iVar2 = param_1[1] << 3;
    bStack53 = (byte)(uVar7 >> 0x1d) | (byte)iVar2;
    uStack49 = (undefined)iVar1;
    uStack56 = (undefined)((uint)iVar2 >> 0x18);
    uStack55 = (undefined)((uint)iVar2 >> 0x10);
    uStack54 = (undefined)((uint)iVar2 >> 8);
    uStack52 = (undefined)((uint)iVar1 >> 0x18);
    uStack51 = (undefined)((uint)iVar1 >> 0x10);
    uVar3 = uVar7 & 0x3f;
    uStack50 = (undefined)((uint)iVar1 >> 8);
    uVar8 = 0x38 - uVar3;
    if (0x37 < uVar3)
    {
        uVar8 = 0x78 - uVar3;
    }
    if (uVar8 != 0)
    {
        FUN_1800094e0(param_1, (undefined8 *)&DAT_1800d3730, (ulonglong)uVar8);
        uVar7 = *param_1;
    }
    uVar8 = uVar7 & 0x3f;
    *param_1 = uVar7 + 8;
    puVar6 = (undefined8 *)&uStack56;
    uVar5 = (ulonglong)(0x40 - uVar8);
    uVar4 = 8;
    if (uVar7 + 8 < 8)
    {
        param_1[1] = param_1[1] + 1;
    }
    if ((uVar8 != 0) && (uVar5 < 9))
    {
        FUN_18003b8e0((undefined8 *)((longlong)param_1 + (ulonglong)uVar8 + 0x28),
                      (undefined8 *)&uStack56, uVar5);
        FUN_180008850((longlong)param_1, (undefined *)(param_1 + 10));
        uVar4 = 8 - uVar5;
        puVar6 = (undefined8 *)(&uStack56 + uVar5);
        uVar8 = 0;
        if (0x3f < uVar4)
        {
            uVar5 = uVar4 >> 6;
            uVar4 = uVar4 + uVar5 * -0x40;
            do
            {
                FUN_180008850((longlong)param_1, (undefined *)puVar6);
                puVar6 = puVar6 + 8;
                uVar5 = uVar5 - 1;
            } while (uVar5 != 0);
        }
        if (uVar4 == 0)
            goto LAB_180009713;
    }
    FUN_18003b8e0((undefined8 *)((longlong)param_1 + (ulonglong)uVar8 + 0x28), puVar6, uVar4);
LAB_180009713:
    *param_2 = *(undefined *)((longlong)param_1 + 0xb);
    param_2[1] = *(undefined *)((longlong)param_1 + 10);
    param_2[2] = (char)(param_1[2] >> 8);
    param_2[3] = *(undefined *)(param_1 + 2);
    param_2[4] = *(undefined *)((longlong)param_1 + 0xf);
    param_2[5] = *(undefined *)((longlong)param_1 + 0xe);
    param_2[6] = (char)(param_1[3] >> 8);
    param_2[7] = *(undefined *)(param_1 + 3);
    param_2[8] = *(undefined *)((longlong)param_1 + 0x13);
    param_2[9] = *(undefined *)((longlong)param_1 + 0x12);
    param_2[10] = (char)(param_1[4] >> 8);
    param_2[0xb] = *(undefined *)(param_1 + 4);
    param_2[0xc] = *(undefined *)((longlong)param_1 + 0x17);
    param_2[0xd] = *(undefined *)((longlong)param_1 + 0x16);
    param_2[0xe] = (char)(param_1[5] >> 8);
    param_2[0xf] = *(undefined *)(param_1 + 5);
    param_2[0x10] = *(undefined *)((longlong)param_1 + 0x1b);
    param_2[0x11] = *(undefined *)((longlong)param_1 + 0x1a);
    param_2[0x12] = (char)(param_1[6] >> 8);
    param_2[0x13] = *(undefined *)(param_1 + 6);
    param_2[0x14] = *(undefined *)((longlong)param_1 + 0x1f);
    param_2[0x15] = *(undefined *)((longlong)param_1 + 0x1e);
    param_2[0x16] = (char)(param_1[7] >> 8);
    param_2[0x17] = *(undefined *)(param_1 + 7);
    param_2[0x18] = *(undefined *)((longlong)param_1 + 0x23);
    param_2[0x19] = *(undefined *)((longlong)param_1 + 0x22);
    param_2[0x1a] = (char)(param_1[8] >> 8);
    param_2[0x1b] = *(undefined *)(param_1 + 8);
    if (param_1[0x1a] == 0)
    {
        param_2[0x1c] = *(undefined *)((longlong)param_1 + 0x27);
        param_2[0x1d] = *(undefined *)((longlong)param_1 + 0x26);
        param_2[0x1e] = (char)(param_1[9] >> 8);
        param_2[0x1f] = *(undefined *)(param_1 + 9);
    }
    FUN_180034d00(uStack48 ^ (ulonglong)auStack88);
    return;
}

char *thunk_FUN_1800789dc(char *param_1, int param_2)
{
    ulonglong uVar1;
    char cVar2;
    code *pcVar3;
    int iVar4;
    errno_t eVar5;
    BOOL BVar6;
    ulong *puVar7;
    char *pcVar8;
    longlong lVar9;
    char **ppcVar10;
    char *pcVar11;
    char *pcVar12;
    char **ppcVar13;
    ulonglong uVar14;
    uint uVar15;
    char *pcVar16;
    char *_MaxCount;
    longlong lVar17;

    pcVar12 = (char *)0x0;
    uVar15 = 0;
    if (param_1 == (char *)0x0)
    {
        puVar7 = __doserrno();
        *puVar7 = 0x16;
        return (char *)0xffffffffffffffff;
    }
    pcVar8 = strchr(param_1, 0x3d);
    pcVar16 = param_1;
    if ((pcVar8 == (char *)0x0) || (pcVar8 == param_1))
    {
    LAB_180078cac:
        puVar7 = __doserrno();
        uVar15 = 0xffffffff;
        *puVar7 = 0x16;
    }
    else
    {
        cVar2 = pcVar8[1];
        if (DAT_180101c90 == DAT_180101ca8)
        {
            DAT_180101c90 = copy_environment_char_(DAT_180101c90);
        }
        if (DAT_180101c90 == (char **)0x0)
        {
            if ((param_2 != 0) && (DAT_180101c98 != (LPVOID)0x0))
            {
                lVar9 = __dcrt_get_or_create_narrow_environment_nolock();
                if (lVar9 != 0)
                {
                    if (DAT_180101c90 == DAT_180101ca8)
                    {
                        DAT_180101c90 = copy_environment_char_(DAT_180101c90);
                    }
                    goto LAB_180078b20;
                }
                goto LAB_180078cac;
            }
            if (cVar2 != '\0')
            {
                DAT_180101c90 = (char **)_calloc_base(1, 8);
                _free_base((LPVOID)0x0);
                if (DAT_180101c90 != (char **)0x0)
                {
                    if (DAT_180101c98 == (LPVOID)0x0)
                    {
                        DAT_180101c98 = _calloc_base(1, 8);
                        _free_base((LPVOID)0x0);
                        if (DAT_180101c98 == (LPVOID)0x0)
                            goto LAB_180078ae3;
                    }
                LAB_180078b20:
                    if (DAT_180101c90 != (char **)0x0)
                        goto LAB_180078b25;
                }
            LAB_180078ae3:
                uVar15 = 0xffffffff;
            }
        }
        else
        {
        LAB_180078b25:
            ppcVar10 = DAT_180101c90;
            _MaxCount = pcVar8 + -(longlong)param_1;
            pcVar11 = *DAT_180101c90;
            ppcVar13 = DAT_180101c90;
            while (pcVar11 != (char *)0x0)
            {
                iVar4 = _strnicoll(param_1, *ppcVar13, (size_t)_MaxCount);
                if ((iVar4 == 0) &&
                    ((_MaxCount[(longlong)*ppcVar13] == '=' || (_MaxCount[(longlong)*ppcVar13] == '\0'))))
                {
                    uVar14 = (longlong)((longlong)ppcVar13 - (longlong)ppcVar10) >> 3;
                    goto LAB_180078b71;
                }
                ppcVar13 = ppcVar13 + 1;
                pcVar11 = *ppcVar13;
            }
            uVar14 = -((longlong)((longlong)ppcVar13 - (longlong)ppcVar10) >> 3);
        LAB_180078b71:
            if ((-1 < (longlong)uVar14) && (*ppcVar10 != (char *)0x0))
            {
                _free_base(ppcVar10[uVar14]);
                if (cVar2 == '\0')
                {
                    while (ppcVar10[uVar14] != (char *)0x0)
                    {
                        ppcVar10[uVar14] = ppcVar10[uVar14 + 1];
                        uVar14 = uVar14 + 1;
                    }
                    ppcVar10 = (char **)_recalloc_base(ppcVar10, uVar14, 8);
                    _free_base((LPVOID)0x0);
                    if (ppcVar10 != (char **)0x0)
                    {
                        DAT_180101c90 = ppcVar10;
                    }
                }
                else
                {
                    ppcVar10[uVar14] = param_1;
                    pcVar16 = pcVar12;
                }
            LAB_180078c2a:
                if (param_2 != 0)
                {
                    lVar9 = -1;
                    do
                    {
                        lVar17 = lVar9;
                        lVar9 = lVar17 + 1;
                    } while (param_1[lVar17 + 1] != '\0');
                    pcVar11 = (char *)_calloc_base(lVar17 + 3, 1);
                    if (pcVar11 != (char *)0x0)
                    {
                        eVar5 = strcpy_s(pcVar11, lVar17 + 3, param_1);
                        if (eVar5 != 0)
                        {
                            _invoke_watson((wchar_t *)0x0, (wchar_t *)0x0, (wchar_t *)0x0, 0, 0);
                            pcVar3 = (code *)swi(3);
                            pcVar12 = (char *)(*pcVar3)();
                            return pcVar12;
                        }
                        (pcVar8 + 1 + (longlong)(pcVar11 + -(longlong)param_1))[-1] = '\0';
                        BVar6 = SetEnvironmentVariableA(pcVar11, (LPCSTR)(-(ulonglong)(cVar2 != '\0') &
                                                                          (ulonglong)(pcVar8 + 1 +
                                                                                      (longlong)(pcVar11 + -(longlong)param_1))));
                        if (BVar6 == 0)
                        {
                            puVar7 = __doserrno();
                            pcVar12 = (char *)0xffffffff;
                            *puVar7 = 0x2a;
                        }
                    }
                    _free_base(pcVar11);
                }
                goto LAB_180078cc3;
            }
            if (cVar2 != '\0')
            {
                uVar1 = -uVar14 + 2;
                if ((-uVar14 <= uVar1) && (uVar1 < 0x1fffffffffffffff))
                {
                    ppcVar10 = (char **)_recalloc_base(ppcVar10, uVar1, 8);
                    _free_base((LPVOID)0x0);
                    if (ppcVar10 != (char **)0x0)
                    {
                        ppcVar10[-uVar14] = param_1;
                        ppcVar10[1 - uVar14] = (char *)0x0;
                        pcVar16 = pcVar12;
                        DAT_180101c90 = ppcVar10;
                        goto LAB_180078c2a;
                    }
                }
                uVar15 = 0xffffffff;
            }
        }
    }
    pcVar12 = (char *)(ulonglong)uVar15;
LAB_180078cc3:
    _free_base(pcVar16);
    return pcVar12;
}

__int64 thunk_FUN_18008310c(uint param_1, __int64 param_2, int param_3)
{
    ulong *puVar1;
    longlong lVar2;
    __int64 _Var3;

    if (param_1 == 0xfffffffe)
    {
        puVar1 = __doserrno();
        *puVar1 = 0;
        puVar1 = __doserrno();
        *puVar1 = 9;
    }
    else
    {
        if ((-1 < (int)param_1) && (param_1 < DAT_180102110))
        {
            lVar2 = (ulonglong)(param_1 & 0x3f) * 0x40;
            if ((*(byte *)(lVar2 + 0x38 +
                           *(longlong *)((longlong)&DAT_180101d10 + ((longlong)(int)param_1 >> 6) * 8)) &
                 1) != 0)
            {
                FID_conflict___acrt_lowio_lock_fh(param_1);
                _Var3 = -1;
                if ((*(byte *)(lVar2 + 0x38 +
                               *(longlong *)((longlong)&DAT_180101d10 + ((longlong)(int)param_1 >> 6) * 8)) &
                     1) == 0)
                {
                    puVar1 = __doserrno();
                    *puVar1 = 9;
                    puVar1 = __doserrno();
                    *puVar1 = 0;
                }
                else
                {
                    _Var3 = common_lseek_nolock___int64_(param_1, param_2, param_3);
                }
                FID_conflict___acrt_lowio_lock_fh(param_1);
                return _Var3;
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

void Unwind_18008a2d0(undefined8 param_1, longlong param_2)
{
    FUN_180029650((_AfxBindHost **)(param_2 + 0xa0));
    return;
}

void Unwind_18008a2eb(undefined8 param_1, longlong param_2)
{
    FUN_180029650((_AfxBindHost **)(param_2 + 0xe0));
    return;
}

void Unwind_18008a306(undefined8 param_1, longlong param_2)
{
    FUN_180029650((_AfxBindHost **)(param_2 + 0xd8));
    return;
}

void Unwind_18008a321(undefined8 param_1, longlong param_2)
{
    FUN_180029650((_AfxBindHost **)(param_2 + 0xa0));
    return;
}

void Unwind_18008a33c(undefined8 param_1, longlong param_2)
{
    FUN_180029650((_AfxBindHost **)(param_2 + 0xe0));
    return;
}

void Unwind_18008a357(undefined8 param_1, longlong param_2)
{
    FUN_180029650((_AfxBindHost **)(param_2 + 0xd8));
    return;
}

undefined8 Catch_All_18008a372(void)
{
    return 0x1800247a6;
}

void Unwind_18008a390(undefined8 param_1, longlong param_2)
{
    thunk_FUN_180060a18(*(LPVOID *)(param_2 + 0x20));
    return;
}

void Unwind_18008a3b0(undefined8 param_1, longlong param_2)
{
    thunk_FUN_180060a18(*(LPVOID *)(param_2 + 0x20));
    return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void Unwind_18008a5e2(void)
{
    _DAT_180101884 = _DAT_180101884 + -1;
    return;
}

undefined *Catch_All_18008a460(void)
{
    return &LAB_18003aa4b;
}
