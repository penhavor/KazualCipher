# -*- coding: utf-8 -*-
"""
Самопроверки, печать тестовых векторов, подробная трассировка Kazual-64
и замер стоимости — портация §12/§13 эталонного однофайловика.
Для повседневной проверки корректности используйте pytest-набор в tests/.
"""

import os
import time
import random as _random

from . import gorn as _gorn
from .gf import (POLY8, POLY16, _mul_poly, MUL8, MUL16, inv8, inv16,
                 ALOG16, cauchy, cauchy_inv_tables, mat_mul_gf8,
                 branch_number, is_mds_submats, mds_rows, mds_apply,
                 mds_cols, mds_apply_cols)
from .gorn import (gorn_hash, gorn_perm, gorn_perm_inv, NBYTES, IV_BYTES,
                   ROUNDS, AFFA, SIGTBL, _fold)
from .sbox import SBOXES, properties, SA1, SC1, SA2, SC2, SA3, SC3
from .forge import Reader, perm_from_int, perm_seed_bytes, multiset_from_int
from .components import (WeavePar, pair_list, carryweave, carryweave_inv,
                         ShutterPar, shutter, shutter_inv)
from .spec import FULL, K64, MICRO
from .rounds import F, F_weights, F_trace, H_trace, cross_consts
from . import schedule as _sched
from .schedule import key_schedule
from .core import encrypt, decrypt, encrypt_trace, hamming, _x
from .batch import encrypt_blocks, decrypt_blocks, cupy_backend, _batch_ctx, _np
from .vectors import VECTORS, K64_VECTORS, EXPECTED_C


_PASS, _FAIL = '  \033[32m✓\033[0m', '  \033[31m✗\033[0m'


def _chk(ok, text):
    print(('%s' % (_PASS if ok else _FAIL)) + ' ' + text)
    return bool(ok)



def _ord_gen(gen, poly, n):
    x, c = 1, 0
    while True:
        x = _mul_poly(x, gen, poly, n)
        c += 1
        if x == 1:
            return c


def _ord16(v):
    x, c = 1, 0
    while True:
        x = MUL16(x, v)
        c += 1
        if x == 1:
            return c


def selftest():
    """Полный цикл самопроверок."""
    rnd = _random.Random(20251017)
    allok = True
    t0 = time.time()

    print('\n§1  ПОЛЯ')
    allok &= _chk(_ord_gen(2, POLY8, 8) == 51, 'порядок(2) в GF(2^8) = 51 (2 НЕ первообразно — ловушка)')
    allok &= _chk(_ord_gen(3, POLY8, 8) == 255, 'порядок(3) в GF(2^8) = 255 (образующий)')
    allok &= _chk(_ord_gen(2, POLY16, 16) == 65535, 'порядок(2) в GF(2^16) = 65535 (образующий)')
    allok &= _chk(all(MUL8(a, b) == MUL8(b, a) for a in rnd.sample(range(256), 12)
                      for b in rnd.sample(range(256), 12)), 'GF(2^8): коммутативность (выборочно)')
    allok &= _chk(all(MUL16(a, inv16(a)) == 1 for a in rnd.sample(range(1, 65536), 200)),
                  'GF(2^16): a · a⁻¹ = 1 (200 элементов)')

    print('\n§2  ГОРН-1024')
    ok = True
    for _ in range(30):
        s0 = os.urandom(NBYTES)
        if gorn_perm_inv(gorn_perm(s0)) != s0:
            ok = False
            break
    allok &= _chk(ok, 'внутренняя перестановка биективна (30 тиглей, явный обратный ход)')
    imgs = []
    for i in range(NBYTES * 8):
        e = bytearray(NBYTES)
        e[i // 8] = 1 << (7 - i % 8)
        imgs.append(int.from_bytes(_fold(bytes(e)), 'big'))
    piv, rk = [], 0
    for v in imgs:
        while v:
            bl = v.bit_length()
            c = [p for p in piv if p.bit_length() == bl]
            if c:
                v ^= c[0]
            else:
                piv.append(v)
                rk += 1
                break
    allok &= _chk(rk == 512, 'ранг свёртки _fold = %d из 512 (сюръективность)' % rk)
    allok &= _chk(all(min(AFFA[r]) > 0 for r in range(ROUNDS)) and
                  all(len(set(SIGTBL[r][p])) == 256
                      for r in range(ROUNDS) for p in range(0, NBYTES, 7)),
                  'Σ-слой: AFFA ≠ 0 везде, сопряжения инверсии биективны (условие губки)')
    base = os.urandom(64)
    h0 = gorn_hash(base, b'sac')
    ds = []
    for i in range(128):
        b2 = bytearray(base)
        b2[i // 8] ^= 1 << (i % 8)
        ds.append(hamming(h0, gorn_hash(bytes(b2), b'sac')))
    allok &= _chk(200 < sum(ds) / len(ds) < 312, 'SAC: среднее %.1f бит из 512 (идеал 256)' % (sum(ds) / len(ds)))
    seen, col = set(), 0
    for _ in range(1500):
        h = gorn_hash(os.urandom(32), b'col')
        col += h in seen
        seen.add(h)
    allok &= _chk(col == 0, 'коллизий на 1500 случайных входов: %d' % col)

    print('\n§3  S-BOX\'Ы (полный перебор) и константы')
    for nm, S, want in zip(('S1 = A1(x^3) Gold  ', 'S2 = A2(x^57) Kasami', 'S3 = A3(x^254) inv  '),
                           SBOXES, ((2, 112, 86), (2, 112, 86), (4, 112, 256))):
        p = properties(S)
        allok &= _chk((p['delta'], p['nl'], p['img']) == want,
                      '%s : delta=%d  NL=%d  deg=%d  |image|=%d/256'
                      % (nm, p['delta'], p['nl'], p['deg'], p['img']))
    allok &= _chk(bytes((SA1, SC1, SA2, SC2, SA3, SC3)) == bytes.fromhex('9B33E23DEDC1'),
                  'аффинные константы S-box\'ов = 9B 33 E2 3D ED C1')
    XM1, XM2 = cross_consts()
    allok &= _chk((XM1, XM2, MUL16(XM1, XM2)) == (0x3423, 0x581D, 0x066F) and
                  _ord16(XM1) == 65535 and _ord16(XM2) == 65535,
                  'M1 = %04X, M2 = %04X первообразны (порядок 65535); M1·M2 = %04X'
                  % (XM1, XM2, MUL16(XM1, XM2)))

    print('\n§1/§3  CAUCHY-MDS: базовая и динамическая')
    ok = all(is_mds_submats(cauchy(n), n, maxsize=(3 if n <= 8 else 2), trials=100)
             for n in (2, 4, 8))
    allok &= _chk(ok, 'MDS-свойство базовых матриц n = 2/4/8: подматрицы до 3×3 перебором')
    for n in (4, 8, 32, 64):
        M = cauchy(n)
        bn = branch_number(M, n, samples=(350 if n <= 32 else 120))
        allok &= _chk(bn == n + 1, 'n=%2d: ветвевое число = %d (= n+1), различных значений = %d'
                      % (n, bn, len({v for row in M for v in row})))
    ok = True
    for n in (32, 64):
        CI = cauchy_inv_tables(n)
        for _ in range(3):
            pi = list(range(n))
            rho = list(range(n))
            rnd.shuffle(pi)
            rnd.shuffle(rho)
            M = cauchy(n, pi, rho)
            Minv = [[CI[rho[j]][pi[i]] for i in range(n)] for j in range(n)]
            P = mat_mul_gf8(M, Minv, n)
            if not all(P[i][j] == (1 if i == j else 0) for i in range(n) for j in range(n)):
                ok = False
            if branch_number(M, n, samples=(200 if n == 32 else 70)) != n + 1:
                ok = False
            if not all(M[i][j] for i in range(n) for j in range(n)):
                ok = False
    allok &= _chk(ok, 'динамическая MDS(pi,rho): BN = n+1, M·M⁻¹ = I, нулей нет (6 наборов)')
    allok &= _chk(all(len({v for row in cauchy(n, range(n), rnd.sample(range(n), n)) for v in row}) == n
                      for n in (8, 32)), 'множество значений динамической MDS = ровно n (от ключа не зависит)')
    ok = True
    for n in (32, 64):
        pi = list(range(n))
        rho = list(range(n))
        rnd.shuffle(pi)
        rnd.shuffle(rho)
        cols = mds_cols(n, pi, rho)
        for _ in range(20):
            v = bytes(rnd.randrange(256) for _ in range(n))
            if mds_apply_cols(v, cols) != mds_apply(v, mds_rows(n, pi, rho)):
                ok = False
    allok &= _chk(ok, 'колоночные big-int таблицы MDS ≡ строчным (40 случайных векторов)')

    print('\n§4  КУЗНИЦА: равномерность')
    from collections import Counter
    buf = bytes(rnd.getrandbits(8) for _ in range(300000))
    rd = Reader(buf)
    c = Counter(rd.unit8() for _ in range(100000))
    allok &= _chk(len(c) == 255 and 0 not in c, 'unit8: 255 значений, нуля нет, разброс %d…%d (ожид. ~390)'
                  % (min(c.values()), max(c.values())))
    rd = Reader(buf)
    c = Counter(rd.unit16() for _ in range(20000))
    allok &= _chk(0 not in c and 1 not in c, 'unit16: значений %d, {0,1} нет' % len(c))
    ps = set(tuple(perm_from_int(rnd.getrandbits(perm_seed_bytes(5) * 8), 5)) for _ in range(4000))
    allok &= _chk(len(ps) == 120, 'код Лемера: все 120 перестановок из 5 элементов достигнуты')
    pat = sorted([0] * 11 + [1] * 11 + [2] * 10)
    ms = set(tuple(multiset_from_int(rnd.getrandbits(200), pat)) for _ in range(3000))
    allok &= _chk(len(ms) == 3000, 'мультимножество 11/11/10: 3000 различных назначений из 3000 проб')
    allok &= _chk(all(sorted(multiset_from_int(rnd.getrandbits(200), pat)) == pat for _ in range(500)),
                  'все назначения — перестановки того же мультимножества')

    print('\n§5  НЕСУЩАЯ И ЗАСЛОНКА')
    ok = True
    for (W, wb, T) in ((8, 64, 4), (4, 64, 4), (8, 8, 4), (4, 8, 4), (2, 16, 2)):
        sub = [[(j, k, rnd.randrange(wb), rnd.getrandbits(wb) | 1, rnd.getrandbits(wb))
                for (j, k) in pair_list(W, t)] for t in range(T)]
        par = WeavePar(T, sub)
        for _ in range(60):
            w0 = [rnd.getrandbits(wb) for _ in range(W)]
            if carryweave_inv(list(carryweave(list(w0), par, wb)), par, wb) != w0:
                ok = False
    allok &= _chk(ok, 'Несущая биективна: 5 конфигураций (W, wb, T), 300 прогонов')
    par = ShutterPar([rnd.getrandbits(32) for _ in range(8)], [rnd.getrandbits(32) for _ in range(8)],
                     [rnd.randrange(32) for _ in range(8)])
    ok = True
    for _ in range(150):
        w0 = [rnd.getrandbits(32) for _ in range(8)]
        if shutter_inv(list(shutter(list(w0), par)), par) != w0:
            ok = False
    allok &= _chk(ok, 'Заслонка (FL/FL⁻¹) биективна: 150 прогонов')

    print('\n§7  ПОЛУРАУНД H, СТАДИЯ A: ОРТОМОРФИЗМ')
    M1c, M2c = cross_consts()
    MM = MUL16(M1c, M2c)
    b1 = b2 = 0
    for _ in range(1000):
        a = rnd.randrange(1, 1 << 16)
        ap = rnd.randrange(1, 1 << 16)
        if MUL16(a, ap) != (MUL16(a, ap ^ MUL16(M2c, M1c)) ^ MUL16(M1c, MUL16(M2c, a))):
            b1 += 1
        d1 = MUL16(a ^ 1, ap ^ 1) ^ MM
        d2 = MUL16(a ^ 1, ap ^ MUL16(M2c, M1c) ^ 1) ^ MUL16(M1c, MUL16(M2c, a))
        if d1 != d2:
            b2 += 1
    allok &= _chk(b1 == 0, 'det(A) = a·a′ — формула сошлась на 1000 парах')
    allok &= _chk(b2 == 0, 'det(A ⊕ id) = (a⊕1)(a′⊕1) ⊕ M1·M2 — формула сошлась на 1000 парах')

    print('\n§6/§9  F, H И ПОЛНЫЙ ШИФР')
    kmM = key_schedule(MICRO, bytes(8))
    img = {F(v.to_bytes(2, 'big'), kmM.ft[0]) for v in range(65536)}
    allok &= _chk(len(img) == 3602, 'F-микро необратима: |image| = %d из 65536 = 2^%.2f'
                  % (len(img), _log2(len(img))))
    km = key_schedule(FULL, os.urandom(64))
    ht = km.ht[3]
    ok = all(sum(1 for v in mds_apply_cols(
        bytes(1 if i == j else 0 for i in range(FULL.fan)), ht.fan)[FULL.n:] if v) == FULL.n
        for j in range(FULL.fan))
    allok &= _chk(ok, 'Веер: wt(Δz) = 1 ⇒ wt(Δ′) = 32 для всех %d позиций' % FULL.fan)
    best = 10 ** 9
    for pos in range(FULL.n):
        for v in (1, 2, 0x80, 0x55, 0xFF):
            x = os.urandom(FULL.n)
            xp_ = bytearray(x)
            xp_[pos] ^= v
            best = min(best, sum(F_weights(x, bytes(xp_), km.ft[0])))
    allok &= _chk(best >= 34, 'активные S-box\'ы в F: min %d на вызов (доказуемая граница 34)' % best)
    ok = 0
    for _ in range(8):
        K, P = os.urandom(64), os.urandom(64)
        k2 = key_schedule(FULL, K)
        if decrypt(FULL, K, encrypt(FULL, K, P, k2), k2) == P:
            ok += 1
    allok &= _chk(ok == 8, 'dec(enc(P)) = P: %d/8 случайных пар (K, P)' % ok)
    K = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c' * 4)
    k2 = key_schedule(FULL, K)
    P0 = os.urandom(64)
    C0 = encrypt(FULL, K, P0, k2)
    ds = []
    for bit in range(0, 512, 4):
        Q = bytearray(P0)
        Q[bit // 8] ^= 1 << (bit % 8)
        ds.append(hamming(C0, encrypt(FULL, K, bytes(Q), k2)))
    allok &= _chk(200 < sum(ds) / len(ds) < 312, 'SAC полного шифра: среднее %.1f бит из 512 (идеал 256)'
                  % (sum(ds) / len(ds)))
    fp = sum(1 for _ in range(20)
             if encrypt(FULL, os.urandom(64), (Px := os.urandom(64))) == Px)
    allok &= _chk(fp == 0, 'неподвижных точек: %d из 20 случайных (K, P)' % fp)

    print('\n§8  РАСПИСАНИЕ КЛЮЧЕЙ')
    kA = key_schedule(FULL, bytes(64), trace=True)
    K1 = bytearray(64)
    K1[0] = 1
    kB = key_schedule(FULL, bytes(K1), trace=True)
    d0 = sum(1 for x, y in zip(bytes.fromhex(kA.trace[0][1] + kA.trace[0][2]),
                               bytes.fromhex(kB.trace[0][1] + kB.trace[0][2])) if x != y)
    allok &= _chk(d0 >= 100, '1 бит ключа → %d из 128 байт различаются уже в out_0' % d0)
    allok &= _chk(kA.used == 1792 and len(kA.material) == 4096,
                  'бюджет материала Kazual-512: использовано ровно %d байт из %d (%.0f%%)'
                  % (kA.used, len(kA.material), 100 * kA.used / len(kA.material)))
    km64 = key_schedule(K64, bytes.fromhex('0001020304050607'))
    allok &= _chk(km64.used == 200 and len(km64.material) == 256,
                  'бюджет материала Kazual-64: использовано ровно %d байт из %d (%.0f%%)'
                  % (km64.used, len(km64.material), 100 * km64.used / len(km64.material)))
    cnt = [0]
    _g = _gorn.gorn_perm

    def _counting(state):
        cnt[0] += 1
        return _g(state)
    _sched._INIT.clear()
    _sched._RC.clear()
    _gorn.gorn_perm = _counting
    try:
        key_schedule(FULL, os.urandom(64))
    finally:
        _gorn.gorn_perm = _g
    allok &= _chk(cnt[0] == 385, 'перестановок ГОРНа на ключ: %d (+6 одноразовых глобальных = 391)' % cnt[0])

    print('\n§10  ПАКЕТНЫЙ ПУТЬ (NumPy/CuPy)')
    if _np is not None:
        Kb = os.urandom(64)
        kmb = key_schedule(FULL, Kb)
        data = os.urandom(64 * 37)
        c_batch = encrypt_blocks(FULL, Kb, data, backend='cpu', km=kmb)
        c_scal = b''.join(encrypt(FULL, Kb, data[i:i + 64], kmb) for i in range(0, len(data), 64))
        allok &= _chk(c_batch == c_scal, 'NumPy-пакет ≡ скалярному пути (37 блоков, Kazual-512)')
        p_batch = decrypt_blocks(FULL, Kb, c_batch, backend='cpu', km=kmb)
        allok &= _chk(p_batch == data, 'NumPy-пакет: dec(enc(data)) = data')
        kt = key_schedule(K64, bytes.fromhex('0001020304050607'))
        dt = os.urandom(8 * 129)
        allok &= _chk(encrypt_blocks(K64, bytes.fromhex('0001020304050607'), dt, backend='cpu', km=kt)
                      == b''.join(encrypt(K64, bytes.fromhex('0001020304050607'), dt[i:i + 8], kt)
                                  for i in range(0, len(dt), 8)),
                      'NumPy-пакет ≡ скалярному (Kazual-64, 129 блоков)')
        cp = cupy_backend()
        if cp is not None:
            c_gpu = encrypt_blocks(FULL, Kb, data, backend='gpu', km=kmb)
            allok &= _chk(c_gpu == c_scal, 'CuPy(GPU)-пакет ≡ скалярному пути')
        else:
            print('  (CuPy/GPU не обнаружен — проверка пропущена)')
    else:
        print('  (NumPy не установлен — проверки пакетного пути пропущены)')

    print('\n%s  (%.1f c)' % ('ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ' if allok else 'ЕСТЬ ПРОВАЛЫ', time.time() - t0))
    return allok


def _log2(x):
    import math
    return math.log2(x)


def print_vectors(check=True):
    """Тестовые векторы: сверяются с ожидаемыми C."""
    print('\n' + '=' * 78)
    print('ТЕСТОВЫЕ ВЕКТОРЫ  Kazual-512  (блок 512 бит, ключ 512 бит)')
    print('=' * 78)
    allok = True
    for (i, kh, ph), exp in zip(VECTORS, EXPECTED_C):
        K, P = bytes.fromhex(kh), bytes.fromhex(ph)
        km = key_schedule(FULL, K)
        C = encrypt(FULL, K, P, km)
        back = decrypt(FULL, K, C, km) == P
        match = C.hex() == exp if check else True
        allok &= back and match
        print('\nвектор #%d   обратный ход: %s   сверка: %s'
              % (i, 'OK' if back else 'ПРОВАЛ', 'OK' if match else 'РАСХОЖДЕНИЕ'))
        print('  K = %s' % kh)
        print('  P = %s' % ph)
        print('  C = %s' % C.hex())
    print('\n' + '-' * 78)
    print('Kazual-64  (блок 64 бита, ключ 0001020304050607)')
    Kt = bytes.fromhex('0001020304050607')
    km = key_schedule(K64, Kt)
    for ph, ch in K64_VECTORS:
        c = encrypt(K64, Kt, bytes.fromhex(ph), km).hex().upper()
        ok = c == ch
        allok &= ok
        print('  %s  ->  %s   %s' % (ph, c, 'OK' if ok else 'ОЖИДАЛОСЬ ' + ch))
    print('-' * 78)
    return allok


def k64_trace():
    """Подробная трассировка Kazual-64: каркас, первый раунд по стадиям, таблицы."""
    print('\n' + '=' * 78)
    print('ПОДРОБНАЯ ТРАССИРОВКА  Kazual-64')
    print('=' * 78)
    K = bytes.fromhex('0001020304050607')
    P = bytes.fromhex('DEADBEEFCAFEBABE')
    Q = bytes.fromhex('5EADBEEFCAFEBABE')
    stepsP, CP, km = encrypt_trace(K64, K, P)
    stepsQ, CQ, _ = encrypt_trace(K64, K, Q)
    print('\nK = %s   P = DEADBEEFCAFEBABE   Q = 5EADBEEFCAFEBABE (перевёрнут бит 31)\n' % K.hex().upper())
    print('%-28s | %-10s %-10s | %-10s %-10s | бит различия' % ('шаг', 'L(P)', 'L(Q)', 'R(P)', 'R(Q)'))
    print('-' * 92)
    for (n1, lp, rp, _), (n2, lq, rq, __) in zip(stepsP, stepsQ):
        dl = hamming(bytes.fromhex(lp), bytes.fromhex(lq)) if lp != '—' else 0
        dr = hamming(bytes.fromhex(rp), bytes.fromhex(rq)) if rp != '—' else 0
        print('%-28s | %-10s %-10s | %-10s %-10s | %s'
              % (n1, lp, lq, rp, rq, ('L:%d R:%d' % (dl, dr)) if rp != '—' else ('%d бит' % dl)))
    print('-' * 92)
    print('C(P) = %s\nC(Q) = %s\nHamming = %d бит из 64 (идеал 32)'
          % (CP.hex().upper(), CQ.hex().upper(), hamming(CP, CQ)))

    # ---- детали H0 и F первого раунда
    n = K64.n
    km2 = km
    L, R = _x(P[:n], km2.WL), _x(P[n:], km2.WR)
    print('\nДетали первого раунда:')
    print('  Забеливание (вход): L=%s R=%s' % (L.hex().upper(), R.hex().upper()))
    uo, p, hsteps = H_trace(L, R, km2.ht[0])
    for label, a, b in hsteps:
        print('  %-34s %s | %s' % (label, a.hex().upper(), b.hex().upper()))
    L, R = uo, p
    d = _x(L, R)
    print('  %-34s %s' % ('Δ = L ⊕ R (вход F1)', d.hex().upper()))
    T, fsteps = F_trace(d, km2.ft[0])
    for label, a, b in fsteps:
        if a is None:
            print('  %-34s —    | %s' % (label, b.hex().upper()))
        else:
            print('  %-34s %s | %s' % (label, a.hex().upper(), b.hex().upper()))

    # ---- таблицы экземпляра Kazual-64
    print('\nТаблицы экземпляра Kazual-64:')
    for i, ht in enumerate(km2.ht):
        a = [ALOG16[v] for v in ht.la]
        ap = [ALOG16[v] for v in ht.lap]
        print('  H%d: a=%s  b=%s  a′=%s  b′=%s' % (
            i,
            ' '.join('%04X' % v for v in a), ' '.join('%04X' % v for v in ht.lb),
            ' '.join('%04X' % v for v in ap), ' '.join('%04X' % v for v in ht.lbp)))
    ft0 = km2.ft[0]
    print('  Несущая Предтакта F0 (слова по %d бит):' % K64.wb_f)
    for t, row in enumerate(ft0.weave.sub):
        for (j, k, al, m, c) in row:
            print('      фаза %d: (j=%d,k=%d,α=%d,m=%X,c=%X)' % (t, j, k, al, m, c))
    ht0 = km2.ht[0]
    print('  Несущая H0 (слова по %d бит):' % K64.wb_h)
    for t, row in enumerate(ht0.weave.sub):
        for (j, k, al, m, c) in row:
            print('      фаза %d: (j=%d,k=%d,α=%d,m=%X,c=%X)' % (t, j, k, al, m, c))
    print('  Заслонка F0: k1=%08X k2=%08X s=%d'
          % (ft0.shutter.k1[0], ft0.shutter.k2[0], ft0.shutter.s[0]))
    fan = K64.fan
    PI, RHO = ht0.PI, ht0.RHO
    print('  Веер H0 (MDS %dx%d), строка 0: %s' % (fan, fan, ' '.join(
        '%02X' % inv8(PI[0] ^ (fan + RHO[j])) for j in range(fan))))
    pi1, rho1 = ft0.pirho[0]
    print('  Такт 1 F0, MDS %dx%d:' % (n, n))
    for i in range(n):
        print('      %s' % ' '.join('%02X' % inv8(pi1[i] ^ (n + rho1[j])) for j in range(n)))
    print('  Слитые таблицы «маска → S-box» такта 1 F0 (первые 32 значения):')
    for i in range(n):
        print('      fused[0][%d]: %s …' % (i, ft0.strokes[0][0][i][:32].hex().upper()))
    print('\nПараметры Kazual-64: блок %d бит, ключ %d бит, %d раунда, %d такта в F, MDS %dx%d, Веер %dx%d,'
          '\n                     Несущая в F: %d слова по %d бита (%d фазы), в H: %d слов по %d бита (%d фазы)'
          % (K64.block_bytes * 8, K64.ks_bytes * 8, K64.rounds, K64.layers, K64.n, K64.n,
             K64.fan, K64.fan, K64.Wf, K64.wb_f, K64.T_f, K64.Wh, K64.wb_h, K64.T_h))


def bench():
    """Замер стоимости: одиночные блоки (скаляр) и пакеты (NumPy/CuPy/процессы)."""
    print('\n' + '=' * 78)
    print('ЗАМЕР СТОИМОСТИ (эталонная реализация: чистый Python + опции NumPy/CuPy)')
    print('=' * 78)
    n, fan = FULL.n, FULL.fan
    per_F = FULL.nw32 * 8 + FULL.T_f * (FULL.Wf // 2) * 6 + FULL.layers * FULL.n \
        + FULL.layers * FULL.n * FULL.n + FULL.n
    per_H = FULL.chunks * 4 * 3 + FULL.T_h * (FULL.Wh // 2) * 6 + fan * fan
    total = FULL.rounds * per_F + (FULL.rounds + 1) * per_H
    print('\nэлементарных операций на блок:')
    print('   F × %d      : %7d   (на одну F: Заслонка %d + Несущая %d + S-слой %d + MDS %d + эпилог %d)'
          % (FULL.rounds, FULL.rounds * per_F, FULL.nw32 * 8, FULL.T_f * (FULL.Wf // 2) * 6,
             FULL.layers * FULL.n, FULL.layers * FULL.n * FULL.n, FULL.n))
    print('   H × %d      : %7d   (на одну H: стадия A %d + Несущая %d + Веер %d)'
          % (FULL.rounds + 1, (FULL.rounds + 1) * per_H, FULL.chunks * 4 * 3,
             FULL.T_h * (FULL.Wh // 2) * 6, fan * fan))
    print('   ИТОГО       : %7d   = %.0f операций на байт' % (total, total / (2 * n)))

    K, P = os.urandom(64), os.urandom(64)
    t = time.time(); km = key_schedule(FULL, K); tks = time.time() - t
    t = time.time()
    for _ in range(200):
        encrypt(FULL, K, P, km)
    te = (time.time() - t) * 1000 / 200
    C = encrypt(FULL, K, P, km)
    t = time.time()
    for _ in range(200):
        decrypt(FULL, K, C, km)
    td = (time.time() - t) * 1000 / 200
    t = time.time()
    for _ in range(20):
        gorn_perm(IV_BYTES)
    tg = (time.time() - t) * 1000 / 20
    print('\nскалярный путь (чистый Python, один блок):')
    print('   расписание ключа ....... %8.1f мс  (385 перестановок ГОРНа на ключ + колоночные таблицы)' % (tks * 1000))
    print('   шифрование блока ...... %8.3f мс  (%.0f блоков/с)' % (te, 1000 / te))
    print('   дешифрование блока .... %8.3f мс  (обратный Веер бесплатен)' % td)
    print('   одна перестановка ГОРНа %8.3f мс' % tg)
    print('   окупаемость расписания  %8.0f блоков ≈ %.0f КБ данных'
          % (tks * 1000 / te, tks * 1000 / te * 64 / 1024))

    B = 4096
    data = os.urandom(64 * B)
    if _np is not None:
        t = time.time()
        _batch_ctx(FULL, km, _np)
        tctx = time.time() - t
        t = time.time()
        encrypt_blocks(FULL, K, data, backend='cpu', km=km)
        tb = time.time() - t
        print('\nпакетный путь NumPy (CPU), %d блоков:' % B)
        print('   построение контекста ... %8.1f мс (один раз на ключ)' % (tctx * 1000))
        print('   шифрование ............ %8.1f мс  = %.1f мкс/блок, %.2f МБ/с (×%.0f к скаляру)'
              % (tb * 1000, tb * 1e6 / B, B * 64 / tb / 1e6, (te / 1000) / (tb / B)))
        ncpu = os.cpu_count() or 1
        if ncpu > 1:
            w = min(4, ncpu)
            B2 = 65536
            data2 = os.urandom(64 * B2)
            t = time.time()
            encrypt_blocks(FULL, K, data2, backend='cpu', km=km)
            t1p = time.time() - t
            t = time.time()
            encrypt_blocks(FULL, K, data2, backend='cpu', workers=w, km=km)
            tm = time.time() - t
            print('\nмежпроцессный параллелизм, %d блоков (%d МБ), %d воркера:'
                  % (B2, B2 * 64 >> 20, w))
            print('   один процесс .......... %8.2f с  = %.2f МБ/с' % (t1p, B2 * 64 / t1p / 1e6))
            print('   %d процесс(а) .......... %8.2f с  = %.2f МБ/с  (×%.1f)'
                  % (w, tm, B2 * 64 / tm / 1e6, t1p / tm))
    else:
        print('\nпакетный путь NumPy: не установлен (pip install numpy — ускорение в десятки раз)')
    cp = cupy_backend()
    if cp is not None:
        B2 = 1 << 16
        data2 = os.urandom(64 * B2)
        t = time.time()
        encrypt_blocks(FULL, K, data2, backend='gpu', km=km)
        cp.cuda.Stream.null.synchronize()
        tg2 = time.time() - t
        print('\nпакетный путь CuPy (GPU), %d блоков:' % B2)
        print('   шифрование ............ %8.1f мс  = %.2f МБ/с' % (tg2 * 1000, B2 * 64 / tg2 / 1e6))
    else:
        print('\nпакетный путь CuPy (GPU): недоступен (pip install cupy + CUDA — ускорение ещё в 10+ раз)')
