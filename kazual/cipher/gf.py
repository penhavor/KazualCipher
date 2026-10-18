# -*- coding: utf-8 -*-
"""
Алгебраическое ядро Kazual: поля GF(2^8) и GF(2^16), матрицы Cauchy-MDS
и их табличные применения (строчные и колоночные big-int формы).

§1 и часть §7 эталонной спецификации.
"""

import random as _random

# GF(2^8), GF(2^16), Cauchy-MDS и её динамическая форма M = P_pi · C · P_rho.

POLY8, GEN8 = 0x11B, 3            # 2 НЕ первообразно (порядок 51); образующий — 3
POLY16, GEN16 = 0x1100B, 2


def _mul_poly(a, b, poly, width):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a >> width:
            a ^= poly
        b >>= 1
    return r


def build_gf(poly, gen, n):
    """Таблицы log/alog GF(2^n). Возвращает (log, alog, mul)."""
    size = 1 << n
    order = size - 1
    alog = [0] * (2 * order)
    log = [0] * size
    x = 1
    for i in range(order):
        alog[i] = x
        log[x] = i
        x = _mul_poly(x, gen, poly, n)
    if x != 1:
        raise ValueError('генератор не первообразен')
    for i in range(order, 2 * order):
        alog[i] = alog[i - order]

    def mul(a, b, _log=log, _alog=alog):
        if a == 0 or b == 0:
            return 0
        return _alog[_log[a] + _log[b]]
    return log, alog, mul


LOG8, ALOG8, MUL8 = build_gf(POLY8, GEN8, 8)
LOG16, ALOG16, MUL16 = build_gf(POLY16, GEN16, 16)


def inv8(a):
    return 0 if a == 0 else ALOG8[(255 - LOG8[a]) % 255]


def inv16(a):
    return 0 if a == 0 else ALOG16[(65535 - LOG16[a]) % 65535]


def cauchy(n, pi=None, rho=None):
    """Динамическая Cauchy-MDS n×n: M[i][j] = (pi(i) ⊕ (n + rho(j)))⁻¹.
    Ветвевое число n+1 при ЛЮБЫХ перестановках pi, rho (определитель Коши)."""
    if pi is None:
        pi = range(n)
    if rho is None:
        rho = range(n)
    return [[inv8(pi[i] ^ (n + rho[j])) for j in range(n)] for i in range(n)]


_CINV = {}


def cauchy_inv_tables(n):
    """Фиксированная C⁻¹ базовой матрицы Коши (кэш): M⁻¹[j][i] = C⁻¹[rho(j)][pi(i)]
    — обратная матрица бесплатна, нужны только переставленные индексы."""
    t = _CINV.get(n)
    if t is None:
        t = _CINV[n] = mat_inv_gf8(cauchy(n), n)
    return t


def mat_mul_gf8(A, B, n):
    C = [[0] * n for _ in range(n)]
    for i in range(n):
        Ai, Ci = A[i], C[i]
        for k in range(n):
            a = Ai[k]
            if a:
                Bk = B[k]
                la = LOG8[a]
                for j in range(n):
                    b = Bk[j]
                    if b:
                        Ci[j] ^= ALOG8[la + LOG8[b]]
    return C


def mat_inv_gf8(M, n):
    A = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(M)]
    for col in range(n):
        p = None
        for r in range(col, n):
            if A[r][col]:
                p = r
                break
        if p is None:
            raise ValueError('матрица вырождена')
        A[col], A[p] = A[p], A[col]
        la = LOG8[inv8(A[col][col])]
        A[col] = [(ALOG8[la + LOG8[v]] if v else 0) for v in A[col]]
        for r in range(n):
            if r != col and A[r][col]:
                lf = LOG8[A[r][col]]
                Ar, Ac = A[r], A[col]
                for j in range(2 * n):
                    v = Ac[j]
                    if v:
                        Ar[j] ^= ALOG8[lf + LOG8[v]]
    return [row[n:] for row in A]


def _det_gf8(M, n):
    M = [row[:] for row in M]
    det = 1
    for c in range(n):
        p = None
        for r in range(c, n):
            if M[r][c]:
                p = r
                break
        if p is None:
            return 0
        if p != c:
            M[c], M[p] = M[p], M[c]
        piv = M[c][c]
        lp = LOG8[piv]
        for r in range(c + 1, n):
            f = M[r][c]
            if f:
                m = ALOG8[(LOG8[f] - lp) % 255]
                Mr, Mc = M[r], M[c]
                lm = LOG8[m]
                for j in range(c, n):
                    v = Mc[j]
                    if v:
                        Mr[j] ^= ALOG8[lm + LOG8[v]]
        det = MUL8(det, piv)
    return det


def branch_number(M, n, samples=2000, seed=12345):
    """B(M) = min по x≠0 (wt(x) + wt(M·x)). n≤2 — перебор; n≤8 — веса 1–2;
    иначе выборка + случайные векторы."""
    rnd = _random.Random(seed)

    def apply(v):
        out = []
        for i in range(n):
            acc = 0
            Mi = M[i]
            for j in range(n):
                a = Mi[j]
                b = v[j]
                if a and b:
                    acc ^= ALOG8[LOG8[a] + LOG8[b]]
            out.append(acc)
        return out

    wt = lambda v: sum(1 for b in v if b)
    best = 2 * n
    cands = []
    if n <= 2:
        cands = [[(x >> (8 * k)) & 0xFF for k in range(n)] for x in range(1, 1 << (8 * n))]
    elif n <= 8:
        for i in range(n):
            for v in range(1, 256):
                e = [0] * n
                e[i] = v
                cands.append(e)
                for j in range(i + 1, n):
                    for u in (1, 0x5A, 0xFF):
                        e2 = [0] * n
                        e2[i] = v
                        e2[j] = u
                        cands.append(e2)
    else:
        for w in (1, 2):
            for _ in range(300):
                v = [0] * n
                for i in rnd.sample(range(n), w):
                    v[i] = rnd.randrange(1, 256)
                cands.append(v)
    for _ in range(samples):
        v = [rnd.randrange(256) for _ in range(n)]
        if any(v):
            cands.append(v)
    for v in cands:
        t = wt(v) + wt(apply(v))
        if t < best:
            best = t
    return best


def is_mds_submats(M, n, maxsize=3, trials=200, seed=777):
    """MDS-свойство: квадратные подматрицы до maxsize×maxsize (для n≤16 — перебор,
    для крупных — случайные выборки) + случайные крупные подматрицы."""
    import itertools
    rnd = _random.Random(seed)
    ms = maxsize if n <= 16 else 1
    for k in range(1, ms + 1):
        pairs = list(itertools.combinations(range(n), k))
        if len(pairs) ** 2 > 200000:
            pairs = [tuple(rnd.sample(range(n), k)) for _ in range(400)]
        for rows in pairs:
            for cols in pairs:
                if _det_gf8([[M[i][j] for j in cols] for i in rows], k) == 0:
                    return False
    hi = min(n, 24)
    if hi >= 5:
        for _ in range(trials):
            k = rnd.randint(4, hi)
            rows = sorted(rnd.sample(range(n), k))
            cols = sorted(rnd.sample(range(n), k))
            if _det_gf8([[M[i][j] for j in cols] for i in rows], k) == 0:
                return False
    return True



# ---------------------------------------------------------------------------
# Общие таблицы: умножение на v в GF(2^8) и XOR-таблицы подмножеств
# ---------------------------------------------------------------------------

MUL8T = [bytes(MUL8(v, x) for x in range(256)) for v in range(256)]


def _subset_xor_table(basis):
    """256 записей: tab[v] = ⊕ битов v из basis[0..7] (линейность GF(2))."""
    tab = [0] * 256
    for b in range(8):
        tab[1 << b] = basis[b]
    for v in range(1, 256):
        lsb = v & -v
        tab[v] = tab[v ^ lsb] ^ tab[lsb]
    return tab



_IDXN = {}


def idx_tables(n):
    """n фиксированных таблиц умножения на inv(n+t): МНОЖЕСТВО ЗНАЧЕНИЙ
    динамической Cauchy-MDS от ключа не зависит — зависит только расположение."""
    t = _IDXN.get(n)
    if t is None:
        t = _IDXN[n] = [MUL8T[inv8(n + t2)] for t2 in range(n)]
    return t


def mds_rows(n, pi, rho):
    """Строчные байт-таблицы M[i][j] = C[pi(i)][rho(j)] — для ОДНОРАЗОВОГО
    применения (расписание ключей)."""
    T = idx_tables(n)
    return [tuple(T[pi[i] ^ rho[j]] for j in range(n)) for i in range(n)]


def mds_apply(x, rows):
    y = bytearray(len(rows))
    for i, r in enumerate(rows):
        acc = 0
        for j, t in enumerate(r):
            acc ^= t[x[j]]
        y[i] = acc
    return bytes(y)


def mds_cols(n, pi, rho):
    """Колоночные big-int таблицы для ГОРЯЧЕГО пути: cols[j][v] — n-байтовое
    слово, байт i = M[i][j] ⊗ v. Применение: ⊕_j cols[j][x[j]] — 2n операций
    вместо n² (линейность ⊗ по v ⇒ таблица собирается из 8 базисных слов)."""
    vals = [inv8(pi[i] ^ (n + rho[j])) for i in range(n) for j in range(n)]
    cols = []
    for j in range(n):
        basis = []
        for b in range(8):
            bit = 1 << b
            ba = bytes(MUL8T[vals[i * n + j]][bit] for i in range(n))
            basis.append(int.from_bytes(ba, 'big'))
        cols.append(_subset_xor_table(basis))
    return cols


def mds_cols_inv(n, pi, rho):
    """Колоночные таблицы M⁻¹: M⁻¹[j][i] = C⁻¹[rho(j)][pi(i)] (бесплатная
    обратная матрица — фиксированная C⁻¹ с переставленными индексами)."""
    CI = cauchy_inv_tables(n)
    cols = []
    for i in range(n):
        piv = pi[i]
        basis = []
        for b in range(8):
            bit = 1 << b
            ba = bytes(MUL8T[CI[rho[j]][piv]][bit] for j in range(n))
            basis.append(int.from_bytes(ba, 'big'))
        cols.append(_subset_xor_table(basis))
    return cols


def mds_apply_cols(x, cols):
    acc = 0
    for tab, xb in zip(cols, x):
        acc ^= tab[xb]
    return acc.to_bytes(len(cols), 'big')
