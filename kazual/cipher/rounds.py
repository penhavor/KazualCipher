# -*- coding: utf-8 -*-
"""
Раундовая функция F (необратимый трёхтактный SPN) и пол-раунд H
(ортоморфизм GF(2^16) → Несущая → Веер MDS), вместе с их КУЗНИЦАМИ
(forge_F, forge_H) и трассировочными вариантами. §7 спецификации.
"""

from .gf import (MUL8T, MUL16, LOG16, ALOG16, inv16,
                 mds_cols, mds_cols_inv, mds_apply_cols)
from .gorn import gorn_hash, gorn_expand
from .sbox import SBOXES
from .forge import (Reader, multiset_from_int, multiset_seed_bytes,
                    perm_seed_bytes, read_perm)
from .components import (ShutterPar, shutter, WeavePar,
                         carryweave, carryweave_inv, pair_list)
from .spec import TAG, to_words, from_words

# ------------------------------------------------------------------ F
class FTables:
    __slots__ = ('spec', 'shutter', 'weave', 'strokes', 'epi', 'pirho')


def forge_F(spec, seed):
    """КУЗНИЦА F: сид 512 бит → Заслонка, Несущая Предтакта, 3 такта
    (маски+φ+π/ρ, слитые таблицы), эпилог. Бюджет — с запасом на отбраковку."""
    n, layers, wb = spec.n, spec.layers, spec.wb_f
    nb_sh = spec.nw32 * 9                          # k1(4)+k2(4)+s(1) на слово
    nb_wv = spec.T_f * (spec.Wf // 2) * (1 + 2 * (wb // 8))
    nb_aff = layers * n * 2
    nb_phi = layers * multiset_seed_bytes(spec.pattern)
    nb_pr = layers * 2 * perm_seed_bytes(n)
    nb_epi = n * 2
    mat = gorn_expand(seed, TAG + b'/FORGE-F', nb_sh + nb_wv + nb_aff + nb_phi + nb_pr + nb_epi + 64)
    rd = Reader(mat)

    ft = FTables()
    ft.spec = spec
    nw = spec.nw32
    ft.shutter = ShutterPar([rd.u32() for _ in range(nw)],
                            [rd.u32() for _ in range(nw)],
                            [rd.byte() % 32 for _ in range(nw)])
    sub = []
    for t in range(spec.T_f):
        sub.append([(j, k, rd.byte() % wb, rd.odd(wb // 8), rd.odd(wb // 8))
                    for (j, k) in pair_list(spec.Wf, t)])
    ft.weave = WeavePar(spec.T_f, sub)
    ft.strokes = []
    ft.pirho = []
    for _ in range(layers):
        A = [rd.unit8() for _ in range(n)]
        B = [rd.byte() for _ in range(n)]
        phi = multiset_from_int(int.from_bytes(rd.take(nb_phi // layers), 'big'), spec.pattern)
        pi = read_perm(rd, n)
        rho = read_perm(rd, n)
        fused = [bytes(x ^ B[i] for x in MUL8T[A[i]]).translate(SBOXES[phi[i]])
                 for i in range(n)]
        ft.strokes.append((fused, mds_cols(n, pi, rho)))
        ft.pirho.append((pi, rho))
    C = [rd.unit8() for _ in range(n)]
    D = [rd.byte() for _ in range(n)]
    ft.epi = [bytes(x ^ D[i] for x in MUL8T[C[i]]) for i in range(n)]
    if rd.p > len(mat):
        raise ValueError('КУЗНИЦА F: переполнение бюджета')
    return ft


def F(x, ft):
    """Раундовая функция F: n байт → n байт. НЕОБРАТИМА (образ ⊆ 2^221.4)."""
    spec = ft.spec
    n = spec.n
    if n >= 4:                                    # Предтакт: Заслонка
        w = to_words(x, 32)
        shutter(w, ft.shutter)
        x = from_words(w, 32)
    w = to_words(x, spec.wb_f)                    # Предтакт: Несущая
    carryweave(w, ft.weave, spec.wb_f)
    x = from_words(w, spec.wb_f)
    for fu, cols in ft.strokes:                   # 3 такта: S-слой → MDS
        x = bytes(t[b] for t, b in zip(fu, x))
        acc = 0
        for tab, xb in zip(cols, x):
            acc ^= tab[xb]
        x = acc.to_bytes(n, 'big')
    return bytes(t[b] for t, b in zip(ft.epi, x))  # эпилог


def F_trace(x, ft):
    """Пошаговая трасса F (используется трассировкой Kazual-64)."""
    spec = ft.spec
    steps = []
    if spec.n >= 4:
        w = to_words(x, 32)
        shutter(w, ft.shutter)
        x = from_words(w, 32)
        steps.append(('Предтакт: Заслонка', None, x))
    w = to_words(x, spec.wb_f)
    carryweave(w, ft.weave, spec.wb_f)
    x = from_words(w, spec.wb_f)
    steps.append(('Предтакт: Несущая', None, x))
    for l, (fu, cols) in enumerate(ft.strokes):
        xin = x
        x = bytes(t[b] for t, b in zip(fu, x))
        sout = x
        x = mds_apply_cols(x, cols)
        steps.append(('Такт %d: маска → S-box' % (l + 1), xin, sout))
        steps.append(('Такт %d: MDS %dx%d' % (l + 1, spec.n, spec.n), sout, x))
    x = bytes(t[b] for t, b in zip(ft.epi, x))
    steps.append(('Эпилог F: T', None, x))
    return x, steps


def F_weights(x, y, ft):
    """Число АКТИВНЫХ S-box'ов на входе каждого такта для пары значений
    (активен = разница на входе S ≠ 0). Измерительный инструмент."""
    spec = ft.spec
    n = spec.n
    if n >= 4:
        a, b = to_words(x, 32), to_words(y, 32)
        shutter(a, ft.shutter)
        shutter(b, ft.shutter)
        x, y = from_words(a, 32), from_words(b, 32)
    a, b = to_words(x, spec.wb_f), to_words(y, spec.wb_f)
    carryweave(a, ft.weave, spec.wb_f)
    carryweave(b, ft.weave, spec.wb_f)
    x, y = from_words(a, spec.wb_f), from_words(b, spec.wb_f)
    acts = []
    for fu, cols in ft.strokes:
        acts.append(sum(1 for i in range(n) if x[i] != y[i]))
        x = bytes(t[u] for t, u in zip(fu, x))
        y = bytes(t[u] for t, u in zip(fu, y))
        x = mds_apply_cols(x, cols)
        y = mds_apply_cols(y, cols)
    return acts


# ------------------------------------------------------------------ H
class HTables:
    __slots__ = ('spec', 'la', 'lb', 'lap', 'lbp', 'ia', 'iap', 'weave',
                 'fan', 'fan_inv', 'PI', 'RHO', 'M1', 'M2', 'lM1', 'lM2')


def cross_consts():
    """(M₁, M₂) — первообразные элементы GF(2^16) из ГОРН("", TAG‖"/H-CROSS/0"):
    два первых слова с установленным младшим битом; при непрохождении проверки
    первообразности (порядок 65535 = 3·5·17·257) счётчик домена увеличивается."""
    c = _CONST.get('v')
    if c is None:
        def primitive(v):
            for d in (3, 5, 17, 257):
                p, e = 1, 65535 // d
                for _ in range(e):
                    p = MUL16(p, v)
                if p == 1:
                    return False
            return True
        ctr = 0
        while True:
            h = gorn_hash(ctr.to_bytes(2, 'big') if ctr else b'', TAG + b'/H-CROSS/0')
            m1 = int.from_bytes(h[0:2], 'big') | 1
            m2 = int.from_bytes(h[2:4], 'big') | 1
            if primitive(m1) and primitive(m2):
                break
            ctr += 1
        c = _CONST['v'] = (m1, m2, ctr)
    return c[0], c[1]


_CONST = {}


def forge_H(spec, seed, stageA):
    """КУЗНИЦА H: сид 512 бит + параметры стадии A → Несущая и Веер (Π, Ρ)."""
    a, b, ap, bp = stageA
    wb = spec.wb_h
    nb_wv = spec.T_h * (spec.Wh // 2) * (1 + 2 * (wb // 8))
    nb_pr = 2 * perm_seed_bytes(spec.fan)
    mat = gorn_expand(seed, TAG + b'/FORGE-H', nb_wv + nb_pr + 32)
    rd = Reader(mat)
    ht = HTables()
    ht.spec = spec
    ht.M1, ht.M2 = cross_consts()
    ht.lM1, ht.lM2 = LOG16[ht.M1], LOG16[ht.M2]
    ht.la = [LOG16[v] for v in a]
    ht.lap = [LOG16[v] for v in ap]
    ht.ia = [inv16(v) for v in a]
    ht.iap = [inv16(v) for v in ap]
    ht.lb, ht.lbp = list(b), list(bp)
    sub = []
    for t in range(spec.T_h):
        sub.append([(j, k, rd.byte() % wb, rd.odd(wb // 8), rd.odd(wb // 8))
                    for (j, k) in pair_list(spec.Wh, t)])
    ht.weave = WeavePar(spec.T_h, sub)
    ht.PI = read_perm(rd, spec.fan)
    ht.RHO = read_perm(rd, spec.fan)
    ht.fan = mds_cols(spec.fan, ht.PI, ht.RHO)
    ht.fan_inv = mds_cols_inv(spec.fan, ht.PI, ht.RHO)
    if rd.p > len(mat):
        raise ValueError('КУЗНИЦА H: переполнение бюджета')
    return ht


def _ortho_A(L, R, ht):
    """Стадия A: u = a⊗L ⊕ b ⊕ M₁⊗R; v = a′⊗R ⊕ b′ ⊕ M₂⊗u (16 независимых пар,
    треугольна). Ортоморфизм всей 512-битной XOR-группы при a,a′≠0 и
    (a⊕1)(a′⊕1) ≠ M₁M₂. Возвращает z = u ‖ v."""
    nc = ht.spec.chunks
    la, lb, lap, lbp = ht.la, ht.lb, ht.lap, ht.lbp
    lM1, lM2 = ht.lM1, ht.lM2
    LOG, ALOG = LOG16, ALOG16
    z = bytearray(4 * nc)
    for c in range(nc):
        lc = (L[2 * c] << 8) | L[2 * c + 1]
        rc = (R[2 * c] << 8) | R[2 * c + 1]
        uc = (ALOG[la[c] + LOG[lc]] if lc else 0) ^ lb[c] \
            ^ (ALOG[lM1 + LOG[rc]] if rc else 0)
        vc = (ALOG[lap[c] + LOG[rc]] if rc else 0) ^ lbp[c] \
            ^ (ALOG[lM2 + LOG[uc]] if uc else 0)
        z[2 * c] = uc >> 8
        z[2 * c + 1] = uc & 0xFF
        z[2 * nc + 2 * c] = vc >> 8
        z[2 * nc + 2 * c + 1] = vc & 0xFF
    return bytes(z)


def _ortho_A_inv(u, v, ht):
    nc = ht.spec.chunks
    lb, lbp = ht.lb, ht.lbp
    lM1, lM2 = ht.lM1, ht.lM2
    LOG, ALOG = LOG16, ALOG16
    ia, iap = ht.ia, ht.iap
    L = bytearray(2 * nc)
    R = bytearray(2 * nc)
    for c in range(nc):
        uc = (u[2 * c] << 8) | u[2 * c + 1]
        vc = (v[2 * c] << 8) | v[2 * c + 1]
        t = vc ^ lbp[c] ^ (ALOG[lM2 + LOG[uc]] if uc else 0)
        rc = MUL16(iap[c], t)
        t2 = uc ^ lb[c] ^ (ALOG[lM1 + LOG[rc]] if rc else 0)
        lc = MUL16(ia[c], t2)
        L[2 * c] = lc >> 8
        L[2 * c + 1] = lc & 0xFF
        R[2 * c] = rc >> 8
        R[2 * c + 1] = rc & 0xFF
    return bytes(L), bytes(R)


def H(L, R, ht):
    """Пол-раунд: A (ортоморфизм) → C (Несущая) → B (Веер MDS 64×64, BN=65).
    Выход (p ⊕ q, p) ⇒ Δ′ = q = M_низ·z: Δ′ = 0 ⇔ Δ = 0; wt(Δz)=1 ⇒ wt(Δ′)=32."""
    n = ht.spec.n
    z = _ortho_A(L, R, ht)
    w = to_words(z, ht.spec.wb_h)
    carryweave(w, ht.weave, ht.spec.wb_h)
    z = from_words(w, ht.spec.wb_h)
    acc = 0
    for tab, zb in zip(ht.fan, z):
        acc ^= tab[zb]
    t = acc.to_bytes(2 * n, 'big')
    p, q = t[:n], t[n:]
    return bytes(a ^ b for a, b in zip(p, q)), p


def Hinv(uo, vo, ht):
    n = ht.spec.n
    p = vo
    y = p + bytes(a ^ b for a, b in zip(uo, vo))     # p ‖ q
    acc = 0
    for tab, yb in zip(ht.fan_inv, y):
        acc ^= tab[yb]
    z = acc.to_bytes(2 * n, 'big')
    w = to_words(z, ht.spec.wb_h)
    carryweave_inv(w, ht.weave, ht.spec.wb_h)
    z = from_words(w, ht.spec.wb_h)
    return _ortho_A_inv(z[:n], z[n:], ht)


def H_trace(L, R, ht):
    """Пошаговая трасса H (используется трассировкой Kazual-64)."""
    n = ht.spec.n
    steps = []
    z = _ortho_A(L, R, ht)
    steps.append(('H, стадия A (ортоморфизм)', z[:n], z[n:]))
    w = to_words(z, ht.spec.wb_h)
    carryweave(w, ht.weave, ht.spec.wb_h)
    z = from_words(w, ht.spec.wb_h)
    steps.append(('H, стадия C (Несущая)', z[:n], z[n:]))
    acc = 0
    for tab, zb in zip(ht.fan, z):
        acc ^= tab[zb]
    t = acc.to_bytes(2 * n, 'big')
    p, q = t[:n], t[n:]
    steps.append(('H, стадия B (Веер): t = p‖q', p, q))
    uo = bytes(a ^ b for a, b in zip(p, q))
    steps.append(('H выход = (p⊕q, p)', uo, p))
    return uo, p, steps
