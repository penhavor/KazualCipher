# -*- coding: utf-8 -*-
"""
Расписание ключей: ГОРН (стадия 0, односторонность) → двутактная GFN Type-2
(стадия 1, биективна) → детерминированная нарезка (стадия 2) → КУЗНИЦА
таблиц F и H. §8 спецификации.
"""

import hashlib
import threading
from collections import OrderedDict

from .gf import MUL8T, MUL16, mds_rows, mds_apply
from . import _accel
from .sbox import SBOXES
from .forge import (Reader, multiset_from_int, multiset_seed_bytes,
                    perm_seed_bytes, read_perm)
from .rounds import forge_F, forge_H, cross_consts
from .spec import TAG

# ГОРН (Стадия 0, односторонность) → двутактная GFN Type-2 (Стадия 1, биективна:
# энтропия ключа не теряется) → детерминированная нарезка (Стадия 2) → КУЗНИЦА.

class KSTables:
    __slots__ = ('fused', 'rows64', 'rows8', 'brlen')


def _ks_tables(spec, X, r):
    """Θ_r — самоизменяющиеся таблицы раунда: из ВЕДУЩЕГО регистра X
    (ведущий не преобразуется ⇒ раунд биективен; скользящие атаки без опоры)."""
    k = spec.cw_k
    brlen = spec.ks_bytes // k
    pat = [i % 3 for i in range(brlen)]
    nb_phi = (k // 2) * multiset_seed_bytes(pat)
    nb_aff = (k // 2) * brlen * 2
    nb_pr = 2 * perm_seed_bytes(spec.ks_bytes)
    mat = _accel.gorn_expand(X + r.to_bytes(2, 'big'), TAG + b'/KS-TBL',
                      nb_phi + nb_aff + nb_pr + 16)
    rd = Reader(mat)
    kt = KSTables()
    kt.brlen = brlen
    kt.fused = []
    for _j in range(k // 2):
        A = [rd.unit8() for _ in range(brlen)]
        B = [rd.byte() for _ in range(brlen)]
        phi = multiset_from_int(int.from_bytes(rd.take(nb_phi // (k // 2)), 'big'), pat)
        kt.fused.append([bytes(x ^ B[i] for x in MUL8T[A[i]]).translate(SBOXES[phi[i]])
                         for i in range(brlen)])
    PI = read_perm(rd, spec.ks_bytes)
    RHO = read_perm(rd, spec.ks_bytes)
    kt.rows64 = mds_rows(spec.ks_bytes, PI, RHO)
    kt.rows8 = mds_rows(brlen, range(brlen), range(brlen))
    return kt


def _gfn_round(spec, Y, kt):
    """Раунд Type-2: нелинейность на чётных ветвях (необратимые S-box'ы допустимы —
    чётная ветвь сохраняется), затем ПОЛНАЯ MDS 64×64 (ветвевое число 65)."""
    k = spec.cw_k
    bl = kt.brlen
    br = [Y[i * bl:(i + 1) * bl] for i in range(k)]
    out = list(br)
    for j in range(k // 2):
        fu = kt.fused[j]
        y = bytes(t[b] for t, b in zip(fu, br[2 * j]))
        y = mds_apply(y, kt.rows8)
        out[2 * j + 1] = bytes(a ^ b for a, b in zip(br[2 * j + 1], y))
    return mds_apply(b''.join(out), kt.rows64)


_RC = {}


def _round_consts(spec):
    key = (spec.name, spec.cw_r)
    t = _RC.get(key)
    if t is None:
        t = _RC[key] = [_accel.gorn_expand(r.to_bytes(4, 'big'), TAG + b'/KS-RC', spec.ks_bytes)
                        for r in range(spec.cw_r)]
    return t


_INIT = {}


def _init_const(spec):
    t = _INIT.get(spec.name)
    if t is None:
        t = _INIT[spec.name] = _accel.gorn_hash(b'', TAG + b'/KS-INIT/' + spec.name.encode())[:spec.ks_bytes]
    return t


_BASE_ROWS = {}


def _base_rows(spec):
    t = _BASE_ROWS.get(spec.ks_bytes)
    if t is None:
        t = _BASE_ROWS[spec.ks_bytes] = mds_rows(spec.ks_bytes,
                                                 range(spec.ks_bytes), range(spec.ks_bytes))
    return t


class KeyMat:
    __slots__ = ('spec', 'WL', 'WR', 'WpL', 'WpR', 'ht', 'ft',
                 'material', 'used', 'trace', 'bctx')


# LRU-кэш расписаний: повторные операции с тем же ключом (пакет файлов,
# повторная расшифровка) не платят ~0.2–0.5 с за пересборку таблиц.
_KS_CACHE = OrderedDict()
_KS_CACHE_MAX = 4
_KS_LOCK = threading.Lock()


def key_schedule(spec, K, trace=False):
    """KeySchedule(K) → km: забеливание, 6 пол-раундов H, 5 функций F.

    Результат кэшируется по (spec, K) — до _KS_CACHE_MAX расписаний;
    km.bctx дополнительно хранит готовые векторные/нативные контексты.
    """
    if len(K) != spec.ks_bytes:
        raise ValueError('ключ: ожидалось %d байт, дано %d' % (spec.ks_bytes, len(K)))
    if not trace:
        ck = (spec.name, hashlib.sha256(K).digest())
        with _KS_LOCK:
            km = _KS_CACHE.get(ck)
            if km is not None:
                _KS_CACHE.move_to_end(ck)
                return km
    km = _key_schedule_build(spec, K, trace)
    if not trace:
        with _KS_LOCK:
            _KS_CACHE[ck] = km
            while len(_KS_CACHE) > _KS_CACHE_MAX:
                _KS_CACHE.popitem(last=False)
    return km


def _key_schedule_build(spec, K, trace=False):
    nb = spec.ks_bytes
    Z = _accel.gorn_hash(K, TAG + b'/KS0')[:nb]                          # Стадия 0
    Y = bytes(a ^ b for a, b in zip(mds_apply(Z, _base_rows(spec)), _init_const(spec)))
    X = Z                                                          # Стадия 1
    RC = _round_consts(spec)
    material = bytearray()
    tr = []
    for r in range(spec.cw_r):
        kt = _ks_tables(spec, X, r)
        X1 = bytes(a ^ b for a, b in zip(_gfn_round(spec, Y, kt), RC[r]))
        Y1 = bytes(a ^ b for a, b in zip(X, X1))
        X, Y = X1, Y1
        material += X + Y
        if trace:
            tr.append((r, X.hex(), Y.hex()))
    material = bytes(material)

    km = KeyMat()                                                  # Стадия 2
    km.spec = spec
    km.material = material
    km.trace = tr
    km.bctx = {}
    n = spec.n
    cur = 0

    def take(k):
        nonlocal cur
        v = material[cur:cur + k]
        cur += k
        return v

    km.WL, km.WR = take(n), take(n)
    km.WpL, km.WpR = take(n), take(n)
    XM1, XM2 = cross_consts()
    MM = MUL16(XM1, XM2)                      # запрещённое значение (a⊕1)(a′⊕1)
    stageA = []
    nc = spec.chunks
    for _i in range(spec.rounds + 1):
        rd = Reader(material[cur:cur + 4 * n + 32])
        cur += 4 * n + 32
        a = [rd.unit16() for _ in range(nc)]
        b = [rd.u16() for _ in range(nc)]
        ap = []
        for c in range(nc):
            while True:                        # отбраковка: (a⊕1)(a′⊕1) ≠ M₁M₂
                v = rd.unit16()
                if MUL16(a[c] ^ 1, v ^ 1) != MM:
                    ap.append(v)
                    break
        bp = [rd.u16() for _ in range(nc)]
        if rd.p > 4 * n + 32:
            raise ValueError('не хватило материала на стадию A')
        stageA.append((a, b, ap, bp))
    hseeds = [take(spec.unit) for _ in range(spec.rounds + 1)]
    fseeds = [take(spec.unit) for _ in range(spec.rounds)]
    km.ht = [forge_H(spec, hseeds[i], stageA[i]) for i in range(spec.rounds + 1)]
    km.ft = [forge_F(spec, fseeds[i]) for i in range(spec.rounds)]
    km.used = cur
    return km
