# -*- coding: utf-8 -*-
"""
kazual.cipher.native — нативное ускорение ядер Kazual (numba JIT).

Побитово идентичные эталонным (gorn.py / rounds.py / core.py) реализации
«горячих» примитивов, компилируемые в машинный код:

  * ГОРН-1024: перестановка, впитывание, дайджест, расширение, потоковый
    хэшер — ускоряет MAC, расписание ключей, растягивание сырых ключей;
  * Kazual-512: шифрование/дешифрование блоков и CTR (keystream ⊕ данные
    одним слитным проходом), параллельно по блокам на всех ядрах CPU.

numba необязательна: модуль регистрирует хуки в _accel.HOOKS только при
успешном импорте; без numba всё работает эталонным путём (медленнее).
Компиляция ядер выполняется один раз и кэшируется на диск (cache=True).
"""

from __future__ import annotations

import os
import sys
import threading

import numpy as np

# u64-представления байтовых таблиц требуют little-endian (x86/ARM — все
# реальные платформы); на big-endian остался бы эталонный путь.
_LE = (sys.byteorder == 'little')

try:
    from numba import njit, prange, set_num_threads, get_num_threads
    import numba as _numba
    NUMBA_AVAILABLE = _LE
except Exception:                                       # pragma: no cover
    NUMBA_AVAILABLE = False

from .gf import MUL8T, LOG16, ALOG16, inv8, cauchy_inv_tables
from .gorn import SIGTBL, ODD, LCST, ROT, IV_BYTES, C16, RATE

_U8 = np.uint8

# ---------------------------------------------------------------------------
# Константные таблицы ГОРНа (строятся один раз, читаются JIT-ядрами)
# ---------------------------------------------------------------------------
_SIG = np.frombuffer(b''.join(b''.join(SIGTBL[r]) for r in range(8)),
                     dtype=_U8).reshape(8, 128, 256).copy()

_MUL8T = np.frombuffer(b''.join(MUL8T), dtype=_U8).reshape(256, 256)

# CT[j][v][i] = C16[i][j] ⊗ v  (колоночный MDS 16×16); u64-вид — по 2 слова
_CT = np.ascontiguousarray(
    _MUL8T[np.asarray(C16, dtype=np.intp)].transpose(1, 2, 0))
_CT64 = _CT.view(np.uint64).reshape(16, 256, 2)

# SH[r][q][i] = 8·((i + 5q + r) mod 16) + q  (косой перенос Ρ)
_SH = np.empty((8, 8, 16), dtype=np.int32)
for _r in range(8):
    for _q in range(8):
        for _i in range(16):
            _SH[_r, _q, _i] = 8 * ((_i + 5 * _q + _r) % 16) + _q

_ODD = np.asarray(ODD, dtype=np.uint64)
_LCST = np.asarray(LCST, dtype=np.uint64) & np.uint64(0xFFFFFFFFFFFFFFFF)
_ROT = np.asarray(ROT, dtype=_U8)
_IV = np.frombuffer(IV_BYTES, dtype=_U8).copy()
_LOG16 = np.asarray(LOG16, dtype=np.int32)
_ALOG16 = np.asarray(ALOG16, dtype=np.uint16)

del _r, _q, _i

# ---------------------------------------------------------------------------
# JIT-ядра ГОРН-1024
# ---------------------------------------------------------------------------

if NUMBA_AVAILABLE:

    @njit(cache=True, boundscheck=False, inline='always')
    def _rotl64(x, k):
        if k == 0:
            return x
        return (x << k) | (x >> (np.uint8(64) - k))

    @njit(cache=True, boundscheck=False, inline='always')
    def _be64_load(state, i):
        v = np.uint64(0)
        for b in range(8):
            v = (v << np.uint8(8)) | np.uint64(state[i * 8 + b])
        return v

    @njit(cache=True, boundscheck=False, inline='always')
    def _be64_store(state, i, v):
        for b in range(8):
            state[i * 8 + b] = np.uint8(v >> np.uint8(56 - 8 * b))

    @njit(cache=True, boundscheck=False, nogil=True)
    def _perm(state):
        """Внутренняя перестановка 1024→1024 бит (in-place). = gorn_perm."""
        tmp = np.empty(128, _U8)
        for r in range(8):
            # Σ: байтовые аффинные подстановки
            for p in range(128):
                state[p] = _SIG[r, p, state[p]]
            # Μ∘Ρ: 8 колоночных MDS 16×16 + косой перенос (u64-слова)
            for q in range(8):
                a0 = np.uint64(0)
                a1 = np.uint64(0)
                for j in range(16):
                    v = state[8 * j + q]
                    if v != 0:
                        a0 ^= _CT64[j, v, 0]
                        a1 ^= _CT64[j, v, 1]
                for i in range(8):
                    tmp[_SH[r, q, i]] = np.uint8(a0 >> np.uint8(8 * i))
                for i in range(8):
                    tmp[_SH[r, q, 8 + i]] = np.uint8(a1 >> np.uint8(8 * i))
            for i in range(128):
                state[i] = tmp[i]
            # Α: 16 независимых ARX-лейн
            for i in range(16):
                x = _be64_load(state, i)
                x = x * _ODD[r, i]
                x ^= x >> np.uint8(29)
                x = _rotl64(x, _ROT[r, i])
                x = x + _LCST[r, i]
                _be64_store(state, i, x)

    @njit(cache=True, boundscheck=False, nogil=True)
    def _absorb(state, buf, nblocks):
        """Впитать nblocks блоков по 64 байта из buf (губка, rate=512 бит)."""
        for b in range(nblocks):
            o0 = b * 64
            for o in range(64):
                state[o] ^= buf[o0 + o]
            _perm(state)

    @njit(cache=True, boundscheck=False, nogil=True)
    def _fold_into(state, out):
        """Свёртка 1024→512 (= _fold) в out[64]."""
        for i in range(8):
            v = _be64_load(state, i)
            v ^= _rotl64(_be64_load(state, i + 8), np.uint8(17))
            v ^= _rotl64(_be64_load(state, (i + 3) % 8 + 8), np.uint8(41))
            v ^= _rotl64(_be64_load(state, (2 * i + 5) % 8 + 8), np.uint8(53))
            for b in range(8):
                out[i * 8 + b] = np.uint8(v >> np.uint8(56 - 8 * b))

    @njit(cache=True, boundscheck=False, nogil=True)
    def _hash_full(msg, tag):
        """gorn_hash(msg, tag): доменное дополнение + губка + свёртка."""
        ntag = tag.shape[0]
        nmsg = msg.shape[0]
        nbody = ntag + 1 + nmsg
        npad = (-nbody - 9) % 64
        total = nbody + 1 + npad + 8
        buf = np.empty(total, _U8)
        for i in range(ntag):
            buf[i] = tag[i]
        buf[ntag] = 0x1F
        off = ntag + 1
        for i in range(nmsg):
            buf[off + i] = msg[i]
        off += nmsg
        buf[off] = 0x80
        for i in range(off + 1, off + 1 + npad):
            buf[i] = 0
        L = np.uint64(nmsg)
        base = off + 1 + npad
        for b in range(8):
            buf[base + b] = np.uint8(L >> np.uint8(56 - 8 * b))
        state = _IV.copy()
        _absorb(state, buf, total // 64)
        _perm(state)
        out = np.empty(64, _U8)
        _fold_into(state, out)
        return out

    @njit(cache=True, boundscheck=False, nogil=True)
    def _expand_full(seed, tag, nbytes):
        """gorn_expand(seed, tag, nbytes): непрерывный отжим по 64 байта."""
        ntag = tag.shape[0]
        nseed = seed.shape[0]
        nbody = ntag + 1 + nseed
        npad = (-nbody - 9) % 64
        total = nbody + 1 + npad + 8
        buf = np.empty(total, _U8)
        for i in range(ntag):
            buf[i] = tag[i]
        buf[ntag] = 0x1F
        off = ntag + 1
        for i in range(nseed):
            buf[off + i] = seed[i]
        off += nseed
        buf[off] = 0x80
        for i in range(off + 1, off + 1 + npad):
            buf[i] = 0
        L = np.uint64(nseed)
        base = off + 1 + npad
        for b in range(8):
            buf[base + b] = np.uint8(L >> np.uint8(56 - 8 * b))
        state = _IV.copy()
        _absorb(state, buf, total // 64)
        out = np.empty(nbytes, _U8)
        d = np.empty(64, _U8)
        done = 0
        while done < nbytes:
            _perm(state)
            _fold_into(state, d)
            k = min(64, nbytes - done)
            for i in range(k):
                out[done + i] = d[i]
            done += k
        return out

else:                                                    # pragma: no cover
    _perm = _absorb = _fold_into = _hash_full = _expand_full = None


# ---------------------------------------------------------------------------
# JIT-ядра Kazual-512 (блок/ключ 512 бит, wb=64)
# ---------------------------------------------------------------------------
# Раскладка кортежа таблиц T (все массивы C-contiguous; рабочий набор
# ~2.6 МиБ на ключ — держится в L2/L3, а не 12 МиБ байтовых MDS-таблиц):
#   T[0]  W       u8[4,32]    забеливание: WL, WR, WpL, WpR
#   T[1]  LB      u16[6,16]   константы b стадии A (H)
#   T[2]  LBP     u16[6,16]   константы b′
#   T[3]  AMUL    u16[6,16,2,256]  байт-сплит таблицы a⊗x   (GF(2¹⁶))
#   T[4]  APMUL   u16[6,16,2,256]  a′⊗x
#   T[5]  IAMUL   u16[6,16,2,256]  a⁻¹⊗x
#   T[6]  IAPMUL  u16[6,16,2,256]  a′⁻¹⊗x
#   T[7]  HJ      i32[6,4,4]  Несущая H: индексы j пар
#   T[8]  HK      i32[6,4,4]  индексы k
#   T[9]  HA      u8[6,4,4]   повороты alpha
#   T[10] HM      u64[6,4,4]  множители m
#   T[11] HC      u64[6,4,4]  константы c
#   T[12] FANN    u64[6,64,32,8]   Веер MDS, nibble-строки (0..15: ⊗e,
#                                  16..31: ⊗(e<<4)); вход.байт zj →
#                                  строки (zj&15) и (zj>>4)+16
#   T[13] FANINVN u64[6,64,32,8]   обратный Веер
#   T[14] FJ      i32[5,4,2]  Несущая F (предтакт)
#   T[15] FK      i32[5,4,2]
#   T[16] FA      u8[5,4,2]
#   T[17] FM      u64[5,4,2]
#   T[18] FC      u64[5,4,2]
#   T[19] SHK1    u32[5,8]    Заслонка: k1
#   T[20] SHK2    u32[5,8]    k2
#   T[21] SHS     u8[5,8]     s
#   T[22] FUSED   u8[5,3,32,256]    слитные «маска→S-box» таблицы тактов F
#   T[23] COLSN   u64[5,3,32,32,4]  колоночные MDS тактов F, nibble-строки
#   T[24] EPI     u8[5,32,256]      эпилог F
#   T[25] M1T     u16[2,256]  байт-сплит таблицы M₁⊗x
#   T[26] M2T     u16[2,256]  M₂⊗x

if NUMBA_AVAILABLE:

    @njit(cache=True, boundscheck=False, inline='always')
    def _b32_to_words(x, w):
        for t in range(8):
            w[t] = ((np.uint32(x[4 * t]) << np.uint8(24))
                    | (np.uint32(x[4 * t + 1]) << np.uint8(16))
                    | (np.uint32(x[4 * t + 2]) << np.uint8(8))
                    | np.uint32(x[4 * t + 3]))

    @njit(cache=True, boundscheck=False, inline='always')
    def _words_to_b32(w, x):
        for t in range(8):
            x[4 * t] = np.uint8(w[t] >> np.uint8(24))
            x[4 * t + 1] = np.uint8(w[t] >> np.uint8(16))
            x[4 * t + 2] = np.uint8(w[t] >> np.uint8(8))
            x[4 * t + 3] = np.uint8(w[t])

    @njit(cache=True, boundscheck=False, inline='always')
    def _b64_to_words(z, w):
        for t in range(8):
            v = np.uint64(0)
            for b in range(8):
                v = (v << np.uint8(8)) | np.uint64(z[8 * t + b])
            w[t] = v

    @njit(cache=True, boundscheck=False, inline='always')
    def _words_to_b64(w, z):
        for t in range(8):
            v = w[t]
            for b in range(8):
                z[8 * t + b] = np.uint8(v >> np.uint8(56 - 8 * b))

    @njit(cache=True, boundscheck=False, inline='always')
    def _shutter32(x, k1, k2, s):
        """Заслонка: чётные слова — FL, нечётные — FL⁻¹ (in-place, u32[8])."""
        for j in range(8):
            y = x[j]
            y1 = y >> np.uint8(16)
            y2 = y & np.uint32(0xFFFF)
            sh = s[j]
            if j % 2 == 0:                       # FL
                rk = y2 & k1[j]
                if sh == 0:
                    rot = rk
                else:
                    rot = (rk << sh) | (rk >> (np.uint8(32) - sh))
                y1 = y1 ^ rot
                y2 = y2 ^ ((y1 | k2[j]) & np.uint32(0xFFFF))
            else:                                # FL⁻¹ (ротация от НОВОГО y2)
                y2 = y2 ^ ((y1 | k2[j]) & np.uint32(0xFFFF))
                rk = y2 & k1[j]
                if sh == 0:
                    rot = rk
                else:
                    rot = (rk << sh) | (rk >> (np.uint8(32) - sh))
                y1 = y1 ^ rot
            x[j] = (y1 << np.uint8(16)) | y2

    @njit(cache=True, boundscheck=False, inline='always')
    def _weave_fwd(w, J, K, A, M, C, P):
        """Несущая (прямой ход): T=4 фазы по P пар слов."""
        for t in range(4):
            for p in range(P):
                j = J[t, p]
                k = K[t, p]
                a = A[t, p]
                xj = w[j]
                if a == 0:
                    r = xj
                else:
                    r = (xj << a) | (xj >> (np.uint8(64) - a))
                x = r + (w[k] * M[t, p])
                w[j] = x
                w[k] = w[k] ^ x ^ C[t, p]

    @njit(cache=True, boundscheck=False, inline='always')
    def _weave_inv(w, J, K, A, M, C, P):
        """Несущая (обратный ход)."""
        for t in range(3, -1, -1):
            for p in range(P):
                j = J[t, p]
                k = K[t, p]
                kold = w[k] ^ w[j] ^ C[t, p]
                d = w[j] - (kold * M[t, p])
                a = A[t, p]
                if a == 0:
                    w[j] = d
                else:
                    w[j] = (d >> a) | (d << (np.uint8(64) - a))
                w[k] = kold

    @njit(cache=True, boundscheck=False, inline='always')
    def _F_into(x, r, T):
        """F: x u8[32] → x (in-place). r — номер раунда (0..4)."""
        w32 = np.empty(8, np.uint32)
        _b32_to_words(x, w32)
        _shutter32(w32, T[19][r], T[20][r], T[21][r])
        _words_to_b32(w32, x)
        w64 = np.empty(4, np.uint64)
        for t in range(4):
            v = np.uint64(0)
            for b in range(8):
                v = (v << np.uint8(8)) | np.uint64(x[8 * t + b])
            w64[t] = v
        _weave_fwd(w64, T[14][r], T[15][r], T[16][r], T[17][r], T[18][r], 2)
        for t in range(4):
            v = w64[t]
            for b in range(8):
                x[8 * t + b] = np.uint8(v >> np.uint8(56 - 8 * b))
        acc32 = np.zeros(4, np.uint64)
        for lay in range(3):
            for i in range(32):
                x[i] = T[22][r, lay, i, x[i]]
            for k in range(4):
                acc32[k] = 0
            for j in range(32):
                yj = x[j]
                lo = yj & np.uint8(15)
                hi = (yj >> np.uint8(4)) + np.uint8(16)
                for k in range(4):
                    acc32[k] ^= T[23][r, lay, j, lo, k] ^ T[23][r, lay, j, hi, k]
            for k in range(4):
                v = acc32[k]
                for b in range(8):
                    x[8 * k + b] = np.uint8(v >> np.uint8(8 * b))
        for i in range(32):
            x[i] = T[24][r, i, x[i]]

    @njit(cache=True, boundscheck=False, inline='always')
    def _H_into(L, R, h, T):
        """H: (L,R) u8[32]×2 → (in-place). h — номер пол-раунда (0..5)."""
        z = np.empty(64, _U8)
        for c in range(16):
            lhi = L[2 * c]
            llo = L[2 * c + 1]
            rhi = R[2 * c]
            rlo = R[2 * c + 1]
            uc = (T[3][h, c, 1, lhi] ^ T[3][h, c, 0, llo] ^ T[1][h, c]
                  ^ (T[25][1, rhi] ^ T[25][0, rlo]))
            vh = np.uint8(uc >> np.uint8(8))
            vl = np.uint8(uc & np.uint8(0xFF))
            vc = (T[4][h, c, 1, rhi] ^ T[4][h, c, 0, rlo] ^ T[2][h, c]
                  ^ (T[26][1, vh] ^ T[26][0, vl]))
            z[2 * c] = vh
            z[2 * c + 1] = vl
            z[32 + 2 * c] = np.uint8(vc >> np.uint8(8))
            z[32 + 2 * c + 1] = np.uint8(vc & np.uint8(0xFF))
        w = np.empty(8, np.uint64)
        _b64_to_words(z, w)
        _weave_fwd(w, T[7][h], T[8][h], T[9][h], T[10][h], T[11][h], 4)
        _words_to_b64(w, z)
        t64 = np.zeros(8, np.uint64)
        for j in range(64):
            zj = z[j]
            lo = zj & np.uint8(15)
            hi = (zj >> np.uint8(4)) + np.uint8(16)
            for k in range(8):
                t64[k] ^= T[12][h, j, lo, k] ^ T[12][h, j, hi, k]
        t = np.empty(64, _U8)
        for k in range(8):
            v = t64[k]
            for b in range(8):
                t[8 * k + b] = np.uint8(v >> np.uint8(8 * b))
        for i in range(32):
            L[i] = t[i] ^ t[32 + i]
            R[i] = t[i]

    @njit(cache=True, boundscheck=False, inline='always')
    def _Hinv_into(L, R, h, T):
        """H⁻¹: вход (uo,vo) в (L,R), выход (L,R)."""
        y = np.empty(64, _U8)
        for i in range(32):
            y[i] = R[i]
            y[32 + i] = L[i] ^ R[i]
        z64 = np.zeros(8, np.uint64)
        for j in range(64):
            yj = y[j]
            lo = yj & np.uint8(15)
            hi = (yj >> np.uint8(4)) + np.uint8(16)
            for k in range(8):
                z64[k] ^= T[13][h, j, lo, k] ^ T[13][h, j, hi, k]
        z = np.empty(64, _U8)
        for k in range(8):
            v = z64[k]
            for b in range(8):
                z[8 * k + b] = np.uint8(v >> np.uint8(8 * b))
        w = np.empty(8, np.uint64)
        _b64_to_words(z, w)
        _weave_inv(w, T[7][h], T[8][h], T[9][h], T[10][h], T[11][h], 4)
        _words_to_b64(w, z)
        for c in range(16):
            uc = (np.uint16(z[2 * c]) << np.uint8(8)) | np.uint16(z[2 * c + 1])
            vc = ((np.uint16(z[32 + 2 * c]) << np.uint8(8))
                  | np.uint16(z[32 + 2 * c + 1]))
            uh = np.uint8(uc >> np.uint8(8))
            ul = np.uint8(uc & np.uint8(0xFF))
            t16 = vc ^ T[2][h, c] ^ (T[26][1, uh] ^ T[26][0, ul])
            th = np.uint8(t16 >> np.uint8(8))
            tl = np.uint8(t16 & np.uint8(0xFF))
            rc = T[6][h, c, 1, th] ^ T[6][h, c, 0, tl]
            rh = np.uint8(rc >> np.uint8(8))
            rl = np.uint8(rc & np.uint8(0xFF))
            t2 = uc ^ T[1][h, c] ^ (T[25][1, rh] ^ T[25][0, rl])
            t2h = np.uint8(t2 >> np.uint8(8))
            t2l = np.uint8(t2 & np.uint8(0xFF))
            lc = T[5][h, c, 1, t2h] ^ T[5][h, c, 0, t2l]
            L[2 * c] = np.uint8(lc >> np.uint8(8))
            L[2 * c + 1] = np.uint8(lc)
            R[2 * c] = np.uint8(rc >> np.uint8(8))
            R[2 * c + 1] = np.uint8(rc)

    @njit(cache=True, boundscheck=False, inline='always')
    def _enc_block(inp, out, T):
        L = np.empty(32, _U8)
        R = np.empty(32, _U8)
        for i in range(32):
            L[i] = inp[i] ^ T[0][0, i]
            R[i] = inp[32 + i] ^ T[0][1, i]
        _H_into(L, R, 0, T)
        x = np.empty(32, _U8)
        for r in range(5):
            for i in range(32):
                x[i] = L[i] ^ R[i]
            _F_into(x, r, T)
            for i in range(32):
                L[i] = L[i] ^ x[i]
                R[i] = R[i] ^ x[i]
            _H_into(L, R, r + 1, T)
        for i in range(32):
            out[i] = L[i] ^ T[0][2, i]
            out[32 + i] = R[i] ^ T[0][3, i]

    @njit(cache=True, boundscheck=False, inline='always')
    def _dec_block(inp, out, T):
        L = np.empty(32, _U8)
        R = np.empty(32, _U8)
        for i in range(32):
            L[i] = inp[i] ^ T[0][2, i]
            R[i] = inp[32 + i] ^ T[0][3, i]
        _Hinv_into(L, R, 5, T)
        x = np.empty(32, _U8)
        for r in range(4, -1, -1):
            for i in range(32):
                x[i] = L[i] ^ R[i]
            _F_into(x, r, T)
            for i in range(32):
                L[i] = L[i] ^ x[i]
                R[i] = R[i] ^ x[i]
            _Hinv_into(L, R, r, T)
        for i in range(32):
            out[i] = L[i] ^ T[0][0, i]
            out[32 + i] = R[i] ^ T[0][1, i]

    @njit(cache=True, boundscheck=False, parallel=True, nogil=True)
    def encrypt_blocks_n(inp, out, nb, T):
        for b in prange(nb):
            _enc_block(inp[b * 64:(b + 1) * 64], out[b * 64:(b + 1) * 64], T)

    @njit(cache=True, boundscheck=False, parallel=True, nogil=True)
    def decrypt_blocks_n(inp, out, nb, T):
        for b in prange(nb):
            _dec_block(inp[b * 64:(b + 1) * 64], out[b * 64:(b + 1) * 64], T)

    @njit(cache=True, boundscheck=False)
    def build_counters_n(out, iv56, ctr0, nb):
        """out (nb*64) ← nb блоков-счётчиков: iv56 ‖ be64(ctr0+i)."""
        for b in range(nb):
            o = b * 64
            for i in range(56):
                out[o + i] = iv56[i]
            ctr = ctr0 + np.uint64(b)
            for i in range(8):
                out[o + 56 + i] = np.uint8(ctr >> np.uint8(56 - 8 * i))

    @njit(cache=True, boundscheck=False)
    def ctr_tail_n(iv56, ctr, tail_len, out_off, out, T):
        """Хвостовой неполный блок CTR: keystream ⊕ out[out_off:…] in-place."""
        blk = np.empty(64, _U8)
        for i in range(56):
            blk[i] = iv56[i]
        c = np.uint64(ctr)
        for i in range(8):
            blk[56 + i] = np.uint8(c >> np.uint8(56 - 8 * i))
        ks = np.empty(64, _U8)
        _enc_block(blk, ks, T)
        for i in range(tail_len):
            out[out_off + i] = ks[i] ^ out[out_off + i]

else:                                                    # pragma: no cover
    encrypt_blocks_n = decrypt_blocks_n = ctr_xor_n = None


# ---------------------------------------------------------------------------
# Обёртки Python-уровня
# ---------------------------------------------------------------------------

class NativeGornHasher:
    """Потоковый ГОРН, побитово равный gorn.GornHasher (нативное впитывание)."""

    __slots__ = ('_st', '_buf', '_msglen', '_tag')

    def __init__(self, tag: bytes = b''):
        if b'\x1f' in tag:
            raise ValueError('тег не должен содержать байт 0x1F '
                             '(разделитель доменов)')
        self._tag = tag
        self._st = _IV.copy()
        self._buf = bytearray(tag + b'\x1f')
        self._msglen = 0

    def update(self, data) -> 'NativeGornHasher':
        self._msglen += len(data)
        self._buf += data
        n = (len(self._buf) // RATE) * RATE
        if n:
            head = self._buf[:n]
            del self._buf[:n]
            _absorb(self._st, np.frombuffer(head, dtype=_U8), n // RATE)
        return self

    def digest(self) -> bytes:
        pad_n = (-len(self._buf) - 9) % RATE
        tail = bytes(self._buf) + b'\x80' + b'\x00' * pad_n \
            + self._msglen.to_bytes(8, 'big')
        _absorb(self._st, _as_u8(tail), len(tail) // RATE)
        _perm(self._st)
        out = np.empty(64, _U8)
        _fold_into(self._st, out)
        return out.tobytes()


def _as_u8(buf):
    """bytes/bytearray/memoryview → uint8-массив (без копирования, если можно)."""
    if isinstance(buf, np.ndarray):
        return buf
    arr = np.frombuffer(buf, dtype=_U8)
    if not arr.flags.writeable:
        # numba специализирует readonly-массивы отдельно; приведём к bytearray
        arr = np.frombuffer(bytearray(buf), dtype=_U8)
    return arr


def gorn_hash_native(msg: bytes, tag: bytes = b'') -> bytes:
    return _hash_full(_as_u8(msg), _as_u8(tag)).tobytes()


def gorn_expand_native(seed: bytes, tag: bytes, nbytes: int) -> bytes:
    return _expand_full(_as_u8(seed), _as_u8(tag), int(nbytes)).tobytes()


class NativeCipher:
    """Нативный контекст Kazual-512 для одного расписания ключей (km)."""

    __slots__ = ('T',)

    def __init__(self, T):
        self.T = T

    # ---- блочные операции (данные кратны 64 Б) ----
    def encrypt_blocks(self, data) -> bytes:
        arr = _as_u8(data)
        nb = arr.shape[0] // 64
        out = np.empty(nb * 64, _U8)
        with _PAR_LOCK:
            encrypt_blocks_n(arr, out, nb, self.T)
        return out.tobytes()

    def decrypt_blocks(self, data) -> bytes:
        arr = _as_u8(data)
        nb = arr.shape[0] // 64
        out = np.empty(nb * 64, _U8)
        with _PAR_LOCK:
            decrypt_blocks_n(arr, out, nb, self.T)
        return out.tobytes()

    # ---- слитный CTR (keystream ⊕ данные), произвольная длина ----
    def ctr_xor(self, data, iv: bytes, ctr_start: int):
        """CTR ⊕ data целиком (iv — 64 Б с подготовленной зоной счётчика)."""
        arr = _as_u8(data)
        n = arr.shape[0]
        out = np.empty(n, _U8)
        nb = n // 64
        iv56 = np.frombuffer(bytearray(iv[:56]), dtype=_U8)
        if nb:
            ctrs = np.empty(nb * 64, _U8)
            build_counters_n(ctrs, iv56, np.uint64(ctr_start), nb)
            with _PAR_LOCK:
                encrypt_blocks_n(ctrs, out, nb, self.T)
            out[:nb * 64] ^= arr[:nb * 64]
        tail = n - nb * 64
        if tail:
            out[nb * 64:] = arr[nb * 64:]
            ctr_tail_n(iv56, ctr_start + nb, tail, nb * 64, out, self.T)
        return out

    def ctr_xor_buf(self, src_arr: np.ndarray, dst: np.ndarray,
                    iv56: np.ndarray, ctr_start: int,
                    scratch: np.ndarray = None) -> None:
        """Слитный CTR для потокового конвейера: dst ← src ⊕ keystream.

        src/dst — кратны 64 Б; scratch — буфер ≥ len(src) (переиспользуется
        между чанками, чтобы не аллоцировать на каждый).
        """
        nb = src_arr.shape[0] // 64
        if scratch is None or scratch.shape[0] < nb * 64:
            scratch = np.empty(nb * 64, _U8)
        build_counters_n(scratch, iv56, np.uint64(ctr_start), nb)
        with _PAR_LOCK:
            encrypt_blocks_n(scratch, dst, nb, self.T)
        dst[:nb * 64] ^= src_arr[:nb * 64]

    def ctr_tail_buf(self, dst: np.ndarray, off: int, tail_len: int,
                     iv56: np.ndarray, ctr: int) -> None:
        """Хвостовой неполный блок: dst[off:off+tail_len] ⊕= keystream(ctr)."""
        ctr_tail_n(iv56, ctr, tail_len, off, dst, self.T)


# ---------------------------------------------------------------------------
# Построение таблиц из KeyMat (векторизовано NumPy, побитово = mds_cols)
# ---------------------------------------------------------------------------

def _weave_arrays(sub):
    """sub[t] = [(j,k,alpha,m,c),…] → (J,K i32[T,P]; A u8; M,C u64)."""
    T = len(sub)
    P = max(len(s) for s in sub)
    J = np.zeros((T, P), np.int32)
    K = np.zeros((T, P), np.int32)
    A = np.zeros((T, P), _U8)
    M = np.zeros((T, P), np.uint64)
    C = np.zeros((T, P), np.uint64)
    for t in range(T):
        for p, (j, k, alpha, m, c) in enumerate(sub[t]):
            J[t, p] = j
            K[t, p] = k
            A[t, p] = alpha
            M[t, p] = np.uint64(m) & np.uint64(0xFFFFFFFFFFFFFFFF)
            C[t, p] = np.uint64(c) & np.uint64(0xFFFFFFFFFFFFFFFF)
    return J, K, A, M, C


def _fan_tables(pi, rho, n, inverse=False):
    """(n,256,n): [j][v][i] — колоночные таблицы Веера (побитово = mds_cols)."""
    if not inverse:
        vals = np.empty((n, n), np.intp)
        for i in range(n):
            for j in range(n):
                vals[i, j] = inv8(pi[i] ^ (n + rho[j]))
        arr = _MUL8T[vals]                     # [i][j][v]
        return np.ascontiguousarray(arr.transpose(1, 2, 0))
    CI = cauchy_inv_tables(n)
    vals = np.empty((n, n), np.intp)
    for i in range(n):
        for j in range(n):
            vals[i, j] = CI[rho[j]][pi[i]]
    arr = _MUL8T[vals]                         # [i][j][v]
    return np.ascontiguousarray(arr.transpose(0, 2, 1))


def _mult16_split(m):
    """Байт-сплит таблицы умножения на m в GF(2¹⁶): (2,256) u16.

    out[0][x] = m⊗x; out[1][x] = m⊗(x<<8). GF(2)-линейность: таблица
    собирается XOR-суммой 16 базисных слов m⊗2ᵇ = ALOG16[LOG16[m]+b].
    """
    out = np.zeros((2, 256), np.uint16)
    if m == 0:
        return out
    lm = int(LOG16[m])
    basis = np.asarray([ALOG16[lm + b] for b in range(16)], np.uint16)
    idx = np.arange(256, dtype=np.uint16)
    bits = ((idx[:, None] >> np.arange(8)) & 1).astype(np.uint16)
    out[0] = np.bitwise_xor.reduce(bits * basis[None, :8], axis=1)
    out[1] = np.bitwise_xor.reduce(bits * basis[None, 8:], axis=1)
    return out


def _nibble_rows(byte_tables, row_words):
    """(…,256,W·8) байт-таблицы → (…,32,W) u64 nibble-строки.

    e = 0..15: слово ⊗e;  e = 16..31: слово ⊗((e−16)<<4).
    """
    sh = byte_tables.shape
    V = np.ascontiguousarray(byte_tables).view(np.uint64).reshape(
        sh[:-2] + (256, row_words))
    out = np.empty(sh[:-2] + (32, row_words), np.uint64)
    out[..., :16, :] = V[..., :16, :]
    out[..., 16:, :] = V[..., 0:256:16, :]
    return np.ascontiguousarray(out)


def prepare_tables(km) -> tuple:
    """KeyMat → кортеж массивов T для JIT-ядер (только Kazual-512)."""
    spec = km.spec
    if spec.name != 'Kazual-512':
        raise ValueError('нативный путь поддерживает только Kazual-512')
    nh = spec.rounds + 1
    nf = spec.rounds
    n = spec.n
    nc = n // 2                            # чанков стадии A
    ph = ((2 * n * 8) // spec.wb_h) // 2   # пар слов на фазу Несущей H
    pf = ((n * 8) // spec.wb_f) // 2       # пар слов на фазу Несущей F

    W = np.stack([np.frombuffer(x, dtype=_U8)
                  for x in (km.WL, km.WR, km.WpL, km.WpR)])

    LB = np.zeros((nh, nc), np.uint16)
    LBP = np.zeros((nh, nc), np.uint16)
    AMUL = np.zeros((nh, nc, 2, 256), np.uint16)
    APMUL = np.zeros((nh, nc, 2, 256), np.uint16)
    IAMUL = np.zeros((nh, nc, 2, 256), np.uint16)
    IAPMUL = np.zeros((nh, nc, 2, 256), np.uint16)
    HJ = np.zeros((nh, 4, ph), np.int32)
    HK = np.zeros_like(HJ)
    HA = np.zeros(HJ.shape, _U8)
    HM = np.zeros(HJ.shape, np.uint64)
    HC = np.zeros(HJ.shape, np.uint64)
    FAN = np.zeros((nh, 2 * n, 256, 2 * n), _U8)
    FANINV = np.zeros((nh, 2 * n, 256, 2 * n), _U8)
    m1 = m2 = None
    for h, ht in enumerate(km.ht):
        LB[h] = ht.lb
        LBP[h] = ht.lbp
        for c in range(nc):
            AMUL[h, c] = _mult16_split(ALOG16[ht.la[c]])
            APMUL[h, c] = _mult16_split(ALOG16[ht.lap[c]])
            IAMUL[h, c] = _mult16_split(ht.ia[c])
            IAPMUL[h, c] = _mult16_split(ht.iap[c])
        J, K, A, M, C = _weave_arrays(ht.weave.sub)
        HJ[h] = J
        HK[h] = K
        HA[h] = A
        HM[h] = M
        HC[h] = C
        FAN[h] = _fan_tables(ht.PI, ht.RHO, 2 * n)
        FANINV[h] = _fan_tables(ht.PI, ht.RHO, 2 * n, inverse=True)
        if m1 is None:
            m1, m2 = ALOG16[ht.lM1], ALOG16[ht.lM2]
    M1T = _mult16_split(int(m1))
    M2T = _mult16_split(int(m2))

    FJ = np.zeros((nf, 4, pf), np.int32)
    FK = np.zeros_like(FJ)
    FA = np.zeros(FJ.shape, _U8)
    FM = np.zeros(FJ.shape, np.uint64)
    FC = np.zeros(FJ.shape, np.uint64)
    SHK1 = np.zeros((nf, spec.nw32), np.uint32)
    SHK2 = np.zeros((nf, spec.nw32), np.uint32)
    SHS = np.zeros((nf, spec.nw32), _U8)
    FUSED = np.zeros((nf, spec.layers, n, 256), _U8)
    COLS = np.zeros((nf, spec.layers, n, 256, n), _U8)
    EPI = np.zeros((nf, n, 256), _U8)
    for r, ft in enumerate(km.ft):
        J, K, A, M, C = _weave_arrays(ft.weave.sub)
        FJ[r] = J
        FK[r] = K
        FA[r] = A
        FM[r] = M
        FC[r] = C
        SHK1[r] = np.asarray(ft.shutter.k1, np.uint32)
        SHK2[r] = np.asarray(ft.shutter.k2, np.uint32)
        SHS[r] = np.asarray(ft.shutter.s, _U8)
        for lay, ((fused, _cols), (pi, rho)) in enumerate(
                zip(ft.strokes, ft.pirho)):
            FUSED[r, lay] = np.frombuffer(b''.join(fused),
                                          dtype=_U8).reshape(n, 256)
            COLS[r, lay] = _fan_tables(pi, rho, n)
        EPI[r] = np.frombuffer(b''.join(ft.epi), dtype=_U8).reshape(n, 256)

    FANN = _nibble_rows(np.ascontiguousarray(FAN), 8)
    FANINVN = _nibble_rows(np.ascontiguousarray(FANINV), 8)
    COLSN = _nibble_rows(np.ascontiguousarray(COLS), 4)
    return (W, LB, LBP, AMUL, APMUL, IAMUL, IAPMUL,
            HJ, HK, HA, HM, HC, FANN, FANINVN,
            FJ, FK, FA, FM, FC, SHK1, SHK2, SHS,
            np.ascontiguousarray(FUSED), COLSN,
            np.ascontiguousarray(EPI), M1T, M2T)


def cipher_for(spec, km):
    """NativeCipher для (spec, km); None — если шифр не Kazual-512."""
    if not NUMBA_AVAILABLE or spec.name != 'Kazual-512':
        return None
    ctx = km.bctx.get('native')
    if ctx is None:
        ctx = km.bctx['native'] = NativeCipher(prepare_tables(km))
    return ctx


# ---------------------------------------------------------------------------
# Потоки, прогрев, регистрация хуков
# ---------------------------------------------------------------------------

_threads_lock = threading.Lock()
_warm = {'done': False, 'running': False}

# ВАЖНО: параллельные регионы numba (prange, слой workqueue/omp) используют
# общий глобальный барьер — два ОДНОВРЕМЕННЫХ parallel-вызова из разных
# потоков роняют процесс. Все точки входа с prange сериализуем этим замком
# (потоки tree-MAC используют nogil-ядра БЕЗ prange и замка не требуют).
_PAR_LOCK = threading.Lock()


def set_threads(n: int) -> None:
    """Ограничить число потоков prange (0 = все доступные ядра)."""
    if not NUMBA_AVAILABLE:
        return
    mx = _numba.config.NUMBA_NUM_THREADS
    if n is None or int(n) <= 0:
        n = mx
    n = max(1, min(int(n), mx))
    with _threads_lock:
        set_num_threads(n)


def get_threads():
    if not NUMBA_AVAILABLE:
        n = os.cpu_count() or 1
        return (n, n)
    return (get_num_threads(), _numba.config.NUMBA_NUM_THREADS)


def warmup() -> None:
    """Скомпилировать все ядра (однократно; вызывается из фонового потока)."""
    if not NUMBA_AVAILABLE or _warm['done'] or _warm['running']:
        return
    _warm['running'] = True
    try:
        tag = b'KazualCipher/native/warmup'
        _hash_full(np.zeros(3, _U8), _as_u8(tag))
        _expand_full(_as_u8(b'seed'), _as_u8(tag), 128)
        h = NativeGornHasher(tag)
        h.update(b'x' * 200)
        h.digest()
        # блочные ядра — на фиктивном расписании (детерминированно)
        from .spec import FULL
        from .schedule import key_schedule
        km = key_schedule(FULL, b'\x00' * 64)
        ctx = cipher_for(FULL, km)
        if ctx is not None:
            blk = np.zeros(64, _U8)
            out = np.zeros(64, _U8)
            with _PAR_LOCK:
                encrypt_blocks_n(blk, out, 1, ctx.T)
                decrypt_blocks_n(out, blk, 1, ctx.T)
            iv56 = np.zeros(56, _U8)
            cs = np.empty(64, _U8)
            build_counters_n(cs, iv56, np.uint64(0), 1)
            ctr_tail_n(iv56, 1, 7, 0, out[:7].copy(), ctx.T)
        _warm['done'] = True
    finally:
        _warm['running'] = False


def is_warm() -> bool:
    return _warm['done']


# ---- регистрация в _accel ----
if NUMBA_AVAILABLE:
    from . import _accel

    _accel.HOOKS.update({
        'gorn_hash': gorn_hash_native,
        'gorn_expand': gorn_expand_native,
        'hasher': NativeGornHasher,
        'cipher_for': cipher_for,
        'set_threads': set_threads,
        'threads': get_threads,
        'warmup': warmup,
    })
