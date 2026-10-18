# -*- coding: utf-8 -*-
"""
Пакетная обработка независимых блоков: NumPy (CPU) / CuPy (GPU) /
multiprocessing. Побитово идентична скалярному пути. §10 спецификации.
"""

import sys

from .gf import MUL8T, LOG16, ALOG16, inv8, cauchy_inv_tables
from .spec import SPECS
from .schedule import key_schedule
from .core import encrypt, decrypt

try:
    import numpy as _np
except Exception:                                   # NumPy необязателен
    _np = None

# Блоки независимы («embarrassingly parallel»): один и тот
# же алгоритм векторизуется по измерению блоков. Результаты ИДЕНТИЧНЫ скалярному
# пути (проверяется самопроверкой). NumPy/CuPy необязательны: без них работает
# скалярный путь; CuPy используется только при наличии GPU.

_GPU_MIN_BLOCKS = 1024          # порог целесообразности GPU (накладные ядра)
_NP_MIN_BLOCKS = 16             # порог целесообразности NumPy
_CHUNK_BLOCKS = 1 << 15         # чанк ограничивает временную память

_cp_probe = {'done': False, 'cp': None}


def cupy_backend():
    """CuPy, если установлен и виден хотя бы один GPU; иначе None (лениво)."""
    if not _cp_probe['done']:
        _cp_probe['done'] = True
        try:
            import cupy as cp
            if cp.cuda.runtime.getDeviceCount() > 0:
                _cp_probe['cp'] = cp
        except Exception:
            pass
    return _cp_probe['cp']


_ARR_CACHE = {}


def _shared_arrays(xp):
    """Общие таблицы бэкенда (кэш на модуль xp)."""
    t = _ARR_CACHE.get(xp.__name__)
    if t is None:
        mul8 = xp.frombuffer(b''.join(MUL8T), dtype=xp.uint8).reshape(256, 256).copy()
        log16 = xp.array(LOG16, dtype=xp.int32)
        alog16 = xp.array(ALOG16, dtype=xp.uint16)
        t = _ARR_CACHE[xp.__name__] = (mul8, log16, alog16)
    return t


def _u_dtype(xp, wb):
    return {64: xp.uint64, 32: xp.uint32, 16: xp.uint16, 8: xp.uint8}[wb]


class BatchCtx:
    """Векторизованные таблицы поверх km для бэкенда xp (numpy-совместимый API)."""

    def __init__(self, spec, km, xp):
        self.spec, self.xp = spec, xp
        self.mul8, self.log16, self.alog16 = _shared_arrays(xp)
        u8 = xp.uint8
        self.WL = xp.frombuffer(km.WL, dtype=u8).copy()
        self.WR = xp.frombuffer(km.WR, dtype=u8).copy()
        self.WpL = xp.frombuffer(km.WpL, dtype=u8).copy()
        self.WpR = xp.frombuffer(km.WpR, dtype=u8).copy()
        self.ftc = [self._ft_ctx(ft) for ft in km.ft]
        self.htc = [self._ht_ctx(ht) for ht in km.ht]

    # ---- построение контекстов таблиц
    def _ct_from_vals(self, vals):
        """vals[i][j] (выход i, вход j) → CT (n_in, 256, n_out): CT[j][v][i] = vals[i][j]⊗v."""
        xp = self.xp
        ni = len(vals)
        nj = len(vals[0])
        v = xp.array([[vals[i][j] for i in range(ni)] for j in range(nj)], dtype=xp.uint8)
        ct = self.mul8[v[:, :, None], xp.arange(256, dtype=xp.intp)[None, None, :]]
        return xp.ascontiguousarray(ct.transpose(0, 2, 1))

    def _ft_ctx(self, ft):
        xp = self.xp
        spec = ft.spec
        n = spec.n
        d = {}
        d['sh'] = (xp.array(ft.shutter.k1, dtype=xp.uint32),
                   xp.array(ft.shutter.k2, dtype=xp.uint32),
                   xp.array(ft.shutter.s, dtype=xp.uint32))
        d['wv'] = (ft.weave, _u_dtype(xp, spec.wb_f), spec.wb_f)
        strokes = []
        for (fu, _cols), (pi, rho) in zip(ft.strokes, ft.pirho):
            fused = xp.frombuffer(b''.join(fu), dtype=xp.uint8).reshape(n, 256).copy()
            vals = [[inv8(pi[i] ^ (n + rho[j])) for j in range(n)] for i in range(n)]
            strokes.append((fused, self._ct_from_vals(vals)))
        d['strokes'] = strokes
        d['epi'] = xp.frombuffer(b''.join(ft.epi), dtype=xp.uint8).reshape(n, 256).copy()
        d['colidx'] = xp.arange(n, dtype=xp.intp)
        return d

    def _ht_ctx(self, ht):
        xp = self.xp
        spec = ht.spec
        fan = spec.fan
        d = {}
        d['la'] = xp.array(ht.la, dtype=xp.int32)
        d['lap'] = xp.array(ht.lap, dtype=xp.int32)
        d['lia'] = xp.array([LOG16[v] for v in ht.ia], dtype=xp.int32)
        d['liap'] = xp.array([LOG16[v] for v in ht.iap], dtype=xp.int32)
        d['lb'] = xp.array(ht.lb, dtype=xp.uint16)
        d['lbp'] = xp.array(ht.lbp, dtype=xp.uint16)
        d['lM1'] = int(ht.lM1)
        d['lM2'] = int(ht.lM2)
        d['wv'] = (ht.weave, _u_dtype(xp, spec.wb_h), spec.wb_h)
        PI, RHO = ht.PI, ht.RHO
        vals = [[inv8(PI[i] ^ (fan + RHO[j])) for j in range(fan)] for i in range(fan)]
        d['fan'] = self._ct_from_vals(vals)
        CI = cauchy_inv_tables(fan)
        vals_inv = [[CI[RHO[j]][PI[i]] for i in range(fan)] for j in range(fan)]
        d['fan_inv'] = self._ct_from_vals(vals_inv)
        return d

    # ---- векторные примитивы
    def _rot(self, v, k, wb):
        if k % wb == 0:
            return v
        k %= wb
        return (v << k) | (v >> (wb - k))

    def _weave(self, words, par, dt, wb, inverse=False):
        rng = range(par.T - 1, -1, -1) if inverse else range(par.T)
        for t in rng:
            for (j, k, alpha, m, c) in par.sub[t]:
                mm, cc = dt(m), dt(c)
                xj, xk = words[:, j], words[:, k]
                if inverse:
                    kold = xk ^ xj ^ cc
                    words[:, j] = self._rot(xj - (kold * mm), (-alpha) % wb, wb)
                    words[:, k] = kold
                else:
                    nx = self._rot(xj, alpha, wb) + (xk * mm)
                    words[:, j] = nx
                    words[:, k] = xk ^ nx ^ cc
        return words

    def _to_words(self, zb, wb):
        xp = self.xp
        k = wb // 8
        dt = _u_dtype(xp, wb)
        W = zb.shape[1] // k
        w = xp.zeros((zb.shape[0], W), dtype=dt)
        for b in range(k):
            w |= zb[:, b::k].astype(dt) << (8 * (k - 1 - b))
        return w

    def _from_words(self, w, wb):
        xp = self.xp
        k = wb // 8
        out = xp.empty((w.shape[0], w.shape[1] * k), dtype=xp.uint8)
        for b in range(k):
            out[:, b::k] = ((w >> (8 * (k - 1 - b))) & 0xFF).astype(xp.uint8)
        return out

    def _shutter(self, x, shp, inverse=False):
        xp = self.xp
        k1, k2, s = shp
        out = xp.empty_like(x)
        for sl, par in ((slice(0, None, 2), 0), (slice(1, None, 2), 1)):
            kk1, kk2, ss = k1[par::2], k2[par::2], s[par::2]
            y = x[:, sl]
            y1 = y >> 16
            y2 = y & 0xFFFF
            safe = xp.where(ss == 0, 1, ss)
            if (par == 0) != inverse:                     # FL
                rk = y2 & kk1
                rot = xp.where(ss == 0, rk, (rk << safe) | (rk >> (32 - safe)))
                y1 = y1 ^ rot
                y2 = (y2 ^ ((y1 | kk2) & 0xFFFF)) & 0xFFFF
            else:                                          # FL⁻¹
                y2 = (y2 ^ ((y1 | kk2) & 0xFFFF)) & 0xFFFF
                rk = y2 & kk1
                rot = xp.where(ss == 0, rk, (rk << safe) | (rk >> (32 - safe)))
                y1 = y1 ^ rot
            out[:, sl] = ((y1 << 16) | y2)
        return out

    def _m16(self, lmul, x16):
        """Пакетное умножение в GF(2^16): ALOG[lmul + LOG[x]] (0 → 0)."""
        xp = self.xp
        idx = lmul + self.log16[x16.astype(xp.int32)]
        return xp.where(x16 != 0, self.alog16[idx], 0).astype(xp.uint16)

    def _mds(self, x, ct):
        """y[:,i] = ⊕_j M[i][j]⊗x[:,j]: n ядер gather + XOR-накопление."""
        acc = self.xp.zeros(x.shape, dtype=self.xp.uint8)
        for j in range(ct.shape[0]):
            acc ^= ct[j][x[:, j]]
        return acc

    def _stageA(self, Lb, Rb, hc):
        """z = u ‖ v: u-чанк c → байты 2c, 2c+1; v-чанк c → байты 2n+2c, 2n+2c+1."""
        xp = self.xp
        u16 = xp.uint16
        n = Lb.shape[1]
        L16 = (Lb[:, 0::2].astype(u16) << 8) | Lb[:, 1::2].astype(u16)
        R16 = (Rb[:, 0::2].astype(u16) << 8) | Rb[:, 1::2].astype(u16)
        u = self._m16(hc['la'], L16) ^ hc['lb'] ^ self._m16(hc['lM1'], R16)
        v = self._m16(hc['lap'], R16) ^ hc['lbp'] ^ self._m16(hc['lM2'], u)
        zb = xp.empty((Lb.shape[0], 2 * n), dtype=xp.uint8)
        zb[:, 0:n:2] = (u >> 8).astype(xp.uint8)
        zb[:, 1:n:2] = (u & 0xFF).astype(xp.uint8)
        zb[:, n::2] = (v >> 8).astype(xp.uint8)
        zb[:, n + 1::2] = (v & 0xFF).astype(xp.uint8)
        return zb

    def _stageA_inv(self, u16, v16, hc):
        rc = self._m16(hc['liap'], v16 ^ hc['lbp'] ^ self._m16(hc['lM2'], u16))
        lc = self._m16(hc['lia'], u16 ^ hc['lb'] ^ self._m16(hc['lM1'], rc))
        return lc, rc

    def _H(self, Lb, Rb, hc):
        par, dt, wb = hc['wv']
        zb = self._stageA(Lb, Rb, hc)
        w = self._weave(self._to_words(zb, wb), par, dt, wb)
        t = self._mds(self._from_words(w, wb), hc['fan'])
        n = self.spec.n
        p, q = t[:, :n], t[:, n:]
        return p ^ q, p

    def _Hinv(self, uo, vo, hc):
        xp = self.xp
        n = self.spec.n
        par, dt, wb = hc['wv']
        y = xp.concatenate((vo, uo ^ vo), axis=1)
        z = self._mds(y, hc['fan_inv'])
        w = self._weave(self._to_words(z, wb), par, dt, wb, inverse=True)
        zb = self._from_words(w, wb)
        u16 = (zb[:, 0:n:2].astype(xp.uint16) << 8) | zb[:, 1:n:2].astype(xp.uint16)
        v16 = (zb[:, n::2].astype(xp.uint16) << 8) | zb[:, n + 1::2].astype(xp.uint16)
        lc, rc = self._stageA_inv(u16, v16, hc)
        Lb = xp.empty((zb.shape[0], n), dtype=xp.uint8)
        Rb = xp.empty((zb.shape[0], n), dtype=xp.uint8)
        Lb[:, 0::2] = (lc >> 8).astype(xp.uint8)
        Lb[:, 1::2] = (lc & 0xFF).astype(xp.uint8)
        Rb[:, 0::2] = (rc >> 8).astype(xp.uint8)
        Rb[:, 1::2] = (rc & 0xFF).astype(xp.uint8)
        return Lb, Rb

    def _F(self, xb, fc):
        spec = self.spec
        n = spec.n
        if n >= 4:
            w32 = self._to_words(xb, 32)
            w32 = self._shutter(w32, fc['sh'])
            xb = self._from_words(w32, 32)
        par, dt, wb = fc['wv']
        w = self._weave(self._to_words(xb, wb), par, dt, wb)
        xb = self._from_words(w, wb)
        ci = fc['colidx']
        for fused, ct in fc['strokes']:
            xb = fused[ci, xb]
            xb = self._mds(xb, ct)
        return fc['epi'][ci, xb]

    # ---- конвейеры
    def _run(self, arr, mode):
        spec = self.spec
        n = spec.n
        L = arr[:, :n] ^ self.WL if mode == 'enc' else arr[:, :n] ^ self.WpL
        R = arr[:, n:] ^ self.WR if mode == 'enc' else arr[:, n:] ^ self.WpR
        if mode == 'enc':
            L, R = self._H(L, R, self.htc[0])
            for i in range(spec.rounds):
                T = self._F(L ^ R, self.ftc[i])
                L, R = self._H(L ^ T, R ^ T, self.htc[i + 1])
            L, R = L ^ self.WpL, R ^ self.WpR
        else:
            L, R = self._Hinv(L, R, self.htc[spec.rounds])
            for i in range(spec.rounds - 1, -1, -1):
                T = self._F(L ^ R, self.ftc[i])
                L, R = self._Hinv(L ^ T, R ^ T, self.htc[i])
            L, R = L ^ self.WL, R ^ self.WR
        out = self.xp.empty_like(arr)
        out[:, :n] = L
        out[:, n:] = R
        return out

    def run(self, data: bytes, mode='enc') -> bytes:
        spec = self.spec
        b = spec.block_bytes
        xp = self.xp
        total = len(data) // b
        out = bytearray(len(data))
        for s in range(0, total, _CHUNK_BLOCKS):
            e = min(s + _CHUNK_BLOCKS, total)
            chunk = data[s * b:e * b]
            arr = xp.frombuffer(bytearray(chunk), dtype=xp.uint8).reshape(e - s, b)
            res = self._run(arr, mode)
            if xp is not _np:                      # CuPy: результат с GPU на хост
                import cupy as _cp
                res = _cp.asnumpy(res)
            out[s * b:e * b] = res.tobytes()
        return bytes(out)

    def encrypt(self, data):
        return self.run(data, 'enc')

    def decrypt(self, data):
        return self.run(data, 'dec')


def _batch_ctx(spec, km, xp):
    ctx = km.bctx.get(xp.__name__)
    if ctx is None:
        ctx = km.bctx[xp.__name__] = BatchCtx(spec, km, xp)
    return ctx


# ---- multiprocessing (fork: воркеры наследуют расписание из родителя;
# ---- spawn/Windows: каждый воркер строит расписание однократно, ~0.5 с) ----
_MP = {}


def _mp_init(spec_name, K):
    spec = SPECS[spec_name]
    km = key_schedule(spec, K)
    _MP['spec'], _MP['K'], _MP['km'] = spec, K, km
    _MP['ctx'] = _batch_ctx(spec, km, _np) if _np is not None else None


def _mp_run(args):
    mode, chunk = args
    if _MP['ctx'] is not None:
        return _MP['ctx'].run(chunk, mode)
    spec, K, km = _MP['spec'], _MP['K'], _MP['km']
    fn = encrypt if mode == 'enc' else decrypt
    b = spec.block_bytes
    return b''.join(fn(spec, K, chunk[i:i + b], km) for i in range(0, len(chunk), b))


def _run_mp(spec, K, data, mode, workers, km):
    global _MP
    import multiprocessing as _mpmod
    from concurrent.futures import ProcessPoolExecutor
    b = spec.block_bytes
    total = len(data) // b
    per = max(256, (total + workers - 1) // workers)
    chunks = [data[i * b:min(i + per, total) * b] for i in range(0, total, per)]
    method = _mpmod.get_start_method(allow_none=True)
    if method == 'fork' or (method is None and sys.platform != 'win32'):
        # fork: заполняем _MP в родителе — воркеры наследуют его copy-on-write
        if km is None:
            km = key_schedule(spec, K)
        _MP = {'spec': spec, 'K': K, 'km': km,
               'ctx': _batch_ctx(spec, km, _np) if _np is not None else None}
        ex = ProcessPoolExecutor(workers)
    else:
        ex = ProcessPoolExecutor(workers, initializer=_mp_init, initargs=(spec.name, K))
    with ex:
        parts = list(ex.map(_mp_run, [(mode, c) for c in chunks]))
    return b''.join(parts)


def _scalar_blocks(spec, K, data, mode, km):
    fn = encrypt if mode == 'enc' else decrypt
    b = spec.block_bytes
    return b''.join(fn(spec, K, data[i:i + b], km) for i in range(0, len(data), b))


def encrypt_blocks(spec, K, data, backend='auto', workers=1, km=None):
    """Пакетное шифрование независимых блоков (межблочный параллелизм).
    backend: 'auto' | 'cpu' (NumPy) | 'gpu' (CuPy) | 'scalar'.
    workers>1 — процессы; выгодно на больших объёмах (порог ниже): на Linux/fork
    расписание наследуется из родителя, на spawn/Windows воркеры строят его сами
    (~0.5 с на воркер)."""
    return _blocks(spec, K, data, 'enc', backend, workers, km)


def decrypt_blocks(spec, K, data, backend='auto', workers=1, km=None):
    return _blocks(spec, K, data, 'dec', backend, workers, km)


def native_ctx(spec, km):
    """Нативный (numba) контекст для spec/km или None."""
    from . import _accel
    return _accel.cipher_for(spec, km)


def _blocks(spec, K, data, mode, backend, workers, km):
    b = spec.block_bytes
    if len(data) % b:
        raise ValueError('данные не кратны блоку %d байт' % b)
    total = len(data) // b
    if total == 0:
        return b''
    if workers and workers > 1 and total >= 2048 * workers:
        return _run_mp(spec, K, data, mode, workers, km)
    if backend in ('auto', 'native'):
        if km is None:
            km = key_schedule(spec, K)
        nc = native_ctx(spec, km)
        if nc is not None:
            return nc.encrypt_blocks(data) if mode == 'enc' \
                else nc.decrypt_blocks(data)
        if backend == 'native':
            raise RuntimeError(
                'нативный бэкенд недоступен (numba не установлен или шифр '
                'не Kazual-512)')
    if backend == 'auto':
        cp = cupy_backend()
        if cp is not None and total >= _GPU_MIN_BLOCKS:
            backend = 'gpu'
        elif _np is not None and total >= _NP_MIN_BLOCKS:
            backend = 'cpu'
        else:
            backend = 'scalar'
    if backend == 'gpu':
        cp = cupy_backend()
        if cp is None:
            raise RuntimeError('CuPy/GPU недоступен')
        if km is None:
            km = key_schedule(spec, K)
        return _batch_ctx(spec, km, cp).run(data, mode)
    if backend == 'cpu':
        if _np is None:
            raise RuntimeError('NumPy недоступен')
        if km is None:
            km = key_schedule(spec, K)
        return _batch_ctx(spec, km, _np).run(data, mode)
    if km is None:
        km = key_schedule(spec, K)
    return _scalar_blocks(spec, K, data, mode, km)
