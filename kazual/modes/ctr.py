# -*- coding: utf-8 -*-
"""
CTR поверх Kazual: keystream = E(K_enc, IV(counter)), без сцеплений —
блоки независимы, паддинга нет, операции параллелятся пакетным путём.

Nonce — синтетический V из SIV: IV = первые block_bytes байт V, младшие
counter_bytes байт отведены под счётчик, старший бит зоны счётчика
обнуляется (приём RFC 5297 Q) — коллизий счётчика с «чужой» зоной нет.
"""

from __future__ import annotations

__all__ = ['counter_bytes_for_block', 'ctr_iv', 'ctr_xor', 'CtrError']

_SEG_BLOCKS = 1 << 12          # блоков на сегмент (~256 КиБ для Kazual-512)
_SEG_NATIVE_BYTES = 1 << 23    # сегмент нативного пути (8 МиБ — prange)


class CtrError(ValueError):
    """Ошибка режима CTR (переполнение счётчика, неверные размеры)."""


def counter_bytes_for_block(block_bytes: int) -> int:
    """Ширина зоны счётчика: 8 байт для крупных блоков, половина — для мелких."""
    if block_bytes < 4:
        raise CtrError('блок %d Б слишком мал для CTR' % block_bytes)
    return 8 if block_bytes >= 16 else block_bytes // 2


def ctr_iv(v: bytes, block_bytes: int) -> bytearray:
    """IV счётчика из V: блок- nonce ‖ зона счётчика со сброшенным старшим битом."""
    if len(v) < block_bytes:
        raise CtrError('V короче блока: %d < %d' % (len(v), block_bytes))
    iv = bytearray(v[:block_bytes])
    cb = counter_bytes_for_block(block_bytes)
    iv[block_bytes - cb] &= 0x7F
    return iv


def ctr_xor(spec, k_enc: bytes, data: bytes, v: bytes, km=None,
            backend: str = 'auto', progress_cb=None) -> bytes:
    """CTR-шифрование = CTR-дешифрование: data ⊕ keystream(K_enc, V).

    progress_cb(fraction 0..1) вызывается по сегментам; km — готовое
    расписание ключей (кэш на операцию).
    """
    from ..cipher.batch import encrypt_blocks
    from ..cipher.schedule import key_schedule

    b = spec.block_bytes
    if not data:
        return b''
    cb = counter_bytes_for_block(b)
    iv = ctr_iv(v, b)
    ctr_start = int.from_bytes(iv[b - cb:], 'big')
    ctr_span = 1 << (8 * cb)
    total_blocks = (len(data) + b - 1) // b
    if ctr_start + total_blocks > ctr_span:
        raise CtrError('переполнение счётчика CTR: сообщение слишком велико')

    if km is None:
        km = key_schedule(spec, k_enc)

    # нативный слитный путь (numba): keystream⊕данные одним проходом,
    # параллельно по блокам — основной ускоритель больших объёмов
    if backend in ('auto', 'native'):
        from ..cipher.batch import native_ctx
        nc = native_ctx(spec, km)
        if nc is not None:
            out = bytearray(len(data))
            seg_bytes = _SEG_NATIVE_BYTES
            done = 0
            for s in range(0, len(data), seg_bytes):
                chunk = data[s:s + seg_bytes]
                seg = nc.ctr_xor(chunk, bytes(iv), ctr_start + s // b)
                out[s:s + len(chunk)] = seg[:len(chunk)].tobytes()
                done += (len(chunk) + b - 1) // b
                if progress_cb is not None:
                    progress_cb(done / total_blocks)
            return bytes(out)
        if backend == 'native':
            raise CtrError('нативный бэкенд недоступен (numba/Kazual-512)')

    out = bytearray(len(data))
    done = 0
    for s in range(0, len(data), _SEG_BLOCKS * b):
        chunk = data[s:s + _SEG_BLOCKS * b]
        nblk = (len(chunk) + b - 1) // b
        base = ctr_start + s // b
        ctrs = bytearray(nblk * b)
        for i in range(nblk):
            ctr = (base + i) % ctr_span
            ctrs[i * b:i * b + b - cb] = iv[:b - cb]
            ctrs[(i + 1) * b - cb:(i + 1) * b] = ctr.to_bytes(cb, 'big')
        ks = encrypt_blocks(spec, k_enc, bytes(ctrs), backend=backend, km=km)
        seg = bytes(x ^ y for x, y in zip(chunk, ks))
        out[s:s + len(seg)] = seg
        done += nblk
        if progress_cb is not None:
            progress_cb(done / total_blocks)
    return bytes(out)
