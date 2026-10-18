# -*- coding: utf-8 -*-
"""
ECB — простой режим: блоки независимы, PKCS#7-дополнение, без контейнера.

Честные ограничения (показываются и в GUI): нет аутентификации, одинаковые
открытые блоки дают одинаковые шифроблоки. Режим учебный/демонстрационный.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, List, Optional

from .padding import pkcs7_pad, pkcs7_unpad
from .siv import PacketField

__all__ = ['encrypt_ecb', 'decrypt_ecb', 'EcbResult']

_SEG_BLOCKS = 1 << 12
ProgressCb = Optional[Callable[[str, Optional[float]], None]]


def _report(cb: ProgressCb, stage: str, frac: Optional[float] = None) -> None:
    if cb is not None:
        cb(stage, frac)


@dataclass
class EcbResult:
    data: bytes
    fields: List[PacketField]
    meta: dict


def _blocks(spec, k_enc, data: bytes, mode: str, km, backend: str,
            progress_cb: ProgressCb) -> bytes:
    from ..cipher.batch import encrypt_blocks, decrypt_blocks
    from ..cipher.schedule import key_schedule
    fn = encrypt_blocks if mode == 'enc' else decrypt_blocks
    b = spec.block_bytes
    if km is None:
        _report(progress_cb, 'Расписание ключей шифра…')
        km = key_schedule(spec, k_enc)
    out = bytearray()
    total = max(1, (len(data) + b - 1) // b)
    done = 0
    for s in range(0, len(data), _SEG_BLOCKS * b):
        chunk = data[s:s + _SEG_BLOCKS * b]
        out += fn(spec, k_enc, chunk, backend=backend, km=km)
        done += (len(chunk) + b - 1) // b
        _report(progress_cb, 'ECB: %s…' % ('шифрование' if mode == 'enc'
                                           else 'дешифрование'),
                done / total)
    return bytes(out)


def encrypt_ecb(spec, cipher_name: str, k_enc: bytes, data: bytes,
                km=None, backend: str = 'auto',
                progress_cb: ProgressCb = None) -> EcbResult:
    """PKCS#7 → ECB-блоки."""
    t0 = time.monotonic()
    padded = pkcs7_pad(data, spec.block_bytes)
    ct = _blocks(spec, k_enc, padded, 'enc', km, backend, progress_cb)
    meta = {
        'cipher': cipher_name, 'mode': 'ecb', 'verified': None,
        'padding': len(padded) - len(data),
        'total_ms': (time.monotonic() - t0) * 1000.0,
    }
    fields = [PacketField('ciphertext', ct,
                          'ECB-блоки + PKCS#7 (+%d Б дополнения)'
                          % (len(padded) - len(data)))]
    return EcbResult(ct, fields, meta)


def decrypt_ecb(spec, cipher_name: str, k_enc: bytes, data: bytes,
                km=None, backend: str = 'auto',
                progress_cb: ProgressCb = None) -> EcbResult:
    """ECB-блоки → снятие PKCS#7 (ошибка дополнения = неверный ключ/порча)."""
    from ..cipher.schedule import key_schedule
    t0 = time.monotonic()
    if km is None:
        _report(progress_cb, 'Расписание ключей шифра…')
        km = key_schedule(spec, k_enc)
    if len(data) == 0 or len(data) % spec.block_bytes:
        from .padding import PaddingError
        raise PaddingError(
            'данные (%d Б) не кратны блоку %d Б — неверный режим/шифр или '
            'файл повреждён' % (len(data), spec.block_bytes))
    padded = _blocks(spec, k_enc, data, 'dec', km, backend, progress_cb)
    pt = pkcs7_unpad(padded, spec.block_bytes)
    meta = {
        'cipher': cipher_name, 'mode': 'ecb', 'verified': None,
        'total_ms': (time.monotonic() - t0) * 1000.0,
    }
    fields = [PacketField('plaintext', pt, 'после снятия PKCS#7')]
    return EcbResult(pt, fields, meta)
