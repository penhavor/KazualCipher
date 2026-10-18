# -*- coding: utf-8 -*-
"""
Источники ключевого материала: пароль (через Argon2id) или сырой ключ
(растягивается ГОРНом — собственным KDF шифра, без внешних примитивов).
"""

from __future__ import annotations

import binascii
import re
from dataclasses import dataclass, field

from .kdf import KdfParams, derive_key

__all__ = ['KeySource', 'PasswordKey', 'RawKey', 'parse_raw_key_hex',
           'KeyMaterialError', 'siv_master_keys', 'mode_key']


class KeyMaterialError(ValueError):
    """Некорректный источник ключа (пустой пароль, битый hex и т.п.)."""


@dataclass(frozen=True)
class PasswordKey:
    """Пароль → Argon2id(salt, PHC-параметры) → мастер-ключ."""
    password: str

    def describe(self) -> str:
        return 'пароль (%d симв.)' % len(self.password)


@dataclass(frozen=True)
class RawKey:
    """Сырой ключ произвольной длины → ГОРН-растягивание до нужного размера."""
    key: bytes = field(repr=False)

    def describe(self) -> str:
        return 'сырой ключ (%d Б)' % len(self.key)


KeySource = (PasswordKey, RawKey)

_HEX_RE = re.compile(r'^(?:[0-9a-fA-F]{2}[\s:]*)+$')


def parse_raw_key_hex(text: str) -> bytes:
    """Hex-строка (пробелы/двоеточия допустимы) → байты; ошибки — KeyMaterialError."""
    cleaned = re.sub(r'[\s:]', '', text or '')
    if not cleaned:
        raise KeyMaterialError('пустой ключ')
    if not re.fullmatch(r'[0-9a-fA-F]+', cleaned):
        raise KeyMaterialError('ключ должен быть шестнадцатеричной строкой '
                               '(цифры 0-9, буквы a-f; пробелы и двоеточия '
                               'допустимы)')
    if len(cleaned) % 2:
        raise KeyMaterialError('в hex-ключе нечётное число цифр (%d)' % len(cleaned))
    try:
        return bytes.fromhex(cleaned)
    except (binascii.Error, ValueError) as exc:
        raise KeyMaterialError('не удалось разобрать hex-ключ: %s' % exc) from exc


def _stretch(spec, cipher_name: str, raw: bytes, domain: bytes,
             nbytes: int) -> bytes:
    from .cipher.gorn import gorn_expand
    from .cipher.spec import TAG
    return gorn_expand(raw, TAG + domain + cipher_name.encode('ascii'), nbytes)


def siv_master_keys(spec, cipher_name: str, source, salt: bytes,
                    params: KdfParams):
    """(K_enc, K_mac) для SIV: по ks_bytes каждый, из одного мастер-материала."""
    ks = spec.ks_bytes
    if isinstance(source, PasswordKey):
        if not source.password:
            raise KeyMaterialError('пустой пароль')
        master = derive_key(source.password, salt, params, 2 * ks)
    elif isinstance(source, RawKey):
        if not source.key:
            raise KeyMaterialError('пустой ключ')
        master = _stretch(spec, cipher_name, source.key, b'/SIV-RAWKEY/', 2 * ks)
    else:
        raise KeyMaterialError('неизвестный источник ключа: %r' % (source,))
    return master[:ks], master[ks:]


def mode_key(spec, cipher_name: str, source, salt: bytes,
             params: KdfParams, domain: bytes) -> bytes:
    """Ключ шифрования (один) для простых режимов — ECB."""
    ks = spec.ks_bytes
    if isinstance(source, PasswordKey):
        if not source.password:
            raise KeyMaterialError('пустой пароль')
        return derive_key(source.password, salt, params, ks)
    if isinstance(source, RawKey):
        if not source.key:
            raise KeyMaterialError('пустой ключ')
        return _stretch(spec, cipher_name, source.key, domain, ks)
    raise KeyMaterialError('неизвестный источник ключа: %r' % (source,))
