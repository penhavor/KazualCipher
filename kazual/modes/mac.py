# -*- coding: utf-8 -*-
"""
MAC для SIV-пакета: V = ГОРН(K_mac ‖ canonical_body, tag=домен).

ГОРН — губка с ёмкостью 512 бит, поэтому конструкция «ключ ‖ сообщение»
не подвержена удлинению (length-extension) и HMAC не требуется.
Тело MAC канонично: каждое поле пакетируется 32/64-битным length-префиксом,
порядок полей фиксирован, отключённые поля входят как пустые (длина 0) —
разночтения исключены. Доменное разделение — тегом с именем шифра.
"""

from __future__ import annotations

import struct

from ..cipher.gorn import GornHasher, gorn_hash

__all__ = ['siv_mac', 'siv_mac_streaming', 'GornMacError', 'mac_domain_tag']

V_BYTES = 64  # тег V = дайджест ГОРН, 512 бит


class GornMacError(ValueError):
    """Ошибка вычисления MAC (не путать с провалом проверки подлинности)."""


def mac_domain_tag(cipher_name: str) -> bytes:
    """Тег домена MAC: разделяет шифры и версии формата."""
    return b'KazualCipher/SIV/v1/' + cipher_name.encode('ascii')


def _frame(*chunks) -> bytes:
    """Каноническая упаковка: u32be(len) ‖ bytes для каждого поля."""
    out = []
    for c in chunks:
        out.append(struct.pack('>I', len(c)))
        out.append(bytes(c))
    return b''.join(out)


def siv_mac(k_mac: bytes, cipher_name: str, prefix: bytes, params_field: bytes,
            random_field: bytes, plaintext: bytes) -> bytes:
    """V (512 бит) = MAC от K_mac и всех полей пакета + открытого текста."""
    body = _frame(prefix, params_field, random_field,
                  struct.pack('>Q', len(plaintext))) + plaintext
    return gorn_hash(k_mac + body, mac_domain_tag(cipher_name))


def siv_mac_streaming(k_mac: bytes, cipher_name: str, prefix: bytes,
                      params_field: bytes, random_field: bytes,
                      plaintext_len: int) -> GornHasher:
    """Потоковый MAC: вернуть хэшер, в который осталось скормить текст.

    Каркас (K_mac, поля пакета и 64-битная длина текста) впитывается сразу;
    далее вызывающий делает hasher.update(часть_текста) с прогрессом и
    hasher.digest() в конце. Побитово равен siv_mac() — проверяется тестом.
    Длина текста известна заранее: при шифровании это len(pt), при
    расшифровании len(ct) (CTR сохраняет длину).
    """
    h = GornHasher(mac_domain_tag(cipher_name))
    h.update(k_mac)
    h.update(_frame(prefix, params_field, random_field,
                    struct.pack('>Q', plaintext_len)))
    return h

