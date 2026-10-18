# -*- coding: utf-8 -*-
"""PKCS#7-дополнение до размера блока (нужно только режиму ECB)."""

__all__ = ['pkcs7_pad', 'pkcs7_unpad', 'PaddingError']


class PaddingError(ValueError):
    """Некорректное PKCS#7-дополнение: неверный ключ или повреждённые данные."""


def pkcs7_pad(data: bytes, block: int) -> bytes:
    """Дополнить data до кратности block (1…255). Пустые данные → полный блок."""
    if not 1 <= block <= 255:
        raise ValueError('размер блока должен быть 1…255 (дан %d)' % block)
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block: int) -> bytes:
    """Снять PKCS#7-дополнение; при любой неконсистентности — PaddingError."""
    if not 1 <= block <= 255:
        raise ValueError('размер блока должен быть 1…255 (дан %d)' % block)
    if len(data) == 0 or len(data) % block:
        raise PaddingError(
            'данные (%d Б) не кратны блоку %d Б — неверные настройки '
            'или повреждённый пакет' % (len(data), block))
    n = data[-1]
    if not 1 <= n <= block or n > len(data):
        raise PaddingError('некорректное дополнение (байт %d) — вероятно, '
                           'неверный пароль или данные повреждены' % n)
    if data[-n:] != bytes([n]) * n:
        raise PaddingError('дополнение неконсистентно — вероятно, неверный '
                           'пароль или данные повреждены')
    return data[:-n]
