# -*- coding: utf-8 -*-
"""
Каркас Лай–Мэсси: encrypt/decrypt одиночного блока и скелетная трасса.
§9 спецификации.
"""

from .rounds import F, H, Hinv
from .schedule import key_schedule


def hamming(a, b):
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))



def _x(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(spec, K, P, km=None):
    """Encrypt(K, P) → C: забеливание → H₀ → 5×(T=F(L⊕R); L⊕=T; R⊕=T; H) → забеливание."""
    if len(K) != spec.ks_bytes or len(P) != spec.block_bytes:
        raise ValueError('ожидаются K=%d байт и P=%d байт' % (spec.ks_bytes, spec.block_bytes))
    if km is None:
        km = key_schedule(spec, K)
    n = spec.n
    L, R = _x(P[:n], km.WL), _x(P[n:], km.WR)
    L, R = H(L, R, km.ht[0])
    for i in range(spec.rounds):
        T = F(_x(L, R), km.ft[i])
        L, R = H(_x(L, T), _x(R, T), km.ht[i + 1])
    return _x(L, km.WpL) + _x(R, km.WpR)


def decrypt(spec, K, C, km=None):
    """Decrypt(K, C) → P: та же F, обратный порядок. Обратимость без F⁻¹:
    после H⁻¹ разность (L⊕T)⊕(R⊕T) = L⊕R восстанавливает T одним пересчётом."""
    if len(K) != spec.ks_bytes or len(C) != spec.block_bytes:
        raise ValueError('ожидаются K=%d байт и C=%d байт' % (spec.ks_bytes, spec.block_bytes))
    if km is None:
        km = key_schedule(spec, K)
    n = spec.n
    L, R = _x(C[:n], km.WpL), _x(C[n:], km.WpR)
    L, R = Hinv(L, R, km.ht[spec.rounds])
    for i in range(spec.rounds - 1, -1, -1):
        T = F(_x(L, R), km.ft[i])
        L, R = Hinv(_x(L, T), _x(R, T), km.ht[i])
    return _x(L, km.WL) + _x(R, km.WR)


def encrypt_trace(spec, K, P):
    """Скелетная трасса каркаса: шаг → (L, R) → примечание."""
    km = key_schedule(spec, K)
    n = spec.n
    steps = [('Открытый текст', P[:n].hex().upper(), P[n:].hex().upper(), '')]
    L, R = _x(P[:n], km.WL), _x(P[n:], km.WR)
    steps.append(('Забеливание (вход)', L.hex().upper(), R.hex().upper(), ''))
    L, R = H(L, R, km.ht[0])
    steps.append(('Пол-раунд H0', L.hex().upper(), R.hex().upper(), ''))
    for i in range(spec.rounds):
        d = _x(L, R)
        steps.append(('Раунд %d: Δ = L⊕R' % (i + 1), d.hex().upper(), '—', 'вход F'))
        T = F(d, km.ft[i])
        steps.append(('  F → T', T.hex().upper(), '—', 'необратимо'))
        L, R = _x(L, T), _x(R, T)
        steps.append(('  L⊕T, R⊕T', L.hex().upper(), R.hex().upper(), 'Δ не изменилась'))
        L, R = H(L, R, km.ht[i + 1])
        steps.append(('Пол-раунд H%d' % (i + 1), L.hex().upper(), R.hex().upper(), ''))
    L, R = _x(L, km.WpL), _x(R, km.WpR)
    steps.append(('Забеливание (выход)', L.hex().upper(), R.hex().upper(), ''))
    return steps, L + R, km
