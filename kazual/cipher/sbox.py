# -*- coding: utf-8 -*-
"""
Статические S-box'ы ядра: Gold x^3 (APN), Kasami x^57 (APN), inverse x^254.
Аффинные константы — из ГОРН(""; "Kazual-512/SBOX-AFFINE/0").
Измерительные функции (δ, NL, степень, образ) — полный перебор. §3 спецификации.
"""

from .gf import MUL8T, MUL8, inv8
from .gorn import gorn_hash

# Три семейства 8×8: Gold x³ (APN), Kasami x^57 (APN), inverse x^254.
# δ, NL, степень и образ измеряются полным перебором (самопроверка).

_AFF = gorn_hash(b'', b'Kazual-512/SBOX-AFFINE/0')


def _reject_nz(data, i):
    """Отбраковка нуля: ровно равномерное распределение на GF(2^8)*."""
    while i < len(data) and data[i] == 0:
        i += 1
    if i >= len(data):
        raise ValueError('исчерпан материал при отбраковке нуля')
    return data[i], i + 1


_i = 0
SA1, _i = _reject_nz(_AFF, _i); SC1 = _AFF[_i]; _i += 1
SA2, _i = _reject_nz(_AFF, _i); SC2 = _AFF[_i]; _i += 1
SA3, _i = _reject_nz(_AFF, _i); SC3 = _AFF[_i]; _i += 1
del _i


def _pow8(a, e):
    r = 1
    for bit in range(e.bit_length() - 1, -1, -1):
        r = MUL8(r, r)
        if (e >> bit) & 1:
            r = MUL8(r, a)
    return r


S1 = bytes(MUL8T[SA1][_pow8(x, 3)] ^ SC1 for x in range(256))   # Gold   x³,  APN, δ=2
S2 = bytes(MUL8T[SA2][_pow8(x, 57)] ^ SC2 for x in range(256))  # Kasami x⁵⁷, APN, δ=2
S3 = bytes(MUL8T[SA3][inv8(x)] ^ SC3 for x in range(256))       # inverse x²⁵⁴, δ=4
SBOXES = (S1, S2, S3)


# ---- измерительные функции (полный перебор; используются самопроверкой) ----
def ddt_delta(S):
    """Дифференциальная равномерность: max по a≠0,b числа решений S(x)⊕S(x⊕a)=b."""
    d = 0
    for a in range(1, 256):
        cnt = [0] * 256
        for x in range(256):
            cnt[S[x] ^ S[x ^ a]] += 1
        m = max(cnt)
        if m > d:
            d = m
    return d


TR = [bin(MUL8(b, x)).count('1') & 1 for b in range(256) for x in range(256)]


def _fwht(v):
    n = len(v)
    h = 1
    while h < n:
        for i in range(0, n, h * 2):
            for j in range(i, i + h):
                a, b = v[j], v[j + h]
                v[j] = a + b
                v[j + h] = a - b
        h *= 2
    return v


def walsh_nl(S):
    """NL(S) = 2^(n-1) − max|W(a,b)|/2 по всем b≠0 и a."""
    mx = 0
    for b in range(1, 256):
        base = TR[b * 256:b * 256 + 256]
        w = _fwht([1 - 2 * base[S[x]] for x in range(256)])
        m = max(abs(v) for v in w)
        if m > mx:
            mx = m
    return (256 - mx) // 2, mx


def _mobius_deg(bits):
    t = list(bits)
    for b in range(8):
        step = 1 << b
        for i in range(256):
            if i & step:
                t[i] ^= t[i ^ step]
    d = 0
    for i in range(256):
        if t[i]:
            w = bin(i).count('1')
            if w > d:
                d = w
    return d


def anf_degree(S):
    return max(_mobius_deg([TR[b * 256:b * 256 + 256][S[x]] for x in range(256)])
               for b in range(1, 256))


def properties(S):
    nl, mx = walsh_nl(S)
    return dict(delta=ddt_delta(S), nl=nl, walsh=mx, deg=anf_degree(S),
                img=len(set(S)), perm=len(set(S)) == 256)
