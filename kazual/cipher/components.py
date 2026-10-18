# -*- coding: utf-8 -*-
"""
Несущая (CarryWeave) — обратимый ARX-микшер независимых пар слов, и
Заслонка (Shutter) — FL/FL⁻¹ с ключевым поворотом. §5 спецификации.
"""

# Несущая: ARX-микшер, W/2 независимых пар на фазу (SIMD-дорожки).
# Заслонка: FL/FL⁻¹ с ключевым поворотом; треугольна ⇒ биективна при любом ключе.

def rotl(x, k, w):
    k %= w
    m = (1 << w) - 1
    return ((x << k) | (x >> (w - k))) & m if k else x


def rotr(x, k, w):
    return rotl(x, (-k) % w, w)


def pair_list(W, t):
    """Пары фазы t: чётные — соседние (0,1),(2,3),…; нечётные — перекрёстные
    (0,W−1),(2,1),(4,3),… Пары в фазе не пересекаются ⇒ независимы."""
    if W < 2:
        return []
    if W == 2 or t % 2 == 0:
        return [(2 * k, 2 * k + 1) for k in range(W // 2)]
    out = [(0, W - 1)]
    out += [(2 * k, 2 * k - 1) for k in range(1, W // 2)]
    return out


class WeavePar:
    __slots__ = ('T', 'sub')

    def __init__(self, T, sub):
        self.T = T              # число фаз
        self.sub = sub          # sub[t] = [(j, k, alpha, m, c), …]


def carryweave(w, par, wb):
    """w — список из W слов ширины wb. Подшаг треуголен: w[j] первым использует
    СТАРОЕ w[k]; w[k] — новое w[j]. Обратимость без обращения умножения."""
    mask = (1 << wb) - 1
    for t in range(par.T):
        for (j, k, alpha, m, c) in par.sub[t]:
            x = (rotl(w[j], alpha, wb) + ((w[k] * m) & mask)) & mask
            w[j] = x
            w[k] = (w[k] ^ x ^ c) & mask
    return w


def carryweave_inv(w, par, wb):
    mask = (1 << wb) - 1
    for t in range(par.T - 1, -1, -1):
        for (j, k, alpha, m, c) in par.sub[t]:
            kold = (w[k] ^ w[j] ^ c) & mask
            w[j] = rotr((w[j] - ((kold * m) & mask)) & mask, alpha, wb)
            w[k] = kold
    return w


def _fl(y, k1, k2, s):
    y1 = y >> 16
    y2 = y & 0xFFFF
    y1 ^= rotl(y2 & k1, s, 32)
    y2 ^= (y1 | k2) & 0xFFFF
    return ((y1 << 16) | y2) & 0xFFFFFFFF


def _fl_inv(y, k1, k2, s):
    y1 = y >> 16
    y2 = y & 0xFFFF
    y2 ^= (y1 | k2) & 0xFFFF
    y1 ^= rotl(y2 & k1, s, 32)
    return ((y1 << 16) | y2) & 0xFFFFFFFF


class ShutterPar:
    __slots__ = ('k1', 'k2', 's')

    def __init__(self, k1, k2, s):
        self.k1, self.k2, self.s = k1, k2, s


def shutter(words, par):
    """Чётные позиции — FL, нечётные — FL⁻¹ (никакой симметрии между половинами)."""
    k1, k2, s = par.k1, par.k2, par.s
    for j in range(len(words)):
        words[j] = _fl(words[j], k1[j], k2[j], s[j]) if j % 2 == 0 \
            else _fl_inv(words[j], k1[j], k2[j], s[j])
    return words


def shutter_inv(words, par):
    k1, k2, s = par.k1, par.k2, par.s
    for j in range(len(words)):
        words[j] = _fl_inv(words[j], k1[j], k2[j], s[j]) if j % 2 == 0 \
            else _fl(words[j], k1[j], k2[j], s[j])
    return words
