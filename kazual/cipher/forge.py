# -*- coding: utf-8 -*-
"""
КУЗНИЦА (Forge) — детерминированный разбор материала расширения ГОРНа:
равномерные примитивы (отбраковка нуля, нечётные множители), код Лемера для
перестановок и мультимножеств. §4 спецификации.
"""

from math import factorial

# Генератор динамических таблиц из раундового сида. Распределение ровно
# равномерное: код Лемера (смещение ≤ 2⁻⁹⁶), отбраковка (0), x|1 (0).

def odd_any(x):
    """x|1: ровно равномерно по нечётным (каждое нечётное достигается двумя входами)."""
    return x | 1


class Reader:
    """Последовательный разбор материала КУЗНИЦЫ (порядок строгий)."""
    __slots__ = ('b', 'p')

    def __init__(self, data):
        self.b = data
        self.p = 0

    def _need(self, n):
        if self.p + n > len(self.b):
            raise ValueError('КУЗНИЦА: исчерпан материал (нужно %d, осталось %d)'
                             % (n, len(self.b) - self.p))

    def take(self, n):
        self._need(n)
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    def byte(self):
        self._need(1)
        v = self.b[self.p]
        self.p += 1
        return v

    def u16(self):
        return int.from_bytes(self.take(2), 'big')

    def u32(self):
        return int.from_bytes(self.take(4), 'big')

    def unit8(self):
        """Отбраковка нуля: ровно равномерно на GF(2^8)*; ожид. 256/255 чтения."""
        while True:
            x = self.byte()
            if x:
                return x

    def unit16(self):
        """Отбраковка {0,1}: ровно равномерно на GF(2^16)\\{0,1}."""
        while True:
            x = self.u16()
            if x > 1:
                return x

    def odd(self, nbytes):
        """Нечётный множитель mod 2^(8·nbytes) (ровно равномерен)."""
        return odd_any(int.from_bytes(self.take(nbytes), 'big'))


_FACT = [1]
for _i in range(1, 129):
    _FACT.append(_FACT[-1] * _i)
del _i


def perm_seed_bytes(n):
    """Байт на перестановку n элементов: ⌈(log₂ n! + 96)/8⌉ — запас ≥ 96 бит."""
    return (_FACT[n].bit_length() + 96 + 7) // 8


def perm_from_int(v, n):
    """Код Лемера: перестановка n элементов из целого v (смещение ≤ 2⁻⁹⁶)."""
    v %= _FACT[n]
    items = list(range(n))
    out = []
    for k in range(n, 0, -1):
        f = _FACT[k - 1]
        idx = v // f
        v -= idx * f
        out.append(items.pop(idx))
    return out


def multiset_count(pattern):
    cnt = {}
    for x in pattern:
        cnt[x] = cnt.get(x, 0) + 1
    total = factorial(len(pattern))
    for k in cnt.values():
        total //= factorial(k)
    return total


def multiset_seed_bytes(pattern):
    return (multiset_count(pattern).bit_length() + 96 + 7) // 8


def _prod_fact(cc, skip):
    r = 1
    for x, k in cc.items():
        if x != skip:
            r *= factorial(k)
    return r


def multiset_from_int(v, pattern):
    """Перестановка МУЛЬТИМНОЖЕСТВА (назначения S-box'ов 11/11/10) кодом Лемера."""
    total = multiset_count(pattern)
    v %= total
    items = list(pattern)
    out = []
    for k in range(len(pattern), 0, -1):
        cc = {}
        for x in items:
            cc[x] = cc.get(x, 0) + 1
        f = _FACT[k - 1]
        for x in sorted(cc):
            block = f // (_FACT[cc[x] - 1] * _prod_fact(cc, x))
            if v < block:
                out.append(x)
                items.remove(x)
                break
            v -= block
    return out


def read_perm(rd, n):
    return perm_from_int(int.from_bytes(rd.take(perm_seed_bytes(n)), 'big'), n)
