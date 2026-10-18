# -*- coding: utf-8 -*-
"""
Инстанции шифра: Kazual-512 (рабочий), Kazual-64 (учебный), Kazual-Micro
(измерительный). §6 спецификации.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Spec:
    name: str
    n: int            # байт в половине блока
    rounds: int       # вызовов F
    layers: int       # тактов внутри F
    wb_h: int         # бит в слове Несущей (H)
    wb_f: int         # бит в слове Несущей (Предтакт F)
    T_h: int          # фаз Несущей в H
    T_f: int          # фаз Несущей в Предтакте
    cw_k: int         # ветвей GFN расписания
    cw_r: int         # раундов расписания
    ks_bytes: int     # байт в регистре расписания

    @property
    def block_bytes(self):  return 2 * self.n
    @property
    def chunks(self):       return self.n // 2
    @property
    def fan(self):          return 2 * self.n
    @property
    def Wh(self):           return (2 * self.n * 8) // self.wb_h
    @property
    def Wf(self):           return (self.n * 8) // self.wb_f
    @property
    def nw32(self):         return max(1, self.n // 4)
    @property
    def pattern(self):      return [i % 3 for i in range(self.n)]
    @property
    def unit(self):         return self.ks_bytes


FULL = Spec('Kazual-512', n=32, rounds=5, layers=3, wb_h=64, wb_f=64,
            T_h=4, T_f=4, cw_k=8, cw_r=32, ks_bytes=64)
# Kazual-64 — учебная масштабная копия Kazual-512: число слов и фаз Несущей
# сохранено (4×4 в Предтакте F, 8×4 в H), поэтому чередование спариваний фаз
# работает как в полной версии; ветвь расписания 4 байта — внутренняя MDS 4×4
# полноценна, φ ветви — равномерный код мультимножества.
K64 = Spec('Kazual-64', n=4, rounds=2, layers=3, wb_h=8, wb_f=8,
           T_h=4, T_f=4, cw_k=2, cw_r=16, ks_bytes=8)
MICRO = Spec('Kazual-Micro', n=2, rounds=1, layers=3, wb_h=16, wb_f=16,
             T_h=2, T_f=2, cw_k=2, cw_r=8, ks_bytes=8)
SPECS = {s.name: s for s in (FULL, K64, MICRO)}

TAG = b'Kazual-512'


def to_words(b, wb):
    k = wb // 8
    return [int.from_bytes(b[i * k:i * k + k], 'big') for i in range(len(b) // k)]


def from_words(w, wb):
    k = wb // 8
    return b''.join(v.to_bytes(k, 'big') for v in w)
