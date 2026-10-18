# -*- coding: utf-8 -*-
"""
kazual.cipher — эталонная реализация блочных шифров семейства Kazual.

Модули:
    gf          поля GF(2^8)/GF(2^16), Cauchy-MDS и табличные применения
    gorn        ГОРН-1024 — собственная сжимающая функция (губка)
    sbox        статические S-box'ы ядра (Gold, Kasami, inverse)
    forge       КУЗНИЦА — равномерный разбор материала расширения
    components  Несущая (CarryWeave) и Заслонка (Shutter)
    spec        инстанции: Kazual-512 / Kazual-64 / Kazual-Micro
    rounds      раундовая функция F и пол-раунд H
    schedule    расписание ключей (GFN Type-2 + КУЗНИЦА)
    core        каркас Лай–Мэсси: encrypt/decrypt одиночного блока
    batch       пакетный путь NumPy/CuPy/multiprocessing
    vectors     тестовые векторы
    selfcheck   самопроверки, трассы и бенчмарк эталонной реализации

Экспериментальная учебная конструкция: независимого криптоанализа
не проходила. Kazual-64 НЕ предназначена для защиты данных.
"""

from .spec import Spec, FULL, K64, MICRO, SPECS, TAG
from .core import encrypt, decrypt, encrypt_trace, hamming
from .schedule import key_schedule, KeyMat
from .batch import encrypt_blocks, decrypt_blocks
from .gorn import gorn_hash, gorn_expand, gorn_perm

__all__ = [
    'Spec', 'FULL', 'K64', 'MICRO', 'SPECS', 'TAG',
    'encrypt', 'decrypt', 'encrypt_trace', 'hamming',
    'key_schedule', 'KeyMat',
    'encrypt_blocks', 'decrypt_blocks',
    'gorn_hash', 'gorn_expand', 'gorn_perm',
]
