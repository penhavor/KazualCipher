# -*- coding: utf-8 -*-
"""
MAC контейнера v2 (tree-MAC): V = корень ГОРН-дерева от K_mac, полей
заголовка и дайджестов листьев открытого текста.

ГОРН — губка с ёмкостью 512 бит, поэтому конструкция «ключ ‖ сообщение»
не подвержена удлинению (length-extension) и HMAC не требуется.
Тело канонично: каждое поле пакетируется u32-префиксом длины, порядок
фиксирован, отключённые поля входят как пустые. Домены разделяются
тегами с именем шифра и версией формата.
"""

from __future__ import annotations

import struct

from ..cipher import _accel
from ..cipher.gorn import GornHasher   # noqa: F401 (этало́н)

__all__ = ['GornMacError', 'tree_leaf_tag', 'tree_leaf_digest',
           'tree_root_hasher', 'tree_mac', 'n_leaves_for',
           'DEFAULT_LEAF_SIZE', 'TREE_ROOT_TAG', 'TREE_LEAF_TAG']

V_BYTES = 64  # тег V = дайджест ГОРН, 512 бит
DEFAULT_LEAF_SIZE = 4 << 20      # 4 МиБ — лист tree-MAC (контейнер v2)


def _frame(*chunks) -> bytes:
    """Каноническая упаковка: u32be(len) ‖ bytes для каждого поля."""
    out = []
    for c in chunks:
        out.append(struct.pack('>I', len(c)))
        out.append(bytes(c))
    return b''.join(out)


class GornMacError(ValueError):
    """Ошибка вычисления MAC (не путать с провалом проверки подлинности)."""


# ---------------------------------------------------------------------------
# Tree-MAC (контейнер v2): параллельный MAC от больших сообщений
# ---------------------------------------------------------------------------
# Одноуровневое Меркле-дерево поверх ГОРНа: листы хэшируются независимо
# (все ядра CPU / пул потоков), корень впитывает дайджесты по порядку.
# Криптостойкость: collision resistance ГОРНа (512-битные дайджесты) +
# ключ только в корне ( forgery требует подбора корневой коллизии без K_mac).

TREE_LEAF_TAG = b'KazualCipher/SIV/v2/leaf/'
TREE_ROOT_TAG = b'KazualCipher/SIV/v2/root/'


def n_leaves_for(total_len: int, leaf_size: int) -> int:
    """Число листьев tree-MAC (пустое сообщение → один пустой лист)."""
    if leaf_size < 64:
        raise GornMacError('leaf_size должен быть ≥ 64 байт')
    return max(1, (total_len + leaf_size - 1) // leaf_size)


def tree_leaf_tag(cipher_name: str, index: int, total_len: int) -> bytes:
    """Домен листа: шифр ‖ номер листа ‖ полная длина (нельзя ни переставить,
    ни обрезать, ни склеить листья разных сообщений)."""
    return (TREE_LEAF_TAG + cipher_name.encode('ascii')
            + struct.pack('>QQ', index, total_len))


def tree_leaf_digest(cipher_name: str, index: int, total_len: int,
                     leaf) -> bytes:
    """Дайджест одного листа (64 Б). release-GIL: потоки идут параллельно."""
    return _accel.gorn_hash(leaf, tree_leaf_tag(cipher_name, index,
                                                total_len))


def tree_root_hasher(k_mac: bytes, cipher_name: str, brand: bytes,
                     params_field: bytes, random_field: bytes,
                     total_len: int, leaf_size: int, n_leaves: int):
    """Корневой хэшер: каркас впитан, осталось скормить дайджесты листьев."""
    h = _accel.native_hasher(TREE_ROOT_TAG + cipher_name.encode('ascii'))
    h.update(k_mac)
    h.update(_frame(brand, params_field, random_field))
    h.update(struct.pack('>QII', total_len, leaf_size, n_leaves))
    return h


def effective_workers(threads: int = 0, cap: int = 64) -> int:
    """threads=0 → авто (сколько доступно); ≥1 → как задано."""
    if threads and threads > 0:
        return max(1, min(int(threads), cap))
    try:
        cur, _mx = _accel.threads_info()
        return max(1, min(int(cur), cap))
    except Exception:                                    # noqa: BLE001
        import os
        return max(1, min(os.cpu_count() or 1, cap))


def tree_mac(k_mac: bytes, cipher_name: str, brand: bytes,
             params_field: bytes, random_field: bytes, data,
             leaf_size: int = DEFAULT_LEAF_SIZE, threads: int = 0,
             progress_cb=None) -> bytes:
    """V (512 бит) = tree-MAC от полей контейнера и данных (в памяти).

    Листья считаются параллельно в пуле потоков (нативное ядро отпускает
    GIL); порядок дайджестов в корне строго по индексам — результат не
    зависит от числа потоков и порядка исполнения.
    """
    mv = memoryview(data)
    total = mv.nbytes
    n = n_leaves_for(total, leaf_size)
    h = tree_root_hasher(k_mac, cipher_name, brand, params_field,
                         random_field, total, leaf_size, n)
    workers = effective_workers(threads)
    if n == 1 or workers <= 1:
        for i in range(n):
            leaf = mv[i * leaf_size:(i + 1) * leaf_size]
            h.update(tree_leaf_digest(cipher_name, i, total, leaf))
            if progress_cb is not None:
                progress_cb((i + 1) / n)
        return h.digest()
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(workers, n)) as ex:
        futs = []
        for i in range(n):
            leaf = bytes(mv[i * leaf_size:(i + 1) * leaf_size])
            futs.append(ex.submit(tree_leaf_digest, cipher_name, i, total,
                                  leaf))
        for i, f in enumerate(futs):
            h.update(f.result())
            if progress_cb is not None:
                progress_cb((i + 1) / n)
    return h.digest()
