# -*- coding: utf-8 -*-
"""Нативный путь (numba) побитово равен эталонному и не зависит от потоков."""

import os
import random
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from kazual.cipher import native
from kazual.cipher.spec import FULL, K64
from kazual.cipher.schedule import key_schedule
from kazual.cipher.core import encrypt, decrypt
from kazual.cipher.gorn import gorn_hash, gorn_expand, GornHasher

pytestmark = pytest.mark.skipif(not native.NUMBA_AVAILABLE,
                                reason='numba не установлена')


@pytest.fixture(scope='module')
def ctx():
    native.warmup()
    km = key_schedule(FULL, os.urandom(64))
    return native.cipher_for(FULL, km)


@pytest.mark.parametrize('n', [0, 1, 55, 64, 100, 4096, 70001])
def test_gorn_hash_identical(n):
    msg = os.urandom(n)
    assert native.gorn_hash_native(msg, b'tag/%d' % n) == gorn_hash(msg,
                                                                   b'tag/%d' % n)


def test_gorn_expand_identical():
    seed = os.urandom(37)
    assert native.gorn_expand_native(seed, b'kdf', 300) == \
        gorn_expand(seed, b'kdf', 300)


def test_native_hasher_identical():
    h1, h2 = GornHasher(b'dom'), native.NativeGornHasher(b'dom')
    data = os.urandom(300000)
    for i in range(0, len(data), 7777):
        h1.update(data[i:i + 7777])
        h2.update(data[i:i + 7777])
    assert h1.digest() == h2.digest() == gorn_hash(data, b'dom')


def test_blocks_identical(ctx):
    rnd = random.Random(11)
    data = os.urandom(64 * rnd.choice([1, 17, 512]))
    K = os.urandom(64)
    km = key_schedule(FULL, K)
    c = native.cipher_for(FULL, km)
    ref = b''.join(encrypt(FULL, K, data[i:i + 64], km)
                   for i in range(0, len(data), 64))
    got = c.encrypt_blocks(data)
    assert got == ref
    assert c.decrypt_blocks(got) == data


def test_ctr_identical(ctx):
    from kazual.modes.ctr import ctr_xor, ctr_iv
    K = os.urandom(64)
    km = key_schedule(FULL, K)
    c = native.cipher_for(FULL, km)
    v = os.urandom(64)
    msg = os.urandom(64 * 33 + 21)
    ref = ctr_xor(FULL, K, msg, v, km=km, backend='scalar')
    iv = ctr_iv(v, 64)
    got = c.ctr_xor(msg, bytes(iv),
                    int.from_bytes(iv[56:64], 'big')).tobytes()
    assert got == ref


def test_k64_has_no_native_ctx():
    km = key_schedule(K64, os.urandom(8))
    assert native.cipher_for(K64, km) is None


def test_tree_mac_thread_invariant():
    from kazual.modes.mac import tree_mac
    k = os.urandom(64)
    data = os.urandom(5 * 1024 * 1024 + 123)
    a = tree_mac(k, 'Kazual-512', b'br', b'pf', b'rf', data, 1 << 20,
                 threads=1)
    b = tree_mac(k, 'Kazual-512', b'br', b'pf', b'rf', data, 1 << 20,
                 threads=4)
    assert a == b and len(a) == 64


def test_native_threads_concurrent_safe(ctx):
    """Несколько потоков одновременно пользуют nogil-ядра (tree-MAC)."""
    leaves = [bytearray(os.urandom(1 << 20)) for _ in range(6)]
    seq = [native.gorn_hash_native(bytes(l), b'x') for l in leaves]
    with ThreadPoolExecutor(4) as ex:
        par = list(ex.map(lambda l: native.gorn_hash_native(bytes(l), b'x'),
                          leaves))
    assert seq == par
