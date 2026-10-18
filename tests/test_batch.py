# -*- coding: utf-8 -*-
"""Пакетный путь (NumPy) побитово равен скалярному."""

import os

import pytest

from kazual.cipher import FULL, K64
from kazual.cipher.batch import _np, encrypt_blocks, decrypt_blocks
from kazual.cipher.core import encrypt, decrypt
from kazual.cipher.schedule import key_schedule

pytestmark = pytest.mark.skipif(_np is None, reason='NumPy не установлен')


@pytest.mark.parametrize('spec,nblocks', [(FULL, 37), (K64, 129)],
                         ids=['K512', 'K64'])
def test_batch_equals_scalar(spec, nblocks):
    K = os.urandom(spec.ks_bytes)
    km = key_schedule(spec, K)
    data = os.urandom(spec.block_bytes * nblocks)
    c_batch = encrypt_blocks(spec, K, data, backend='cpu', km=km)
    c_scal = b''.join(encrypt(spec, K, data[i:i + spec.block_bytes], km)
                      for i in range(0, len(data), spec.block_bytes))
    assert c_batch == c_scal
    assert decrypt_blocks(spec, K, c_batch, backend='cpu', km=km) == data


def test_batch_rejects_unaligned():
    with pytest.raises(ValueError):
        encrypt_blocks(FULL, os.urandom(64), b'\x00' * 65)


def test_scalar_path_explicit():
    K = os.urandom(64)
    km = key_schedule(FULL, K)
    data = os.urandom(64 * 5)
    assert encrypt_blocks(FULL, K, data, backend='scalar', km=km) == \
        encrypt_blocks(FULL, K, data, backend='cpu', km=km)
