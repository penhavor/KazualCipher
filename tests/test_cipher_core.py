# -*- coding: utf-8 -*-
"""Ядро шифра и ГОРН: обратимость, инкрементальный хэш, CTR-примитивы."""

import os

import pytest

from kazual.cipher import FULL, K64, encrypt, decrypt, key_schedule
from kazual.cipher.gorn import gorn_hash, gorn_perm, gorn_perm_inv, GornHasher
from kazual.modes.ctr import ctr_iv, counter_bytes_for_block, CtrError
from kazual.modes.padding import pkcs7_pad, pkcs7_unpad, PaddingError


@pytest.mark.parametrize('spec', [FULL, K64], ids=['K512', 'K64'])
def test_roundtrip_random(spec, rnd):
    K = os.urandom(spec.ks_bytes)
    km = key_schedule(spec, K)
    for _ in range(3):
        P = os.urandom(spec.block_bytes)
        C = encrypt(spec, K, P, km)
        assert C != P
        assert decrypt(spec, K, C, km) == P


def test_gorn_perm_bijective():
    for _ in range(3):
        s = os.urandom(128)
        assert gorn_perm_inv(gorn_perm(s)) == s


def test_gorn_hasher_equals_oneshot(rnd):
    """Инкрементальный ГОРН побитово равен gorn_hash при любом дроблении."""
    for _ in range(6):
        msg = os.urandom(rnd.randrange(0, 400))
        tag = os.urandom(rnd.randrange(0, 24))
        h = GornHasher(tag)
        pos = 0
        while pos < len(msg):
            step = rnd.randrange(1, 97)
            h.update(msg[pos:pos + step])
            pos += step
        assert h.digest() == gorn_hash(msg, tag)
        assert h.digest() == gorn_hash(msg, tag)     # digest идемпотентен


def test_gorn_hash_tag_domain():
    assert gorn_hash(b'abc', b'one') != gorn_hash(b'abc', b'two')
    with pytest.raises(ValueError):
        gorn_hash(b'x', b'\x1f')


def test_ctr_iv_counters(rnd):
    v = os.urandom(64)
    iv = ctr_iv(v, 64)
    assert bytes(iv[:56]) == v[:56]
    assert iv[56] & 0x80 == 0                        # старший бит зоны сброшен
    assert counter_bytes_for_block(64) == 8
    assert counter_bytes_for_block(8) == 4
    with pytest.raises(CtrError):
        ctr_iv(b'\x00' * 4, 8)


def test_pkcs7_roundtrip(rnd):
    for block in (8, 64):
        for n in (0, 1, block - 1, block, block + 5):
            data = os.urandom(n)
            padded = pkcs7_pad(data, block)
            assert len(padded) % block == 0
            assert pkcs7_unpad(padded, block) == data


def test_pkcs7_rejects_garbage():
    with pytest.raises(PaddingError):
        pkcs7_unpad(b'\x00' * 63 + b'\xff', 64)      # дополнение больше блока
    with pytest.raises(PaddingError):
        pkcs7_unpad(b'\x01' * 63 + b'\x02', 64)      # неконсистентно
    with pytest.raises(PaddingError):
        pkcs7_unpad(b'\x01' * 63, 64)                # не кратно блоку
    with pytest.raises(PaddingError):
        pkcs7_unpad(b'', 64)
