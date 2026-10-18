# -*- coding: utf-8 -*-
"""Тестовые векторы из спецификации (§14): побитовое совпадение с эталоном."""

import pytest

from kazual.cipher import FULL, K64, encrypt, decrypt, key_schedule
from kazual.cipher.vectors import VECTORS, EXPECTED_C, K64_VECTORS


@pytest.mark.parametrize('idx,expected', list(enumerate(EXPECTED_C)))
def test_kazual512_vectors(idx, expected):
    i, kh, ph = VECTORS[idx]
    K, P = bytes.fromhex(kh), bytes.fromhex(ph)
    km = key_schedule(FULL, K)
    C = encrypt(FULL, K, P, km)
    assert C.hex() == expected, 'вектор #%d: шифротекст не совпал' % i
    assert decrypt(FULL, K, C, km) == P, 'вектор #%d: обратный ход' % i


@pytest.mark.parametrize('ph,ch', K64_VECTORS)
def test_kazual64_vectors(ph, ch):
    K = bytes.fromhex('0001020304050607')
    km = key_schedule(K64, K)
    assert encrypt(K64, K, bytes.fromhex(ph), km).hex().upper() == ch
    assert decrypt(K64, K, bytes.fromhex(ch), km) == bytes.fromhex(ph)


def test_wrong_key_lengths_rejected():
    with pytest.raises(ValueError):
        encrypt(FULL, b'short', b'\x00' * 64)
    with pytest.raises(ValueError):
        decrypt(K64, b'\x00' * 8, b'\x00' * 7)
