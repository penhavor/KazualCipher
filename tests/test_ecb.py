# -*- coding: utf-8 -*-
"""ECB: раундтрип, дополнение, документированное свойство одинаковых блоков."""

import os

import pytest

from kazual.cipher import FULL, K64
from kazual.modes.ecb import decrypt_ecb, encrypt_ecb
from kazual.modes.padding import PaddingError
from kazual.modes.siv import PacketFormatError  # noqa: F401 (смежный импорт)

from conftest import SAMPLE_BYTES


@pytest.mark.parametrize('spec', [K64, FULL], ids=['K64', 'K512'])
def test_ecb_roundtrip(spec):
    K = os.urandom(spec.ks_bytes)
    res = encrypt_ecb(spec, spec.name, K, SAMPLE_BYTES)
    assert len(res.data) % spec.block_bytes == 0
    back = decrypt_ecb(spec, spec.name, K, res.data)
    assert back.data == SAMPLE_BYTES


def test_ecb_wrong_key_padding_error():
    K = os.urandom(8)
    res = encrypt_ecb(K64, 'Kazual-64', K, SAMPLE_BYTES)
    with pytest.raises(PaddingError):
        decrypt_ecb(K64, 'Kazual-64', os.urandom(8), res.data)


def test_ecb_unaligned_rejected():
    K = os.urandom(8)
    with pytest.raises(PaddingError):
        decrypt_ecb(K64, 'Kazual-64', K, b'\x00' * 9)


def test_ecb_equal_blocks_property():
    """Документированное свойство ECB: равные открытые блоки → равные шифро."""
    K = os.urandom(8)
    block = os.urandom(8)
    res = encrypt_ecb(K64, 'Kazual-64', K, block * 4)
    ct = res.data
    assert ct[:8] == ct[8:16] == ct[16:24] == ct[24:32]


def test_ecb_empty_message_is_one_block():
    K = os.urandom(64)
    res = encrypt_ecb(FULL, 'Kazual-512', K, b'')
    assert len(res.data) == 64
    assert decrypt_ecb(FULL, 'Kazual-512', K, res.data).data == b''
