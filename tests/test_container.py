# -*- coding: utf-8 -*-
"""Контейнер v2: сборка/разбор заголовка, стойкость к порче."""

import struct

import pytest

from kazual.modes import container as ct
from kazual.modes.siv import PacketFormatError


def _hdr(**kw):
    phc = b'$argon2id$v=19$m=1024,t=1,p=1'
    base = dict(cipher_name='Kazual-512', mode=ct.MODE_SIV, brand=b'brand/v3',
                params_field=struct.pack('>H', len(phc)) + phc,
                random_field=b'\x11' * 32, leaf_size=4 << 20, total_len=12345,
                v=b'\x22' * 64)
    base.update(kw)
    return ct.build_header(**base)


def test_roundtrip():
    h = _hdr()
    info = ct.parse_header(h)
    assert info.cipher_name == 'Kazual-512'
    assert info.mode == ct.MODE_SIV
    assert info.brand == b'brand/v3'
    assert info.kdf_params.memory_kib == 1024
    assert info.random_field == b'\x11' * 32
    assert info.leaf_size == 4 << 20
    assert info.total_len == 12345
    assert info.v == b'\x22' * 64
    assert info.payload_offset == len(h)
    assert ct.is_container(h)


def test_ecb_header():
    h = ct.build_header('Kazual-64', ct.MODE_ECB, brand=b'', params_field=b'',
                        random_field=b'', total_len=80)
    info = ct.parse_header(h)
    assert info.mode == ct.MODE_ECB and info.cipher_name == 'Kazual-64'
    assert info.v == b'' and info.leaf_size == 0


def test_no_optional_fields():
    h = _hdr(brand=b'', params_field=b'', random_field=b'')
    info = ct.parse_header(h)
    assert info.brand == b'' and info.params_field == b'' \
        and info.random_field == b''
    assert not info.params_enabled and not info.random_enabled


@pytest.mark.parametrize('cut', [5, 8, 10, 40, 60, 100, len(_hdr()) - 1])
def test_truncated_rejected(cut):
    h = _hdr()[:cut]
    with pytest.raises(PacketFormatError):
        ct.parse_header(h)


def test_bad_magic_and_version():
    h = bytearray(_hdr())
    h[0] ^= 0xFF
    with pytest.raises(PacketFormatError):
        ct.parse_header(bytes(h))
    h = bytearray(_hdr())
    h[4] = 9
    with pytest.raises(PacketFormatError):
        ct.parse_header(bytes(h))


def test_unknown_cipher_id():
    h = bytearray(_hdr())
    h[5] = 77
    with pytest.raises(PacketFormatError):
        ct.parse_header(bytes(h))


def test_brand_too_long():
    with pytest.raises(PacketFormatError):
        ct.build_header('Kazual-512', ct.MODE_SIV, brand=b'x' * 256,
                        total_len=1, leaf_size=64, v=b'\x00' * 64)


def test_describe_has_cipher_and_mode():
    info = ct.parse_header(_hdr())
    d = info.describe()
    assert 'Kazual-512' in d and 'SIV' in d
