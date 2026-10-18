# -*- coding: utf-8 -*-
"""Движок высокого уровня: настройки → результат, предупреждения, ошибки."""

import pytest

from kazual import engine
from kazual.engine import Settings, encrypt, decrypt
from kazual.keys import PasswordKey, RawKey, parse_raw_key_hex, KeyMaterialError
from kazual.modes.siv import MacError, SivOptions

from conftest import FAST_KDF, SAMPLE_BYTES


def st(**kw):
    base = dict(cipher='Kazual-64', mode='siv', source=RawKey(b'\x01' * 8),
                kdf_params=FAST_KDF, siv=SivOptions(kdf_params=FAST_KDF))
    base.update(kw)
    return Settings(**base)


def test_siv_roundtrip_with_warnings():
    r = encrypt(st(), SAMPLE_BYTES)
    assert r.mode == 'siv' and r.cipher == 'Kazual-64'
    assert any('учебный' in w for w in r.warnings)
    d = decrypt(st(), r.data)
    assert d.data == SAMPLE_BYTES
    assert d.meta['verified'] is True


def test_ecb_roundtrip_and_warning():
    s = st(mode='ecb')
    r = encrypt(s, SAMPLE_BYTES)
    assert any('ECB' in w for w in r.warnings)
    d = decrypt(s, r.data)
    assert d.data == SAMPLE_BYTES
    assert d.meta['verified'] is None


def test_warnings_for_disabled_fields():
    s = st(siv=SivOptions(kdf_params=FAST_KDF, random_enabled=False,
                          params_enabled=False, prefix_enabled=False))
    r = encrypt(s, SAMPLE_BYTES)
    text = ' '.join(r.warnings)
    assert 'детерминировано' in text
    assert 'params не сохраняются' in text
    assert 'prefix отключён' in text


def test_empty_password_rejected():
    with pytest.raises(engine.KazualError):
        encrypt(st(source=PasswordKey('')), b'x')
    with pytest.raises(engine.KazualError):
        Settings(cipher='нет-такого', mode='siv',
                 source=RawKey(b'\x00')).validate()


def test_wrong_mode_password_tamper():
    r = encrypt(st(source=PasswordKey('pw')), SAMPLE_BYTES)
    with pytest.raises(MacError):
        decrypt(st(source=PasswordKey('pw2')), r.data)


def test_raw_key_hex_parser():
    assert parse_raw_key_hex('de ad:be ef') == bytes.fromhex('deadbeef')
    for bad in ('', 'zzz', 'abc', '1 2 3'):
        with pytest.raises(KeyMaterialError):
            parse_raw_key_hex(bad)


def test_progress_callback_called():
    seen = []

    def cb(stage, frac=None):
        seen.append((stage, frac))

    encrypt(st(), b'\x00' * 200_000, progress=cb)
    assert seen and any(f is not None for _, f in seen)


def test_unknown_cipher_or_mode():
    with pytest.raises(engine.KazualError):
        encrypt(st(cipher='AES-256'), b'x')
    with pytest.raises(engine.KazualError):
        encrypt(st(mode='gcm'), b'x')
