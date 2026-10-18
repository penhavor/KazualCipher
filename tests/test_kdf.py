# -*- coding: utf-8 -*-
"""KDF: PHC-строки, границы Argon2, детерминированность вывода ключей."""

import pytest

from kazual.kdf import (KdfParams, KdfParamsError, derive_key,
                        DEFAULT_KDF_PARAMS)


def test_phc_roundtrip():
    p = KdfParams(65536, 3, 4)
    s = p.phc_string()
    assert s == '$argon2id$v=19$m=65536,t=3,p=4'
    assert KdfParams.parse(s) == p
    assert KdfParams.parse(s.encode('ascii')) == p


def test_phc_parse_errors():
    for bad in ('', '$argon2i$v=19$m=64,t=1,p=1', '$argon2id$m=64,t=1,p=1',
                '$argon2id$v=19$m=64,t=0,p=1', 'm=64,t=1,p=1',
                '$argon2id$v=19$m=64,t=1,p=1,x=2'):
        with pytest.raises(KdfParamsError):
            KdfParams.parse(bad)


def test_argon2_boundaries():
    with pytest.raises(KdfParamsError):
        KdfParams(memory_kib=8, parallelism=4).validate()      # m < 8·p
    with pytest.raises(KdfParamsError):
        KdfParams(iterations=0).validate()
    with pytest.raises(KdfParamsError):
        KdfParams(parallelism=0).validate()
    with pytest.raises(KdfParamsError):
        KdfParams(version=13).validate()
    KdfParams(memory_kib=32, parallelism=4).validate()         # m = 8·p — ок


def test_derive_key_deterministic_and_sensitive():
    salt = b'\x01' * 32
    a = derive_key('пароль', salt, KdfParams(64, 1, 1), 96)
    b = derive_key('пароль', salt, KdfParams(64, 1, 1), 96)
    c = derive_key('пароль2', salt, KdfParams(64, 1, 1), 96)
    d = derive_key('пароль', b'\x02' * 32,
                   KdfParams(64, 1, 1), 96)
    assert a == b and len(a) == 96
    assert a != c and a != d


def test_derive_key_rejects_empty_password():
    with pytest.raises(KdfParamsError):
        derive_key('', b'\x00' * 32, KdfParams(64, 1, 1), 32)


def test_describe():
    assert '64 МиБ' in KdfParams(65536, 3, 4).describe()
    assert '64 КиБ' in KdfParams(64, 1, 1).describe()
