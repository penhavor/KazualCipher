# -*- coding: utf-8 -*-
"""SIV-пакет: все комбинации галочек, тамперинг, детерминизм, самоописание."""

import itertools
import os

import pytest

from kazual.cipher import FULL, K64
from kazual.engine import Settings
from kazual.keys import PasswordKey, RawKey
from kazual.modes import siv as sivmod
from kazual.modes.mac import siv_mac, siv_mac_streaming
from kazual.modes.siv import (MacError, PacketFormatError, MAGIC,
                              PREFIX_BYTES, RANDOM_BYTES, V_BYTES,
                              decrypt_siv, encrypt_siv, parse_packet)

from conftest import FAST_KDF, PASSWORD, RAWKEY, SAMPLE_BYTES, siv_opts

SPEC = K64          # учебный шифр — быстрее; формат пакета общий
NAME = 'Kazual-64'


def enc(opts, data=SAMPLE_BYTES, source=RAWKEY):
    return encrypt_siv(SPEC, NAME, source, data, opts)


def dec(opts, packet, source=RAWKEY):
    return decrypt_siv(SPEC, NAME, source, packet, opts)


@pytest.mark.parametrize('prefix,params,random',
                         list(itertools.product([True, False], repeat=3)))
def test_roundtrip_all_toggle_combos(prefix, params, random):
    opts = siv_opts(prefix_enabled=prefix, params_enabled=params,
                    random_enabled=random)
    res = enc(opts)
    back = dec(opts, res.data)
    assert back.data == SAMPLE_BYTES
    # состав полей соответствует галочкам
    sizes = {f.name: f.size for f in res.fields}
    assert (sizes['prefix'] == PREFIX_BYTES) == prefix
    assert (sizes['params'] > 0) == params
    assert (sizes['random'] == RANDOM_BYTES) == random
    assert sizes['V'] == V_BYTES


def test_packet_layout_concat():
    opts = siv_opts()
    res = enc(opts)
    blob = b''.join(f.data for f in res.fields)
    assert blob == res.data
    assert len(res.data) == PREFIX_BYTES + len(res.fields[1].data) \
        + RANDOM_BYTES + V_BYTES + len(SAMPLE_BYTES)
    assert res.data[:len(MAGIC)] == MAGIC


@pytest.mark.parametrize('pos', ['prefix', 'params', 'random', 'v', 'ct'])
def test_tamper_detected(pos):
    opts = siv_opts()
    res = enc(opts)
    pkt = bytearray(res.data)
    sizes = {f.name: f.size for f in res.fields}
    off = {'prefix': 0,
           'params': sizes['prefix'],
           'random': sizes['prefix'] + sizes['params'],
           'v': sizes['prefix'] + sizes['params'] + sizes['random'],
           'ct': sizes['prefix'] + sizes['params'] + sizes['random']
                 + V_BYTES}[pos]
    pkt[off] ^= 0x01
    # любое изменение обязано отвергаться: либо форматом (если задета
    # структура полей), либо MAC'ом (если задеты данные/тег)
    with pytest.raises((MacError, PacketFormatError)):
        dec(opts, bytes(pkt))


def test_wrong_password_detected():
    res = enc(siv_opts(), source=PasswordKey('верный'))
    with pytest.raises(MacError):
        dec(siv_opts(), res.data, source=PasswordKey('неверный'))


def test_determinism_without_random():
    on = siv_opts()
    off = siv_opts(random_enabled=False)
    a, b = enc(off).data, enc(off).data
    assert a == b, 'без random шифрование обязано быть детерминированным'
    c, d = enc(on).data, enc(on).data
    assert c != d, 'с random пакеты обязаны различаться'


def test_fixed_random():
    opts = siv_opts(fixed_random_hex='ab' * 32)
    a = enc(opts).data
    b = enc(opts).data
    assert a == b
    assert dec(opts, a).data == SAMPLE_BYTES
    bad = siv_opts(fixed_random_hex='ab' * 31)
    with pytest.raises(PacketFormatError):
        enc(bad)
    with pytest.raises(PacketFormatError):
        enc(siv_opts(fixed_random_hex='zz' * 32))


def test_custom_prefix_text():
    text = 'мой-бренд/v2.1'
    opts = siv_opts(prefix_text=text)
    res = enc(opts)
    raw = text.encode('utf-8')
    assert res.fields[0].data[4:4 + len(raw)] == raw
    assert dec(opts, res.data).data == SAMPLE_BYTES
    long_text = 'х' * (PREFIX_BYTES - len(MAGIC) + 1)
    with pytest.raises(PacketFormatError):
        enc(siv_opts(prefix_text=long_text))


def test_params_self_describing():
    from kazual.kdf import KdfParams
    o1 = siv_opts(kdf_params=KdfParams(64, 1, 1))
    o2 = siv_opts(kdf_params=KdfParams(128, 2, 1))     # другие в GUI
    pkt = enc(o1, source=PASSWORD).data
    # GUI-параметры иные, но пакет несёт свои — расшифровка обязана пройти
    assert dec(o2, pkt, source=PASSWORD).data == SAMPLE_BYTES
    # без params в пакете — только текущие настройки GUI
    o3 = siv_opts(params_enabled=False, kdf_params=KdfParams(64, 1, 1))
    pkt3 = enc(o3, source=PASSWORD).data
    assert dec(o3, pkt3, source=PASSWORD).data == SAMPLE_BYTES
    with pytest.raises((MacError, PacketFormatError)):
        dec(o2, pkt3, source=PASSWORD)


def test_prefix_guards():
    withp = enc(siv_opts()).data
    without = enc(siv_opts(prefix_enabled=False)).data
    with pytest.raises(PacketFormatError):
        dec(siv_opts(prefix_enabled=False), withp)     # hint: включите
    with pytest.raises(PacketFormatError):
        dec(siv_opts(), without)                        # нет магических байт
    with pytest.raises(PacketFormatError):
        dec(siv_opts(), b'\x00' * 10)                   # обрезок
    with pytest.raises(PacketFormatError):
        dec(siv_opts(), b'')


def test_empty_and_large_plaintext():
    opts = siv_opts()
    for data in (b'', os.urandom(64 * 1024)):
        assert dec(opts, enc(opts, data).data).data == data


def test_streaming_mac_equals_oneshot(rnd):
    k_mac = os.urandom(16)
    prefix, params_f, rnd_f = os.urandom(32), os.urandom(10), os.urandom(32)
    pt = os.urandom(rnd.randrange(1, 5000))
    h = siv_mac_streaming(k_mac, NAME, prefix, params_f, rnd_f, len(pt))
    pos = 0
    while pos < len(pt):
        h.update(pt[pos:pos + 997])
        pos += 997
    assert h.digest() == siv_mac(k_mac, NAME, prefix, params_f, rnd_f, pt)


def test_parse_packet_fields():
    opts = siv_opts()
    res = enc(opts)
    pk = parse_packet(res.data, opts)
    assert pk.prefix == res.fields[0].data
    assert pk.v == res.fields[3].data
    assert pk.kdf_params == FAST_KDF
    assert pk.ciphertext == res.fields[4].data


def test_kazual512_packet_roundtrip():
    from kazual.cipher import FULL as F
    opts = siv_opts()
    res = encrypt_siv(F, 'Kazual-512', RAWKEY, SAMPLE_BYTES, opts)
    back = decrypt_siv(F, 'Kazual-512', RAWKEY, res.data, opts)
    assert back.data == SAMPLE_BYTES
