# -*- coding: utf-8 -*-
"""Потоковая обработка файлов: раундтрипы, отмена, атомарность, пакет."""

import os
import threading

import pytest

from kazual import engine, stream
from kazual.engine import Settings
from kazual.kdf import KdfParams
from kazual.keys import PasswordKey
from kazual.modes.siv import MacError, PacketFormatError

FAST = KdfParams(1024, 1, 1)
DATA = os.urandom(3 * 1024 * 1024 + 777)      # больше листа 1 МиБ и чанка? нет


def st(**kw):
    base = dict(cipher='Kazual-512', mode='siv', source=PasswordKey('pw'),
                kdf_params=FAST, small_file_mib=1)
    base.update(kw)
    return Settings(**base)


@pytest.fixture
def src_file(tmp_path):
    p = tmp_path / 'src.bin'
    p.write_bytes(DATA)
    return str(p)


def test_siv2_stream_roundtrip(tmp_path, src_file):
    s = st(siv=engine.Settings().siv)
    s.siv.leaf_size = 1 << 20
    dst = tmp_path / 'out.kaz'
    rep = stream.encrypt_file(s, src_file, str(dst))
    assert rep.ok and rep.out_bytes > rep.in_bytes
    back = tmp_path / 'back.bin'
    rep2 = stream.decrypt_file(s, str(dst), str(back))
    assert rep2.ok
    assert open(back, 'rb').read() == DATA


def test_siv1_stream_roundtrip(tmp_path, src_file):
    s = st()
    s.siv.version = 1
    dst = tmp_path / 'v1.kaz'
    assert stream.encrypt_file(s, src_file, str(dst)).ok
    back = tmp_path / 'back.bin'
    assert stream.decrypt_file(s, str(dst), str(back)).ok
    assert open(back, 'rb').read() == DATA


def test_ecb2_stream_roundtrip(tmp_path, src_file):
    s = st(mode='ecb')
    dst = tmp_path / 'e.kaz'
    assert stream.encrypt_file(s, src_file, str(dst)).ok
    back = tmp_path / 'back.bin'
    assert stream.decrypt_file(s, str(dst), str(back)).ok
    assert open(back, 'rb').read() == DATA


def test_tampered_file_rejected(tmp_path, src_file):
    s = st()
    dst = tmp_path / 't.kaz'
    stream.encrypt_file(s, src_file, str(dst))
    raw = bytearray(dst.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    dst.write_bytes(bytes(raw))
    back = tmp_path / 'back.bin'
    with pytest.raises(MacError):
        stream.decrypt_file(s, str(dst), str(back))
    assert not back.exists(), '.part должен быть удалён'


def test_wrong_password_rejected(tmp_path, src_file):
    s = st()
    dst = tmp_path / 'p.kaz'
    stream.encrypt_file(s, src_file, str(dst))
    back = tmp_path / 'back.bin'
    with pytest.raises(MacError):
        stream.decrypt_file(st(source=PasswordKey('other')), str(dst),
                             str(back))


def test_cancel_cleans_part(tmp_path, src_file):
    s = st()
    dst = tmp_path / 'c.kaz'
    ev = threading.Event()
    ev.set()
    with pytest.raises(stream.OperationCancelled):
        stream.encrypt_file(s, src_file, str(dst), cancel=ev)
    assert not (tmp_path / 'c.kaz.part').exists()
    assert not dst.exists()


def test_batch_and_collision_names(tmp_path):
    files = []
    for i in range(3):
        p = tmp_path / ('b%d.bin' % i)
        p.write_bytes(os.urandom(5000))
        files.append(str(p))
    s = st()
    jobs = [(f, stream.resolve_output_path(f, True)) for f in files]
    reps = stream.encrypt_files(s, jobs, None, None)
    assert all(r.ok for r in reps)
    # коллизии: повторное шифрование рядом даёт «(1)»
    d2 = stream.resolve_output_path(files[0], True, overwrite=False)
    assert d2.endswith('(1).kaz')
    # пакетная расшифровка: src=.kaz, dst=явный
    out = tmp_path / 'out'
    out.mkdir()
    dec_jobs = [(dst, str(out / os.path.basename(src))) for src, dst in jobs]
    reps2 = stream.decrypt_files(s, dec_jobs, None, None)
    assert all(r.ok for r in reps2), [r.error for r in reps2]
    for src, _ in jobs:
        assert (out / os.path.basename(src)).read_bytes() == \
            open(src, 'rb').read()


def test_one_file_error_not_fatal(tmp_path):
    good = tmp_path / 'good.bin'
    good.write_bytes(b'x' * 100)
    s = st()
    jobs = [(str(good), str(good) + '.kaz'),
            (str(tmp_path / 'missing.bin'), str(tmp_path / 'm.kaz'))]
    reps = stream.encrypt_files(s, jobs, None, None)
    assert reps[0].ok and not reps[1].ok


def test_resolve_output_naming(tmp_path):
    p = tmp_path / 'x.kaz'
    p.write_bytes(b'1')
    assert stream.resolve_output_path(str(p), False).endswith('x')
    q = tmp_path / 'y.txt'
    q.write_bytes(b'1')
    assert stream.resolve_output_path(str(q), False).endswith(
        'y.txt.decrypted')
    outdir = tmp_path / 'od'
    outdir.mkdir()
    r = stream.resolve_output_path(str(q), True, str(outdir))
    assert r.startswith(str(outdir))


def test_inspect_versions(tmp_path, src_file):
    s = st()
    dst = tmp_path / 'i.kaz'
    stream.encrypt_file(s, src_file, str(dst))
    d = stream.inspect_file(str(dst))
    assert d['version'] == 2 and d['cipher'] == 'Kazual-512'
    assert d['phc'] == FAST.phc_string()
    raw = tmp_path / 'raw.bin'
    raw.write_bytes(os.urandom(128))
    d0 = stream.inspect_file(str(raw))
    assert d0['version'] == 0
    with pytest.raises(PacketFormatError):
        stream.decrypt_file(st(), str(raw), str(tmp_path / 'x.bin'))
