# -*- coding: utf-8 -*-
"""
kazual.stream — потоковая обработка файлов с постоянным потреблением ОЗУ.

Всё тяжёлое (10 ГБ и больше) идёт через этот модуль: данные никогда не
загружаются в память целиком.

  * SIV, шифрование: проход 1 — tree-MAC (листья хэшируются пулом потоков
    прямо с диска, нативное ядро отпускает GIL → все ядра заняты);
    проход 2 — CTR-шифрование сегментами (numba prange / NumPy) с записью.
  * SIV, расшифрование: один проход — CTR-дешифрование + запись во
    временный .part + параллельный tree-MAC по пути; тег V проверяется в
    конце: не сошёлся — .part удаляется, пользователь НЕ получает
    непроверенные данные под итоговым именем.
  * ECB: один проход, PKCS#7 на хвосте.

Память: очереди ограничены (несколько листьев + сегмент CTR) — десятки
МиБ независимо от размера файла. Запись атомарна: os.replace(.part → dst).
Отмена проверяется между сегментами; .part при отмене/ошибке удаляется.
Читается только контейнер v2 (kazual/modes/container.py).
"""

from __future__ import annotations

import os
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field as dc_field
from typing import Callable, List, Optional, Tuple

from .cipher.spec import SPECS
from .cipher.schedule import key_schedule
from .cipher.batch import native_ctx
from .keys import siv_master_keys, mode_key
from .modes import container as ct
from .modes.mac import (tree_root_hasher, tree_leaf_digest, n_leaves_for,
                        effective_workers)
from .modes.ctr import ctr_iv, counter_bytes_for_block, CtrError
from .modes.padding import pkcs7_pad, pkcs7_unpad, PaddingError
from .modes.siv import PacketFormatError, MacError, RANDOM_BYTES
from .modes.siv2 import resolve_v2_fields

try:
    import numpy as _np
except Exception:                                        # pragma: no cover
    _np = None

__all__ = ['OperationCancelled', 'FileReport', 'encrypt_file', 'decrypt_file',
           'encrypt_files', 'decrypt_files', 'resolve_output_path',
           'inspect_data', 'inspect_file', 'DEFAULT_CHUNK']

DEFAULT_CHUNK = 8 << 20          # сегмент CTR/ECB (8 МиБ)
_READAHEAD = ct.HEADER_MAX + 4096


class OperationCancelled(Exception):
    """Операция прервана пользователем (временные файлы удалены)."""


@dataclass
class FileReport:
    """Отчёт по одному файлу пакетной операции."""
    src: str
    dst: str = ''
    ok: bool = False
    error: str = ''
    in_bytes: int = 0
    out_bytes: int = 0
    seconds: float = 0.0
    info: str = ''
    warnings: List[str] = dc_field(default_factory=list)


ProgressCb = Optional[Callable[[str, Optional[float]], None]]


# ---------------------------------------------------------------------------
# Вспомогательное
# ---------------------------------------------------------------------------

def _cancelled(cancel) -> bool:
    if cancel is None:
        return False
    if hasattr(cancel, 'is_set'):
        return bool(cancel.is_set())
    return bool(cancel())


def _check_cancel(cancel) -> None:
    if _cancelled(cancel):
        raise OperationCancelled('операция отменена пользователем')


def _report(cb, stage, frac=None):
    if cb is not None:
        cb(stage, frac)


def _speed(nbytes: float, secs: float) -> str:
    if secs <= 0:
        return ''
    r = nbytes / secs / (1 << 20)
    return ' · %.1f МиБ/с' % r if r >= 1 else ' · %.2f МиБ/с' % r


def _rm(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _fsync_close(f) -> None:
    try:
        f.flush()
        os.fsync(f.fileno())
    except OSError:
        pass


def resolve_output_path(src: str, encrypting: bool, outdir: Optional[str] = None,
                        overwrite: bool = False) -> str:
    """Куда сохранить результат: имя по правилам + защита от перезаписи.

    Шифрование: имя + '.kaz'. Расшифрование: '.kaz' снимается, иначе
    добавляется '.decrypted'. outdir=None — рядом с источником. Если файл
    существует и overwrite выключен — подбирается свободное имя «… (1)».
    """
    base = os.path.basename(src)
    if encrypting:
        name = base + '.kaz'
    else:
        low = base.lower()
        if low.endswith('.kaz'):
            name = base[:-4] or (base + '.decrypted')
        else:
            name = base + '.decrypted'
    directory = outdir if outdir else os.path.dirname(os.path.abspath(src))
    dst = os.path.join(directory, name)
    if not overwrite:
        root, ext = os.path.splitext(dst)
        i = 1
        while os.path.exists(dst):
            dst = '%s (%d)%s' % (root, i, ext)
            i += 1
            if i > 9999:
                raise OSError('не подобрать свободное имя для %s' % dst)
    return dst


def inspect_data(head: bytes, size: Optional[int] = None) -> dict:
    """Определить формат по первым байтам — для автоподстройки GUI.

    Возвращает dict: version (2|0), cipher, mode, phc, brand, random,
    leaf_size, total_len, describe. version=0 — контейнер не распознан.
    """
    out = {'version': 0, 'describe': ''}
    if not head:
        return out
    if ct.is_container(head):
        try:
            info = ct.parse_header(head)
        except PacketFormatError as exc:
            out['version'] = 2
            out['error'] = str(exc)
            out['describe'] = 'контейнер v2 не разобран: %s' % exc
            return out
        out.update({
            'version': 2,
            'cipher': info.cipher_name,
            'mode': 'siv' if info.mode == ct.MODE_SIV else 'ecb',
            'phc': info.kdf_params.phc_string() if info.kdf_params else None,
            'brand': info.brand.decode('utf-8', 'replace'),
            'random': info.random_enabled,
            'leaf_size': info.leaf_size,
            'total_len': info.total_len,
            'payload_offset': info.payload_offset,
            'describe': info.describe(),
        })
        return out
    out['describe'] = ('контейнер Kazual v2 не найден: файл повреждён, '
                       'обрезан или создан другой программой')
    return out


def inspect_file(path: str) -> dict:
    with open(path, 'rb') as f:
        head = f.read(min(_READAHEAD, 1 << 20))
    return inspect_data(head, os.path.getsize(path))


# ---------------------------------------------------------------------------
# CTR-сегмент: native (numba, параллельно) или запасной путь
# ---------------------------------------------------------------------------

class _CtrEngine:
    """CTR поверх файла: native (numba, параллельно) или запасной путь."""

    def __init__(self, spec, k_enc, v: bytes, km, backend: str):
        self.spec = spec
        self.b = spec.block_bytes
        self.k_enc = k_enc
        self.km = km
        self.backend = backend
        iv = ctr_iv(v, self.b)
        self.cb = counter_bytes_for_block(self.b)
        self.ctr0 = int.from_bytes(iv[self.b - self.cb:], 'big')
        self.iv = bytes(iv)
        self.nc = None
        if backend in ('auto', 'native'):
            self.nc = native_ctx(spec, km)
            if self.nc is not None and _np is not None:
                self.iv56 = _np.frombuffer(bytearray(iv[:self.b - self.cb]),
                                           dtype=_np.uint8)
        if backend == 'native' and self.nc is None:
            raise CtrError('нативный бэкенд недоступен (numba не установлена '
                           'или шифр не Kazual-512)')
        self.scratch = None

    def _check_span(self, total_blocks: int):
        span = 1 << (8 * self.cb)
        if self.ctr0 + total_blocks > span:
            raise CtrError('переполнение счётчика CTR: сообщение слишком '
                           'велико для этого тега V')

    def xor_into(self, src_arr, dst_arr, n: int, abs_block: int) -> None:
        """dst[:n] = src[:n] ⊕ keystream (блоки от abs_block)."""
        nb = n // self.b
        if nb:
            self.nc.ctr_xor_buf(src_arr[:nb * self.b], dst_arr[:nb * self.b],
                                self.iv56, self.ctr0 + abs_block,
                                self.scratch)
        tail = n - nb * self.b
        if tail:
            off = nb * self.b
            dst_arr[off:n] = src_arr[off:n]
            self.nc.ctr_tail_buf(dst_arr, off, tail, self.iv56,
                                 self.ctr0 + abs_block + nb)

    def xor_bytes(self, chunk: bytes, abs_block: int) -> bytes:
        """Универсальный путь (без native): сегмент байт → байт."""
        if self.nc is not None and _np is not None:
            src = _np.frombuffer(bytearray(chunk), dtype=_np.uint8)
            dst = _np.empty_like(src)
            self.xor_into(src, dst, len(chunk), abs_block)
            return dst.tobytes()
        from .modes.ctr import ctr_xor
        b = self.b
        iv_at = bytearray(self.iv)
        ctr = (self.ctr0 + abs_block) % (1 << (8 * self.cb))
        iv_at[b - self.cb:] = ctr.to_bytes(self.cb, 'big')
        return ctr_xor(self.spec, self.k_enc, chunk, bytes(iv_at),
                       km=self.km, backend=self.backend)


def _read_exactly(f, buf) -> None:
    """Прочитать ровно len(buf) байт в buf (memoryview/bytearray)."""
    mv = memoryview(buf)
    got = 0
    n = len(mv)
    while got < n:
        r = f.readinto(mv[got:])
        if not r:
            raise OSError('неожиданный конец файла (прочитано %d из %d)'
                          % (got, n))
        got += r


# ---------------------------------------------------------------------------
# Шифрование файла
# ---------------------------------------------------------------------------

def encrypt_file(st, src: str, dst: str, progress_cb: ProgressCb = None,
                 cancel=None) -> FileReport:
    """Зашифровать файл src → dst согласно настройкам st (engine.Settings)."""
    t0 = time.monotonic()
    rep = FileReport(src=src, dst=dst)
    size = os.path.getsize(src)
    rep.in_bytes = size
    st.validate()
    parent = os.path.dirname(os.path.abspath(dst))
    if parent:
        os.makedirs(parent, exist_ok=True)
    opts = st.effective_siv_options()

    limit = int(getattr(st, 'small_file_mib', 32)) << 20
    if size <= limit:
        return _encrypt_file_inmem(st, src, dst, size, progress_cb, cancel,
                                   t0)

    tmp = dst + '.part'
    try:
        if st.mode == 'siv':
            _stream_encrypt_siv2(st, opts, src, tmp, size, progress_cb,
                                 cancel)
        else:
            _stream_encrypt_ecb(st, opts, src, tmp, size, progress_cb, cancel)
        _check_cancel(cancel)
        os.replace(tmp, dst)
    except BaseException:
        _rm(tmp)
        raise
    rep.ok = True
    rep.out_bytes = os.path.getsize(dst)
    rep.seconds = time.monotonic() - t0
    return rep


def _encrypt_file_inmem(st, src, dst, size, progress_cb, cancel, t0):
    """Маленький файл — в памяти одним проходом (проще и быстрее)."""
    from .engine import encrypt as engine_encrypt
    with open(src, 'rb') as f:
        data = f.read()
    _check_cancel(cancel)
    res = engine_encrypt(st, data, progress=progress_cb)
    _check_cancel(cancel)
    tmp = dst + '.part'
    try:
        with open(tmp, 'wb') as f:
            f.write(res.data)
            _fsync_close(f)
        os.replace(tmp, dst)
    except BaseException:
        _rm(tmp)
        raise
    rep = FileReport(src=src, dst=dst, ok=True, in_bytes=size,
                     out_bytes=len(res.data),
                     seconds=time.monotonic() - t0,
                     warnings=list(res.warnings))
    rep.info = '%s · %s' % (res.cipher, res.mode.upper())
    return rep


def _stream_encrypt_siv2(st, opts, src, tmp, size, progress_cb, cancel):
    cipher_name = st.cipher
    spec = SPECS[cipher_name]
    brand, params_field, random_field = resolve_v2_fields(cipher_name, opts)
    salt = random_field if random_field else b'\x00' * RANDOM_BYTES
    _report(progress_cb, 'Вывод ключей…')
    k_enc, k_mac = siv_master_keys(spec, cipher_name, st.source, salt,
                                   opts.kdf_params)
    _report(progress_cb, 'Расписание ключей шифра…')
    km = key_schedule(spec, k_enc)
    leaf = max(64, int(opts.leaf_size))
    n = n_leaves_for(size, leaf)
    workers = min(effective_workers(st.threads), max(1, n))

    # ---- проход 1: tree-MAC прямо с диска, листья параллельно ----
    _report(progress_cb, 'Проход 1/2: tree-MAC (%d лист×%d МиБ, %d поток)…'
            % (n, leaf >> 20, workers), 0.0)
    h = tree_root_hasher(k_mac, cipher_name, brand, params_field,
                         random_field, size, leaf, n)
    t1 = time.monotonic()
    pool = ThreadPoolExecutor(workers) if workers > 1 and n > 1 else None
    pending = deque()
    done_bytes = 0
    try:
        with open(src, 'rb') as f:
            for idx in range(n):
                _check_cancel(cancel)
                want = min(leaf, size - idx * leaf)
                buf = bytearray(want)
                _read_exactly(f, buf)
                if pool is not None:
                    pending.append(pool.submit(tree_leaf_digest, cipher_name,
                                               idx, size, buf))
                    while len(pending) >= workers * 2:
                        h.update(pending.popleft().result())
                else:
                    h.update(tree_leaf_digest(cipher_name, idx, size, buf))
                done_bytes += want
                _report(progress_cb,
                        'Проход 1/2: tree-MAC · %d%%%s'
                        % (100 * done_bytes // max(size, 1),
                           _speed(done_bytes, time.monotonic() - t1)),
                        0.45 * done_bytes / max(size, 1))
        while pending:
            h.update(pending.popleft().result())
    finally:
        if pool is not None:
            pool.shutdown(wait=False)
    _check_cancel(cancel)
    v = h.digest()

    header = ct.build_header(cipher_name, ct.MODE_SIV, brand=brand,
                             params_field=params_field,
                             random_field=random_field, leaf_size=leaf,
                             total_len=size, v=v)
    _stream_ctr_pass(st, spec, k_enc, v, km, src, tmp, size, header,
                     progress_cb, cancel)


def _stream_ctr_pass(st, spec, k_enc, v, km, src, tmp, size, header,
                     progress_cb, cancel):
    """Записать header в tmp и пройти файл CTR-ом (native или запасной)."""
    eng = _CtrEngine(spec, k_enc, v, km, st.backend)
    b = eng.b
    eng._check_span((size + b - 1) // b)
    chunk = DEFAULT_CHUNK
    native = eng.nc is not None and _np is not None
    if native:
        in_arr = _np.empty(chunk, dtype=_np.uint8)
        out_arr = _np.empty(chunk, dtype=_np.uint8)
        eng.scratch = _np.empty(chunk, dtype=_np.uint8)
    t2 = time.monotonic()
    done = 0
    with open(src, 'rb') as fi, open(tmp, 'wb') as fo:
        fo.write(header)
        while done < size:
            _check_cancel(cancel)
            want = min(chunk, size - done)
            if native:
                _read_exactly(fi, memoryview(in_arr)[:want])
                eng.xor_into(in_arr, out_arr, want, done // b)
                fo.write(memoryview(out_arr)[:want])
            else:
                buf = fi.read(want)
                if len(buf) != want:
                    raise OSError('файл %s неожиданно сократился' % src)
                fo.write(eng.xor_bytes(buf, done // b))
            done += want
            _report(progress_cb, 'Проход 2/2: шифрование CTR · %d%%%s'
                    % (100 * done // max(size, 1),
                       _speed(done, time.monotonic() - t2)),
                    0.45 + 0.55 * done / max(size, 1))
        _fsync_close(fo)


def _stream_encrypt_ecb(st, opts, src, tmp, size, progress_cb, cancel):
    """ECB: один проход, контейнер v2 с самоописанием KDF."""
    from .cipher.batch import encrypt_blocks
    cipher_name = st.cipher
    spec = SPECS[cipher_name]
    brand, params_field, random_field = resolve_v2_fields(cipher_name, opts)
    salt = random_field if random_field else b'\x00' * RANDOM_BYTES
    _report(progress_cb, 'Вывод ключа…')
    k_enc = mode_key(spec, cipher_name, st.source, salt, opts.kdf_params,
                     b'/ECB-RAWKEY/')
    _report(progress_cb, 'Расписание ключей шифра…')
    km = key_schedule(spec, k_enc)
    header = ct.build_header(cipher_name, ct.MODE_ECB, brand=brand,
                             params_field=params_field,
                             random_field=random_field, total_len=size)
    b = spec.block_bytes
    chunk = DEFAULT_CHUNK - (DEFAULT_CHUNK % b)
    t2 = time.monotonic()
    done = 0
    carry = b''
    with open(src, 'rb') as fi, open(tmp, 'wb') as fo:
        fo.write(header)
        while True:
            _check_cancel(cancel)
            buf = fi.read(chunk)
            if not buf:
                break
            data = carry + buf
            nfull = (len(data) // b) * b
            if nfull:
                fo.write(encrypt_blocks(spec, k_enc, data[:nfull],
                                        backend=st.backend, km=km))
            carry = data[nfull:]
            done += len(buf)
            _report(progress_cb, 'Шифрование ECB · %d%%%s'
                    % (100 * done // max(size, 1),
                       _speed(done, time.monotonic() - t2)),
                    done / max(size, 1))
        padded = pkcs7_pad(carry, b)
        fo.write(encrypt_blocks(spec, k_enc, padded, backend=st.backend,
                                km=km))
        _fsync_close(fo)


# ---------------------------------------------------------------------------
# Расшифрование файла
# ---------------------------------------------------------------------------

def decrypt_file(st, src: str, dst: str, progress_cb: ProgressCb = None,
                 cancel=None) -> FileReport:
    """Расшифровать файл src → dst. Все параметры читаются из контейнера."""
    t0 = time.monotonic()
    rep = FileReport(src=src, dst=dst)
    size = os.path.getsize(src)
    rep.in_bytes = size
    st.validate()
    parent = os.path.dirname(os.path.abspath(dst))
    if parent:
        os.makedirs(parent, exist_ok=True)

    with open(src, 'rb') as f:
        head = f.read(min(_READAHEAD, size)) if size else b''
    det = inspect_data(head, size)
    rep.info = det.get('describe', '')
    if det['version'] != 2:
        raise PacketFormatError(det.get('describe') or
                                'файл не распознан как контейнер Kazual v2')

    opts = st.effective_siv_options()
    limit = int(getattr(st, 'small_file_mib', 32)) << 20
    if size <= limit:
        return _decrypt_file_inmem(st, src, dst, size, det, progress_cb,
                                   cancel, t0)

    tmp = dst + '.part'
    try:
        info = ct.parse_header(head, file_size=size)
        if info.mode == ct.MODE_SIV:
            _stream_decrypt_siv2(st, info, src, tmp, size, progress_cb,
                                 cancel)
        else:
            _stream_decrypt_ecb(st, info, src, tmp, size, progress_cb,
                                cancel)
        _check_cancel(cancel)
        os.replace(tmp, dst)
    except BaseException:
        _rm(tmp)
        raise
    rep.ok = True
    rep.out_bytes = os.path.getsize(dst)
    rep.seconds = time.monotonic() - t0
    return rep


def _decrypt_file_inmem(st, src, dst, size, det, progress_cb, cancel, t0):
    from .engine import decrypt as engine_decrypt
    with open(src, 'rb') as f:
        data = f.read()
    _check_cancel(cancel)
    res = engine_decrypt(st, data, progress=progress_cb)
    _check_cancel(cancel)
    tmp = dst + '.part'
    try:
        with open(tmp, 'wb') as f:
            f.write(res.data)
            _fsync_close(f)
        os.replace(tmp, dst)
    except BaseException:
        _rm(tmp)
        raise
    rep = FileReport(src=src, dst=dst, ok=True, in_bytes=size,
                     out_bytes=len(res.data),
                     seconds=time.monotonic() - t0,
                     info=det.get('describe', ''),
                     warnings=list(res.warnings))
    return rep


def _stream_decrypt_siv2(st, info, src, tmp, size, progress_cb, cancel):
    cipher_name = info.cipher_name
    spec = SPECS[cipher_name]
    opts = st.effective_siv_options()
    salt = info.random_field if info.random_field else b'\x00' * RANDOM_BYTES
    params = info.kdf_params if info.kdf_params is not None else opts.kdf_params
    _report(progress_cb, 'Вывод ключей…')
    k_enc, k_mac = siv_master_keys(spec, cipher_name, st.source, salt, params)
    _report(progress_cb, 'Расписание ключей шифра…')
    km = key_schedule(spec, k_enc)
    eng = _CtrEngine(spec, k_enc, info.v, km, st.backend)
    b = eng.b
    total = info.total_len
    eng._check_span((total + b - 1) // b)
    leaf = max(64, info.leaf_size)
    n = n_leaves_for(total, leaf)
    workers = min(effective_workers(st.threads), max(1, n))
    h = tree_root_hasher(k_mac, cipher_name, info.brand, info.params_field,
                         info.random_field, total, leaf, n)
    native = eng.nc is not None and _np is not None
    if native:
        in_arr = _np.empty(leaf, dtype=_np.uint8)
        out_arr = _np.empty(leaf, dtype=_np.uint8)
        eng.scratch = _np.empty(leaf, dtype=_np.uint8)
    pool = ThreadPoolExecutor(workers) if workers > 1 and n > 1 else None
    pending = deque()
    t2 = time.monotonic()
    done = 0
    try:
        with open(src, 'rb') as fi, open(tmp, 'wb') as fo:
            fi.seek(info.payload_offset)
            for idx in range(n):
                _check_cancel(cancel)
                want = min(leaf, total - idx * leaf)
                if native:
                    _read_exactly(fi, memoryview(in_arr)[:want])
                    eng.xor_into(in_arr, out_arr, want, (idx * leaf) // b)
                    fo.write(memoryview(out_arr)[:want])
                    leafbuf = bytearray(memoryview(out_arr)[:want])
                else:
                    buf = fi.read(want)
                    if len(buf) != want:
                        raise OSError('файл неожиданно сократился')
                    pt = eng.xor_bytes(buf, (idx * leaf) // b)
                    fo.write(pt)
                    leafbuf = bytearray(pt)
                if pool is not None:
                    pending.append(pool.submit(tree_leaf_digest, cipher_name,
                                               idx, total, leafbuf))
                    while len(pending) >= workers * 2:
                        h.update(pending.popleft().result())
                else:
                    h.update(tree_leaf_digest(cipher_name, idx, total,
                                              leafbuf))
                done += want
                _report(progress_cb,
                        'Дешифрование + tree-MAC · %d%%%s'
                        % (100 * done // max(total, 1),
                           _speed(done, time.monotonic() - t2)),
                        0.97 * done / max(total, 1))
            while pending:
                h.update(pending.popleft().result())
            _fsync_close(fo)
    finally:
        if pool is not None:
            pool.shutdown(wait=False)
    _check_cancel(cancel)
    _report(progress_cb, 'Проверка подлинности…', 0.98)
    import hmac as _hmac
    if not _hmac.compare_digest(h.digest(), info.v):
        raise MacError(
            'проверка подлинности НЕ пройдена: неверный пароль/ключ или файл '
            'повреждён (шифр, режим и параметры прочитаны из самого файла — '
            'остальная причина только в ключе или данных)')


def _stream_decrypt_ecb(st, info, src, tmp, size, progress_cb, cancel):
    """ECB (контейнер v2): самоописание KDF из заголовка."""
    cipher_name = info.cipher_name
    spec = SPECS[cipher_name]
    opts = st.effective_siv_options()
    salt = info.random_field if info.random_field else b'\x00' * RANDOM_BYTES
    params = info.kdf_params if info.kdf_params is not None else opts.kdf_params
    _report(progress_cb, 'Вывод ключа…')
    k_enc = mode_key(spec, cipher_name, st.source, salt, params,
                     b'/ECB-RAWKEY/')
    _report(progress_cb, 'Расписание ключей шифра…')
    km = key_schedule(spec, k_enc)
    _ecb_decrypt_body(st, spec, k_enc, km, src, tmp, info.payload_offset,
                      size - info.payload_offset, progress_cb, cancel,
                      info.total_len)


def _ecb_decrypt_body(st, spec, k_enc, km, src, tmp, payload_off, payload_len,
                      progress_cb, cancel, expect_total):
    from .cipher.batch import decrypt_blocks
    b = spec.block_bytes
    if payload_len == 0 or payload_len % b:
        raise PaddingError(
            'данные (%d Б) не кратны блоку %d Б — файл повреждён или это не '
            'контейнер Kazual' % (payload_len, b))
    chunk = DEFAULT_CHUNK - (DEFAULT_CHUNK % b)
    t2 = time.monotonic()
    done = 0
    hold = b''
    written = 0
    with open(src, 'rb') as fi, open(tmp, 'wb') as fo:
        fi.seek(payload_off)
        while done < payload_len:
            _check_cancel(cancel)
            want = min(chunk, payload_len - done)
            buf = fi.read(want)
            if len(buf) != want:
                raise OSError('файл неожиданно сократился')
            pt = decrypt_blocks(spec, k_enc, buf, backend=st.backend, km=km)
            combined = hold + pt
            if done + want < payload_len:
                fo.write(combined[:-b])
                written += len(combined) - b
                hold = combined[-b:]
            else:
                out = pkcs7_unpad(combined, b)
                fo.write(out)
                written += len(out)
                hold = b''
            done += want
            _report(progress_cb, 'Дешифрование ECB · %d%%%s'
                    % (100 * done // max(payload_len, 1),
                       _speed(done, time.monotonic() - t2)),
                    0.97 * done / max(payload_len, 1))
        _fsync_close(fo)
    if expect_total is not None and written != expect_total:
        raise PaddingError(
            'размер результата (%d Б) не совпал с total_len из контейнера '
            '(%d Б) — файл повреждён или неверен пароль' % (written,
                                                            expect_total))


# ---------------------------------------------------------------------------
# Пакетная обработка нескольких файлов
# ---------------------------------------------------------------------------

def _run_batch(fn, st, jobs, progress_cb, cancel) -> List[FileReport]:
    reports: List[FileReport] = []
    sizes = []
    for src, _dst in jobs:
        try:
            sizes.append(os.path.getsize(src))
        except OSError:
            sizes.append(0)
    total = sum(sizes) or 1
    done = 0
    for i, ((src, dst), sz) in enumerate(zip(jobs, sizes)):
        name = os.path.basename(src)

        def cb(stage, frac=None, _i=i, _done=done, _sz=sz, _name=name):
            if progress_cb is None:
                return
            g = (_done + (frac or 0.0) * _sz) / total
            progress_cb('[%d/%d] %s — %s' % (_i + 1, len(jobs), _name, stage),
                        g)

        _check_cancel(cancel)
        try:
            rep = fn(st, src, dst, cb, cancel)
        except OperationCancelled:
            raise
        except Exception as exc:                           # noqa: BLE001
            rep = FileReport(src=src, dst=dst, ok=False,
                             error='%s: %s' % (type(exc).__name__, exc),
                             in_bytes=sz)
        reports.append(rep)
        done += sz
        if progress_cb is not None:
            progress_cb('[%d/%d] %s — %s' % (
                i + 1, len(jobs), name,
                'готово' if rep.ok else 'ОШИБКА: %s' % rep.error),
                done / total)
    return reports


def encrypt_files(st, jobs: List[Tuple[str, str]],
                  progress_cb: ProgressCb = None,
                  cancel=None) -> List[FileReport]:
    """Зашифровать список пар (src, dst); ошибки файла не валят пакет."""
    return _run_batch(encrypt_file, st, jobs, progress_cb, cancel)


def decrypt_files(st, jobs: List[Tuple[str, str]],
                  progress_cb: ProgressCb = None,
                  cancel=None) -> List[FileReport]:
    """Расшифровать список пар (src, dst)."""
    return _run_batch(decrypt_file, st, jobs, progress_cb, cancel)
