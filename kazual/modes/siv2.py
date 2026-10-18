# -*- coding: utf-8 -*-
"""
SIV в контейнере v2: самоопределяемый пакет + параллельный tree-MAC.

  * заголовок сам описывает шифр, режим, состав полей, бренд, параметры
    Argon2id, leaf_size и длину данных — расшифровке не нужны «галочки»;
  * V считается деревом (листья параллельно по ядрам) — MAC больших
    файлов ускоряется пропорционально числу потоков;
  * CTR и вывод ключей — прежние (Kazual-CTR от V‖counter).
"""

from __future__ import annotations

import hmac
import time
from typing import Callable, Optional

from ..kdf import KdfParams
from ..keys import siv_master_keys, PasswordKey
from . import container as ct
from .mac import tree_mac, n_leaves_for, DEFAULT_LEAF_SIZE
from .ctr import ctr_xor
from .siv import PacketField, SivResult, MacError, PacketFormatError

__all__ = ['encrypt_siv2', 'decrypt_siv2', 'encrypt_ecb2', 'decrypt_ecb2']

ProgressCb = Optional[Callable[[str, Optional[float]], None]]


def _report(cb: ProgressCb, stage: str, frac: Optional[float] = None) -> None:
    if cb is not None:
        cb(stage, frac)


def resolve_v2_fields(cipher_name: str, opts) -> tuple:
    """(brand, params_field, random_field) по SivOptions (version=2)."""
    brand = b''
    if opts.prefix_enabled:
        text = opts.prefix_text or ''
        brand = text.encode('utf-8')
        if len(brand) > 255:
            raise PacketFormatError(
                'бренд длиннее 255 байт (%d) — сократите текст' % len(brand))
    params_field = opts.resolve_params_field() if opts.params_enabled else b''
    random_field = opts.resolve_random()
    return brand, params_field, random_field


# ---------------------------------------------------------------------------
# SIV v2
# ---------------------------------------------------------------------------

def encrypt_siv2(spec, cipher_name: str, source, plaintext: bytes, opts,
                 progress_cb: ProgressCb = None, backend: str = 'auto',
                 threads: int = 0) -> SivResult:
    """Собрать контейнер v2: header(brand,params,random,leaf,V) ‖ CTR."""
    t0 = time.monotonic()
    meta: dict = {'cipher': cipher_name, 'mode': 'siv', 'version': 2}

    _report(progress_cb, 'Поля контейнера…')
    brand, params_field, random_field = resolve_v2_fields(cipher_name, opts)
    leaf_size = int(getattr(opts, 'leaf_size', DEFAULT_LEAF_SIZE)
                    or DEFAULT_LEAF_SIZE)
    salt = random_field if random_field else b'\x00' * ct.RANDOM_BYTES

    _report(progress_cb, 'Вывод ключей (%s)…' %
            (opts.kdf_params.describe() if isinstance(source, PasswordKey)
             else 'ГОРН-растягивание сырого ключа'))
    t = time.monotonic()
    k_enc, k_mac = siv_master_keys(spec, cipher_name, source, salt,
                                   opts.kdf_params)
    meta['kdf_ms'] = (time.monotonic() - t) * 1000.0

    _report(progress_cb, 'Расписание ключей шифра…')
    from ..cipher.schedule import key_schedule
    t = time.monotonic()
    km = key_schedule(spec, k_enc)
    meta['ks_ms'] = (time.monotonic() - t) * 1000.0

    _report(progress_cb, 'Синтез V: tree-MAC от данных…', 0.0)
    t = time.monotonic()
    v = tree_mac(k_mac, cipher_name, brand, params_field, random_field,
                 plaintext, leaf_size, threads,
                 progress_cb=lambda f: _report(
                     progress_cb, 'Синтез V: tree-MAC…', 0.5 * f))
    meta['mac_ms'] = (time.monotonic() - t) * 1000.0

    _report(progress_cb, 'Шифрование CTR…', 0.5)
    t = time.monotonic()
    ct_bytes = ctr_xor(spec, k_enc, plaintext, v, km=km, backend=backend,
                       progress_cb=lambda f: _report(
                           progress_cb, 'Шифрование CTR…', 0.5 + 0.5 * f))
    meta['ctr_ms'] = (time.monotonic() - t) * 1000.0

    header = ct.build_header(cipher_name, ct.MODE_SIV, brand=brand,
                             params_field=params_field,
                             random_field=random_field, leaf_size=leaf_size,
                             total_len=len(plaintext), v=v)
    packet = header + ct_bytes
    meta.update({
        'phc': opts.kdf_params.phc_string() if isinstance(source, PasswordKey)
               else None,
        'salt_hex': salt.hex(),
        'v_hex': v.hex(),
        'leaf_size': leaf_size,
        'n_leaves': n_leaves_for(len(plaintext), leaf_size),
        'overhead': len(packet) - len(plaintext),
        'total_ms': (time.monotonic() - t0) * 1000.0,
        'deterministic': not random_field,
    })
    fields = [
        PacketField('header', header[:ct._FIXED],
                    'магия ‖ версия ‖ шифр ‖ режим ‖ флаги ‖ бренд-длина'),
        PacketField('brand', brand,
                    'текст-метка (необязательно)' if brand else 'пусто'),
        PacketField('params', params_field,
                    'PHC-строка Argon2id' if params_field else 'не сохраняются'),
        PacketField('random', random_field,
                    'соль/nonce' if random_field else 'детерминированный режим'),
        PacketField('leaf', leaf_size.to_bytes(4, 'big'),
                    'размер листа tree-MAC: %d КиБ' % (leaf_size // 1024)),
        PacketField('total_len', len(plaintext).to_bytes(8, 'big'),
                    'длина открытых данных'),
        PacketField('V', v, 'тег подлинности (корень tree-MAC)'),
        PacketField('ciphertext', ct_bytes, 'CTR(K_enc, V‖counter)'),
    ]
    return SivResult(packet, fields, meta)


def decrypt_siv2(source, packet: bytes, opts, progress_cb: ProgressCb = None,
                 backend: str = 'auto', threads: int = 0,
                 info: Optional[ct.ContainerInfo] = None) -> SivResult:
    """Расшифровать контейнер v2; все настройки берутся ИЗ пакета."""
    t0 = time.monotonic()
    if info is None:
        info = ct.parse_header(packet, file_size=len(packet))
    if info.mode != ct.MODE_SIV:
        raise PacketFormatError('контейнер v2 содержит режим ECB, не SIV')
    from ..cipher.spec import SPECS
    spec = SPECS[info.cipher_name]
    cipher_name = info.cipher_name
    meta: dict = {'cipher': cipher_name, 'mode': 'siv', 'version': 2}

    salt = info.random_field if info.random_field else b'\x00' * ct.RANDOM_BYTES
    params: KdfParams = info.kdf_params if info.kdf_params is not None \
        else opts.kdf_params

    _report(progress_cb, 'Вывод ключей…')
    t = time.monotonic()
    k_enc, k_mac = siv_master_keys(spec, cipher_name, source, salt, params)
    meta['kdf_ms'] = (time.monotonic() - t) * 1000.0

    _report(progress_cb, 'Расписание ключей шифра…')
    from ..cipher.schedule import key_schedule
    t = time.monotonic()
    km = key_schedule(spec, k_enc)
    meta['ks_ms'] = (time.monotonic() - t) * 1000.0

    payload = packet[info.payload_offset:]
    if len(payload) != info.total_len:
        raise PacketFormatError(
            'шифрограмма (%d Б) не соответствует total_len (%d Б)'
            % (len(payload), info.total_len))

    _report(progress_cb, 'Дешифрование CTR…', 0.0)
    t = time.monotonic()
    pt = ctr_xor(spec, k_enc, payload, info.v, km=km, backend=backend,
                 progress_cb=lambda f: _report(
                     progress_cb, 'Дешифрование CTR…', 0.5 * f))
    meta['ctr_ms'] = (time.monotonic() - t) * 1000.0

    _report(progress_cb, 'Проверка подлинности (tree-MAC)…', 0.5)
    t = time.monotonic()
    v_calc = tree_mac(k_mac, cipher_name, info.brand, info.params_field,
                      info.random_field, pt, info.leaf_size, threads,
                      progress_cb=lambda f: _report(
                          progress_cb, 'Проверка подлинности (tree-MAC)…',
                          0.5 + 0.5 * f))
    meta['mac_ms'] = (time.monotonic() - t) * 1000.0
    if not hmac.compare_digest(v_calc, info.v):
        raise MacError(
            'проверка подлинности НЕ пройдена: неверный пароль/ключ или '
            'данные изменены (все остальные параметры прочитаны из файла)')

    meta.update({
        'phc': params.phc_string() if isinstance(source, PasswordKey) else None,
        'params_from_packet': info.kdf_params is not None,
        'salt_hex': salt.hex(),
        'v_hex': info.v.hex(),
        'leaf_size': info.leaf_size,
        'verified': True,
        'overhead': len(packet) - len(pt),
        'total_ms': (time.monotonic() - t0) * 1000.0,
    })
    fields = [
        PacketField('header', info.header[:ct._FIXED], 'из файла'),
        PacketField('brand', info.brand,
                    info.brand.decode('utf-8', 'replace') or 'пусто'),
        PacketField('params', info.params_field,
                    params.phc_string()),
        PacketField('random', info.random_field,
                    'соль из файла' if info.random_field else 'нет'),
        PacketField('leaf', info.leaf_size.to_bytes(4, 'big'),
                    '%d КиБ' % (info.leaf_size // 1024)),
        PacketField('total_len', info.total_len.to_bytes(8, 'big'),
                    '%d Б' % info.total_len),
        PacketField('V', info.v, 'тег подлинности — сошёлся'),
        PacketField('ciphertext', payload, 'расшифровано CTR'),
    ]
    return SivResult(pt, fields, meta)


# ---------------------------------------------------------------------------
# ECB в контейнере v2 (самоописание: шифр + KDF-параметры в заголовке)
# ---------------------------------------------------------------------------

def encrypt_ecb2(spec, cipher_name: str, source, plaintext: bytes, opts,
                 progress_cb: ProgressCb = None,
                 backend: str = 'auto') -> SivResult:
    from ..keys import mode_key
    from ..cipher.schedule import key_schedule
    from .ecb import encrypt_ecb
    t0 = time.monotonic()
    brand, params_field, random_field = resolve_v2_fields(cipher_name, opts)
    salt = random_field if random_field else b'\x00' * ct.RANDOM_BYTES

    _report(progress_cb, 'Вывод ключа…')
    k_enc = mode_key(spec, cipher_name, source, salt, opts.kdf_params,
                     b'/ECB-RAWKEY/')
    _report(progress_cb, 'Расписание ключей шифра…')
    km = key_schedule(spec, k_enc)
    _report(progress_cb, 'Шифрование ECB…', 0.1)
    res = encrypt_ecb(spec, cipher_name, k_enc, plaintext, km=km,
                      backend=backend,
                      progress_cb=lambda stage, frac=None: _report(
                          progress_cb, 'Шифрование ECB…',
                          0.1 + 0.9 * (frac if frac is not None else 0.0)))
    header = ct.build_header(cipher_name, ct.MODE_ECB, brand=brand,
                             params_field=params_field,
                             random_field=random_field,
                             total_len=len(plaintext))
    packet = header + res.data
    meta = dict(res.meta)
    meta.update({
        'version': 2,
        'phc': opts.kdf_params.phc_string() if isinstance(source, PasswordKey)
               else None,
        'salt_hex': salt.hex(),
        'overhead': len(packet) - len(plaintext),
        'total_ms': (time.monotonic() - t0) * 1000.0,
        'deterministic': not random_field,
    })
    fields = [
        PacketField('header', header, 'заголовок контейнера v2 (ECB)'),
        PacketField('ciphertext', res.data,
                    'ECB-блоки + PKCS#7 (+%d Б)' % res.meta.get('padding', 0)),
    ]
    return SivResult(packet, fields, meta)


def decrypt_ecb2(source, packet: bytes, opts, progress_cb: ProgressCb = None,
                 backend: str = 'auto',
                 info: Optional[ct.ContainerInfo] = None) -> SivResult:
    from ..keys import mode_key
    from ..cipher.schedule import key_schedule
    from ..cipher.spec import SPECS
    from .ecb import decrypt_ecb
    t0 = time.monotonic()
    if info is None:
        info = ct.parse_header(packet, file_size=len(packet))
    if info.mode != ct.MODE_ECB:
        raise PacketFormatError('контейнер v2 содержит режим SIV, не ECB')
    spec = SPECS[info.cipher_name]
    cipher_name = info.cipher_name
    salt = info.random_field if info.random_field else b'\x00' * ct.RANDOM_BYTES
    params = info.kdf_params if info.kdf_params is not None else opts.kdf_params

    _report(progress_cb, 'Вывод ключа…')
    k_enc = mode_key(spec, cipher_name, source, salt, params, b'/ECB-RAWKEY/')
    _report(progress_cb, 'Расписание ключей шифра…')
    km = key_schedule(spec, k_enc)
    payload = packet[info.payload_offset:]
    _report(progress_cb, 'Дешифрование ECB…', 0.1)
    res = decrypt_ecb(spec, cipher_name, k_enc, payload, km=km,
                      backend=backend,
                      progress_cb=lambda stage, frac=None: _report(
                          progress_cb, 'Дешифрование ECB…',
                          0.1 + 0.9 * (frac if frac is not None else 0.0)))
    meta = dict(res.meta)
    meta.update({
        'version': 2,
        'phc': params.phc_string() if isinstance(source, PasswordKey) else None,
        'params_from_packet': info.kdf_params is not None,
        'salt_hex': salt.hex(),
        'overhead': len(packet) - len(res.data),
        'total_ms': (time.monotonic() - t0) * 1000.0,
    })
    fields = [
        PacketField('header', info.header, 'из файла'),
        PacketField('plaintext', res.data, 'после снятия PKCS#7'),
    ]
    return SivResult(res.data, fields, meta)
