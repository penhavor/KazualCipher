# -*- coding: utf-8 -*-
"""
SIV-пакет Kazual: аутентифицированное шифрование с синтезированным IV.

Макет пакета (порядок конкатенации строгий):

    prefix ‖ params ‖ random ‖ V ‖ шифрограмма

    prefix  (256 бит)  «магические байты» 89 4B 5A 4C + бренд + версия —
                       форматный фильтр «свой/чужой, той ли версии»; сам по
                       себе нулевая энтропия, но покрыт MAC'ом. Отключаем,
                       текст настраиваем.
    params  (u16+ASCII) самоопписание KDF в PHC-стиле
                       "$argon2id$v=19$m=65536,t=3,p=4" — пакет читаем
                       старыми настройками, даже когда параметры подняли.
                       Отключаем — тогда расшифровка текущими параметрами.
    random  (256 бит)  соль Argon2id: один пароль → разный мастер на каждое
                       сообщение; наблюдатель не видит повторов. Отключаем —
                       шифрование становится детерминированным (нулевая соль).
    V       (512 бит)  синтетический nonce для CTR И тег подлинности в одном
                       лице: MAC(K_mac) от всех полей пакета + открытого текста.
    шифрограмма        CTR(K_enc, V‖counter): блоки независимы, паддинга нет.

Суть SIV: даже если ГСЧ сломается и random повторится, V (функция от текста)
разведёт одинаковые тексты по разным keystream'ам — и наоборот, совпадение V
выдаст детерминированный повтор. Подлинность: любое изменение любого байта
пакета (включая prefix/params/random) рвёт MAC.
"""

from __future__ import annotations

import hmac
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ..kdf import KdfParams, KdfParamsError, DEFAULT_KDF_PARAMS
from .mac import siv_mac, siv_mac_streaming, V_BYTES
from .ctr import ctr_xor
from ..keys import siv_master_keys, PasswordKey, RawKey

__all__ = ['SivOptions', 'SivPacket', 'SivResult', 'encrypt_siv',
           'decrypt_siv', 'MacError', 'PacketFormatError',
           'PREFIX_BYTES', 'RANDOM_BYTES', 'V_BYTES', 'MAGIC',
           'default_prefix_text', 'PacketField']

PREFIX_BYTES = 32        # 256 бит — фиксированная ширина поля prefix
RANDOM_BYTES = 32        # 256 бит — соль/nonce
MAGIC = b'\x89KZL'       # «магические байты» — как \x89PNG у картинок


class PacketFormatError(ValueError):
    """Пакет не соответствует ожидаемому формату/настройкам."""


class MacError(ValueError):
    """Провал проверки подлинности (V не сошёлся)."""


def default_prefix_text(cipher_name: str) -> str:
    """Текст prefix по умолчанию: бренд + версия (магические байты — отдельно)."""
    return '%s/v1.0' % cipher_name


@dataclass(frozen=True)
class PacketField:
    """Поле пакета — для визуализации и отчётов."""
    name: str
    data: bytes
    description: str = ''

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class SivOptions:
    """Тонкая настройка полей пакета (всё переключается из GUI)."""
    prefix_enabled: bool = True
    prefix_text: Optional[str] = None      # None/'' → default_prefix_text()
    params_enabled: bool = True
    kdf_params: KdfParams = field(default_factory=lambda: DEFAULT_KDF_PARAMS)
    random_enabled: bool = True
    fixed_random_hex: str = ''             # '' → os.urandom

    def resolve_prefix(self, cipher_name: str) -> bytes:
        """Байты поля prefix (32 Б) или b'' — если поле отключено."""
        if not self.prefix_enabled:
            return b''
        text = self.prefix_text if self.prefix_text else \
            default_prefix_text(cipher_name)
        raw = MAGIC + text.encode('utf-8')
        if len(raw) > PREFIX_BYTES:
            raise PacketFormatError(
                'prefix слишком длинный: %d Б (максимум %d Б, из них %d Б — '
                'магические %s)' % (len(raw), PREFIX_BYTES, len(MAGIC),
                                    MAGIC.hex(' ').upper()))
        return raw.ljust(PREFIX_BYTES, b'\x00')

    def resolve_params_field(self) -> bytes:
        """Байты поля params (u16be длина + PHC-строка) или b''."""
        if not self.params_enabled:
            return b''
        phc = self.kdf_params.phc_string().encode('ascii')
        if len(phc) > 0xFFFF:
            raise PacketFormatError('PHC-строка длиннее 65535 байт')
        return struct.pack('>H', len(phc)) + phc

    def resolve_random(self) -> bytes:
        """32 случайных байта, фиксированное значение или b'' (поле выключено)."""
        if not self.random_enabled:
            return b''
        if self.fixed_random_hex:
            cleaned = ''.join(self.fixed_random_hex.split())
            try:
                raw = bytes.fromhex(cleaned)
            except ValueError as exc:
                raise PacketFormatError(
                    'фиксированный random: не hex-строка (%s)' % exc) from exc
            if len(raw) != RANDOM_BYTES:
                raise PacketFormatError(
                    'фиксированный random: нужно ровно %d байт '
                    '(%d hex-цифр), дано %d'
                    % (RANDOM_BYTES, RANDOM_BYTES * 2, len(raw)))
            return raw
        return os.urandom(RANDOM_BYTES)


@dataclass
class SivPacket:
    """Разобранный пакет — результат decrypt (и отладочный инструмент)."""
    prefix: bytes
    params_field: bytes
    kdf_params: Optional[KdfParams]
    random_field: bytes
    v: bytes
    ciphertext: bytes


@dataclass
class SivResult:
    """Итог операции: данные + разобранные поля + служебная информация."""
    data: bytes
    fields: List[PacketField]
    meta: dict


ProgressCb = Optional[Callable[[str, Optional[float]], None]]


def _report(cb: ProgressCb, stage: str, frac: Optional[float] = None) -> None:
    if cb is not None:
        cb(stage, frac)


# ---------------------------------------------------------------------------
# Шифрование
# ---------------------------------------------------------------------------

def encrypt_siv(spec, cipher_name: str, source, plaintext: bytes,
                opts: SivOptions, progress_cb: ProgressCb = None,
                backend: str = 'auto') -> SivResult:
    """Собрать SIV-пакет: prefix ‖ params ‖ random ‖ V ‖ CTR(plaintext)."""
    t0 = time.monotonic()
    meta: dict = {'cipher': cipher_name, 'mode': 'siv'}

    _report(progress_cb, 'Поля пакета (prefix / params / random)…')
    prefix = opts.resolve_prefix(cipher_name)
    params_field = opts.resolve_params_field()
    random_field = opts.resolve_random()
    salt = random_field if opts.random_enabled else b'\x00' * RANDOM_BYTES

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

    _report(progress_cb, 'Синтез V: MAC от полей пакета и текста…', 0.05)
    t = time.monotonic()
    v = siv_mac(k_mac, cipher_name, prefix, params_field, random_field,
                plaintext)
    meta['mac_ms'] = (time.monotonic() - t) * 1000.0

    _report(progress_cb, 'Шифрование CTR…', 0.1)
    t = time.monotonic()
    ct = ctr_xor(spec, k_enc, plaintext, v, km=km, backend=backend,
                 progress_cb=lambda f: _report(
                     progress_cb, 'Шифрование CTR…', 0.1 + 0.9 * f))
    meta['ctr_ms'] = (time.monotonic() - t) * 1000.0

    packet = prefix + params_field + random_field + v + ct
    meta.update({
        'phc': opts.kdf_params.phc_string() if isinstance(source, PasswordKey)
               else None,
        'salt_hex': salt.hex(),
        'v_hex': v.hex(),
        'overhead': len(packet) - len(plaintext),
        'total_ms': (time.monotonic() - t0) * 1000.0,
        'deterministic': not opts.random_enabled,
    })
    fields = [
        PacketField('prefix', prefix,
                    'магические байты + бренд + версия' if prefix else
                    'поле отключено'),
        PacketField('params', params_field,
                    'PHC-строка Argon2id с u16-длиной' if params_field else
                    'поле отключено'),
        PacketField('random', random_field,
                    'соль/nonce (детерминированный режим, если выключено)'
                    if random_field else 'поле отключено'),
        PacketField('V', v, 'синтетический nonce + тег подлинности (MAC)'),
        PacketField('ciphertext', ct, 'CTR(K_enc, V‖counter)'),
    ]
    return SivResult(packet, fields, meta)


# ---------------------------------------------------------------------------
# Разбор и расшифрование
# ---------------------------------------------------------------------------

def parse_packet(packet: bytes, opts: SivOptions) -> SivPacket:
    """Разобрать пакет по текущим настройкам полей; ошибки — PacketFormatError."""
    pos = 0
    n = len(packet)

    if opts.prefix_enabled:
        if n < PREFIX_BYTES:
            raise PacketFormatError(
                'пакет короче поля prefix (%d < %d байт)' % (n, PREFIX_BYTES))
        prefix = packet[pos:pos + PREFIX_BYTES]
        if prefix[:len(MAGIC)] != MAGIC:
            raise PacketFormatError(
                'пакет не начинается с магических байт %s — неверный режим, '
                'шифр или файл повреждён' % MAGIC.hex(' ').upper())
        pos += PREFIX_BYTES
    else:
        prefix = b''
        if n >= len(MAGIC) and packet[:len(MAGIC)] == MAGIC:
            raise PacketFormatError(
                'похоже, пакет содержит prefix (магические байты %s), но в '
                'настройках prefix отключён — включите галочку'
                % MAGIC.hex(' ').upper())

    if opts.params_enabled:
        if n < pos + 2:
            raise PacketFormatError('пакет обрезан: нет длины поля params')
        (plen,) = struct.unpack('>H', packet[pos:pos + 2])
        if n < pos + 2 + plen:
            raise PacketFormatError(
                'пакет обрезан: params обещает %d байт, доступно %d'
                % (plen, n - pos - 2))
        params_field = packet[pos:pos + 2 + plen]
        pos += 2 + plen
        try:
            kdf_params = KdfParams.parse(packet[pos - plen:pos])
        except KdfParamsError as exc:
            raise PacketFormatError(
                'поле params не разобрано (%s) — пакет создан с другими '
                'настройками или повреждён' % exc) from exc
    else:
        params_field = b''
        kdf_params = None

    if opts.random_enabled:
        if n < pos + RANDOM_BYTES:
            raise PacketFormatError(
                'пакет обрезан: нет поля random (%d байт)' % RANDOM_BYTES)
        random_field = packet[pos:pos + RANDOM_BYTES]
        pos += RANDOM_BYTES
    else:
        random_field = b''

    if n < pos + V_BYTES:
        raise PacketFormatError(
            'пакет обрезан: нет тега V (%d байт)' % V_BYTES)
    v = packet[pos:pos + V_BYTES]
    pos += V_BYTES
    return SivPacket(prefix, params_field, kdf_params, random_field, v,
                     packet[pos:])


def decrypt_siv(spec, cipher_name: str, source, packet: bytes,
                opts: SivOptions, progress_cb: ProgressCb = None,
                backend: str = 'auto') -> SivResult:
    """Разобрать пакет, расшифровать CTR и проверить подлинность (V)."""
    t0 = time.monotonic()
    meta: dict = {'cipher': cipher_name, 'mode': 'siv'}

    _report(progress_cb, 'Разбор пакета…')
    pk = parse_packet(packet, opts)
    params = pk.kdf_params if pk.kdf_params is not None else opts.kdf_params
    salt = pk.random_field if opts.random_enabled else b'\x00' * RANDOM_BYTES

    _report(progress_cb, 'Вывод ключей…')
    t = time.monotonic()
    k_enc, k_mac = siv_master_keys(spec, cipher_name, source, salt, params)
    meta['kdf_ms'] = (time.monotonic() - t) * 1000.0

    _report(progress_cb, 'Расписание ключей шифра…')
    from ..cipher.schedule import key_schedule
    t = time.monotonic()
    km = key_schedule(spec, k_enc)
    meta['ks_ms'] = (time.monotonic() - t) * 1000.0

    _report(progress_cb, 'Дешифрование CTR…', 0.05)
    t = time.monotonic()
    pt = ctr_xor(spec, k_enc, pk.ciphertext, pk.v, km=km, backend=backend,
                 progress_cb=lambda f: _report(
                     progress_cb, 'Дешифрование CTR…', 0.05 + 0.75 * f))
    meta['ctr_ms'] = (time.monotonic() - t) * 1000.0

    _report(progress_cb, 'Проверка подлинности (MAC)…', 0.85)
    t = time.monotonic()
    h = siv_mac_streaming(k_mac, cipher_name, pk.prefix, pk.params_field,
                          pk.random_field, len(pt))
    step = max(1, len(pt) // 20)
    for i in range(0, len(pt), step):
        h.update(pt[i:i + step])
    v_calc = h.digest()
    meta['mac_ms'] = (time.monotonic() - t) * 1000.0
    if not hmac.compare_digest(v_calc, pk.v):
        raise MacError(
            'проверка подлинности НЕ пройдена: неверный пароль/ключ, '
            'повреждённые данные или настройки пакета (prefix / params / '
            'random) не совпадают с настройками при шифровании')

    meta.update({
        'phc': params.phc_string() if isinstance(source, PasswordKey) else None,
        'params_from_packet': pk.kdf_params is not None,
        'salt_hex': salt.hex(),
        'v_hex': pk.v.hex(),
        'verified': True,
        'overhead': len(packet) - len(pt),
        'total_ms': (time.monotonic() - t0) * 1000.0,
    })
    fields = [
        PacketField('prefix', pk.prefix, 'из пакета' if pk.prefix else 'отключён'),
        PacketField('params', pk.params_field,
                    pk.kdf_params.phc_string() if pk.kdf_params else 'отключены'),
        PacketField('random', pk.random_field,
                    'соль из пакета' if pk.random_field else 'отключён'),
        PacketField('V', pk.v, 'тег подлинности — сошёлся'),
        PacketField('ciphertext', pk.ciphertext, 'расшифровано CTR'),
    ]
    return SivResult(pt, fields, meta)
