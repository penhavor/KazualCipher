# -*- coding: utf-8 -*-
"""
Контейнер Kazual v2 — самоопределяемый формат пакета/файла.

Контейнер описывает себя сам: шифр, режим, состав полей, параметры
Argon2id, размер листа tree-MAC и длина данных лежат в заголовке, а
расшифровка всегда берёт настройки ИЗ файла — угадывать ничего не нужно.

Макет (big-endian):

    magic      4B   89 4B 5A 4C  («‰KZL», как ‰PNG у картинок)
    ver        1B   = 2
    cipher_id  1B   0 = Kazual-512, 1 = Kazual-64
    mode       1B   0 = SIV, 1 = ECB
    flags      1B   bit0 params · bit1 random · bit2 tree-MAC (SIV)
    brand_len  1B   длина текста-бренда (0…255)
    brand      nB   произвольный UTF-8 текст (метка владельца/версии)
    params     2B+ASCII  PHC-строка Argon2id ($argon2id$v=19$m=…,t=…,p=…)
    random     32B  соль/nonce
    leaf_size  4B   размер листа tree-MAC (только SIV)
    total_len  8B   длина открытых данных
    V          64B  тег подлинности (только SIV)
    payload    …    SIV: CTR-шифрограмма · ECB: блоки + PKCS#7

Подлинность SIV v2 (tree-MAC, параллелится по ядрам):

    d_i = ГОРН(лист_i; «…/v2/leaf/»‖шифр‖u64(i)‖u64(total_len))
    V   = ГОРН(K_mac ‖ frame(brand,params,random) ‖ u64(total)‖u32(leaf)
               ‖u32(n) ‖ d_0…d_{n-1}; «…/v2/root/»‖шифр)

ECB аутентификации не имеет — режим учебный.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from ..kdf import KdfParams, KdfParamsError
from .siv import MAGIC, RANDOM_BYTES, PacketFormatError

__all__ = ['VER', 'MODE_SIV', 'MODE_ECB', 'F_PARAMS', 'F_RANDOM', 'F_TREE',
           'CIPHER_IDS', 'CIPHER_BY_ID', 'ContainerInfo', 'build_header',
           'parse_header', 'is_container', 'MIN_HEAD_SIV', 'MIN_HEAD_ECB',
           'HEADER_MAX']

VER = 2
MODE_SIV = 0
MODE_ECB = 1

F_PARAMS = 0x01
F_RANDOM = 0x02
F_TREE = 0x04          # tree-MAC (обязателен для SIV v2)

CIPHER_IDS = {'Kazual-512': 0, 'Kazual-64': 1}
CIPHER_BY_ID = {0: 'Kazual-512', 1: 'Kazual-64'}

_FIXED = 9             # magic+ver+cipher+mode+flags+brand_len
MIN_HEAD_ECB = _FIXED + 8
MIN_HEAD_SIV = _FIXED + 4 + 8 + 64
HEADER_MAX = _FIXED + 255 + 2 + 65535 + RANDOM_BYTES + 4 + 8 + 64


@dataclass
class ContainerInfo:
    """Разобранный заголовок контейнера v2."""
    cipher_name: str
    mode: int                          # MODE_SIV | MODE_ECB
    brand: bytes = b''
    params_field: bytes = b''          # целиком (u16-длина + PHC) или b''
    kdf_params: Optional[KdfParams] = None
    random_field: bytes = b''          # 32B или b''
    leaf_size: int = 0                 # только SIV
    total_len: int = 0
    v: bytes = b''                      # 64B, только SIV
    payload_offset: int = 0
    header: bytes = b''

    @property
    def params_enabled(self) -> bool:
        return bool(self.params_field)

    @property
    def random_enabled(self) -> bool:
        return bool(self.random_field)

    def describe(self) -> str:
        """Человекочитаемая сводка для GUI."""
        mode = 'SIV' if self.mode == MODE_SIV else 'ECB'
        parts = ['контейнер v2 · %s · %s' % (self.cipher_name, mode)]
        if self.kdf_params is not None:
            parts.append('Argon2id m=%d, t=%d, p=%d (из файла)'
                         % (self.kdf_params.memory_kib,
                            self.kdf_params.iterations,
                            self.kdf_params.parallelism))
        elif self.mode == MODE_SIV or self.params_field == b'':
            parts.append('параметры KDF НЕ в файле — берутся из настроек')
        if self.brand:
            parts.append('бренд: «%s»' % self.brand.decode('utf-8', 'replace'))
        parts.append('random: %s' % ('есть' if self.random_field else 'нет'))
        if self.mode == MODE_SIV:
            parts.append('данные: %d Б · лист MAC: %d КиБ'
                         % (self.total_len, self.leaf_size // 1024))
        return ' · '.join(parts)


def build_header(cipher_name: str, mode: int, brand: bytes = b'',
                 params_field: bytes = b'', random_field: bytes = b'',
                 leaf_size: int = 0, total_len: int = 0,
                 v: bytes = b'') -> bytes:
    """Собрать заголовок контейнера v2 (без payload)."""
    if cipher_name not in CIPHER_IDS:
        raise PacketFormatError('неизвестный шифр для контейнера: %s'
                                % cipher_name)
    if len(brand) > 255:
        raise PacketFormatError('бренд длиннее 255 байт (%d)' % len(brand))
    flags = 0
    if params_field:
        flags |= F_PARAMS
    if random_field:
        flags |= F_RANDOM
    if mode == MODE_SIV:
        if len(v) != 64:
            raise PacketFormatError('V должен быть 64 байта')
        if leaf_size < 64:
            raise PacketFormatError('leaf_size ≥ 64 байт')
        flags |= F_TREE
    out = bytearray()
    out += MAGIC
    out += bytes((VER, CIPHER_IDS[cipher_name], mode, flags, len(brand)))
    out += brand
    if params_field:
        out += params_field
    if random_field:
        if len(random_field) != RANDOM_BYTES:
            raise PacketFormatError('random: нужно %d байт' % RANDOM_BYTES)
        out += random_field
    if mode == MODE_SIV:
        out += struct.pack('>I', leaf_size)
    out += struct.pack('>Q', total_len)
    if mode == MODE_SIV:
        out += v
    return bytes(out)


def is_container(head: bytes) -> bool:
    """Это контейнер v2? (достаточно первых 5 байт)."""
    return len(head) >= 5 and head[:4] == MAGIC and head[4] == VER


def parse_header(buf: bytes, file_size: Optional[int] = None) -> ContainerInfo:
    """Разобрать заголовок из первых байт файла/пакета.

    buf должен содержать как минимум весь заголовок (до payload);
    file_size — если известен, проверяется согласованность длины.
    Ошибки — PacketFormatError с понятным текстом.
    """
    n = len(buf)
    if n < _FIXED:
        raise PacketFormatError('файл короче заголовка контейнера (%d Б)' % n)
    if buf[:4] != MAGIC:
        raise PacketFormatError(
            'файл не начинается с магических байтов %s — это не контейнер '
            'Kazual v2' % MAGIC.hex(' ').upper())
    ver = buf[4]
    if ver != VER:
        raise PacketFormatError('версия контейнера %d не поддерживается '
                                '(ожидалась %d)' % (ver, VER))
    cipher_id = buf[5]
    if cipher_id not in CIPHER_BY_ID:
        raise PacketFormatError('неизвестный идентификатор шифра: %d'
                                % cipher_id)
    mode = buf[6]
    if mode not in (MODE_SIV, MODE_ECB):
        raise PacketFormatError('неизвестный режим контейнера: %d' % mode)
    flags = buf[7]
    if flags & ~0x07:
        raise PacketFormatError('зарезервированные биты flags установлены '
                                '(0x%02X) — файл от более новой версии?'
                                % flags)
    brand_len = buf[8]
    pos = _FIXED
    if n < pos + brand_len:
        raise PacketFormatError('файл обрезан: нет текста бренда')
    brand = bytes(buf[pos:pos + brand_len])
    pos += brand_len

    params_field = b''
    kdf_params = None
    if flags & F_PARAMS:
        if n < pos + 2:
            raise PacketFormatError('файл обрезан: нет длины params')
        (plen,) = struct.unpack('>H', buf[pos:pos + 2])
        if n < pos + 2 + plen:
            raise PacketFormatError('файл обрезан: params обещает %d Б'
                                    % plen)
        params_field = bytes(buf[pos:pos + 2 + plen])
        pos += 2 + plen
        try:
            kdf_params = KdfParams.parse(params_field[2:])
        except KdfParamsError as exc:
            raise PacketFormatError('поле params не разобрано (%s) — файл '
                                    'повреждён или создан другой программой'
                                    % exc) from exc

    random_field = b''
    if flags & F_RANDOM:
        if n < pos + RANDOM_BYTES:
            raise PacketFormatError('файл обрезан: нет поля random')
        random_field = bytes(buf[pos:pos + RANDOM_BYTES])
        pos += RANDOM_BYTES

    leaf_size = 0
    if mode == MODE_SIV:
        if n < pos + 4:
            raise PacketFormatError('файл обрезан: нет leaf_size')
        (leaf_size,) = struct.unpack('>I', buf[pos:pos + 4])
        pos += 4
        if leaf_size < 64:
            raise PacketFormatError('leaf_size=%d некорректен' % leaf_size)

    if n < pos + 8:
        raise PacketFormatError('файл обрезан: нет total_len')
    (total_len,) = struct.unpack('>Q', buf[pos:pos + 8])
    pos += 8

    v = b''
    if mode == MODE_SIV:
        if n < pos + 64:
            raise PacketFormatError('файл обрезан: нет тега V')
        v = bytes(buf[pos:pos + 64])
        pos += 64
        if total_len + pos > n and file_size is None:
            pass                        # buf может быть только заголовком
    if file_size is not None:
        expect = pos + total_len
        if mode == MODE_SIV and file_size != expect:
            raise PacketFormatError(
                'размер файла (%d Б) не совпадает с заголовком (ожидалось '
                '%d Б) — файл обрезан или повреждён' % (file_size, expect))
        if mode == MODE_ECB and (file_size < pos
                                 or (file_size - pos) % 64 != 0
                                 or (file_size - pos) == 0):
            if cipher_id == 0:
                raise PacketFormatError(
                    'размер ECB-payload (%d Б) не кратен блоку 64 Б — файл '
                    'обрезан или повреждён' % (file_size - pos))
    return ContainerInfo(
        cipher_name=CIPHER_BY_ID[cipher_id], mode=mode, brand=brand,
        params_field=params_field, kdf_params=kdf_params,
        random_field=random_field, leaf_size=leaf_size, total_len=total_len,
        v=v, payload_offset=pos, header=bytes(buf[:pos]))
