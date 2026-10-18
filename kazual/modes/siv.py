# -*- coding: utf-8 -*-
"""
Базовые типы SIV-пакета Kazual и настройки полей контейнера v2.

С версии 1.1.1 формат записи один — самоопределяемый контейнер v2
(kazual/modes/container.py): шифр, режим, параметры Argon2id и состав
полей хранятся в заголовке файла.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Optional

from ..kdf import KdfParams, DEFAULT_KDF_PARAMS

__all__ = ['SivOptions', 'SivResult', 'MacError', 'PacketFormatError',
           'RANDOM_BYTES', 'MAGIC', 'PacketField']

RANDOM_BYTES = 32        # 256 бит — соль/nonce
MAGIC = b'\x89KZL'       # «магические байты» — как \x89PNG у картинок


class PacketFormatError(ValueError):
    """Пакет не соответствует ожидаемому формату/настройкам."""


class MacError(ValueError):
    """Провал проверки подлинности (V не сошёлся)."""


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
    """Настройка полей контейнера v2 (всё переключается из GUI)."""
    prefix_enabled: bool = True          # бренд-метка в заголовке
    prefix_text: Optional[str] = None     # текст бренда ('' / None → не писать)
    params_enabled: bool = True
    kdf_params: KdfParams = field(default_factory=lambda: DEFAULT_KDF_PARAMS)
    random_enabled: bool = True          # вкл — случайная соль, выкл — детерминизм
    leaf_size: int = 4 * 1024 * 1024     # лист tree-MAC

    def resolve_params_field(self) -> bytes:
        """Байты поля params (u16be длина + PHC-строка) или b''."""
        if not self.params_enabled:
            return b''
        phc = self.kdf_params.phc_string().encode('ascii')
        if len(phc) > 0xFFFF:
            raise PacketFormatError('PHC-строка длиннее 65535 байт')
        return struct.pack('>H', len(phc)) + phc

    def resolve_random(self) -> bytes:
        """32 случайных байта соли или b'' (детерминированный режим)."""
        if not self.random_enabled:
            return b''
        return os.urandom(RANDOM_BYTES)


@dataclass
class SivResult:
    """Итог операции: данные + разобранные поля + служебная информация."""
    data: bytes
    fields: list
    meta: dict
