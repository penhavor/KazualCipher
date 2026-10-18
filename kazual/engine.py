# -*- coding: utf-8 -*-
"""
kazual.engine — высокоуровневый фасад: «настройки → данные → результат».
Единственная точка входа, которую используют GUI и CLI.

    settings = Settings(cipher='Kazual-512', mode='siv', source=PasswordKey('…'),
                        siv=SivOptions(...))
    res = encrypt(settings, plaintext, progress=cb)   # res.data — пакет
    res = decrypt(settings, packet, progress=cb)      # res.data — текст

Результат всегда сопровождается разобранными полями пакета (для
визуализации) и мета-информацией (тайминги, V, PHC-строка, предупреждения).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .cipher.spec import SPECS, FULL, K64
from .kdf import KdfParams, DEFAULT_KDF_PARAMS
from .keys import (KeySource, PasswordKey, RawKey, KeyMaterialError,
                   siv_master_keys, mode_key)
from .modes.siv import (SivOptions, SivResult, PacketField, encrypt_siv,
                        decrypt_siv)
from .modes.ecb import encrypt_ecb, decrypt_ecb, EcbResult
from .modes.padding import PaddingError                      # noqa: F401 (реэкспорт)
from .modes.siv import MacError, PacketFormatError            # noqa: F401 (реэкспорт)

__all__ = ['CipherInfo', 'CIPHERS', 'MODES', 'Settings', 'Result',
           'encrypt', 'decrypt', 'KazualError']

_ZERO_SALT = b'\x00' * 32   # ECB: контейнера для random нет — соль нулевая


class KazualError(Exception):
    """Базовая ошибка движка (GUI показывает её текст дословно)."""


@dataclass(frozen=True)
class CipherInfo:
    """Описание шифра для списков выбора."""
    name: str
    block_bits: int
    key_bits: int
    rounds: int
    educational: bool
    subtitle: str

    @property
    def spec(self):
        return SPECS[self.name]


CIPHERS: List[CipherInfo] = [
    CipherInfo('Kazual-512', 512, 512, 5, False,
               'блок 512 бит · ключ 512 бит · 5 тяжёлых раундов'),
    CipherInfo('Kazual-64', 64, 64, 2, True,
               'блок 64 бита · ключ 64 бита · 2 раунда — учебный, НЕ для защиты'),
]
CIPHER_BY_NAME = {c.name: c for c in CIPHERS}

MODES = {
    'siv': 'SIV — аутентифицированное шифрование (рекомендуется)',
    'ecb': 'ECB — простой режим без аутентификации',
}


@dataclass
class Settings:
    """Все регуляторы одной структурой — GUI собирает её из виджетов."""
    cipher: str = 'Kazual-512'
    mode: str = 'siv'                        # 'siv' | 'ecb'
    source: KeySource = field(default_factory=lambda: PasswordKey(''))
    kdf_params: KdfParams = field(default_factory=lambda: DEFAULT_KDF_PARAMS)
    siv: SivOptions = field(default_factory=SivOptions)
    backend: str = 'auto'                    # auto | cpu | gpu | scalar

    def validate(self) -> None:
        if self.cipher not in CIPHER_BY_NAME:
            raise KazualError('неизвестный шифр: %s' % self.cipher)
        if self.mode not in MODES:
            raise KazualError('неизвестный режим: %s' % self.mode)
        if isinstance(self.source, PasswordKey) and not self.source.password:
            raise KazualError('введите пароль')
        if isinstance(self.source, RawKey) and not self.source.key:
            raise KazualError('введите сырой ключ')
        self.kdf_params.validate()

    def effective_siv_options(self) -> SivOptions:
        """SivOptions с актуальными KDF-параметрами из сайдбара."""
        o = self.siv
        return SivOptions(
            prefix_enabled=o.prefix_enabled, prefix_text=o.prefix_text,
            params_enabled=o.params_enabled, kdf_params=self.kdf_params,
            random_enabled=o.random_enabled,
            fixed_random_hex=o.fixed_random_hex)


@dataclass
class Result:
    """Единый результат для GUI/CLI."""
    data: bytes
    cipher: str
    mode: str
    fields: List[PacketField]
    meta: dict
    warnings: List[str]


def _collect_warnings(st: Settings) -> List[str]:
    w: List[str] = []
    info = CIPHER_BY_NAME[st.cipher]
    if info.educational:
        w.append('Kazual-64 — учебный шифр: 64-битный ключ и блок. '
                 'НЕ предназначен для защиты данных.')
    if st.mode == 'ecb':
        w.append('ECB: нет проверки подлинности; одинаковые открытые блоки '
                 'дают одинаковые шифроблоки.')
        if isinstance(st.source, PasswordKey):
            w.append('ECB с паролем: соль нулевая (контейнера для random '
                     'нет) — один пароль всегда даёт один ключ.')
    else:
        o = st.effective_siv_options()
        if not o.random_enabled:
            w.append('random отключён: шифрование детерминировано (нулевая '
                     'соль), одинаковый текст даёт одинаковый пакет.')
        if not o.params_enabled:
            w.append('params не сохраняются в пакет: расшифровать можно '
                     'только с теми же параметрами Argon2id в настройках.')
        if not o.prefix_enabled:
            w.append('prefix отключён: пакет лишён форматного фильтра '
                     '«свой/чужой» (на защиту это не влияет — V покрывает всё).')
    return w


def _spec(st: Settings):
    return CIPHER_BY_NAME[st.cipher].spec


def encrypt(st: Settings, data: bytes,
            progress: Optional[Callable[[str, Optional[float]], None]] = None,
            ) -> Result:
    """Зашифровать данные согласно настройкам."""
    st.validate()
    warnings = _collect_warnings(st)
    if st.mode == 'siv':
        res: SivResult = encrypt_siv(
            _spec(st), st.cipher, st.source, data,
            st.effective_siv_options(), progress_cb=progress,
            backend=st.backend)
    else:
        t0 = time.monotonic()
        if progress:
            progress('Вывод ключа…', None)
        k_enc = mode_key(_spec(st), st.cipher, st.source, _ZERO_SALT,
                         st.kdf_params, b'/ECB-RAWKEY/')
        km = None
        if progress:
            progress('Расписание ключей шифра…', None)
        from .cipher.schedule import key_schedule
        km = key_schedule(_spec(st), k_enc)
        res: EcbResult = encrypt_ecb(_spec(st), st.cipher, k_enc, data,
                                     km=km, backend=st.backend,
                                     progress_cb=progress)
        res.meta['kdf_ms'] = (time.monotonic() - t0) * 1000.0
    return Result(res.data, st.cipher, st.mode, res.fields, res.meta,
                  warnings)


def decrypt(st: Settings, data: bytes,
            progress: Optional[Callable[[str, Optional[float]], None]] = None,
            ) -> Result:
    """Расшифровать данные; для SIV — с проверкой подлинности (V)."""
    st.validate()
    warnings = _collect_warnings(st)
    if st.mode == 'siv':
        res: SivResult = decrypt_siv(
            _spec(st), st.cipher, st.source, data,
            st.effective_siv_options(), progress_cb=progress,
            backend=st.backend)
    else:
        if progress:
            progress('Вывод ключа…', None)
        k_enc = mode_key(_spec(st), st.cipher, st.source, _ZERO_SALT,
                         st.kdf_params, b'/ECB-RAWKEY/')
        if progress:
            progress('Расписание ключей шифра…', None)
        from .cipher.schedule import key_schedule
        km = key_schedule(_spec(st), k_enc)
        res: EcbResult = decrypt_ecb(_spec(st), st.cipher, k_enc, data,
                                     km=km, backend=st.backend,
                                     progress_cb=progress)
    return Result(res.data, st.cipher, st.mode, res.fields, res.meta,
                  warnings)
