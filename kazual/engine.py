# -*- coding: utf-8 -*-
"""
kazual.engine — высокоуровневый фасад: «настройки → данные → результат».
Единственная точка входа, которую используют GUI и CLI.

    settings = Settings(cipher='Kazual-512', mode='siv', source=PasswordKey('…'),
                        siv=SivOptions(...))
    res = encrypt(settings, plaintext, progress=cb)   # res.data — контейнер
    res = decrypt(settings, packet, progress=cb)      # res.data — текст

Файлы (в том числе огромные — поток с постоянным ОЗУ, все ядра CPU):

    from kazual import stream
    rep = stream.encrypt_file(settings, 'big.iso', 'big.iso.kaz', progress)
    reps = stream.encrypt_files(settings, [(src, dst), …], progress, cancel)

Расшифровка САМА определяет формат по содержимому: контейнер v2 несёт в
заголовке шифр, режим, параметры Argon2id и состав полей — настройки
панели для него не используются (только пароль/ключ).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .cipher.spec import SPECS
from .kdf import KdfParams, DEFAULT_KDF_PARAMS
from .keys import KeySource, PasswordKey, RawKey
from .modes.siv import SivOptions, SivResult, PacketField
from .modes.siv2 import (encrypt_siv2, decrypt_siv2, encrypt_ecb2,
                         decrypt_ecb2)
from .modes.ecb import encrypt_ecb, decrypt_ecb, EcbResult
from .modes import container as ct
from .modes.padding import PaddingError                      # noqa: F401 (реэкспорт)
from .modes.siv import MacError, PacketFormatError            # noqa: F401 (реэкспорт)

__all__ = ['CipherInfo', 'CIPHERS', 'CIPHER_BY_NAME', 'MODES', 'Settings',
           'Result', 'encrypt', 'decrypt', 'KazualError']

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
               'блок 64 бита · ключ 64 бита · 2 раунда — учебный'),
]
CIPHER_BY_NAME = {c.name: c for c in CIPHERS}

MODES = {
    'siv': 'SIV — аутентифицированное шифрование (рекомендуется)',
    'ecb': 'ECB — простой режим без аутентификации (учебный)',
}


@dataclass
class Settings:
    """Все регуляторы одной структурой — GUI собирает её из виджетов."""
    cipher: str = 'Kazual-512'
    mode: str = 'siv'                        # 'siv' | 'ecb'
    source: KeySource = field(default_factory=lambda: PasswordKey(''))
    kdf_params: KdfParams = field(default_factory=lambda: DEFAULT_KDF_PARAMS)
    siv: SivOptions = field(default_factory=SivOptions)
    backend: str = 'auto'                    # auto|native|cpu|gpu|scalar
    threads: int = 0                         # 0 = все ядра
    small_file_mib: int = 32                 # порог «в памяти» для файлов

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
        """SivOptions с актуальными KDF-параметрами из настроек."""
        o = self.siv
        return SivOptions(
            prefix_enabled=o.prefix_enabled, prefix_text=o.prefix_text,
            params_enabled=o.params_enabled, kdf_params=self.kdf_params,
            random_enabled=o.random_enabled,
            leaf_size=o.leaf_size)


@dataclass
class Result:
    """Единый результат для GUI/CLI."""
    data: bytes
    cipher: str
    mode: str
    fields: List[PacketField]
    meta: dict
    warnings: List[str]


def _collect_warnings(st: Settings, cipher: Optional[str] = None,
                      mode: Optional[str] = None) -> List[str]:
    """Функциональные предупреждения (без повторяющейся «страшилки» —
    одно полное предупреждение о природе шифра живёт в «О шифре»)."""
    w: List[str] = []
    info = CIPHER_BY_NAME[cipher or st.cipher]
    if info.educational:
        w.append('Kazual-64 — учебный шифр (64-битные блок и ключ), '
                 'не для защиты данных.')
    mode = mode or st.mode
    if mode == 'ecb':
        w.append('ECB: нет проверки подлинности; одинаковые открытые блоки '
                 'дают одинаковые шифроблоки.')
    else:
        o = st.effective_siv_options()
        if not o.random_enabled:
            w.append('random отключён: шифрование детерминировано — '
                     'одинаковые данные дают одинаковый пакет.')
        if not o.params_enabled:
            w.append('params не сохраняются в файл: расшифровать можно '
                     'только с теми же параметрами Argon2id.')
    return w


def _spec(st: Settings):
    return CIPHER_BY_NAME[st.cipher].spec


def encrypt(st: Settings, data: bytes,
            progress: Optional[Callable[[str, Optional[float]], None]] = None,
            ) -> Result:
    """Зашифровать данные согласно настройкам (по умолчанию — контейнер v2)."""
    st.validate()
    warnings = _collect_warnings(st)
    if st.mode == 'siv':
        res: SivResult = encrypt_siv2(
            _spec(st), st.cipher, st.source, data,
            st.effective_siv_options(), progress_cb=progress,
            backend=st.backend, threads=st.threads)
    else:
        res = encrypt_ecb2(
            _spec(st), st.cipher, st.source, data,
            st.effective_siv_options(), progress_cb=progress,
            backend=st.backend)
    return Result(res.data, st.cipher, st.mode, res.fields, res.meta,
                  warnings)


def decrypt(st: Settings, data: bytes,
            progress: Optional[Callable[[str, Optional[float]], None]] = None,
            ) -> Result:
    """Расшифровать данные.

    Контейнер распознаётся автоматически: шифр, режим, KDF-параметры и
    состав полей берутся ИЗ файла (настройки панели игнорируются — кроме
    пароля/ключа).
    """
    st.validate()
    if not ct.is_container(data):
        raise PacketFormatError(
            'данные не распознаны как контейнер Kazual v2: файл повреждён, '
            'обрезан или создан другой программой')
    return _decrypt_v2(st, data, progress)


def _decrypt_v2(st: Settings, data: bytes, progress) -> Result:
    info = ct.parse_header(data, file_size=len(data))
    cipher_name = info.cipher_name
    mode = 'siv' if info.mode == ct.MODE_SIV else 'ecb'
    warnings = _collect_warnings(st, cipher=cipher_name, mode=mode)
    opts = st.effective_siv_options()
    if info.mode == ct.MODE_SIV:
        res: SivResult = decrypt_siv2(st.source, data, opts,
                                      progress_cb=progress,
                                      backend=st.backend, threads=st.threads,
                                      info=info)
    else:
        res = decrypt_ecb2(st.source, data, opts, progress_cb=progress,
                           backend=st.backend, info=info)
    res.meta['detected'] = info.describe()
    if info.kdf_params is None:
        res.meta['params_note'] = ('в файле нет параметров KDF — '
                                   'использованы параметры из настроек')
    return Result(res.data, cipher_name, mode, res.fields, res.meta,
                  warnings)
