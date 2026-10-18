# -*- coding: utf-8 -*-
"""
kazual.kdf — вывод ключей из пароля: Argon2id (argon2-cffi) и параметры
в PHC-строке, которые укладываются в поле params SIV-пакета и читаются
обратно при расшифровке (пакет самоопределяем).

PHC-строка: ``$argon2id$v=19$m=65536,t=3,p=4``
    m — память, КиБ;  t — итерации;  p — параллелизм;  v — версия Argon2.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ['KdfParams', 'KdfParamsError', 'derive_key', 'DEFAULT_KDF_PARAMS']


class KdfParamsError(ValueError):
    """Некорректные параметры KDF или неверная PHC-строка."""


# Границы из спецификации Argon2 (RFC 9106):
_ARGON2_MIN_MEMORY_KIB_PER_LANE = 8
_ARGON2_MAX_PARALLELISM = 2 ** 24 - 1
_ARGON2_MAX_MEMORY_KIB = 2 ** 32 - 1
_ARGON2_MAX_ITERATIONS = 2 ** 32 - 1

_PHC_RE = re.compile(
    r'^\$argon2id\$v=(?P<v>\d+)\$m=(?P<m>\d+),t=(?P<t>\d+),p=(?P<p>\d+)$'
)


@dataclass(frozen=True)
class KdfParams:
    """Параметры Argon2id (PHC-стиль). Неизменяемы — безопасно передавать."""

    memory_kib: int = 65536   # m: память в КиБ (64 МиБ по умолчанию)
    iterations: int = 3       # t: число проходов
    parallelism: int = 4      # p: число «дорожек»
    version: int = 19         # v: версия алгоритма (0x13)

    def validate(self) -> None:
        """Проверить границы Argon2; при нарушении — KdfParamsError."""
        if not isinstance(self.memory_kib, int) or not (
                _ARGON2_MIN_MEMORY_KIB_PER_LANE * self.parallelism
                <= self.memory_kib <= _ARGON2_MAX_MEMORY_KIB):
            raise KdfParamsError(
                'm должно быть в диапазоне %d…%d КиБ (m ≥ 8·p)'
                % (_ARGON2_MIN_MEMORY_KIB_PER_LANE * max(1, self.parallelism),
                   _ARGON2_MAX_MEMORY_KIB))
        if not isinstance(self.iterations, int) or not (
                1 <= self.iterations <= _ARGON2_MAX_ITERATIONS):
            raise KdfParamsError('t должно быть в диапазоне 1…%d'
                                 % _ARGON2_MAX_ITERATIONS)
        if not isinstance(self.parallelism, int) or not (
                1 <= self.parallelism <= _ARGON2_MAX_PARALLELISM):
            raise KdfParamsError('p должно быть в диапазоне 1…%d'
                                 % _ARGON2_MAX_PARALLELISM)
        if self.version != 19:
            raise KdfParamsError('поддерживается только версия Argon2 v=19 '
                                 '(дано v=%s)' % self.version)

    def phc_string(self) -> str:
        """PHC-строка параметров: то, что кладётся в поле params пакета."""
        self.validate()
        return '$argon2id$v=%d$m=%d,t=%d,p=%d' % (
            self.version, self.memory_kib, self.iterations, self.parallelism)

    @classmethod
    def parse(cls, s) -> 'KdfParams':
        """Разбор PHC-строки. Принимает str или bytes."""
        if isinstance(s, (bytes, bytearray)):
            try:
                s = bytes(s).decode('ascii')
            except UnicodeDecodeError:
                raise KdfParamsError('params: не-ASCII байты в PHC-строке')
        s = s.strip()
        m = _PHC_RE.match(s)
        if not m:
            raise KdfParamsError(
                'params: ожидалась PHC-строка вида '
                '"$argon2id$v=19$m=65536,t=3,p=4", дано "%s"' % s)
        p = cls(version=int(m.group('v')), memory_kib=int(m.group('m')),
                iterations=int(m.group('t')), parallelism=int(m.group('p')))
        p.validate()
        return p

    def describe(self) -> str:
        """Человекочитаемое описание для GUI."""
        mem = self.memory_kib
        mem_s = ('%d МиБ' % (mem // 1024)) if mem >= 1024 and mem % 1024 == 0 \
            else ('%g МиБ' % (mem / 1024) if mem >= 1024 else '%d КиБ' % mem)
        return 'Argon2id: память %s, итераций %d, параллелизм %d' % (
            mem_s, self.iterations, self.parallelism)


DEFAULT_KDF_PARAMS = KdfParams()


def derive_key(password, salt: bytes, params: KdfParams,
               out_len: int) -> bytes:
    """Argon2id(password, salt) → out_len байт ключевого материала.

    Принимает пароль как str (кодируется в UTF-8) или bytes.
    """
    try:
        from argon2.low_level import hash_secret_raw, Type
    except ImportError as exc:                       # pragma: no cover
        raise RuntimeError(
            'не установлен argon2-cffi — выполните: '
            'pip install -r requirements.txt') from exc
    if isinstance(password, str):
        password = password.encode('utf-8')
    if not password:
        raise KdfParamsError('пустой пароль')
    if out_len < 1:
        raise ValueError('out_len должно быть ≥ 1')
    params.validate()
    try:
        return hash_secret_raw(
            secret=bytes(password), salt=bytes(salt),
            time_cost=params.iterations, memory_cost=params.memory_kib,
            parallelism=params.parallelism, hash_len=out_len,
            type=Type.ID, version=params.version)
    except Exception as exc:
        raise KdfParamsError('Argon2id отклонил параметры: %s' % exc) from exc
