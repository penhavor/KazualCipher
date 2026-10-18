# -*- coding: utf-8 -*-
"""
Слой диспетчеризации ускорителей.

Все «горячие» модули (расписание ключей, MAC, потоковое шифрование)
обращаются сюда, а не напрямую к эталонному чистому Python. Если доступно
нативное ускорение (numba JIT, см. native.py) — используется оно
(побитово идентично эталону, проверяется тестами); иначе — эталонный путь.

Регистрация хуков: native.py при успешной инициализации заполняет HOOKS;
этот модуль лениво загружает native по первому обращению (или по warmup()).
"""

from __future__ import annotations

import threading

__all__ = ['HOOKS', 'available', 'warmup', 'status_line',
           'gorn_hash', 'gorn_expand', 'native_hasher', 'cipher_for',
           'set_threads', 'threads_info']

# Хуки, которые заполняет native.py:
#   'gorn_hash'(msg: bytes, tag: bytes) -> bytes
#   'gorn_expand'(seed: bytes, tag: bytes, nbytes: int) -> bytes
#   'hasher'(tag: bytes) -> объект с .update(bytes)/.digest() (побитово =
#              gorn.GornHasher)
#   'cipher_for'(spec, km) -> NativeCipher | None
#   'set_threads'(n: int) -> None
#   'threads'() -> (current, max)
#   'warmup'() -> None  (прекомпиляция ядер в фоне)
HOOKS: dict = {}

_lock = threading.Lock()
_load_state = {'tried': False, 'error': None}


def _ensure_loaded() -> bool:
    """Лениво загрузить native.py (один раз; поток безопасно)."""
    if HOOKS:
        return True
    with _lock:
        if HOOKS:
            return True
        if _load_state['tried']:
            return False
        _load_state['tried'] = True
        try:
            from . import native  # noqa: F401 (импорт регистрирует хуки)
        except Exception as exc:                       # noqa: BLE001
            _load_state['error'] = exc
            return False
    return bool(HOOKS)


def available() -> bool:
    """Доступно ли нативное ускорение (numba)."""
    return _ensure_loaded()


def warmup() -> None:
    """Загрузить native и скомпилировать ядра (вызывается из фонового потока)."""
    if _ensure_loaded() and 'warmup' in HOOKS:
        HOOKS['warmup']()


def status_line() -> str:
    """Короткое описание ускорителя для статус-бара GUI / bench."""
    if _ensure_loaded():
        try:
            cur, mx = HOOKS['threads']()
            return 'numba JIT · %d/%d потоков' % (cur, mx)
        except Exception:                              # noqa: BLE001
            return 'numba JIT'
    if _load_state['error'] is not None:
        return 'эталонный Python-путь (numba недоступен: %s)' % (
            type(_load_state['error']).__name__)
    return 'эталонный Python-путь'


# ---------------------------------------------------------------------------
# Диспетчеры
# ---------------------------------------------------------------------------

def gorn_hash(msg: bytes, tag: bytes = b'') -> bytes:
    if _ensure_loaded():
        return HOOKS['gorn_hash'](msg, tag)
    from .gorn import gorn_hash as _ref
    return _ref(msg, tag)


def gorn_expand(seed: bytes, tag: bytes, nbytes: int) -> bytes:
    if _ensure_loaded():
        return HOOKS['gorn_expand'](seed, tag, nbytes)
    from .gorn import gorn_expand as _ref
    return _ref(seed, tag, nbytes)


def native_hasher(tag: bytes = b''):
    """Инкрементальный хэшер: нативный, если доступен, иначе эталонный."""
    if _ensure_loaded() and 'hasher' in HOOKS:
        return HOOKS['hasher'](tag)
    from .gorn import GornHasher
    return GornHasher(tag)


def cipher_for(spec, km):
    """Нативный контекст шифра для (spec, km) или None (нет ускорения)."""
    if _ensure_loaded() and 'cipher_for' in HOOKS:
        try:
            return HOOKS['cipher_for'](spec, km)
        except Exception:                              # noqa: BLE001
            return None
    return None


def set_threads(n: int) -> None:
    """Число потоков prange (0 = все ядра)."""
    if _ensure_loaded() and 'set_threads' in HOOKS:
        HOOKS['set_threads'](int(n))


def threads_info():
    if _ensure_loaded() and 'threads' in HOOKS:
        try:
            return HOOKS['threads']()
        except Exception:                              # noqa: BLE001
            pass
    import os
    n = os.cpu_count() or 1
    return (n, n)
