# -*- coding: utf-8 -*-
"""
kazual.config — конфигурации программы. ВСЕ состояния программы живут
в JSON-файлах внутри папки программы: KazualCipher/configs/.

    configs/default.json   загружается при старте («конфиг по умолчанию»)
    configs/<имя>.json     именованные снимки состояния (профили)

Правила:
  * любое изменение состояния (настройки, вкладка, правила вывода, размер
    и развёрнутость окна) сохраняется АВТОМАТИЧЕСКИ и в реальном времени
    в ТЕКУЩИЙ конфиг (по умолчанию — default.json);
  * «Сохранить как…» — снимок текущего состояния под новым именем;
  * «Загрузить» — применить файл к программе (он становится текущим);
  * «Сделать по умолчанию» — текущий конфиг становится загружаемым
    при старте (копируется в default.json);
  * «Сбросить к встроенным» — встроенные значения из кода применяются
    к виджетам И сохраняются; испорченный файл не фатален: переименовруется
    в *.broken, стартуем со встроенных значений;
  * пароль не сохраняется НИКОГДА.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

__all__ = ['DEFAULTS', 'KDF_PRESETS', 'ConfigError', 'configs_dir',
           'default_path', 'list_configs', 'load', 'save', 'reset',
           'deep_merge', 'DEFAULT_NAME']

APP_NAME = 'KazualCipher'
DEFAULT_NAME = 'default'

DEFAULTS = {
    # --- шифр и режим ---
    'cipher': 'Kazual-512',           # Kazual-512 | Kazual-64
    'mode': 'siv',                    # siv | ecb
    # --- ключ (пароль не сохраняется никогда) ---
    'key_source': 'password',         # password | hex
    'raw_key_hex': '',
    # --- Argon2id ---
    'kdf_preset': 'balanced',         # balanced | fast | strong | custom
    'kdf_m': 65536,                   # память, КиБ
    'kdf_t': 3,                       # итерации
    'kdf_p': 4,                       # параллелизм
    # --- пакет (единственный формат — контейнер v2) ---
    'brand_text': '',                 # текст-метка в заголовке ('' = нет)
    'params_enabled': True,           # PHC-параметры Argon2id в файл
    'random_enabled': True,           # случайная соль (off = детерминизм)
    # --- производительность ---
    'backend': 'auto',                # auto | native | cpu | gpu | scalar
    'threads': 0,                     # 0 = все ядра
    'leaf_mib': 4,                    # лист tree-MAC, МиБ
    'small_file_mib': 32,             # файлы до этого размера — в памяти
    # --- файлы ---
    'out_rule': 'next',               # next = рядом с источником | folder
    'out_dir': '',
    'overwrite': False,               # иначе свободное имя «… (1)»
    # --- интерфейс (полное состояние окна) ---
    'warning_ack': False,             # показано ли предупреждение 1 раз
    'tab': 0,
    'advanced_open': False,
    'window': {'w': 1280, 'h': 880, 'x': None, 'y': None,
               'maximized': False, 'fullscreen': False},
}

KDF_PRESETS = {
    'balanced': (65536, 3, 4),        # 64 МиБ — обычный пароль
    'fast': (1024, 2, 1),             # быстро (тесты, слабые машины)
    'strong': (262144, 4, 4),         # 256 МиБ — параноидально
}


class ConfigError(Exception):
    """Ошибка чтения/записи конфига (GUI показывает текст дословно)."""


# ---------------------------------------------------------------------------
# Пути: всё внутри папки программы
# ---------------------------------------------------------------------------

def program_dir() -> Path:
    """Корень программы (там же, где main.py)."""
    return Path(__file__).resolve().parents[1]


def configs_dir() -> Path:
    """KazualCipher/configs/ — единственное место хранения конфигов."""
    return program_dir() / 'configs'


def default_path() -> Path:
    return configs_dir() / (DEFAULT_NAME + '.json')


def config_path(name: str) -> Path:
    name = os.path.basename(name)
    if not name.endswith('.json'):
        name += '.json'
    return configs_dir() / name


def list_configs() -> List[str]:
    """Имена конфигов (без .json), default всегда первый."""
    d = configs_dir()
    names = []
    if d.is_dir():
        names = sorted(p.stem for p in d.glob('*.json'))
    if DEFAULT_NAME in names:
        names.remove(DEFAULT_NAME)
    return [DEFAULT_NAME] + names


def _legacy_user_config() -> Optional[Path]:
    """Старое расположение (до 1.1.1) — для одноразовой миграции."""
    if sys.platform == 'win32':
        base = os.environ.get('APPDATA') or str(Path.home() / 'AppData'
                                                / 'Roaming')
        p = Path(base) / APP_NAME / 'config.json'
    elif sys.platform == 'darwin':
        p = Path.home() / 'Library' / 'Application Support' / APP_NAME \
            / 'config.json'
    else:
        base = os.environ.get('XDG_CONFIG_HOME') or str(Path.home() / '.config')
        p = Path(base) / APP_NAME.lower() / 'config.json'
    return p if p.is_file() else None


def _migrate_once() -> None:
    """Перенести старый пользовательский конфиг в configs/default.json."""
    if default_path().is_file():
        return
    old = _legacy_user_config()
    if old is not None:
        configs_dir().mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(old, default_path())
            old.rename(old.with_suffix('.json.migrated'))
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Чтение/запись
# ---------------------------------------------------------------------------

def deep_merge(base: dict, override) -> dict:
    """Рекурсивно наложить override на копию base (нет ключа → из base)."""
    out = copy.deepcopy(base)
    if not isinstance(override, dict):
        return out
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _int(cfg: dict, key: str, default: int, lo: int, hi: int) -> int:
    try:
        return min(hi, max(lo, int(cfg.get(key, default))))
    except (TypeError, ValueError):
        return default


def _sanitize(cfg: dict) -> dict:
    """Каждый ключ правится независимо: одна битая запись не ломает остальные."""
    if cfg.get('cipher') not in ('Kazual-512', 'Kazual-64'):
        cfg['cipher'] = DEFAULTS['cipher']
    if cfg.get('mode') not in ('siv', 'ecb'):
        cfg['mode'] = DEFAULTS['mode']
    if cfg.get('key_source') not in ('password', 'hex'):
        cfg['key_source'] = DEFAULTS['key_source']
    if cfg.get('backend') not in ('auto', 'native', 'cpu', 'gpu', 'scalar'):
        cfg['backend'] = DEFAULTS['backend']
    if cfg.get('kdf_preset') not in ('balanced', 'fast', 'strong', 'custom'):
        cfg['kdf_preset'] = DEFAULTS['kdf_preset']
    if cfg.get('out_rule') not in ('next', 'folder'):
        cfg['out_rule'] = DEFAULTS['out_rule']
    cfg['threads'] = _int(cfg, 'threads', DEFAULTS['threads'], 0, 512)
    cfg['leaf_mib'] = _int(cfg, 'leaf_mib', DEFAULTS['leaf_mib'], 1, 64)
    cfg['small_file_mib'] = _int(cfg, 'small_file_mib',
                                 DEFAULTS['small_file_mib'], 1, 4096)
    cfg['kdf_m'] = _int(cfg, 'kdf_m', DEFAULTS['kdf_m'], 8, 4 * 1024 * 1024)
    cfg['kdf_t'] = _int(cfg, 'kdf_t', DEFAULTS['kdf_t'], 1, 1000)
    cfg['kdf_p'] = _int(cfg, 'kdf_p', DEFAULTS['kdf_p'], 1, 32)
    cfg['tab'] = _int(cfg, 'tab', DEFAULTS['tab'], 0, 9)
    for k in ('params_enabled', 'random_enabled', 'overwrite',
              'warning_ack', 'advanced_open'):
        cfg[k] = bool(cfg.get(k, DEFAULTS[k]))
    for k in ('brand_text', 'raw_key_hex', 'out_dir'):
        if not isinstance(cfg.get(k, ''), str):
            cfg[k] = ''
    if not isinstance(cfg.get('window'), dict):
        cfg['window'] = copy.deepcopy(DEFAULTS['window'])
    else:
        w = cfg['window']
        for k, dflt in (('w', 1280), ('h', 880)):
            w[k] = _int(w, k, dflt, 400, 8192)
        for k in ('x', 'y'):
            try:
                w[k] = None if w.get(k) is None else int(w.get(k))
            except (TypeError, ValueError):
                w[k] = None
        w['maximized'] = bool(w.get('maximized', False))
        w['fullscreen'] = bool(w.get('fullscreen', False))
    return cfg


def load(name: Optional[str] = None, quiet: bool = True) -> dict:
    """Загрузить конфиг по имени (None → default). Всегда полный словарь:
    отсутствующие ключи дополняются встроенными значениями."""
    _migrate_once()
    p = config_path(name or DEFAULT_NAME)
    if not p.is_file():
        return copy.deepcopy(DEFAULTS)
    try:
        with open(p, 'r', encoding='utf-8') as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            raise ValueError('корень конфига — не объект')
        return _sanitize(deep_merge(DEFAULTS, raw))
    except Exception as exc:                               # noqa: BLE001
        if not quiet:
            raise ConfigError('не удалось прочитать %s: %s' % (p, exc)) \
                from exc
        try:
            p.rename(p.with_suffix('.json.broken'))
        except OSError:
            pass
        return copy.deepcopy(DEFAULTS)


def save(cfg: dict, name: Optional[str] = None) -> Path:
    """Атомарно сохранить конфиг под именем (None → default)."""
    cfg = _sanitize(deep_merge(DEFAULTS, cfg))
    p = config_path(name or DEFAULT_NAME)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix='.cfg-',
                               suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return p


def reset(name: Optional[str] = None) -> dict:
    """Сбросить к встроенным значениям: вернуть словарь И сохранить его."""
    cfg = copy.deepcopy(DEFAULTS)
    save(cfg, name)
    return cfg
