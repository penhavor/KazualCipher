# -*- coding: utf-8 -*-
"""Конфигурации: папка configs/ в программе, default.json, снимки, санитизация."""

import json

import pytest

from kazual import config as c


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    cfgs = tmp_path / 'configs'
    cfgs.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(c, 'configs_dir', lambda: cfgs)
    return cfgs


def test_defaults_when_no_file():
    d = c.load()
    assert d == c.DEFAULTS
    assert d['window']['maximized'] is False


def test_list_configs_default_first(_isolated):
    (_isolated / 'bbb.json').write_text('{}', encoding='utf-8')
    (_isolated / 'aaa.json').write_text('{}', encoding='utf-8')
    assert c.list_configs() == ['default', 'aaa', 'bbb']


def test_save_load_named(_isolated):
    d = c.load()
    d['brand_text'] = 'мой бренд'
    d['threads'] = 7
    c.save(d, 'профиль')
    assert (_isolated / 'профиль.json').is_file()
    d2 = c.load('профиль')
    assert d2['brand_text'] == 'мой бренд' and d2['threads'] == 7


def test_default_is_loaded_at_start(_isolated):
    d = c.load()
    d['cipher'] = 'Kazual-64'
    c.save(d, c.DEFAULT_NAME)
    assert c.load()['cipher'] == 'Kazual-64'


def test_sanitize_per_key(_isolated):
    (_isolated / 'default.json').write_text(json.dumps({
        'cipher': 'AES', 'mode': 'gcm', 'threads': -5, 'leaf_mib': 9999,
        'kdf_m': 'zz', 'window': {'w': 10}}, ), encoding='utf-8')
    d = c.load()
    assert d['cipher'] == 'Kazual-512' and d['mode'] == 'siv'
    assert d['threads'] == 0 and d['leaf_mib'] == 64
    assert d['kdf_m'] == c.DEFAULTS['kdf_m']
    assert d['window']['w'] == 400            # санитизировано, остальное цело
    assert d['window']['h'] == c.DEFAULTS['window']['h']


def test_broken_file_renamed(_isolated):
    (_isolated / 'default.json').write_text('{битый', encoding='utf-8')
    d = c.load()
    assert d == c.DEFAULTS
    assert (_isolated / 'default.json.broken').is_file()


def test_reset_returns_and_saves_dict(_isolated):
    c.save({'cipher': 'Kazual-64'}, 'default')
    d = c.reset()
    assert isinstance(d, dict) and d['cipher'] == 'Kazual-512'
    assert c.load()['cipher'] == 'Kazual-512'


def test_password_never_saved(_isolated):
    d = c.load()
    c.save(d, 'x')
    data = json.loads((_isolated / 'x.json').read_text(encoding='utf-8'))
    assert 'password' not in data
