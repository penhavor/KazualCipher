# -*- coding: utf-8 -*-
"""Смоук-тест GUI (offscreen): окно собирается, конфиг применяется,
полный цикл «текст → пакет → текст» и автоопределение файлов работают.

Маркер gui: пропускается без PySide6. Таймауты короткие — всё, что может
зависнуть, считается провалом.
"""

import os
import time

import pytest

pytest.importorskip('PySide6')

from PySide6.QtWidgets import QApplication          # noqa: E402


@pytest.fixture(scope='module')
def app():
    import os
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    from PySide6.QtWidgets import QApplication
    a = QApplication.instance() or QApplication([])
    from kazual.app.theme import apply_theme
    apply_theme(a)
    return a


@pytest.fixture
def window(app, tmp_path, monkeypatch):
    # изоляция: конфиги теста живут в tmp, предупреждение уже «показано»
    from kazual import config as appconfig
    cfgs = tmp_path / 'configs'
    cfgs.mkdir(parents=True, exist_ok=True)
    (cfgs / 'default.json').write_text('{"warning_ack": true}',
                                       encoding='utf-8')
    monkeypatch.setattr(appconfig, 'configs_dir', lambda: cfgs)
    from kazual.app.main_window import MainWindow
    w = MainWindow()
    w.show()
    app.processEvents()
    yield w
    w.close()
    app.processEvents()


def _spin(app, window, limit=90):
    t0 = time.time()
    while window.is_busy() and time.time() - t0 < limit:
        app.processEvents()
        time.sleep(0.02)
    assert not window.is_busy(), 'операция не завершилась за %d с' % limit


def test_window_builds(window):
    assert window.tabs.count() == 5
    names = [window.tabs.tabText(i) for i in range(5)]
    assert names == ['Шифрование', 'Расшифрование', 'Пакет', 'Настройки',
                     'О шифре']


def test_config_roundtrip(window):
    window.sidebar.ed_password.setText('секрет')
    cfg = window.collect_config()
    assert cfg['cipher'] == 'Kazual-512'
    assert cfg['mode'] == 'siv'
    assert cfg['params_enabled'] is True
    window.apply_config(cfg, save=True)
    import kazual.config as cfgmod
    assert cfgmod.default_path().is_file()


def test_encrypt_text_cycle(app, window):
    pg = window.page_encrypt
    window.sidebar.ed_password.setText('пароль-из-теста')
    pg.in_text.setPlainText('привет из GUI-смоука!')
    pg.run_encrypt()
    _spin(app, window)
    assert pg._last_data, 'результат не появился'
    # расшифровка текстом
    dg = window.page_decrypt
    window.tabs.setCurrentWidget(dg)
    from kazual.app.pages import common
    dg.in_text.setPlainText(common.encode_output(pg._last_data, 'base64'))
    app.processEvents()
    dg.run_decrypt()
    _spin(app, window)
    assert dg.out_text.toPlainText() == 'привет из GUI-смоука!'
    # карточка определения показала v2
    assert dg.card.isVisible()


def test_decrypt_file_locks_panel(app, window, tmp_path):
    from kazual import engine, stream
    from kazual.keys import PasswordKey
    from kazual.kdf import KdfParams
    st = engine.Settings(cipher='Kazual-512', mode='siv',
                         source=PasswordKey('pw'),
                         kdf_params=KdfParams(1024, 1, 1),
                         small_file_mib=1)
    src = tmp_path / 'data.bin'
    src.write_bytes(os.urandom(64 * 10))
    dst = str(src) + '.kaz'
    rep = stream.encrypt_file(st, str(src), dst)
    assert rep.ok

    dg = window.page_decrypt
    window.tabs.setCurrentWidget(dg)
    dg.rb_files.setChecked(True)
    window.sidebar.ed_password.setText('pw')
    dg.files.add_paths([dst])
    app.processEvents()
    assert dg.card.isVisible(), 'карточка автоопределения не показана'
    assert window.sidebar.is_locked(), 'панель не заблокирована по файлу'
    # параметры подтянулись из файла
    assert window.sidebar.sp_m.value() == 1024
    # расшифровка в файл
    outdir = tmp_path / 'out'
    outdir.mkdir()
    dg.out_rules.rb_dir.setChecked(True)
    dg.out_rules.row_dir.set_path(str(outdir))
    dg.run_decrypt()
    _spin(app, window)
    assert (outdir / 'data.bin').read_bytes() == src.read_bytes()
    dg.files.clear()
    app.processEvents()
    assert not window.sidebar.is_locked()


def test_multi_file_encrypt(app, window, tmp_path):
    pg = window.page_encrypt
    window.sidebar.ed_password.setText('пачка')
    files = []
    for i in range(3):
        p = tmp_path / ('f%d.bin' % i)
        p.write_bytes(os.urandom(2048))
        files.append(str(p))
    pg.files.add_paths(files)
    pg.rb_files.setChecked(True)
    app.processEvents()
    pg.run_encrypt()
    _spin(app, window)
    for f in files:
        assert os.path.isfile(f + '.kaz'), 'нет результата для %s' % f


def test_settings_page_apply(window):
    sp = window.page_settings
    sp.sp_threads.setValue(3)
    sp.cmb_backend.setCurrentIndex(1)   # native
    cfg = sp.collect_config()
    assert cfg['threads'] == 3 and cfg['backend'] == 'native'
    window.apply_config(cfg)
    assert window.sidebar._threads == 3
    window.apply_config({'threads': 0, 'backend': 'auto'})


def test_lock_scoped_to_decrypt_tab(app, window, tmp_path):
    """Блокировка панели по файлу не мешает шифрованию на другой вкладке."""
    from kazual import engine, stream
    from kazual.keys import PasswordKey
    from kazual.kdf import KdfParams
    st = engine.Settings(cipher='Kazual-512', mode='siv',
                         source=PasswordKey('pw'),
                         kdf_params=KdfParams(1024, 1, 1), small_file_mib=1)
    src = tmp_path / 'd.bin'
    src.write_bytes(os.urandom(3000))
    dst = str(src) + '.kaz'
    assert stream.encrypt_file(st, str(src), dst).ok

    dg = window.page_decrypt
    window.tabs.setCurrentWidget(dg)
    dg.rb_files.setChecked(True)
    dg.files.add_paths([dst])
    app.processEvents()
    assert window.sidebar.is_locked()
    # уходим на шифрование — панель свободна
    window.tabs.setCurrentWidget(window.page_encrypt)
    app.processEvents()
    assert not window.sidebar.is_locked()
    assert window.sidebar.cmb_cipher.isEnabled()
    # возвращаемся — блокировка восстановлена
    window.tabs.setCurrentWidget(dg)
    app.processEvents()
    assert window.sidebar.is_locked()
