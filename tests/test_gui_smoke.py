# -*- coding: utf-8 -*-
"""Смоук-тест GUI (offscreen): окно собирается, полный цикл работает.

Помечен маркером gui: пропускается, если нет PySide6 или дисплея/платформы.
"""

import time

import pytest

pytest.importorskip('PySide6')

from PySide6.QtCore import Qt                      # noqa: E402
from PySide6.QtWidgets import QApplication, QLabel  # noqa: E402


@pytest.fixture(scope='module')
def app():
    import os
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    a = QApplication.instance() or QApplication([])
    from kazual.app.theme import apply_theme
    apply_theme(a)
    return a


@pytest.fixture
def window(app):
    from kazual.app.main_window import MainWindow
    w = MainWindow()
    w.show()
    app.processEvents()
    yield w
    w.close()
    app.processEvents()


def _wait(window, limit=120):
    t0 = time.time()
    while window.is_busy() and time.time() - t0 < limit:
        QApplication.processEvents()
        time.sleep(0.02)
    QApplication.processEvents()
    assert not window.is_busy(), 'воркер не завершился вовремя'


@pytest.mark.gui
def test_window_builds(app, window):
    assert window.windowTitle().startswith('KazualCipher')
    assert window.tabs.count() == 4
    assert window.sidebar.lst_cipher.count() == 2
    assert window.sidebar.lst_mode.count() == 2


@pytest.mark.gui
def test_full_cycle_siv(app, window):
    w = window
    w.sidebar.lst_cipher.setCurrentRow(1)          # Kazual-64 — быстрее
    w.sidebar.cmb_preset.setCurrentIndex(1)        # быстрый KDF
    w.sidebar.ed_password.setText('gui-test')
    w.page_encrypt.in_text.setPlainText('GUI round-trip: привет!')
    w.page_encrypt.run_encrypt()
    _wait(w)
    pkt = w.page_encrypt.out_text.toPlainText()
    assert len(pkt) > 40

    w.page_decrypt.in_text.setPlainText(pkt)
    w.page_decrypt.run_decrypt()
    _wait(w)
    assert 'GUI round-trip: привет!' in w.page_decrypt.out_text.toPlainText()
    labels = [lbl.text()
              for i in range(w.page_decrypt.banner_box.count())
              for lbl in w.page_decrypt.banner_box.itemAt(i).widget()
              .findChildren(QLabel)]
    assert any('Подлинность подтверждена' in t for t in labels)


@pytest.mark.gui
def test_packet_page_example(app, window):
    w = window
    w.sidebar.lst_cipher.setCurrentRow(1)
    w.sidebar.cmb_preset.setCurrentIndex(1)
    w.sidebar.ed_password.setText('gui-test')
    w.tabs.setCurrentIndex(2)
    w.page_packet._build_example()
    _wait(w)
    assert w.page_packet.table.rowCount() >= 6     # 5 полей + ИТОГО
    w.sidebar.ck_random.setChecked(False)
    QApplication.processEvents()
    w.sidebar.ck_random.setChecked(True)


@pytest.mark.gui
def test_about_page_renders(app, window):
    w = window
    w.tabs.setCurrentIndex(3)
    QApplication.processEvents()
    html = w.page_about.findChild(
        __import__('PySide6.QtWidgets', fromlist=['QTextBrowser'])
        .QTextBrowser).toHtml()
    assert 'Kazual' in html
