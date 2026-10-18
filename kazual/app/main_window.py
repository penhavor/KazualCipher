# -*- coding: utf-8 -*-
"""Главное окно KazualCipher: сайдбар настроек + страницы-вкладки."""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import Qt, QSettings, QTimer
from PySide6.QtGui import QAction, QIcon, QKeySequence
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QMainWindow, QMessageBox,
                               QProgressBar, QScrollArea, QTabWidget,
                               QVBoxLayout, QWidget)

from .. import __version__, engine
from . import theme
from .sidebar import SettingsPanel
from .pages.encrypt_page import EncryptPage
from .pages.decrypt_page import DecryptPage
from .pages.packet_page import PacketPage
from .pages.about_page import AboutPage
from .workers import TaskWorker

_ASSETS = Path(__file__).resolve().parents[2] / 'assets'


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('KazualCipher — Kazual-512 / Kazual-64')
        self.resize(1240, 820)
        self.setMinimumSize(1040, 700)
        icon = _ASSETS / 'icon.svg'
        if icon.is_file():
            self.setWindowIcon(QIcon(str(icon)))

        self._worker: TaskWorker | None = None
        self._busy_page = None
        self._ready = False

        self._build_ui()
        self._build_menu()
        self._load_state()
        self._prewarm_timer = QTimer(self)
        self._prewarm_timer.setInterval(250)
        self._prewarm_timer.timeout.connect(self._check_prewarm)
        QTimer.singleShot(120, self._start_prewarm)

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ---- шапка ----
        header = QWidget()
        header.setStyleSheet('background: %s; border-bottom: 1px solid %s;'
                             % (theme.PANEL, theme.BORDER))
        h = QHBoxLayout(header)
        h.setContentsMargins(18, 10, 18, 10)
        logo = QLabel()
        pix_path = _ASSETS / 'icon.svg'
        if pix_path.is_file():
            from PySide6.QtGui import QPixmap
            pix = QPixmap(str(pix_path))
            if not pix.isNull():
                logo.setPixmap(pix.scaled(
                    40, 40,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation))
        title_box = QVBoxLayout()
        title_box.setSpacing(0)
        t = QLabel('KazualCipher')
        t.setProperty('kind', 'title')
        s = QLabel('экспериментальные шифры Kazual-512 / Kazual-64 · режимы '
                   'SIV и ECB')
        s.setProperty('kind', 'subtitle')
        title_box.addWidget(t)
        title_box.addWidget(s)
        h.addWidget(logo)
        h.addSpacing(10)
        h.addLayout(title_box)
        h.addStretch(1)
        chip = QLabel('не для защиты реальных данных')
        chip.setProperty('kind', 'chip')
        chip.setToolTip('Экспериментальная учебная конструкция: не проходила '
                        'независимого криптоанализа. Подробности — вкладка '
                        '«О шифре».')
        ver = QLabel('v%s' % __version__)
        ver.setProperty('kind', 'chipVersion')
        h.addWidget(chip)
        h.addSpacing(8)
        h.addWidget(ver)
        root.addWidget(header)

        # ---- тело: сайдбар + вкладки ----
        body = QHBoxLayout()
        body.setContentsMargins(14, 12, 14, 8)
        body.setSpacing(14)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFixedWidth(356)
        self.sidebar = SettingsPanel()
        scroll.setWidget(self.sidebar)
        body.addWidget(scroll)

        self.tabs = QTabWidget()
        self.page_encrypt = EncryptPage(self)
        self.page_decrypt = DecryptPage(self)
        self.page_packet = PacketPage(self)
        self.page_about = AboutPage(self)
        self.tabs.addTab(self.page_encrypt, 'Шифрование')
        self.tabs.addTab(self.page_decrypt, 'Расшифрование')
        self.tabs.addTab(self.page_packet, 'Пакет')
        self.tabs.addTab(self.page_about, 'О шифре')
        body.addWidget(self.tabs, 1)
        root.addLayout(body, 1)

        # ---- статус-бар ----
        sb = self.statusBar()
        self.lbl_status = QLabel('готово')
        sb.addWidget(self.lbl_status, 1)
        self.status_progress = QProgressBar()
        self.status_progress.setFixedWidth(160)
        self.status_progress.setRange(0, 0)
        self.status_progress.setVisible(False)
        sb.addPermanentWidget(self.status_progress)

        self.sidebar.changed.connect(self._on_settings_changed)

    def _build_menu(self):
        m_file = self.menuBar().addMenu('&Файл')
        act_spec = QAction('Открыть спецификацию…', self)
        act_spec.triggered.connect(self.page_about._open_spec)
        m_file.addAction(act_spec)
        m_file.addSeparator()
        act_quit = QAction('Выход', self)
        act_quit.setShortcut(QKeySequence.StandardKey.Quit)
        act_quit.triggered.connect(self.close)
        m_file.addAction(act_quit)

        m_help = self.menuBar().addMenu('&Справка')
        act_about_cipher = QAction('О шифре и режимах', self)
        act_about_cipher.triggered.connect(
            lambda: self.tabs.setCurrentWidget(self.page_about))
        m_help.addAction(act_about_cipher)
        act_about = QAction('О программе…', self)
        act_about.triggered.connect(self._about_dialog)
        m_help.addAction(act_about)

    def _about_dialog(self):
        QMessageBox.about(
            self, 'О программе',
            '<h3>KazualCipher v%s</h3>'
            '<p>Графическая оболочка семейства экспериментальных блочных '
            'шифров Kazual (Kazual-512, Kazual-64) с режимами SIV и ECB.</p>'
            '<p style="color:%s"><b>Предупреждение:</b> экспериментальная '
            'учебная конструкция, не проходила независимого криптоанализа и '
            'не предназначена для защиты реальных данных.</p>'
            '<p>Python + PySide6 · MIT License</p>'
            % (__version__, theme.WARNING))

    # ------------------------------------------------------- task running
    def is_busy(self) -> bool:
        return self._worker is not None

    def run_task(self, fn, on_ok, on_err, page=None):
        """Запустить fn(progress_cb) в фоне; UI блокируется до завершения."""
        if self.is_busy():
            return
        page = page or self.tabs.currentWidget()
        self._busy_page = page
        self.sidebar.setEnabled(False)
        if hasattr(page, 'set_busy'):
            page.set_busy(True)
        self.status_progress.setVisible(True)

        w = TaskWorker(fn, self)
        w.progress.connect(self._on_task_progress)
        w.finished_ok.connect(lambda r: self._finish_task(on_ok, r, None))
        w.failed.connect(lambda e: self._finish_task(on_err, None, e))
        self._worker = w
        w.start()

    def _on_task_progress(self, stage, frac):
        page = self._busy_page
        if page is not None and hasattr(page, 'on_progress'):
            page.on_progress(stage, frac)
        else:
            self.set_status(stage)

    def _finish_task(self, cb, result, exc):
        w = self._worker
        self._worker = None
        page = self._busy_page
        self._busy_page = None
        self.sidebar.setEnabled(True)
        if page is not None and hasattr(page, 'set_busy'):
            page.set_busy(False)
        self.status_progress.setVisible(False)
        if w is not None:
            w.deleteLater()
        if exc is not None:
            cb(exc)
        else:
            cb(result)

    def cancel_task(self):
        if self._worker is not None:
            self._worker.cancel()
            self.set_status('отмена — жду ближайшую контрольную точку…')

    def set_status(self, text: str):
        self.lbl_status.setText(text)

    def refresh_packet_page(self, result: engine.Result = None):
        self.page_packet.refresh(result)

    def _on_settings_changed(self):
        self.page_packet.refresh()
        self._save_state_debounced()

    # ------------------------------------------------------------ prewarm
    def _start_prewarm(self):
        self.set_status('инициализация таблиц шифра…')

        def work():
            try:
                import kazual.cipher.selfcheck        # noqa: F401
            except Exception:
                pass
            self._ready = True

        self._prewarm_thread = threading.Thread(target=work, daemon=True)
        self._prewarm_thread.start()
        self._prewarm_timer.start()

    def _check_prewarm(self):
        if self._ready:
            self._prewarm_timer.stop()
            from PySide6.QtCore import QMetaObject, Q_ARG
            try:
                import numpy
                extra = 'NumPy ✓'
            except ImportError:
                extra = 'NumPy не установлен — будет скалярный путь (медленнее)'
            self.set_status('готово · %s' % extra)

    # -------------------------------------------------------- persistence
    def _settings_obj(self) -> QSettings:
        return QSettings('KazualCipher', 'KazualCipher')

    def _save_state_debounced(self):
        if not hasattr(self, '_save_timer'):
            self._save_timer = QTimer(self)
            self._save_timer.setSingleShot(True)
            self._save_timer.setInterval(600)
            self._save_timer.timeout.connect(self._save_state)
        self._save_timer.start()

    def _save_state(self):
        q = self._settings_obj()
        state = self.sidebar.save_state()
        for k, v in state.items():
            q.setValue('ui/' + k, v)
        q.setValue('ui/tab', self.tabs.currentIndex())
        q.setValue('ui/geometry', self.saveGeometry())
        q.sync()

    def _load_state(self):
        q = self._settings_obj()
        if q.contains('ui/cipherRow'):
            state = {k[3:]: q.value(k) for k in q.allKeys()
                     if k.startswith('ui/') and k != 'ui/tab'
                     and k != 'ui/geometry'}
            try:
                self.sidebar.load_state(state)
            except (TypeError, ValueError):
                self.sidebar.set_defaults()
            tab = q.value('ui/tab', 0)
            try:
                self.tabs.setCurrentIndex(int(tab))
            except (TypeError, ValueError):
                pass
            geo = q.value('ui/geometry')
            if geo is not None:
                self.restoreGeometry(geo)
        else:
            self.sidebar.set_defaults()

    def closeEvent(self, event):                              # noqa: N802
        self._save_state()
        if self._worker is not None:
            self._worker.cancel()
            self._worker.wait(1500)
        event.accept()
