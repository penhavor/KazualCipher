# -*- coding: utf-8 -*-
"""Главное окно KazualCipher: сайдбар настроек + страницы-вкладки."""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QIcon, QKeySequence
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QMainWindow, QMessageBox,
                               QProgressBar, QScrollArea, QTabWidget,
                               QVBoxLayout, QWidget)

from .. import __version__, config as appconfig, engine
from . import theme
from .sidebar import SettingsPanel
from .pages.encrypt_page import EncryptPage
from .pages.decrypt_page import DecryptPage
from .pages.packet_page import PacketPage
from .pages.settings_page import SettingsPage
from .pages.about_page import AboutPage, WARNING_TEXT
from .workers import TaskWorker

_ASSETS = Path(__file__).resolve().parents[2] / 'assets'


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('KazualCipher %s — Kazual-512 / Kazual-64'
                            % __version__)
        self.setMinimumSize(1080, 720)
        for name in ('icon.png', 'icon.svg'):
            p = _ASSETS / name
            if p.is_file():
                self.setWindowIcon(QIcon(str(p)))
                break

        self.cfg = appconfig.load()
        self.cfg_name = appconfig.DEFAULT_NAME
        self._worker: TaskWorker | None = None
        self._busy_page = None
        self._ready = False

        self._build_ui()
        self._build_menu()
        self._apply_config_all(self.cfg)
        self._restore_window()
        self._prewarm()

        if not self.cfg.get('warning_ack'):
            QTimer.singleShot(200, self._show_first_run_warning)

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
        h.setContentsMargins(18, 8, 18, 8)
        logo = QLabel()
        for name in ('icon.png', 'icon.svg'):
            pix_path = _ASSETS / name
            if pix_path.is_file():
                from PySide6.QtGui import QPixmap
                pix = QPixmap(str(pix_path))
                if not pix.isNull():
                    logo.setPixmap(pix.scaled(
                        38, 38,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation))
                break
        title_box = QVBoxLayout()
        title_box.setSpacing(0)
        t = QLabel('KazualCipher')
        t.setProperty('kind', 'title')
        s = QLabel('шифры Kazual-512 / Kazual-64 · SIV и ECB · файлы любого '
                   'размера')
        s.setProperty('kind', 'subtitle')
        title_box.addWidget(t)
        title_box.addWidget(s)
        h.addWidget(logo)
        h.addSpacing(10)
        h.addLayout(title_box)
        h.addStretch(1)
        ver = QLabel('v%s' % __version__)
        ver.setProperty('kind', 'chipVersion')
        h.addWidget(ver)
        root.addWidget(header)

        # ---- тело: сайдбар + вкладки ----
        body = QHBoxLayout()
        body.setContentsMargins(14, 10, 14, 6)
        body.setSpacing(14)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFixedWidth(360)
        self.sidebar = SettingsPanel()
        scroll.setWidget(self.sidebar)
        body.addWidget(scroll)

        self.tabs = QTabWidget()
        self.page_encrypt = EncryptPage(self)
        self.page_decrypt = DecryptPage(self)
        self.page_packet = PacketPage(self)
        self.page_settings = SettingsPage(self)
        self.page_about = AboutPage(self)
        self.tabs.addTab(self.page_encrypt, 'Шифрование')
        self.tabs.addTab(self.page_decrypt, 'Расшифрование')
        self.tabs.addTab(self.page_packet, 'Пакет')
        self.tabs.addTab(self.page_settings, 'Настройки')
        self.tabs.addTab(self.page_about, 'О шифре')
        body.addWidget(self.tabs, 1)
        root.addLayout(body, 1)

        # ---- статус-бар ----
        sb = self.statusBar()
        self.lbl_status = QLabel('готово')
        sb.addWidget(self.lbl_status, 1)
        self.status_progress = QProgressBar()
        self.status_progress.setFixedWidth(150)
        self.status_progress.setRange(0, 0)
        self.status_progress.setVisible(False)
        sb.addPermanentWidget(self.status_progress)
        self.lbl_accel = QLabel('')
        self.lbl_accel.setProperty('kind', 'chipVersion')
        sb.addPermanentWidget(self.lbl_accel)

        self.sidebar.changed.connect(self._on_settings_changed)
        self.tabs.currentChanged.connect(self._on_tab_changed)

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

        m_cfg = self.menuBar().addMenu('&Настройки')
        a = QAction('Сохранить конфиг как…', self)
        a.triggered.connect(self.page_settings._save_as)
        m_cfg.addAction(a)
        a = QAction('Сделать текущий конфиг по умолчанию', self)
        a.triggered.connect(self.page_settings._make_default)
        m_cfg.addAction(a)
        m_cfg.addSeparator()
        a = QAction('Сбросить к встроенным значениям', self)
        a.triggered.connect(self.page_settings._reset)
        m_cfg.addAction(a)

        m_help = self.menuBar().addMenu('&Справка')
        a = QAction('О шифре и режимах', self)
        a.triggered.connect(
            lambda: self.tabs.setCurrentWidget(self.page_about))
        m_help.addAction(a)
        a = QAction('О программе…', self)
        a.triggered.connect(self._about_dialog)
        m_help.addAction(a)

    def _about_dialog(self):
        QMessageBox.about(
            self, 'О программе',
            '<h3>KazualCipher v%s</h3>'
            '<p>Графическая оболочка семейства экспериментальных блочных '
            'шифров Kazual (Kazual-512, Kazual-64): аутентифицированный '
            'режим SIV с самоопределяемым контейнером v2, ECB, потоковая '
            'обработка файлов любого размера, нативное ускорение (numba) '
            'на всех ядрах CPU.</p>'
            '<p>Python + PySide6 · MIT License</p>'
            % __version__)

    # ------------------------------------------------------- first launch
    def _show_first_run_warning(self):
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle('Прежде чем начать')
        box.setText('<b>Честно о безопасности.</b><br><br>%s<br><br>'
                    '<span style="color:%s">Полный текст всегда доступен на '
                    'вкладке «О шифре» — больше программа напоминать об этом '
                    'не будет.</span>'
                    % (WARNING_TEXT.replace('\n', ' '), theme.MUTED))
        box.setStandardButtons(QMessageBox.StandardButton.Ok)
        box.button(QMessageBox.StandardButton.Ok).setText('Понятно')
        box.exec()
        self.cfg['warning_ack'] = True
        self._save_config()

    # ------------------------------------------------------- task running
    def is_busy(self) -> bool:
        return self._worker is not None

    def run_task(self, fn, on_ok, on_err, page=None):
        """Запустить fn(progress_cb, cancel_event) в фоне."""
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
        # сайдбар снова активен; «замок» отдельных виджетов (параметры из
        # файла) при этом сохраняется — он управляется страницей расшифровки
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
        self._save_config_debounced()

    def _on_tab_changed(self, idx: int):
        """Блокировка панели по файлу действует только на вкладке
        «Расшифрование»: на прочих вкладках панель снова доступна, а при
        возврате определение повторяется и блокировка возвращается."""
        if self.tabs.widget(idx) is self.page_decrypt:
            self.page_decrypt.refresh_detection()
        else:
            self.sidebar.unlock()

    # ------------------------------------------------------------ config
    def _apply_config_all(self, cfg: dict):
        self.sidebar.apply_config(cfg)
        for p in (self.page_encrypt, self.page_decrypt, self.page_settings):
            if hasattr(p, 'apply_config'):
                p.apply_config(cfg)
        self.tabs.setCurrentIndex(min(int(cfg.get('tab', 0)),
                                      self.tabs.count() - 1))
        for pg in (self.page_encrypt, self.page_decrypt):
            pg.out_rules.set_defaults(cfg.get('out_rule', 'next'),
                                      cfg.get('out_dir', ''),
                                      cfg.get('overwrite', False))
        self.page_packet.refresh()

    def apply_config(self, cfg: dict, save: bool = False):
        """Полностью применить новый конфиг (загрузка из файла/сброс)."""
        self.cfg = cfg
        self._apply_config_all(cfg)
        self._apply_performance_now()
        if save:
            self._save_config()

    def collect_config(self) -> dict:
        cfg = dict(self.cfg)
        cfg.update(self.sidebar.collect_config())
        cfg.update(self.page_encrypt.out_rules.collect())
        cfg.update(self.page_settings.collect_config())
        cfg['tab'] = self.tabs.currentIndex()
        cfg['window'] = {
            'w': self.width(), 'h': self.height(),
            'x': self.x(), 'y': self.y(),
            'maximized': self.isMaximized(),
            'fullscreen': self.isFullScreen(),
        }
        return cfg

    def _save_config(self):
        """Реальное время: всё состояние → текущий файл конфига."""
        try:
            self.cfg = self.collect_config()
            appconfig.save(self.cfg, self.cfg_name)
        except OSError:
            pass

    # --- правила вывода: синхронизация страниц + автосохранение ---
    def on_out_rules_changed(self, source):
        if getattr(self, '_syncing_rules', False):
            return
        self._syncing_rules = True
        try:
            vals = source.collect()
            other = (self.page_decrypt.out_rules if source is
                     self.page_encrypt.out_rules
                     else self.page_encrypt.out_rules)
            other.set_defaults(vals['out_rule'], vals['out_dir'],
                               vals['overwrite'])
        finally:
            self._syncing_rules = False
        self._save_config_debounced()

    # --- геометрия окна — тоже часть конфига (реальное время) ---
    def resizeEvent(self, ev):                              # noqa: N802
        super().resizeEvent(ev)
        if hasattr(self, 'cfg'):
            self._save_config_debounced()

    def moveEvent(self, ev):                                # noqa: N802
        super().moveEvent(ev)
        if hasattr(self, 'cfg'):
            self._save_config_debounced()

    def changeEvent(self, ev):                              # noqa: N802
        super().changeEvent(ev)
        if ev.type() == ev.Type.WindowStateChange and hasattr(self, 'cfg'):
            self._save_config_debounced()

    def _save_config_debounced(self):
        if not hasattr(self, '_save_timer'):
            self._save_timer = QTimer(self)
            self._save_timer.setSingleShot(True)
            self._save_timer.setInterval(600)
            self._save_timer.timeout.connect(self._save_config)
        self._save_timer.start()

    def _apply_performance_now(self):
        from ..cipher import _accel
        threads = int(self.cfg.get('threads', 0))
        try:
            _accel.set_threads(threads)
        except Exception:                                  # noqa: BLE001
            pass
        self.sidebar.set_performance(self.cfg.get('backend', 'auto'),
                                     threads,
                                     int(self.cfg.get('leaf_mib', 4)),
                                     int(self.cfg.get('small_file_mib', 32)))

    def _restore_window(self):
        w = self.cfg.get('window', {})
        try:
            if w.get('w') and w.get('h'):
                self.resize(int(w['w']), int(w['h']))
            if w.get('x') is not None and w.get('y') is not None:
                self.move(int(w['x']), int(w['y']))
            if w.get('fullscreen'):
                self.showFullScreen()
            elif w.get('maximized'):
                self.showMaximized()
        except (TypeError, ValueError):
            self.resize(1280, 880)

    # ------------------------------------------------------------ prewarm
    def _prewarm(self):
        """Фон: таблицы эталона + компиляция native-ядер + статус."""
        self.set_status('инициализация ускорителей…')
        self._apply_performance_now()

        def work():
            try:
                import kazual.cipher.selfcheck  # noqa: F401 (таблицы)
            except Exception:                              # noqa: BLE001
                pass
            try:
                from ..cipher import _accel
                _accel.warmup()
            except Exception:                              # noqa: BLE001
                pass
            self._ready = True

        self._prewarm_thread = threading.Thread(target=work, daemon=True)
        self._prewarm_thread.start()
        self._prewarm_timer = QTimer(self)
        self._prewarm_timer.setInterval(400)
        self._prewarm_timer.timeout.connect(self._check_prewarm)
        self._prewarm_timer.start()

    def _check_prewarm(self):
        if not self._ready:
            return
        self._prewarm_timer.stop()
        from ..cipher import _accel
        line = _accel.status_line()
        self.lbl_accel.setText(line)
        self.set_status('готово')
        try:
            self.page_settings.refresh_status()
        except RuntimeError:
            pass

    def closeEvent(self, event):                              # noqa: N802
        self._save_config()
        if self._worker is not None:
            self._worker.cancel()
            self._worker.wait(2500)
        event.accept()
