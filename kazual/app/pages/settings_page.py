# -*- coding: utf-8 -*-
"""Страница «Настройки»: производительность, ускорители и файлы конфигурации."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (QComboBox, QFileDialog, QFormLayout,
                               QGroupBox, QHBoxLayout, QLabel, QMessageBox,
                               QPlainTextEdit, QPushButton, QSpinBox,
                               QVBoxLayout, QWidget)

from ... import config as appconfig
from .. import theme


class PipWorker(QThread):
    """pip install в фоне (вывод построчно — в лог страницы)."""

    line = Signal(str)
    done = Signal(int)

    def __init__(self, args, parent=None):
        super().__init__(parent)
        self._args = args

    def run(self):  # noqa: D102
        try:
            p = subprocess.Popen(
                [sys.executable, '-m', 'pip'] + self._args,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding='utf-8', errors='replace')
            for ln in p.stdout:
                ln = ln.rstrip()
                if ln:
                    self.line.emit(ln)
            p.wait()
            self.done.emit(p.returncode)
        except Exception as exc:                          # noqa: BLE001
            self.line.emit('ошибка: %s' % exc)
            self.done.emit(-1)


def accelerator_status() -> str:
    """Сводка доступных ускорителей (для отображения)."""
    parts = []
    try:
        import numba
        parts.append('numba %s ✓' % numba.__version__)
    except ImportError:
        parts.append('numba ✗ (эталонный Python-путь — медленно)')
    try:
        import numpy
        parts.append('NumPy %s ✓' % numpy.__version__)
    except ImportError:
        parts.append('NumPy ✗')
    try:
        import cupy  # noqa: F401 (проба наличия)
        parts.append('CuPy ✓ (GPU доступен)')
    except Exception:                                     # noqa: BLE001
        has_gpu = shutil.which('nvidia-smi') is not None
        parts.append('CuPy ✗ (GPU-ускорение%s)'
                     % (' — обнаружен NVIDIA GPU, можно установить'
                        if has_gpu else ' не установлено'))
    cores = os.cpu_count() or 1
    parts.append('ядер CPU: %d' % cores)
    return ' · '.join(parts)


class SettingsPage(QWidget):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self._pip = None
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 16, 24, 16)
        root.setSpacing(12)

        head = QLabel('Настройки')
        head.setProperty('kind', 'title')
        root.addWidget(head)

        # ---- производительность ----
        g = QGroupBox('Производительность')
        v = QVBoxLayout(g)
        v.setSpacing(8)
        self.lbl_accel = QLabel()
        self.lbl_accel.setWordWrap(True)
        self.lbl_accel.setStyleSheet('font-size: 9pt; color: %s;' % theme.MUTED)
        v.addWidget(self.lbl_accel)

        form = QFormLayout()
        form.setHorizontalSpacing(10)
        self.cmb_backend = QComboBox()
        self.cmb_backend.addItem('Авто (лучший доступный)', 'auto')
        self.cmb_backend.addItem('Нативный (numba, все ядра)', 'native')
        self.cmb_backend.addItem('NumPy (векторный)', 'cpu')
        self.cmb_backend.addItem('GPU (CuPy, если установлен)', 'gpu')
        self.cmb_backend.addItem('Эталонный скалярный (для проверок)',
                                 'scalar')
        self.cmb_backend.setToolTip(
            '«Авто» выбирает: numba (быстрее всего) → CuPy/GPU → NumPy → '
            'эталонный путь.')
        form.addRow('Бэкенд шифра:', self.cmb_backend)

        self.sp_threads = QSpinBox()
        self.sp_threads.setRange(0, max(8, (os.cpu_count() or 4) * 2))
        self.sp_threads.setSpecialValueText('все ядра')
        self.sp_threads.setToolTip('Сколько потоков использовать для MAC и '
                                   'шифрования (0 = все доступные ядра).')
        form.addRow('Потоки:', self.sp_threads)

        self.sp_leaf = QSpinBox()
        self.sp_leaf.setRange(1, 64)
        self.sp_leaf.setSuffix(' МиБ')
        self.sp_leaf.setToolTip(
            'Размер листа tree-MAC (параллельный MAC контейнера v2).\n'
            'Больше лист — меньше накладных расходов; 4 МиБ — баланс.')
        form.addRow('Лист tree-MAC:', self.sp_leaf)

        self.sp_small = QSpinBox()
        self.sp_small.setRange(1, 4096)
        self.sp_small.setSuffix(' МиБ')
        self.sp_small.setToolTip(
            'Файлы до этого размера обрабатываются в памяти одним проходом;\n'
            'крупнее — потоково с постоянным потреблением ОЗУ.')
        form.addRow('Порог «в памяти»:', self.sp_small)
        v.addLayout(form)

        row = QHBoxLayout()
        self.btn_install_numba = QPushButton()
        self.btn_install_numba.clicked.connect(
            lambda: self._pip_install(['install', '--upgrade', 'numba']))
        row.addWidget(self.btn_install_numba)
        self.btn_install_cupy = QPushButton()
        self.btn_install_cupy.setToolTip(
            'cupy-cuda12x (~100 МБ). Нужен GPU NVIDIA и драйвер CUDA 12.\n'
            'Для этого шифра CPU-путь на многоядерных машинах обычно не '
            'медленнее — GPU полезен на очень больших объёмах.\n'
            'Автоматически не ставится сознательно: пакет тяжёлый и '
            'привязан к версии CUDA.')
        self.btn_install_cupy.clicked.connect(
            lambda: self._pip_install(['install', '--upgrade',
                                       'cupy-cuda12x']))
        row.addWidget(self.btn_install_cupy)
        row.addStretch(1)
        v.addLayout(row)
        note = QLabel('numba устанавливается автоматически при первом '
                      'запуске main.py; эти кнопки — для случая, когда '
                      'автоустановка не удалась (не было интернета), и для '
                      'обновления. CuPy — только по желанию.')
        note.setWordWrap(True)
        note.setStyleSheet('font-size: 8.5pt; color: %s;' % theme.MUTED)
        v.addWidget(note)

        self.pip_log = QPlainTextEdit()
        self.pip_log.setReadOnly(True)
        self.pip_log.setFont(theme.mono_font(8))
        self.pip_log.setMaximumHeight(110)
        self.pip_log.setVisible(False)
        v.addWidget(self.pip_log)
        root.addWidget(g)

        # ---- конфигурация ----
        g = QGroupBox('Конфигурация')
        v = QVBoxLayout(g)
        v.setSpacing(8)
        lbl = QLabel('Всё состояние программы (настройки, вкладка, правила '
                     'вывода, размер и развёрнутость окна) сохраняется '
                     'автоматически в реальном времени в текущий конфиг. '
                     'Все конфиги лежат в папке программы: '
                     'KazualCipher/configs/. При старте загружается '
                     'default.json — «конфиг по умолчанию».')
        lbl.setWordWrap(True)
        lbl.setStyleSheet('font-size: 9pt; color: %s;' % theme.MUTED)
        v.addWidget(lbl)
        self.lbl_cfg_path = QLabel()
        self.lbl_cfg_path.setFont(theme.mono_font(8))
        self.lbl_cfg_path.setWordWrap(True)
        self.lbl_cfg_path.setStyleSheet(
            'color: %s; background: %s; border: 1px solid %s;'
            'border-radius: 6px; padding: 4px 8px;'
            % (theme.TEAL, theme.CARD, theme.BORDER))
        v.addWidget(self.lbl_cfg_path)

        row = QHBoxLayout()
        row.addWidget(QLabel('Конфиг:'))
        self.cmb_configs = QComboBox()
        self.cmb_configs.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.cmb_configs.setMinimumContentsLength(14)
        row.addWidget(self.cmb_configs, 1)
        btn_load = QPushButton('Загрузить')
        btn_load.setToolTip('Применить выбранный файл к программе; он станет '
                            'текущим (изменения будут сохраняться в него).')
        btn_load.clicked.connect(self._load_selected)
        row.addWidget(btn_load)
        v.addLayout(row)

        row = QHBoxLayout()
        btn_save_as = QPushButton('Сохранить как…')
        btn_save_as.setToolTip('Снимок текущего состояния под новым именем.')
        btn_save_as.clicked.connect(self._save_as)
        btn_default = QPushButton('Сделать по умолчанию')
        btn_default.setToolTip('Текущее состояние станет загружаться при '
                               'старте программы (default.json).')
        btn_default.clicked.connect(self._make_default)
        btn_reset = QPushButton('Сбросить к встроенным')
        btn_reset.setToolTip('Встроенные в код значения: применяются к '
                             'виджетам СРАЗУ и сохраняются в текущий конфиг.')
        btn_reset.clicked.connect(self._reset)
        row.addWidget(btn_save_as)
        row.addWidget(btn_default)
        row.addWidget(btn_reset)
        row.addStretch(1)
        v.addLayout(row)
        root.addWidget(g)

        root.addStretch(1)
        self.refresh_status()

    # ------------------------------------------------------------- actions
    def refresh_status(self):
        self.lbl_accel.setText(accelerator_status())
        self._refresh_configs_list()
        self.lbl_cfg_path.setText(
            'текущий: configs/%s.json · при старте загружается: '
            'configs/default.json' % self.win.cfg_name)
        # кнопки установки показывают фактическое состояние ускорителей
        try:
            import numba
            self.btn_install_numba.setText(
                'Обновить numba (установлена ✓, v%s)' % numba.__version__)
            self.btn_install_numba.setStyleSheet('')
        except ImportError:
            self.btn_install_numba.setText(
                'Установить numba (ускорение в ~40 раз — СЕЙЧАС НЕ СТОИТ!)')
            self.btn_install_numba.setStyleSheet(
                'color: %s; border-color: %s;' % (theme.WARNING,
                                                   theme.WARNING))
        try:
            import cupy                                    # noqa: F401
            self.btn_install_cupy.setText('Обновить CuPy (установлен ✓)')
        except Exception:                                # noqa: BLE001
            self.btn_install_cupy.setText(
                'Установить GPU-поддержку (CuPy, ~100 МБ, опционально)')

    def _pip_install(self, args):
        if self._pip is not None and self._pip.isRunning():
            return
        self.pip_log.setVisible(True)
        self.pip_log.setPlainText('$ pip %s\n' % ' '.join(args))
        self._pip = PipWorker(args, self)
        self._pip.line.connect(lambda s: self.pip_log.appendPlainText(s))
        self._pip.done.connect(self._pip_done)
        self._pip.start()

    def _pip_done(self, code):
        self.refresh_status()
        if code == 0:
            self.pip_log.appendPlainText(
                '\n✓ Готово. Перезапуск программы не требуется — ускоритель '
                'подхватится автоматически.')
        else:
            self.pip_log.appendPlainText(
                '\n✗ pip завершился с кодом %s — проверьте соединение с '
                'интернетом и вывод выше.' % code)

    def _refresh_configs_list(self):
        cur = self.cmb_configs.currentText()
        self.cmb_configs.blockSignals(True)
        self.cmb_configs.clear()
        self.cmb_configs.addItems(appconfig.list_configs())
        idx = self.cmb_configs.findText(cur or appconfig.DEFAULT_NAME)
        self.cmb_configs.setCurrentIndex(max(0, idx))
        self.cmb_configs.blockSignals(False)

    def _load_selected(self):
        name = self.cmb_configs.currentText()
        try:
            cfg = appconfig.load(name)
        except appconfig.ConfigError as exc:
            QMessageBox.critical(self, 'Ошибка', str(exc))
            return
        self.win.cfg_name = name
        self.win.apply_config(cfg, save=False)
        self.refresh_status()
        self.win.set_status('Конфиг загружен: %s' % name)

    def _save_as(self):
        from PySide6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(
            self, 'Сохранить конфиг',
            'Имя нового конфига (ляжет в configs/):',
            text='мой-профиль')
        if not ok or not name.strip():
            return
        name = name.strip()
        if name == appconfig.DEFAULT_NAME:
            QMessageBox.information(
                self, 'Имя занято',
                'default — служебное имя конфига по умолчанию.\n'
                'Чтобы сделать текущий конфиг дефолтным, нажмите '
                '«Сделать по умолчанию».')
            return
        try:
            appconfig.save(self.win.collect_config(), name)
        except OSError as exc:
            QMessageBox.critical(self, 'Ошибка', 'Не удалось сохранить: %s'
                                 % exc)
            return
        self.win.cfg_name = name
        self.win.cfg = self.win.collect_config()
        self._refresh_configs_list()
        self.cmb_configs.setCurrentText(name)
        self.refresh_status()
        self.win.set_status('Конфиг сохранён: %s' % name)

    def _make_default(self):
        try:
            appconfig.save(self.win.collect_config(),
                           appconfig.DEFAULT_NAME)
        except OSError as exc:
            QMessageBox.critical(self, 'Ошибка', 'Не удалось сохранить: %s'
                                 % exc)
            return
        self.win.cfg_name = appconfig.DEFAULT_NAME
        self._refresh_configs_list()
        self.refresh_status()
        self.win.set_status('Текущий конфиг назначен загружаемым при старте')

    def _reset(self):
        r = QMessageBox.question(
            self, 'Сбросить настройки',
            'Применить встроенные значения по умолчанию ко всем виджетам '
            'и сохранить их в текущий конфиг (%s.json)?'
            % self.win.cfg_name,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if r != QMessageBox.StandardButton.Yes:
            return
        cfg = appconfig.reset(self.win.cfg_name)   # вернёт словарь И сохранит
        self.win.apply_config(cfg, save=False)
        self.refresh_status()
        self.win.set_status('Настройки сброшены к встроенным значениям')

    # ------------------------------------------------------------- config
    def apply_config(self, cfg: dict):
        self._refresh_configs_list()
        backend = cfg.get('backend', 'auto')
        i = self.cmb_backend.findData(backend)
        self.cmb_backend.setCurrentIndex(max(0, i))
        self.sp_threads.setValue(int(cfg.get('threads', 0)))
        self.sp_leaf.setValue(int(cfg.get('leaf_mib', 4)))
        self.sp_small.setValue(int(cfg.get('small_file_mib', 32)))
        self.refresh_status()

    def collect_config(self) -> dict:
        return {'backend': self.cmb_backend.currentData(),
                'threads': self.sp_threads.value(),
                'leaf_mib': self.sp_leaf.value(),
                'small_file_mib': self.sp_small.value()}

    def set_busy(self, busy: bool):
        pass

    def on_progress(self, stage, frac):
        pass
