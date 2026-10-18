# -*- coding: utf-8 -*-
"""Страница «Шифрование»: текст или файл → пакет (Base64/HEX/файл)."""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLabel,
                               QPlainTextEdit, QProgressBar, QPushButton,
                               QRadioButton, QStackedWidget, QVBoxLayout,
                               QWidget)

from ... import engine
from . import common
from .. import theme


class EncryptPage(QWidget):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self):
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 18, 24, 18)
        v.setSpacing(12)

        head = QLabel('Шифрование')
        head.setProperty('kind', 'title')
        sub = QLabel('Соберите настройки в панели слева — результат можно '
                     'скопировать текстом или сохранить в файл.')
        sub.setProperty('kind', 'subtitle')
        sub.setWordWrap(True)
        v.addWidget(head)
        v.addWidget(sub)

        # источник данных
        src_row = QHBoxLayout()
        self.rb_text = QRadioButton('Текст')
        self.rb_file = QRadioButton('Файл')
        self.rb_text.setChecked(True)
        src_row.addWidget(self.rb_text)
        src_row.addWidget(self.rb_file)
        src_row.addStretch(1)
        v.addLayout(src_row)

        self.stack = QStackedWidget()

        # --- текстовая страница ---
        tp = QWidget()
        tv = QVBoxLayout(tp)
        tv.setContentsMargins(0, 0, 0, 0)
        tv.setSpacing(8)
        self.in_text = QPlainTextEdit()
        self.in_text.setPlaceholderText('Введите текст для шифрования…')
        self.in_text.setMinimumHeight(110)
        tv.addWidget(self.in_text, 3)

        fmt_row = QHBoxLayout()
        fmt_row.addWidget(QLabel('Формат результата:'))
        self.cmb_fmt = QComboBox()
        self.cmb_fmt.addItems(['Base64', 'HEX'])
        self.cmb_fmt.setFixedWidth(110)
        fmt_row.addWidget(self.cmb_fmt)
        fmt_row.addStretch(1)
        self.btn_copy = QPushButton('Копировать')
        self.btn_copy.setEnabled(False)
        self.btn_copy.clicked.connect(self._copy_result)
        self.btn_save_txt = QPushButton('Сохранить в файл…')
        self.btn_save_txt.setEnabled(False)
        self.btn_save_txt.clicked.connect(self._save_text_result)
        fmt_row.addWidget(self.btn_copy)
        fmt_row.addWidget(self.btn_save_txt)
        tv.addLayout(fmt_row)

        self.out_text = QPlainTextEdit()
        self.out_text.setReadOnly(True)
        self.out_text.setFont(theme.mono_font(9))
        self.out_text.setPlaceholderText('здесь появится пакет…')
        self.out_text.setMinimumHeight(90)
        tv.addWidget(self.out_text, 2)
        self.stack.addWidget(tp)

        # --- файловая страница ---
        fp = QWidget()
        fv = QVBoxLayout(fp)
        fv.setContentsMargins(0, 0, 0, 0)
        fv.setSpacing(8)
        fv.addWidget(QLabel('Исходный файл:'))
        self.row_in_file = common.FileRow('/путь/к/файлу…', 'open')
        fv.addWidget(self.row_in_file)
        fv.addWidget(QLabel('Файл результата (двоичный пакет):'))
        self.row_out_file = common.FileRow('/путь/к/файлу.kaz (пусто = имя + .kaz)',
                                           'save')
        fv.addWidget(self.row_out_file)
        hint = QLabel('Скорость — десятки-сотни КиБ/с (эталонная реализация на '
                      'Python/NumPy): для больших файлов закладывайте время.')
        hint.setProperty('kind', 'muted')
        hint.setStyleSheet('font-size: 8.5pt;')
        hint.setWordWrap(True)
        fv.addWidget(hint)
        fv.addStretch(1)
        self.stack.addWidget(fp)

        v.addWidget(self.stack, 1)
        self.rb_text.toggled.connect(lambda on: self.stack.setCurrentIndex(0 if on else 1))

        # --- кнопка действия и прогресс ---
        act = QHBoxLayout()
        self.btn_run = QPushButton('Зашифровать')
        self.btn_run.setProperty('kind', 'primary')
        self.btn_run.setMinimumWidth(190)
        self.btn_run.clicked.connect(self.run_encrypt)
        self.btn_cancel = QPushButton('Отмена')
        self.btn_cancel.setProperty('kind', 'danger')
        self.btn_cancel.setVisible(False)
        self.btn_cancel.clicked.connect(lambda: self.win.cancel_task())
        act.addWidget(self.btn_run)
        act.addWidget(self.btn_cancel)
        act.addSpacing(16)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setVisible(False)
        self.progress.setFixedWidth(220)
        act.addWidget(self.progress)
        self.lbl_stage = QLabel('')
        self.lbl_stage.setProperty('kind', 'muted')
        self.lbl_stage.setStyleSheet('font-size: 9pt;')
        act.addWidget(self.lbl_stage, 1)
        v.addLayout(act)

        # --- баннер результата ---
        self.banner_box = QVBoxLayout()
        self.banner_box.setSpacing(6)
        v.addLayout(self.banner_box)
        v.addStretch(0)

        self._last_data = b''
        self.cmb_fmt.currentIndexChanged.connect(lambda _: self._render_output())

        from PySide6.QtGui import QShortcut, QKeySequence
        QShortcut(QKeySequence('Ctrl+Return'), self,
                  activated=self.run_encrypt,
                  context=Qt.ShortcutContext.WidgetWithChildrenShortcut)

    # ------------------------------------------------------------- actions
    def _clear_banner(self):
        while self.banner_box.count():
            item = self.banner_box.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _show_banner(self, kind, title, lines=None):
        self._clear_banner()
        self.banner_box.addWidget(common.banner(kind, title, lines))

    def _add_banner(self, kind, title, lines=None):
        self.banner_box.addWidget(common.banner(kind, title, lines))

    def set_busy(self, busy: bool):
        self.btn_run.setEnabled(not busy)
        self.btn_cancel.setVisible(busy)
        self.progress.setVisible(busy)
        if busy:
            self.progress.setRange(0, 0)          # неопределённый
            self.lbl_stage.setText('подготовка…')
        else:
            self.lbl_stage.setText('')

    def on_progress(self, stage: str, frac):
        if frac is None:
            self.progress.setRange(0, 0)
        else:
            if self.progress.maximum() == 0:
                self.progress.setRange(0, 1000)
            self.progress.setValue(int(frac * 1000))
        self.lbl_stage.setText(stage)
        self.win.set_status(stage)

    def run_encrypt(self):
        if self.win.is_busy():
            return
        try:
            st = self.win.sidebar.settings()
        except engine.KazualError as exc:
            self._show_banner('err', '✗ %s' % exc)
            return

        if self.rb_text.isChecked():
            data = self.in_text.toPlainText().encode('utf-8')
            if not data:
                self._show_banner('err', '✗ Введите текст для шифрования')
                return
            dest_path = None
        else:
            src = self.row_in_file.path()
            if not src or not os.path.isfile(src):
                self._show_banner('err', '✗ Выберите существующий исходный файл')
                return
            try:
                with open(src, 'rb') as f:
                    data = f.read()
            except OSError as exc:
                self._show_banner('err', '✗ Не удалось прочитать файл: %s' % exc)
                return
            dest_path = self.row_out_file.path() or (src + '.kaz')

        def task(progress_cb):
            return engine.encrypt(st, data, progress=progress_cb)

        self.win.run_task(task, lambda r: self._on_ok(r, dest_path),
                          self._on_err)

    # ------------------------------------------------------------ results
    def _render_output(self):
        if self._last_data:
            self.out_text.setPlainText(common.encode_output(
                self._last_data,
                'hex' if self.cmb_fmt.currentIndex() == 1 else 'base64'))

    def _on_ok(self, res: engine.Result, dest_path):
        info = res.meta
        lines = []
        lines.append('Пакет: %s (данные %s + оверхед %s)' % (
            common.human_size(len(res.data)),
            common.human_size(len(res.data) - info.get(
                'overhead', info.get('padding', 0))),
            common.human_size(info.get('overhead', info.get('padding', 0)))))
        if res.mode == 'siv':
            v = info.get('v_hex', '')
            lines.append('V (тег подлинности): %s…%s' % (v[:16], v[-8:]))
        if info.get('phc'):
            lines.append('KDF: %s' % info['phc'])
        lines.append('Время: %.0f мс' % info.get('total_ms', 0))

        if dest_path is None:
            self._last_data = res.data
            self._render_output()
            self.btn_copy.setEnabled(True)
            self.btn_save_txt.setEnabled(True)
        else:
            try:
                Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
                with open(dest_path, 'wb') as f:
                    f.write(res.data)
            except OSError as exc:
                self._show_banner('err', '✗ Файл не сохранён: %s' % exc)
                return
            lines.append('Сохранено: %s' % dest_path)

        self._clear_banner()
        self._add_banner('ok', '✓ Зашифровано — %s · %s' %
                         (res.cipher, res.mode.upper()), lines)
        if res.warnings:
            self._add_banner('warn', '⚠ Обратите внимание', res.warnings)
        self.win.set_status('Шифрование завершено')
        self.win.refresh_packet_page(res)

    def _on_err(self, exc):
        import traceback
        from ..workers import CancelledError
        if isinstance(exc, CancelledError):
            self._show_banner('info', 'Операция отменена')
            self.win.set_status('Отменено')
        elif type(exc).__module__.startswith('kazual'):
            self._show_banner('err', '✗ %s' % exc)
            self.win.set_status('Ошибка: %s' % exc)
        else:
            traceback.print_exception(exc)
            self._show_banner('err', '✗ Внутренняя ошибка: %s: %s' %
                              (type(exc).__name__, exc),
                              ['подробности в терминале'])
            self.win.set_status('Внутренняя ошибка')

    def _copy_result(self):
        QGuiApplication.clipboard().setText(self.out_text.toPlainText())
        self.win.set_status('Пакет скопирован в буфер обмена')

    def _save_text_result(self):
        ext = 'hex' if self.cmb_fmt.currentIndex() == 1 else 'b64'
        path, _ = QFileDialog.getSaveFileName(
            self, 'Сохранить пакет', 'kazual-packet.%s' % ext,
            'Текст (*.%s);;Все файлы (*)' % ext)
        if not path:
            return
        try:
            with open(path, 'w', encoding='ascii') as f:
                f.write(self.out_text.toPlainText())
        except OSError as exc:
            self._show_banner('err', '✗ Не удалось сохранить: %s' % exc)
            return
        self.win.set_status('Сохранено: %s' % path)
