# -*- coding: utf-8 -*-
"""Страница «Расшифрование»: пакет (Base64/HEX/файл) → текст или файл."""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QShortcut, QKeySequence
from PySide6.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLabel,
                               QPlainTextEdit, QProgressBar, QPushButton,
                               QRadioButton, QStackedWidget, QVBoxLayout,
                               QWidget)

from ... import engine
from .. import theme
from . import common


class DecryptPage(QWidget):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self._last_plain = b''
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self):
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 18, 24, 18)
        v.setSpacing(12)

        head = QLabel('Расшифрование')
        head.setProperty('kind', 'title')
        sub = QLabel('Вставьте пакет или выберите файл. Настройки полей '
                     '(prefix / params / random) должны совпадать с теми, '
                     'что были при шифровании — params читаются из пакета.')
        sub.setProperty('kind', 'subtitle')
        sub.setWordWrap(True)
        v.addWidget(head)
        v.addWidget(sub)

        src_row = QHBoxLayout()
        self.rb_text = QRadioButton('Текст')
        self.rb_file = QRadioButton('Файл')
        self.rb_text.setChecked(True)
        src_row.addWidget(self.rb_text)
        src_row.addWidget(self.rb_file)
        src_row.addSpacing(18)
        src_row.addWidget(QLabel('Формат входа:'))
        self.cmb_fmt = QComboBox()
        self.cmb_fmt.addItems(['Авто', 'Base64', 'HEX'])
        self.cmb_fmt.setFixedWidth(100)
        self.cmb_fmt.setToolTip('Авто: строгая hex-строка чётной длины → HEX,\n'
                                'иначе Base64.')
        src_row.addWidget(self.cmb_fmt)
        src_row.addStretch(1)
        v.addLayout(src_row)

        self.stack = QStackedWidget()

        # --- текстовая страница ---
        tp = QWidget()
        tv = QVBoxLayout(tp)
        tv.setContentsMargins(0, 0, 0, 0)
        tv.setSpacing(8)
        self.in_text = QPlainTextEdit()
        self.in_text.setFont(theme.mono_font(9))
        self.in_text.setPlaceholderText(
            'Вставьте пакет (Base64 или HEX)…')
        self.in_text.setMinimumHeight(110)
        tv.addWidget(self.in_text, 3)

        out_row = QHBoxLayout()
        self.btn_copy = QPushButton('Копировать текст')
        self.btn_copy.setEnabled(False)
        self.btn_copy.clicked.connect(self._copy_result)
        self.btn_save = QPushButton('Сохранить как…')
        self.btn_save.setEnabled(False)
        self.btn_save.clicked.connect(self._save_result)
        out_row.addWidget(self.btn_copy)
        out_row.addWidget(self.btn_save)
        out_row.addStretch(1)
        self.lbl_out_kind = QLabel('')
        self.lbl_out_kind.setProperty('kind', 'muted')
        self.lbl_out_kind.setStyleSheet('font-size: 9pt;')
        out_row.addWidget(self.lbl_out_kind)
        tv.addLayout(out_row)

        self.out_text = QPlainTextEdit()
        self.out_text.setReadOnly(True)
        self.out_text.setPlaceholderText('здесь появится результат…')
        self.out_text.setMinimumHeight(90)
        tv.addWidget(self.out_text, 2)
        self.stack.addWidget(tp)

        # --- файловая страница ---
        fp = QWidget()
        fv = QVBoxLayout(fp)
        fv.setContentsMargins(0, 0, 0, 0)
        fv.setSpacing(8)
        fv.addWidget(QLabel('Файл пакета:'))
        self.row_in_file = common.FileRow('/путь/к/файлу.kaz…', 'open')
        fv.addWidget(self.row_in_file)
        fv.addWidget(QLabel('Куда сохранить результат (пусто = предложить):'))
        self.row_out_file = common.FileRow('/путь/к/результату…', 'save')
        fv.addWidget(self.row_out_file)
        fv.addStretch(1)
        self.stack.addWidget(fp)

        v.addWidget(self.stack, 1)
        self.rb_text.toggled.connect(
            lambda on: self.stack.setCurrentIndex(0 if on else 1))

        act = QHBoxLayout()
        self.btn_run = QPushButton('Расшифровать')
        self.btn_run.setProperty('kind', 'primary')
        self.btn_run.setMinimumWidth(210)
        self.btn_run.clicked.connect(self.run_decrypt)
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

        self.banner_box = QVBoxLayout()
        self.banner_box.setSpacing(6)
        v.addLayout(self.banner_box)
        v.addStretch(0)

        QShortcut(QKeySequence('Ctrl+Return'), self,
                  activated=self.run_decrypt,
                  context=Qt.ShortcutContext.WidgetWithChildrenShortcut)

    # ------------------------------------------------------------- actions
    def _clear_banner(self):
        while self.banner_box.count():
            item = self.banner_box.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _add_banner(self, kind, title, lines=None):
        self.banner_box.addWidget(common.banner(kind, title, lines))

    def _show_banner(self, kind, title, lines=None):
        self._clear_banner()
        self._add_banner(kind, title, lines)

    def set_busy(self, busy: bool):
        self.btn_run.setEnabled(not busy)
        self.btn_cancel.setVisible(busy)
        self.progress.setVisible(busy)
        if busy:
            self.progress.setRange(0, 0)
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

    def run_decrypt(self):
        if self.win.is_busy():
            return
        try:
            st = self.win.sidebar.settings()
        except engine.KazualError as exc:
            self._show_banner('err', '✗ %s' % exc)
            return

        fmt = ('auto', 'base64', 'hex')[self.cmb_fmt.currentIndex()]
        dest_path = self.row_out_file.path() or None
        if self.rb_text.isChecked():
            try:
                data = common.decode_text_input(self.in_text.toPlainText(), fmt)
            except engine.KazualError as exc:
                self._show_banner('err', '✗ %s' % exc)
                return
            if not data:
                self._show_banner('err', '✗ Пустые данные')
                return
        else:
            src = self.row_in_file.path()
            if not src or not os.path.isfile(src):
                self._show_banner('err', '✗ Выберите существующий файл пакета')
                return
            try:
                with open(src, 'rb') as f:
                    data = f.read()
            except OSError as exc:
                self._show_banner('err', '✗ Не удалось прочитать файл: %s' % exc)
                return
            if dest_path is None:
                dest_path = self._suggest_name(src)

        def task(progress_cb):
            return engine.decrypt(st, data, progress=progress_cb)

        self.win.run_task(task, lambda r: self._on_ok(r, dest_path),
                          self._on_err)

    @staticmethod
    def _suggest_name(src: str) -> str:
        base = src
        for suffix in ('.kaz', '.b64', '.hex', '.encrypted'):
            if base.lower().endswith(suffix):
                base = base[:-len(suffix)]
        return base + '.decrypted'

    # ------------------------------------------------------------ results
    def _on_ok(self, res: engine.Result, dest_path):
        info = res.meta
        self._last_plain = res.data

        # --- текстовое представление результата
        text = common.try_decode_utf8(res.data)
        if text is not None:
            self.out_text.setFont(self.in_text.font())
            self.out_text.setPlainText(text)
            self.lbl_out_kind.setText('текст UTF-8 · %s'
                                      % common.human_size(len(res.data)))
        else:
            self.out_text.setFont(theme.mono_font(9))
            preview = res.data[:512]
            self.out_text.setPlainText(
                'Двоичные данные (%s). Первые %d байт в HEX:\n\n%s%s' % (
                    common.human_size(len(res.data)), len(preview),
                    preview.hex(' ').upper(),
                    '\n…' if len(res.data) > len(preview) else ''))
            self.lbl_out_kind.setText('двоичные данные — сохраните в файл')

        self.btn_copy.setEnabled(text is not None)
        self.btn_save.setEnabled(True)

        # --- баннеры
        lines = ['Время: %.0f мс' % info.get('total_ms', 0)]
        if info.get('phc'):
            src = ('из пакета' if info.get('params_from_packet')
                   else 'из настроек')
            lines.append('KDF: %s (%s)' % (info['phc'], src))
        if dest_path and not self.rb_text.isChecked():
            try:
                Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
                with open(dest_path, 'wb') as f:
                    f.write(res.data)
                lines.append('Сохранено: %s' % dest_path)
            except OSError as exc:
                self._show_banner('err', '✗ Файл не сохранён: %s' % exc)
                return

        self._clear_banner()
        if res.mode == 'siv':
            self._add_banner(
                'ok', '✓ Подлинность подтверждена',
                ['Тег V сошёлся: MAC от всех полей пакета и текста совпал — '
                 'пароль верен, данные не изменялись ни на бит.'] + lines)
        else:
            self._add_banner(
                'warn', '⚠ Расшифровано без проверки подлинности',
                ['ECB не содержит MAC: успешное снятие PKCS#7-дополнения не '
                 'гарантирует, что пароль верен, а данные не изменены.'] + lines)
        if res.warnings:
            self._add_banner('warn', '⚠ Обратите внимание', res.warnings)
        self.win.set_status('Расшифрование завершено')
        self.win.refresh_packet_page(res)

    def _on_err(self, exc):
        import traceback
        from ..workers import CancelledError
        from ...modes.siv import MacError, PacketFormatError
        from ...modes.padding import PaddingError
        if isinstance(exc, CancelledError):
            self._show_banner('info', 'Операция отменена')
            self.win.set_status('Отменено')
        elif isinstance(exc, MacError):
            self._show_banner('err', '✗ Проверка подлинности НЕ пройдена', [
                str(exc),
                'Подсказка: сверьте шифр, режим и галочки полей пакета '
                '(prefix / params / random) с настройками при шифровании.'])
            self.win.set_status('MAC не сошёлся')
        elif isinstance(exc, (PacketFormatError, PaddingError)):
            self._show_banner('err', '✗ Формат пакета не распознан', [str(exc)])
            self.win.set_status('Ошибка формата')
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
        self.win.set_status('Скопировано в буфер обмена')

    def _save_result(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Сохранить результат',
                                              'decrypted.bin', 'Все файлы (*)')
        if not path:
            return
        try:
            with open(path, 'wb') as f:
                f.write(self._last_plain)
        except OSError as exc:
            self._show_banner('err', '✗ Не удалось сохранить: %s' % exc)
            return
        self.win.set_status('Сохранено: %s' % path)
