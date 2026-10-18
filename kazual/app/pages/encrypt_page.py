# -*- coding: utf-8 -*-
"""Страница «Шифрование»: текст или несколько файлов → контейнеры Kazual."""

from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QShortcut, QKeySequence
from PySide6.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLabel,
                               QPlainTextEdit, QProgressBar, QPushButton,
                               QRadioButton, QStackedWidget, QVBoxLayout,
                               QWidget)

from ... import engine, stream
from .. import theme
from . import common


class EncryptPage(QWidget):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self._last_data = b''
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self):
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 16, 24, 16)
        v.setSpacing(10)

        head = QLabel('Шифрование')
        head.setProperty('kind', 'title')
        v.addWidget(head)

        # ---- что шифруем ----
        src_row = QHBoxLayout()
        self.rb_text = QRadioButton('Текст')
        self.rb_files = QRadioButton('Файлы (можно сразу несколько)')
        self.rb_text.setChecked(True)
        src_row.addWidget(self.rb_text)
        src_row.addSpacing(18)
        src_row.addWidget(self.rb_files)
        src_row.addStretch(1)
        v.addLayout(src_row)

        self.stack = QStackedWidget()

        # --- текст ---
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
        self.out_text.setPlaceholderText('здесь появится результат…')
        self.out_text.setMinimumHeight(90)
        tv.addWidget(self.out_text, 2)
        self.stack.addWidget(tp)

        # --- файлы ---
        fp = QWidget()
        fv = QVBoxLayout(fp)
        fv.setContentsMargins(0, 0, 0, 0)
        fv.setSpacing(8)
        self.files = common.FileListWidget()
        self.files.changed.connect(self._update_run_button)
        fv.addWidget(self.files, 1)
        fv.addWidget(QLabel('Куда сохранять результаты:'))
        self.out_rules = common.OutputRules('.kaz')
        self.out_rules.changed.connect(
            lambda: self.win.on_out_rules_changed(self.out_rules))
        fv.addWidget(self.out_rules)
        self.stack.addWidget(fp)

        v.addWidget(self.stack, 1)
        self.rb_text.toggled.connect(
            lambda on: self._switch_mode(0 if on else 1))

        # ---- действие и прогресс ----
        act = QHBoxLayout()
        self.btn_run = QPushButton('Зашифровать')
        self.btn_run.setProperty('kind', 'primary')
        self.btn_run.setMinimumWidth(200)
        self.btn_run.clicked.connect(self.run_encrypt)
        self.btn_cancel = QPushButton('Отмена')
        self.btn_cancel.setProperty('kind', 'danger')
        self.btn_cancel.setVisible(False)
        self.btn_cancel.clicked.connect(lambda: self.win.cancel_task())
        act.addWidget(self.btn_run)
        act.addWidget(self.btn_cancel)
        act.addSpacing(14)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setVisible(False)
        self.progress.setFixedWidth(200)
        act.addWidget(self.progress)
        self.lbl_stage = QLabel('')
        self.lbl_stage.setProperty('kind', 'muted')
        self.lbl_stage.setStyleSheet('font-size: 9pt;')
        self.lbl_stage.setWordWrap(False)
        act.addWidget(self.lbl_stage, 1)
        v.addLayout(act)

        self.banners = common.BannerBox()
        v.addLayout(self.banners)

        self.cmb_fmt.currentIndexChanged.connect(lambda _: self._render_output())
        QShortcut(QKeySequence('Ctrl+Return'), self,
                  activated=self.run_encrypt,
                  context=Qt.ShortcutContext.WidgetWithChildrenShortcut)

    def _switch_mode(self, idx: int):
        self.stack.setCurrentIndex(idx)
        self._update_run_button()

    def _update_run_button(self):
        if self.stack.currentIndex() == 1:
            n = len(self.files.paths())
            self.btn_run.setText('Зашифровать %s'
                                 % ('%d файл(ов)' % n if n else ''))
            self.btn_run.setEnabled(n > 0)
        else:
            self.btn_run.setText('Зашифровать')
            self.btn_run.setEnabled(True)

    # ------------------------------------------------------------- actions
    def set_busy(self, busy: bool):
        self.btn_run.setEnabled(not busy)
        self.btn_cancel.setVisible(busy)
        self.progress.setVisible(busy)
        self.files.setEnabled(not busy)
        self.out_rules.setEnabled(not busy)
        if busy:
            self.progress.setRange(0, 0)
            self.lbl_stage.setText('подготовка…')
        else:
            self.lbl_stage.setText('')
            self._update_run_button()

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
            self.banners.show('err', '✗ %s' % exc)
            return

        if self.rb_text.isChecked():
            data = self.in_text.toPlainText().encode('utf-8')
            if not data:
                self.banners.show('err', '✗ Введите текст для шифрования')
                return

            def task(progress_cb, cancel):
                return engine.encrypt(st, data, progress=progress_cb)

            self.win.run_task(task, self._on_ok_text, self._on_err)
        else:
            srcs = self.files.paths()
            if not srcs:
                self.banners.show('err', '✗ Добавьте хотя бы один файл')
                return
            outdir = self.out_rules.outdir()
            if self.out_rules.rb_dir.isChecked() and not outdir:
                self.banners.show('err', '✗ Укажите папку для результатов '
                                         '(или выберите «Рядом с источником»)')
                return
            overwrite = self.out_rules.overwrite()
            try:
                jobs = [(s, stream.resolve_output_path(s, True, outdir,
                                                       overwrite))
                        for s in srcs]
            except OSError as exc:
                self.banners.show('err', '✗ %s' % exc)
                return
            if outdir:
                os.makedirs(outdir, exist_ok=True)

            def task(progress_cb, cancel):
                return stream.encrypt_files(st, jobs, progress_cb, cancel)

            self.win.run_task(task, self._on_ok_files, self._on_err)

    # ------------------------------------------------------------ results
    def _render_output(self):
        if self._last_data:
            self.out_text.setPlainText(common.encode_output(
                self._last_data,
                'hex' if self.cmb_fmt.currentIndex() == 1 else 'base64'))

    def _on_ok_text(self, res: engine.Result):
        info = res.meta
        self._last_data = res.data
        self._render_output()
        self.btn_copy.setEnabled(True)
        self.btn_save_txt.setEnabled(True)
        lines = ['Размер: %s (данные %s + служебные поля %s)' % (
            common.human_size(len(res.data)),
            common.human_size(len(res.data) - info.get(
                'overhead', info.get('padding', 0))),
            common.human_size(info.get('overhead', info.get('padding', 0))))]
        if res.mode == 'siv' and info.get('v_hex'):
            v = info['v_hex']
            lines.append('Тег подлинности V: %s…%s' % (v[:16], v[-8:]))
        if info.get('phc'):
            lines.append('KDF в файле: %s' % info['phc'])
        lines.append('Время: %.2f с' % (info.get('total_ms', 0) / 1000.0))
        self.banners.clear()
        self.banners.add('ok', '✓ Зашифровано — %s · %s · формат v%d'
                         % (res.cipher, res.mode.upper(),
                            info.get('version', 1)), lines)
        self._add_functional_notes(res)
        self.win.set_status('Шифрование завершено')
        self.win.refresh_packet_page(res)

    def _on_ok_files(self, reports):
        ok = [r for r in reports if r.ok]
        bad = [r for r in reports if not r.ok]
        total_in = sum(r.in_bytes for r in reports)
        total_t = sum(r.seconds for r in reports) or 0.001
        lines = []
        for r in reports:
            if r.ok:
                lines.append('✓ %s → %s (%s, %.1f с)' % (
                    os.path.basename(r.src), r.dst,
                    common.human_size(r.out_bytes), r.seconds))
            else:
                lines.append('✗ %s: %s' % (os.path.basename(r.src), r.error))
        self.banners.clear()
        speed = total_in / total_t / (1 << 20)
        self.banners.add(
            'ok' if not bad else ('err' if not ok else 'warn'),
            '✓ Зашифровано файлов: %d из %d · %s · средняя скорость '
            '%.1f МиБ/с' % (len(ok), len(reports),
                            common.human_size(total_in), speed),
            lines[:40])
        notes = []
        for r in ok:
            notes.extend(r.warnings)
        if notes:
            self.banners.add('info', 'Примечания', sorted(set(notes)))
        self.win.set_status('Шифрование завершено: %d из %d'
                            % (len(ok), len(reports)))

    def _add_functional_notes(self, res: engine.Result):
        if res.warnings:
            self.banners.add('info', 'Примечания', res.warnings)

    def _on_err(self, exc):
        import traceback
        from ..workers import CancelledError
        if isinstance(exc, CancelledError):
            self.banners.show('info', 'Операция отменена')
            self.win.set_status('Отменено')
        elif type(exc).__module__.startswith('kazual'):
            self.banners.show('err', '✗ %s' % exc)
            self.win.set_status('Ошибка: %s' % exc)
        else:
            traceback.print_exception(exc)
            self.banners.show('err', '✗ Внутренняя ошибка: %s: %s'
                              % (type(exc).__name__, exc),
                              ['подробности в терминале/журнале'])
            self.win.set_status('Внутренняя ошибка')

    def _copy_result(self):
        QGuiApplication.clipboard().setText(self.out_text.toPlainText())
        self.win.set_status('Скопировано в буфер обмена')

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
            self.banners.show('err', '✗ Не удалось сохранить: %s' % exc)
            return
        self.win.set_status('Сохранено: %s' % path)

    # ---- конфиг ----
    def apply_config(self, cfg: dict):
        self.out_rules.set_defaults(cfg.get('out_rule', 'next'),
                                    cfg.get('out_dir', ''),
                                    cfg.get('overwrite', False))

    def collect_config(self) -> dict:
        return self.out_rules.collect()
