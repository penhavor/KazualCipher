# -*- coding: utf-8 -*-
"""Страница «Расшифрование»: контейнер Kazual (текст или файлы) → данные.

Ключевое поведение: параметры НЕ вводятся вручную — программа сама читает
шифр, режим, параметры Argon2id и состав полей из файла (контейнер v2) и
блокирует панель настроек на время операции.
"""

from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QShortcut, QKeySequence
from PySide6.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLabel,
                               QPlainTextEdit, QProgressBar, QPushButton,
                               QRadioButton, QStackedWidget, QVBoxLayout,
                               QWidget)

from ... import engine, stream
from ...modes.siv import MacError, PacketFormatError
from ...modes.padding import PaddingError
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
        v.setContentsMargins(24, 16, 24, 16)
        v.setSpacing(10)

        head = QLabel('Расшифрование')
        head.setProperty('kind', 'title')
        v.addWidget(head)

        self.card = common.DetectionCard()
        v.addWidget(self.card)

        src_row = QHBoxLayout()
        self.rb_text = QRadioButton('Текст (пакет)')
        self.rb_files = QRadioButton('Файлы (можно сразу несколько)')
        self.rb_text.setChecked(True)
        src_row.addWidget(self.rb_text)
        src_row.addSpacing(18)
        src_row.addWidget(self.rb_files)
        src_row.addSpacing(18)
        src_row.addWidget(QLabel('Формат входа:'))
        self.cmb_fmt = QComboBox()
        self.cmb_fmt.addItems(['Авто', 'Base64', 'HEX'])
        self.cmb_fmt.setFixedWidth(100)
        self.cmb_fmt.setToolTip('Авто: строгая hex-строка чётной длины → HEX,'
                                '\nиначе Base64.')
        src_row.addWidget(self.cmb_fmt)
        src_row.addStretch(1)
        v.addLayout(src_row)

        self.stack = QStackedWidget()

        # --- текст ---
        tp = QWidget()
        tv = QVBoxLayout(tp)
        tv.setContentsMargins(0, 0, 0, 0)
        tv.setSpacing(8)
        self.in_text = QPlainTextEdit()
        self.in_text.setFont(theme.mono_font(9))
        self.in_text.setPlaceholderText('Вставьте пакет (Base64 или HEX)…')
        self.in_text.setMinimumHeight(110)
        self.in_text.textChanged.connect(self._on_text_changed)
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

        # --- файлы ---
        fp = QWidget()
        fv = QVBoxLayout(fp)
        fv.setContentsMargins(0, 0, 0, 0)
        fv.setSpacing(8)
        self.files = common.FileListWidget()
        self.files.changed.connect(self._on_files_changed)
        fv.addWidget(self.files, 1)
        fv.addWidget(QLabel('Куда сохранять результаты:'))
        self.out_rules = common.OutputRules()
        self.out_rules.changed.connect(
            lambda: self.win.on_out_rules_changed(self.out_rules))
        fv.addWidget(self.out_rules)
        self.stack.addWidget(fp)

        v.addWidget(self.stack, 1)
        self.rb_text.toggled.connect(
            lambda on: self._switch_mode(0 if on else 1))

        act = QHBoxLayout()
        self.btn_run = QPushButton('Расшифровать')
        self.btn_run.setProperty('kind', 'primary')
        self.btn_run.setMinimumWidth(220)
        self.btn_run.clicked.connect(self.run_decrypt)
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
        act.addWidget(self.lbl_stage, 1)
        v.addLayout(act)

        self.banners = common.BannerBox()
        v.addLayout(self.banners)

        QShortcut(QKeySequence('Ctrl+Return'), self,
                  activated=self.run_decrypt,
                  context=Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._update_run_button()

    def _switch_mode(self, idx: int):
        self.stack.setCurrentIndex(idx)
        self._update_run_button()
        self._refresh_detection()

    def _update_run_button(self):
        if self.stack.currentIndex() == 1:
            n = len(self.files.paths())
            self.btn_run.setText('Расшифровать %s'
                                 % ('%d файл(ов)' % n if n else ''))
            self.btn_run.setEnabled(n > 0)
        else:
            self.btn_run.setText('Расшифровать')
            self.btn_run.setEnabled(True)

    # --------------------------------------------------------- detection
    def _on_files_changed(self):
        self._update_run_button()
        self._refresh_detection()

    _text_detect_timer = None

    def _on_text_changed(self):
        # дебаунс: определим формат через 400 мс после последнего ввода
        from PySide6.QtCore import QTimer
        if self._text_detect_timer is None:
            self._text_detect_timer = QTimer(self)
            self._text_detect_timer.setSingleShot(True)
            self._text_detect_timer.setInterval(400)
            self._text_detect_timer.timeout.connect(self._refresh_detection)
        self._text_detect_timer.start()

    def _current_head(self):
        """Первые байты текущего входа (текст или первый файл) или None."""
        try:
            if self.stack.currentIndex() == 1:
                paths = self.files.paths()
                if not paths:
                    return None, None
                p = paths[0]
                with open(p, 'rb') as f:
                    return f.read(70000), os.path.getsize(p)
            text = self.in_text.toPlainText().strip()
            if not text:
                return None, None
            fmt = ('auto', 'base64', 'hex')[self.cmb_fmt.currentIndex()]
            data = common.decode_text_input(text, fmt)
            return data[:70000], len(data)
        except (engine.KazualError, OSError, ValueError):
            return None, None

    def refresh_detection(self):
        self._refresh_detection()

    def _refresh_detection(self):
        head, size = self._current_head()
        if head is None:
            self.card.hide_detection()
            self.win.sidebar.unlock()
            return
        det = stream.inspect_data(head, size)
        n_files = len(self.files.paths()) if self.stack.currentIndex() == 1 \
            else 1
        multi = n_files > 1
        if det['version'] == 2:
            if 'error' in det:
                self.card.show_detection('Контейнер v2 — не читается',
                                         det['describe'], theme.DANGER)
                self.win.sidebar.unlock()
                return
            body = det['describe']
            if multi:
                body += ('\nВ пакетном режиме параметры каждого файла '
                         'читаются из него же — панель настроек влияет '
                         'только на пароль/ключ.')
            self.card.show_detection('Параметры прочитаны из файла — '
                                     'настройки заблокированы', body)
            self.win.sidebar.lock_from_detection(
                'Параметры из файла', det['describe'].split(' · ', 1)[-1])
            self._apply_detected_to_sidebar(det)
        else:
            self.card.show_detection('Контейнер Kazual не найден',
                                     det['describe'] or
                                     'Файл повреждён или создан другой '
                                     'программой — расшифровать его нельзя.',
                                     theme.DANGER)
            self.win.sidebar.unlock()

    def _apply_detected_to_sidebar(self, det: dict):
        """Мягко подстроить панель под контейнер v2 (под блокировкой)."""
        sb = self.win.sidebar
        sb._loading = True
        try:
            sb.cmb_cipher.setCurrentIndex(
                0 if det.get('cipher') == 'Kazual-512' else 1)
            sb.cmb_mode.setCurrentIndex(0 if det.get('mode') == 'siv' else 1)
            if det.get('phc'):
                from ...kdf import KdfParams
                from ...config import KDF_PRESETS
                from ..sidebar import _PRESET_BY_ID
                p = KdfParams.parse(det['phc'])
                sb.sp_m.setValue(p.memory_kib)
                sb.sp_t.setValue(p.iterations)
                sb.sp_p.setValue(p.parallelism)
                hit = next((pid for pid, (m, t, pp) in KDF_PRESETS.items()
                            if (m, t, pp) == (p.memory_kib, p.iterations,
                                              p.parallelism)), None)
                sb.cmb_preset.setCurrentIndex(
                    _PRESET_BY_ID.get(hit, sb.cmb_preset.count() - 1))
            sb.ed_brand.setText(det.get('brand') or '')
            sb.ck_random.setChecked(bool(det.get('random', True)))
            sb.ck_params.setChecked(det.get('phc') is not None)
        finally:
            sb._loading = False

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

    def run_decrypt(self):
        if self.win.is_busy():
            return
        self._refresh_detection()
        try:
            st = self.win.sidebar.settings()
        except engine.KazualError as exc:
            self.banners.show('err', '✗ %s' % exc)
            return

        fmt = ('auto', 'base64', 'hex')[self.cmb_fmt.currentIndex()]
        if self.rb_text.isChecked():
            try:
                data = common.decode_text_input(self.in_text.toPlainText(),
                                                fmt)
            except engine.KazualError as exc:
                self.banners.show('err', '✗ %s' % exc)
                return
            if not data:
                self.banners.show('err', '✗ Пустые данные')
                return

            def task(progress_cb, cancel):
                return engine.decrypt(st, data, progress=progress_cb)

            self.win.run_task(task, self._on_ok_text, self._on_err)
        else:
            srcs = self.files.paths()
            if not srcs:
                self.banners.show('err', '✗ Добавьте хотя бы один файл')
                return
            outdir = self.out_rules.outdir()
            if self.out_rules.rb_dir.isChecked() and not outdir:
                self.banners.show('err', '✗ Укажите папку для результатов')
                return
            overwrite = self.out_rules.overwrite()
            try:
                jobs = [(s, stream.resolve_output_path(s, False, outdir,
                                                       overwrite))
                        for s in srcs]
            except OSError as exc:
                self.banners.show('err', '✗ %s' % exc)
                return
            if outdir:
                os.makedirs(outdir, exist_ok=True)

            def task(progress_cb, cancel):
                return stream.decrypt_files(st, jobs, progress_cb, cancel)

            self.win.run_task(task, self._on_ok_files, self._on_err)

    # ------------------------------------------------------------ results
    def _on_ok_text(self, res: engine.Result):
        info = res.meta
        self._last_plain = res.data
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

        lines = ['Время: %.2f с' % (info.get('total_ms', 0) / 1000.0)]
        if info.get('phc'):
            src = ('из файла' if info.get('params_from_packet')
                   else 'из настроек')
            lines.append('KDF: %s (%s)' % (info['phc'], src))
        if info.get('detected'):
            lines.append(info['detected'])
        self.banners.clear()
        if res.mode == 'siv':
            self.banners.add('ok', '✓ Подлинность подтверждена — %s · %s'
                             % (res.cipher, 'формат v%d'
                                % info.get('version', 1)),
                             ['Тег V сошёлся: пароль верен, данные не '
                              'изменялись ни на бит.'] + lines)
        else:
            self.banners.add('warn', '⚠ Расшифровано без проверки '
                                     'подлинности (ECB)',
                             ['Успешное снятие PKCS#7 не гарантирует, что '
                              'пароль верен, а данные не изменены.'] + lines)
        if res.warnings:
            self.banners.add('info', 'Примечания', res.warnings)
        self.win.set_status('Расшифрование завершено')
        self.win.refresh_packet_page(res)

    def _on_ok_files(self, reports):
        ok = [r for r in reports if r.ok]
        bad = [r for r in reports if not r.ok]
        total_out = sum(r.out_bytes for r in reports)
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
        speed = total_out / total_t / (1 << 20)
        siv = ok and ok[0].info.find('SIV') >= 0
        title = ('✓ Расшифровано файлов: %d из %d · подлинность '
                 'подтверждена' % (len(ok), len(reports))) if siv else \
                ('✓ Расшифровано файлов: %d из %d' % (len(ok), len(reports)))
        self.banners.add('ok' if not bad else ('err' if not ok else 'warn'),
                         title,
                         lines[:40] + ['Средняя скорость: %.1f МиБ/с'
                                       % speed])
        if not siv and ok:
            self.banners.add('warn', '⚠ ECB: без проверки подлинности',
                             ['Успешная расшифровка ECB не доказывает, что '
                              'данные не изменялись.'])
        self.win.set_status('Расшифрование завершено: %d из %d'
                            % (len(ok), len(reports)))

    def _on_err(self, exc):
        import traceback
        from ..workers import CancelledError
        if isinstance(exc, CancelledError):
            self.banners.show('info', 'Операция отменена')
            self.win.set_status('Отменено')
        elif isinstance(exc, MacError):
            self.banners.show('err', '✗ Проверка подлинности НЕ пройдена', [
                str(exc)])
            self.win.set_status('MAC не сошёлся')
        elif isinstance(exc, (PacketFormatError, PaddingError)):
            self.banners.show('err', '✗ Формат не распознан', [str(exc)])
            self.win.set_status('Ошибка формата')
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

    def _save_result(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Сохранить результат',
                                              'decrypted.bin', 'Все файлы (*)')
        if not path:
            return
        try:
            with open(path, 'wb') as f:
                f.write(self._last_plain)
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
