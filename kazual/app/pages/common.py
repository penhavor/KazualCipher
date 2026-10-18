# -*- coding: utf-8 -*-
"""Общие строительные блоки страниц ввода/вывода."""

from __future__ import annotations

import base64
import binascii
import os
import re
from typing import List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QFileDialog, QFrame, QHBoxLayout,
                               QLabel, QLineEdit, QListWidget, QListWidgetItem,
                               QPushButton, QRadioButton, QVBoxLayout,
                               QWidget)

from ... import engine
from .. import theme

_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')


def decode_text_input(text: str, fmt: str = 'auto') -> bytes:
    """Строка из поля ввода → байты пакета. fmt: 'auto' | 'base64' | 'hex'."""
    s = text.strip()
    if not s:
        raise engine.KazualError('вставьте данные для расшифровки')
    compact = re.sub(r'\s+', '', s)
    is_hex = bool(_HEX_RE.match(compact)) and len(compact) % 2 == 0
    if fmt == 'hex' or (fmt == 'auto' and is_hex):
        if not is_hex:
            raise engine.KazualError(
                'данные не похожи на hex-строку (ожидались пары цифр 0-9a-f '
                'чётной длины)')
        return bytes.fromhex(compact)
    if fmt == 'base64' or fmt == 'auto':
        try:
            return base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise engine.KazualError(
                'не удалось распознать формат: это не Base64 (%s) и не HEX. '
                'Проверьте, что скопировали пакет целиком.' % exc) from exc
    raise engine.KazualError('неизвестный формат ввода: %s' % fmt)


def encode_output(data: bytes, fmt: str) -> str:
    """Байты → строка для поля вывода. fmt: 'base64' | 'hex'."""
    if fmt == 'hex':
        return data.hex().upper()
    return base64.b64encode(data).decode('ascii')


def try_decode_utf8(data: bytes) -> Optional[str]:
    """UTF-8-текст из байт или None (двоичные данные)."""
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return None


def human_size(n: float) -> str:
    """1024 → «1.0 КиБ»; байты без дробной части."""
    if n < 1024:
        return '%d Б' % n
    for unit in ('КиБ', 'МиБ', 'ГиБ', 'ТиБ'):
        n /= 1024.0
        if n < 1024 or unit == 'ТиБ':
            return '%.1f %s' % (n, unit)
    return '%d Б' % n


class FileRow(QWidget):
    """Строка «путь + кнопка Обзор…» (для одиночных путей/папок)."""

    def __init__(self, placeholder: str, mode: str = 'open', parent=None):
        super().__init__(parent)
        self.mode = mode
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(6)
        self.edit = QLineEdit()
        self.edit.setPlaceholderText(placeholder)
        self.edit.setClearButtonEnabled(mode == 'open')
        btn = QPushButton('Обзор…')
        btn.setFixedWidth(86)
        btn.clicked.connect(self._browse)
        h.addWidget(self.edit, 1)
        h.addWidget(btn)

    def _browse(self):
        if self.mode == 'open':
            path, _ = QFileDialog.getOpenFileName(self, 'Выберите файл')
        elif self.mode == 'dir':
            path = QFileDialog.getExistingDirectory(self, 'Выберите папку')
        else:
            path, _ = QFileDialog.getSaveFileName(self, 'Сохранить как')
        if path:
            self.edit.setText(path)

    def path(self) -> str:
        return self.edit.text().strip()

    def set_path(self, p: str):
        self.edit.setText(p)


class FileListWidget(QWidget):
    """Список файлов для пакетной обработки: добавление, удаление, drag&drop.

    Показывает имя и размер; хранит абсолютные пути без дубликатов.
    """

    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)

        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.btn_add = QPushButton('+ Файлы…')
        self.btn_add_dir = QPushButton('+ Папку…')
        self.btn_rm = QPushButton('− Убрать')
        self.btn_clear = QPushButton('Очистить')
        for b in (self.btn_add, self.btn_add_dir, self.btn_rm,
                  self.btn_clear):
            b.setStyleSheet('padding: 5px 10px;')
        bar.addWidget(self.btn_add)
        bar.addWidget(self.btn_add_dir)
        bar.addStretch(1)
        bar.addWidget(self.btn_rm)
        bar.addWidget(self.btn_clear)
        v.addLayout(bar)

        self.list = QListWidget()
        self.list.setAcceptDrops(True)
        self.list.setDragDropMode(QListWidget.DragDropMode.NoDragDrop)
        self.list.setSelectionMode(
            QListWidget.SelectionMode.ExtendedSelection)
        self.list.setUniformItemSizes(True)
        self.list.setMinimumHeight(120)
        v.addWidget(self.list, 1)

        self.lbl_count = QLabel('Файлов: 0 — перетащите сюда или нажмите '
                                '«+ Файлы…»')
        self.lbl_count.setProperty('kind', 'muted')
        self.lbl_count.setStyleSheet('font-size: 8.5pt;')
        v.addWidget(self.lbl_count)

        self.btn_add.clicked.connect(self._add_files)
        self.btn_add_dir.clicked.connect(self._add_dir)
        self.btn_rm.clicked.connect(self._remove)
        self.btn_clear.clicked.connect(self.clear)
        self.list.viewport().installEventFilter(self)
        self.list.model().rowsInserted.connect(lambda *_: self._update_count())
        self.list.model().rowsRemoved.connect(lambda *_: self._update_count())

    # ---- drag & drop ----
    def eventFilter(self, obj, ev):                       # noqa: N802
        if obj is self.list.viewport():
            from PySide6.QtCore import QEvent
            if ev.type() == QEvent.Type.DragEnter:
                if ev.mimeData().hasUrls():
                    ev.acceptProposedAction()
                    return True
            elif ev.type() == QEvent.Type.Drop:
                urls = [u.toLocalFile() for u in ev.mimeData().urls()
                        if u.isLocalFile()]
                if urls:
                    self.add_paths(urls)
                    ev.acceptProposedAction()
                    return True
        return super().eventFilter(obj, ev)

    # ---- API ----
    def _add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, 'Выберите файлы')
        if paths:
            self.add_paths(paths)

    def _add_dir(self):
        d = QFileDialog.getExistingDirectory(self, 'Выберите папку')
        if not d:
            return
        try:
            entries = sorted(
                os.path.join(d, n) for n in os.listdir(d)
                if os.path.isfile(os.path.join(d, n)))
        except OSError:
            entries = []
        if entries:
            self.add_paths(entries)

    def add_paths(self, paths):
        existing = set(self.paths())
        added = False
        for p in paths:
            p = os.path.abspath(p)
            if os.path.isdir(p):
                for root, _dirs, files in os.walk(p):
                    for n in sorted(files):
                        fp = os.path.join(root, n)
                        if fp not in existing:
                            self._append(fp)
                            existing.add(fp)
                            added = True
            elif os.path.isfile(p) and p not in existing:
                self._append(p)
                existing.add(p)
                added = True
        if added:
            self.changed.emit()
            self._update_count()

    def _append(self, p: str):
        try:
            size = os.path.getsize(p)
            txt = '%s  —  %s' % (p, human_size(size))
        except OSError:
            txt = p
        item = QListWidgetItem(txt)
        item.setData(Qt.ItemDataRole.UserRole, p)
        item.setToolTip(p)
        self.list.addItem(item)

    def _remove(self):
        for item in self.list.selectedItems():
            self.list.takeItem(self.list.row(item))
        self.changed.emit()
        self._update_count()

    def clear(self):
        self.list.clear()
        self.changed.emit()
        self._update_count()

    def paths(self) -> List[str]:
        return [self.list.item(i).data(Qt.ItemDataRole.UserRole)
                for i in range(self.list.count())]

    def _update_count(self):
        n = self.list.count()
        total = 0
        for i in range(n):
            p = self.list.item(i).data(Qt.ItemDataRole.UserRole)
            try:
                total += os.path.getsize(p)
            except OSError:
                pass
        self.lbl_count.setText(
            'Файлов: %d · суммарно %s' % (n, human_size(total)) if n
            else 'Файлов: 0 — перетащите сюда или нажмите «+ Файлы…»')

    def setEnabled(self, on: bool):                       # noqa: N802
        super().setEnabled(on)


class OutputRules(QWidget):
    """Правила сохранения результатов пакетной операции."""

    changed = Signal()

    def __init__(self, enc_suffix: str = '.kaz', parent=None):
        super().__init__(parent)
        self.enc_suffix = enc_suffix
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)
        row = QHBoxLayout()
        row.setSpacing(14)
        self.rb_next = QRadioButton('Рядом с источником')
        self.rb_dir = QRadioButton('В папку:')
        self.rb_next.setChecked(True)
        row.addWidget(self.rb_next)
        row.addWidget(self.rb_dir)
        row.addStretch(1)
        v.addLayout(row)
        self.row_dir = FileRow('папка для результатов…', 'dir')
        self.row_dir.setEnabled(False)
        v.addWidget(self.row_dir)
        self.ck_overwrite = QCheckBox('Перезаписывать существующие файлы '
                                      '(иначе будет подобрано свободное имя)')
        v.addWidget(self.ck_overwrite)
        self.rb_dir.toggled.connect(self.row_dir.setEnabled)
        def _emit(*_):
            if not getattr(self, '_loading', False):
                self.changed.emit()
        self.rb_next.toggled.connect(_emit)
        self.rb_dir.toggled.connect(_emit)
        self.row_dir.edit.textChanged.connect(_emit)
        self.ck_overwrite.toggled.connect(_emit)

    # ---- API ----
    def outdir(self) -> Optional[str]:
        return self.row_dir.path() or None if self.rb_dir.isChecked() else None

    def overwrite(self) -> bool:
        return self.ck_overwrite.isChecked()

    def set_defaults(self, out_rule: str, out_dir: str, overwrite: bool):
        self._loading = True
        try:
            self._set(out_rule, out_dir, overwrite)
        finally:
            self._loading = False

    def _set(self, out_rule: str, out_dir: str, overwrite: bool):
        self.rb_dir.setChecked(out_rule == 'folder' and bool(out_dir))
        self.rb_next.setChecked(not self.rb_dir.isChecked())
        if out_dir:
            self.row_dir.set_path(out_dir)
        self.ck_overwrite.setChecked(overwrite)

    def collect(self) -> dict:
        return {'out_rule': 'folder' if self.rb_dir.isChecked() else 'next',
                'out_dir': self.row_dir.path(),
                'overwrite': self.ck_overwrite.isChecked()}


class DetectionCard(QFrame):
    """Карточка «что определено по файлу» для страницы расшифровки."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty('kind', 'bannerInfo')
        v = QVBoxLayout(self)
        v.setContentsMargins(12, 8, 12, 8)
        v.setSpacing(2)
        self.title = QLabel('')
        self.title.setWordWrap(True)
        self.title.setStyleSheet('font-weight: 700; color: %s; '
                                 'background: transparent;' % theme.TEAL)
        self.body = QLabel('')
        self.body.setWordWrap(True)
        self.body.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.body.setStyleSheet('color: %s; background: transparent; '
                                'font-size: 9pt;' % theme.TEXT)
        v.addWidget(self.title)
        v.addWidget(self.body)
        self.setVisible(False)

    def show_detection(self, title: str, body: str, color: str = None):
        self.title.setText(title)
        self.body.setText(body)
        c = color or theme.TEAL
        self.title.setStyleSheet('font-weight: 700; color: %s; '
                                 'background: transparent;' % c)
        self.setVisible(True)

    def hide_detection(self):
        self.setVisible(False)


def banner(kind: str, title: str, lines=None) -> QWidget:
    """Цветной баннер результата: kind = ok|warn|err|info."""
    prop = {'ok': 'bannerOk', 'warn': 'bannerWarn', 'err': 'bannerErr',
            'info': 'bannerInfo'}[kind]
    color = {'ok': theme.SUCCESS, 'warn': theme.WARNING,
             'err': theme.DANGER, 'info': theme.TEXT}[kind]
    frame = QFrame()
    frame.setProperty('kind', prop)
    v = QVBoxLayout(frame)
    v.setContentsMargins(12, 8, 12, 8)
    v.setSpacing(2)
    t = QLabel(title)
    t.setWordWrap(True)
    t.setStyleSheet('font-weight: 700; color: %s; background: transparent;'
                    % color)
    v.addWidget(t)
    for line in (lines or []):
        lbl = QLabel(line)
        lbl.setWordWrap(True)
        lbl.setStyleSheet(
            'color: %s; background: transparent; font-size: 9pt;' % color)
        lbl.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        v.addWidget(lbl)
    return frame


class BannerBox(QVBoxLayout):
    """Стопка баннеров с очисткой (результаты операций)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSpacing(6)

    def clear(self):
        while self.count():
            item = self.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def show(self, kind, title, lines=None):
        self.clear()
        self.add(kind, title, lines)

    def add(self, kind, title, lines=None):
        self.addWidget(banner(kind, title, lines))
