# -*- coding: utf-8 -*-
"""Общие строительные блоки страниц ввода/вывода."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QFileDialog, QFrame, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QVBoxLayout, QWidget)

from ... import engine
from .. import theme

_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')


def decode_text_input(text: str, fmt: str = 'auto') -> bytes:
    """Строка из поля ввода → байты пакета. fmt: 'auto' | 'base64' | 'hex'.

    Авто-распознавание: строгая hex-строка чётной длины → hex, иначе Base64.
    Base64-пакеты практически всегда содержат символы вне 0-9a-f, поэтому
    перепутать форматы почти невозможно; при сомнениях формат задаётся вручную.
    """
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
    """Строка «путь к файлу + кнопка Обзор»."""

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
        else:
            path, _ = QFileDialog.getSaveFileName(self, 'Сохранить как')
        if path:
            self.edit.setText(path)

    def path(self) -> str:
        return self.edit.text().strip()

    def set_path(self, p: str):
        self.edit.setText(p)


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
