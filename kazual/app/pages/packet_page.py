# -*- coding: utf-8 -*-
"""Страница «Пакет»: живая схема SIV-пакета и разбор реального примера."""

from __future__ import annotations

from PySide6.QtCore import Qt, QRectF, Signal
from PySide6.QtGui import (QBrush, QColor, QFont, QPainter, QPen,
                           QGuiApplication)
from PySide6.QtWidgets import (QHBoxLayout, QHeaderView, QLabel, QPushButton,
                               QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget, QPlainTextEdit)

from ... import engine
from .. import theme
from . import common

FIELD_COLORS = {
    'prefix': '#f5a623',
    'params': '#2dd4bf',
    'random': '#6d5df6',
    'V': '#34d399',
    'ciphertext': '#5b8def',
}

FIELD_NOTES = {
    'prefix': '«магические байты» 89 4B 5A 4C + бренд + версия — как ‰PNG у '
              'картинок. Нулевая энтропия и нулевая защита сам по себе: это '
              'форматный фильтр «свой/чужой, той ли версии», покрытый MAC’ом.',
    'params': 'самоопписание KDF в PHC-стиле ($argon2id$m=…,t=…,p=…) с '
              'u16-длиной. Поднимете m/t — старые пакеты останутся читаемыми: '
              'параметры лежат в них самих.',
    'random': 'соль Argon2id: даже один пароль даёт разный мастер-ключ на '
              'каждое сообщение; наблюдатель не видит повторов. Безопасность '
              'от него не зависит: если ГСЧ сломается и random повторится, '
              'V всё равно разведёт разные тексты (в этом суть SIV).',
    'V': 'синтетический nonce для CTR и тег подлинности в одном лице: '
         'MAC(K_mac) от всех полей пакета + открытого текста. Всегда 512 бит.',
    'ciphertext': 'CTR(K_enc, V‖counter) без сцеплений: блоки независимы, '
                  'параллелятся, паддинга нет.',
}


class PacketDiagram(QWidget):
    """Схематичная диаграмма пакета: ширина ∝ √размера поля."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(128)
        self._fields = []            # [(name, size, enabled)]
        self._total_note = ''

    def set_fields(self, fields, total_note=''):
        self._fields = fields
        self._total_note = total_note
        self.update()

    def paintEvent(self, ev):                              # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w = self.width() - 8
        h = 62.0
        y = 26.0

        fields = self._fields or []
        if not fields:
            p.setPen(QColor(theme.MUTED))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                       'Выберите режим SIV слева — здесь появится схема пакета')
            p.end()
            return

        # ширины: sqrt-масштаб с минимумом; отключённые поля — узкие
        import math
        weights = []
        for name, size, enabled in fields:
            weights.append(math.sqrt(max(size, 1)) * 2.6 if enabled else 6.0)
        total_w = sum(weights)
        gap = 4
        avail = w - gap * (len(fields) - 1)
        widths = [max(10.0, avail * wt / total_w) for wt in weights]

        p.setFont(QFont(self.font().family(), 11, QFont.Weight.Bold))
        p.drawText(QRectF(8, 2, w, 20), Qt.AlignmentFlag.AlignLeft,
                   'Макет пакета: ' + ' + '.join(
                       n if e else '%s̶' % n for n, _, e in fields))

        x = 4.0
        small = QFont(self.font().family(), 8)
        for (name, size, enabled), bw in zip(fields, widths):
            color = QColor(FIELD_COLORS.get(name, theme.MUTED))
            rect = QRectF(x, y, bw, h)
            if enabled:
                color.setAlpha(58)
                p.setPen(QPen(QColor(FIELD_COLORS.get(name, theme.MUTED)), 1.6))
                p.setBrush(QBrush(color))
                p.drawRoundedRect(rect, 8, 8)
                p.setPen(QColor(theme.TEXT))
                p.setFont(QFont(self.font().family(), 9, QFont.Weight.DemiBold))
                if bw > 64:
                    p.drawText(rect.adjusted(4, 4, -4, -18),
                               Qt.AlignmentFlag.AlignCenter, name)
                    p.setFont(small)
                    p.setPen(QColor(theme.MUTED))
                    p.drawText(rect.adjusted(4, 20, -4, -4),
                               Qt.AlignmentFlag.AlignCenter,
                               '%d Б' % size if size else '—')
                else:
                    p.setFont(small)
                    p.drawText(rect.adjusted(-18, 4, 18, -20),
                               Qt.AlignmentFlag.AlignCenter, name)
                    p.setPen(QColor(theme.MUTED))
                    p.drawText(rect.adjusted(-24, 24, 24, -2),
                               Qt.AlignmentFlag.AlignCenter, '%d Б' % size)
            else:
                pen = QPen(QColor(theme.MUTED), 1.2, Qt.PenStyle.DashLine)
                p.setPen(pen)
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawRoundedRect(rect, 8, 8)
                p.setFont(small)
                p.drawText(rect.adjusted(-20, 0, 20, 0),
                           Qt.AlignmentFlag.AlignCenter, '%s выкл' % name)
            x += bw + gap

        p.setFont(small)
        p.setPen(QColor(theme.MUTED))
        p.drawText(QRectF(8, y + h + 4, w, 18), Qt.AlignmentFlag.AlignLeft,
                   self._total_note)
        p.end()


class PacketPage(QWidget):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self._build()
        self.refresh()

    def _build(self):
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 18, 24, 18)
        v.setSpacing(12)

        head = QLabel('Структура пакета')
        head.setProperty('kind', 'title')
        sub = QLabel('Схема обновляется вживую при переключении галочек '
                     'слева; кнопка ниже собирает настоящий пакет на '
                     'примере текста и раскладывает его по байтам.')
        sub.setProperty('kind', 'subtitle')
        sub.setWordWrap(True)
        v.addWidget(head)
        v.addWidget(sub)

        self.diagram = PacketDiagram()
        v.addWidget(self.diagram)

        # ---- живой пример ----
        row = QHBoxLayout()
        self.btn_example = QPushButton('Собрать пример на текущих настройках')
        self.btn_example.clicked.connect(self._build_example)
        row.addWidget(self.btn_example)
        self.lbl_example_state = QLabel('')
        self.lbl_example_state.setProperty('kind', 'muted')
        self.lbl_example_state.setStyleSheet('font-size: 9pt;')
        row.addWidget(self.lbl_example_state, 1)
        v.addLayout(row)

        self.ed_example = QPlainTextEdit()
        self.ed_example.setPlainText('Kazual packet demo — пример пакета')
        self.ed_example.setMaximumHeight(56)
        self.ed_example.setToolTip('Текст примера (можно изменить)')
        v.addWidget(self.ed_example)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(['Поле', 'Размер', 'Содержимое'])
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setStyleSheet('QTableWidget { background: %s; border: 1px '
                                 'solid %s; border-radius: 10px; }'
                                 'QHeaderView::section { background: %s; '
                                 'border: none; padding: 6px; color: %s; }'
                                 % (theme.PANEL, theme.BORDER, theme.PANEL,
                                    theme.MUTED))
        self.table.setMinimumHeight(180)
        v.addWidget(self.table, 1)

        # ---- описания полей ----
        notes = QLabel('')
        notes.setWordWrap(True)
        notes.setTextFormat(Qt.TextFormat.RichText)
        notes.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        notes.setStyleSheet('font-size: 9pt; color: %s;' % theme.MUTED)
        notes.setText('<br>'.join(
            '<b style="color:%s">%s</b> — %s'
            % (FIELD_COLORS[k], k, FIELD_NOTES[k])
            for k in ('prefix', 'params', 'random', 'V', 'ciphertext')))
        v.addWidget(notes, 0)

    # -------------------------------------------------------------- logic
    def refresh(self, result: engine.Result = None):
        """Перерисовать схему по текущим настройкам сайдбара."""
        sb = self.win.sidebar
        if sb.mode() != 'siv':
            self.diagram.set_fields(
                [('ciphertext', 64, True)],
                'ECB: контейнера нет — только шифроблоки с PKCS#7-дополнением '
                '(оверхед 1…%d Б)' % engine.CIPHER_BY_NAME[
                    sb.cipher_name()].spec.block_bytes)
            self.btn_example.setEnabled(True)
            return
        opts = sb.siv_options()
        try:
            prefix = opts.resolve_prefix(sb.cipher_name())
            params = opts.resolve_params_field()
        except (engine.KazualError, ValueError):
            prefix, params = b'', b''
        sample_len = max(1, len(self.ed_example.toPlainText().encode('utf-8')))
        rnd = 32 if opts.random_enabled else 0
        fields = [
            ('prefix', len(prefix), opts.prefix_enabled),
            ('params', len(params), opts.params_enabled),
            ('random', rnd, opts.random_enabled),
            ('V', 64, True),
            ('ciphertext', sample_len, True),
        ]
        total = sum(s for _, s, e in fields if e)
        self.diagram.set_fields(
            fields,
            'пример: текст %d Б → пакет %d Б (оверхед +%d Б, %.0f%%)'
            % (sample_len, total, total - sample_len,
               100.0 * (total - sample_len) / sample_len))

    def _build_example(self):
        if self.win.is_busy():
            return
        try:
            st = self.win.sidebar.settings()
        except engine.KazualError as exc:
            self.lbl_example_state.setText('✗ %s' % exc)
            return
        data = self.ed_example.toPlainText().encode('utf-8')

        def task(progress_cb):
            return engine.encrypt(st, data, progress=progress_cb)

        self.lbl_example_state.setText('собираю пример…')
        self.btn_example.setEnabled(False)
        self.win.run_task(task, self._on_example, self._on_example_err,
                          page=self)

    def _on_example(self, res: engine.Result):
        self.btn_example.setEnabled(True)
        self.lbl_example_state.setText(
            'пример собран: %s · %s · %d Б' %
            (res.cipher, res.mode.upper(), len(res.data)))
        self.table.setRowCount(0)
        for f in res.fields:
            if not f.size and f.name != 'ciphertext':
                content = '— отключено —'
            elif f.name == 'params' and f.size:
                content = f.data[2:].decode('ascii', 'replace')
            elif f.name == 'prefix' and f.size:
                content = ('%s  «%s»' % (
                    f.data[:4].hex(' ').upper(),
                    f.data[4:].rstrip(b'\x00').decode('utf-8', 'replace')))
            else:
                hexs = f.data.hex(' ').upper()
                content = hexs if len(hexs) <= 96 else hexs[:96] + ' …'
            r = self.table.rowCount()
            self.table.insertRow(r)
            name_item = QTableWidgetItem(f.name)
            name_item.setForeground(QBrush(QColor(
                FIELD_COLORS.get(f.name, theme.TEXT))))
            fnt = QFont()
            fnt.setBold(True)
            name_item.setFont(fnt)
            self.table.setItem(r, 0, name_item)
            self.table.setItem(r, 1, QTableWidgetItem(
                common.human_size(f.size)))
            c_item = QTableWidgetItem(content)
            c_item.setFont(theme.mono_font(8))
            self.table.setItem(r, 2, c_item)
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem('ИТОГО'))
        self.table.setItem(r, 1, QTableWidgetItem(
            common.human_size(len(res.data))))
        self.table.setItem(r, 2, QTableWidgetItem(
            'оверхед +%d Б' % res.meta.get('overhead', 0)))

    def _on_example_err(self, exc):
        self.btn_example.setEnabled(True)
        from ..workers import CancelledError
        if isinstance(exc, CancelledError):
            self.lbl_example_state.setText('отменено')
        else:
            self.lbl_example_state.setText('✗ %s' % exc)

    def set_busy(self, busy: bool):
        self.btn_example.setEnabled(not busy)

    def on_progress(self, stage, frac):
        self.lbl_example_state.setText(stage)
        self.win.set_status(stage)
