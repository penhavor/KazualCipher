# -*- coding: utf-8 -*-
"""
Панель настроек (сайдабар): выбор шифра и режима списком, источник ключа,
параметры Argon2id и тонкая настройка полей SIV-пакета (галочки + значения).
Всё, что здесь меняется, мгновенно отражается на вкладке «Пакет» и
сохраняется в QSettings (кроме пароля — он не сохраняется НИКОГДА).
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFormLayout, QGroupBox,
                               QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QPushButton, QSpinBox,
                               QStackedWidget, QVBoxLayout, QWidget)

from .. import engine
from ..kdf import KdfParams
from ..keys import PasswordKey, RawKey, parse_raw_key_hex, KeyMaterialError
from ..modes.siv import (SivOptions, MAGIC, PREFIX_BYTES, RANDOM_BYTES,
                         default_prefix_text, PacketFormatError)
from . import theme

_PRESETS = {
    'По умолчанию (64 МиБ · 3 · 4)': KdfParams(65536, 3, 4),
    'Быстрый (1 МиБ · 2 · 1)': KdfParams(1024, 2, 1),
    'Максимум (256 МиБ · 4 · 4)': KdfParams(262144, 4, 4),
}
_CUSTOM_PRESET = 'Свои параметры…'


def _two_line_item(lw: QListWidget, title: str, subtitle: str,
                   height: int = 58) -> QListWidgetItem:
    """Элемент списка «название + подпись» (шифры/режимы)."""
    item = QListWidgetItem(lw)
    item.setSizeHint(item.sizeHint().__class__(0, height))
    w = QWidget()
    v = QVBoxLayout(w)
    v.setContentsMargins(8, 5, 8, 5)
    v.setSpacing(1)
    t = QLabel(title)
    t.setStyleSheet('font-weight: 700; font-size: 11pt; background: transparent;')
    s = QLabel(subtitle)
    s.setWordWrap(True)
    s.setStyleSheet('color: %s; font-size: 8.5pt; background: transparent;'
                    % theme.MUTED)
    v.addWidget(t)
    v.addWidget(s)
    lw.setItemWidget(item, w)
    return item


class SettingsPanel(QWidget):
    """Собирает engine.Settings из виджетов; сигнал changed — на любое изменение."""

    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._loading = False
        self._build()
        self._wire()
        self._update_visibility()

    # ------------------------------------------------------------------ UI
    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)

        # ---- шифр ----
        g_cipher = QGroupBox('Шифр')
        v = QVBoxLayout(g_cipher)
        self.lst_cipher = QListWidget()
        for c in engine.CIPHERS:
            _two_line_item(self.lst_cipher, c.name, c.subtitle, 78)
        self.lst_cipher.setCurrentRow(0)
        self.lst_cipher.setToolTip(
            'Kazual-512 — рабочий шифр (блок/ключ 512 бит, 5 раундов).\n'
            'Kazual-64 — учебная версия того же алгоритма (блок/ключ 64 бита,\n'
            '2 раунда), пригодна для ручного счёта; НЕ для защиты данных.')
        v.addWidget(self.lst_cipher)
        root.addWidget(g_cipher)

        # ---- режим ----
        g_mode = QGroupBox('Режим работы')
        v = QVBoxLayout(g_mode)
        self.lst_mode = QListWidget()
        _two_line_item(self.lst_mode, 'SIV',
                       'аутентифицированное шифрование · пакет: prefix + params '
                       '+ random + V + шифрограмма · рекомендуется', 96)
        _two_line_item(self.lst_mode, 'ECB',
                       'простой режим · блоки независимы · PKCS#7 · без '
                       'проверки подлинности', 78)
        self.lst_mode.setCurrentRow(0)
        v.addWidget(self.lst_mode)
        root.addWidget(g_mode)

        # ---- ключ ----
        g_key = QGroupBox('Ключ')
        v = QVBoxLayout(g_key)
        self.cmb_key_src = QComboBox()
        self.cmb_key_src.addItem('Пароль (Argon2id)')
        self.cmb_key_src.addItem('Сырой ключ (hex)')
        v.addWidget(self.cmb_key_src)

        self.stack_key = QStackedWidget()
        # страница пароля
        pw = QWidget()
        hp = QHBoxLayout(pw)
        hp.setContentsMargins(0, 0, 0, 0)
        self.ed_password = QLineEdit()
        self.ed_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.ed_password.setPlaceholderText('пароль…')
        self.btn_eye = QPushButton('показать')
        self.btn_eye.setProperty('kind', 'flat')
        self.btn_eye.setCheckable(True)
        self.btn_eye.setFixedWidth(84)
        self.btn_eye.setToolTip('Показать/скрыть пароль')
        hp.addWidget(self.ed_password, 1)
        hp.addWidget(self.btn_eye)
        self.stack_key.addWidget(pw)
        # страница сырого ключа
        rk = QWidget()
        vr = QVBoxLayout(rk)
        vr.setContentsMargins(0, 0, 0, 0)
        vr.setSpacing(4)
        self.ed_rawkey = QLineEdit()
        self.ed_rawkey.setFont(theme.mono_font(9))
        self.ed_rawkey.setPlaceholderText('deadbeef cafebabe …')
        self.lbl_rawkey_hint = QLabel(
            'любая длина · растягивается ГОРНом до %d бит' % 0)
        self.lbl_rawkey_hint.setProperty('kind', 'muted')
        self.lbl_rawkey_hint.setStyleSheet('font-size: 8.5pt;')
        vr.addWidget(self.ed_rawkey)
        vr.addWidget(self.lbl_rawkey_hint)
        self.stack_key.addWidget(rk)
        v.addWidget(self.stack_key)
        root.addWidget(g_key)

        # ---- KDF ----
        self.g_kdf = QGroupBox('Параметры KDF — Argon2id')
        v = QVBoxLayout(self.g_kdf)
        v.setSpacing(6)
        self.cmb_preset = QComboBox()
        for name in list(_PRESETS) + [_CUSTOM_PRESET]:
            self.cmb_preset.addItem(name)
        v.addWidget(self.cmb_preset)

        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(6)
        self.sp_m = QSpinBox()
        self.sp_m.setRange(8, 4 * 1024 * 1024)
        self.sp_m.setValue(65536)
        self.sp_m.setSuffix(' КиБ')
        self.sp_m.setGroupSeparatorShown(True)
        self.sp_m.setToolTip('m — память в КиБ (минимум 8·p)')
        self.sp_t = QSpinBox()
        self.sp_t.setRange(1, 1000)
        self.sp_t.setValue(3)
        self.sp_t.setToolTip('t — число итераций (проходов)')
        self.sp_p = QSpinBox()
        self.sp_p.setRange(1, 32)
        self.sp_p.setValue(4)
        self.sp_p.setToolTip('p — параллелизм (дорожки/ядра)')
        form.addRow('m (память)', self.sp_m)
        form.addRow('t (итерации)', self.sp_t)
        form.addRow('p (параллелизм)', self.sp_p)
        v.addLayout(form)

        self.lbl_phc = QLabel()
        self.lbl_phc.setFont(theme.mono_font(8))
        self.lbl_phc.setStyleSheet(
            'color: %s; background: %s; border: 1px solid %s; border-radius: 6px;'
            'padding: 4px 8px;' % (theme.TEAL, theme.CARD, theme.BORDER))
        self.lbl_phc.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        v.addWidget(self.lbl_phc)
        self.lbl_kdf_note = QLabel()
        self.lbl_kdf_note.setProperty('kind', 'muted')
        self.lbl_kdf_note.setStyleSheet('font-size: 8.5pt;')
        self.lbl_kdf_note.setWordWrap(True)
        v.addWidget(self.lbl_kdf_note)
        root.addWidget(self.g_kdf)

        # ---- пакет SIV ----
        self.g_packet = QGroupBox('Пакет SIV')
        v = QVBoxLayout(self.g_packet)
        v.setSpacing(8)

        self.ck_prefix = QCheckBox('prefix — магические байты + бренд')
        self.ck_prefix.setToolTip(
            'Форматный фильтр «свой/чужой, той ли версии» — как \\x89PNG у '
            'картинок.\n256 бит: %s + текст, дополненный нулями.\nСам по себе '
            'нулевая энтропия, но покрыт MAC\u2019ом.' % MAGIC.hex(' ').upper())
        v.addWidget(self.ck_prefix)
        self.ed_prefix = QLineEdit()
        self.ed_prefix.setPlaceholderText(default_prefix_text('Kazual-512'))
        self.ed_prefix.setToolTip('Текст после магических байт (бренд + версия)')
        v.addWidget(self.ed_prefix)
        self.lbl_prefix_info = QLabel()
        self.lbl_prefix_info.setProperty('kind', 'muted')
        self.lbl_prefix_info.setStyleSheet('font-size: 8.5pt;')
        v.addWidget(self.lbl_prefix_info)

        self.ck_params = QCheckBox('params — PHC-строка Argon2id в пакете')
        self.ck_params.setToolTip(
            'Самоопписание KDF ($argon2id$m=…,t=…,p=…) с u16-длиной.\n'
            'Поднимете m/t — старые пакеты останутся читаемыми.\n'
            'Если выключить — расшифровать можно только с текущими '
            'параметрами в этой панели.')
        v.addWidget(self.ck_params)

        self.ck_random = QCheckBox('random — соль/nonce, 256 бит')
        self.ck_random.setToolTip(
            'Соль Argon2id: один пароль → разный мастер-ключ на каждое '
            'сообщение;\nнаблюдатель не видит повторов. Безопасность от него '
            'не зависит:\nесли ГСЧ сломается и random повторится, V всё равно '
            'разведёт разные тексты (в этом суть SIV).')
        v.addWidget(self.ck_random)
        self.ed_fixed_random = QLineEdit()
        self.ed_fixed_random.setFont(theme.mono_font(9))
        self.ed_fixed_random.setPlaceholderText(
            'фикс. значение: 64 hex-цифры (пусто = ГСЧ)')
        self.ed_fixed_random.setToolTip(
            'Необязательно: своё значение random вместо случайного —\n'
            'для воспроизводимых тестов. 32 байта = 64 hex-цифры.')
        v.addWidget(self.ed_fixed_random)

        lbl_v = QLabel('V — 512 бит: синтетический nonce CTR и тег '
                       'подлинности (MAC от всех полей + текста). Всегда в '
                       'пакете.')
        lbl_v.setProperty('kind', 'muted')
        lbl_v.setStyleSheet('font-size: 8.5pt;')
        lbl_v.setWordWrap(True)
        v.addWidget(lbl_v)
        root.addWidget(self.g_packet)

        # ---- предупреждение для учебного шифра ----
        self.lbl_edu = QLabel('⚠ Kazual-64 — учебный шифр: НЕ для защиты '
                              'данных ни при каких условиях.')
        self.lbl_edu.setWordWrap(True)
        self.lbl_edu.setStyleSheet(
            'color: %s; background: #33270f; border: 1px solid #7a5a17;'
            'border-radius: 8px; padding: 8px; font-size: 9pt;' % theme.WARNING)
        self.lbl_edu.hide()
        root.addWidget(self.lbl_edu)

        root.addStretch(1)
        self._update_phc()
        self._update_prefix_info()

    # ------------------------------------------------------------- wiring
    def _wire(self):
        self.lst_cipher.currentRowChanged.connect(self._on_changed)
        self.lst_mode.currentRowChanged.connect(self._on_changed)
        self.cmb_key_src.currentIndexChanged.connect(self._on_changed)
        self.ed_password.textChanged.connect(self._on_changed)
        self.ed_rawkey.textChanged.connect(self._on_changed)
        self.btn_eye.toggled.connect(self._toggle_eye)
        self.cmb_preset.currentIndexChanged.connect(self._apply_preset)
        for sp in (self.sp_m, self.sp_t, self.sp_p):
            sp.valueChanged.connect(self._on_spin_changed)
        self.ck_prefix.toggled.connect(self._on_changed)
        self.ed_prefix.textChanged.connect(self._on_prefix_text)
        self.ck_params.toggled.connect(self._on_changed)
        self.ck_random.toggled.connect(self._on_changed)
        self.ed_fixed_random.textChanged.connect(self._on_changed)

    def _toggle_eye(self, on: bool):
        self.ed_password.setEchoMode(
            QLineEdit.EchoMode.Normal if on
            else QLineEdit.EchoMode.Password)
        self.btn_eye.setText('скрыть' if on else 'показать')

    def _on_changed(self, *_):
        if not self._loading:
            self._update_visibility()
            self.changed.emit()

    def _on_prefix_text(self, *_):
        self._update_prefix_info()
        self._on_changed()

    def _on_spin_changed(self, *_):
        if self._loading:
            return
        # m ≥ 8·p — граница Argon2; мягко подводим пресет к «Свои»
        if self.sp_m.value() < 8 * self.sp_p.value():
            self.sp_m.blockSignals(True)
            self.sp_m.setValue(8 * self.sp_p.value())
            self.sp_m.blockSignals(False)
        self._apply_preset(self.cmb_preset.count() - 1)   # «Свои параметры…»
        self._update_phc()
        self.changed.emit()

    def _apply_preset(self, idx: int):
        name = self.cmb_preset.itemText(idx)
        if name in _PRESETS:
            p = _PRESETS[name]
            self._loading = True
            self.sp_m.setValue(p.memory_kib)
            self.sp_t.setValue(p.iterations)
            self.sp_p.setValue(p.parallelism)
            self._loading = False
        self._update_phc()
        if not self._loading:
            self._update_visibility()
            self.changed.emit()

    def _update_phc(self):
        self.lbl_phc.setText(self.kdf_params().phc_string())

    def _update_prefix_info(self):
        text = self.prefix_text() or default_prefix_text(self.cipher_name())
        n = len(MAGIC) + len(text.encode('utf-8'))
        ok = n <= PREFIX_BYTES
        self.lbl_prefix_info.setText(
            '%s: %s + «%s» = %d из %d байт%s' % (
                '✓' if ok else '✗', MAGIC.hex(' ').upper(), text, n,
                PREFIX_BYTES, '' if ok else ' — СОКРАТИТЕ ТЕКСТ'))
        self.lbl_prefix_info.setStyleSheet(
            'font-size: 8.5pt; color: %s;' % (theme.MUTED if ok else theme.DANGER))
        self.ed_prefix.setStyleSheet('' if ok else 'border: 1px solid %s;'
                                     % theme.DANGER)

    def _update_visibility(self):
        siv = self.mode() == 'siv'
        password = self.cmb_key_src.currentIndex() == 0
        self.stack_key.setCurrentIndex(0 if password else 1)
        self.g_packet.setVisible(siv)
        self.g_kdf.setVisible(password)
        self.lbl_edu.setVisible(self.cipher_name() == 'Kazual-64')
        self.lbl_rawkey_hint.setText(
            'любая длина · растягивается ГОРНом до %d бит'
            % (engine.CIPHER_BY_NAME[self.cipher_name()].key_bits))
        if siv:
            self.lbl_kdf_note.setText(
                'Записываются в поле params пакета' if self.ck_params.isChecked()
                else 'НЕ записываются в пакет — расшифровка только с ними же')
        else:
            self.lbl_kdf_note.setText(
                'ECB не хранит параметры: расшифровка — только с теми же')
        self._update_prefix_info()

    # -------------------------------------------------------------- API
    def cipher_name(self) -> str:
        return engine.CIPHERS[self.lst_cipher.currentRow()].name

    def mode(self) -> str:
        return 'siv' if self.lst_mode.currentRow() == 0 else 'ecb'

    def kdf_params(self) -> KdfParams:
        return KdfParams(memory_kib=self.sp_m.value(),
                         iterations=self.sp_t.value(),
                         parallelism=self.sp_p.value())

    def prefix_text(self) -> str:
        return self.ed_prefix.text().strip()

    def key_source(self):
        if self.cmb_key_src.currentIndex() == 0:
            pw = self.ed_password.text()
            if not pw:
                raise engine.KazualError('введите пароль (или переключитесь '
                                         'на сырой ключ)')
            return PasswordKey(pw)
        raw = self.ed_rawkey.text()
        if not raw.strip():
            raise engine.KazualError('введите сырой ключ в hex '
                                     '(или переключитесь на пароль)')
        try:
            return RawKey(parse_raw_key_hex(raw))
        except KeyMaterialError as exc:
            raise engine.KazualError(str(exc)) from exc

    def siv_options(self) -> SivOptions:
        """Настройки пакета без валидации ключа — для живой схемы «Пакет»."""
        return SivOptions(
            prefix_enabled=self.ck_prefix.isChecked(),
            prefix_text=self.prefix_text() or None,
            params_enabled=self.ck_params.isChecked(),
            kdf_params=self.kdf_params(),
            random_enabled=self.ck_random.isChecked(),
            fixed_random_hex=self.ed_fixed_random.text().strip(),
        )

    def settings(self) -> engine.Settings:
        """Собрать настройки; при ошибке ввода — engine.KazualError с текстом."""
        siv = self.siv_options()
        # ранняя валидация полей пакета — до тяжёлых операций
        name = self.cipher_name()
        try:
            siv.resolve_prefix(name)
            if siv.fixed_random_hex and siv.random_enabled:
                fixed = bytes.fromhex(''.join(siv.fixed_random_hex.split()))
                if len(fixed) != RANDOM_BYTES:
                    raise ValueError('нужно ровно %d байт' % RANDOM_BYTES)
        except (PacketFormatError, ValueError) as exc:
            raise engine.KazualError('настройки пакета: %s' % exc) from exc
        st = engine.Settings(cipher=name, mode=self.mode(),
                             source=self.key_source(),
                             kdf_params=self.kdf_params(), siv=siv)
        st.validate()
        return st

    # ------------------------------------------- persistence (QSettings)
    def save_state(self) -> dict:
        return {
            'cipherRow': self.lst_cipher.currentRow(),
            'modeRow': self.lst_mode.currentRow(),
            'keySrc': self.cmb_key_src.currentIndex(),
            'rawkey': self.ed_rawkey.text(),
            'm': self.sp_m.value(), 't': self.sp_t.value(),
            'p': self.sp_p.value(),
            'prefixOn': self.ck_prefix.isChecked(),
            'prefixText': self.ed_prefix.text(),
            'paramsOn': self.ck_params.isChecked(),
            'randomOn': self.ck_random.isChecked(),
            'fixedRandom': self.ed_fixed_random.text(),
        }

    def load_state(self, s: dict):
        self._loading = True
        try:
            self.lst_cipher.setCurrentRow(int(s.get('cipherRow', 0)))
            self.lst_mode.setCurrentRow(int(s.get('modeRow', 0)))
            self.cmb_key_src.setCurrentIndex(int(s.get('keySrc', 0)))
            self.ed_rawkey.setText(s.get('rawkey', ''))
            params = KdfParams(int(s.get('m', 65536)), int(s.get('t', 3)),
                               int(s.get('p', 4)))
            preset_hit = next((i for i, (nm, p) in enumerate(_PRESETS.items())
                               if p == params), None)
            self.cmb_preset.setCurrentIndex(
                preset_hit if preset_hit is not None
                else self.cmb_preset.count() - 1)
            if preset_hit is None:
                self.sp_m.setValue(params.memory_kib)
                self.sp_t.setValue(params.iterations)
                self.sp_p.setValue(params.parallelism)
            self.ck_prefix.setChecked(s.get('prefixOn', True))
            self.ed_prefix.setText(s.get('prefixText', ''))
            self.ck_params.setChecked(s.get('paramsOn', True))
            self.ck_random.setChecked(s.get('randomOn', True))
            self.ed_fixed_random.setText(s.get('fixedRandom', ''))
        finally:
            self._loading = False
        self._update_visibility()
        self._update_phc()

    def set_defaults(self):
        """Значения по умолчанию (первый запуск)."""
        self.ck_prefix.setChecked(True)
        self.ck_params.setChecked(True)
        self.ck_random.setChecked(True)
