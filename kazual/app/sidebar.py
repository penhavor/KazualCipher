# -*- coding: utf-8 -*-
"""
Панель настроек (сайдабар): шифр, режим, ключ, Argon2id и «Дополнительно»
(формат пакета, бренд, поля params/random). Управляется словарём конфига
(kazual.config): apply_config() / collect_config(). Всё, что меняется,
мгновенно отражается на вкладке «Пакет» и автосохраняется.

Для расшифровки контейнеров v2 панель умеет блокироваться: настройки
читаются из файла, а не вводятся вручную (lock_from_detection/unlock).
Пароль в конфиг не попадает НИКОГДА.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFormLayout, QFrame,
                               QGroupBox, QHBoxLayout, QLabel, QLineEdit,
                               QPushButton, QSpinBox, QStackedWidget,
                               QVBoxLayout, QWidget)

from .. import engine
from ..kdf import KdfParams
from ..keys import PasswordKey, RawKey, parse_raw_key_hex, KeyMaterialError
from ..modes.siv import SivOptions, MAGIC
from . import theme

_PRESET_ITEMS = [
    ('Стандартный — 64 МиБ · 3 прохода · 4 дорожки', 'balanced'),
    ('Быстрый — 1 МиБ · 2 · 1 (тесты, слабые машины)', 'fast'),
    ('Усиленный — 256 МиБ · 4 · 4 (медленный вход по паролю)', 'strong'),
    ('Свои параметры…', 'custom'),
]
_PRESET_BY_ID = {pid: i for i, (_, pid) in enumerate(_PRESET_ITEMS)}


class SettingsPanel(QWidget):
    """Собирает engine.Settings из виджетов; сигнал changed — на любое изменение."""

    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._loading = False
        self._locked = False
        self._build()
        self._wire()
        self._refresh_dynamic()

    # ------------------------------------------------------------------ UI
    @staticmethod
    def _fit_combo(c):
        """Комбобокс не растягивается по самому длинному пункту — иначе
        сайдбар расползается и текст обрезается."""
        from PySide6.QtWidgets import QComboBox
        c.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        c.setMinimumContentsLength(18)
        c.setToolTipDuration(-1)

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 8, 0)
        root.setSpacing(10)

        # ---- баннер блокировки (расшифровка: параметры из файла) ----
        self.lock_banner = QLabel()
        self.lock_banner.setWordWrap(True)
        self.lock_banner.setStyleSheet(
            'color: %s; background: #14321f; border: 1px solid #1f6b40;'
            'border-radius: 8px; padding: 8px; font-size: 9pt;' % theme.SUCCESS)
        self.lock_banner.hide()
        root.addWidget(self.lock_banner)

        # ---- шифр ----
        g = QGroupBox('Шифр')
        v = QVBoxLayout(g)
        v.setSpacing(4)
        self.cmb_cipher = QComboBox()
        for c in engine.CIPHERS:
            self.cmb_cipher.addItem(c.name)
        self._fit_combo(self.cmb_cipher)
        v.addWidget(self.cmb_cipher)
        self.lbl_cipher = QLabel()
        self.lbl_cipher.setProperty('kind', 'muted')
        self.lbl_cipher.setWordWrap(True)
        self.lbl_cipher.setStyleSheet('font-size: 8.5pt;')
        v.addWidget(self.lbl_cipher)
        root.addWidget(g)

        # ---- режим ----
        g = QGroupBox('Режим')
        v = QVBoxLayout(g)
        v.setSpacing(4)
        self.cmb_mode = QComboBox()
        self.cmb_mode.addItem('SIV — с проверкой подлинности')
        self.cmb_mode.addItem('ECB — простой (учебный)')
        self._fit_combo(self.cmb_mode)
        v.addWidget(self.cmb_mode)
        self.lbl_mode = QLabel()
        self.lbl_mode.setProperty('kind', 'muted')
        self.lbl_mode.setWordWrap(True)
        self.lbl_mode.setStyleSheet('font-size: 8.5pt;')
        v.addWidget(self.lbl_mode)
        root.addWidget(g)

        # ---- ключ ----
        g = QGroupBox('Ключ')
        v = QVBoxLayout(g)
        v.setSpacing(6)
        self.cmb_key_src = QComboBox()
        self.cmb_key_src.addItem('Пароль (через Argon2id)')
        self.cmb_key_src.addItem('Сырой ключ (hex)')
        self._fit_combo(self.cmb_key_src)
        v.addWidget(self.cmb_key_src)

        self.stack_key = QStackedWidget()
        pw = QWidget()
        hp = QHBoxLayout(pw)
        hp.setContentsMargins(0, 0, 0, 0)
        self.ed_password = QLineEdit()
        self.ed_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.ed_password.setPlaceholderText('пароль…')
        self.btn_eye = QPushButton('показать')
        self.btn_eye.setProperty('kind', 'flat')
        self.btn_eye.setCheckable(True)
        self.btn_eye.setFixedWidth(86)
        self.btn_eye.setToolTip('Показать/скрыть пароль')
        hp.addWidget(self.ed_password, 1)
        hp.addWidget(self.btn_eye)
        self.stack_key.addWidget(pw)

        rk = QWidget()
        vr = QVBoxLayout(rk)
        vr.setContentsMargins(0, 0, 0, 0)
        vr.setSpacing(3)
        self.ed_rawkey = QLineEdit()
        self.ed_rawkey.setFont(theme.mono_font(9))
        self.ed_rawkey.setPlaceholderText('deadbeef cafebabe …')
        self.lbl_rawkey = QLabel()
        self.lbl_rawkey.setStyleSheet('font-size: 8.5pt;')
        self.lbl_rawkey.setWordWrap(True)
        vr.addWidget(self.ed_rawkey)
        vr.addWidget(self.lbl_rawkey)
        self.stack_key.addWidget(rk)
        v.addWidget(self.stack_key)

        # ---- KDF ----
        self.cmb_preset = QComboBox()
        for name, _pid in _PRESET_ITEMS:
            self.cmb_preset.addItem(name)
        self._fit_combo(self.cmb_preset)
        v.addWidget(self.cmb_preset)
        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.setHorizontalSpacing(8)
        form.setVerticalSpacing(4)
        self.sp_m = QSpinBox()
        self.sp_m.setRange(8, 4 * 1024 * 1024)
        self.sp_m.setValue(65536)
        self.sp_m.setSuffix(' КиБ')
        self.sp_m.setGroupSeparatorShown(True)
        self.sp_m.setToolTip('m — память в КиБ (минимум 8·p)')
        self.sp_t = QSpinBox()
        self.sp_t.setRange(1, 1000)
        self.sp_t.setValue(3)
        self.sp_t.setToolTip('t — число проходов')
        self.sp_p = QSpinBox()
        self.sp_p.setRange(1, 32)
        self.sp_p.setValue(4)
        self.sp_p.setToolTip('p — параллелизм (дорожки)')
        form.addRow('m (память)', self.sp_m)
        form.addRow('t (проходы)', self.sp_t)
        form.addRow('p (дорожки)', self.sp_p)
        v.addLayout(form)
        self.lbl_phc = QLabel()
        self.lbl_phc.setFont(theme.mono_font(8))
        self.lbl_phc.setStyleSheet(
            'color: %s; background: %s; border: 1px solid %s;'
            'border-radius: 6px; padding: 3px 6px;'
            % (theme.TEAL, theme.CARD, theme.BORDER))
        self.lbl_phc.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_phc.setToolTip('Эта строка сохраняется в файл (поле params) '
                                'и при расшифровке берётся оттуда')
        v.addWidget(self.lbl_phc)
        root.addWidget(g)

        # ---- дополнительно (сворачиваемое) ----
        self.btn_adv = QPushButton('Дополнительно  ▾')
        self.btn_adv.setProperty('kind', 'flat')
        self.btn_adv.setCheckable(True)
        self.btn_adv.setStyleSheet(
            'text-align: left; padding: 8px 10px; font-weight: 600;'
            'background: %s; border: 1px solid %s; border-radius: 8px;'
            % (theme.PANEL, theme.BORDER))
        root.addWidget(self.btn_adv)

        self.g_adv = QGroupBox('Тонкая настройка пакета')
        va = QVBoxLayout(self.g_adv)
        va.setSpacing(8)

        note = QLabel('Файлы сохраняются в самоопределяемом контейнере: '
                      'при расшифровке шифр, режим и параметры читаются '
                      'из самого файла — угадывать ничего не нужно.')
        note.setProperty('kind', 'muted')
        note.setWordWrap(True)
        note.setStyleSheet('font-size: 8.5pt;')
        va.addWidget(note)

        va.addWidget(self._sep())
        va.addWidget(QLabel('Бренд (метка в заголовке, необязательно):'))
        self.ed_brand = QLineEdit()
        self.ed_brand.setPlaceholderText('например: мои-архивы/v3')
        va.addWidget(self.ed_brand)
        self.lbl_brand = QLabel()
        self.lbl_brand.setStyleSheet('font-size: 8.5pt;')
        va.addWidget(self.lbl_brand)

        self.ck_params = QCheckBox('Параметры KDF в файле (params)')
        self.ck_params.setChecked(True)
        self.ck_params.setToolTip(
            'Сохранять PHC-строку Argon2id ($argon2id$m=…,t=…,p=…) в файл.\n'
            'Тогда он сам расскажет, с какими параметрами создан, и\n'
            'расшифровка не потребует ничего вспоминать. Рекомендуется.')
        va.addWidget(self.ck_params)

        self.ck_random = QCheckBox('Случайная соль (random)')
        self.ck_random.setChecked(True)
        self.lbl_random_note = QLabel()
        self.lbl_random_note.setWordWrap(True)
        self.ck_random.setToolTip(
            'Соль/nonce 256 бит: один и тот же пароль даёт разный ключ на\n'
            'каждый файл — наблюдатель не видит повторов. Рекомендуется.\n'
            'Снять галочку = детерминированный режим (нулевая соль).')
        va.addWidget(self.ck_random)
        va.addWidget(self.lbl_random_note)
        self.g_adv.setVisible(False)
        root.addWidget(self.g_adv)

        root.addStretch(1)

    def _sep(self) -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet('color: %s; background: %s; max-height: 1px;'
                           % (theme.BORDER, theme.BORDER))
        return line

    # ------------------------------------------------------------- wiring
    def _wire(self):
        self.btn_adv.toggled.connect(self._on_adv_toggle)
        for w in (self.cmb_cipher, self.cmb_mode, self.cmb_key_src):
            w.currentIndexChanged.connect(self._on_changed)
        self.cmb_preset.currentIndexChanged.connect(self._on_preset)
        self.ed_password.textChanged.connect(lambda *_: self.changed.emit())
        self.ed_rawkey.textChanged.connect(self._on_changed)
        self.btn_eye.toggled.connect(self._toggle_eye)
        for sp in (self.sp_m, self.sp_t, self.sp_p):
            sp.valueChanged.connect(self._on_spin_changed)
        self.ed_brand.textChanged.connect(self._on_changed)
        self.ck_params.toggled.connect(self._on_changed)
        self.ck_random.toggled.connect(self._on_changed)

    def _on_adv_toggle(self, on: bool):
        self.g_adv.setVisible(on)
        self.btn_adv.setText('Дополнительно  ▴' if on
                             else 'Дополнительно  ▾')

    def _toggle_eye(self, on: bool):
        self.ed_password.setEchoMode(
            QLineEdit.EchoMode.Normal if on
            else QLineEdit.EchoMode.Password)
        self.btn_eye.setText('скрыть' if on else 'показать')

    def _on_changed(self, *_):
        if not self._loading:
            self._refresh_dynamic()
            self.changed.emit()

    def _on_spin_changed(self, *_):
        if self._loading:
            return
        if self.sp_m.value() < 8 * self.sp_p.value():
            self.sp_m.blockSignals(True)
            self.sp_m.setValue(8 * self.sp_p.value())
            self.sp_m.blockSignals(False)
        # ручная правка → пресет «Свои»
        idx = self.cmb_preset.count() - 1
        if self.cmb_preset.currentIndex() != idx:
            self.cmb_preset.blockSignals(True)
            self.cmb_preset.setCurrentIndex(idx)
            self.cmb_preset.blockSignals(False)
        self._refresh_dynamic()
        self.changed.emit()

    # ----------------------------------------------------------- динамика
    def _refresh_dynamic(self):
        """Подписи, валидация и видимость — по текущим значениям."""
        info = engine.CIPHERS[self.cmb_cipher.currentIndex()]
        self.lbl_cipher.setText(info.subtitle)
        siv = self.cmb_mode.currentIndex() == 0
        self.lbl_mode.setText(
            'Пакет: заголовок + тег подлинности V + шифрограмма. Любая '
            'подмена байта обнаруживается.' if siv else
            'Независимые блоки + PKCS#7, без проверки подлинности. '
            'Учебно-демонстрационный режим.')
        password = self.cmb_key_src.currentIndex() == 0
        self.stack_key.setCurrentIndex(0 if password else 1)
        self.cmb_preset.setEnabled(password)
        self.sp_m.setEnabled(password and self._is_custom_preset())
        self.sp_t.setEnabled(password and self._is_custom_preset())
        self.sp_p.setEnabled(password and self._is_custom_preset())
        self.lbl_phc.setVisible(password)
        self.lbl_phc.setText(self.kdf_params().phc_string())

        # сырой ключ — живая валидация
        raw = self.ed_rawkey.text().strip()
        if not raw:
            self.lbl_rawkey.setText('любая длина · растягивается ГОРНом до '
                                    '%d бит' % info.key_bits)
            self.lbl_rawkey.setStyleSheet('font-size: 8.5pt; color: %s;'
                                          % theme.MUTED)
        else:
            try:
                b = parse_raw_key_hex(raw)
                self.lbl_rawkey.setText('✓ %d байт · растягивается ГОРНом до '
                                        '%d бит' % (len(b), info.key_bits))
                self.lbl_rawkey.setStyleSheet('font-size: 8.5pt; color: %s;'
                                              % theme.SUCCESS)
            except KeyMaterialError as exc:
                self.lbl_rawkey.setText('✗ %s' % exc)
                self.lbl_rawkey.setStyleSheet('font-size: 8.5pt; color: %s;'
                                              % theme.DANGER)

        # бренд — счётчик байт
        if True:
            n = len(self.ed_brand.text().encode('utf-8'))
            if n == 0:
                self.lbl_brand.setText('пусто — бренд не записывается')
                self.lbl_brand.setStyleSheet('font-size: 8.5pt; color: %s;'
                                             % theme.MUTED)
            elif n <= 255:
                self.lbl_brand.setText('✓ %d из 255 байт' % n)
                self.lbl_brand.setStyleSheet('font-size: 8.5pt; color: %s;'
                                             % theme.SUCCESS)
            else:
                self.lbl_brand.setText('✗ %d байт — максимум 255, сократите'
                                       % n)
                self.lbl_brand.setStyleSheet('font-size: 8.5pt; color: %s;'
                                             % theme.DANGER)

        # random: только галочка — либо случайная соль, либо детерминизм
        self.lbl_random_note.setText(
            'галочка снята: полный детерминизм (нулевая соль) — одинаковые '
            'данные и ключ дадут одинаковый файл'
            if not self.ck_random.isChecked() else
            'соль генерируется случайно на каждый файл')
        self.lbl_random_note.setStyleSheet(
            'font-size: 8.5pt; color: %s;'
            % (theme.WARNING if not self.ck_random.isChecked()
               else theme.MUTED))

    def _update_prefix_hint(self):
        self.ed_brand.setToolTip(
            'Текст-метка в заголовке контейнера (до 255 байт). Заголовок '
            'любого файла начинается с магических байтов %s — по ним '
            'формат узнаётся автоматически.' % MAGIC.hex(' ').upper())

    def _is_custom_preset(self) -> bool:
        return self.cmb_preset.currentIndex() == self.cmb_preset.count() - 1

    # -------------------------------------------------------------- API
    def cipher_name(self) -> str:
        return engine.CIPHERS[self.cmb_cipher.currentIndex()].name

    def mode(self) -> str:
        return 'siv' if self.cmb_mode.currentIndex() == 0 else 'ecb'

    def kdf_params(self) -> KdfParams:
        return KdfParams(memory_kib=self.sp_m.value(),
                         iterations=self.sp_t.value(),
                         parallelism=self.sp_p.value())

    def key_source(self):
        if self.cmb_key_src.currentIndex() == 0:
            pw = self.ed_password.text()
            if not pw:
                raise engine.KazualError('введите пароль (или переключитесь '
                                         'на сырой ключ)')
            return PasswordKey(pw)
        raw = self.ed_rawkey.text()
        if not raw.strip():
            raise engine.KazualError('введите сырой ключ в hex (или '
                                     'переключитесь на пароль)')
        try:
            return RawKey(parse_raw_key_hex(raw))
        except KeyMaterialError as exc:
            raise engine.KazualError('сырой ключ: %s' % exc) from exc

    def siv_options(self) -> SivOptions:
        """Настройки пакета (без валидации ключа) — для схемы и движка."""
        return SivOptions(
            prefix_enabled=bool(self.ed_brand.text().strip()),
            prefix_text=self.ed_brand.text().strip() or None,
            params_enabled=self.ck_params.isChecked(),
            kdf_params=self.kdf_params(),
            random_enabled=self.ck_random.isChecked(),
            leaf_size=self._leaf_size,
        )

    def settings(self) -> engine.Settings:
        """Собрать настройки; при ошибке ввода — engine.KazualError с текстом."""
        siv = self.siv_options()
        if len((siv.prefix_text or '').encode('utf-8')) > 255:
            raise engine.KazualError('бренд длиннее 255 байт — сократите '
                                     'текст в «Дополнительно»')
        st = engine.Settings(cipher=self.cipher_name(), mode=self.mode(),
                             source=self.key_source(),
                             kdf_params=self.kdf_params(), siv=siv,
                             backend=self._backend, threads=self._threads,
                             small_file_mib=self._small_file_mib)
        st.validate()
        return st

    # runtime-параметры производительности подставляет окно из конфига
    _backend = 'auto'
    _threads = 0
    _small_file_mib = 32
    _leaf_size = 4 * 1024 * 1024

    def set_performance(self, backend: str, threads: int, leaf_mib: int,
                        small_file_mib: int):
        self._backend = backend
        self._threads = threads
        self._leaf_size = max(64, leaf_mib * 1024 * 1024)
        self._small_file_mib = small_file_mib

    # ----------------------------------------------------- config binding
    def apply_config(self, cfg: dict):
        """Выставить виджеты по конфигу (без сигналов changed)."""
        self._loading = True
        try:
            self.cmb_cipher.setCurrentIndex(
                0 if cfg.get('cipher', 'Kazual-512') == 'Kazual-512' else 1)
            self.cmb_mode.setCurrentIndex(0 if cfg.get('mode') == 'siv' else 1)
            self.cmb_key_src.setCurrentIndex(
                0 if cfg.get('key_source', 'password') == 'password' else 1)
            self.ed_rawkey.setText(cfg.get('raw_key_hex', ''))
            m, t, p = int(cfg.get('kdf_m', 65536)), int(cfg.get('kdf_t', 3)), \
                int(cfg.get('kdf_p', 4))
            preset = cfg.get('kdf_preset', 'balanced')
            if preset in ('balanced', 'fast', 'strong'):
                from ..config import KDF_PRESETS
                pm, pt, pp = KDF_PRESETS[preset]
                if (pm, pt, pp) != (m, t, p):
                    preset = 'custom'
            self.cmb_preset.setCurrentIndex(
                _PRESET_BY_ID.get(preset, 0))
            self.sp_m.setValue(m)
            self.sp_t.setValue(t)
            self.sp_p.setValue(p)
            self.ed_brand.setText(cfg.get('brand_text', ''))
            self.ck_params.setChecked(bool(cfg.get('params_enabled', True)))
            self.ck_random.setChecked(bool(cfg.get('random_enabled', True)))
            self.set_performance(cfg.get('backend', 'auto'),
                                 int(cfg.get('threads', 0)),
                                 int(cfg.get('leaf_mib', 4)),
                                 int(cfg.get('small_file_mib', 32)))
            self.btn_adv.setChecked(bool(cfg.get('advanced_open', False)))
        finally:
            self._loading = False
        self._refresh_dynamic()

    def collect_config(self) -> dict:
        """Собрать изменения виджетов в словарь (для записи в конфиг)."""
        from ..config import KDF_PRESETS
        preset_idx = self.cmb_preset.currentIndex()
        preset = _PRESET_ITEMS[preset_idx][1]
        if preset != 'custom':
            m, t, p = KDF_PRESETS[preset]
            # если спин-ы расходятся с пресетом — это «custom»
            if (m, t, p) != (self.sp_m.value(), self.sp_t.value(),
                             self.sp_p.value()):
                preset = 'custom'
        return {
            'cipher': self.cipher_name(),
            'mode': self.mode(),
            'key_source': 'password' if self.cmb_key_src.currentIndex() == 0
                          else 'hex',
            'raw_key_hex': self.ed_rawkey.text().strip(),
            'kdf_preset': preset,
            'kdf_m': self.sp_m.value(),
            'kdf_t': self.sp_t.value(),
            'kdf_p': self.sp_p.value(),
            'brand_text': self.ed_brand.text().strip(),
            'params_enabled': self.ck_params.isChecked(),
            'random_enabled': self.ck_random.isChecked(),
            'advanced_open': self.btn_adv.isChecked(),
        }

    # --------------------------------------------------------------- lock
    def lock_from_detection(self, title: str, body: str = ''):
        """Заблокировать панель: параметры читаются из файла."""
        self._locked = True
        for w in (self.cmb_cipher, self.cmb_mode, self.cmb_preset,
                  self.sp_m, self.sp_t, self.sp_p,
                  self.ed_brand, self.ck_params, self.ck_random,
                  self.btn_adv):
            w.setEnabled(False)
        self.lock_banner.setText(
            '<b>Параметры считаны из файла.</b> Панель заблокирована: шифр, '
            'режим и KDF взяты из расшифровываемого файла (подробности — в '
            'карточке на странице).')
        self.lock_banner.show()

    def unlock(self):
        self._locked = False
        for w in (self.cmb_cipher, self.cmb_mode, self.cmb_preset,
                  self.sp_m, self.sp_t, self.sp_p,
                  self.ed_brand, self.ck_params, self.ck_random,
                  self.btn_adv):
            w.setEnabled(True)
        self._refresh_dynamic()
        self.lock_banner.hide()

    def is_locked(self) -> bool:
        return self._locked

    def _on_preset(self, idx: int):
        """Выбран пресет — проставить m/t/p и обновить вид."""
        if self._loading:
            return
        self._apply_preset_selection(idx)
        self._refresh_dynamic()
        self.changed.emit()

    def _apply_preset_selection(self, idx: int):
        from ..config import KDF_PRESETS
        pid = _PRESET_ITEMS[idx][1]
        if pid in KDF_PRESETS:
            m, t, p = KDF_PRESETS[pid]
            self._loading = True
            try:
                self.sp_m.setValue(m)
                self.sp_t.setValue(t)
                self.sp_p.setValue(p)
            finally:
                self._loading = False
