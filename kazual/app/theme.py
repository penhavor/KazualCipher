# -*- coding: utf-8 -*-
"""Тема оформления KazualCipher: тёмная палитра + QSS."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase
from PySide6.QtWidgets import QApplication

# ---------------------------------------------------------------------------
# Палитра
# ---------------------------------------------------------------------------
BG = '#10131a'          # фон окна
PANEL = '#171b24'       # панели/сайдабар
CARD = '#1d222d'        # карточки, поля ввода
CARD_ALT = '#232936'    # hover
BORDER = '#2a3040'      # границы
TEXT = '#e8ebf2'        # основной текст
MUTED = '#8b93a7'       # приглушённый
ACCENT = '#6d5df6'      # индиго — основное действие
ACCENT_HOVER = '#7f70ff'
ACCENT_SOFT = '#2b2c4d' # фон выделения
TEAL = '#2dd4bf'        # успех / акцент-2
SUCCESS = '#34d399'
WARNING = '#f5a623'
DANGER = '#f0526a'

MONO_FAMILIES = ['JetBrains Mono', 'Cascadia Code', 'Fira Code', 'Consolas',
                 'Menlo', 'DejaVu Sans Mono', 'Courier New']


def mono_font(point_size: int = 10) -> QFont:
    """Моноширинный шрифт для hex/дампов (первый доступный в системе)."""
    families = set(QFontDatabase.families())
    for fam in MONO_FAMILIES:
        if fam in families:
            return QFont(fam, point_size)
    f = QFont('monospace', point_size)
    f.setStyleHint(QFont.StyleHint.Monospace)
    return f


def apply_theme(app: QApplication) -> None:
    """Fusion + тёмная палитра + QSS. Вызывается один раз при старте."""
    app.setStyle('Fusion')

    from PySide6.QtGui import QPalette
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(BG))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Base, QColor(CARD))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor(CARD_ALT))
    pal.setColor(QPalette.ColorRole.Text, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Button, QColor(PANEL))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.BrightText, QColor(TEAL))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(ACCENT))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor('#ffffff'))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(CARD_ALT))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(MUTED))
    app.setPalette(pal)

    f = app.font()
    f.setPointSize(10)
    app.setFont(f)

    app.setStyleSheet(_QSS)


from pathlib import Path as _Path
_ASSETS = str(_Path(__file__).resolve().parents[2] / 'assets').replace('\\', '/')

_QSS = '''
* { outline: none; }

QMainWindow, QDialog { background: %(bg)s; }

QWidget { color: %(text)s; font-size: 10pt; }

QToolTip {
    background: %(card_alt)s; color: %(text)s;
    border: 1px solid %(border)s; border-radius: 6px; padding: 6px 8px;
}

/* ---------- заголовки групп ---------- */
QGroupBox {
    background: %(panel)s;
    border: 1px solid %(border)s;
    border-radius: 10px;
    margin-top: 14px;
    padding: 10px 8px 8px 8px;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px; top: 2px;
    padding: 0 6px;
    color: %(muted)s;
    font-size: 9pt;
    letter-spacing: 1px;
    text-transform: uppercase;
}

/* ---------- поля ввода ---------- */
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background: %(card)s;
    border: 1px solid %(border)s;
    border-radius: 8px;
    padding: 6px 10px;
    selection-background-color: %(accent)s;
    selection-color: white;
}
QPlainTextEdit, QTextEdit { padding: 8px 10px; }
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus,
QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
    border: 1px solid %(accent)s;
}
QLineEdit:disabled, QPlainTextEdit:disabled, QSpinBox:disabled,
QComboBox:disabled { color: %(muted)s; background: %(panel)s; }
QComboBox QAbstractItemView {
    background: %(card_alt)s;
    border: 1px solid %(border)s;
    border-radius: 8px;
    selection-background-color: %(accent_soft)s;
    selection-color: %(text)s;
    padding: 4px;
}
QSpinBox::up-button, QSpinBox::down-button {
    subcontrol-origin: border; width: 20px;
    background: transparent; border: none;
}
QSpinBox::up-button { subcontrol-position: top right; height: 50%%; }
QSpinBox::down-button { subcontrol-position: bottom right; height: 50%%; }
QSpinBox::up-button:hover { background: %(card_alt)s; }
QSpinBox::down-button:hover { background: %(card_alt)s; }
QSpinBox::up-arrow { image: url("%(assets)s/spin_up.png"); width: 10px; height: 7px; }
QSpinBox::down-arrow { image: url("%(assets)s/spin_down.png"); width: 10px; height: 7px; }
QSpinBox::up-arrow:hover { image: url("%(assets)s/spin_up_hover.png"); }
QSpinBox::down-arrow:hover { image: url("%(assets)s/spin_down_hover.png"); }
QSpinBox::up-arrow:disabled, QSpinBox::down-arrow:disabled { image: none; }

/* ---------- кнопки ---------- */
QPushButton {
    background: %(card_alt)s;
    border: 1px solid %(border)s;
    border-radius: 8px;
    padding: 7px 16px;
    font-weight: 600;
}
QPushButton:hover { background: #2b3242; border-color: #3a4256; }
QPushButton:pressed { background: %(card)s; }
QPushButton:disabled { color: %(muted)s; background: %(panel)s; border-color: %(border)s; }

QPushButton[kind="primary"] {
    background: %(accent)s; border: none; color: white;
    padding: 10px 22px; border-radius: 10px; font-size: 11pt;
}
QPushButton[kind="primary"]:hover { background: %(accent_hover)s; }
QPushButton[kind="primary"]:pressed { background: #5a4ce0; }
QPushButton[kind="primary"]:disabled { background: #3a3c5c; color: #9a9ec4; }

QPushButton[kind="danger"] { color: %(danger)s; border-color: #4a2c38; }
QPushButton[kind="danger"]:hover { background: #33212b; }

QPushButton[kind="flat"] { background: transparent; border: none; color: %(muted)s; padding: 4px 8px; }
QPushButton[kind="flat"]:hover { color: %(text)s; background: %(card)s; }

/* ---------- чекбоксы и радио ---------- */
QCheckBox, QRadioButton { spacing: 8px; padding: 2px 0; }
QCheckBox::indicator, QRadioButton::indicator {
    width: 18px; height: 18px; border-radius: 5px;
    border: 1.5px solid %(border)s; background: %(card)s;
}
QRadioButton::indicator { border-radius: 9px; }
QCheckBox::indicator:hover, QRadioButton::indicator:hover { border-color: %(accent)s; }
QCheckBox::indicator:checked {
    background: %(accent)s; border-color: %(accent)s;
    image: url(:/qt-project.org/styles/commonstyle/images/standardbutton-apply-16.png);
}
QRadioButton::indicator:checked {
    background: %(card)s; border: 4px solid %(accent)s;
}
QCheckBox:disabled, QRadioButton:disabled { color: %(muted)s; }

/* ---------- списки выбора (шифр/режим) ---------- */
QListWidget {
    background: %(panel)s; border: 1px solid %(border)s;
    border-radius: 10px; padding: 4px; outline: none;
}
QListWidget::item {
    border-radius: 8px; margin: 2px 0; padding: 6px 8px;
    border: 1px solid transparent;
}
QListWidget::item:hover { background: %(card)s; }
QListWidget::item:selected {
    background: %(accent_soft)s; border: 1px solid %(accent)s;
}

/* ---------- вкладки ---------- */
QTabWidget::pane { border: none; background: transparent; top: -1px; }
QTabBar::tab {
    background: transparent; color: %(muted)s;
    padding: 9px 20px; margin-right: 4px;
    border: none; border-bottom: 2px solid transparent;
    font-weight: 600; font-size: 10.5pt;
}
QTabBar::tab:hover { color: %(text)s; }
QTabBar::tab:selected { color: %(text)s; border-bottom: 2px solid %(accent)s; }

/* ---------- прогресс ---------- */
QProgressBar {
    background: %(card)s; border: 1px solid %(border)s;
    border-radius: 6px; height: 12px; text-align: center;
    color: transparent;
}
QProgressBar::chunk { background: %(accent)s; border-radius: 5px; }

/* ---------- скроллбары ---------- */
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #323a4d; border-radius: 4px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: #414b63; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: #323a4d; border-radius: 4px; min-width: 28px; }
QScrollBar::handle:horizontal:hover { background: #414b63; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

/* ---------- статус и меню ---------- */
QStatusBar { background: %(panel)s; border-top: 1px solid %(border)s; color: %(muted)s; }
QStatusBar::item { border: none; }
QMenuBar { background: %(panel)s; border-bottom: 1px solid %(border)s; padding: 2px 6px; }
QMenuBar::item { padding: 5px 10px; border-radius: 6px; background: transparent; }
QMenuBar::item:selected { background: %(card_alt)s; }
QMenu { background: %(card_alt)s; border: 1px solid %(border)s; border-radius: 8px; padding: 6px; }
QMenu::item { padding: 6px 22px; border-radius: 6px; }
QMenu::item:selected { background: %(accent_soft)s; }
QMenu::separator { height: 1px; background: %(border)s; margin: 4px 8px; }

/* ---------- прочее ---------- */
QScrollArea { border: none; background: transparent; }
QSplitter::handle { background: %(border)s; }
QLabel[kind="muted"] { color: %(muted)s; }
QLabel[kind="title"] { font-size: 15pt; font-weight: 700; }
QLabel[kind="subtitle"] { color: %(muted)s; font-size: 9.5pt; }
QLabel[kind="chip"] {
    color: %(warning)s; border: 1px solid %(warning)s; border-radius: 10px;
    padding: 2px 10px; font-size: 8.5pt; font-weight: 600;
}
QLabel[kind="chipVersion"] {
    color: %(muted)s; border: 1px solid %(border)s; border-radius: 10px;
    padding: 2px 10px; font-size: 8.5pt;
}
QFrame[kind="bannerOk"] { background: #14321f; border: 1px solid #1f6b40; border-radius: 10px; }
QFrame[kind="bannerWarn"] { background: #33270f; border: 1px solid #7a5a17; border-radius: 10px; }
QFrame[kind="bannerErr"] { background: #36141d; border: 1px solid #7a2438; border-radius: 10px; }
QFrame[kind="bannerInfo"] { background: %(card)s; border: 1px solid %(border)s; border-radius: 10px; }
''' % {
    'assets': _ASSETS,
    'bg': BG, 'panel': PANEL, 'card': CARD, 'card_alt': CARD_ALT,
    'border': BORDER, 'text': TEXT, 'muted': MUTED, 'accent': ACCENT,
    'accent_hover': ACCENT_HOVER, 'accent_soft': ACCENT_SOFT, 'teal': TEAL,
    'success': SUCCESS, 'warning': WARNING, 'danger': DANGER,
}
