# -*- coding: utf-8 -*-
"""kazual.app — графический интерфейс KazualCipher (PySide6)."""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QObject, QEvent
from PySide6.QtWidgets import QAbstractSpinBox, QComboBox


class _WheelGuard(QObject):
    """Колёсико мыши — только для навигации: не меняет значения
    спинбоксов и комбобоксов (случайные прокруты портили настройки)."""

    def eventFilter(self, obj, ev):                         # noqa: N802
        if ev.type() == QEvent.Type.Wheel and isinstance(
                obj, (QAbstractSpinBox, QComboBox)):
            ev.ignore()
            return True
        return super().eventFilter(obj, ev)


def run(argv=None) -> int:
    """Создать QApplication, показать главное окно, войти в цикл событий."""
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtGui import QIcon
    except ImportError as exc:
        from .. import missing_deps_hint
        sys.stderr.write(missing_deps_hint(exc))
        return 1

    if sys.platform == 'win32':
        # свой AppUserModelID → в панели задач Windows будет иконка
        # программы, а не значок python.exe
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                'KazualCipher.App.1')
        except Exception:                                   # noqa: BLE001
            pass

    from .theme import apply_theme
    from .main_window import MainWindow

    app = QApplication.instance() or QApplication(argv or sys.argv)
    app.setApplicationName('KazualCipher')
    app.setOrganizationName('KazualCipher')
    app.setApplicationDisplayName('KazualCipher')
    assets = Path(__file__).resolve().parents[2] / 'assets'
    for name in ('icon.png', 'icon.svg'):
        p = assets / name
        if p.is_file():
            app.setWindowIcon(QIcon(str(p)))
            break
    apply_theme(app)
    app.installEventFilter(_WheelGuard())

    win = MainWindow()
    win.show()
    return app.exec()


__all__ = ['run']
