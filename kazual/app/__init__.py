# -*- coding: utf-8 -*-
"""kazual.app — графический интерфейс KazualCipher (PySide6)."""

from __future__ import annotations

import sys


def run(argv=None) -> int:
    """Создать QApplication, показать главное окно, войти в цикл событий."""
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as exc:
        from .. import missing_deps_hint
        sys.stderr.write(missing_deps_hint(exc))
        return 1

    from .theme import apply_theme
    from .main_window import MainWindow

    app = QApplication.instance() or QApplication(argv or sys.argv)
    app.setApplicationName('KazualCipher')
    app.setOrganizationName('KazualCipher')
    apply_theme(app)

    win = MainWindow()
    win.show()
    return app.exec()


__all__ = ['run']
