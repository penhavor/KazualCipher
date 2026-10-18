#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KazualCipher — точка входа.

    python main.py            запуск графического интерфейса

Запуск двойным кликом (Windows): используйте start.bat — он сам создаст
.venv и поставит зависимости. Этот файл тоже можно кликать: при ошибке
окно не закроется мгновенно, а покажет причину и инструкцию.

Консольные команды (самопроверки, векторы, шифрование из терминала):
    python -m kazual --help

Требуется Python 3.9+ и зависимости:  pip install -r requirements.txt
"""

import sys

_PAUSE_HINT = '\nНажмите Enter, чтобы закрыть окно…'


def _pause(code: int) -> int:
    """Не дать консоли закрыться мгновенно при запуске двойным кликом.

    Пауза нужна только когда окно «приехало» с двойного клика (stdin —
    терминал). В скриптах/CI (stdin не tty) не мешаем.
    """
    try:
        if sys.stdin is not None and sys.stdin.isatty():
            input(_PAUSE_HINT)
    except (EOFError, KeyboardInterrupt):
        pass
    return code


def main() -> int:
    if sys.version_info < (3, 9):
        sys.stderr.write(
            'KazualCipher требует Python 3.9 или новее (обнаружен %s).\n'
            'Скачайте свежий Python: https://www.python.org/downloads/\n'
            % sys.version.split()[0])
        return _pause(1)

    # запускаемся из любого каталога: пакет лежит рядом с main.py
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    try:
        import PySide6                                  # noqa: F401
    except ImportError as exc:
        from kazual import missing_deps_hint
        sys.stderr.write(missing_deps_hint(exc))
        return _pause(1)

    try:
        from kazual.app import run
    except ImportError as exc:
        from kazual import missing_deps_hint
        sys.stderr.write(missing_deps_hint(exc))
        return _pause(1)

    try:
        return run()
    except Exception:                                # noqa: BLE001
        import traceback
        sys.stderr.write('\nKazualCipher аварийно завершился:\n')
        traceback.print_exc()
        return _pause(1)


if __name__ == '__main__':
    sys.exit(main())
