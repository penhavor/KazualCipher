# -*- coding: utf-8 -*-
"""
KazualCipher — GUI-обёртка и режимы работы для семейства блочных шифров
Kazual (Kazual-512 и Kazual-64).

Подпакеты:
    kazual.cipher  эталонная реализация шифров (чистый Python + NumPy-пакеты)
    kazual.modes   режимы работы: SIV-пакет (аутентифицированное шифрование)
                   и ECB (простой режим), CTR, PKCS#7-дополнение
    kazual.kdf     Argon2id (PHC-параметры) и вывод ключей
    kazual.engine  высокоуровневый фасад, который использует GUI
    kazual.app     графический интерфейс (PySide6)

ДИСКЛЕЙМЕР: экспериментальная учебная конструкция, не проходила
независимого криптоанализа и не предназначена для защиты реальных данных.
"""

__version__ = '1.0.0'
__author__ = 'KazualCipher contributors'
__license__ = 'MIT'


def missing_deps_hint(exc: Exception) -> str:
    """Единая человекочитаемая подсказка при нехватке зависимостей.

    Используется main.py (запуск двойным кликом: окно не закрывается,
    показывается инструкция) и kazual.app.run().
    """
    return (
        '\n'
        '  KazualCipher: не хватает зависимостей (%s).\n'
        '\n'
        '  Что сделать (один раз):\n'
        '\n'
        '    Windows:   запустите start.bat двойным кликом — он сам\n'
        '               создаст .venv и поставит всё необходимое.\n'
        '    Linux/mac: ./start.sh сделает то же самое.\n'
        '\n'
        '    Вручную:\n'
        '      python -m venv .venv\n'
        '      # Windows:      .venv\\Scripts\\activate\n'
        '      # Linux / macOS: source .venv/bin/activate\n'
        '      pip install -r requirements.txt\n'
        '      python main.py\n'
        '\n'
        '  Папки .venv нет в архиве сознательно: виртуальное окружение\n'
        '  привязано к конкретному компьютеру и ОС, поэтому создаётся\n'
        '  у вас один раз (или автоматически через start.bat / start.sh).\n'
        % exc
    )
