#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KazualCipher — точка входа. Ничего больше запускать не нужно.

    python main.py        (или двойной клик по файлу)

Что делает этот файл:
  1. Если все зависимости установлены — сразу открывает программу
     (на Windows — без висящей консоли).
  2. Если зависимостей нет — сам открывает консоль установки, сам создаёт
     окружение .venv, сам ставит всё необходимое (нужен интернет), затем
     сам запускает программу и закрывает консоль. От пользователя требуется
     только подождать.
  3. Если окружение .venv уже создано, но запуск был системным Python —
     прозрачно перезапускается внутри .venv.

Консольные команды (самопроверки, векторы, шифрование из терминала):
    python -m kazual --help
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(HERE, '.venv')

IS_WIN = sys.platform == 'win32'
IS_MAC = sys.platform == 'darwin'

CORE_PACKAGES = ['PySide6>=6.5', 'numpy>=1.24', 'argon2-cffi>=23.1']
FAST_PACKAGES = ['numba>=0.59']          # ускорение ~40×; без неё тоже работает

_INTERNAL_FLAGS = ('--bootstrap', '--relaunched', '--no-relaunch')


# ---------------------------------------------------------------------------
# Проверка зависимостей
# ---------------------------------------------------------------------------

def _deps_missing():
    """Список отсутствующих обязательных зависимостей ([] = всё на месте)."""
    missing = []
    for mod in ('PySide6', 'numpy', 'argon2'):
        try:
            __import__(mod)
        except ImportError:
            missing.append({'PySide6': 'PySide6', 'numpy': 'numpy',
                            'argon2': 'argon2-cffi'}[mod])
    return missing


def _venv_pythons():
    if IS_WIN:
        py = os.path.join(VENV_DIR, 'Scripts', 'python.exe')
        pyw = os.path.join(VENV_DIR, 'Scripts', 'pythonw.exe')
    else:
        py = os.path.join(VENV_DIR, 'bin', 'python')
        pyw = None
    return py, (pyw if pyw and os.path.isfile(pyw) else py)


# ---------------------------------------------------------------------------
# Перезапуски (консоль/venv) — прозрачно для пользователя
# ---------------------------------------------------------------------------

def _has_visible_console() -> bool:
    """Запущены ли мы в видимой консоли (двойной клик по .py на Windows)."""
    if not IS_WIN:
        return False
    if sys.stdout is None:                    # pythonw — консоли нет
        return False
    try:
        import ctypes
        return ctypes.windll.kernel32.GetConsoleWindow() != 0
    except Exception:                          # noqa: BLE001
        return sys.stdout.isatty()


def _relaunch_hidden() -> bool:
    """Windows: перезапустить себя без консоли (pythonw). True = удалось."""
    pyw = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
    if not os.path.isfile(pyw):
        return False
    env = dict(os.environ, KAZUAL_RELAUNCHED='1')
    try:
        subprocess.Popen(
            [pyw, os.path.join(HERE, 'main.py')],
            cwd=HERE, env=env, close_fds=True,
            creationflags=getattr(subprocess, 'DETACHED_PROCESS', 0)
            | getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0))
        return True
    except OSError:
        return False


def _run_in_venv() -> int:
    """Передать управление Python'у из .venv (он уже со всеми зависимостями)."""
    py, pyw = _venv_pythons()
    if IS_WIN:
        env = dict(os.environ, KAZUAL_RELAUNCHED='1')
        subprocess.Popen([pyw, os.path.join(HERE, 'main.py')], cwd=HERE,
                         env=env, close_fds=True,
                         creationflags=getattr(subprocess, 'DETACHED_PROCESS',
                                               0))
        return 0
    os.execv(py, [py, os.path.join(HERE, 'main.py')] +
             [a for a in sys.argv[1:] if a not in _INTERNAL_FLAGS])
    return 0


def _console_python() -> str:
    """Интерпретатор с консольным выводом (pythonw → python)."""
    exe = sys.executable
    if exe.lower().endswith('pythonw.exe'):
        alt = exe[:-len('pythonw.exe')] + 'python.exe'
        if os.path.isfile(alt):
            return alt
    return exe


def _open_bootstrap_console() -> bool:
    """Отдельное окно консоли для установки зависимостей (без нас)."""
    args = [_console_python(), os.path.join(HERE, 'main.py'), '--bootstrap']
    try:
        if IS_WIN:
            subprocess.Popen(
                args, cwd=HERE,
                creationflags=subprocess.CREATE_NEW_CONSOLE)
            return True
        if IS_MAC:
            subprocess.Popen(
                ['osascript', '-e',
                 'tell application "Terminal" to activate',
                 '-e', 'tell application "Terminal" to do script "%s"'
                 % ' '.join('"%s"' % a for a in args)])
            return True
        for term in ('x-terminal-emulator', 'xterm', 'gnome-terminal',
                     'konsole', 'xfce4-terminal', 'mate-terminal',
                     'tilix', 'alacritty', 'kitty'):
            exe = _which(term)
            if exe:
                if term in ('gnome-terminal', 'konsole', 'xfce4-terminal',
                            'mate-terminal', 'tilix'):
                    subprocess.Popen([exe, '--'] + args, cwd=HERE)
                elif term == 'kitty':
                    subprocess.Popen([exe] + args, cwd=HERE)
                else:
                    subprocess.Popen([exe, '-e', ' '.join(args)], cwd=HERE)
                return True
    except OSError:
        pass
    return False


def _which(name: str):
    for d in os.environ.get('PATH', '').split(os.pathsep):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


# ---------------------------------------------------------------------------
# Bootstrap: создание .venv и установка зависимостей (в консоли)
# ---------------------------------------------------------------------------

def _say(msg: str = ''):
    print(msg, flush=True)


def _run(cmd, **kw):
    _say('  $ ' + ' '.join(cmd))
    return subprocess.call(cmd, cwd=HERE, **kw)


def bootstrap() -> int:
    """Создать .venv (если нет), поставить зависимости, запустить GUI."""
    _say('')
    _say('=' * 64)
    _say('  KazualCipher — первоначальная настройка')
    _say('=' * 64)
    _say('')
    if sys.version_info < (3, 9):
        _say('  ОШИБКА: нужен Python 3.9 или новее (сейчас %s).'
             % sys.version.split()[0])
        _say('  Скачайте свежий Python: https://www.python.org/downloads/')
        _pause(1)
        return 1

    py, _pyw = _venv_pythons()
    have_venv = os.path.isfile(py)

    if not have_venv:
        _say('[1/3] Создаю виртуальное окружение .venv …')
        rc = _run([sys.executable, '-m', 'venv', VENV_DIR])
        if rc != 0 and IS_WIN:
            launcher = _which('py')
            if launcher:
                rc = _run([launcher, '-3', '-m', 'venv', VENV_DIR])
        if rc != 0 or not os.path.isfile(py):
            _say('')
            _say('  ОШИБКА: не удалось создать .venv. Проверьте, что Python')
            _say('  установлен с компонентом venv (обычно он входит в состав).')
            _pause(1)
            return 1
    else:
        _say('[1/3] Виртуальное окружение .venv уже есть — использую его.')

    _say('')
    _say('[2/3] Устанавливаю зависимости (нужен интернет, может занять')
    _say('      несколько минут)…')
    _run([py, '-m', 'pip', 'install', '--upgrade', 'pip'])
    rc_core = _run([py, '-m', 'pip', 'install'] + CORE_PACKAGES)
    rc_fast = _run([py, '-m', 'pip', 'install'] + FAST_PACKAGES)
    if rc_core != 0:
        req = os.path.join(HERE, 'requirements.txt')
        if os.path.isfile(req):
            _say('  Повторная попытка по requirements.txt …')
            rc_core = _run([py, '-m', 'pip', 'install', '-r', req])
    if rc_core != 0:
        _say('')
        _say('  ОШИБКА: установка основных зависимостей не удалась.')
        _say('  Проверьте интернет-соединение и запустите main.py ещё раз.')
        _pause(1)
        return 1
    if rc_fast != 0:
        _say('')
        _say('  ВНИМАНИЕ: numba (ускоритель ~40×) не установился — программа')
        _say('  будет работать, но медленнее. Можно повторить позже из')
        _say('  окна программы: Настройки → «Установить/обновить numba».')

    # проверка, что окружение действительно рабочее
    check = subprocess.call(
        [py, '-c', 'import PySide6, numpy, argon2'], cwd=HERE)
    if check != 0:
        _say('')
        _say('  ОШИБКА: зависимости установились, но не импортируются.')
        _pause(1)
        return 1

    _say('')
    _say('[3/3] Готово! Запускаю KazualCipher…')
    _say('      (это окно сейчас закроется; повторная установка при')
    _say('       следующих запусках не потребуется)')
    if IS_WIN:
        _, pyw = _venv_pythons()
        env = dict(os.environ, KAZUAL_RELAUNCHED='1')
        subprocess.Popen([pyw, os.path.join(HERE, 'main.py')], cwd=HERE,
                         env=env, close_fds=True,
                         creationflags=getattr(subprocess, 'DETACHED_PROCESS',
                                               0))
        return 0
    os.execv(py, [py, os.path.join(HERE, 'main.py')])
    return 0


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

def run_gui() -> int:
    sys.path.insert(0, HERE)
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


def _pause(code: int) -> int:
    try:
        if sys.stdin is not None and sys.stdin.isatty():
            input('\nНажмите Enter, чтобы закрыть окно…')
    except (EOFError, KeyboardInterrupt, OSError):
        pass
    return code


def _console_attached() -> bool:
    """Видна ли нам консоль (можно печатать прогресс установки сюда)."""
    if sys.stdout is None:
        return False
    try:
        return bool(sys.stdout.isatty())
    except (ValueError, OSError):
        return False


def main() -> int:
    args = [a for a in sys.argv[1:] if a not in _INTERNAL_FLAGS]

    # явный bootstrap-режим (консоль установки)
    if '--bootstrap' in sys.argv:
        return bootstrap()

    if sys.version_info < (3, 9):
        sys.stderr.write(
            'KazualCipher требует Python 3.9 или новее (обнаружен %s).\n'
            'Скачайте свежий Python: https://www.python.org/downloads/\n'
            % sys.version.split()[0])
        return _pause(1)

    sys.path.insert(0, HERE)
    in_venv = os.path.realpath(sys.prefix) != getattr(
        sys, 'base_prefix', sys.prefix)
    relaunched = ('--relaunched' in sys.argv
                  or 'KAZUAL_RELAUNCHED' in os.environ)
    venv_py, _venv_pyw = _venv_pythons()
    have_venv = os.path.isfile(venv_py)
    missing = _deps_missing()

    if not missing:
        # Всё на месте — запуск без лишних окон.
        if (IS_WIN and not relaunched and not args
                and _has_visible_console()):
            if have_venv and subprocess.call(
                    [venv_py, '-c', 'import PySide6, numpy, argon2'],
                    cwd=HERE) == 0:
                return _run_in_venv()          # здоровое .venv — в него
            if _relaunch_hidden():
                return 0                        # тот же Python, но без консоли
        return run_gui()

    # Зависимостей нет.
    if have_venv and not in_venv:
        # .venv существует — передаём управление ему; если и там пусто,
        # он сам уйдёт в bootstrap.
        return _run_in_venv()

    if in_venv and _console_attached():
        return bootstrap()      # ставим в текущее окружение, прогресс виден

    if _console_attached():
        return bootstrap()

    # Консоли нет (двойной клик через pythonw, файловый менеджер):
    # открываем отдельное окно установки.
    if _open_bootstrap_console():
        return 0
    return bootstrap()          # крайний случай — вслепую, но пытаемся


if __name__ == '__main__':
    sys.exit(main())
