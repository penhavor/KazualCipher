#!/bin/sh
# ============================================================================
#  KazualCipher — запуск (Linux / macOS).
#  Первый запуск: создаёт .venv и ставит зависимости (нужен интернет).
#  Использование:  ./start.sh      (или: sh start.sh)
# ============================================================================
set -e
cd "$(dirname "$0")"

if [ ! -x ".venv/bin/python" ]; then
    echo "Первый запуск: создаю виртуальное окружение .venv ..."
    python3 -m venv .venv
    echo "Устанавливаю зависимости (PySide6, numpy, argon2-cffi)..."
    ".venv/bin/python" -m pip install --upgrade pip
    ".venv/bin/python" -m pip install -r requirements.txt
fi

exec ".venv/bin/python" main.py "$@"
