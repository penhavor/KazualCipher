# -*- coding: utf-8 -*-
"""
Консольный интерфейс KazualCipher.

    python -m kazual gui                     графический интерфейс (по умолчанию)
    python -m kazual selftest                полные самопроверки шифров (~15 с)
    python -m kazual vectors                 тестовые векторы
    python -m kazual trace                   подробная трассировка Kazual-64
    python -m kazual bench                   замер скорости

    python -m kazual enc  --cipher Kazual-512 --password "секрет" \\
                          --input файл --output файл.kaz
    python -m kazual dec  --cipher Kazual-512 --password "секрет" \\
                          --input файл.kaz --output файл
    python -m kazual enc  --text "привет" --key-hex deadbeef --mode ecb

Пакет SIV настраивается теми же «галочками», что и в GUI:
    --no-prefix | --prefix-text ТЕКСТ | --no-params | --no-random |
    --fixed-random HEX(64 цифры) | --kdf m,t,p   (например --kdf 65536,3,4)
"""

from __future__ import annotations

import argparse
import base64
import sys

from . import __version__


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='kazual',
        description='KazualCipher — шифры Kazual-512/Kazual-64, режимы SIV/ECB')
    p.add_argument('--version', action='version',
                   version='KazualCipher %s' % __version__)
    sub = p.add_subparsers(dest='cmd')

    sub.add_parser('gui', help='запустить графический интерфейс')
    sub.add_parser('selftest', help='полные самопроверки (~15 с)')
    sub.add_parser('vectors', help='тестовые векторы')
    sub.add_parser('trace', help='трассировка Kazual-64')
    sub.add_parser('bench', help='замер скорости')

    for name in ('enc', 'dec'):
        sp = sub.add_parser(name, help='зашифровать' if name == 'enc'
                            else 'расшифровать')
        sp.add_argument('--cipher', choices=['Kazual-512', 'Kazual-64'],
                        default='Kazual-512')
        sp.add_argument('--mode', choices=['siv', 'ecb'], default='siv')
        key = sp.add_mutually_exclusive_group(required=True)
        key.add_argument('--password', help='пароль (Argon2id)')
        key.add_argument('--key-hex', help='сырой ключ в hex')
        sp.add_argument('--text', help='данные текстом (вместо --input)')
        sp.add_argument('--input', help='файл с данными')
        sp.add_argument('--output', help='файл результата (иначе stdout)')
        sp.add_argument('--format', choices=['auto', 'b64', 'hex'],
                        default='auto',
                        help='enc: формат вывода (auto=b64); dec: формат '
                             'входа (auto: строгий hex → hex, иначе b64)')
        # тонкая настройка SIV-пакета
        sp.add_argument('--no-prefix', action='store_true')
        sp.add_argument('--prefix-text', default=None)
        sp.add_argument('--no-params', action='store_true')
        sp.add_argument('--no-random', action='store_true')
        sp.add_argument('--fixed-random', default='')
        sp.add_argument('--kdf', default=None, metavar='M,T,P',
                        help='параметры Argon2id, например 65536,3,4')
    return p


def _make_settings(a):
    from .engine import Settings, KazualError
    from .kdf import KdfParams, DEFAULT_KDF_PARAMS
    from .keys import PasswordKey, RawKey, parse_raw_key_hex
    from .modes.siv import SivOptions

    if a.kdf:
        try:
            m, t, p = (int(x) for x in a.kdf.split(','))
            kdf = KdfParams(m, t, p)
            kdf.validate()
        except (ValueError, Exception) as exc:
            raise KazualError('--kdf: ожидалось M,T,P (%s)' % exc)
    else:
        kdf = DEFAULT_KDF_PARAMS
    source = PasswordKey(a.password) if a.password else \
        RawKey(parse_raw_key_hex(a.key_hex))
    siv = SivOptions(prefix_enabled=not a.no_prefix,
                     prefix_text=a.prefix_text,
                     params_enabled=not a.no_params,
                     kdf_params=kdf,
                     random_enabled=not a.no_random,
                     fixed_random_hex=a.fixed_random)
    return Settings(cipher=a.cipher, mode=a.mode, source=source,
                    kdf_params=kdf, siv=siv)


def _decode_text(s: str, fmt: str) -> bytes:
    """Строка пакета → байты (hex при строгом соответствии, иначе Base64)."""
    import re
    compact = re.sub(r'\s+', '', s)
    if fmt == 'hex' or (fmt == 'auto'
                        and re.fullmatch(r'[0-9a-fA-F]+', compact)
                        and len(compact) % 2 == 0):
        return bytes.fromhex(compact)
    return base64.b64decode(compact, validate=True)


def _cmd_crypt(a) -> int:
    from .engine import encrypt, decrypt

    st = _make_settings(a)
    if a.text is not None:
        if a.cmd == 'dec':
            try:
                data = _decode_text(a.text, a.format)
            except Exception as exc:
                sys.stderr.write('не удалось распознать формат пакета: %s\n'
                                 'подсказка: --format b64|hex\n' % exc)
                return 2
        else:
            data = a.text.encode('utf-8')
    elif a.input:
        with open(a.input, 'rb') as f:
            raw = f.read()
        if a.cmd == 'dec':
            # текстовый пакет в файле? пробуем раскодировать, иначе сырые байты
            try:
                data = _decode_text(raw.decode('ascii'), a.format)
            except Exception:
                data = raw
        else:
            data = raw
    else:
        sys.stderr.write('нужно --text или --input\n')
        return 2

    last_stage = ['']

    def progress(stage, frac=None):
        line = '\r[%s] %s%s' % (
            ' ' * 10 if frac is None else ('=' * int(frac * 10)).ljust(10),
            stage, '' if frac is None else ' %.0f%%' % (frac * 100))
        if line != last_stage[0]:
            sys.stderr.write(line)
            last_stage[0] = line

    fn = encrypt if a.cmd == 'enc' else decrypt
    res = fn(st, data, progress=progress)
    sys.stderr.write('\r' + ' ' * 70 + '\r')

    if a.output:
        with open(a.output, 'wb') as f:
            f.write(res.data)
        sys.stderr.write('сохранено: %s (%d байт)\n'
                         % (a.output, len(res.data)))
    else:
        if a.cmd == 'dec':
            try:
                sys.stdout.write(res.data.decode('utf-8') + '\n')
            except UnicodeDecodeError:
                sys.stdout.write(base64.b64encode(res.data).decode() + '\n')
        else:
            out = res.data.hex().upper() if a.format == 'hex' \
                else base64.b64encode(res.data).decode()
            sys.stdout.write(out + '\n')
    for w in res.warnings:
        sys.stderr.write('предупреждение: %s\n' % w)
    if res.mode == 'siv' and a.cmd == 'dec':
        sys.stderr.write('подлинность: ПОДТВЕРЖДЕНА (V сошёлся)\n')
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    if not argv:
        argv = ['gui']
    a = parser.parse_args(argv)

    if a.cmd == 'gui':
        from .app import run
        return run()
    if a.cmd in ('selftest', 'vectors', 'trace', 'bench'):
        from .cipher import selfcheck
        if a.cmd == 'selftest':
            return 0 if selfcheck.selftest() else 1
        if a.cmd == 'vectors':
            return 0 if selfcheck.print_vectors() else 1
        if a.cmd == 'trace':
            selfcheck.k64_trace()
            return 0
        selfcheck.bench()
        return 0
    if a.cmd in ('enc', 'dec'):
        from .engine import KazualError
        try:
            return _cmd_crypt(a)
        except KazualError as exc:
            sys.stderr.write('ошибка: %s\n' % exc)
            return 1
        except Exception as exc:                            # noqa: BLE001
            mod = type(exc).__module__
            if mod.startswith('kazual'):
                sys.stderr.write('ошибка: %s\n' % exc)
                return 1
            raise
    parser.print_help()
    return 0
