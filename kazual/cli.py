# -*- coding: utf-8 -*-
"""
Консольный интерфейс KazualCipher.

    python -m kazual                     графический интерфейс (по умолчанию)
    python -m kazual gui                 то же явно
    python -m kazual selftest            полные самопроверки шифров (~15 с)
    python -m kazual vectors             тестовые векторы
    python -m kazual trace               подробная трассировка Kazual-64
    python -m kazual bench               замер скорости (включая native)

    # один или несколько файлов (контейнер v2 создаётся автоматически):
    python -m kazual enc --password "секрет" --input a.txt b.txt --outdir out/
    python -m kazual dec --password "секрет" --input out/a.txt.kaz out/b.txt.kaz
    python -m kazual enc --password "секрет" --input big.iso
                (результат рядом: big.iso.kaz)

    # тонкая настройка пакета:
    --no-params | --no-random | --brand ТЕКСТ | --kdf M,T,P |
    --threads N | --backend auto|native|cpu|gpu|scalar | --leaf-mib N |
    --overwrite
"""

from __future__ import annotations

import argparse
import base64
import os
import sys

from . import __version__


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='kazual',
        description='KazualCipher — шифры Kazual-512/Kazual-64, режимы '
                    'SIV/ECB, контейнер v2, потоковая обработка файлов')
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
        sp.add_argument('--input', nargs='+', metavar='FILE',
                        help='файл(ы); при нескольких результат кладётся '
                             'рядом с каждым или в --outdir')
        sp.add_argument('--output', help='файл результата (для одного '
                                         'входа; иначе stdout)')
        sp.add_argument('--outdir', help='папка результатов (пакетный режим)')
        sp.add_argument('--overwrite', action='store_true',
                        help='перезаписывать существующие файлы')
        sp.add_argument('--format', choices=['auto', 'b64', 'hex'],
                        default='auto',
                        help='enc: формат вывода текста (auto=b64); '
                             'dec: формат входа для --text')
        # тонкая настройка контейнера
        sp.add_argument('--brand', default=None,
                        help='текст-метка в заголовке v2 (бренд/версия)')
        sp.add_argument('--no-params', action='store_true',
                        help='не сохранять параметры Argon2id в файл')
        sp.add_argument('--no-random', action='store_true',
                        help='детерминированный режим (нулевая соль)')
        sp.add_argument('--kdf', default=None, metavar='M,T,P',
                        help='параметры Argon2id, например 65536,3,4')
        # производительность
        sp.add_argument('--threads', type=int, default=0,
                        help='потоки (0 = все ядра)')
        sp.add_argument('--backend', default='auto',
                        choices=['auto', 'native', 'cpu', 'gpu', 'scalar'])
        sp.add_argument('--leaf-mib', type=int, default=4,
                        help='лист tree-MAC в МиБ (по умолчанию 4)')
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
    siv = SivOptions(prefix_enabled=bool(a.brand),
                     prefix_text=a.brand,
                     params_enabled=not a.no_params,
                     kdf_params=kdf,
                     random_enabled=not a.no_random,
                     leaf_size=max(64, a.leaf_mib * 1024 * 1024))
    return Settings(cipher=a.cipher, mode=a.mode, source=source,
                    kdf_params=kdf, siv=siv, backend=a.backend,
                    threads=a.threads)


def _decode_text(s: str, fmt: str) -> bytes:
    """Строка пакета → байты (hex при строгом соответствии, иначе Base64)."""
    import re
    compact = re.sub(r'\s+', '', s)
    if fmt == 'hex' or (fmt == 'auto'
                        and re.fullmatch(r'[0-9a-fA-F]+', compact)
                        and len(compact) % 2 == 0):
        return bytes.fromhex(compact)
    return base64.b64decode(compact, validate=True)


def _progress_printer():
    last = ['']

    def progress(stage, frac=None):
        line = '\r[%s] %s%s' % (
            ' ' * 10 if frac is None else ('=' * int(frac * 10)).ljust(10),
            stage, '' if frac is None else ' %.0f%%' % (frac * 100))
        if line != last[0]:
            sys.stderr.write(line)
            last[0] = line
    return progress


def _cmd_crypt(a) -> int:
    from .engine import encrypt, decrypt
    from . import stream

    st = _make_settings(a)
    progress = _progress_printer()

    # ---- текстовый режим ----
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
        fn = encrypt if a.cmd == 'enc' else decrypt
        res = fn(st, data, progress=progress)
        sys.stderr.write('\r' + ' ' * 70 + '\r')
        if a.output:
            with open(a.output, 'wb') as f:
                f.write(res.data if a.cmd == 'enc' else res.data)
            sys.stderr.write('сохранено: %s (%d байт)\n'
                             % (a.output, len(res.data)))
        else:
            if a.cmd == 'dec':
                try:
                    sys.stdout.write(res.data.decode('utf-8') + '\n')
                except UnicodeDecodeError:
                    sys.stdout.write(base64.b64encode(res.data).decode()
                                     + '\n')
            else:
                out = res.data.hex().upper() if a.format == 'hex' \
                    else base64.b64encode(res.data).decode()
                sys.stdout.write(out + '\n')
        _print_notes(res)
        return 0

    # ---- файловый режим (потоковый, любой размер) ----
    if not a.input:
        sys.stderr.write('нужно --text или --input FILE [FILE …]\n')
        return 2
    enc = (a.cmd == 'enc')
    if a.output and len(a.input) > 1:
        sys.stderr.write('--output допустим только для одного --input; '
                         'для нескольких используйте --outdir\n')
        return 2
    if a.outdir:
        os.makedirs(a.outdir, exist_ok=True)
    try:
        jobs = []
        for src in a.input:
            dst = a.output if a.output else stream.resolve_output_path(
                src, enc, a.outdir, a.overwrite)
            jobs.append((src, dst))
    except OSError as exc:
        sys.stderr.write('ошибка: %s\n' % exc)
        return 1
    fn = stream.encrypt_files if enc else stream.decrypt_files
    reports = fn(st, jobs, progress, None)
    sys.stderr.write('\r' + ' ' * 70 + '\r')
    rc = 0
    for r in reports:
        if r.ok:
            sys.stderr.write('%s → %s (%s, %.1f с)\n'
                             % (r.src, r.dst, _hs(r.out_bytes), r.seconds))
            if r.info and not enc:
                sys.stderr.write('   %s\n' % r.info)
        else:
            sys.stderr.write('%s: ОШИБКА %s\n' % (r.src, r.error))
            rc = 1
    return rc


def _hs(n):
    for unit in ('Б', 'КиБ', 'МиБ', 'ГиБ'):
        if n < 1024 or unit == 'ГиБ':
            return '%.1f %s' % (n, unit) if unit != 'Б' else '%d Б' % n
        n /= 1024.0
    return '%d Б' % n


def _print_notes(res):
    for w in res.warnings:
        sys.stderr.write('примечание: %s\n' % w)
    if res.mode == 'siv' and res.meta.get('verified'):
        sys.stderr.write('подлинность: ПОДТВЕРЖДЕНА (V сошёлся)\n')


def _bench() -> int:
    from .cipher import selfcheck
    selfcheck.bench()
    selfcheck.bench_native()
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
    if a.cmd in ('selftest', 'vectors', 'trace'):
        from .cipher import selfcheck
        if a.cmd == 'selftest':
            return 0 if selfcheck.selftest() else 1
        if a.cmd == 'vectors':
            return 0 if selfcheck.print_vectors() else 1
        selfcheck.k64_trace()
        return 0
    if a.cmd == 'bench':
        return _bench()
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
