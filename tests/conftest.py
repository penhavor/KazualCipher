# -*- coding: utf-8 -*-
"""Общие фикстуры: быстрые KDF-параметры, ключи, примеры данных."""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kazual.kdf import KdfParams                      # noqa: E402
from kazual.keys import PasswordKey, RawKey            # noqa: E402
from kazual.modes.siv import SivOptions                # noqa: E402

# Argon2id на минимуме — тесты должны бегать быстро; стойкость здесь не важна
FAST_KDF = KdfParams(memory_kib=64, iterations=1, parallelism=1)
PASSWORD = PasswordKey('тестовый-пароль-123')
RAWKEY = RawKey(bytes(range(16)))


@pytest.fixture
def fast_kdf():
    return FAST_KDF


@pytest.fixture
def rnd():
    import random
    return random.Random(20261018)


def siv_opts(**kw):
    base = dict(prefix_enabled=True, params_enabled=True,
                random_enabled=True, kdf_params=FAST_KDF)
    base.update(kw)
    return SivOptions(**base)


SAMPLE_TEXT = 'Привет, Kazual! The quick brown fox jumps over the lazy dog.'
SAMPLE_BYTES = SAMPLE_TEXT.encode('utf-8')
BIG_BYTES = os.urandom(64 * 1024)
