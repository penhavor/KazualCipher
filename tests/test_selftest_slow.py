# -*- coding: utf-8 -*-
"""Тяжёлые проверки эталонной реализации (полный selftest + векторы).

Запуск:  pytest -m slow
"""

import pytest

from kazual.cipher import selfcheck


@pytest.mark.slow
def test_full_selftest():
    assert selfcheck.selftest() is True


@pytest.mark.slow
def test_print_vectors():
    assert selfcheck.print_vectors() is True
