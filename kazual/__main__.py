# -*- coding: utf-8 -*-
"""python -m kazual → консольный интерфейс (см. kazual.cli)."""

import sys

from .cli import main

if __name__ == '__main__':
    sys.exit(main())
