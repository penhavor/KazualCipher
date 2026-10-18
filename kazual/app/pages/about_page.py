# -*- coding: utf-8 -*-
"""Страница «О шифре»: справка по семейству Kazual, форматам и честности.

Здесь живёт ЕДИНСТВЕННОЕ полное предупреждение о статусе шифра — остальные
страницы намеренно не дублируют его (однажды принято при первом запуске).
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QHBoxLayout, QPushButton, QTextBrowser,
                               QVBoxLayout, QWidget)

from .. import theme
from ... import __version__


def _spec_path() -> Path:
    return Path(__file__).resolve().parents[3] / 'docs' / 'specification.html'


WARNING_TEXT = (
    'Kazual — экспериментальная учебная конструкция: она не проходила '
    'независимого криптоанализа и не имеет формального доказательства '
    'стойкости. Не используйте её как единственную защиту данных, которые '
    'вы не готовы потерять. Для боевых задач применяйте проверенные '
    'стандарты (AES-GCM, ChaCha20-Poly1305). Режим SIV v2 даёт стандартную '
    'структуру аутентифицированного шифрования, но опирается на '
    'собственные неисследованные примитивы (ГОРН-1024 как MAC/KDF, '
    'Kazual как блочный шифр). Kazual-64 — учебный шифр с 64-битными блоком '
    'и ключом, не для защиты данных ни при каких условиях.')


_HTML = '''
<style>
  body { color: %(text)s; font-size: 10.5pt; line-height: 1.55; }
  h1 { font-size: 17pt; margin-bottom: 2px; }
  h2 { font-size: 13pt; color: %(accent_light)s; margin-top: 22px;
       border-bottom: 1px solid %(border)s; padding-bottom: 4px; }
  a { color: %(teal)s; }
  code, pre { font-family: %(mono)s; background: %(card)s; border-radius: 6px; }
  code { padding: 1px 5px; }
  pre { padding: 10px 14px; border: 1px solid %(border)s; overflow-x: auto; }
  table { border-collapse: collapse; width: 100%%; margin: 8px 0; }
  th, td { border: 1px solid %(border)s; padding: 6px 10px; text-align: left;
           vertical-align: top; }
  th { background: %(card)s; color: %(muted)s; font-weight: 600; }
  .warn { background: #33270f; border: 1px solid #7a5a17; border-radius: 10px;
          padding: 12px 16px; color: %(warn_color)s; }
  .muted { color: %(muted)s; }
  b.accent { color: %(accent_light)s; }
</style>

<h1>KazualCipher <span class="muted">v%(version)s</span></h1>
<p class="muted">Графическая оболочка и режимы работы для семейства
экспериментальных блочных шифров <b>Kazual</b>.</p>

<div class="warn"><b>⚠ Честно о безопасности (единственное полное
предупреждение — других по интерфейсу рассыпано не будет).</b>
%(warning)s</div>

<h2>Семейство</h2>
<table>
<tr><th></th><th>Kazual-512</th><th>Kazual-64</th></tr>
<tr><td>блок / ключ</td><td>512 / 512 бит</td><td>64 / 64 бита</td></tr>
<tr><td>раундов</td><td>5 вызовов F + 6 пол-раундов H</td><td>2 + 3</td></tr>
<tr><td>назначение</td><td>рабочий шифр для компьютера</td>
    <td>учебный: счёт вручную, даже на бумаге</td></tr>
<tr><td>каркас</td><td colspan="2">схема Лай–Мэсси с ключевым пол-раундом H;
    F — необратимый трёхтактный SPN (Заслонка + Несущая + «маска → S-box →
    Cauchy-MDS» × 3); H — ортоморфизм GF(2¹⁶) → Несущая → Веер MDS;
    расписание — ГОРН-1024 → двутактная GFN Type-2 → КУЗНИЦА динамических
    таблиц</td></tr>
<tr><td>примитивы</td><td colspan="2">ни одного внешнего криптопримитива:
    собственная губка ГОРН-1024, алгебры GF(2⁸)·GF(2¹⁶)·Z₂⁶⁴, константы —
    цифры π и e</td></tr>
</table>

<h2>Режимы работы</h2>
<p><b class="accent">SIV</b> — аутентифицированное шифрование с
синтетическим IV. Пароль → Argon2id → мастер-ключ → <code>K_enc ‖ K_mac</code>.
Сначала <code>V = MAC(K_mac)</code> от всех полей заголовка и открытого
текста (tree-MAC: листья параллельно на всех ядрах), затем
<code>шифрограмма = CTR(K_enc, V‖counter)</code>. Любая подмена любого
байта файла рвёт тег V.</p>
<p><b class="accent">ECB</b> — простой режим: независимые блоки +
дополнение PKCS#7. Без аутентификации, одинаковые открытые блоки дают
одинаковые шифроблоки — учебно-демонстрационный.</p>

<h2>Контейнер v2 (по умолчанию с версии 1.1)</h2>
<p>Файл <b>сам описывает себя</b>: шифр, режим, параметры Argon2id, состав
полей и размер листа MAC лежат в заголовке. При расшифровке программа
читает их из файла — угадывать «галочки» больше не нужно.</p>
<pre>magic ‖ ver ‖ cipher ‖ mode ‖ flags ‖ brand ‖ [params] ‖ [random] ‖ leaf_size ‖ total_len ‖ V ‖ шифрограмма</pre>
<table>
<tr><th>поле</th><th>размер</th><th>зачем</th></tr>
<tr><td><b>magic+ver+cipher+mode+flags</b></td><td>8 бит…8 байт</td>
    <td>узнавание формата «свой/чужой», шифр, режим, какие поля присутствуют</td></tr>
<tr><td><b>brand</b></td><td>0…255 Б</td>
    <td>текстовая метка владельца/версии (необязательно), покрыта MAC’ом</td></tr>
<tr><td><b>params</b></td><td>u16 + ASCII</td>
    <td>PHC-строка <code>$argon2id$v=19$m=…,t=…,p=…</code> — самоописание KDF</td></tr>
<tr><td><b>random</b></td><td>256 бит</td>
    <td>соль Argon2id: один пароль → разный ключ на каждый файл</td></tr>
<tr><td><b>leaf_size + total_len</b></td><td>u32 + u64</td>
    <td>параметры tree-MAC и точная длина данных (защита от обрезания)</td></tr>
<tr><td><b>V</b></td><td>512 бит</td>
    <td>тег подлинности = корень tree-MAC; он же nonce для CTR</td></tr>
<tr><td><b>шифрограмма</b></td><td>= тексту</td>
    <td><code>CTR(K_enc, V‖counter)</code>, без паддинга</td></tr>
</table>

<h2>Скорость и большие файлы</h2>
<p>С версии 1.1 ядра шифра и MAC компилируются в машинный код (numba JIT) и
работают параллельно на всех ядрах CPU; файлы любого размера обрабатываются
потоково — потребление ОЗУ постоянно (десятки мегабайт) и не зависит от
размера файла. Порядок величин на современном многоядерном CPU:
<b>сотни МиБ/с</b> для CTR и tree-MAC; узкое место — дисковая подсистема.
Расписание ключа кэшируется; временные файлы пишутся атомарно
(<code>.part</code> → переименование), при отмене удаляются.</p>

<h2>Состав проекта</h2>
<pre>main.py                  запуск GUI + автоустановка зависимостей
kazual/cipher/           эталонная реализация шифров + native.py (numba JIT)
kazual/modes/            контейнер v2, SIV (+tree-MAC), ECB, CTR, PKCS#7
kazual/stream.py         потоковые конвейеры для файлов любого размера
kazual/config.py         система конфигураций (JSON)
kazual/kdf.py            Argon2id + PHC-параметры
kazual/keys.py           пароль / сырой ключ → K_enc, K_mac
kazual/engine.py         фасад «настройки → данные → результат»
kazual/app/              GUI (PySide6)
kazual/cli.py            консоль: python -m kazual …
tests/                   pytest-набор (для разработки)
docs/specification.html  полная спецификация Kazual-512/64</pre>

<p class="muted">Лицензия MIT · полная спецификация шифра — кнопка
«Открыть спецификацию» выше.</p>
'''


class AboutPage(QWidget):
    def __init__(self, win):
        super().__init__(win)
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 16, 24, 16)
        v.setSpacing(10)

        row = QHBoxLayout()
        btn_spec = QPushButton('Открыть спецификацию (HTML)')
        btn_spec.setToolTip(str(_spec_path()))
        btn_spec.clicked.connect(self._open_spec)
        row.addWidget(btn_spec)
        row.addStretch(1)
        v.addLayout(row)

        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        mono = ', '.join(theme.MONO_FAMILIES[:3])
        browser.setHtml(_HTML % {
            'version': __version__,
            'warning': WARNING_TEXT,
            'text': theme.TEXT, 'muted': theme.MUTED, 'card': theme.CARD,
            'border': theme.BORDER, 'accent_light': '#9d8bff',
            'teal': theme.TEAL, 'warn_color': theme.WARNING, 'mono': mono,
        })
        v.addWidget(browser, 1)

    def _open_spec(self):
        p = _spec_path()
        if p.is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(p)))
        else:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.information(
                self, 'Спецификация не найдена',
                'Файл docs/specification.html не найден рядом с проектом:\n%s'
                % p)

    def set_busy(self, busy: bool):
        pass

    def on_progress(self, stage, frac):
        pass
