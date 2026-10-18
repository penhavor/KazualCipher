# -*- coding: utf-8 -*-
"""Страница «О шифре»: справка по семейству Kazual, режимам и честности."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl, Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QHBoxLayout, QPushButton, QTextBrowser,
                               QVBoxLayout, QWidget)

from .. import theme
from ... import __version__


def _spec_path() -> Path:
    return Path(__file__).resolve().parents[3] / 'docs' / 'specification.html'


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
          padding: 12px 16px; color: %(warning)s; }
  .muted { color: %(muted)s; }
  b.accent { color: %(accent_light)s; }
</style>

<h1>KazualCipher <span class="muted">v%(version)s</span></h1>
<p class="muted">Графическая оболочка и режимы работы для семейства
экспериментальных блочных шифров <b>Kazual</b>.</p>

<div class="warn"><b>⚠ Честно о безопасности.</b> Kazual — экспериментальная
учебная конструкция: она <u>не проходила независимого криптоанализа</u>, не
имеет формального доказательства стойкости и <u>не предназначена для защиты
реальных данных</u>. Режим SIV добавляет стандартную структуру
аутентифицированного шифрования, но опирается на те же неисследованные
примитивы (ГОРН-1024 как MAC/KDF). Kazual-64 — учебный шифр с 64-битными
блоком и ключом, не для защиты данных ни при каких условиях.</div>

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
Сначала <code>V = MAC(K_mac)</code> от всех полей пакета и открытого текста,
затем <code>шифрограмма = CTR(K_enc, V‖counter)</code>. Любая подмена любого
байта пакета (включая prefix, params, random) рвёт тег V.</p>
<p><b class="accent">ECB</b> — простой режим: независимые блоки +
дополнение PKCS#7. Без аутентификации, одинаковые открытые блоки дают
одинаковые шифроблоки — учебно-демонстрационный.</p>

<h2>Макет SIV-пакета</h2>
<pre>prefix + params + random + V + шифрограмма        («+» — конкатенация)</pre>
<table>
<tr><th>поле</th><th>размер</th><th>зачем</th><th>настраивается</th></tr>
<tr><td><b>prefix</b></td><td>256 бит</td>
    <td>«магические байты» <code>89 4B 5A 4C</code> (‰KZL) + бренд + версия —
        как ‰PNG у картинок. Форматный фильтр «свой/чужой, той ли версии»;
        энтропии не несёт, но покрыт MAC’ом</td>
    <td>галочка + свой текст</td></tr>
<tr><td><b>params</b></td><td>u16 + ASCII</td>
    <td>самоопписание KDF в PHC-стиле
        <code>$argon2id$v=19$m=65536,t=3,p=4</code>: поднимете m/t — старые
        пакеты останутся читаемыми</td>
    <td>галочка + свои m/t/p</td></tr>
<tr><td><b>random</b></td><td>256 бит</td>
    <td>соль Argon2id: один пароль → разный мастер на каждое сообщение;
        наблюдатель не видит повторов. Безопасность от него не зависит:
        если ГСЧ сломается и random повторится, V всё равно разведёт разные
        тексты (в этом и была суть SIV)</td>
    <td>галочка + фиксированное значение</td></tr>
<tr><td><b>V</b></td><td>512 бит</td>
    <td>синтетический nonce для CTR и тег подлинности в одном лице:
        MAC от всех полей пакета + открытого текста</td>
    <td>всегда в пакете</td></tr>
<tr><td><b>шифрограмма</b></td><td>= тексту</td>
    <td><code>CTR(K_enc, V‖counter)</code> без сцеплений — блоки независимы,
        параллелятся, паддинга нет</td>
    <td>—</td></tr>
</table>
<p class="muted">MAC = ГОРН(K_mac ‖ каноническая-упаковка-полей ‖ текст) —
губка с ёмкостью 512 бит, поэтому конструкция «ключ ‖ сообщение» не
удлиняема (length-extension) и HMAC не требуется. Домены разделены тегом
с именем шифра и версией формата.</p>

<h2>Состав проекта</h2>
<pre>main.py                  запуск GUI
kazual/cipher/           эталонная реализация шифров (§1–§12 спецификации)
kazual/modes/            SIV, ECB, CTR, MAC, PKCS#7
kazual/kdf.py            Argon2id + PHC-параметры
kazual/keys.py           пароль / сырой ключ → K_enc, K_mac
kazual/engine.py         фасад «настройки → данные → результат»
kazual/app/              GUI (PySide6)
kazual/cli.py            консоль: python -m kazual …
tests/                   pytest-набор (не для пользователя)
docs/specification.html  полная спецификация Kazual-512/64</pre>

<h2>Скорость</h2>
<p class="muted">Это эталонная реализация на Python: NumPy-пакетный путь
ускоряет независимые блоки в десятки раз, но порядок величин —
единицы-десятки КиБ/с для Kazual-512 (расписание ключа ≈ 0.5 с, зато оно
кэшируется на операцию). Kazual-64 легче на порядок. MAC (ГОРН) — порядка
100 КиБ/с. Для мегабайтов закладывайте минуты; интерфейс показывает прогресс
и поддерживает отмену.</p>

<p class="muted">Лицензия MIT · полная спецификация шифра — кнопка
«Открыть спецификацию» выше.</p>
'''


class AboutPage(QWidget):
    def __init__(self, win):
        super().__init__(win)
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 18, 24, 18)
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
            'text': theme.TEXT, 'muted': theme.MUTED, 'card': theme.CARD,
            'border': theme.BORDER, 'accent_light': '#9d8bff',
            'teal': theme.TEAL, 'warning': theme.WARNING, 'mono': mono,
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
