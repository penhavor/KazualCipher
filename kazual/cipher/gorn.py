# -*- coding: utf-8 -*-
"""
ГОРН-1024 — собственная сжимающая функция Kazual: губка с тиглем 16×64 бита,
8 раундов «Σ Μ Ρ Α», ёмкость 512 бит. Режимы: дайджест (gorn_hash) и
расширение/KDF (gorn_expand). §2 и §11 спецификации (обратный ход — для
самопроверки биективности).
"""

from .gf import MUL8T, cauchy, cauchy_inv_tables, inv8, _subset_xor_table

# Собственная сжимающая функция: тигель 16×64 бита, 8 раундов «Σ Μ Ρ Α».
# Оптимизация: Μ (8 колоночных MDS 16×16) и Ρ (косой перенос) слиты в один
# проход по 1024-битному слову — колоночные big-int таблицы + поворот слотов.

M64 = (1 << 64) - 1
M1024 = (1 << 1024) - 1
LANES, NBYTES, ROUNDS, RATE = 16, 128, 8, 64        # ёмкость губки = 512 бит

PI_HEX = ("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
          "452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B5470917"
          "9216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96"
          "BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69")
E_HEX = ("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
         "324E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F59584"
         "90CFD47D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF"
         "8A9A276BCFBFA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED87")

POOL = [int(PI_HEX[i * 16:(i + 1) * 16], 16) for i in range(16)] + \
       [int(E_HEX[i * 16:(i + 1) * 16], 16) for i in range(16)]   # 32 слова × 64 бита
IV = POOL[0:16]
IV_BYTES = b''.join(w.to_bytes(8, 'big') for w in IV)


def rotl64(x, k):
    k &= 63
    return ((x << k) | (x >> (64 - k))) & M64 if k else x


def _poolbyte(k, sh):
    """Байт sh слова Π[k] (нумерация от младшего)."""
    return (POOL[k % 32] >> (sh % 8) * 8) & 0xFF


def _nz8(x):
    """Гарантия ненулевого множителя для ФИКСИРОВАННЫХ констант пула:
    подстановка 0 → 0x5A. Отбраковка к конечному пулу неприменима; фактически
    ни один используемый байт пула не равен нулю (проверяется самопроверкой),
    поэтому подставка не срабатывает. Нулевой множитель сделал бы Σ-слой
    невырожденно постоянным и разрушил биективность перестановки ГОРНа."""
    return x if x else 0x5A


# ---- константы стадий: явные формулы индексации пула ----
ODD = [[((rotl64(POOL[(r + i) % 32], (5 * r + 3 * i + 7) % 64)
          ^ POOL[(7 * r + 5 * i + 11) % 32]) | 1) & M64
        for i in range(LANES)] for r in range(ROUNDS)]
LCST = [[rotl64(POOL[(3 * r + 11 * i + 13) % 32], (11 * r + 7 * i + 1) % 64)
          ^ POOL[(5 * r + 13 * i + 17) % 32]
         for i in range(LANES)] for r in range(ROUNDS)]
ROT = [[1 + (rotl64(POOL[(3 * r + 5 * i + 1) % 32], (r + i) % 64)
             >> ((r + 3 * i) % 8) * 8) % 61
        for i in range(LANES)] for r in range(ROUNDS)]
SIG = [[_poolbyte(r + p, p * 7 + r * 3) for p in range(NBYTES)] for r in range(ROUNDS)]
SIGB = [[_poolbyte(3 * p + r + 9, p + 5 * r) for p in range(NBYTES)] for r in range(ROUNDS)]
AFFA = [[_nz8(_poolbyte(r * 5 + p, p * 3 + r)) for p in range(NBYTES)] for r in range(ROUNDS)]
AFFC = [[_poolbyte(p + 2 * r + 5, p * 5 + r * 11) for p in range(NBYTES)] for r in range(ROUNDS)]

C16 = cauchy(16)

# Σ-слой: 8×128 таблиц по 256 Б — аффинное сопряжение инверсии x↦A⊗(x⊕Bg)⁻¹⊕C⊕Sg
# (биекция: AFFA ≠ 0)
SIGTBL = [[bytes(MUL8T[AFFA[r][p]][inv8(x ^ SIGB[r][p])] ^ (AFFC[r][p] ^ SIG[r][p])
                 for x in range(256)) for p in range(NBYTES)] for r in range(ROUNDS)]


def _build_gorn_ctab():
    """Колоночные big-int таблицы Μ: _GCTAB[j][v] — 1024-битное слово, в слоте
    лейны i (байт по смещению 8i+7) стоит C16[i][j] ⊗ v."""
    ct = []
    for j in range(LANES):
        basis = []
        for b in range(8):
            ba = bytearray(NBYTES)
            for i in range(LANES):
                ba[8 * i + 7] = MUL8T[C16[i][j]][1 << b]
            basis.append(int.from_bytes(ba, 'big'))
        ct.append(_subset_xor_table(basis))
    return ct


_GCTAB = _build_gorn_ctab()
_GEXT = [[1016 - 8 * q - 64 * j for j in range(LANES)] for q in range(8)]
_GSH = [[(5 * q + r) % LANES for q in range(8)] for r in range(ROUNDS)]
_GASM = [56 - 8 * q for q in range(8)]


def _mds_rho(state, r):
    """Σ = Μ∘Ρ: 8 независимых колоночных MDS 16×16 + косой перенос байтов
    byte(i,q) → byte((i+5q+r) mod 16, q). Один проход по 1024-битному слову."""
    S = int.from_bytes(state, 'big')
    CT = _GCTAB
    shs = _GSH[r]
    acc = 0
    for q in range(8):
        ext = _GEXT[q]
        colq = 0
        for j in range(LANES):
            cb = (S >> ext[j]) & 0xFF
            if cb:
                colq ^= CT[j][cb]
        sh = shs[q]
        if sh:
            colq = ((colq >> (64 * sh)) | (colq << (1024 - 64 * sh))) & M1024
        acc ^= colq << _GASM[q]
    return acc.to_bytes(NBYTES, 'big')


def _sigma(state, r):
    return bytes(tbl[b] for tbl, b in zip(SIGTBL[r], state))


def _alpha(state, r):
    """ARX-лейны: 16 независимых слов (×, ⊕≫29, rotl, +). Все шаги биективны."""
    odd, lc, ro = ODD[r], LCST[r], ROT[r]
    out = []
    fb, tb = int.from_bytes, bytes
    for i in range(LANES):
        x = fb(state[8 * i:8 * i + 8], 'big')
        x = (x * odd[i]) & M64
        x ^= x >> 29
        k = ro[i]
        x = ((x << k) | (x >> (64 - k))) & M64
        x = (x + lc[i]) & M64
        out.append(tb(x.to_bytes(8, 'big')))
    return b''.join(out)


def gorn_perm(state: bytes) -> bytes:
    """Внутренняя перестановка 1024 → 1024 бит. Биективна (все стадии биективны,
    Σ-слой — аффинные сопряжения инверсии с ненулевым множителем)."""
    for r in range(ROUNDS):
        state = _sigma(state, r)
        state = _mds_rho(state, r)
        state = _alpha(state, r)
    return state


def _fold(state: bytes) -> bytes:
    """Свёртка 1024 → 512. Блок «низ-низ» равен единице ⇒ ранг ровно 512."""
    w = [int.from_bytes(state[8 * i:8 * i + 8], 'big') for i in range(LANES)]
    out = bytearray(64)
    for i in range(8):
        v = (w[i] ^ rotl64(w[i + 8], 17)
             ^ rotl64(w[(i + 3) % 8 + 8], 41) ^ rotl64(w[(2 * i + 5) % 8 + 8], 53))
        out[8 * i:8 * i + 8] = v.to_bytes(8, 'big')
    return bytes(out)


def _pad(msg: bytes, tag: bytes) -> list:
    """Доменное разделение + длина: tag ‖ 0x1F ‖ msg ‖ 0x80 ‖ 0x00… ‖ len64be(msg)."""
    if b'\x1f' in tag:
        raise ValueError('тег не должен содержать байт 0x1F (разделитель доменов)')
    body = tag + b'\x1f' + msg
    n = (-len(body) - 9) % RATE
    body = body + b'\x80' + b'\x00' * n + len(msg).to_bytes(8, 'big')
    return [body[i:i + RATE] for i in range(0, len(body), RATE)]


def _absorb(blocks, s=IV_BYTES):
    for B in blocks:
        s = gorn_perm((int.from_bytes(s, 'big')
                       ^ (int.from_bytes(B, 'big') << 512)).to_bytes(NBYTES, 'big'))
    return s


def gorn_hash(msg: bytes, tag: bytes = b'') -> bytes:
    """Дайджест 512 бит (губка: впитывание + финальная перестановка + свёртка)."""
    return _fold(gorn_perm(_absorb(_pad(msg, tag))))


class GornHasher:
    """Инкрементальный ГОРН: потоковый дайджест, побитово равен gorn_hash.

    Нужен для MAC/файлов: данные впитываются порциями, память O(RATE),
    можно сообщать прогресс. Порядок блоков идентичен _pad().
    """

    __slots__ = ('_state', '_buf', '_msglen', '_tag')

    def __init__(self, tag: bytes = b''):
        if b'\x1f' in tag:
            raise ValueError('тег не должен содержать байт 0x1F (разделитель доменов)')
        self._tag = tag
        self._state = IV_BYTES
        self._buf = bytearray(tag + b'\x1f')
        self._msglen = 0

    def update(self, data: bytes) -> 'GornHasher':
        """Поглотить очередную порцию сообщения."""
        self._msglen += len(data)
        self._buf += data
        n = (len(self._buf) // RATE) * RATE
        if n:
            head, self._buf = self._buf[:n], self._buf[n:]
            self._state = _absorb(
                [bytes(head[i:i + RATE]) for i in range(0, n, RATE)],
                self._state)
        return self

    def digest(self) -> bytes:
        """Финал: доменное дополнение + длина → дайджест 512 бит.

        Хэшер одноразовый: повторный вызов даст тот же результат, но
        update() после digest() запрещён (состояние финализировано).
        """
        pad_n = (-len(self._buf) - 9) % RATE
        tail = bytes(self._buf) + b'\x80' + b'\x00' * pad_n \
            + self._msglen.to_bytes(8, 'big')
        state = _absorb([tail[i:i + RATE] for i in range(0, len(tail), RATE)],
                        self._state)
        return _fold(gorn_perm(state))



def gorn_expand(seed: bytes, tag: bytes, nbytes: int) -> bytes:
    """Режим расширения (KDF): непрерывный отжим, одна перестановка на 64 байта."""
    s = _absorb(_pad(seed, tag))
    out = bytearray()
    while len(out) < nbytes:
        s = gorn_perm(s)
        out += _fold(s)
    return bytes(out[:nbytes])


forge = gorn_expand                       # псевдоним: режим расширения = КУЗНИЦА



# ==============================================================================
# ОБРАТНЫЙ ХОД ГОРНА (§11 — только для самопроверки биективности)
# ==============================================================================


def _rotr64(x, k):
    k &= 63
    return ((x >> k) | (x << (64 - k))) & M64 if k else x


def _xsr_inv(y, s):
    """Обращение x ← x ⊕ (x ≫ s) (унипотентный сдвиг)."""
    x = y
    sh = s
    while sh < 64:
        x ^= (y >> sh)
        y = x
        sh += s
    return x & M64


_ODDINV = [[pow(ODD[r][i], -1, 1 << 64) for i in range(LANES)] for r in range(ROUNDS)]
_SIGINV = [[None] * NBYTES for _ in range(ROUNDS)]
for _rr in range(ROUNDS):
    for _pp in range(NBYTES):
        _tt = bytearray(256)
        for _xx in range(256):
            _tt[SIGTBL[_rr][_pp][_xx]] = _xx
        _SIGINV[_rr][_pp] = bytes(_tt)
del _rr, _pp, _tt, _xx
_C16INV = cauchy_inv_tables(16)
_T16INV = {v: MUL8T[v] for v in {v for row in _C16INV for v in row}}


def gorn_perm_inv(state):
    """Явный обратный ход gorn_perm — доказательство биективности перестановки."""
    for r in range(ROUNDS - 1, -1, -1):
        out = bytearray(NBYTES)
        odd, lc, ro = _ODDINV[r], LCST[r], ROT[r]
        for i in range(LANES):
            x = int.from_bytes(state[8 * i:8 * i + 8], 'big')
            x = (x - lc[i]) & M64
            x = _rotr64(x, ro[i])
            x = _xsr_inv(x, 29)
            x = (x * odd[i]) & M64
            out[8 * i:8 * i + 8] = x.to_bytes(8, 'big')
        state = bytes(out)
        out = bytearray(NBYTES)                       # Ρ⁻¹
        for q in range(8):
            sh = (5 * q + r) % LANES
            for i in range(LANES):
                out[i * 8 + q] = state[((i + sh) % LANES) * 8 + q]
        state = bytes(out)
        grid = [list(state[i * 8:i * 8 + 8]) for i in range(LANES)]   # Μ⁻¹
        for q in range(8):
            col = [grid[i][q] for i in range(LANES)]
            for i in range(LANES):
                ci = _C16INV[i]
                acc = 0
                for j in range(LANES):
                    v = col[j]
                    if v:
                        acc ^= _T16INV[ci[j]][v]
                grid[i][q] = acc
        state = bytes(b for row in grid for b in row)
        t = _SIGINV[r]                                  # Σ⁻¹
        state = bytes(t[p][state[p]] for p in range(NBYTES))
    return state
