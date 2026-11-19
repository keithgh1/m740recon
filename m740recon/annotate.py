"""Annotations for the --suggest draft and the JSON model: what the bytes
and addresses outside the code look like.  Nothing here changes decoding.

memory_map  how the code uses addresses outside the image: pages mostly read
            and written are RAM; others are inputs, outputs or both (I/O).
            An address that is only written and receives three or more
            HD44780 command values (0x38, 0x0C, 0x06, 0x01, ...) is likely an
            LCD controller's command register.
fonts       dot-matrix glyph data: runs of 256-byte windows where neighbouring
            bytes differ by few bits (column after column of a glyph) and blank
            columns (0x00) are common.  Only regions with no traced code.
text        runs of printable ASCII that read as words, outside code and fonts.
"""

import re
from collections import defaultdict, namedtuple

Region = namedtuple("Region", "start end kind note")

_READS = {"lda", "ldx", "ldy", "cmp", "cpx", "cpy", "adc", "sbc", "and", "ora", "eor",
          "bit", "tst", "bbs", "bbc"}
_WRITES = {"sta", "stx", "sty", "ldm"}
_RMW = {"inc", "dec", "asl", "lsr", "rol", "ror", "seb", "clb", "com", "rrf"}
_LCD = {0x38, 0x30, 0x28, 0x0C, 0x0E, 0x0F, 0x06, 0x01, 0x02, 0x80}
_IMM = re.compile(r"#0x([0-9a-f]+)")
_POP = [bin(i).count("1") for i in range(256)]
_WIN, _STEP = 256, 128


def memory_map(mem, lo, hi):
    """(regions, lcd addresses).  Regions cover pages above zero page."""
    acc = defaultdict(lambda: [0, 0])
    imms = defaultdict(set)
    last_imm = None
    for a, inst in mem.iter_instructions():
        if not lo <= a < hi:
            continue
        text = str(inst)
        mn = text.split()[0]
        m = _IMM.search(text)
        if mn == "lda" and "#" in text and m:
            last_imm = int(m.group(1), 16)
            continue
        r = inst.data_ref_address
        if r is not None and not lo <= r < hi:
            if mn in _READS:
                acc[r][0] += 1
            if mn in _WRITES:
                acc[r][1] += 1
                if mn == "ldm" and m:
                    imms[r].add(int(m.group(1), 16))
                elif mn == "sta" and last_imm is not None:
                    imms[r].add(last_imm)
            if mn in _RMW:
                acc[r][0] += 1
                acc[r][1] += 1
        if mn not in ("ldx", "ldy"):
            last_imm = None
    pages = defaultdict(lambda: {"rw": 0, "r": 0, "w": 0})
    for addr, (rd, wr) in acc.items():
        if addr >= 0x100:
            pages[addr >> 8]["rw" if rd and wr else ("r" if rd else "w")] += 1
    regions = []
    for pg in sorted(pages):
        p = pages[pg]
        total = p["rw"] + p["r"] + p["w"]
        kind = ("ram" if p["rw"] >= max(2, 0.5 * total) else
                "io" if p["r"] and p["w"] else "in" if p["r"] else "out")
        if regions and regions[-1][2] == kind and regions[-1][1] == pg:
            regions[-1][1] = pg + 1
        else:
            regions.append([pg, pg + 1, kind])
    notes = {"ram": "read and written: RAM", "in": "only read: an input or a peripheral",
             "out": "only written: an output or a peripheral", "io": "read and written at different addresses: I/O"}
    out = [Region(a << 8, b << 8, k, notes[k]) for a, b, k in regions]
    lcd = sorted(a for a, v in imms.items()
                 if a >= 0x100 and acc[a][0] == 0 and len(v & _LCD) >= 3)
    return out, [(a, sorted(imms[a] & _LCD)) for a in lcd]


def _glyph_window(w):
    n = len(w)
    s1 = sum(_POP[w[i] ^ w[i + 1]] for i in range(n - 1)) / (n - 1.0)
    s2 = sum(_POP[w[i] ^ w[i + 2]] for i in range(n - 2)) / (n - 2.0)
    zero = w.count(0) / float(n)
    printable = sum(1 for b in w if 0x20 <= b < 0x7F) / float(n)
    # blank or erased memory is not a font, however smooth it looks
    common = max(w.count(b) for b in set(w))
    return (min(s1, s2) <= 2.6 and zero >= 0.12 and w.count(0xFF) < n // 2
            and printable < 0.75 and common < 0.9 * n and len(set(w)) >= 4)


def _code_bytes(mem, lo, hi):
    """1 for every byte already typed: instructions, vectors / pointers,
    words and text.  Annotations never claim typed bytes."""
    code = bytearray(0x10000)
    for a, inst in mem.iter_instructions():
        if lo <= a < hi:
            for i in range(len(inst)):
                code[(a + i) & 0xFFFF] = 1
    for a in range(lo, hi):
        if (mem.is_vector_start(a) or mem.is_vector_continuation(a) or mem.is_word_start(a)
                or mem.is_text_start(a)):
            code[a] = 1
            code[(a + 1) & 0xFFFF] = 1
    return code


def fonts(mem, lo, hi, min_windows=8):
    """Glyph regions [Region] with no traced code in them."""
    code = _code_bytes(mem, lo, hi)
    flags = []
    for a in range(lo, hi - _WIN + 1, _STEP):
        w = bytes(mem[a:a + _WIN])
        flags.append((a, _glyph_window(w) and not any(code[a:a + _WIN])))
    out, start, count = [], None, 0
    for a, g in flags + [(hi, False)]:
        if g:
            if start is None:
                start, count = a, 0
            count += 1
        elif start is not None:
            if count >= min_windows:
                end = min(a - _STEP + _WIN, hi)
                out.append(Region(start, end, "font", "dot-matrix glyph columns"))
            start = None
    return out


def _wordy(txt):
    """Reads as words: mostly letters, digits and punctuation; every run of 3+
    letters is UPPER, lower or Capitalized; at least one such run has a vowel
    and is not an alphabet sequence (character tables like 'LMNOP')."""
    good = sum(1 for c in txt if c.isalnum() or c in " .,:!-/()'")
    if good < 0.8 * len(txt):
        return False
    words = [w for w in re.findall(r"[A-Za-z]+", txt) if len(w) >= 3]
    if not words:
        return False
    # tables of repeated bytes ('HKKKKKIIIIII', 'ooooooo') are not text
    repeated = sum(len(m.group(0)) for m in re.finditer(r"(.)\1{2,}", txt))
    if repeated * 10 > len(txt) * 4:
        return False
    for w in words:
        if not (w.isupper() or w.islower() or (w[0].isupper() and w[1:].islower())):
            return False
    for w in words:
        steps = sum(1 for a, b in zip(w.lower(), w.lower()[1:]) if ord(b) - ord(a) == 1)
        if any(c in "aeiouy" for c in w.lower()) and steps * 2 < len(w) - 1:
            return True
    return False


def _monotonic(bs):
    d = [b - a for a, b in zip(bs, bs[1:])]
    return len(bs) >= 8 and (all(x >= 0 for x in d) or all(x <= 0 for x in d))


def text(mem, lo, hi, avoid=(), min_len=6):
    """Text runs [Region] outside code and outside `avoid` regions."""
    code = _code_bytes(mem, lo, hi)
    blocked = bytearray(code)
    for r in avoid:
        for a in range(r.start, r.end):
            blocked[a & 0xFFFF] = 1
    out, a = [], lo
    while a < hi:
        b = a
        while b < hi and not blocked[b] and 0x20 <= mem[b] <= 0x7E:
            b += 1
        if b - a >= min_len:
            bs = bytes(mem[a:b])
            txt = bs.decode("ascii")
            if not _monotonic(list(bs)) and _wordy(txt):
                out.append(Region(a, b, "text", txt))
            a = b
        a = max(a + 1, b)
    return out
