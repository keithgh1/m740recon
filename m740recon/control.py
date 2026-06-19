"""Control file parser.

A control file lets a user supply disassembly facts -- which device, which
addresses contain code, and what to name them -- without editing the source of
m740recon.  It is a simple line-oriented text format in the spirit of da65's
info file.

Format (one directive per line; '#' starts a comment; quotes group a comment
string):

    device    M50734
    entry     0x8130 reset            # address contains code; optional name
    label     0xc063 tbl_ctrl_std     # name an address (no tracing)
    label     0x8533 main_loop "fetch host byte and dispatch"
    comment   0x82a7 "power-on head fire / beep"
    segment   sys 0x4000 0x8000 rom1.bin@0x4000   # build the image from slices
    range     0x06bd 0x071d byte      # force a region to data
    addrtable 0xc0d4 stride=3 entryoff=1 terminator=0x00 label=cmd_esc_

`entry` registers a traced entry point (use it for handlers reached only by
computed jumps); `label` only names an address.  Both may carry a name, and a
name may be followed by a quoted comment.  `segment` builds the image from file
slices (NAME START END zero|PATH[@OFF]); when any segment is given, no binary
argument is passed.  `range START END KIND` types a region as byte (data),
word (.word values), addr (.word pointers, symbol-substituted), or text
(.ascii).
`addrtable START [opts]` decodes a table of code pointers: each entry is
`stride` bytes with the 2-byte pointer at `entryoff`, ending at `end=`,
`count=`, or `terminator=`; pointers are rendered as .word, traced as code, and
named `label=`PREFIX + the entry character/index.  User symbols are non-weak:
the automatic symbol generator never overwrites them.
"""

import os
import shlex
from collections import namedtuple

from m740recon.symbols import Symbol

# A memory segment: bytes for [start, end) sourced from a file slice or zeros.
Segment = namedtuple("Segment", "name start end kind path off")

# A table of code pointers.  Each entry is `stride` bytes; the 2-byte little-
# endian pointer sits at offset `entryoff` within the entry.  The table ends at
# `end`, after `count` entries, or when the entry's first byte equals
# `terminator`.  Each pointer is rendered as a .word, traced as code, and (if
# `label_prefix` is set) the target is named prefix+token(entry).
AddrTable = namedtuple(
    "AddrTable", "start end count stride entryoff terminator label_prefix names")

# optional `names=ascii` map: control-code mnemonics + punctuation names, so a
# dispatch table named e.g. label=ctl_ produces ctl_BEL, ctl_LF, cmd_esc_bang.
_ASCII_NAMES = {
    0x00: 'NUL', 0x01: 'SOH', 0x02: 'STX', 0x03: 'ETX', 0x04: 'EOT',
    0x05: 'ENQ', 0x06: 'ACK', 0x07: 'BEL', 0x08: 'BS', 0x09: 'HT',
    0x0a: 'LF', 0x0b: 'VT', 0x0c: 'FF', 0x0d: 'CR', 0x0e: 'SO', 0x0f: 'SI',
    0x10: 'DLE', 0x11: 'DC1', 0x12: 'DC2', 0x13: 'DC3', 0x14: 'DC4',
    0x15: 'NAK', 0x16: 'SYN', 0x17: 'ETB', 0x18: 'CAN', 0x19: 'EM',
    0x1a: 'SUB', 0x1b: 'ESC', 0x1c: 'FS', 0x1d: 'GS', 0x1e: 'RS', 0x1f: 'US',
    0x20: 'SP', 0x21: 'bang', 0x22: 'dquote', 0x23: 'hash', 0x24: 'dollar',
    0x25: 'percent', 0x26: 'amp', 0x27: 'quote', 0x28: 'lparen', 0x29: 'rparen',
    0x2a: 'star', 0x2b: 'plus', 0x2c: 'comma', 0x2d: 'minus', 0x2e: 'dot',
    0x2f: 'slash', 0x3a: 'colon', 0x3b: 'semi', 0x3c: 'lt', 0x3d: 'eq',
    0x3e: 'gt', 0x3f: 'qmark', 0x40: 'at', 0x5b: 'lbrack', 0x5c: 'bslash',
    0x5d: 'rbrack', 0x5e: 'caret', 0x5f: 'under', 0x60: 'backtick',
    0x7b: 'lbrace', 0x7c: 'pipe', 0x7d: 'rbrace', 0x7e: 'tilde', 0x7f: 'DEL',
}


class ControlError(Exception):
    """Raised on a malformed control file, with the offending line number."""


class ControlFile(object):
    def __init__(self, base_dir=None):
        self.base_dir = base_dir        # for resolving relative segment paths
        self.device = None
        self.entry_points = []          # list of int addresses to trace as code
        self.segments = []              # list of Segment (memory map)
        self.addr_tables = []           # list of AddrTable (dispatch tables)
        self.ranges = []                # list of (start, end, kind) data ranges
        self._symbols_by_addr = {}      # addr -> Symbol (first writer wins)
        self.comments = {}              # addr -> text (comment-only directives)

    def build_image(self):
        """Assemble the 64K image described by the segment directives."""
        image = bytearray(0x10000)
        for seg in self.segments:
            if seg.kind == "zero":
                continue
            path = seg.path
            if not os.path.isabs(path):
                path = os.path.join(self.base_dir or ".", path)
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except OSError as e:
                raise ControlError("segment %s: %s" % (seg.name, e))
            need = seg.end - seg.start
            chunk = data[seg.off:seg.off + need]
            if len(chunk) < need:
                raise ControlError(
                    "segment %s: source %s too short (need %d bytes at 0x%x, got %d)"
                    % (seg.name, path, need, seg.off, len(chunk)))
            image[seg.start:seg.end] = chunk
        return image

    def resolve_tables(self, image):
        """Expand every addrtable against `image`.

        Returns (pointer_addrs, data_addrs, symbols):
          - pointer_addrs: addresses of 2-byte code pointers, to be treated as
            vectors (rendered as .word, traced, target annotated as code).
          - data_addrs: the non-pointer bytes of each entry, to mark as data.
          - symbols: non-weak Symbols naming the pointer targets (first wins).
        """
        pointer_addrs = []
        data_addrs = []
        syms = {}                       # target addr -> Symbol (first writer wins)
        used_names = set()              # names already taken (must stay unique)
        for tbl in self.addr_tables:
            addr = tbl.start
            index = 0
            while addr + tbl.stride <= len(image):
                # require the whole entry to fit inside [start, end) so the
                # pointer read below never crosses end into the next region
                if tbl.end is not None and addr + tbl.stride > tbl.end:
                    break
                if tbl.count is not None and index >= tbl.count:
                    break
                if tbl.terminator is not None and image[addr] == tbl.terminator:
                    break
                ptr = addr + tbl.entryoff
                target = image[ptr] | (image[ptr + 1] << 8)
                pointer_addrs.append(ptr)
                for da in range(addr, addr + tbl.stride):
                    if da < ptr or da >= ptr + 2:
                        data_addrs.append(da)
                if tbl.label_prefix and target not in syms:
                    # two entries (here or in another table) can map different
                    # targets to the same token; keep names unique so the
                    # listing never emits a duplicate label that as740 rejects
                    name = tbl.label_prefix + _token(tbl, image[addr], index)
                    unique = name
                    suffix = 2
                    while unique in used_names:
                        unique = "%s_%d" % (name, suffix)
                        suffix += 1
                    used_names.add(unique)
                    syms[target] = Symbol(target, unique, weak=False)
                addr += tbl.stride
                index += 1
        return pointer_addrs, data_addrs, list(syms.values())

    @property
    def symbols(self):
        """User (non-weak) Symbols to merge into the SymbolTable."""
        return list(self._symbols_by_addr.values())

    def _add_symbol(self, addr, name, comment=""):
        # first writer wins, matching the wrapper's setdefault behavior
        if addr not in self._symbols_by_addr:
            self._symbols_by_addr[addr] = Symbol(addr, name, comment, weak=False)


def _token(tbl, keybyte, index):
    """Name suffix for a table entry: the entry's character if alphanumeric,
    an ASCII mnemonic if names=ascii, else a hex byte (keyed tables) or the
    entry index (dense tables)."""
    if tbl.entryoff > 0:
        ch = chr(keybyte)
        if ch.isalnum():
            return ch
        if tbl.names == "ascii" and keybyte in _ASCII_NAMES:
            return _ASCII_NAMES[keybyte]
        return "%02x" % keybyte
    return str(index)


def _parse_int(token, lineno):
    try:
        return int(token, 0)
    except ValueError:
        raise ControlError("line %d: bad address %r" % (lineno, token))


def parse(text, base_dir=None):
    """Parse control-file text and return a ControlFile."""
    cf = ControlFile(base_dir=base_dir)
    for lineno, raw in enumerate(text.splitlines(), 1):
        try:
            tokens = shlex.split(raw, comments=True)
        except ValueError as e:
            raise ControlError("line %d: %s" % (lineno, e))
        if not tokens:
            continue
        op = tokens[0].lower()
        args = tokens[1:]

        if op == "device":
            if len(args) != 1:
                raise ControlError("line %d: device needs one name" % lineno)
            cf.device = args[0]

        elif op == "entry":
            if not (1 <= len(args) <= 3):
                raise ControlError("line %d: entry ADDR [NAME] [\"comment\"]" % lineno)
            addr = _parse_int(args[0], lineno)
            cf.entry_points.append(addr)
            if len(args) >= 2:
                comment = args[2] if len(args) >= 3 else ""
                cf._add_symbol(addr, args[1], comment)

        elif op == "label":
            if not (2 <= len(args) <= 3):
                raise ControlError("line %d: label ADDR NAME [\"comment\"]" % lineno)
            addr = _parse_int(args[0], lineno)
            comment = args[2] if len(args) >= 3 else ""
            cf._add_symbol(addr, args[1], comment)

        elif op == "comment":
            if len(args) != 2:
                raise ControlError("line %d: comment ADDR \"text\"" % lineno)
            addr = _parse_int(args[0], lineno)
            cf.comments[addr] = args[1]

        elif op == "segment":
            # segment NAME START END SOURCE   where SOURCE is "zero" or PATH[@OFF]
            if len(args) != 4:
                raise ControlError(
                    "line %d: segment NAME START END (zero|PATH[@OFF])" % lineno)
            name = args[0]
            start = _parse_int(args[1], lineno)
            end = _parse_int(args[2], lineno)
            if not (0 <= start < end <= 0x10000):
                raise ControlError(
                    "line %d: segment %s range 0x%x-0x%x out of bounds"
                    % (lineno, name, start, end))
            src = args[3]
            if src.lower() == "zero":
                cf.segments.append(Segment(name, start, end, "zero", None, 0))
            else:
                if "@" in src:
                    path, off_s = src.rsplit("@", 1)
                    off = _parse_int(off_s, lineno)
                else:
                    path, off = src, 0
                cf.segments.append(Segment(name, start, end, "file", path, off))

        elif op == "range":
            # range START END KIND  -- type a region: byte | word | addr | text
            #   byte: force to data (.byte), keeping it out of the code trace
            #   word: 16-bit little-endian values (.word 0xNNNN)
            #   addr: 16-bit pointers, symbol-substituted (.word label)
            #   text: ASCII (.ascii runs, .byte for non-printable)
            if len(args) != 3:
                raise ControlError("line %d: range START END byte|word|addr|text"
                                   % lineno)
            start = _parse_int(args[0], lineno)
            end = _parse_int(args[1], lineno)
            kind = args[2].lower()
            if not (0 <= start < end <= 0x10000):
                raise ControlError("line %d: range 0x%x-0x%x out of bounds"
                                   % (lineno, start, end))
            if kind not in ("byte", "word", "addr", "text"):
                raise ControlError(
                    "line %d: range kind %r not one of byte/word/addr/text"
                    % (lineno, kind))
            if kind in ("word", "addr") and (end - start) % 2:
                raise ControlError(
                    "line %d: %s range must have an even length" % (lineno, kind))
            cf.ranges.append((start, end, kind))

        elif op == "addrtable":
            # addrtable START [stride=N entryoff=K terminator=0xNN end=0x.. count=N label=PFX]
            if len(args) < 1:
                raise ControlError("line %d: addrtable START [opts]" % lineno)
            start = _parse_int(args[0], lineno)
            opt = {"end": None, "count": None, "stride": 2,
                   "entryoff": 0, "terminator": None, "label": None, "names": None}
            for kv in args[1:]:
                if "=" not in kv:
                    raise ControlError("line %d: addrtable option %r needs key=value"
                                       % (lineno, kv))
                key, val = kv.split("=", 1)
                key = key.lower()
                if key not in opt:
                    raise ControlError("line %d: unknown addrtable option %r"
                                       % (lineno, key))
                opt[key] = val if key in ("label", "names") else _parse_int(val, lineno)
            if opt["end"] is None and opt["count"] is None and opt["terminator"] is None:
                raise ControlError(
                    "line %d: addrtable needs end=, count=, or terminator=" % lineno)
            if opt["entryoff"] + 2 > opt["stride"]:
                raise ControlError(
                    "line %d: addrtable entryoff+2 exceeds stride" % lineno)
            if opt["names"] not in (None, "ascii"):
                raise ControlError(
                    "line %d: addrtable names=%r unknown (only 'ascii')"
                    % (lineno, opt["names"]))
            cf.addr_tables.append(AddrTable(
                start, opt["end"], opt["count"], opt["stride"],
                opt["entryoff"], opt["terminator"], opt["label"], opt["names"]))

        else:
            raise ControlError("line %d: unknown directive %r" % (lineno, op))

    return cf


def load(path):
    base_dir = os.path.dirname(os.path.abspath(path))
    with open(path, "r") as f:
        return parse(f.read(), base_dir=base_dir)
