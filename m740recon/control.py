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
import re
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

# A hardware or flag signal as written in the control file (`pin` / `bit`).
# `addr` is an int or an unresolved name (an SFR or a label); it is resolved
# against the symbol table once the device is known (see signals.py).  `lo`
# and `hi` are the bit range (equal for a single bit).  `where` locates the
# directive for error messages.
# `space` names a second address space (None = the program space) and
# `access` limits the signal to reads or writes of its bits (None = both), so
# a register whose bits mean one thing when read and another when written can
# carry one signal of each.
SignalDecl = namedtuple(
    "SignalDecl",
    "kind addr lo hi name direction active high low source description where "
    "space access", defaults=(None, None))

# `pointer ADDR TARGET [space=NAME]`: the zero-page pair at ADDR holds the
# fixed address TARGET (in space NAME), so indirect accesses through it can be
# attributed.  `addr` may be an unresolved label name.
PointerDecl = namedtuple("PointerDecl", "addr target space comment where")

# `group NAME SIGNAL...`: related signals reported together.
GroupDecl = namedtuple("GroupDecl", "name members description where")

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SIGNAL_SOURCES = ("schematic", "firmware", "datasheet", "guess")
_PIN_DIRECTIONS = ("in", "out", "bidir")

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
        self.signals = []               # list of SignalDecl (pin / bit)
        self.groups = []                # list of GroupDecl
        self.pointers = []              # list of PointerDecl

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
        return resolve_addr_tables(self.addr_tables, image)

    @property
    def symbols(self):
        """User (non-weak) Symbols to merge into the SymbolTable."""
        return list(self._symbols_by_addr.values())

    def _add_symbol(self, addr, name, comment=""):
        # first writer wins, matching the wrapper's setdefault behavior
        if addr not in self._symbols_by_addr:
            self._symbols_by_addr[addr] = Symbol(addr, name, comment, weak=False)


def resolve_addr_tables(tables, image, used_names=None):
    """Expand AddrTable records against `image` (see ControlFile.resolve_tables).
    `used_names` (a set) keeps names unique across several calls."""
    pointer_addrs = []
    data_addrs = []
    syms = {}                       # target addr -> Symbol (first writer wins)
    used_names = set() if used_names is None else used_names
    for tbl in tables:
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


class _Token(str):
    """A control-file token.  `quoted` is True when the whole token was one
    quoted string, so it is text (a description or comment), never an
    option, a direction or a name."""
    quoted = False


def _tokenize(raw):
    """Split one control-file line the way shlex.split(posix, comments)
    does, but remember which tokens were wholly quoted.  Raises ValueError
    on an unterminated quote."""
    tokens = []
    i, n = 0, len(raw)
    while i < n:
        c = raw[i]
        if c.isspace():
            i += 1
            continue
        if c == "#":
            break
        chars = []
        segments = 0
        whole_quote = c in "\"'"
        while i < n and not raw[i].isspace():
            c = raw[i]
            if c == "#":
                i = n                         # comment ends token and line
                break
            if c in "\"'":
                quote = c
                i += 1
                closed = False
                while i < n:
                    c = raw[i]
                    if c == quote:
                        closed = True
                        i += 1
                        break
                    if (quote == '"' and c == "\\" and i + 1 < n and
                            raw[i + 1] in '"\\'):
                        chars.append(raw[i + 1])
                        i += 2
                        continue
                    chars.append(c)
                    i += 1
                if not closed:
                    raise ValueError("No closing quotation")
                segments += 1
                continue
            if c == "\\" and i + 1 < n:
                chars.append(raw[i + 1])
                i += 2
                segments += 2                 # not a single quoted string
                continue
            chars.append(c)
            i += 1
            segments += 2
        tok = _Token("".join(chars))
        tok.quoted = whole_quote and segments == 1
        tokens.append(tok)
    return tokens


def _parse_loc(token, where):
    """Parse ADDR.BIT or ADDR.LO-HI (either order).  ADDR is a number or a
    name; returns (addr, lo, hi) with addr an int or a str."""
    if "." not in token:
        raise ControlError("%s: signal location %r must be ADDR.BIT or "
                           "ADDR.LO-HI" % (where, token))
    addr_s, bits_s = token.rsplit(".", 1)
    if not addr_s:
        raise ControlError("%s: signal location %r has no address"
                           % (where, token))
    try:
        addr = int(addr_s, 0)
    except ValueError:
        if not _IDENT_RE.match(addr_s):
            raise ControlError("%s: bad signal address %r" % (where, addr_s))
        addr = addr_s
    else:
        if not 0 <= addr <= 0xFFFF:
            raise ControlError("%s: signal address 0x%x out of range"
                               % (where, addr))
    parts = bits_s.split("-")
    if len(parts) > 2 or not all(p.isdigit() for p in parts):
        raise ControlError("%s: bad bit %r (use 0-7 or LO-HI)" % (where, bits_s))
    nums = [int(p) for p in parts]
    if any(n > 7 for n in nums):
        raise ControlError("%s: bit number out of range 0-7 in %r"
                           % (where, token))
    lo, hi = min(nums), max(nums)
    return addr, lo, hi


def _parse_signal(op, args, where):
    """Parse the arguments of a `pin` or `bit` directive."""
    usage = ("pin LOC NAME [in|out|bidir] [active=high|low] [high=TEXT] "
             "[low=TEXT] [source=...] [\"description\"]" if op == "pin" else
             "bit LOC NAME [high=TEXT] [low=TEXT] [source=...] "
             "[space=NAME] [access=read|write] [\"description\"]")
    if len(args) < 2:
        raise ControlError("%s: %s" % (where, usage))
    addr, lo, hi = _parse_loc(args[0], where)
    name = args[1]
    if not _IDENT_RE.match(name):
        raise ControlError("%s: bad signal name %r" % (where, name))
    opts = {"active": None, "high": None, "low": None, "source": None,
            "space": None, "access": None}
    direction = None
    description = None
    for tok in args[2:]:
        if getattr(tok, "quoted", False):
            if description is not None:
                raise ControlError("%s: unexpected %r (only one description "
                                   "is allowed)" % (where, str(tok)))
            description = str(tok)
            continue
        key, eq, val = tok.partition("=")
        if eq and _IDENT_RE.match(key):
            key = key.lower()
            if op == "pin":
                allowed = ("active", "high", "low", "source")
            else:
                allowed = ("high", "low", "source", "space", "access")
            if key not in allowed:
                raise ControlError("%s: unknown %s option %r" % (where, op, key))
            if opts[key] is not None:
                raise ControlError("%s: option %r given twice" % (where, key))
            opts[key] = val
        elif tok.lower() in _PIN_DIRECTIONS and description is None:
            if op != "pin":
                raise ControlError("%s: bit has no direction (use pin for a "
                                   "port pin)" % where)
            if direction is not None:
                raise ControlError("%s: direction given twice (%s, %s)"
                                   % (where, direction, tok.lower()))
            direction = tok.lower()
        elif description is None:
            description = tok
        else:
            raise ControlError("%s: unexpected %r (quote a description that "
                               "contains spaces)" % (where, tok))
    if opts["active"] is not None:
        opts["active"] = opts["active"].lower()
        if opts["active"] not in ("high", "low"):
            raise ControlError("%s: active= must be high or low" % where)
    if opts["source"] is not None:
        opts["source"] = opts["source"].lower()
        if opts["source"] not in _SIGNAL_SOURCES:
            raise ControlError("%s: source= must be one of %s"
                               % (where, "/".join(_SIGNAL_SOURCES)))
    if opts["access"] is not None:
        opts["access"] = opts["access"].lower()
        if opts["access"] not in ("read", "write"):
            raise ControlError("%s: access= must be read or write" % where)
    if opts["space"] is not None and not _IDENT_RE.match(opts["space"]):
        raise ControlError("%s: bad space name %r" % (where, opts["space"]))
    return SignalDecl(op, addr, lo, hi, name, direction, opts["active"],
                      opts["high"], opts["low"], opts["source"],
                      description or "", where, opts["space"], opts["access"])


def _parse_pointer(args, where):
    """pointer ADDR TARGET [space=NAME] ["comment"]"""
    if not 2 <= len(args) <= 4:
        raise ControlError("%s: pointer ADDR TARGET [space=NAME] "
                           "[\"comment\"]" % where)
    try:
        addr = int(args[0], 0)
    except ValueError:
        if not _IDENT_RE.match(args[0]):
            raise ControlError("%s: bad pointer address %r" % (where, args[0]))
        addr = args[0]
    else:
        if not 0 <= addr <= 0xFE:
            raise ControlError("%s: pointer 0x%x must be a zero-page address "
                               "(0x00-0xfe)" % (where, addr))
    try:
        target = int(args[1], 0)
    except ValueError:
        raise ControlError("%s: bad pointer target %r" % (where, args[1]))
    if not 0 <= target <= 0xFFFF:
        raise ControlError("%s: pointer target 0x%x out of range"
                           % (where, target))
    space = None
    comment = ""
    for tok in args[2:]:
        if getattr(tok, "quoted", False):
            if comment:
                raise ControlError("%s: unexpected %r" % (where, str(tok)))
            comment = str(tok)
            continue
        key, eq, val = tok.partition("=")
        if eq and key.lower() == "space":
            if space is not None:
                raise ControlError("%s: option 'space' given twice" % where)
            if not _IDENT_RE.match(val):
                raise ControlError("%s: bad space name %r" % (where, val))
            space = val
        elif eq and _IDENT_RE.match(key):
            raise ControlError("%s: unknown pointer option %r" % (where, key))
        elif not comment:
            comment = tok
        else:
            raise ControlError("%s: unexpected %r" % (where, tok))
    return PointerDecl(addr, target, space, comment, where)


def _parse_int(token, lineno):
    try:
        return int(token, 0)
    except ValueError:
        raise ControlError("line %d: bad address %r" % (lineno, token))


def parse(text, base_dir=None):
    """Parse control-file text and return a ControlFile."""
    cf = ControlFile(base_dir=base_dir)
    _parse_into(cf, text, base_dir, None, ())
    return cf


def _parse_into(cf, text, base_dir, source, stack):
    """Parse `text` into `cf`.  `source` names the file for error messages
    (None for the top-level text, whose messages stay "line N: ...");
    `stack` holds the absolute paths of the files currently being included,
    for cycle detection."""
    for lineno, raw in enumerate(text.splitlines(), 1):
        try:
            _parse_line(cf, raw, lineno, base_dir, source, stack)
        except ControlError as e:
            if source is None or getattr(e, "located", False):
                raise
            err = ControlError("%s: %s" % (source, e))
            err.located = True
            raise err


def _resolve_path(path, base_dir):
    if os.path.isabs(path):
        return path
    return os.path.join(base_dir or ".", path)


def _parse_line(cf, raw, lineno, base_dir, source, stack):
    if True:
        try:
            tokens = _tokenize(raw)
        except ValueError as e:
            raise ControlError("line %d: %s" % (lineno, e))
        if not tokens:
            return
        op = tokens[0].lower()
        args = tokens[1:]

        if op == "include":
            if len(args) != 1:
                raise ControlError("line %d: include PATH" % lineno)
            path = os.path.abspath(_resolve_path(args[0], base_dir))
            # compare real paths, so a file reached again through a link is
            # still a cycle
            key = os.path.normcase(os.path.realpath(path))
            if key in [os.path.normcase(os.path.realpath(p)) for p in stack]:
                chain = " -> ".join(os.path.basename(p) for p in stack + (path,))
                raise ControlError("line %d: include cycle: %s" % (lineno, chain))
            try:
                with open(path, "r") as f:
                    sub = f.read()
            except OSError as e:
                raise ControlError("line %d: include %s: %s"
                                   % (lineno, args[0], e.strerror or e))
            _parse_into(cf, sub, os.path.dirname(path), path, stack + (path,))

        elif op in ("pin", "bit"):
            where = "line %d" % lineno
            if source is not None:
                where = "%s: line %d" % (source, lineno)
            try:
                cf.signals.append(_parse_signal(op, args, where))
            except ControlError as e:
                e.located = True
                raise

        elif op == "pointer":
            where = "line %d" % lineno
            if source is not None:
                where = "%s: line %d" % (source, lineno)
            try:
                cf.pointers.append(_parse_pointer(args, where))
            except ControlError as e:
                e.located = True
                raise

        elif op == "group":
            where = "line %d" % lineno
            if source is not None:
                where = "%s: line %d" % (source, lineno)
            if len(args) < 2:
                err = ControlError("%s: group NAME SIGNAL [SIGNAL...] "
                                   "[\"description\"]" % where)
                err.located = True
                raise err
            members = list(args[1:])
            description = ""
            # a quoted final token is the description, even a one-word one
            if getattr(members[-1], "quoted", False) and len(members) > 1:
                description = str(members.pop())
            for m in [args[0]] + members:
                if not _IDENT_RE.match(m):
                    err = ControlError("%s: bad name %r in group" % (where, m))
                    err.located = True
                    raise err
            cf.groups.append(GroupDecl(args[0], members, description, where))

        elif op == "device":
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
                if source is not None:
                    path = _resolve_path(path, base_dir)
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


def load(path):
    """Parse the control file at `path`.  Every error names the file and
    line it comes from."""
    path = os.path.abspath(path)
    base_dir = os.path.dirname(path)
    with open(path, "r") as f:
        text = f.read()
    cf = ControlFile(base_dir=base_dir)
    _parse_into(cf, text, base_dir, path, (path,))
    return cf
