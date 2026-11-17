"""Named hardware and flag signals.

A signal names one bit, or a contiguous range of bits, at an address: a port
pin, an SFR control bit, a RAM flag, or a bit of an external register.  The
control file declares them with `pin` and `bit` (see control.py); this module
resolves those declarations against the symbol table and indexes them by
(address, bit) for the access classifier.

Signals are descriptive only.  Their names never become assembler symbols, so
they cannot affect the listing's reassembly.

A signal may live in a named second address space (`space=`), reached only
through declared pointers, and may be limited to reads or to writes of its
bits (`access=`), so one register bit can carry a read meaning and a write
meaning.  Lookups without a space see only the program space.
"""

from collections import namedtuple

from m740recon.control import ControlError


class Signal(object):
    __slots__ = ("name", "kind", "address", "lo", "hi", "direction", "active",
                 "high", "low", "source", "description", "group", "space",
                 "access", "where", "loc")

    def __init__(self, decl, address, loc):
        self.name = decl.name
        self.kind = decl.kind               # 'pin' or 'bit'
        self.address = address
        self.lo = decl.lo
        self.hi = decl.hi
        self.direction = decl.direction     # 'in' / 'out' / 'bidir' / None
        self.active = decl.active           # 'high' / 'low' / None
        self.high = decl.high               # text for level 1, or None
        self.low = decl.low                 # text for level 0, or None
        self.source = decl.source
        self.description = decl.description
        self.group = None
        self.space = decl.space             # None = program space
        self.access = decl.access           # None / 'read' / 'write'
        self.where = decl.where
        self.loc = loc                      # display form, e.g. "P0.6"

    @property
    def width(self):
        return self.hi - self.lo + 1

    @property
    def is_field(self):
        return self.hi != self.lo

    @property
    def mask(self):
        return ((1 << self.width) - 1) << self.lo

    @property
    def display_name(self):
        return self.name + ("?" if self.source == "guess" else "")

    def level_text(self, level):
        """Meaning of a single-bit level from the declaration, or None.
        Prefers the high=/low= text, then active=."""
        text = self.high if level else self.low
        if text:
            return text
        if self.active is not None:
            asserted = (level == 1) == (self.active == "high")
            return "asserted" if asserted else "not asserted"
        return None

    def serves(self, op):
        """True if this signal applies to an access of kind `op` ('read',
        'write', or None for either)."""
        return op is None or self.access is None or self.access == op

    def __repr__(self):
        return "Signal(%s @ 0x%04x.%d-%d)" % (self.name, self.address,
                                              self.lo, self.hi)


# A declared pointer: the zero-page pair at `address` holds `target`.
Pointer = namedtuple("Pointer", "address target space comment where loc")


class SignalMap(object):
    """All signals of a control file, resolved and indexed."""

    def __init__(self, signals=(), groups=None, pointers=None):
        self.signals = list(signals)          # declaration order
        self.groups = groups or []            # list of (name, [Signal], description)
        self.pointers = pointers or {}        # zero-page address -> Pointer
        self.by_name = {}
        self.by_bit = {}                      # (space, address, bit) -> [Signal]
        self.by_address = {}                  # (space, address) -> [Signal]
        for sig in self.signals:
            self.by_name[sig.name] = sig
            self.by_address.setdefault((sig.space, sig.address), []).append(sig)
            for bit in range(sig.lo, sig.hi + 1):
                self.by_bit.setdefault((sig.space, sig.address, bit),
                                       []).append(sig)

    def __len__(self):
        return len(self.signals)

    def __bool__(self):
        return bool(self.signals)

    __nonzero__ = __bool__

    @property
    def active(self):
        """True if anything is declared that the analysis acts on: signals
        or pointers.  Truth (bool) means signals only, which is what the
        signal reports, discovery and lint key on."""
        return bool(self.signals or self.pointers)

    def at(self, address, bit, space=None, op=None):
        """The signal on `bit` of `address` (in `space`) that applies to an
        access of kind `op`, or None."""
        for sig in self.by_bit.get((space, address, bit), ()):
            if sig.serves(op):
                return sig
        return None

    def on_address(self, address, space=None, op=None):
        return [s for s in self.by_address.get((space, address), ())
                if s.serves(op)]

    def in_mask(self, address, mask, space=None, op=None):
        """Signals at `address` with at least one bit inside `mask`."""
        return [s for s in self.on_address(address, space, op)
                if s.mask & mask]


def _accesses(sig):
    return {"read", "write"} if sig.access is None else {sig.access}


def _resolve_address(decl, names):
    if isinstance(decl.addr, int):
        return decl.addr, "0x%02x" % decl.addr if decl.addr < 0x100 \
            else "0x%04x" % decl.addr
    if decl.addr in names:
        found = decl.addr
    else:
        folded = [n for n in names if n.lower() == decl.addr.lower()]
        if len(folded) != 1:
            raise ControlError("%s: unknown register or label %r in signal %s"
                               % (decl.where, decl.addr, decl.name))
        found = folded[0]
    addr = names[found]
    if not 0 <= addr <= 0xFFFF:
        raise ControlError("%s: label %r in signal %s is at 0x%x, out of "
                           "range" % (decl.where, found, decl.name, addr))
    return addr, found


def _resolve_pointer(decl, names):
    if isinstance(decl.addr, int):
        return decl.addr, "0x%02x" % decl.addr
    if decl.addr in names and 0 <= names[decl.addr] <= 0xFE:
        return names[decl.addr], decl.addr
    raise ControlError("%s: pointer %r is not a known zero-page label"
                       % (decl.where, decl.addr))


def build(decls, group_decls, symbols, pointer_decls=()):
    """Resolve SignalDecl / GroupDecl lists and return a SignalMap.

    `symbols` is an iterable of Symbol: the device SFR symbols plus the control
    file's own labels.  Automatic (weak) names are ignored, so a location such
    as `mem_0052.7` must be written as a number.  Raises ControlError on any
    inconsistency."""
    names = {}
    for sym in symbols:
        if not sym.weak:
            names.setdefault(sym.name, sym.address)

    signals = []
    by_name = {}
    owner = {}                       # (space, address, bit) -> [Signal]
    for decl in decls:
        if decl.name in by_name:
            raise ControlError("%s: signal %s already defined at %s"
                               % (decl.where, decl.name,
                                  by_name[decl.name].where))
        address, base = _resolve_address(decl, names)
        if decl.space is not None:
            base = "%s:%s" % (decl.space, base)
        if decl.lo == decl.hi:
            loc = "%s.%d" % (base, decl.lo)
        else:
            loc = "%s.%d-%d" % (base, decl.lo, decl.hi)
        sig = Signal(decl, address, loc)
        for bit in range(sig.lo, sig.hi + 1):
            key = (sig.space, address, bit)
            for other in owner.get(key, ()):
                if _accesses(other) & _accesses(sig):
                    raise ControlError(
                        "%s: signal %s overlaps %s (%s) on bit %d of 0x%04x"
                        % (decl.where, sig.name, other.name, other.where,
                           bit, address))
            owner.setdefault(key, []).append(sig)
        by_name[sig.name] = sig
        signals.append(sig)

    groups = []
    seen_groups = set()
    for g in group_decls:
        if g.name in seen_groups:
            raise ControlError("%s: group %s already defined" % (g.where, g.name))
        seen_groups.add(g.name)
        members = []
        for m in g.members:
            sig = by_name.get(m)
            if sig is None:
                raise ControlError("%s: group %s names unknown signal %s"
                                   % (g.where, g.name, m))
            if sig.group is not None and sig.group != g.name:
                raise ControlError("%s: signal %s is already in group %s"
                                   % (g.where, m, sig.group))
            sig.group = g.name
            members.append(sig)
        groups.append((g.name, members, g.description))

    pointers = {}
    for p in pointer_decls:
        zp, base = _resolve_pointer(p, names)
        if zp in pointers:
            raise ControlError("%s: pointer at 0x%02x already declared at %s"
                               % (p.where, zp, pointers[zp].where))
        loc = "%s0x%04x" % (p.space + ":" if p.space else "", p.target)
        pointers[zp] = Pointer(zp, p.target, p.space, p.comment, p.where, loc)
    return SignalMap(signals, groups, pointers)
