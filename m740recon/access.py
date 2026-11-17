"""Classify instructions into accesses of named signals.

This is the single place that turns decoded instructions into hardware facts.
The listing annotations, the signal report, the JSON model and the lint all
consume the Access records produced here.

Only provable facts are recorded.  A bit instruction names its bit in the
opcode, so its accesses are `exact`.  Facts that need value tracking are
`derived`.  Anything else is left unannotated.
"""

from collections import namedtuple

from m740recon.tables import AddressModes

# address    instruction address
# signal     the Signal accessed
# kind       'test' | 'read' | 'set' | 'clear' | 'write' | 'toggle'
#            | 'direction' | 'function'  (a write to the port's direction or
#            function register that configures this signal's pin)
# level      for set/clear/write: the value written to the signal (an int,
#            the field value for a multi-bit signal); for test: the level on
#            which the branch is taken; for direction: 1 output, 0 input;
#            for function: 1 special function, 0 port; None when unknown
# bit        for a single bit of a multi-bit field, its index within the
#            field; otherwise None
# confidence 'exact' | 'derived'
# text       rendered comment fragment
# scope      'bit'      the instruction singles out this signal's bit
#                       (seb/clb/bbs/bbc, including on A after a load)
#            'mask'     a mask or read-modify-write selects this signal
#            'register' a whole-register read or write
Access = namedtuple("Access",
                    "address signal kind level bit confidence text scope")

# 740 bit instructions: bit number in the top three opcode bits, operation in
# the low five.
_BIT_OPS = {
    0x07: ("test", 1),   # bbs N,zp,rel   branch if bit set
    0x17: ("test", 0),   # bbc N,zp,rel   branch if bit clear
    0x0F: ("set", 1),    # seb N,zp
    0x1F: ("clear", 0),  # clb N,zp
}
_BIT_OPS_ACC = frozenset((0x03, 0x13, 0x0B, 0x1B))   # same ops on A


def bit_operation(opcode):
    """(kind, level, bit, on_accumulator) for a 740 bit instruction, else None."""
    low = opcode & 0x1F
    bit = opcode >> 5
    if low in _BIT_OPS:
        kind, level = _BIT_OPS[low]
        return kind, level, bit, False
    if low in _BIT_OPS_ACC:
        kind = {0x03: "test", 0x13: "test", 0x0B: "set", 0x1B: "clear"}[low]
        level = 1 if low in (0x03, 0x0B) else 0
        return kind, level, bit, True
    return None


def _subject(sig, bit):
    if bit is None:
        return sig.display_name
    return "%s[%d]" % (sig.display_name, bit)


def _level_word(sig, bit, level):
    """How a single-bit level reads for this signal, or None for raw."""
    if bit is not None:            # a bit inside a field has no own meaning
        return None
    return sig.level_text(level)


def render(sig, kind, level, bit=None):
    """Comment text for one access."""
    subject = _subject(sig, bit)
    if kind == "direction":
        word = {1: "output", 0: "input"}.get(level, "direction unknown")
        return "%s: %s" % (subject, word)
    if kind == "function":
        word = {1: "special function", 0: "port"}.get(level,
                                                       "function unknown")
        return "%s: %s" % (subject, word)
    if kind == "test":
        word = _level_word(sig, bit, level)
        if word is None:
            word = "set" if level else "clear"
        return "%s: branch if %s" % (subject, word)
    if kind in ("set", "clear"):
        text = "%s = %d" % (subject, level)
        word = _level_word(sig, bit, level)
        if word:
            text += " (%s)" % word
        return text
    if kind == "write":
        if level is None:
            return "writes %s (value unknown)" % subject
        if sig.is_field and bit is None:
            return "%s = %d" % (subject, level)
        text = "%s = %d" % (subject, level)
        word = _level_word(sig, bit, level)
        if word:
            text += " (%s)" % word
        return text
    if kind == "read":
        return "reads %s" % subject
    if kind == "toggle":
        return "toggles %s" % subject
    raise ValueError(kind)


def port_latches(ports):
    """{input-latch address: data address} for ports that have an input
    latch: a read of the latch is a read of the port's pins."""
    return {m["input"]: m["data"] for m in (ports or {}).values()
            if m.get("input") is not None}


def port_shadows(ports):
    """{register address: (data address, 'direction'|'function', output
    value)} for the direction and function registers of `ports` (a device's
    port metadata, or None)."""
    out = {}
    for meta in (ports or {}).values():
        if meta.get("direction") is not None:
            out[meta["direction"]] = (meta["data"], "direction",
                                      meta.get("output", 1))
        if meta.get("function") is not None:
            out[meta["function"]] = (meta["data"], "function", 1)
    return out


def config_level(kind, bit_value, output):
    """Meaning of a written direction/function bit: 1 output (or special
    function), 0 input (or port), None if unknown."""
    if bit_value not in (0, 1):
        return None
    if kind == "direction":
        return 1 if bit_value == output else 0
    return bit_value


def rmw_reads(address, smap, loc, confidence, latches=None):
    """A read-modify-write instruction at `address` also reads the whole
    register at `loc` (space, address).  Signals declared access=read mean
    something different from what is written there, so their read is
    recorded; signals serving both directions are covered by the write.
    Reading a port's input latch reads that port's pins."""
    space, reg = loc
    if space is None and reg in (latches or {}):
        reg = latches[reg]
    return [Access(address, sig, "read", None, None, confidence,
                   render(sig, "read", None), "register")
            for sig in smap.on_address(reg, space, "read")
            if sig.access == "read"]


def _bit_accesses(address, inst, smap, shadows=None, latches=None):
    op = bit_operation(inst.opcode)
    if op is None:
        return []
    kind, level, bit, on_acc = op
    if on_acc:
        return []            # needs value tracking (see regflow.py)
    out = []
    zp = inst.zp_addr
    if kind == "test" and zp in (latches or {}):
        zp = latches[zp]                 # testing the latch tests the pin
    sig = smap.at(zp, bit, None, "read" if kind == "test" else "write")
    if sig is not None:
        field_bit = (bit - sig.lo) if sig.is_field else None
        out.append(Access(address, sig, kind, level, field_bit, "exact",
                          render(sig, kind, level, field_bit), "bit"))
    if kind in ("set", "clear"):
        out.extend(rmw_reads(address, smap, (None, inst.zp_addr), "exact",
                             latches))
    shadow = (shadows or {}).get(inst.zp_addr)
    if shadow is not None and kind in ("set", "clear"):
        data, ckind, output = shadow
        psig = smap.at(data, bit)
        if psig is not None:
            lvl = config_level(ckind, level, output)
            fb = (bit - psig.lo) if psig.is_field else None
            out.append(Access(address, psig, ckind, lvl, fb, "exact",
                              render(psig, ckind, lvl, fb), "bit"))
    return out


def classify(memory, smap, ports=None, spaces=None, pointer_sites=None):
    """Return the list of Access records for every decoded instruction, in
    address order: bit instructions (exact) plus whole-register and masked
    accesses found by the register-flow pass (see regflow.py).  With the
    device's `ports` metadata, writes to direction and function registers
    are also attributed to the signals on the pins they configure.  With
    `spaces` metadata, accesses through pointers into a second address space
    are checked against that space's enable bit.  If `pointer_sites` is a
    list, every indirect access through a declared pointer is appended to it
    (see regflow.PointerSite)."""
    accesses = []
    if not smap.active:
        return accesses
    shadows = port_shadows(ports)
    latches = port_latches(ports)
    for address, inst in memory.iter_instructions():
        if inst.addr_mode in (AddressModes.ZeroPageBit,
                              AddressModes.ZeroPageBitRelative):
            accesses.extend(_bit_accesses(address, inst, smap, shadows,
                                          latches))
    import sys
    from m740recon import regflow
    accesses.extend(regflow.register_accesses(
        memory, smap, sys.modules[__name__], shadows, spaces, pointer_sites,
        latches))
    accesses.sort(key=lambda a: a.address)     # stable: keeps per-site order
    return accesses


def pointer_tag(ps):
    """Where an indirect access through a declared pointer goes, as shown in
    brackets before its annotation: '[dme:0x4002]', '[dme:0x4002|0x4003
    Y=2,3]', '[dme:0x4000+Y, Y unknown]', '[0x4000, dme off: program
    space]'.  A trailing '?' marks a space whose enable bit is not proven
    set at that point."""
    ptr = ps.pointer
    space = ptr.space
    if ps.state in ("off", "mode"):
        why = "%s off" % space if ps.state == "off" else \
            "mode does not reach %s" % space
        where = "|".join("0x%04x" % a for _, a in ps.locs) if ps.locs else \
            "0x%04x+index" % ptr.target
        return "%s, %s: program space" % (where, why)
    prefix = space + ":" if space and ps.state != "program" else ""
    mark = "?" if ps.state == "assumed" else ""
    if ps.locs is None:
        return "%s0x%04x+Y%s, Y unknown" % (prefix, ptr.target, mark)
    text = prefix + "|".join("0x%04x" % a for _, a in ps.locs) + mark
    if len(ps.locs) > 1:
        text += " %s=%s" % (ps.register, ",".join(str(i) for i in ps.index))
    return text


def listing_annotations(memory, accesses, pointer_sites=()):
    """Everything the listing shows for signals: the per-instruction access
    annotations, the destination of every indirect access through a
    declared pointer, and, at each call to a summarized leaf routine, the
    routine's effects (see effects.py)."""
    from m740recon import effects
    notes = annotations(accesses)
    for ps in pointer_sites:
        body = notes.get(ps.site) or ("reads" if ps.op == "read" else "writes")
        notes[ps.site] = "[%s] %s" % (pointer_tag(ps), body)
    summaries = effects.leaf_summaries(memory, accesses)
    for site, text in effects.call_site_annotations(memory, summaries).items():
        notes[site] = notes[site] + "; " + text if site in notes else text
    return notes


def annotations(accesses):
    """Listing annotations: instruction address -> comment text.  Several
    plain reads at one instruction collapse to "reads A, B"; several writes
    of unknown value to "writes A, B (value unknown)"."""
    by_addr = {}
    for acc in accesses:
        by_addr.setdefault(acc.address, []).append(acc)
    out = {}
    for addr, accs in by_addr.items():
        parts = []
        reads = [a for a in accs if a.kind == "read"]
        unknown = [a for a in accs if a.kind == "write" and a.level is None]
        config = [a for a in accs if a.kind in ("direction", "function")]
        rest = [a for a in accs
                if a not in reads and a not in unknown and a not in config]
        for kind, words in (("direction", {1: "outputs", 0: "inputs",
                                           None: "direction unknown"}),
                            ("function", {1: "special function",
                                          0: "port function",
                                          None: "function unknown"})):
            these = [a for a in config if a.kind == kind]
            for lvl in (1, 0, None):
                names = [_subject(a.signal, a.bit) for a in these
                         if a.level == lvl]
                if names:
                    parts.append("%s %s" % (words[lvl], ", ".join(names)))
        if reads:
            parts.append("reads " + ", ".join(
                _subject(a.signal, a.bit) for a in reads))
        if unknown:
            parts.append("writes %s (value unknown)" % ", ".join(
                _subject(a.signal, a.bit) for a in unknown))
        parts.extend(a.text for a in rest)
        out[addr] = "; ".join(parts)
    return out
