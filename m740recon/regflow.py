"""Whole-register, masked and pointer-indirect signal accesses.

A block-local pass over the decoded code that attributes non-bit
instructions to declared signals:

    ldm #imm,X                  write, exact
    lda #imm ... sta X          write, derived (also stx / sty)
    lda X ... ora|and|eor #m
          ... sta X             set / clear / toggle of the bits m touches
    lda X ... and #m            read of the signals under m
    lda X ... bbs|bbc N,a       test of the signal on bit N
    lda X (no refinement)       read of every signal at X
    cmp|bit|tst|... X           read of every signal at X
    sta X (value unknown)       write, value unknown
    com X                       toggle;  inc|dec|asl|... X: write, unknown

X is a location the instruction provably reaches: a zero-page or absolute
operand, an indexed operand whose index register is known, or the location
an indirect access reaches through a declared `pointer` (`[zp],y` with Y
known, `[zp,x]` with X known).  Such a location may be in a named second
address space; when the device describes how that space is enabled (see
devices.py `spaces`), the pass tracks the enable bit and attributes an
access to the space only while it is on; an access made while it is
provably off goes to the program space instead, and one made while its
state is unknown is marked `assumed`.  A write the pass cannot place (an
unknown index, an unresolved indirect store) may hit anything, so it makes
the enable state unknown and forgets what A was known to hold relative to
memory.

A read-modify-write sequence is recognized only on a location whose
signals have one meaning for reads and writes alike: on a register declared
with separate read and write signals (`access=`), what is read back is not
what was written, so a load and a store are reported separately.

Soundness follows the tracer's value tracking: state is carried only along
straight-line fallthrough and is reset at every block leader (jump / call
target, entry point) and after every call.  One exception: a jump target
that is not a call target, entry point, vector or computed-jump target, and
whose every incoming edge is static, starts with what all of those edges
agree on for the index register Y (as a set of possible values) and the T
flag.  This resolves the common "set Y, branch to a shared indirect access"
idiom.  Values are proven constants or proven copies of a location's bits;
anything else is unknown and reported as such, never guessed.

The 740 T flag redirects A-operations to the zero-page byte at X.  The pass
assumes T = 0 on entry to a routine and that a called routine returns with
T as it found it; `set` and `clt` set it, `php`/`plp` restore it when they
pair up in the same block, and an unpaired `plp` makes it unknown.  While T
is set or unknown only facts that hold either way are recorded.
"""

from collections import namedtuple

from m740recon.tables import AddressModes, FlowTypes

# A tracked accumulator is a list of 8 bit states (bit 0 first):
#   0 / 1   known constant bit
#   'o'     the original bit of the location A was loaded from
#   'i'     that bit inverted
#   None    unknown
# together with the location it was loaded from (None for no relation).
#
# A location is (space, address); space None is the program space.

_PRESERVE_A = frozenset((
    "clc", "sec", "cli", "sei", "cld", "sed", "clv", "nop",
    "cmp", "cpx", "cpy", "bit", "tst",
    "sta", "stx", "sty", "pha", "php", "plp",
    "seb", "clb", "bbs", "bbc", "ldm",
    "inc", "dec", "inx", "iny", "dex", "dey", "ldx", "ldy",
    "bcc", "bcs", "beq", "bmi", "bne", "bpl", "bvc", "bvs", "bra",
    "jmp", "rts", "rti", "brk", "stp", "wit", "fst", "slw",
))
_RMW_UNKNOWN = frozenset(("inc", "dec", "asl", "lsr", "rol", "ror", "rrf"))
_READS_OPERAND = frozenset(("lda", "ldx", "ldy", "and", "ora", "eor", "adc",
                            "sbc", "cmp", "cpx", "cpy", "bit", "tst",
                            "mul", "div"))
_STORES = frozenset(("sta", "stx", "sty"))
# A-operations that write M(X) instead of A while T is set
_T_WRITES = frozenset(("lda", "and", "ora", "eor", "adc", "sbc"))
# A-operations that read M(X) instead of A while T is set
_T_READS = frozenset(("and", "ora", "eor", "adc", "sbc", "cmp"))
# instructions that leave X and Y unchanged (whether or not T redirects them)
_KEEP_XY = frozenset((
    "lda", "and", "ora", "eor", "adc", "sbc", "cmp", "cpx", "cpy", "bit",
    "tst", "sta", "stx", "sty", "ldm", "seb", "clb", "bbs", "bbc",
    "inc", "dec", "asl", "lsr", "rol", "ror", "rrf", "com",
    "txa", "tya", "pha", "php", "pla", "plp", "mul", "div",
    "clc", "sec", "cli", "sei", "cld", "sed", "clv", "nop",
    "bcc", "bcs", "beq", "bmi", "bne", "bpl", "bvc", "bvs", "bra",
))
_INDIRECT = (AddressModes.IndirectY, AddressModes.IndirectX)
_NO_OPERAND = (AddressModes.Implied, AddressModes.Accumulator)
_MAX_PASSES = 6

# One indirect access through a declared pointer.
#   pointer   the Pointer
#   op        'read' or 'write'
#   locs      the (space, address) locations it may reach, or None when the
#             index is unknown
#   state     'program' (pointer has no space), 'declared' (space with no
#             device metadata), 'on', 'assumed' (enable state unknown),
#             'off' (space disabled: program space), 'mode' (addressing mode
#             does not reach the space: program space)
#   index     the possible values of the index register, or None
#   register  the index register: 'Y' for [zp],y, 'X' for [zp,x] (where X
#             selects the pointer)
PointerSite = namedtuple("PointerSite",
                         "site pointer op locs state index register")


def _mnemonic(inst):
    return inst.disasm_template.split(" ", 1)[0]


def _direct_loc(inst):
    """The program-space location an instruction reads or writes directly
    (zero page or absolute, unindexed), else None."""
    am = inst.addr_mode
    if am in (AddressModes.ZeroPage, AddressModes.ZeroPageImmediate,
              AddressModes.ZeroPageBit, AddressModes.ZeroPageBitRelative):
        return (None, inst.zp_addr)
    if am == AddressModes.Absolute and inst.flow_type == FlowTypes.Continue:
        return (None, inst.abs_addr)
    return None


def _const(value):
    return [(value >> b) & 1 for b in range(8)]


def _writes_memory(inst, m, t_mode):
    """True if the instruction may store to memory."""
    if m in _STORES or m == "ldm" or m == "com":
        return True
    if m in ("seb", "clb") and inst.addr_mode == AddressModes.ZeroPageBit:
        return True
    if m in _RMW_UNKNOWN and inst.addr_mode not in _NO_OPERAND:
        return True
    return bool(t_mode) and m in _T_WRITES


class _A(object):
    __slots__ = ("src", "bits")

    def __init__(self, src, bits):
        self.src = src
        self.bits = bits

    @property
    def value(self):
        if all(b in (0, 1) for b in self.bits):
            return sum(b << i for i, b in enumerate(self.bits))
        return None

    def detach(self):
        """The location A was loaded from has changed: A keeps its known
        constant bits but no longer mirrors that location."""
        self.src = None
        self.bits = [b if b in (0, 1) else None for b in self.bits]


class _Pending(object):
    """A load of a signal-bearing location into A, awaiting refinement."""
    __slots__ = ("site", "loc", "conf", "mask_site", "mask", "refined",
                 "consumed")

    def __init__(self, site, loc, conf):
        self.site = site
        self.loc = loc
        self.conf = conf
        self.mask_site = None
        self.mask = None
        self.refined = False
        self.consumed = False


class RegisterFlow(object):
    def __init__(self, memory, smap, access_mod, shadows=None, spaces=None,
                 latches=None):
        self.memory = memory
        self.smap = smap
        self.acc = access_mod
        self.shadows = shadows or {}
        self.latches = latches or {}      # input-latch address -> data address
        self.spaces = spaces or {}
        self.out = []
        self.pointer_sites = []
        # space enable bits: (register, bit) -> [(space, on value)]
        self.enables = {}
        for name, meta in self.spaces.items():
            reg, bit, value = meta["enable"]
            self.enables.setdefault((reg, bit), []).append((name, value))
        self.enable_regs = {reg for reg, _ in self.enables}

    # -- emission ---------------------------------------------------------

    def _emit(self, site, sig, kind, level, confidence, bit=None,
              scope="register"):
        self.out.append(self.acc.Access(
            site, sig, kind, level, bit, confidence,
            self.acc.render(sig, kind, level, bit), scope))

    def _read_loc(self, loc):
        """Reads of a port's input latch are reads of that port's pins."""
        if loc[0] is None and loc[1] in self.latches:
            return (None, self.latches[loc[1]])
        return loc

    def _sigs(self, loc, op=None):
        if op == "read":
            loc = self._read_loc(loc)
        return self.smap.on_address(loc[1], loc[0], op)

    def _split(self, loc):
        """True if some bit of the location has a read-only signal and a
        write-only signal, i.e. it means one thing when read and another
        when written, so what is read back is not what was written.  A
        location with only write-only (or only read-only) signals declares
        no different read-back meaning and is treated like memory."""
        readers, writers = set(), set()
        for s in self.smap.on_address(loc[1], loc[0]):
            bits = set(range(s.lo, s.hi + 1))
            if s.access == "read":
                readers |= bits
            elif s.access == "write":
                writers |= bits
        return bool(readers & writers)

    def _read_all(self, site, loc, conf="derived"):
        for sig in self._sigs(loc, "read"):
            self._emit(site, sig, "read", None, conf)

    def _rmw_read(self, site, loc, conf):
        self.out.extend(self.acc.rmw_reads(site, self.smap, loc, conf,
                                           self.latches))

    def _write_unknown(self, site, loc, conf="derived"):
        for sig in self._sigs(loc, "write"):
            if sig.direction != "in":
                self._emit(site, sig, "write", None, conf)

    def _write_bits(self, site, loc, bits, src, conf):
        """Store A (or a constant) with bit states `bits` to `loc`.

        It is a read-modify-write when A was loaded from `loc` and the
        location reads back what is written; then only the bits A changed
        are reported, as set / clear / toggle.  Otherwise every write
        signal is written.  Whole-register writes skip pins declared as
        inputs (writing an input's latch has no effect outside the chip);
        a read-modify-write that changes an input's bit is reported, since
        the code singled that bit out."""
        rmw = src == loc and not self._split(loc)
        scope = "mask" if rmw else "register"
        for sig in self._sigs(loc, "write"):
            if sig.direction == "in" and not rmw:
                continue
            states = bits[sig.lo:sig.hi + 1]
            if all(s in (0, 1) for s in states):
                value = sum(s << i for i, s in enumerate(states))
                if rmw and not sig.is_field:
                    # read-modify-write of one bit: a set or clear
                    kind = "set" if value else "clear"
                    self._emit(site, sig, kind, value, conf, None, scope)
                elif rmw or sig.direction != "in":
                    self._emit(site, sig, "write", value, conf, None, scope)
            elif rmw and all(s == "o" for s in states):
                continue                         # written back unchanged
            elif rmw and all(s == "i" for s in states):
                self._emit(site, sig, "toggle", None, conf, None, scope)
            else:
                self._emit(site, sig, "write", None, conf, None, scope)

    def _config_bits(self, site, reg, bits, confidence):
        """A store to a port's direction or function register: report the
        configuration of every signal on that port's pins."""
        data, ckind, output = self.shadows[reg]
        for sig in self.smap.on_address(data):
            levels = {self.acc.config_level(ckind, b, output)
                      for b in bits[sig.lo:sig.hi + 1]}
            level = levels.pop() if len(levels) == 1 else None
            self._emit(site, sig, ckind, level, confidence)

    # -- state ------------------------------------------------------------

    def _set_y(self, values):
        """values: an int, a set of ints, or None (unknown)."""
        if isinstance(values, int):
            values = frozenset([values])
        self.yset = frozenset(values) if values else None
        self.y = next(iter(self.yset)) if self.yset and \
            len(self.yset) == 1 else None

    def _reset(self, seed=None):
        """Start a block.  `seed` is (Y set, T) agreed by every incoming
        edge of a join point, or None."""
        self._finish()
        self.a = None
        self.x = None
        yseed, tseed = seed if seed is not None else (None, False)
        self._set_y(yseed)
        self.t = tseed
        self.pending = None
        self.space_on = {}
        self.stack = []

    def _finish(self):
        """A is about to be lost: settle the pending load, if any."""
        p = getattr(self, "pending", None)
        if p is None:
            return
        self.pending = None
        if p.consumed:
            return
        if p.mask_site is not None:
            rl = self._read_loc(p.loc)
            under = self.smap.in_mask(rl[1], p.mask, rl[0], "read")
            for sig in under:
                self._emit(p.mask_site, sig, "read", None, p.conf,
                           None, "mask")
            # signals outside the mask do not reach the value
            return
        if not p.refined:
            self._read_all(p.site, p.loc, p.conf)

    def _lose_a(self):
        self._finish()
        self.a = None

    def _memory_written(self, locs):
        """Memory at `locs` (a list, or None when the target is unknown) is
        about to change: update what depends on its old contents."""
        if locs is None:
            self.space_on = {}
            if self.a is not None and self.a.src is not None:
                self.a.detach()
            return
        for loc in locs:
            if self.a is not None and self.a.src == loc:
                self.a.detach()
            if loc[0] is None and loc[1] in self.enable_regs and len(locs) > 1:
                for (reg, _), spaces in self.enables.items():
                    if reg == loc[1]:
                        for space, _ in spaces:
                            self.space_on[space] = None

    # -- enable bits of second address spaces -----------------------------

    def _track_enables(self, inst, m, locs):
        """Update the enable state of second address spaces for a write to
        the single location `locs[0]`."""
        if not self.enables or not locs or len(locs) != 1:
            return
        loc = locs[0]
        if loc[0] is not None or loc[1] not in self.enable_regs:
            return
        reg = loc[1]
        if m in ("seb", "clb") and inst.addr_mode == AddressModes.ZeroPageBit:
            from m740recon.access import bit_operation
            _, level, bit, _ = bit_operation(inst.opcode)
            for space, value in self.enables.get((reg, bit), ()):
                self.space_on[space] = level == value
            return
        for (ereg, bit), spaces in self.enables.items():
            if ereg != reg:
                continue
            if m == "ldm":
                bits = _const(inst.immediate)
            elif m == "sta" and self.a is not None and not self.t:
                bits = self.a.bits
            elif m in ("stx", "sty"):
                val = self.x if m == "stx" else self.y
                bits = _const(val) if val is not None else [None] * 8
            else:
                bits = [None] * 8
            for space, value in spaces:
                b = bits[bit]
                self.space_on[space] = (b == value) if b in (0, 1) else None

    # -- operand locations ------------------------------------------------

    def _pointer(self, site, inst, m):
        """Resolve an indirect access through a declared pointer.
        Returns (locs, confidence) or None when no declared pointer is used;
        locs is None when the index is unknown."""
        am = inst.addr_mode
        if am == AddressModes.IndirectY:
            ptr = self.smap.pointers.get(inst.zp_addr)
            index, register = self.yset, "Y"
            offsets = index
        else:
            if self.x is None:
                return None
            ptr = self.smap.pointers.get((inst.zp_addr + self.x) & 0xFF)
            index, register = frozenset([self.x]), "X"
            offsets = frozenset([0])
        if ptr is None:
            return None
        space = ptr.space
        if space is None:
            state = "program"
        else:
            meta = self.spaces.get(space)
            if meta is None:
                state = "declared"
            elif am not in meta["modes"]:
                state, space = "mode", None
            else:
                on = self.space_on.get(space)
                if on is True:
                    state = "on"
                elif on is False:
                    state, space = "off", None
                else:
                    state = "assumed"
        locs = None
        if offsets is not None:
            locs = sorted({(space, (ptr.target + i) & 0xFFFF)
                           for i in offsets}, key=lambda l: l[1])
        op = "write" if m in _STORES else "read"
        self.pointer_sites.append(PointerSite(
            site, ptr, op, locs, state,
            sorted(index) if index is not None else None, register))
        return locs, ("assumed" if state == "assumed" else "derived")

    def _locations(self, site, inst, m):
        """(locs, confidence) for the instruction's memory operand: a list
        of locations, or None if it has none or it cannot be resolved."""
        loc = _direct_loc(inst)
        if loc is not None:
            return [loc], "derived"
        am = inst.addr_mode
        if am == AddressModes.ZeroPageX and self.x is not None:
            base = (inst.zp_addr + self.x) & 0xFF
            if m == "div":  # 16-bit dividend at zp+X, zp+X+1
                return [(None, base), (None, (base + 1) & 0xFF)], "derived"
            return [(None, base)], "derived"
        if am == AddressModes.ZeroPageY and self.y is not None:
            return [(None, (inst.zp_addr + self.y) & 0xFF)], "derived"
        if am == AddressModes.AbsoluteX and self.x is not None:
            return [(None, (inst.abs_addr + self.x) & 0xFFFF)], "derived"
        if am == AddressModes.AbsoluteY and self.y is not None:
            return [(None, (inst.abs_addr + self.y) & 0xFFFF)], "derived"
        if am in _INDIRECT and (m in _READS_OPERAND or m in _STORES):
            got = self._pointer(site, inst, m)
            if got is not None:
                return got
        return None, "derived"

    # -- walk -------------------------------------------------------------

    def run(self):
        """Iterate to a fixpoint on the state carried into join points,
        then return the accesses of the final pass."""
        eligible = self._joinable_leaders()
        seeds = {}
        for _ in range(len(eligible) + _MAX_PASSES):
            edges = self._pass(seeds)
            new = {}
            for leader in eligible:
                preds = edges.get(leader)
                if not preds:
                    continue
                ysets = [y for y, _ in preds]
                yseed = None
                if all(y is not None for y in ysets):
                    yseed = frozenset().union(*ysets) or None
                ts = {t for _, t in preds}
                tseed = ts.pop() if len(ts) == 1 else None
                if yseed is not None or tseed is not False:
                    new[leader] = (yseed, tseed)
            if new == seeds:
                return self.out
            seeds = new
        # no fixpoint within the bound: drop all carried state, which holds
        # on every path
        self._pass({})
        return self.out

    def _joinable_leaders(self):
        """Jump targets whose predecessors are all static: not call targets,
        entry points, vector / table targets, or computed-jump targets."""
        excluded = set(getattr(self.memory, "computed_targets", ()))
        for vaddr, _ in self.memory.iter_vectors():
            excluded.add(self.memory.read_word(vaddr))
        out = set()
        for addr, _ in self.memory.iter_instructions():
            if (self.memory.is_jump_target(addr) and
                    not self.memory.is_call_target(addr) and
                    not self.memory.is_entry_point(addr) and
                    addr not in excluded):
                out.add(addr)
        return out

    def _pass(self, seeds):
        """One walk over the code.  Emits accesses into fresh lists and
        returns {jump target: [(Y set or None, T) on each incoming edge]}."""
        self.out = []
        self.pointer_sites = []
        edges = {}
        self.pending = None
        self._reset()
        prev_falls_through = False
        prev_end = None
        for address, inst in self.memory.iter_instructions():
            leader = (self.memory.is_jump_target(address) or
                      self.memory.is_call_target(address) or
                      self.memory.is_entry_point(address))
            contiguous = address == prev_end
            if contiguous and prev_falls_through:
                edges.setdefault(address, []).append((self.yset, self.t))
            prev_end = address + len(inst)
            if leader or not prev_falls_through or not contiguous:
                self._reset(seeds.get(address))
            m = _mnemonic(inst)
            t_mode = self.t is not False
            locs, conf = self._locations(address, inst, m)
            if _writes_memory(inst, m, t_mode):
                target = locs
                if t_mode and m in _T_WRITES:
                    target = [(None, self.x)] if self.x is not None else None
                self._track_enables(inst, m, target)
                # a single-location sta, seb or clb updates what A mirrors
                # precisely in _step
                if not (m in ("sta", "seb", "clb") and not t_mode and
                        target and len(target) == 1):
                    self._memory_written(target)
            if m == "set":
                self._lose_a()
                self.t = True
            elif m == "clt":
                self.t = False
            elif m == "php":
                self.stack.append(("P", self.t))
            elif m == "pha":
                self.stack.append(("A",))
            elif m == "plp":
                top = self.stack.pop() if self.stack else None
                self.t = top[1] if top and top[0] == "P" else None
            elif t_mode:
                self._step_t_mode(address, inst, m, locs, conf)
            else:
                self._step(address, inst, m, locs, conf)
            if m == "pla" and self.stack:
                self.stack.pop()
            flow = inst.flow_type
            if flow in (FlowTypes.ConditionalJump, FlowTypes.UnconditionalJump):
                target = inst.code_ref_address
                if target is not None:
                    edges.setdefault(target, []).append((self.yset, self.t))
            if flow in (FlowTypes.SubroutineCall,
                        FlowTypes.IndirectSubroutineCall):
                # the callee may change anything but returns with the stack
                # balanced and T as it found it
                t, stack = self.t, self.stack
                self._reset()
                self.t, self.stack = t, stack
            prev_falls_through = flow in (
                FlowTypes.Continue, FlowTypes.ConditionalJump,
                FlowTypes.SubroutineCall, FlowTypes.IndirectSubroutineCall)
        self._finish()
        return edges

    def _step_t_mode(self, site, inst, m, locs, conf):
        """T set or unknown: A-operations may act on M(X).  Record only what
        holds either way: operands read, stores of unknown values."""
        self._finish()
        loc = _direct_loc(inst)
        if loc is not None and loc[1] in self.shadows:
            if m == "ldm":
                self._config_bits(site, loc[1], _const(inst.immediate), "exact")
            elif m in _STORES:
                self._config_bits(site, loc[1], [None] * 8, "derived")
        for l in locs or ():
            if m in _READS_OPERAND:
                self._read_all(site, l, conf)
            elif m in _STORES:
                self._write_unknown(site, l, conf)
            elif m in _RMW_UNKNOWN and inst.addr_mode not in _NO_OPERAND:
                self._rmw_read(site, l, conf)
                self._write_unknown(site, l, conf)
            elif m == "ldm":
                self._write_bits(site, l, _const(inst.immediate), None, "exact")
            elif m == "com":
                self._rmw_read(site, l, conf)
                for sig in self._sigs(l, "write"):
                    if sig.direction != "in":
                        self._emit(site, sig, "toggle", None, conf)
        if m in _T_READS and self.x is not None and self.t is True:
            self._read_all(site, (None, self.x), conf)
        if m in _T_WRITES and self.x is not None:
            self._write_unknown(site, (None, self.x), conf)
        # A may or may not have been redirected; X and Y change only by
        # instructions that write them
        self.a = None
        if m in ("ldx", "ldy"):
            val = (inst.immediate if inst.addr_mode == AddressModes.Immediate
                   else None)
            if m == "ldx":
                self.x = val
            else:
                self._set_y(val)
        elif m not in _KEEP_XY:
            self.x = None
            self._set_y(None)

    def _step(self, site, inst, m, locs, conf):
        am = inst.addr_mode
        loc = locs[0] if locs and len(locs) == 1 else None
        multi = locs if locs and len(locs) > 1 else None
        # one of several locations, by path; div reads both its bytes
        if multi and conf != "assumed" and m != "div":
            conf = "path"
        # signals at the location, or (for an input latch) on its port pins
        has = bool(loc is not None and (self._sigs(loc) or
                                        self._sigs(loc, "read")))

        if loc is not None and loc[0] is None and loc[1] in self.shadows:
            reg = loc[1]
            if m == "ldm":
                self._config_bits(site, reg, _const(inst.immediate), "exact")
            elif m == "sta":
                bits = list(self.a.bits) if self.a is not None else [None] * 8
                bits = [b if b in (0, 1) else None for b in bits]
                self._config_bits(site, reg, bits, "derived")
            elif m in ("stx", "sty"):
                val = self.x if m == "stx" else self.y
                bits = _const(val) if val is not None else [None] * 8
                self._config_bits(site, reg, bits, "derived")

        if m == "ldm":
            if has:
                self._write_bits(site, loc, _const(inst.immediate), None,
                                 "exact")
            return

        if m == "lda":
            self._lose_a()
            if am == AddressModes.Immediate:
                self.a = _A(None, _const(inst.immediate))
            elif loc is not None:
                self.a = _A(loc, ["o"] * 8)
                if self._sigs(loc, "read"):
                    self.pending = _Pending(site, loc, conf)
            elif multi:
                for l in multi:
                    self._read_all(site, l, conf)
            return

        if m in ("ldx", "ldy"):
            val = inst.immediate if am == AddressModes.Immediate else None
            for l in locs or ():
                self._read_all(site, l, conf)
            if m == "ldx":
                self.x = val
            else:
                self._set_y(val)
            return

        if m in ("and", "ora", "eor") and am == AddressModes.Immediate:
            if self.a is not None:
                imm = inst.immediate
                bits = self.a.bits
                for b in range(8):
                    on = (imm >> b) & 1
                    s = bits[b]
                    if m == "and" and not on:
                        bits[b] = 0
                    elif m == "ora" and on:
                        bits[b] = 1
                    elif m == "eor" and on:
                        bits[b] = {0: 1, 1: 0, "o": "i", "i": "o",
                                   None: None}[s]
                p = self.pending
                if (m == "and" and p is not None and p.mask_site is None
                        and self.a.src == p.loc):
                    p.mask_site = site
                    p.mask = imm
            return

        if m in ("inc", "dec") and am in _NO_OPERAND:
            # inc a / dec a change A
            if self.a is not None and self.a.value is not None:
                step = 1 if m == "inc" else -1
                value = (self.a.value + step) & 0xFF
                self._lose_a()
                self.a = _A(None, _const(value))
            else:
                self._lose_a()
            return

        if m in _STORES:
            targets = multi or ([loc] if loc is not None else [])
            for l in targets:
                if not self._sigs(l, "write"):
                    continue
                if m == "sta":
                    if self.a is None:
                        self._write_unknown(site, l, conf)
                    else:
                        self._write_bits(site, l, list(self.a.bits),
                                         None if multi else self.a.src, conf)
                else:
                    val = self.x if m == "stx" else self.y
                    if val is None:
                        self._write_unknown(site, l, conf)
                    else:
                        self._write_bits(site, l, _const(val), None, conf)
            p = self.pending
            if (m == "sta" and not multi and loc is not None and
                    p is not None and p.loc == loc and self.a is not None and
                    self.a.src == loc and not self._split(loc)):
                p.consumed = True
            if m == "sta" and loc is not None and self.a is not None:
                # memory now holds A: A mirrors the new contents if the
                # location reads back what is written
                if self._split(loc):
                    self.a.detach()
                else:
                    self.a.src = loc
                    self.a.bits = [b if b in (0, 1) else "o"
                                   for b in self.a.bits]
            elif m == "sta" and multi and self.a is not None:
                self.a.detach()
            return

        if am in (AddressModes.AccumulatorBit,
                  AddressModes.AccumulatorBitRelative):
            self._acc_bit(site, inst)
            return

        if am == AddressModes.ZeroPageBit and m in ("seb", "clb"):
            # the bit instruction itself is classified in access.py; here
            # it only changes what A mirrors
            if self.a is not None and self.a.src == loc:
                from m740recon.access import bit_operation
                _, _, bit, _ = bit_operation(inst.opcode)
                self.a.bits[bit] = None if self.a.bits[bit] in ("o", "i") \
                    else self.a.bits[bit]
            return

        if m == "com" and has:
            self._rmw_read(site, loc, conf)
            for sig in self._sigs(loc, "write"):
                if sig.direction != "in":
                    self._emit(site, sig, "toggle", None, conf)
            return
        if m in _RMW_UNKNOWN and has and am not in _NO_OPERAND:
            self._rmw_read(site, loc, conf)
            self._write_unknown(site, loc, conf)
            return

        if m in _READS_OPERAND:
            for l in locs or ():
                self._read_all(site, l, conf)

        if m in ("tax", "tay"):
            val = self.a.value if self.a is not None else None
            if m == "tax":
                self.x = val
            else:
                self._set_y(val)
            return
        if m in ("txa", "tya"):
            val = self.x if m == "txa" else self.y
            self._lose_a()
            if val is not None:
                self.a = _A(None, _const(val))
            return
        if m == "txs":
            return
        if m == "pla":
            self._lose_a()
            return
        if m in ("inx", "dex", "tsx"):
            self.x = None
            if m == "tsx":
                return
        if m in ("iny", "dey"):
            self._set_y(None)
        if m not in _PRESERVE_A:
            self._lose_a()
            if m not in _KEEP_XY:
                self.x = None
                self._set_y(None)

    def _acc_bit(self, site, inst):
        from m740recon.access import bit_operation
        kind, level, bit, _ = bit_operation(inst.opcode)
        if self.a is None:
            return
        state = self.a.bits[bit]
        if kind == "test":
            p = self.pending
            src = self.a.src
            if state in ("o", "i") and src is not None:
                rl = self._read_loc(src)
                sig = self.smap.at(rl[1], bit, rl[0], "read")
                if sig is not None:
                    lvl = level if state == "o" else 1 - level
                    fb = (bit - sig.lo) if sig.is_field else None
                    conf = p.conf if p is not None and p.loc == src \
                        else "derived"
                    self._emit(site, sig, "test", lvl, conf, fb, "bit")
                    if p is not None and p.loc == src:
                        p.refined = True
            return
        self.a.bits[bit] = level          # seb N,a / clb N,a


def register_accesses(memory, smap, access_mod, shadows=None, spaces=None,
                      pointer_sites=None, latches=None):
    flow = RegisterFlow(memory, smap, access_mod, shadows, spaces, latches)
    out = flow.run()
    if pointer_sites is not None:
        pointer_sites.extend(flow.pointer_sites)
    return out
