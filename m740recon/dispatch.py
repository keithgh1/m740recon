"""Dispatch tables whose existence the code itself proves.

Two shapes, both found on real firmware:

Search-routine tables.  A zero-page pointer pair P/P+1 is loaded with a
constant (`ldm #lo,P` / `ldm #hi,P+1`) shortly before `jmp [P]` or `jsr [P]`,
with a `jsr` in between: the called routine searches the table P points at
and leaves the matching handler in P.  The constant is the table's address.
The record layout (stride, where the key and the pointer sit, the terminator
key) is read from the data: every pointer before the terminator has to look
like the start of code.

Loop-indexed tables.  `ldx #0 / L: txa / asl a (k times) / tay ... /
inx / cpx #N / bcc L` walks N records of 2^k bytes, and the handler is
loaded with `lda T,y / lda T+1,y` before `jmp/jsr [P]`.  The loop bound
gives the exact record count.

Each table found is returned as a control-file AddrTable (so it is resolved,
rendered and named exactly like a hand-written `addrtable` line) together
with how it was found.  Handlers of keyed tables are named from their keys
(`tbl_c0d4_E`, `tbl_c063_BEL`).
"""

import re
from collections import namedtuple

from m740recon.control import AddrTable
from m740recon.dataflow import _Regs, _apply_effects
from m740recon.disasm import disassemble
from m740recon.tables import AddressModes, FlowTypes

Found = namedtuple("Found", "table kind site records")

_LDM = re.compile(r"^ldm #0x([0-9a-f]+),0x([0-9a-f]+)$")
_IMM = re.compile(r"#0x([0-9a-f]+)")
_LAYOUTS = [(3, 0, 1), (3, 2, 0), (4, 0, 1), (4, 0, 2), (4, 3, 0), (4, 2, 0), (2, None, 0)]
_MAX_RECORDS = 128
_TRIAL = 64
_CONTINUE = (FlowTypes.Continue, FlowTypes.ConditionalJump,
             FlowTypes.SubroutineCall, FlowTypes.IndirectSubroutineCall)
_STOPS = (FlowTypes.Stop, FlowTypes.SubroutineReturn, FlowTypes.UnconditionalJump)


def _is_code(mem, a):
    a &= 0xFFFF
    return mem.is_instruction_start(a) or mem.is_instruction_continuation(a)


def _is_fill(mem, a):
    b = mem[a & 0xFFFF]
    return b in (0x00, 0xFF) and all(mem[(a + i) & 0xFFFF] == b for i in range(4))


class Plausibility(object):
    """Does an address look like the start of code?  A known instruction
    start does; otherwise a straight-line trial decode must reach a flow
    stop or known code without fill, an illegal opcode, leaving [lo, hi) or
    running into the middle of an instruction."""

    def __init__(self, mem, lo, hi, unsupported=frozenset()):
        self.mem, self.lo, self.hi = mem, lo, hi
        self.unsupported = unsupported
        self._cache = {}
        from m740recon.detect import _written_pages
        pages = _written_pages(mem, lo, hi)
        self.ram_span = (min(pages), max(pages)) if pages else None

    def external(self, t):
        """A target outside the image that is not RAM / I/O: another ROM."""
        if self.lo <= t < self.hi or t < 0x0100 or t in (0xFFFF,):
            return False
        span = self.ram_span
        return not (span and span[0] <= (t >> 8) <= span[1])

    def __call__(self, t):
        if t not in self._cache:
            self._cache[t] = self._check(t)
        return self._cache[t]

    def _check(self, t):
        mem = self.mem
        if not self.lo <= t < self.hi:
            return False
        if mem.is_instruction_start(t):
            return True
        pc = t
        for _ in range(_TRIAL):
            if not self.lo <= pc < self.hi:
                return False
            if mem.is_instruction_start(pc):
                return True
            if _is_code(mem, pc) or _is_fill(mem, pc):
                return False
            inst = disassemble(mem, pc, self.unsupported)
            if inst.illegal or pc + len(inst) > self.hi:
                return False
            if any(_is_code(mem, pc + i) for i in range(1, len(inst))):
                return False
            if inst.flow_type not in _CONTINUE:
                return True
            pc += len(inst)
        return True


def _free(mem, a, n):
    """Bytes not yet typed as code or pointers."""
    return all(not _is_code(mem, a + i) and not mem.is_vector_start((a + i) & 0xFFFF)
               and not mem.is_vector_continuation((a + i) & 0xFFFF) for i in range(n))


# ----------------------------------------------------- search-routine tables

def search_sites(mem, lo, hi):
    """[(site, table address)] for constant pointers handed to a search."""
    insts = list(mem.iter_instructions())
    out = []
    for k, (a, inst) in enumerate(insts):
        if not lo <= a < hi or inst.addr_mode != AddressModes.ZeroPageIndirect:
            continue
        zp = inst.zp_addr
        # Scanning back from the jump: the pointer must be loaded before the
        # search call (a load after it makes the pointer a plain code
        # address), and no branch between the load and the call may skip
        # the call (that path would jump through the constant unsearched).
        vals, call_at, ok = {}, None, True
        for j in range(k - 1, max(-1, k - 14), -1):
            pa, prev = insts[j]
            m = _LDM.match(str(prev))
            if m and int(m.group(2), 16) in (zp, (zp + 1) & 0xFF):
                if call_at is None:
                    ok = False
                    break
                vals.setdefault(int(m.group(2), 16), int(m.group(1), 16))
            if prev.flow_type == FlowTypes.SubroutineCall and call_at is None:
                call_at = pa
            elif (call_at is not None and len(vals) < 2
                  and prev.flow_type == FlowTypes.ConditionalJump
                  and prev.code_ref_address is not None
                  and call_at < prev.code_ref_address <= a):
                ok = False
                break
            if prev.flow_type in _STOPS:
                break
        if ok and call_at is not None and zp in vals and ((zp + 1) & 0xFF) in vals:
            out.append((a, vals[zp] | (vals[(zp + 1) & 0xFF] << 8)))
    return out


def _walk_layout(mem, base, lo, hi, plausible, stride, koff, poff):
    """(records, terminator) for one candidate layout, or None.  A keyed
    table may point into a ROM that was not given (external targets), as long
    as most of its targets are code here and it ends at a terminator key."""
    recs, ext, a = [], 0, base
    for _ in range(_MAX_RECORDS):
        if not lo <= a <= hi - stride:
            return None
        if koff is not None and mem[a + koff] in (0x00, 0xFF):
            if len(recs) >= 2 and ext * 2 <= len(recs):
                return recs, mem[a + koff]
            return None
        if not _free(mem, a, stride) and not mem.is_vector_start(a + poff):
            return None
        t = mem[a + poff] | (mem[a + poff + 1] << 8)
        if not plausible(t):
            if koff is not None and plausible.external(t):
                ext += 1
            else:
                # an unkeyed table ends at its first implausible pointer
                return (recs, None) if koff is None and len(recs) >= 2 else None
        recs.append(t)
        a += stride
    return None


def search_tables(mem, lo, hi, plausible):
    found = []
    for site, base in search_sites(mem, lo, hi):
        best = None
        for stride, koff, poff in _LAYOUTS:
            walked = _walk_layout(mem, base, lo, hi, plausible, stride, koff, poff)
            if walked and (best is None or len(walked[0]) > len(best[1][0])):
                best = ((stride, koff, poff), walked)
        if best is None:
            continue
        (stride, koff, poff), (recs, term) = best
        prefix = "tbl_%04x_" % base
        if koff is not None:
            table = AddrTable(base, None, None, stride, poff, term, prefix, "ascii",
                              koff or None)
        else:
            table = AddrTable(base, None, len(recs), stride, poff, None, prefix, None)
        found.append(Found(table, "search", site, len(recs)))
    return found


# ------------------------------------------------------- loop-indexed tables

def _indexed_dispatch(mem, lo, hi):
    """(index of site in insts, site, table address, index register, insts)
    for jmp/jsr [P] whose pointer comes from `lda T,r` / `lda T+1,r`."""
    insts = list(mem.iter_instructions())
    regs = _Regs()
    falls = False
    for k, (a, inst) in enumerate(insts):
        leader = mem.is_jump_target(a) or mem.is_call_target(a) or mem.is_entry_point(a)
        if leader or not falls:
            regs = _Regs()
        if inst.addr_mode == AddressModes.ZeroPageIndirect and lo <= a < hi:
            ls = regs.zp_src.get(inst.zp_addr)
            hs = regs.zp_src.get((inst.zp_addr + 1) & 0xFF)
            if (ls and hs and ls[0] == "idx" and hs[0] == "idx" and ls[2] == hs[2]
                    and hs[1] == (ls[1] + 1) & 0xFFFF):
                yield k, a, ls[1], ls[2], insts
        regs = _apply_effects(inst, regs)
        falls = inst.flow_type in _CONTINUE


def _loop_bound(insts, k, reg):
    """(count, stride) when the index register is a scaled loop counter."""
    start = max(0, k - 48)
    window = insts[start:k]
    text = [str(i) for _, i in window]
    for d in range(len(window) - 1, 1, -1):
        if text[d] != "ta" + reg:
            continue
        shifts, j = 0, d - 1
        while j >= 0 and text[j] == "asl a":
            shifts, j = shifts + 1, j - 1
        if j < 0 or not re.match(r"^t[xy]a$", text[j]):
            return None
        ctr = text[j][1]
        def_addr = window[j][0]
        tail = insts[start + j:k + 24]
        tt = [str(i) for _, i in tail]
        for g in range(len(tt) - 2):
            if (tt[g] == "in" + ctr and tt[g + 1].startswith("cp%s #" % ctr)
                    and tt[g + 2].startswith("bcc")):
                target = tail[g + 2][1].code_ref_address
                if target is None or target > def_addr:
                    continue
                before = [str(i) for a, i in insts[max(0, k - 64):k] if a < target]
                if "ld%s #0x00" % ctr in before[-6:]:
                    return int(_IMM.search(tt[g + 1]).group(1), 16), 1 << shifts
        return None
    return None


def loop_tables(mem, lo, hi, plausible):
    found = []
    for k, site, base, reg, insts in _indexed_dispatch(mem, lo, hi):
        bound = _loop_bound(insts, k, reg)
        if not bound:
            continue
        count, stride = bound
        if count < 1 or count > _MAX_RECORDS:
            continue
        ok = True
        for i in range(count):
            p = base + i * stride
            if not lo <= p < hi - 1:
                ok = False
                break
            if not plausible(mem[p] | (mem[p + 1] << 8)):
                ok = False                    # all or nothing
                break
        if ok:
            table = AddrTable(base, None, count, stride, 0, None, "tbl_%04x_" % base, None)
            found.append(Found(table, "loop", site, count))
    return found


def find_tables(mem, lo, hi, unsupported=frozenset(), known=()):
    """Proven dispatch tables in the traced memory not already in `known`
    (table start addresses).  Returns [Found]."""
    plausible = Plausibility(mem, lo, hi, unsupported)
    out, seen = [], set(known)
    for f in search_tables(mem, lo, hi, plausible) + loop_tables(mem, lo, hi, plausible):
        if f.table.start in seen:
            continue
        # a table the user (or an earlier round) already typed is not new
        if mem.is_vector_start(f.table.start + f.table.entryoff):
            continue
        seen.add(f.table.start)
        out.append(f)
    return out
