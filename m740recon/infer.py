"""The inferred tier (`--advanced`): code found by evidence, not proof.

Everything here may be wrong, so it follows three rules:
  1. it only adds entry points; it never types bytes (no .word, no data),
     so a wrong guess cannot hide real code behind a typed region;
  2. every entry it adds is a Discovery with its source, a confidence and a
     reason, shown in the listing, the JSON model and --suggest;
  3. an entry whose code contradicts the rest (jumps into the middle of an
     instruction, an indirect jump through an SFR, a call into erased ROM)
     is dropped, the run repeats without it, until nothing contradicts.

Sources:
  table  runs of 2/3/4-byte records holding pointers to plausible code: all
         targets start right after a routine end, or the records carry
         strictly increasing keys and end at a 0x00 key with at least half of
         the targets after routine ends;
  gap    the byte after a routine end, explored as a small control-flow
         graph, accepted when it calls known routines (two, or one plus
         mostly familiar RAM / SFR use) and never contradicts known code.
"""

from collections import namedtuple

from m740recon.devices import Devices
from m740recon.disasm import disassemble
from m740recon.dispatch import Plausibility, _is_code, _is_fill
from m740recon.tables import AddressModes, FlowTypes

Discovery = namedtuple("Discovery", "address source confidence reason")

_FALLS = (FlowTypes.Continue, FlowTypes.ConditionalJump,
          FlowTypes.SubroutineCall, FlowTypes.IndirectSubroutineCall)
_STOPS = (FlowTypes.Stop, FlowTypes.UnconditionalJump, FlowTypes.SubroutineReturn,
          FlowTypes.IndirectUnconditionalJump)
_ROUNDS = 12
_PASSES = 4
_EXPLORE_LIMIT = 256


def _typed(mem, a, reserved=frozenset()):
    a &= 0xFFFF
    return (a in reserved or _is_code(mem, a) or mem.is_vector_start(a)
            or mem.is_vector_continuation(a) or mem.is_word_start(a) or mem.is_text_start(a))


def _anchored(mem, t):
    """Known code, or the bytes before t end a routine."""
    if mem.is_instruction_start(t):
        return True
    if mem[(t - 1) & 0xFFFF] in (0x60, 0x40):
        return True
    if mem[(t - 3) & 0xFFFF] == 0x4C:
        return True
    return mem[(t - 2) & 0xFFFF] in (0x80, 0xB2)


# ------------------------------------------------------------------ tables

def _keys_ok(mem, run, stride, koff_ptr):
    """Strictly increasing, non-zero key bytes and a 0x00-key record after."""
    for o in [o for o in range(stride) if o not in (koff_ptr, koff_ptr + 1)]:
        keys = [mem[rec + o] for rec, _, _ in run]
        if 0 in keys or keys != sorted(set(keys)) or len(set(keys)) != len(keys):
            continue
        end = run[-1][0] + stride
        if mem[(end + o) & 0xFFFF] == 0x00:
            return True
    return False


def table_entries(mem, lo, hi, plausible, reserved):
    """[(target, table start, stride, records, keyed)] from pointer tables."""
    typed = bytearray(hi - lo + 4)           # 1 where a byte is already typed
    for a in range(lo, hi):
        if _typed(mem, a, reserved):
            typed[a - lo] = 1
    cands = []
    for stride in (2, 3, 4):
        for k in range(stride - 1):
            for phase in range(stride):
                a, run = lo + phase, []
                while a + stride <= hi:
                    ok = not any(typed[a - lo:a - lo + stride])
                    t = None
                    if ok:
                        t = mem[a + k] | (mem[(a + k + 1) & 0xFFFF] << 8)
                        ok = plausible(t)
                    if ok:
                        run.append((a, a + k, t))
                    else:
                        _close(mem, run, stride, k, cands)
                        run = []
                    a += stride
                _close(mem, run, stride, k, cands)
    cands.sort(key=lambda c: -c[0])
    taken, out = set(), []
    for span, start, stride, run, keyed in cands:
        used = set()
        for _, slot, _ in run:
            used.update((slot, slot + 1))
        if used & taken:
            continue
        taken |= used
        for rec, slot, t in run:
            out.append((t, start, stride, len(run), keyed, slot))
    return out


def _close(mem, run, stride, k, cands):
    if len(run) < 4:
        return
    anchored = sum(1 for _, _, t in run if _anchored(mem, t))
    if anchored == len(run):
        cands.append((len(run) * stride, run[0][0], stride, list(run), False))
    elif stride >= 3 and anchored * 2 >= len(run) and _keys_ok(mem, run, stride, k):
        cands.append((len(run) * stride, run[0][0], stride, list(run), True))


# -------------------------------------------------------------------- gaps

def _known_refs(mem, lo, hi):
    out = set()
    for _, inst in mem.iter_instructions():
        r = inst.data_ref_address
        if r is not None and not lo <= r < hi:
            out.add(r)
    return out


def _explore(mem, start, lo, hi, unsupported, known, reserved):
    """Evidence for code at `start`, or None when it contradicts known code."""
    ev = dict(calls=0, refs=0, known=0)
    seen = {}
    todo = [start]
    while todo:
        pc = todo.pop()
        if pc in seen:
            continue
        if mem.is_instruction_start(pc):
            continue
        if not lo <= pc < hi or _is_code(mem, pc) or _is_fill(mem, pc):
            return None
        inst = disassemble(mem, pc, unsupported)
        n = len(inst)
        if inst.illegal or pc + n > hi:
            return None
        if any(_typed(mem, pc + i, reserved) or (pc + i) in seen for i in range(n)):
            return None
        seen[pc] = n
        if len(seen) > _EXPLORE_LIMIT:
            return None
        r = inst.data_ref_address
        if r is not None and not lo <= r < hi:
            ev["refs"] += 1
            ev["known"] += r in known
        ft = inst.flow_type
        if ft == FlowTypes.SubroutineCall and inst.code_ref_address is not None \
                and mem.is_call_target(inst.code_ref_address):
            ev["calls"] += 1
        if ft in _FALLS:
            todo.append((pc + n) & 0xFFFF)
        if ft in (FlowTypes.ConditionalJump, FlowTypes.UnconditionalJump) \
                and inst.code_ref_address is not None:
            todo.append(inst.code_ref_address)
    covered = set()
    for a, n in seen.items():
        span = set(range(a, a + n))
        if span & covered:
            return None
        covered |= span
    return ev


def _accept(ev):
    return ev["calls"] >= 2 or (ev["calls"] >= 1 and ev["refs"]
                                and ev["known"] * 2 >= ev["refs"])


def gap_entries(mem, lo, hi, unsupported, reserved):
    known = _known_refs(mem, lo, hi)
    out = []
    for a, inst in mem.iter_instructions():
        if not lo <= a < hi or inst.flow_type not in _STOPS:
            continue
        c = (a + len(inst)) & 0xFFFF
        if not lo <= c < hi or _typed(mem, c, reserved) or _is_fill(mem, c):
            continue
        ev = _explore(mem, c, lo, hi, unsupported, known, reserved)
        if ev is not None and _accept(ev):
            out.append((c, a, ev))
    return out


# ------------------------------------------------------------- contradictions

def contradictions(mem, base_mem, seed, lo, hi, sfr):
    """Reasons the seed's own new code contradicts the rest ([] when clean).
    Calls are not followed: a shared callee is judged on its own seed."""
    why, seen, todo = [], set(), [seed]
    while todo and len(seen) < 4000:
        a = todo.pop()
        if a in seen or base_mem.is_instruction_start(a):
            continue
        if not mem.is_instruction_start(a):
            if mem.is_instruction_continuation(a):
                why.append("jumps into the middle of 0x%04x" % a)
            continue
        seen.add(a)
        inst = mem.get_instruction(a)
        ft = inst.flow_type
        if (ft in (FlowTypes.IndirectUnconditionalJump, FlowTypes.IndirectSubroutineCall)
                and inst.addr_mode == AddressModes.ZeroPageIndirect
                and getattr(inst, "zp_addr", None) in sfr):
            why.append("indirect jump through SFR at 0x%04x" % a)
        nxt = (a + len(inst)) & 0xFFFF
        if ft in _FALLS:
            if mem.is_instruction_continuation(nxt):
                why.append("falls into the middle of an instruction at 0x%04x" % a)
            todo.append(nxt)
        t = inst.code_ref_address
        if t is not None and ft in (FlowTypes.ConditionalJump, FlowTypes.UnconditionalJump,
                                    FlowTypes.SubroutineCall):
            if ft == FlowTypes.SubroutineCall:
                if lo <= t < hi and _is_fill(mem, t):
                    why.append("calls erased ROM at 0x%04x" % a)
            else:
                if mem.is_instruction_continuation(t):
                    why.append("jumps into the middle of 0x%04x" % a)
                todo.append(t)
    return why


# -------------------------------------------------------------------- driver

def run(build, rom, device, start_address, lo, hi, **kwargs):
    """Run the inferred tier.  `build` is command.build_disassembly; kwargs
    are its keyword arguments (entry points, symbols, ranges...).  Returns
    (memory, symbol_table, discoveries, dropped) where dropped maps an
    address to the reasons it was removed."""
    unsupported = Devices[device].get("unsupported_opcodes", frozenset())
    sfr = {s.address for s in Devices[device]["symbol_table"]
           if s.address < 0x100 and not s.weak}
    user_entries = list(kwargs.pop("entry_points", ()))
    kwargs.setdefault("analyze", True)
    kwargs.setdefault("discover_tables", True)

    def full(extra):
        return build(rom, device, start_address,
                     entry_points=user_entries + sorted(extra), **kwargs)

    base_mem, base_sym = full(())
    # later rounds reuse the proven tables found here instead of searching again
    ptrs, data, syms = getattr(base_mem, "dispatch_inputs", ((), (), ()))
    quick = dict(kwargs, proven=False,
                 vectors_extra=list(kwargs.get("vectors_extra", ())) + list(ptrs),
                 data_addrs=list(kwargs.get("data_addrs", ())) + list(data),
                 extra_symbols=list(syms) + list(kwargs.get("extra_symbols", ())))

    def rebuild(extra):
        return build(rom, device, start_address,
                     entry_points=user_entries + sorted(extra), **quick)

    banned, dropped = set(), {}
    for _ in range(_PASSES):
        found = {}                      # address -> Discovery
        reserved = set()
        mem, sym = base_mem, base_sym
        for _ in range(_ROUNDS):
            add = False
            plausible = Plausibility(mem, lo, hi, unsupported)
            for t, tstart, stride, nrec, keyed, slot in table_entries(mem, lo, hi, plausible,
                                                                      reserved):
                reserved.update((slot, slot + 1))
                if t in found or t in banned or mem.is_instruction_start(t):
                    continue
                kind = "keyed table" if keyed else "pointer table"
                found[t] = Discovery(t, "table@0x%04x" % tstart, "medium",
                                     "%s at 0x%04x (%d records of %d bytes)"
                                     % (kind, tstart, nrec, stride))
                add = True
            for c, after, ev in gap_entries(mem, lo, hi, unsupported, reserved):
                if c in found or c in banned:
                    continue
                found[c] = Discovery(c, "gap", "medium",
                                     "follows the routine end at 0x%04x; calls %d known "
                                     "routine%s" % (after, ev["calls"],
                                                    "" if ev["calls"] == 1 else "s"))
                add = True
            if not add:
                break
            mem, sym = rebuild(found)
        bad = {}
        for addr in found:
            why = contradictions(mem, base_mem, addr, lo, hi, sfr)
            if why:
                bad[addr] = why
        if not bad:
            break
        banned |= set(bad)
        dropped.update(bad)
    kept = [d for a, d in sorted(found.items()) if a not in banned]
    # final build with the full proven tier: inferred code may reveal a table
    mem, sym = full({d.address for d in kept})
    return mem, sym, kept, dropped
