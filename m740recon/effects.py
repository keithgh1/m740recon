"""Routine-level signal effects.

leaf_summaries() finds small subroutines whose signal effects are certain:
every call to them performs the same writes, in the same order.  Their
effects are then shown at each call site (`jsr sub_ff6e  ; -> EE_CS = 1`).

A routine qualifies when, from its entry to its first `rts`:
  - it is at most MAX_INSTRUCTIONS instructions long;
  - it makes no calls and no computed jumps, and does not jump away;
  - its only branches are counted delay loops: a `bne` back over a body
    of nothing but `nop`s ending in one `dex` / `dey` / `inx` / `iny`.
    Such a loop always ends (the counter reaches zero within 256 turns)
    and contains no effect, so every effect runs exactly once.  Any other
    branch could skip an effect, repeat one, or never let one run;
  - it has at least one signal access, and every access is an exact write
    (set / clear / write / toggle, or a pin direction or function
    setting, from a bit instruction or ldm).

reach() computes, over the static call graph, which routines can lead to a
write of each signal.  Computed calls are not followed, so it is a lower
bound.
"""

from m740recon.tables import FlowTypes

MAX_INSTRUCTIONS = 8
_WRITE_KINDS = frozenset(("set", "clear", "write", "toggle"))
# configuring a pin (direction / function register) is also a fixed effect
_EFFECT_KINDS = _WRITE_KINDS | frozenset(("direction", "function"))


_COUNTERS = frozenset(("dex", "dey", "inx", "iny"))


def _mnemonic(inst):
    return inst.disasm_template.split(" ", 1)[0]


def _is_delay_loop(memory, target, branch_addr, branch):
    """True if `branch` (at `branch_addr`) is a bne back to `target` over a
    body of nops ending in a single counter step."""
    if _mnemonic(branch) != "bne":
        return False
    body = []
    addr = target
    while addr < branch_addr:
        if not memory.is_instruction_start(addr):
            return False
        inst = memory.get_instruction(addr)
        body.append(_mnemonic(inst))
        addr += len(inst)
    if addr != branch_addr or not body:
        return False
    return body[-1] in _COUNTERS and all(m == "nop" for m in body[:-1])


def _straight_body(memory, entry):
    """Instruction addresses from `entry` to its first rts, or None if the
    routine does not meet the leaf rules (other than the access rules)."""
    body = []
    addr = entry
    while len(body) < MAX_INSTRUCTIONS:
        if not memory.is_instruction_start(addr):
            return None
        inst = memory.get_instruction(addr)
        body.append(addr)
        flow = inst.flow_type
        if flow == FlowTypes.SubroutineReturn:
            if inst.disasm_template.split(" ", 1)[0] != "rts":
                return None                  # rti: not a callable leaf
            return body
        if flow == FlowTypes.ConditionalJump:
            target = inst.code_ref_address
            if target is None or not (entry <= target < addr):
                return None                  # forward or outward branch
            if not _is_delay_loop(memory, target, addr, inst):
                return None                  # may skip or repeat an effect
        elif flow != FlowTypes.Continue:
            return None                      # call, jump, computed, stop
        addr = (addr + len(inst)) & 0xFFFF
    return None


def leaf_summaries(memory, accesses):
    """{routine entry: [Access, ...]} for every qualifying leaf subroutine,
    effects in address order."""
    by_site = {}
    for acc in accesses:
        by_site.setdefault(acc.address, []).append(acc)
    out = {}
    for addr, _ in memory.iter_instructions():
        if not memory.is_call_target(addr):
            continue
        body = _straight_body(memory, addr)
        if body is None:
            continue
        effects = [a for site in body for a in by_site.get(site, [])]
        # the read half of a read-modify-write is not an effect of its own
        writes = {a.address for a in effects if a.kind in _WRITE_KINDS}
        effects = [a for a in effects
                   if not (a.kind == "read" and a.address in writes)]
        if not effects:
            continue
        if all(a.kind in _EFFECT_KINDS and a.confidence == "exact"
               for a in effects):
            out[addr] = effects
    return out


def effect_text(effects):
    return "; ".join(a.text for a in effects)


def call_site_annotations(memory, summaries):
    """{call site: "-> effects"} for every direct call to a summarized leaf."""
    out = {}
    for addr, inst in memory.iter_instructions():
        if inst.flow_type != FlowTypes.SubroutineCall:
            continue
        target = inst.code_ref_address
        if target in summaries:
            out[addr] = "-> " + effect_text(summaries[target])
    return out


def suggested_name(effects):
    """A name for a leaf whose whole effect is one signal operation (or a
    set-then-clear pulse of one signal), else None."""
    names = {a.signal.name for a in effects}
    if len(names) != 1:
        return None
    base = names.pop().lower()
    kinds = [a.kind for a in effects]
    if len(effects) == 1:
        a = effects[0]
        if a.kind == "write" and a.signal.is_field:
            return "%s_write" % base
        if a.kind in ("set", "clear", "toggle"):
            return "%s_%s" % (base, a.kind)
        if a.kind == "write":
            return "%s_%s" % (base, "set" if a.level else "clear")
        return None
    # a pulse: the same physical bit driven one way and then the other
    if len(effects) != 2 or not all(k in ("set", "clear", "write")
                                    for k in kinds):
        return None
    first, second = effects
    if first.signal.is_field and (first.bit is None or second.bit is None):
        return None                       # a whole-field write, not one bit
    if first.bit != second.bit:
        return None
    if None in (first.level, second.level) or first.level == second.level:
        return None
    return "%s_pulse" % base


def reach(routines, writers):
    """Reverse reachability over static call edges.

    `routines` is the report model's routine list (each with "name" and
    "called_by"); `writers` maps a signal name to the set of routine names
    that write it directly.  Returns {signal name: sorted routine names that
    can call, directly or through other routines, a direct writer}."""
    callers = {}
    for r in routines:
        callers[r["name"]] = {e["name"] for e in r["called_by"]}
    out = {}
    for sig, direct in writers.items():
        seen = set()
        todo = list(direct)
        while todo:
            name = todo.pop()
            for c in callers.get(name, ()):
                if c not in seen and c not in direct:
                    seen.add(c)
                    todo.append(c)
        out[sig] = sorted(seen)
    return out
