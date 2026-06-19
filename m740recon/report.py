"""Structured reports derived from a traced disassembly.

Reads only already-traced state (instructions, jump/call annotations, vectors,
symbols) and builds a program model of routines and the call edges between
them.  The model renders either as a machine-readable JSON document
(`to_json`) or as a human-readable call-graph report (`format_call_graph`).
Nothing here mutates the disassembly, so a report is safe to produce after any
trace, with or without --analyze.

A "routine" is a call target, an entry point, or an interrupt/reset vector
handler -- the roots the listing names `sub_*` / `lab_*` plus explicit entry
points.  Each routine owns the half-open address interval from its entry to
the next routine entry; a call or tail-jump instruction is attributed to
whichever routine's interval contains it.  Direct calls (`jsr abs`,
special-page `jsr`) and cross-routine jumps (tail calls) become edges;
computed `jsr [zp]` / `jmp [zp]` sites cannot name a target from the
instruction alone and are reported as a count instead of as edges.
"""

import bisect
import json

from m740recon.tables import FlowTypes

_CALL_FLOWS = frozenset((FlowTypes.SubroutineCall,))
# A tail call is an *unconditional* jump into another routine.  A conditional
# branch may fall through, so it is not a tail call and is not reported as an edge.
_TAILCALL_FLOWS = frozenset((FlowTypes.UnconditionalJump,))
_INDIRECT_FLOWS = frozenset((FlowTypes.IndirectSubroutineCall,
                             FlowTypes.IndirectUnconditionalJump))


def _hex(addr):
    return "0x%04x" % addr


def _name(symbol_table, addr):
    if addr in symbol_table:
        return symbol_table[addr].name
    return _hex(addr)


def build_model(memory, symbol_table, start_address, image_len, device=None):
    """Return a JSON-ready dict describing the program's routines, the call
    edges between them, the vector table, and a full cross-reference map."""
    instructions = list(memory.iter_instructions())

    # Vectors, and the handler addresses they point at (routine roots).  Read
    # the pointer little-endian (as the tracer and listing do).
    vectors = []
    vector_targets = set()
    for vaddr, _ in memory.iter_vectors():
        target = memory.read_word(vaddr)
        is_code = memory.is_instruction_start(target)
        vectors.append((vaddr, target, is_code))
        if is_code:
            vector_targets.add(target)

    # Routine roots: call targets + entry points + vector handlers.
    roots = set(vector_targets)
    for addr, _ in instructions:
        if memory.is_call_target(addr) or memory.is_entry_point(addr):
            roots.add(addr)
    roots = sorted(roots)

    def region_of(addr):
        i = bisect.bisect_right(roots, addr) - 1
        return roots[i] if i >= 0 else None

    routines = {}
    for r in roots:
        kinds = []
        if memory.is_call_target(r):
            kinds.append("subroutine")
        if memory.is_entry_point(r):
            kinds.append("entry")
        if r in vector_targets:
            kinds.append("vector")
        routines[r] = {
            "address": _hex(r),
            "name": _name(symbol_table, r),
            "kind": kinds,
            "instructions": 0,
            "calls": [],        # outgoing edges
            "called_by": [],    # incoming edges
        }

    edges = []                  # (caller_root, target, type, site)
    indirect_sites = 0
    xrefs = {}                  # target -> set(site)
    for addr, inst in instructions:
        caller = region_of(addr)
        if caller is not None:
            routines[caller]["instructions"] += 1

        # cross-reference map (code + data), same definition as the listing
        for ref in (inst.code_ref_address, inst.data_ref_address):
            if ref is not None:
                xrefs.setdefault(ref, set()).add(addr)

        flow = inst.flow_type
        if flow in _INDIRECT_FLOWS:
            indirect_sites += 1
            continue
        target = inst.code_ref_address
        if target is None or caller is None:
            continue
        if flow in _CALL_FLOWS:
            edges.append((caller, target, "call", addr))
        elif flow in _TAILCALL_FLOWS and target in routines and target != caller:
            edges.append((caller, target, "tailcall", addr))

    for caller, target, etype, site in edges:
        routines[caller]["calls"].append({
            "to": _hex(target), "name": _name(symbol_table, target),
            "type": etype, "site": _hex(site)})
        if target in routines:
            routines[target]["called_by"].append({
                "from": _hex(caller), "name": _name(symbol_table, caller),
                "type": etype, "site": _hex(site)})

    for r in routines.values():
        r["calls"].sort(key=lambda e: (e["site"], e["to"]))
        r["called_by"].sort(key=lambda e: (e["site"], e["from"]))

    return {
        "meta": {
            "format": "m740recon-report/1",
            "device": device,
            "start": _hex(start_address),
            "length": image_len,
            "routine_count": len(roots),
            "call_edge_count": len(edges),
            "indirect_sites": indirect_sites,
        },
        "symbols": [
            {"address": _hex(a), "name": s.name,
             "comment": s.comment, "weak": s.weak}
            for a, s in symbol_table.items()],
        "vectors": [
            {"address": _hex(v), "name": _name(symbol_table, v),
             "target": _hex(t), "target_name": _name(symbol_table, t),
             "target_is_code": is_code}
            for (v, t, is_code) in vectors],
        "routines": [routines[r] for r in roots],
        "xrefs": [
            {"address": _hex(a), "from": [_hex(s) for s in sorted(srcs)]}
            for a, srcs in sorted(xrefs.items())],
    }


def to_json(model):
    """Render a model as a deterministic, pretty-printed JSON document."""
    return json.dumps(model, indent=2) + "\n"


def format_call_graph(model):
    """Render a model as a human-readable call-graph report."""
    meta = model["meta"]
    lines = ["; m740recon call graph",
             "; device %s, %d routines, %d call edges" % (
                 meta["device"] or "?", meta["routine_count"],
                 meta["call_edge_count"])]
    if meta["indirect_sites"]:
        lines.append("; %d computed (indirect) call/jump site(s) not shown as "
                     "edges" % meta["indirect_sites"])
    lines.append("")

    for r in model["routines"]:
        kinds = (" [%s]" % ",".join(r["kind"])) if r["kind"] else ""
        lines.append("%s%s" % (r["name"], kinds))
        for e in r["calls"]:
            tag = "" if e["type"] == "call" else "  (%s)" % e["type"]
            lines.append("    -> %-22s ; @%s%s" % (e["name"], e["site"], tag))
        callers, seen = [], set()
        for e in r["called_by"]:
            if e["from"] not in seen:
                seen.add(e["from"])
                callers.append(e["name"])
        lines.append("    <- " + (", ".join(callers) if callers
                                  else "(no static callers)"))
        lines.append("")

    orphans = [r["name"] for r in model["routines"]
               if "subroutine" in r["kind"] and not r["called_by"]]
    if orphans:
        lines.append("; %d subroutine(s) with no static callers "
                     "(indirect-only or dead):" % len(orphans))
        lines.extend(";   %s" % n for n in orphans)

    return "\n".join(lines).rstrip() + "\n"
