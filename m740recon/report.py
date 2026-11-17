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


def build_model(memory, symbol_table, start_address, image_len, device=None,
                signal_map=None, accesses=None, pointer_sites=None):
    """Return a JSON-ready dict describing the program's routines, the call
    edges between them, the vector table, and a full cross-reference map.

    When `signal_map` declares signals, the model also carries a `signals`
    section (each signal with its accesses), a `groups` section, and a
    per-routine `signals` summary.  Without signals the model is unchanged."""
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

    model = {
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
    if signal_map:
        _add_signals(model, routines, region_of, symbol_table, signal_map,
                     accesses or [], memory)
    if signal_map is not None and signal_map.pointers:
        _add_pointers(model, routines, region_of, signal_map,
                      pointer_sites or [])
    return model


def _add_pointers(model, routines, region_of, smap, sites):
    from m740recon.access import pointer_tag
    by_ptr = {}
    for ps in sites:
        root = region_of(ps.site)
        by_ptr.setdefault(ps.pointer.address, []).append({
            "site": _hex(ps.site),
            "routine": routines[root]["name"] if root is not None else None,
            "op": ps.op,
            "state": ps.state,
            "locations": None if ps.locs is None else [
                {"space": sp, "address": _hex(a)} for sp, a in ps.locs],
            "index": ps.index,
            "index_register": ps.register,
            "text": pointer_tag(ps),
        })
    model["pointers"] = [
        {"address": "0x%02x" % p.address, "target": _hex(p.target),
         "space": p.space, "comment": p.comment,
         "accesses": sorted(by_ptr.get(p.address, []),
                            key=lambda a: a["site"])}
        for _, p in sorted(smap.pointers.items())]


def _signal_header(sig):
    return {
        "name": sig.name,
        "kind": sig.kind,
        "location": sig.loc,
        "address": _hex(sig.address),
        "bits": [sig.lo, sig.hi],
        "direction": sig.direction,
        "active": sig.active,
        "high": sig.high,
        "low": sig.low,
        "source": sig.source,
        "description": sig.description,
        "group": sig.group,
        "space": sig.space,
        "access": sig.access,
    }


def _add_signals(model, routines, region_of, symbol_table, smap, accesses,
                 memory):
    from m740recon import effects
    by_signal = {}
    per_routine = {}            # routine root -> {signal name -> set(kinds)}
    for acc in accesses:
        root = region_of(acc.address)
        by_signal.setdefault(acc.signal.name, []).append({
            "site": _hex(acc.address),
            "routine": routines[root]["name"] if root is not None else None,
            "kind": acc.kind,
            "level": acc.level,
            "bit": acc.bit,
            "confidence": acc.confidence,
            "scope": acc.scope,
            "text": acc.text,
        })
        if root is not None:
            per_routine.setdefault(root, {}).setdefault(
                acc.signal.name, set()).add(acc.kind)

    signals = []
    for sig in smap.signals:
        entry = _signal_header(sig)
        entry["accesses"] = sorted(by_signal.get(sig.name, []),
                                   key=lambda a: (a["site"], a["kind"]))
        signals.append(entry)
    model["signals"] = signals
    model["groups"] = [
        {"name": name, "description": desc,
         "members": [m.name for m in members]}
        for name, members, desc in smap.groups]
    group_of = {s.name: s.group for s in smap.signals}
    summaries = effects.leaf_summaries(memory, accesses)
    for root, r in routines.items():
        touched = per_routine.get(root, {})
        r["signals"] = [{"name": n, "kinds": sorted(k)}
                        for n, k in sorted(touched.items())]
        if root in summaries:
            r["effect"] = [a.text for a in summaries[root]]
            weak = root not in symbol_table or symbol_table[root].weak
            name = effects.suggested_name(summaries[root])
            if name and weak:
                r["suggested_name"] = name
        groups = {group_of[n] for n in touched}
        if touched and len(groups) == 1 and None not in groups:
            r["group_primitive"] = groups.pop()

    # which routines can lead to a write of each signal (static calls only)
    writers = {}
    for sig in signals:
        names = {a["routine"] for a in sig["accesses"]
                 if a["kind"] in ("set", "clear", "write", "toggle")
                 and a["routine"] is not None}
        if names:
            writers[sig["name"]] = names
            sig["written_by"] = sorted(names)
    reached = effects.reach([routines[r] for r in sorted(routines)], writers)
    for sig in signals:
        if sig["name"] in reached:
            sig["reached_from"] = reached[sig["name"]]
    model["meta"]["signal_count"] = len(signals)
    model["meta"]["signal_access_count"] = len(accesses)


_CONFIG = ("direction", "function")


def format_signals(model):
    """Render the signals section of a model as a text report: grouped
    signals first (in group order), then ungrouped ones, each followed by its
    accesses; signals never accessed are listed at the end."""
    meta = model["meta"]
    lines = ["; m740recon signal report",
             "; device %s, %d signals, %d accesses" % (
                 meta["device"] or "?", meta.get("signal_count", 0),
                 meta.get("signal_access_count", 0)),
             ""]
    by_name = {s["name"]: s for s in model.get("signals", [])}
    ordered = []
    for g in model.get("groups", []):
        ordered.append(("group", g))
        ordered.extend(("signal", by_name[m]) for m in g["members"])
    grouped = {m for g in model.get("groups", []) for m in g["members"]}
    loose = [s for s in model.get("signals", []) if s["name"] not in grouped]
    if loose and model.get("groups"):
        ordered.append(("group", None))
    ordered.extend(("signal", s) for s in loose)

    never = []
    for what, item in ordered:
        if what == "group":
            if item is None:
                lines.append("[ungrouped]")
            else:
                title = "[group %s]" % item["name"]
                if item["description"]:
                    title += " " + item["description"]
                lines.append(title)
            lines.append("")
            continue
        lines.append(_signal_title(item))
        if not [a for a in item["accesses"] if a["kind"] not in _CONFIG]:
            # configuring a pin's direction or function is not using it
            lines.append("  (never accessed)")
            never.append(item)
        width = max([len(a["routine"] or "?") for a in item["accesses"]] + [8])
        for a in item["accesses"]:
            lines.append("  %s  %s  %-9s  %s" % (
                (a["routine"] or "?").ljust(width), a["site"], a["kind"],
                a["text"]))
        if item.get("reached_from"):
            shown = item["reached_from"][:8]
            more = len(item["reached_from"]) - len(shown)
            lines.append("  reached from %d routine(s): %s%s" % (
                len(item["reached_from"]), ", ".join(shown),
                (", +%d more" % more) if more else ""))
        lines.append("")

    if never:
        lines.append("; %d signal(s) never accessed:" % len(never))
        lines.extend(";   %s (%s)" % (s["name"], s["location"]) for s in never)
        lines.append("")

    for p in model.get("pointers", []):
        accs = p["accesses"]
        where = "%s%s" % (p["space"] + ":" if p["space"] else "", p["target"])
        title = "; pointer %s -> %s" % (p["address"], where)
        if p["comment"]:
            title += "  " + p["comment"]
        lines.append(title)
        resolved = [a for a in accs if a["locations"] is not None and
                    a["state"] not in ("off", "mode")]
        unknown = [a for a in accs if a["locations"] is None]
        program = [a for a in accs if a["state"] in ("off", "mode")]
        assumed = [a for a in resolved if a["state"] == "assumed"]
        lines.append(";   %d access(es): %d resolved (%d with the space "
                     "enable not proven), %d index unknown, %d to the "
                     "program space" % (len(accs), len(resolved), len(assumed),
                                        len(unknown), len(program)))
        for label, group in (("index unknown", unknown),
                             ("to the program space", program)):
            if group:
                lines.append(";   %s at: %s" % (label, ", ".join(
                    a["site"] for a in group)))
        lines.append("")

    if model.get("lint"):
        lines.append("; lint: %d finding(s) comparing the declarations with "
                     "the firmware:" % len(model["lint"]))
        lines.extend(";   [%s] %s" % (f["rule"], f["text"])
                     for f in model["lint"])
        lines.append("")

    routines = model.get("routines", [])
    leaves = [r for r in routines if r.get("effect")]
    if leaves:
        lines.append("; %d leaf routine(s) with fixed signal effects "
                     "(shown at each call site):" % len(leaves))
        for r in leaves:
            line = ";   %-20s -> %s" % (r["name"], "; ".join(r["effect"]))
            if r.get("suggested_name"):
                line += "   [suggested name: %s]" % r["suggested_name"]
            lines.append(line)
        lines.append("")
    prims = {}
    for r in routines:
        if r.get("group_primitive"):
            prims.setdefault(r["group_primitive"], []).append(r["name"])
    for g in sorted(prims):
        lines.append("; routines touching only group %s: %s" % (
            g, ", ".join(prims[g])))
    if prims:
        lines.append("")
    if any(s.get("reached_from") for s in model.get("signals", [])) and \
            model["meta"]["indirect_sites"]:
        lines.append("; 'reached from' follows static calls only; %d computed "
                     "call/jump site(s) are not followed, so it is a lower "
                     "bound" % model["meta"]["indirect_sites"])
    return "\n".join(lines).rstrip() + "\n"


def find_routine(model, key):
    """(start, end) of the routine named `key` or starting at address `key`
    (an int); end is the next routine's start or the end of the image.
    Returns None when there is no such routine."""
    roots = [int(r["address"], 16) for r in model["routines"]]
    names = [r["name"] for r in model["routines"]]
    if isinstance(key, int):
        if key not in roots:
            return None
        i = roots.index(key)
    elif key in names:
        i = names.index(key)
    else:
        return None
    meta = model["meta"]
    image_end = int(meta["start"], 16) + meta["length"]
    end = roots[i + 1] if i + 1 < len(roots) else image_end
    return roots[i], end


def format_signal(model, name):
    """The --signals report section for one signal, or None if unknown."""
    sigs = [s for s in model.get("signals", []) if s["name"] == name]
    if not sigs:
        return None
    one = dict(model)
    one["signals"] = sigs
    one["groups"] = []
    one["routines"] = []
    one["pointers"] = []          # pointers are not per-signal
    one["lint"] = [f for f in model.get("lint", [])
                   if f["text"].startswith(name + " (")]
    one["meta"] = dict(model["meta"])
    one["meta"]["signal_count"] = 1
    one["meta"]["signal_access_count"] = len(sigs[0]["accesses"])
    one["meta"]["indirect_sites"] = model["meta"]["indirect_sites"]
    return format_signals(one)


def _signal_title(sig):
    parts = []
    if sig["direction"]:
        parts.append(sig["direction"])
    if sig["active"]:
        parts.append("active %s" % sig["active"])
    if sig["high"]:
        parts.append("high = %s" % sig["high"])
    if sig["low"]:
        parts.append("low = %s" % sig["low"])
    title = "%s (%s)" % (sig["name"], sig["location"])
    if parts:
        title += "  " + ", ".join(parts)
    if sig["source"]:
        title += "   [source: %s]" % sig["source"]
    if sig["description"]:
        title += "  " + sig["description"]
    return title


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
        if r.get("signals"):
            lines.append("    signals: " + ", ".join(
                "%s(%s)" % (t["name"], ",".join(t["kinds"]))
                for t in r["signals"]))
        lines.append("")

    orphans = [r["name"] for r in model["routines"]
               if "subroutine" in r["kind"] and not r["called_by"]]
    if orphans:
        lines.append("; %d subroutine(s) with no static callers "
                     "(indirect-only or dead):" % len(orphans))
        lines.extend(";   %s" % n for n in orphans)

    return "\n".join(lines).rstrip() + "\n"
