"""Zero-configuration port discovery.

With no signals declared, report which port bits the firmware touches and
how, and give a direction for each.  `--suggest` turns the same facts into
control-file `pin` lines to paste and rename.

Ports come from the device's port metadata when it has some (see
devices.py); otherwise a "port" is any device SFR whose name is exactly P
followed by digits (P0, P1, ...).

A direction is taken from the firmware's own constant writes to the port's
direction register when there are any (out, in, or bidir when it writes
both).  Otherwise it is inferred from use and marked with '?': a bit the
firmware sets or clears is likely an output, a bit it only tests or reads
is likely an input.
"""

import re

from m740recon import control, signals
from m740recon.devices import Devices

_PORT_RE = re.compile(r"^P\d+$")
_CONFIG = ("direction", "function")
_WRITE_KINDS = ("set", "clear", "write", "toggle")


def has_metadata(device):
    return bool(Devices[device].get("ports"))


def port_registers(device):
    """[(name, data address)] of the device's ports, by port number."""
    meta = Devices[device].get("ports")
    if meta:
        ports = [(name, m["data"]) for name, m in meta.items()]
    else:
        ports = [(s.name, s.address) for s in Devices[device]["symbol_table"]
                 if _PORT_RE.match(s.name)]
    return sorted(ports, key=lambda p: int(p[0][1:]))


def raw_signal_map(device):
    """One guessed single-bit signal per bit of every port, named after its
    location (P0_6)."""
    decls = []
    locs = []
    for name, addr in port_registers(device):
        for bit in range(8):
            decls.append(control.SignalDecl(
                "pin", addr, bit, bit, "%s_%d" % (name, bit), None, None, None,
                None, "guess", "", "discovery"))
            locs.append("%s.%d" % (name, bit))
    smap = signals.build(decls, [], Devices[device]["symbol_table"])
    for sig, loc in zip(smap.signals, locs):
        sig.loc = loc
    return smap


def port_bit_map(device):
    """raw_signal_map() with each signal named by its port bit (P0.6), for
    listing annotations when no signals are declared."""
    smap = raw_signal_map(device)
    for sig in smap.signals:
        sig.name = sig.loc
        sig.source = None
    return smap


_BIT_RUN = re.compile(r"P(\d)\.\d(?:, P\1\.\d)+")


def compact_bits(text):
    """Shorten runs of consecutive port bits: 'P3.3, P3.4, P3.5' -> 'P3.3-5'."""
    def fold(m):
        port = m.group(1)
        bits = [int(b) for b in re.findall(r"P%s\.(\d)" % port, m.group(0))]
        out, i = [], 0
        while i < len(bits):
            j = i
            while j + 1 < len(bits) and bits[j + 1] == bits[j] + 1:
                j += 1
            out.append("P%s.%d" % (port, bits[i]) if j - i < 2 else
                       "P%s.%d-%d" % (port, bits[i], bits[j]))
            if 0 < j - i < 2:
                out.extend("P%s.%d" % (port, b) for b in bits[i + 1:j + 1])
            i = j + 1
        return ", ".join(out)
    return _BIT_RUN.sub(fold, text)


def rows(model):
    """Per touched port bit: dict(loc, name, address, counts, direction,
    certain, routines, specific), in port/bit order.  `model` is a report
    model built with the raw signal map.

    A bit is touched when some access reads or writes it (configuring its
    direction alone does not count).  It is `specific` when some instruction
    singles it out (a bit instruction, a mask, a read-modify-write).
    `direction` is 'out' / 'in' / 'bidir' / None; `certain` is True when it
    comes from direction-register writes rather than from use.  A bit
    touched only by whole-register accesses gets no use-inferred direction:
    such accesses say nothing about how one pin is wired.  For an input,
    whole-register writes do not count as touching it, matching how a
    declared input is analyzed (writing an input's latch has no effect
    outside the chip)."""
    out = []
    for sig in model.get("signals", []):
        accs = sig["accesses"]
        usage = [a for a in accs if a["kind"] not in _CONFIG]
        if not usage:
            continue
        levels = {a["level"] for a in accs
                  if a["kind"] == "direction" and a["level"] is not None}
        evidence = [a for a in usage if a["scope"] in ("bit", "mask")]
        certain = bool(levels)
        if levels:
            direction = {frozenset([1]): "out", frozenset([0]): "in"}.get(
                frozenset(levels), "bidir")
        elif evidence:
            writes = [a for a in evidence if a["kind"] in _WRITE_KINDS]
            direction = "out" if writes else "in"
        else:
            direction = None
        if direction == "in":
            usage = [a for a in usage
                     if not (a["kind"] == "write" and a["scope"] == "register")]
            if not usage:
                continue
        counts = {}
        for a in usage:
            counts[a["kind"]] = counts.get(a["kind"], 0) + 1
        routines = []
        for a in usage:
            r = a["routine"] or "?"
            if r not in routines:
                routines.append(r)
        out.append({"loc": sig["location"], "name": sig["name"],
                    "address": int(sig["address"], 16), "bit": sig["bits"][0],
                    "counts": counts, "direction": direction,
                    "certain": certain, "routines": routines,
                    "specific": bool(evidence)})
    return out


def _counts_text(counts):
    order = ("test", "read", "set", "clear", "write", "toggle")
    return ", ".join("%d %s" % (counts[k], k) for k in order if k in counts)


def _direction_text(row):
    if row["direction"] is None:
        return "-"
    return row["direction"] + ("" if row["certain"] else "?")


def format_discovery(model, device):
    ports = port_registers(device)
    names = " ".join(n for n, _ in ports) or "(none)"
    lines = ["; m740recon port discovery (no signals declared)"]
    if has_metadata(device):
        lines += ["; device %s; ports from device metadata: %s" % (device, names),
                  "; direction: from the firmware's direction-register writes,",
                  "; or inferred from use where marked '?' (set/cleared = likely",
                  "; output, only tested/read = likely input)."]
    else:
        lines += ["; device %s; ports examined: %s" % (device, names),
                  "; a port is a device SFR named P<digit>; direction, function and",
                  "; input-latch registers are not examined.  Directions are inferred:",
                  "; a bit the firmware sets or clears is likely an output, a bit it",
                  "; only tests or reads is likely an input."]
    lines.append("")
    found = rows(model)
    if not found:
        lines.append("; no port bit accesses found")
    specific = [r for r in found if r["specific"]]
    whole = [r for r in found if not r["specific"]]
    for row in specific:
        lines.append(_row_text(row))
    if whole:
        lines.append("")
        lines.append("; touched only by whole-register reads/writes:")
        for row in whole:
            lines.append(_row_text(row))
    lines.append("")
    lines.append("; run with --suggest for control-file lines to start from")
    return "\n".join(lines) + "\n"


def _row_text(row):
    shown = ", ".join(row["routines"][:6])
    if len(row["routines"]) > 6:
        shown += ", +%d more" % (len(row["routines"]) - 6)
    return "%-6s %-6s %-28s %s" % (row["loc"], _direction_text(row),
                                   _counts_text(row["counts"]), shown)


def format_suggest(model, device, declared=None):
    """Control-file lines for touched port bits.  Bits already covered by a
    signal in `declared` (a SignalMap) are skipped, so the output can be
    appended to the control file it came from.  A bit with no known
    direction is emitted commented out."""
    lines = ["# m740recon --suggest: one pin line per port bit the firmware",
             "# touches.  Rename each signal, add high=/low= or active=, and",
             "# change source=guess once a fact is confirmed.",
             "# device %s" % device,
             ""]
    # locations must resolve when the lines are read back: use the device's
    # name for the register (P4IN on the M50734, not the port name P4) or a
    # number; names must not clash with signals already declared
    sfr = {}
    for sym in Devices[device]["symbol_table"]:
        if not sym.weak:
            sfr.setdefault(sym.address, sym.name)
    taken = set(declared.by_name) if declared is not None else set()
    skipped = 0
    for row in rows(model):
        if declared and declared.at(row["address"], row["bit"]):
            skipped += 1
            continue
        loc = "%s.%d" % (sfr.get(row["address"], "0x%02x" % row["address"]),
                         row["bit"])
        name = row["name"]
        suffix = 2
        while name in taken:
            name = "%s_%d" % (row["name"], suffix)
            suffix += 1
        taken.add(name)
        note = _counts_text(row["counts"])
        if not row["specific"]:
            note += ", whole-register only"
        if row["direction"] is not None:
            if not row["certain"]:
                note += ", direction inferred from use"
            lines.append("pin %-6s %-6s %-5s source=guess   # %s" % (
                loc, name, row["direction"], note))
        else:
            lines.append("#pin %-6s %-6s       source=guess   # %s" % (
                loc, name, note))
    if skipped:
        lines.append("# %d touched bit(s) already declared, not repeated"
                     % skipped)
    return "\n".join(lines) + "\n"
