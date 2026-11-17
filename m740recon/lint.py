"""Check a board description against what the firmware does.

Rules (each finding is one line of text):

  direction   a pin declared `in` or `out` is configured the other way by a
              constant write to its direction register
  unused      a declared signal is never read or written (configuring its
              direction or function does not count)
  out-read    a pin declared `out` is only ever read or tested
  in-written  a pin declared `in` is written by a bit or mask operation
  undeclared  a port bit the firmware singles out (bit instruction, mask,
              read-modify-write) has no declared signal

Findings are facts about the firmware relative to the declarations.  A
finding is not necessarily an error in either: a pin can legitimately be
switched between input and output at run time.
"""

_CONFIG = ("direction", "function")
_WRITES = ("set", "clear", "write", "toggle")


def _sites(accs, limit=6):
    sites = sorted({a.address for a in accs})
    text = ", ".join("0x%04x" % s for s in sites[:limit])
    if len(sites) > limit:
        text += ", +%d more" % (len(sites) - limit)
    return text


def check(smap, accesses, raw_accesses=()):
    """Return lint findings as (rule, text) pairs.

    `accesses` are the declared signals' accesses; `raw_accesses` those of
    the raw per-bit port map (discover.raw_signal_map), used to find port
    bits the firmware singles out that no signal covers."""
    by_sig = {}
    for a in accesses:
        by_sig.setdefault(a.signal.name, []).append(a)

    out = []
    for sig in smap.signals:
        accs = by_sig.get(sig.name, [])
        usage = [a for a in accs if a.kind not in _CONFIG]
        label = "%s (%s)" % (sig.name, sig.loc)

        if sig.direction in ("in", "out"):
            want = 1 if sig.direction == "out" else 0
            wrong = [a for a in accs if a.kind == "direction"
                     and a.level is not None and a.level != want]
            if wrong:
                other = "an input" if want else "an output"
                out.append(("direction", "%s: declared %s, but the firmware "
                            "makes it %s at %s" % (label, sig.direction,
                                                   other, _sites(wrong))))

        if not usage:
            out.append(("unused", "%s: never read or written by the "
                        "firmware" % label))
            continue

        writes = [a for a in usage if a.kind in _WRITES]
        if sig.direction == "out" and not writes:
            out.append(("out-read", "%s: declared out, but only ever read "
                        "or tested" % label))
        if sig.direction == "in":
            hard = [a for a in writes if a.scope in ("bit", "mask")]
            if hard:
                out.append(("in-written", "%s: declared in, but written at "
                            "%s" % (label, _sites(hard))))

    undeclared = {}
    for a in raw_accesses:
        if a.kind in _CONFIG or a.scope not in ("bit", "mask"):
            continue
        op = "read" if a.kind in ("test", "read") else "write"
        if smap.at(a.signal.address, a.signal.lo, None, op) is not None:
            continue
        undeclared.setdefault(a.signal.loc, []).append(a)
    for loc in sorted(undeclared, key=_loc_key):
        accs = undeclared[loc]
        out.append(("undeclared", "%s: singled out at %d site(s) (%s) but no "
                    "signal is declared" % (loc, len({a.address for a in accs}),
                                            _sites(accs))))
    return out


def _loc_key(loc):
    port, _, bit = loc.partition(".")
    digits = "".join(c for c in port if c.isdigit())
    return (int(digits) if digits else 0, port, int(bit) if bit.isdigit() else 0)
