"""`--suggest`: a draft control file from everything m740recon found.

Every finding becomes a control-file line followed by `# conf=WORD  reason`:
  proven   follows from the code (vectors, a table the code hands to a
           search routine or walks in a counted loop)
  high     detection with a wide margin
  medium   detection with a narrow margin, or code found by evidence
  low      shown for review only: written commented out
The draft always parses as a control file.  With `-c`, only what the file
does not already say is written, so the output can be appended to it.

Lines that would change how the file is used are written commented out:
a `segment` line means the binary is no longer passed on the command line,
so the detected memory map is offered, not imposed.
"""

import os


def _conf(word, reason):
    return "# conf=%s  %s" % (word, reason)


def _line(directive, conf, reason, live=True, width=46):
    text = directive if live else "# " + directive
    return "%-*s %s" % (width, text, _conf(conf, reason))


def _source(path, off):
    """A segment SOURCE token for `path`: absolute, since the draft may be
    saved anywhere, and quoted when the control-file tokenizer needs it."""
    tok = "%s@0x%x" % (os.path.abspath(path).replace("\\", "/"), off)
    if any(c.isspace() or c in "#\"'" for c in tok):
        tok = '"%s"' % tok.replace('"', '\\"')
    return tok


def _clean(t):
    """Text safe inside a control-file comment."""
    return t.replace('"', "'").replace("#", "")


def build(cf, device, device_given, detection, memory, placed,
          inferred, dropped, pin_text, annotations=None):
    """Return the draft as text.

    cf            the control file given with -c, or None
    device        the device in use; device_given when -m / cf named it
    detection     the CLI's detection dict (base, device, bank, unmapped...)
    memory        traced memory (with .dispatch_tables)
    placed        [(path, base, size, file offset)] of the binaries given
    inferred      [infer.Discovery] kept; dropped {address: [reasons]}
    pin_text      discover.format_suggest output (pin lines)
    """
    out = ["# m740recon --suggest: a draft control file built from what the firmware",
           "# shows.  Each line ends with how sure m740recon is and why; lines with",
           "# conf=low are commented out.  Keep, rename or delete lines, then run",
           ("#   m740recon -c THIS_FILE %s" % " ".join(p for p, _, _, _ in placed))
           if placed else "#   m740recon -c THIS_FILE",
           ""]

    # -- the chip and the memory map --------------------------------------
    before = len(out)
    if not device_given:
        d = detection.get("device")
        if d:
            conf = d["confidence"]
            reason = d["reason"] + ("; runner-up %s" % d["runner_up"] if d.get("runner_up") else "")
            out.append(_line("device %s" % device, conf, reason, live=conf != "low"))
        else:
            out.append(_line("device %s" % device, "low", "default; not detected", live=False))
    if placed and not (cf is not None and cf.segments):
        files = detection.get("files") or [detection.get("base", {})]
        for n, ((path, base, size, off), info) in enumerate(zip(placed, files)):
            name = "rom" if len(placed) == 1 else "rom%d" % (n + 1)
            seg = "segment %s 0x%04x 0x%05x %s" % (name, base, base + size,
                                               _source(path, off))
            why = ("load address: %s.  Uncomment to fix the memory map; then run "
                   "without the binary argument" % info.get("reason", ""))
            out.append(_line(seg, info.get("confidence", "medium"), why, live=False))
    for u in detection.get("unmapped", []):
        out.append(_line("segment other %s %s OTHER_ROM.bin@0x0" % (u["from"], "0x%04x" % (int(u["to"], 16) + 1)),
                         "low", "%d calls and jumps go here, outside this image; another ROM?"
                         % u["references"], live=False))
    if len(out) > before:
        out.append("")

    # -- dispatch tables the code proves ----------------------------------
    known_tables = {t.start for t in cf.addr_tables} if cf is not None else set()
    tables = [f for f in getattr(memory, "dispatch_tables", []) if f.table.start not in known_tables]
    if tables:
        out.append("# dispatch tables (handlers are named tbl_ADDR_KEY; rename the prefix)")
        for f in tables:
            t = f.table
            parts = ["addrtable 0x%04x stride=%d entryoff=%d" % (t.start, t.stride, t.entryoff)]
            if t.keyoff is not None:
                parts.append("keyoff=%d" % t.keyoff)
            if t.terminator is not None:
                parts.append("terminator=0x%02x" % t.terminator)
            if t.count is not None:
                parts.append("count=%d" % t.count)
            parts.append("label=%s" % t.label_prefix)
            if t.names:
                parts.append("names=%s" % t.names)
            proof = {"search": "handed to the search routine at 0x%04x",
                     "loop": "walked by the counted loop at 0x%04x"}[f.kind] % f.site
            out.append(_line(" ".join(parts), "proven", "%d records; %s" % (f.records, proof)))
        out.append("")

    # -- code found by evidence -------------------------------------------
    known_entries = set(cf.entry_points) if cf is not None else set()
    known_names = {s.address for s in cf.symbols} if cf is not None else set()
    fresh = [d for d in inferred if d.address not in known_entries | known_names]
    if fresh or dropped:
        out.append("# code found by evidence, not proof (--advanced)")
        for d in fresh:
            out.append(_line("entry 0x%04x" % d.address, d.confidence, d.reason))
        for a, why in sorted(dropped.items()):
            if a in known_entries:
                continue
            out.append(_line("entry 0x%04x" % a, "low", "dropped: " + "; ".join(why[:2]),
                             live=False))
        out.append("")

    # -- memory and data the code does not execute ---------------------------
    if annotations:
        regions, lcd, fonts, texts = annotations
        labelled = {sym.address for sym in cf.symbols} if cf is not None else set()
        typed = [(r0, r1) for r0, r1, _ in cf.ranges] if cf is not None else []

        def overlaps(r):
            return any(r.start < b and a < r.end for a, b in typed)
        info = [r for r in regions]
        if info or lcd:
            out.append("# memory the code uses outside this image")
            for r in info:
                out.append("#   %-4s 0x%04x-0x%04x  %s" % (r.kind, r.start, r.end - 1, r.note))
            for addr, cmds in lcd:
                if addr in labelled:
                    continue
                out.append(_line("label 0x%04x lcd_cmd" % addr, "medium",
                                 "only written; gets HD44780 commands %s"
                                 % ", ".join("0x%02x" % c for c in cmds)))
            out.append("")
        fonts = [r for r in fonts if not overlaps(r)]
        texts = [r for r in texts if not overlaps(r)]
        if fonts or texts:
            out.append("# data: fonts and text (no traced code inside)")
            for r in fonts:
                big = r.end - r.start >= 0x1000
                out.append(_line("range 0x%04x 0x%04x byte" % (r.start, r.end),
                                 "medium" if big else "low",
                                 "font: dot-matrix glyph columns, %d bytes" % (r.end - r.start),
                                 live=big))
            for r in texts:
                sample = _clean(r.note[:40])
                out.append(_line("range 0x%04x 0x%04x text" % (r.start, r.end), "medium",
                                 "text: '%s'" % sample))
            out.append("")

    # -- signals (the pin survey) -----------------------------------------
    pins = [l for l in pin_text.splitlines()
            if l.startswith("pin ") or l.startswith("#pin ") or "already declared" in l]
    if pins:
        out.append("# port bits the firmware touches: rename each signal, add high=/low= or")
        out.append("# active=, and change source=guess once a fact is confirmed")
        out.extend(pins)
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"
