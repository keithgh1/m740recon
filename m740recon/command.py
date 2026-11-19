'''
Usage: m740recon [options] [-c controlfile] [<rom.bin> ...]

Options:
  -m, --mcutype TYPE   select the MCU type (default: detected from the image
                       and named in the listing header)
  -c, --control FILE   read a control file for entry points, labels, the
                       device, and/or a segment memory map (see control.py).
                       If the control file defines segments, the image is
                       built from them and no binary argument is given.
                       Otherwise each binary is placed where its code
                       says it belongs (load address inferred); several
                       binaries (e.g. two EPROMs) are placed side by side.
  -A, --advanced       also look for code by evidence rather than proof
                       (pointer tables, code after routine ends); every entry
                       found this way is marked "inferred" in the listing
  -a, --analyze        (always on now) value tracking of computed jumps
  -x, --xref           annotate labels with '; xref:' lines listing the
                       instructions that reference each address
      --auto-tables    same as --advanced
  -j, --json           emit a machine-readable JSON model (routines, call
                       edges, vectors, symbols, xrefs) instead of the listing
  -g, --call-graph     emit a human-readable call-graph report instead of the
                       listing
  -s, --signals        emit a report of every declared pin/bit signal and the
                       instructions that access it, instead of the listing
                       With no signals declared, reports which port bits the
                       firmware touches and infers their direction instead
      --suggest        print a draft control file: device, memory map,
                       dispatch tables, code found by evidence and pin lines,
                       each with its confidence and reason (with -c: only
                       what the file does not already say)
      --suggest=pins   only the pin lines (the earlier --suggest output)
      --signal NAME    print the --signals report for one signal only
      --routine R      print the code of one routine only: everything
                       reachable from its entry without entering another
                       routine (R is a routine name or a hex address such
                       as 0x8130); for reading, not for reassembly
      --no-annotate    do not add hardware-signal comments to the listing
                       (they are added only when the control file defines
                       pin/bit signals)
  -h, --help           show this help

'''

import os, sys, getopt

from m740recon.disasm import disassemble
from m740recon.trace import Tracer
from m740recon.memory import Memory
from m740recon.listing import Printer
from m740recon.symbols import SymbolTable
from m740recon.devices import Devices
from m740recon import control


class _AddressSet(object):
    """Addresses in a list of [start, end) ranges: membership like a range,
    iteration in address order."""

    def __init__(self, ranges):
        self.ranges = sorted(ranges)
        self._mask = bytearray(0x10001)
        for s, e in self.ranges:
            self._mask[s:e] = b"\x01" * (e - s)

    def __contains__(self, address):
        return 0 <= address <= 0x10000 and self._mask[address] == 1

    def __iter__(self):
        for s, e in self.ranges:
            for a in range(s, e):
                yield a


def build_disassembly(rom, device, start_address, entry_points=(),
                      vectors_extra=(), data_addrs=(), extra_symbols=(),
                      analyze=False, readonly_ranges=None, word_addrs=(),
                      addr_word_addrs=(), text_ranges=(), discover_tables=False,
                      proven=True, trace_ranges=None):
    """Trace and symbol-analyze an image; return (memory, symbol_table).

    Shared by the CLI and the test harness so both follow the exact same path.
    When analyze is set, value tracking resolves indirect jumps/calls; pointers
    read through `jmp [abs]` are trusted only inside readonly_ranges (defaults
    to the whole image, which is correct for a single ROM).

    With `proven` (the default), dispatch tables that the code itself proves
    (see dispatch.py) are decoded too, to a fixpoint: each round's new code
    can reveal the next table.  They are recorded on `memory.dispatch_tables`
    and named below any symbol in `extra_symbols`, so user names win.

    `trace_ranges` ([(start, end)]) limits tracing to the bytes that came from
    files when `rom` is padded (an image below the top of memory, or gaps
    between files); calls into the padding are not followed.
    """
    if trace_ranges is None:
        traceable_range = range(start_address, start_address + len(rom) + 1)
    else:
        traceable_range = _AddressSet(trace_ranges)
    # the device's own vectors that the image does not cover cannot be traced
    # (e.g. a 13-bit part's 0x1ff4 table when the ROM sits higher); extra
    # vectors from a control file must still be inside and are checked later
    device_vectors = [v for v in Devices[device]["vector_table"] if v in traceable_range]
    if readonly_ranges is None:
        readonly_ranges = [(start_address, start_address + len(rom))]
    # opcodes the selected core does not implement are decoded as data
    unsupported = Devices[device].get("unsupported_opcodes", frozenset())
    decoder = disassemble
    if unsupported:
        decoder = lambda mem, pc: disassemble(mem, pc, unsupported)

    def trace(more_vectors=(), more_data=()):
        memory = Memory(bytearray(rom))
        for addr in list(data_addrs) + list(more_data):
            if memory.is_unknown(addr):
                memory.set_data(addr)
        for addr in word_addrs:
            memory.set_word(addr)
        for addr in addr_word_addrs:
            memory.set_vector(addr)     # rendered as .word with symbol substitution
        for start, end in text_ranges:
            memory.set_text(start, end)
        vectors = device_vectors + list(vectors_extra) + list(more_vectors)
        Tracer(memory, list(entry_points), vectors, traceable_range,
               analyze=analyze or discover_tables, readonly_ranges=readonly_ranges,
               discover_tables=discover_tables).trace(decoder)
        return memory

    memory = trace()
    found, table_ptrs, table_data, table_syms = [], [], [], []
    if proven and readonly_ranges:
        from m740recon import dispatch
        lo = min(s for s, _ in readonly_ranges)
        hi = max(e for _, e in readonly_ranges)
        used = {sym.name for sym in extra_symbols}
        # terminates: each round must add a table start not seen before
        while True:
            new = dispatch.find_tables(memory, lo, hi, unsupported,
                                       known=[f.table.start for f in found])
            # only tables inside trusted (ROM) ranges
            new = [f for f in new
                   if any(rs <= f.table.start < re_ for rs, re_ in readonly_ranges)]
            if not new:
                break
            found += new
            for f in new:
                ptrs, data, syms = control.resolve_addr_tables([f.table], memory, used)
                if f.kind == "loop":
                    # the record layout around the pointer is unknown: type only
                    # the span from the first pointer to the end of the last one
                    t = f.table
                    end = t.start + (f.records - 1) * t.stride + 2
                    data = [d for d in data if t.start <= d < end]
                table_ptrs += [p for p in ptrs if p in traceable_range]
                table_data += data
                table_syms += syms
            memory = trace(table_ptrs, table_data)
    memory.dispatch_tables = found
    # what the proven tier added, so a caller can rebuild without searching again
    memory.dispatch_inputs = (list(table_ptrs), list(table_data), list(table_syms))
    symbol_table = SymbolTable(list(Devices[device]["symbol_table"]) + table_syms +
                               list(extra_symbols))
    symbol_table.analyze_symbols(memory)
    return memory, symbol_table


def build_signal_map(cf, device):
    """Resolve the control file's pin/bit/group declarations for `device`.
    Returns an empty SignalMap when none are declared."""
    from m740recon import signals
    if cf is None or not (cf.signals or cf.pointers):
        if cf is not None and cf.groups:
            raise control.ControlError(
                "%s: group declared but no pin/bit signals" % cf.groups[0].where)
        return signals.SignalMap()
    syms = list(Devices[device]["symbol_table"]) + list(cf.symbols)
    return signals.build(cf.signals, cf.groups, syms, cf.pointers)


def signal_accesses(memory, smap, device=None, pointer_sites=None):
    from m740recon import access
    dev = Devices[device] if device else {}
    return access.classify(memory, smap, dev.get("ports"), dev.get("spaces"),
                           pointer_sites)


def signal_lint(memory, smap, accesses, device):
    """Lint findings [(rule, text)] for the declared signals; empty when
    none are declared."""
    if not smap:
        return []
    from m740recon import discover, lint
    raw = discover.raw_signal_map(device)
    return lint.check(smap, accesses, signal_accesses(memory, raw, device))


def routine_blocks(memory, start, roots):
    """The code of the routine entered at `start`: every instruction
    reachable from it by fallthrough and static branches, without entering
    other routines (`roots`, the entries of all routines) or following
    calls.  Returns ([(start, end) of each contiguous run], {entries of
    other routines it jumps or falls into})."""
    from m740recon.tables import FlowTypes
    seen = set()
    exits = set()
    todo = [start]
    while todo:
        addr = todo.pop()
        if addr in seen or not memory.is_instruction_start(addr):
            continue
        if addr != start and addr in roots:
            exits.add(addr)
            continue
        seen.add(addr)
        inst = memory.get_instruction(addr)
        flow = inst.flow_type
        if flow in (FlowTypes.Continue, FlowTypes.ConditionalJump,
                    FlowTypes.SubroutineCall, FlowTypes.IndirectSubroutineCall):
            todo.append((addr + len(inst)) & 0xFFFF)
        if flow in (FlowTypes.ConditionalJump, FlowTypes.UnconditionalJump):
            target = inst.code_ref_address
            if target is not None:
                todo.append(target)
    runs = []
    for addr in sorted(seen):
        end = addr + len(memory.get_instruction(addr))
        if runs and runs[-1][1] == addr:
            runs[-1] = (runs[-1][0], end)
        else:
            runs.append((addr, end))
    return runs, exits


def control_comments(cf):
    """Map addresses to user comment text (from `comment` and label comments)."""
    comments = dict(cf.comments)
    for sym in cf.symbols:
        if sym.comment:
            comments.setdefault(sym.address, sym.comment)
    return comments


def control_args(cf, rom, base=0):
    """Translate a ControlFile into build_disassembly keyword arguments.
    `rom` is the image as loaded at `base`.

    Symbol precedence (later overrides earlier in SymbolTable): device symbols,
    then addrtable-generated names, then explicit `label`/`entry` names.
    """
    image = rom
    if base or len(rom) < 0x10000:
        # tables name absolute addresses
        image = bytearray(b"\xff" * 0x10000)
        image[base:base + len(rom)] = rom
    pointer_addrs, data_addrs, table_symbols = cf.resolve_tables(
        image, base, min(base + len(rom), 0x10000))
    word_addrs, addr_word_addrs, text_ranges = [], [], []
    for start, end, kind in cf.ranges:
        if kind == "byte":
            data_addrs.extend(range(start, end))
        elif kind == "word":
            word_addrs.extend(range(start, end, 2))
        elif kind == "addr":
            addr_word_addrs.extend(range(start, end, 2))
        elif kind == "text":
            text_ranges.append((start, end))
    kwargs = dict(
        entry_points=list(cf.entry_points),
        vectors_extra=pointer_addrs,
        data_addrs=data_addrs,
        extra_symbols=list(table_symbols) + list(cf.symbols),
        word_addrs=word_addrs,
        addr_word_addrs=addr_word_addrs,
        text_ranges=text_ranges,
    )
    # When a control file defines a memory map, only file-backed (ROM) segments
    # are trustworthy for pointer analysis; pointers in zero/RAM segments are
    # not.  Restrict readonly_ranges to the ROM segments -- possibly empty, so an
    # all-RAM map trusts nothing -- rather than letting it default to the whole
    # image.  (With no segments, the binary path's whole-image default applies.)
    if cf.segments:
        kwargs["readonly_ranges"] = [(s.start, s.end)
                                     for s in cf.segments if s.kind == "file"]
    return kwargs


def _require_data(path, data):
    if not data:
        sys.stderr.write("m740recon: %s is empty.\n" % path)
        sys.exit(2)


def place_binary(rom, header, notices, detection):
    """Choose where a lone binary sits in memory (and which bank of an image
    larger than 64 KiB to use).  Returns (image bytes, base address); exits
    when the image cannot be placed without a control file."""
    from m740recon import detect
    if len(rom) > 0x10000:
        banks = detect.split_banks(rom)
        if len(banks) != 1:
            offs = ", ".join("0x%05x" % off for off, _ in banks) or "none"
            sys.stderr.write(
                "m740recon: the file is %d KiB, more than the 64 KiB a 740 can "
                "address, and %d of its 32 KiB banks hold data (file offsets %s).\n"
                "Describe which bank sits where with segment lines in a control "
                "file (see AGENTS.md).\n" % (len(rom) // 1024, len(banks), offs))
            sys.exit(2)
        off, data = banks[0]
        header.append("bank    file 0x%05x-0x%05x   the only programmed 32 KiB bank of %d KiB"
                      % (off, off + len(data) - 1, len(rom) // 1024))
        notices.append("the file is %d KiB; only the 32 KiB bank at file offset 0x%05x "
                       "holds data, so that bank is disassembled" % (len(rom) // 1024, off))
        detection["bank"] = {"file_offset": "0x%05x" % off, "size": len(data)}
        rom = bytearray(data)
    guess = detect.infer_base(rom)
    if guess.base is None:
        base = 0x10000 - len(rom)
        # the long-standing default; worth a header line, not a notice
        header.append("base    0x%04x   assumed (top of memory): %s; a segment line "
                      "sets it" % (base, guess.reason))
        detection["base"] = {"address": "0x%04x" % base, "method": "assumed",
                             "confidence": "low", "reason": guess.reason}
    else:
        base = guess.base
        how = "given by size" if guess.method == "fills" else "detected (%s)" % guess.confidence
        header.append("base    0x%04x   %s: %s" % (base, how, guess.reason))
        detection["base"] = {"address": "0x%04x" % base, "method": guess.method,
                             "confidence": guess.confidence, "reason": guess.reason}
    return rom, base


def fit_control_file(cf, size, base, header, detection):
    """A control file without segments was written against some placement
    of the binary.  When its entry points and tables lie outside the
    detected placement but inside the top-of-memory one (where the binary
    sat before detection existed), use the top of memory."""
    addrs = list(cf.entry_points) + [t.start for t in cf.addr_tables]
    top = 0x10000 - size

    def covers(b):
        return all(b <= a < b + size for a in addrs)

    if not addrs or base == top or covers(base) or not covers(top):
        return base
    reason = ("the control file's entry points and tables lie there, not at the "
              "detected 0x%04x" % base)
    header[:] = [h for h in header if not h.startswith("base ")]
    header.append("base    0x%04x   from the control file: %s" % (top, reason))
    detection["base"] = {"address": "0x%04x" % top, "method": "control",
                         "confidence": "high", "reason": reason}
    return top


def place_files(paths, header, detection):
    """Place several ROM files, each at its own inferred load address.
    Returns (image bytes from the lowest base, lowest base, placed) where
    placed is [(path, base, size, file offset)].  Exits with segment lines to
    fill in when a file cannot be placed or two files overlap."""
    from m740recon import detect
    placed, problems = [], []
    for path in paths:
        with open(path, "rb") as f:
            data = f.read()
        _require_data(path, data)
        off = 0
        if len(data) > 0x10000:
            banks = detect.split_banks(data)
            if len(banks) != 1:
                problems.append("%s: %d KiB with %d programmed 32 KiB banks"
                                % (path, len(data) // 1024, len(banks)))
                continue
            off, data = banks[0]
        guess = detect.infer_base(data)
        if guess.base is None:
            problems.append("%s: no load address stands out (%s)" % (path, guess.reason))
            continue
        placed.append((path, guess.base, len(data), off, data, guess))
    spans = sorted((b, b + n, p) for p, b, n, _, _, _ in placed)
    for (a0, a1, p0), (b0, b1, p1) in zip(spans, spans[1:]):
        if b0 < a1:
            problems.append("%s (0x%04x-0x%04x) overlaps %s (0x%04x-0x%04x)"
                            % (p0, a0, a1 - 1, p1, b0, b1 - 1))
    if problems:
        sys.stderr.write("m740recon: cannot place the files on their own:\n")
        for text in problems:
            sys.stderr.write("  %s\n" % text)
        sys.stderr.write("Describe the memory map in a control file instead, e.g.:\n")
        for path in paths:
            sys.stderr.write("  segment NAME 0xSTART 0xEND %s@0x0\n" % path)
        sys.exit(2)
    lo = min(b for _, b, _, _, _, _ in placed)
    hi = max(b + n for _, b, n, _, _, _ in placed)
    image = bytearray(b"\xff" * (hi - lo))
    for path, base, n, off, data, guess in placed:
        image[base - lo:base - lo + n] = data
        header.append("file    %s at 0x%04x-0x%04x, %s (%s): %s"
                      % (os.path.basename(path), base, base + n - 1,
                         "given by size" if guess.method == "fills" else "detected",
                         guess.confidence, guess.reason))
    detection["files"] = [{"path": p, "base": "0x%04x" % b, "size": n,
                           "confidence": g.confidence, "reason": g.reason}
                          for p, b, n, _, _, g in placed]
    return image, lo, [(p, b, n, off) for p, b, n, off, _, _ in placed]


def choose_device(data, base, default, header, notices, detection):
    """Detect the device when the user did not name one."""
    from m740recon import detect
    guess = detect.detect_device(data, base, build=build_disassembly)
    if guess.device is None:
        header.append("device  %s   default: %s" % (default, guess.reason))
        notices.append("could not detect the device (%s); using %s.  Name the chip "
                       "with -m." % (guess.reason, default))
        return default
    if not guess.fits and guess.vector_fit <= 0:
        # no vector of any layout points at code: the best row is no
        # evidence, so keep the default rather than let it change decoding.
        # (A partial fit, e.g. only the reset vector set, still is evidence.)
        reason = "no device's vectors fit (best %s: %s)" % (guess.device, guess.reason)
        header.append("device  %s   default: %s" % (default, reason))
        detection["device"] = {"name": default, "confidence": "low", "reason": reason,
                               "runner_up": None, "fits": False}
        notices.append("this does not look like 740 code (%s); using %s.  Name "
                       "the chip with -m if you know it." % (reason, default))
        return default
    runner = "; runner-up %s" % guess.runner_up if guess.runner_up else ""
    header.append("device  %s   detected (%s): %s%s"
                  % (guess.device, guess.confidence, guess.reason, runner))
    detection["device"] = {"name": guess.device, "confidence": guess.confidence,
                           "reason": guess.reason, "runner_up": guess.runner_up,
                           "fits": guess.fits}
    if not guess.fits:
        notices.append("this does not look like 740 code (%s); using %s anyway.  Name "
                       "the chip with -m if you know it." % (guess.reason, guess.device))
    elif guess.confidence != "high":
        notices.append("the device is a close call: %s (%s), runner-up %s.  Name the "
                       "chip with -m if you know it." % (guess.device, guess.reason,
                                                        guess.runner_up))
    return guess.device


def report_tables(memory, header, detection):
    """Name the dispatch tables the proven tier decoded."""
    found = getattr(memory, "dispatch_tables", [])
    if not found:
        return
    how = {"search": "handed to the search routine", "loop": "walked by a counted loop"}
    handlers = sum(f.records for f in found)
    header.append("tables  %d dispatch table%s, %d handlers (proven by the code): %s"
                  % (len(found), "" if len(found) == 1 else "s", handlers,
                     ", ".join("0x%04x" % f.table.start for f in found)))
    detection["tables"] = [{"address": "0x%04x" % f.table.start, "records": f.records,
                            "stride": f.table.stride, "pointer_offset": f.table.entryoff,
                            "proof": how[f.kind], "site": "0x%04x" % f.site}
                           for f in found]


def report_inferred(inferred, dropped, header, detection):
    """Summarize the inferred tier (--advanced)."""
    tables = sum(1 for d in inferred if d.source.startswith("table"))
    gaps = len(inferred) - tables
    header.append("advanced %d entries inferred (%d from tables, %d from gaps), %d dropped "
                  "as contradictory" % (len(inferred), tables, gaps, len(dropped)))
    detection["inferred"] = [{"address": "0x%04x" % d.address, "source": d.source,
                              "confidence": d.confidence, "reason": d.reason}
                             for d in inferred]
    detection["dropped"] = [{"address": "0x%04x" % a, "reasons": why}
                            for a, why in sorted(dropped.items())]


def annotations(memory, ranges, detection):
    """Memory map, LCD ports, fonts and text (annotate.py) over the ROM
    `ranges`; also recorded in the detection dict for the JSON model."""
    from m740recon import annotate
    regions, lcd, fonts, texts = [], [], [], []
    lo = min(a for a, _ in ranges)
    hi = max(b for _, b in ranges)
    for a, b in ranges:
        f = annotate.fonts(memory, a, b)
        fonts += f
        texts += annotate.text(memory, a, b, avoid=f)
    regions, lcd = annotate.memory_map(memory, lo, hi)
    regions = [r for r in regions if not any(a <= r.start < b for a, b in ranges)]
    detection["annotations"] = {
        "memory": [{"from": "0x%04x" % r.start, "to": "0x%04x" % (r.end - 1), "kind": r.kind}
                   for r in regions],
        "lcd": ["0x%04x" % a for a, _ in lcd],
        "fonts": [{"from": "0x%04x" % r.start, "to": "0x%04x" % (r.end - 1)} for r in fonts],
        "text": [{"from": "0x%04x" % r.start, "to": "0x%04x" % (r.end - 1), "text": r.note}
                 for r in texts]}
    return regions, lcd, fonts, texts


def report_unmapped(memory, lo, hi, header, notices, detection):
    """Say when code calls into address space no image covers."""
    from m740recon import detect
    runs = detect.unmapped_targets(memory, lo, hi)
    if not runs:
        return
    where = ", ".join("0x%04x-0x%04x" % (a << 8, (b << 8) | 0xFF) for a, b, _ in runs)
    count = sum(n for _, _, n in runs)
    header.append("note    %d calls and jumps go to %s, outside this image: another ROM?"
                  % (count, where))
    notices.append("%d calls and jumps go to %s, outside this image.  If another ROM "
                   "lives there, describe both with segment lines in a control file."
                   % (count, where))
    detection["unmapped"] = [{"from": "0x%04x" % (a << 8), "to": "0x%04x" % ((b << 8) | 0xFF),
                              "references": n} for a, b, n in runs]


def main():

    # --suggest takes an optional scope (--suggest=pins); getopt cannot
    # express an optional argument, so normalize it first
    argv, suggest_scope = [], "all"
    for a in sys.argv[1:]:
        if a.startswith("--suggest="):
            suggest_scope = a.split("=", 1)[1]
            if suggest_scope not in ("all", "pins"):
                sys.stderr.write("--suggest scope must be 'all' or 'pins'\n")
                sys.exit(1)
            a = "--suggest"
        argv.append(a)
    try:
        opts, args = getopt.getopt(argv, "hm:c:axjgsA",
                                   ["help", "mcutype=", "control=", "analyze", "advanced",
                                    "xref", "auto-tables", "json", "call-graph",
                                    "no-annotate", "signals", "suggest",
                                    "signal=", "routine="])
    except getopt.GetoptError:
        sys.stderr.write(__doc__)
        sys.exit(1)

    default_device  = "M3886"
    selected_device = default_device
    mcutype_given   = False
    control_path    = None
    analyze         = True     # value tracking is sound and always on
    advanced        = False
    show_xrefs      = False
    discover_tables = False
    json_report     = False
    callgraph_report = False
    annotate        = True
    signals_report  = False
    suggest         = False
    one_signal      = None
    one_routine     = None

    for opt, val in opts:
        if opt in ("-h", "--help"):
            print(__doc__)
            sys.exit(0)
        elif opt in ("-m", "--mcutype"):
            if val not in Devices.keys():
                sys.stderr.write("Unsupported MCU type requested (%s)! Currently supported: %s\n"%(val, ', '.join(Devices.keys())))
                sys.exit(2)
            else:
                selected_device = val
                mcutype_given = True
        elif opt in ("-c", "--control"):
            control_path = val
        elif opt in ("-a", "--analyze"):
            analyze = True
        elif opt in ("-A", "--advanced"):
            advanced = True
        elif opt in ("-x", "--xref"):
            show_xrefs = True
        elif opt == "--auto-tables":
            advanced = True
        elif opt in ("-j", "--json"):
            json_report = True
        elif opt in ("-g", "--call-graph"):
            callgraph_report = True
        elif opt in ("-s", "--signals"):
            signals_report = True
        elif opt == "--suggest":
            suggest = True
        elif opt == "--signal":
            one_signal = val
        elif opt == "--routine":
            one_routine = val
        elif opt == "--no-annotate":
            annotate = False
        else:
            sys.stderr.write(__doc__)
            sys.exit(1)

    if one_routine is not None:
        others = [name for name, on in (
            ("-j", json_report), ("-g", callgraph_report),
            ("--signals", signals_report), ("--signal", one_signal is not None),
            ("--suggest", suggest)) if on]
        if others:
            sys.stderr.write("--routine cannot be combined with %s\n"
                             % ", ".join(others))
            sys.exit(1)

    # An optional control file supplies entry points, labels, a memory map,
    # and/or the device.
    cf = None
    if control_path is not None:
        try:
            cf = control.load(control_path)
        except (OSError, control.ControlError) as e:
            sys.stderr.write("Control file error: %s\n" % e)
            sys.exit(2)
        # device precedence: explicit -m wins, else control file, else detected
        if cf.device is not None and not mcutype_given:
            if cf.device not in Devices.keys():
                sys.stderr.write("Control file requests unsupported MCU type (%s)!\n" % cf.device)
                sys.exit(2)
            selected_device = cf.device
    device_given = mcutype_given or (cf is not None and cf.device is not None)

    # Facts inferred because the user did not give them: listed in the
    # listing header (and JSON); notices go to stderr only when a person
    # should look.
    header, notices, detection = [], [], {}

    # The image comes either from a control-file memory map (segments) or from
    # binaries placed where their code says they belong.
    end_address = None
    placed, file_ranges = [], None
    if cf is not None and cf.segments:
        if len(args) != 0:
            sys.stderr.write("Do not pass a binary file when the control file "
                             "defines segments.\n")
            sys.exit(1)
        try:
            rom = cf.build_image()
        except control.ControlError as e:
            sys.stderr.write("Control file error: %s\n" % e)
            sys.exit(2)
        start_address = 0
        detect_data, detect_base = rom, 0
    else:
        if len(args) == 0:
            sys.stderr.write(__doc__)
            sys.exit(1)
        if len(args) == 1:
            with open(args[0], 'rb') as f:
                rom = bytearray(f.read())
            _require_data(args[0], rom)
            rom, start_address = place_binary(rom, header, notices, detection)
            if cf is not None:
                start_address = fit_control_file(cf, len(rom), start_address,
                                                 header, detection)
            bank = detection.get("bank")
            placed = [(args[0], start_address, len(rom),
                       int(bank["file_offset"], 16) if bank else 0)]
        else:
            rom, start_address, placed = place_files(args, header, detection)
            file_ranges = [(b, b + n) for _, b, n, _ in placed]
        detect_data, detect_base = rom, start_address
        if start_address + len(rom) < 0x10000:
            end_address = start_address + len(rom)

    if not device_given:
        selected_device = choose_device(detect_data, detect_base, selected_device,
                                        header, notices, detection)

    kwargs = {}
    if cf is not None:
        try:
            kwargs = control_args(cf, rom, start_address)
        except control.ControlError as e:
            sys.stderr.write("Control file error: %s\n" % e)
            sys.exit(2)
    if file_ranges:
        kwargs.setdefault("readonly_ranges", file_ranges)   # gaps are not ROM
    if end_address is not None:
        # pad above an image that sits below the top of memory; only the
        # image itself is trusted for pointer analysis
        kwargs.setdefault("readonly_ranges", [(start_address, end_address)])
        rom = rom + bytearray(b"\xff" * (0x10000 - end_address))
    image_len = (end_address or 0x10000) - start_address
    # what is ROM: control-file file segments, the placed files, or the image
    rom_ranges = kwargs.get("readonly_ranges") or [(start_address, start_address + image_len)]
    if file_ranges or end_address is not None:
        kwargs["trace_ranges"] = rom_ranges     # the 0xFF padding is not code
    inferred, dropped = [], {}
    if suggest and suggest_scope == "all":
        advanced = True             # the draft includes code found by evidence
    if advanced and not detection.get("device", {}).get("fits", True):
        # guesses on top of a doubtful device would only add wrong code
        advanced = False
        notices.append("not looking for code by evidence: the image does not look like "
                       "740 code.  Name the chip with -m to do it anyway.")
    if advanced:
        from m740recon import infer
        ro = kwargs.get("readonly_ranges") or [(start_address, start_address + image_len)]
        lo, hi = min(a for a, _ in ro), max(b for _, b in ro)
    try:
        if advanced:
            memory, symbol_table, inferred, dropped = infer.run(
                build_disassembly, rom, selected_device, start_address, lo, hi,
                analyze=analyze, discover_tables=True, **kwargs)
            report_inferred(inferred, dropped, header, detection)
        else:
            memory, symbol_table = build_disassembly(rom, selected_device,
                                                     start_address, analyze=analyze,
                                                     discover_tables=discover_tables,
                                                     **kwargs)
    except ValueError as e:
        # an entry point or vector outside the traced image
        sys.stderr.write("m740recon: %s (the image is 0x%04x-0x%04x).  Add a segment "
                         "line to the control file to place the binary.\n"
                         % (e, start_address, start_address + image_len - 1))
        sys.exit(2)
    report_tables(memory, header, detection)
    if not (cf is not None and cf.segments):
        report_unmapped(memory, start_address, start_address + image_len,
                        header, notices, detection)
    for text in notices:
        sys.stderr.write("m740recon: note: %s\n" % text)

    try:
        smap = build_signal_map(cf, selected_device)
    except control.ControlError as e:
        sys.stderr.write("Control file error: %s\n" % e)
        sys.exit(2)
    pointer_sites = []
    accesses = signal_accesses(memory, smap, selected_device, pointer_sites)
    findings = signal_lint(memory, smap, accesses, selected_device)
    for rule, text in findings:
        sys.stderr.write("m740recon: lint: %s\n" % text)

    if suggest or (signals_report and not smap):
        from m740recon import discover, report
        raw = discover.raw_signal_map(selected_device)
        model = report.build_model(memory, symbol_table, start_address,
                                   image_len, selected_device, signal_map=raw,
                                   accesses=signal_accesses(
                                       memory, raw, selected_device))
        if suggest:
            pin_text = discover.format_suggest(model, selected_device, declared=smap)
            if suggest_scope == "pins":
                sys.stdout.write(pin_text)
            else:
                from m740recon import suggest as draft
                sys.stdout.write(draft.build(
                    cf, selected_device, device_given, detection, memory,
                    placed, inferred, dropped, pin_text,
                    annotations=annotations(memory, rom_ranges, detection)))
        else:
            sys.stdout.write(discover.format_discovery(model, selected_device))
        return

    if one_signal is not None:
        from m740recon import report
        model = report.build_model(memory, symbol_table, start_address,
                                   image_len, selected_device,
                                   signal_map=smap, accesses=accesses)
        model["lint"] = [{"rule": r, "text": t} for r, t in findings]
        text = report.format_signal(model, one_signal) if smap else None
        if text is None:
            names = ", ".join(s.name for s in smap.signals) or "(none declared)"
            sys.stderr.write("Unknown signal %r; declared: %s\n"
                             % (one_signal, names))
            sys.exit(2)
        sys.stdout.write(text)
        return

    if json_report or callgraph_report or signals_report:
        from m740recon import report
        model = report.build_model(memory, symbol_table, start_address,
                                   image_len, selected_device,
                                   signal_map=smap, accesses=accesses,
                                   pointer_sites=pointer_sites)
        if smap:
            model["lint"] = [{"rule": r, "text": t} for r, t in findings]
        if json_report and advanced:
            # annotations are inferences; plain JSON stays as it was
            annotations(memory, rom_ranges, detection)
        if detection:
            model["detection"] = detection
        if json_report:
            sys.stdout.write(report.to_json(model))
        elif callgraph_report:
            sys.stdout.write(report.format_call_graph(model))
        else:
            sys.stdout.write(report.format_signals(model))
        return

    comments = control_comments(cf) if cf is not None else {}
    for d in inferred:
        note = "inferred (%s): %s" % (d.confidence, d.reason)
        if d.address in comments:
            note = comments[d.address] + "\n" + note
        comments[d.address] = note
    notes = {}
    if annotate and smap.active:
        from m740recon import access
        notes = access.listing_annotations(memory, accesses, pointer_sites)
    elif annotate:
        # no signals declared: name the port bits touched
        from m740recon import access, discover
        bits = discover.port_bit_map(selected_device)
        notes = {site: discover.compact_bits(text) for site, text in
                 access.listing_annotations(
                     memory, signal_accesses(memory, bits, selected_device),
                     []).items()}
    printer = Printer(memory,
                      start_address,
                      symbol_table,
                      comments=comments,
                      show_xrefs=show_xrefs,
                      annotations=notes,
                      end_address=end_address,
                      header=header,
                      )
    if one_routine is not None:
        from m740recon import report
        model = report.build_model(memory, symbol_table, start_address,
                                   image_len, selected_device)
        key = one_routine
        try:
            key = int(one_routine, 16) if one_routine.lower().startswith(
                "0x") else one_routine
        except ValueError:
            pass
        span = report.find_routine(model, key)
        if span is None:
            sys.stderr.write("Unknown routine %r (give a routine name or the "
                             "hex address of a routine entry)\n" % one_routine)
            sys.exit(2)
        start = span[0]
        roots = {int(r["address"], 16) for r in model["routines"]}
        runs, exits = routine_blocks(memory, start, roots)
        for i, (lo, hi) in enumerate(runs):
            if i:
                print("    ; ...")
            printer.print_region(lo, hi)
        if exits:
            print("    ; continues into: %s" % ", ".join(
                printer.format_abs_address(a) for a in sorted(exits)))
        return
    printer.print_listing()


if __name__ == '__main__':
    main()
