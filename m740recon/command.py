'''
Usage: m740recon [-m MCUtype] [-c controlfile] [<filename.bin>]

Options:
  -m, --mcutype TYPE   select the MCU type (default: M3886)
  -c, --control FILE   read a control file for entry points, labels, the
                       device, and/or a segment memory map (see control.py).
                       If the control file defines segments, the image is
                       built from them and no binary argument is given.
  -a, --analyze        track register/zero-page values to resolve computed
                       jumps and discover the code behind them
  -x, --xref           annotate labels with '; xref:' lines listing the
                       instructions that reference each address
      --auto-tables    with analysis, enumerate ROM jump tables feeding
                       computed jumps and trace their handlers (heuristic)
  -j, --json           emit a machine-readable JSON model (routines, call
                       edges, vectors, symbols, xrefs) instead of the listing
  -g, --call-graph     emit a human-readable call-graph report instead of the
                       listing
  -s, --signals        emit a report of every declared pin/bit signal and the
                       instructions that access it, instead of the listing
                       With no signals declared, reports which port bits the
                       firmware touches and infers their direction instead
      --suggest        print control-file pin lines for every port bit the
                       firmware touches, as a starting point
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

import sys, getopt

from m740recon.disasm import disassemble
from m740recon.trace import Tracer
from m740recon.memory import Memory
from m740recon.listing import Printer
from m740recon.symbols import SymbolTable
from m740recon.devices import Devices
from m740recon import control


def build_disassembly(rom, device, start_address, entry_points=(),
                      vectors_extra=(), data_addrs=(), extra_symbols=(),
                      analyze=False, readonly_ranges=None, word_addrs=(),
                      addr_word_addrs=(), text_ranges=(), discover_tables=False):
    """Trace and symbol-analyze an image; return (memory, symbol_table).

    Shared by the CLI and the test harness so both follow the exact same path.
    When analyze is set, value tracking resolves indirect jumps/calls; pointers
    read through `jmp [abs]` are trusted only inside readonly_ranges (defaults
    to the whole image, which is correct for a single ROM).
    """
    memory = Memory(bytearray(rom))
    for addr in data_addrs:
        memory.set_data(addr)
    for addr in word_addrs:
        memory.set_word(addr)
    for addr in addr_word_addrs:
        memory.set_vector(addr)         # rendered as .word with symbol substitution
    for start, end in text_ranges:
        memory.set_text(start, end)
    vectors = list(Devices[device]["vector_table"]) + list(vectors_extra)
    traceable_range = range(start_address, start_address + len(rom) + 1)
    if readonly_ranges is None:
        readonly_ranges = [(start_address, start_address + len(rom))]
    # opcodes the selected core does not implement are decoded as data
    unsupported = Devices[device].get("unsupported_opcodes", frozenset())
    decoder = disassemble
    if unsupported:
        decoder = lambda mem, pc: disassemble(mem, pc, unsupported)
    Tracer(memory, list(entry_points), vectors, traceable_range,
           analyze=analyze or discover_tables, readonly_ranges=readonly_ranges,
           discover_tables=discover_tables).trace(decoder)
    symbol_table = SymbolTable(list(Devices[device]["symbol_table"]) +
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


def control_args(cf, rom):
    """Translate a ControlFile into build_disassembly keyword arguments.

    Symbol precedence (later overrides earlier in SymbolTable): device symbols,
    then addrtable-generated names, then explicit `label`/`entry` names.
    """
    pointer_addrs, data_addrs, table_symbols = cf.resolve_tables(rom)
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


def main():

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hm:c:axjgs",
                                   ["help", "mcutype=", "control=", "analyze",
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
    analyze         = False
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
        elif opt in ("-x", "--xref"):
            show_xrefs = True
        elif opt == "--auto-tables":
            discover_tables = True
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
        # device precedence: explicit -m wins, else control file, else default
        if cf.device is not None and not mcutype_given:
            if cf.device not in Devices.keys():
                sys.stderr.write("Control file requests unsupported MCU type (%s)!\n" % cf.device)
                sys.exit(2)
            selected_device = cf.device

    # The image comes either from a control-file memory map (segments) or from
    # a single binary aligned to the top of memory.
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
    else:
        if len(args) == 0:
            sys.stderr.write(__doc__)
            sys.exit(1)
        with open(args[0], 'rb') as f:
            rom = bytearray(f.read())
        start_address = 0x10000 - len(rom)

    kwargs = control_args(cf, rom) if cf is not None else {}
    memory, symbol_table = build_disassembly(rom, selected_device,
                                             start_address, analyze=analyze,
                                             discover_tables=discover_tables,
                                             **kwargs)

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
                                   len(rom), selected_device, signal_map=raw,
                                   accesses=signal_accesses(
                                       memory, raw, selected_device))
        if suggest:
            sys.stdout.write(discover.format_suggest(model, selected_device,
                                                     declared=smap))
        else:
            sys.stdout.write(discover.format_discovery(model, selected_device))
        return

    if one_signal is not None:
        from m740recon import report
        model = report.build_model(memory, symbol_table, start_address,
                                   len(rom), selected_device,
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
                                   len(rom), selected_device,
                                   signal_map=smap, accesses=accesses,
                                   pointer_sites=pointer_sites)
        if smap:
            model["lint"] = [{"rule": r, "text": t} for r, t in findings]
        if json_report:
            sys.stdout.write(report.to_json(model))
        elif callgraph_report:
            sys.stdout.write(report.format_call_graph(model))
        else:
            sys.stdout.write(report.format_signals(model))
        return

    comments = control_comments(cf) if cf is not None else {}
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
                      )
    if one_routine is not None:
        from m740recon import report
        model = report.build_model(memory, symbol_table, start_address,
                                   len(rom), selected_device)
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
