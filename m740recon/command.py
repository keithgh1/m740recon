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
        opts, args = getopt.getopt(sys.argv[1:], "hm:c:axjg",
                                   ["help", "mcutype=", "control=", "analyze",
                                    "xref", "auto-tables", "json", "call-graph"])
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
        else:
            sys.stderr.write(__doc__)
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

    if json_report or callgraph_report:
        from m740recon import report
        model = report.build_model(memory, symbol_table, start_address,
                                   len(rom), selected_device)
        if json_report:
            sys.stdout.write(report.to_json(model))
        else:
            sys.stdout.write(report.format_call_graph(model))
        return

    comments = control_comments(cf) if cf is not None else {}
    printer = Printer(memory,
                      start_address,
                      symbol_table,
                      comments=comments,
                      show_xrefs=show_xrefs,
                      )
    printer.print_listing()


if __name__ == '__main__':
    main()
