# m740recon

## Overview

m740recon is an advanced disassembler and static analyzer for Renesas/Mitsubishi 740 firmware. Beyond producing as740-compatible assembly, it performs recursive-traversal code/data separation, data-flow value-tracking, declarative control-file driven analysis, cross-referencing, and call-graph / JSON reporting to accelerate reverse-engineering of 8-bit Mitsubishi microcontroller ROMs.

m740recon disassembles firmware for many 8-bit Mitsubishi microcontrollers and generates output compatible with the [as740](http://shop-pdp.net/ashtml/as740.htm) assembler. The 16- and 32-bit Mitsubishi microcontrollers use different instruction sets and are not supported.

The underlying disassembler lineage was developed to disassemble the firmware of the [Volkswagen Gamma V](https://github.com/mnaberez/vwradio) and [Volkswagen Rhapsody](https://github.com/mnaberez/vwradio) car radios made by TechniSat. Both radios use the [M38869FFAHP](http://6502.org/documents/datasheets/mitsubishi/renesas_3886_group_users_manual.pdf) microcontroller.

## Features

 - **Identical reassembly.**  The assembly output of m740recon assembles to a bit-for-bit exact copy of the original binary using as740.  A pure-Python structural round-trip verifies the same property without an external assembler.

 - **Code / data separation.**  Starting from the vectors at the top of memory, m740recon uses recursive-traversal disassembly to separate code from data.

 - **Symbol generation.**  Hardware registers, vectors, referenced memory locations, branch labels, and subroutines are named automatically instead of writing hardcoded addresses.

 - **Declarative control files (`-c`).**  A da65-style control file supplies the device, entry points, labels/comments, a segment memory map, typed data ranges (`byte`/`word`/`addr`/`text`), and address-tables that decode dispatch tables into named handlers — instead of editing source.

 - **Device hierarchy (`-m`).**  Devices are defined as a base/group/part inheritance hierarchy in `devices.py`, covering the M37450/51, M3802/07/3886, M50734, and many other 740-family parts plus aliases.  A device can also gate opcodes its core does not implement so they decode as data; the hook is in place for cores that need it, though no bundled device currently uses it.

 - **Value-tracking analysis (`-a`, `--auto-tables`).**  Optional constant-propagation resolves computed `jmp [zp]` / `jsr [zp]` targets; `--auto-tables` enumerates contiguous ROM jump tables that feed them.  Both are additive and reassembly-safe.

 - **Cross-references (`-x`).**  Annotates each label with the instructions that reference it.

 - **Reports (`-j`, `-g`).**  Emits a machine-readable JSON model or a human-readable call graph instead of the listing (see [Reports and visualization](#reports-and-visualization)).

## Installation

m740recon is written in Python and requires Python 3.8 or later.  You can download the package from this git repository and then install it into a virtual environment with:

```
$ git clone https://github.com/keithgh1/m740recon.git
$ cd m740recon
$ python3 -m venv ./venv
$ ./venv/bin/pip3 install --editable '.[test]'
```

After running the above, you can run the disassembler with `./venv/bin/m740recon`
or run its unit tests with `./venv/bin/pytest`.

## Usage

m740recon accepts a plain binary file as input.  The file is assumed to be a ROM image that should be aligned to the top of memory.  For example, if a 32K file is given, m740recon will assume the image should be located at 0x8000-0xFFFF.  After loading the image, the disassembler reads the vectors at the top of memory and starts tracing instructions from there.

```
$ ./venv/bin/m740recon input.bin > output.asm
```

The default MCU type is the `M3886` series.  Other types may be specified with the `-m` option, e.g. `-m M37450` or `-m M50734`.  You can add support for new devices by editing `devices.py`.

For anything beyond a single top-aligned ROM — a RAM/ROM split, additional entry points, dispatch tables, or data regions — supply a control file with `-c` instead of editing source.  A control file gives the device, a segment memory map, entry points, labels and comments, typed data ranges, and address-tables that decode dispatch tables into named handlers:

```
$ ./venv/bin/m740recon -c firmware.m740 > output.asm        # device + memory map + labels
$ ./venv/bin/m740recon -c firmware.m740 -a -x > output.asm  # + analysis + xrefs
```

The control-file extension `.m740` refers to the 740 chip family.  A complete, annotated control file that exercises every directive — device, a segment memory map, entry points, labels, comments, typed data ranges, and an address-table — is included at [`docs/example.m740`](docs/example.m740).

Most binaries include some computed jumps.  `-a`/`--analyze` tracks register and zero-page values to resolve `jmp [zp]` / `jsr [zp]` targets, and `--auto-tables` enumerates the ROM jump tables that feed them.  Addresses that still can't be resolved automatically can be named directly in the control file.

Once disassembled, the output file can be re-assembled to an identical binary using [as740](http://shop-pdp.net/ashtml/as740.htm).  A sample [`Makefile`](m740recon/tests/end_to_end/Makefile) is included that shows the required as740 commands.

### Reports and visualization

In addition to the assembly listing, m740recon can emit two reports derived from the traced program.  Both read only already-traced state and print to stdout in place of the listing:

```
$ ./venv/bin/m740recon -c firmware.m740 --call-graph > callgraph.txt   # human-readable
$ ./venv/bin/m740recon -c firmware.m740 --json       > report.json     # machine-readable
```

`--call-graph` lists each routine with the routines it calls and the routines that call it.  `--json` writes a structured model (`m740recon-report/1`): routines (each with its outgoing/incoming call edges), vectors, symbols, and a full cross-reference map.

The JSON model renders into a [Graphviz](https://graphviz.org/) diagram.  A full firmware graph is usually too large to read, so filter to a routine of interest — for example, everything reachable from one routine, two levels deep:

```python
# report_to_dot.py: turn `m740recon --json` output into Graphviz
import json, sys
model = json.load(open(sys.argv[1]))
routines = {r["address"]: r for r in model["routines"]}
by_name = {r["name"]: r["address"] for r in model["routines"]}
root = by_name[sys.argv[2]]
depth = int(sys.argv[3]) if len(sys.argv) > 3 else 2

seen, frontier = set(), {root}
for _ in range(depth + 1):
    seen |= frontier
    frontier = {e["to"] for a in frontier if a in routines
                for e in routines[a]["calls"]} - seen

print("digraph g {\n  rankdir=LR;\n  node [shape=box, fontname=Helvetica];")
for a in seen:
    for e in routines.get(a, {}).get("calls", []):
        if e["to"] in seen:
            dash = "" if e["type"] == "call" else " [style=dashed]"
            print('  "%s" -> "%s"%s;' % (routines[a]["name"], e["name"], dash))
print("}")
```

```
$ ./venv/bin/m740recon -c firmware.m740 --json > report.json
$ python report_to_dot.py report.json main_loop 2 | dot -Tsvg -o callgraph.svg
```

## Testing

```
$ ./venv/bin/pytest
```

The suite is self-contained: every input is a synthetic fixture or the repository's own `testprog.asm`, so no external ROM image is required.

The end-to-end reassembly tests use the real [as740](http://shop-pdp.net/ashtml/as740.htm) + aslink to prove the listing assembles bit-for-bit back to the input.  When that toolchain is not found on `PATH` (or as `<tool>.exe` in `~/bin`) those tests **skip** and the rest of the suite still passes — the pure-Python structural round-trip (`test_roundtrip`) keeps re-encoding verified in the meantime.  Set `M740_REQUIRE_AS740=1` to turn a missing toolchain into a hard failure instead (recommended for CI that must never let the reassembly guarantee go unverified).  To run the full check locally, build `as740` and `aslink` from the ASxxxx source and put them on `PATH`.

## Relationship to m740dasm

m740recon is a friendly fork of [m740dasm](https://github.com/mnaberez/m740dasm) by Mike Naberezny, used under its BSD-3-Clause license. m740dasm provides the proven 740-family instruction set, the recursive-traversal disassembler core, automatic symbol generation, and the bit-for-bit-exact reassembly guarantee.

m740recon builds on that foundation with a static-analysis and reverse-engineering focus, adding:

 - declarative da65-style control files (`-c`) for device selection, segment memory maps, entry points, labels/comments, typed data ranges, and address-table decoding;
 - a base/group/part device inheritance hierarchy spanning many 740-family parts and aliases;
 - data-flow value-tracking (`-a`) to resolve computed `jmp [zp]` / `jsr [zp]` targets, with automatic ROM jump-table enumeration (`--auto-tables`);
 - cross-reference annotation (`-x`); and
 - human-readable call-graph and machine-readable JSON reports for visualization.

m740recon is an independent project. Mike Naberezny does not endorse, sponsor, or maintain m740recon, and m740dasm is credited only as the basis from which this fork is derived.

## Author

m740recon is maintained by [Keith Monahan](https://github.com/keithgh1).

The original m740dasm disassembler, on which m740recon is based, was created by [Mike Naberezny](https://github.com/mnaberez) ([m740dasm](https://github.com/mnaberez/m740dasm)).

## License

m740recon is distributed under the BSD-3-Clause license. The original copyright notice, conditions, and disclaimer — copyright (c) 2018 Mike Naberezny and contributors — are retained in [LICENSE](LICENSE.txt). Additions made in this fork are copyright (c) 2026 Keith Monahan. See [LICENSE](LICENSE.txt) for the full text.
