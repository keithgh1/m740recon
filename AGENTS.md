# AGENTS.md

Guidance for AI coding agents and other automated tools using or changing
m740recon.  Humans may find it a useful quick reference too; the README has
the full story.

## What the tool does

m740recon disassembles firmware for the Mitsubishi/Renesas 740 family of
8-bit microcontrollers.  Its listing reassembles byte-for-byte with the
ASxxxx `as740` assembler.  On top of that it can:

- follow computed jumps (`-a`) and decode dispatch tables;
- name what is wired to the chip's pins and what RAM flag bits mean, and
  annotate every instruction that touches them;
- report routines, call edges, signals and lint findings as text or JSON.

Python 3.8 or later, no third-party dependencies.

## Commands

`m740recon` is the installed entry point; `python -m m740recon.command`
is equivalent.  All output goes to stdout; lint findings and errors go to
stderr.

```
m740recon firmware.bin > out.asm                 # zero setup: top-aligned ROM, default device M3886
m740recon -m M50734 firmware.bin > out.asm       # pick the device
m740recon -c fw.m740 > out.asm                   # control file (device, memory map, names, signals)
m740recon -c fw.m740 -a -x > out.asm             # + computed-jump analysis + xref comments
m740recon -c fw.m740 -j > model.json             # JSON model (docs/json_model.md)
m740recon -c fw.m740 -g                          # call graph
m740recon -c fw.m740 --signals                   # signal report (or port discovery if none declared)
m740recon -c fw.m740 --suggest                   # pin lines for touched, undeclared port bits
m740recon -c fw.m740 --signal PE                 # one signal's report section
m740recon -c fw.m740 --routine main_loop         # one routine's listing (name or 0xADDR)
m740recon -c fw.m740 --no-annotate               # listing without signal comments
```

If the control file has `segment` lines, it builds the image itself and no
binary argument is given; otherwise pass the binary after the options.

## Working loop for a new firmware

1. Run with no configuration and read the output.  Pick the device with
   `-m` if it is not an M3886.  The listing already names the port bits
   each instruction touches (`reads P0.1`).
2. Create a control file with `device`, and `segment` lines if the ROM is
   not a single image at the top of memory.
3. Run `--signals` with no signals declared: it lists the port bits the
   firmware touches and their direction.  Run `--suggest` and paste its
   `pin` lines into the control file.
4. Rename the suggested pins as you learn what they are (schematic,
   datasheet, behavior).  Add `high=` / `low=` or `active=`, and set
   `source=` to where each fact came from.  Add `bit` lines for RAM flags.
5. Rerun.  Read the lint findings on stderr; each one is a place where the
   declarations and the firmware disagree.  Use `--routine` and `--signal`
   to look at one thing at a time instead of the whole listing.
6. Use `-j` for anything you parse.  Do not parse the text listing or text
   reports; their layout may change.

## Control-file reference

One directive per line.  `#` starts a comment.  Numbers are C-style
(`0x8000`, `0o17`, `4660`).  Quote any text containing spaces.  For any
address, the first directive that names it wins.

| Directive | Meaning |
|---|---|
| `device NAME` | device (an explicit `-m` overrides it) |
| `segment NAME START END zero\|PATH[@OFF]` | build the 64K image from file slices; START inclusive, END exclusive |
| `include PATH` | read another control file (relative to this one; may nest; cycles rejected) |
| `entry ADDR [NAME] ["comment"]` | trace code at ADDR (for code reached only by computed jumps) |
| `label ADDR NAME ["comment"]` | name an address without tracing it |
| `comment ADDR "text"` | a `;` comment line above ADDR in the listing |
| `range START END byte\|word\|addr\|text` | type a data region |
| `addrtable START [stride=N] [entryoff=K] [terminator=V\|end=ADDR\|count=N] [label=PREFIX] [names=ascii]` | decode a table of code pointers |
| `pin LOC NAME [in\|out\|bidir] [active=high\|low] [high=TEXT] [low=TEXT] [source=schematic\|firmware\|datasheet\|guess] ["description"]` | a signal on a port pin or bit range |
| `bit LOC NAME [high=TEXT] [low=TEXT] [source=...] [space=NAME] [access=read\|write] ["description"]` | any other named bit: an SFR control bit, a RAM flag, or a bit of an external register |
| `pointer ADDR TARGET [space=NAME] ["comment"]` | the zero-page pair at ADDR holds the fixed address TARGET (in address space NAME); indirect accesses through it are attributed |
| `group NAME SIGNAL... ["description"]` | related signals, reported together |

`LOC` is `ADDR.BIT` or `ADDR.LO-HI`.  `ADDR` is a number, a device SFR name
(`P0`, `ICON1`), or a `label`.  Automatic names (`mem_0052`) are not
accepted; write the number.  A signal name must be an identifier and unique,
and no two signals may share a bit, except a read-only and a write-only
signal (`access=`), which may: one register bit often means one thing when
read and another when written.

`space=` places a bit in a second address space that only declared pointers
reach (direct and absolute operands always address the program space).  If
the device describes the space (the M50734 describes its DME data space:
enabled by P0FUNC bit 5, reached only by `(zp),Y`), each access through the
pointer is checked against the enable bit: provably on, it is attributed;
provably off, it goes to the program space; unknown, it is attributed and
marked `?` in the listing (`assumed` in JSON).

See `docs/example.m740` for every directive in context.

## Rules that must stay true

When changing the code, keep all of these:

1. Output that existed before signal support stays byte-identical: the
   listing with `--no-annotate`, and `-j` / `-g` with no signals declared.
   (With no configuration the listing names the port bits it touches;
   that is the only change, and it is comment text.)  The golden tests
   enforce it; never regenerate an existing golden to make
   a test pass.  Regenerate only when the change to the output is the point,
   and review the diff.
2. The listing reassembles byte-exact with `as740`.  Annotations are
   comment text only; signal names never become assembler symbols.
3. Report only what is provable.  A wrong annotation is worse than none:
   when a value is unknown, say so or say nothing.
4. Never commit ROM images or firmware-derived data that reproduces ROM
   contents.  Tests use synthetic images built in `tests/fixtures.py`.
5. Stay generic to the 740 family: nothing may assume a particular board.
6. No new dependencies; Python 3.8 compatible; the CLI uses `getopt`.

## Tests

```
python -m pytest -q
```

- `as740` and `aslink` (ASxxxx) must be on PATH for the reassembly tests;
  without them those tests skip.  `M740_REQUIRE_AS740=1` makes their
  absence a failure.
- `tests/test_realworld_nx1020.py` runs against the Star NX-1020 printer
  example in `examples/nx1020/`.  Its ROM images are not committed: they
  are downloaded on first run (`m740recon/tests/nx1020_roms.py`, pinned
  commit, SHA-256 checked).  Without network the tests skip;
  `M740RECON_REQUIRE_NX1020=1` makes that a failure.
  Its goldens live in `tests/golden/nx1020/`.  After an intended output
  change, regenerate them with
  `python -m m740recon.tests.update_nx1020_golden` and review the diff.
  Never regenerate `presignal.json`: it pins the output from before
  signal support, which a control file without signals must still give.
- Regenerate a golden on purpose with
  `python -m m740recon.tests.test_golden --update` (likewise
  `test_example`, `test_signals`).

## Where things are

| Module | Role |
|---|---|
| `command.py` | CLI and the shared build path (`build_disassembly`, `control_args`, `build_signal_map`, `signal_accesses`, `signal_lint`) |
| `disasm.py`, `tables.py` | instruction decoding |
| `trace.py`, `dataflow.py` | code tracing and computed-jump analysis |
| `control.py` | control-file parser |
| `devices.py` | device SFRs, vectors, optional port metadata |
| `signals.py` | resolved signals (`SignalMap`) |
| `access.py`, `regflow.py` | instructions to signal accesses; the single source of hardware facts |
| `effects.py` | leaf-routine effects, call-graph reach, name suggestions |
| `discover.py` | zero-configuration port discovery and `--suggest` |
| `lint.py` | declarations versus firmware |
| `listing.py` | the as740 listing |
| `report.py` | JSON model, call graph, signal report |
