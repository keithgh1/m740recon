# Supported devices

m740recon ships with definitions for 24 740-family parts, selectable by 48 names: the 24 part names plus 24 aliases for sibling part numbers and alternate spellings (some parts have several aliases, many have none).  Choose a device with `-m`, or with the `device` directive in a control file (`-c`); an explicit `-m` takes precedence over the control file.  Without either, the device is detected from the image.

```
$ ./venv/bin/m740recon -m M50734 input.bin > output.asm
```

Names are case-sensitive and must match exactly.  Passing an unrecognized name prints the full list of accepted names:

```
$ ./venv/bin/m740recon -m bogus input.bin
Unsupported MCU type requested (bogus)! Currently supported: ...
```

A device definition supplies the interrupt/reset vector table and a symbol table that names the special-function registers (SFRs), I/O ports, and vectors of that part, so the listing reads in datasheet terms instead of bare addresses.  Devices are organized as a base/group/part inheritance hierarchy in [`m740recon/devices.py`](../m740recon/devices.py): a group base (for example the shared core behind `M3802`/`M3807`/`M3886`) defines the common vectors and ports, and each part inherits it and then adds or overrides its own SFRs.  A device may also declare opcodes its core does not implement so they decode as data rather than instructions; the hook exists but no bundled device currently needs it.

Two devices carry extra metadata for the signal features:

| Device | Port metadata | Address spaces |
|---|---|---|
| `50734` (`M50734`) | P0-P4: data, direction, P0 function and P1 input-latch registers | `dme`: enabled by P0FUNC bit 5, reached by `(zp),Y` |
| `M3886` | P0-P7: data and direction registers | - |

With port metadata, writes to direction and function registers are shown in pin terms, discovery uses the real ports and the firmware's own direction settings, and the lint can check declared directions.  Other devices fall back to registers named `P0`, `P1`, ... for discovery and skip those checks.  The M50734 DME rule that only `(zp),Y` reaches the data space rests on the behavior of real firmware, since the datasheet does not name the addressing modes.

Note the mix of naming conventions: a few parts carry an `M` prefix (`M3886`, `M3802`, `M3807`) while most are bare numbers (`50734`, `50740A`, `37410M3`).  The familiar `M3xxxx`/`M5xxxx` spellings (`M37450`, `M37451`, `M50734`) are provided as aliases of the bare-number entries.

## Hand-curated cores

Vectors and SFR names for these cores are hand-verified; a datasheet-sourced reference register map for each is included in this directory (`m3886.py`, `m50734.py` and so on, one file per core).

| Device | Aliases |
|---|---|
| `7450` | `M37450`, `37450S1`, `37450M4`, `37450M8`, `37450S2`, `37450S4` |
| `7451` | `M37451` |
| `M3802` | - |
| `M3807` | - |
| `M3886` | - |
| `50734` | `M50734`, `50734_10` |

## MELPS 740 devices (datasheet-derived)

These entries were generated from the MELPS 740 databook.  Their vectors and register addresses come from the datasheet and are reliable.  The SFR symbol names are heuristic and may be refined, so treat the mnemonics as a starting point.  None overlaps a hand-curated core above.

| Device | Aliases |
|---|---|
| `50740A` | `50741` |
| `50742` | `50708` |
| `50743` | - |
| `50744` | `50746` |
| `50745` | - |
| `50747` | `50747H` |
| `50752` | `50757`, `50758` |
| `50753` | - |
| `50754` | `50954`, `50955` |
| `50930` | `50931`, `50932` |
| `50940` | `50941` |
| `50943` | - |
| `50944` | - |
| `50950` | `50951` |
| `50957` | `50959` |
| `50964` | `50963` |
| `37410M3` | `37410M4` |
| `37415M4` | - |

A few parts place their vectors well below the top of a 64K image: `50740A`/`50752` at `0x1FFE` (an 8K space) and `50930`/`37410M3`/`37415M4` at `0x3FFE` (a 16K space).  m740recon detects where such a ROM sits from its code (see [Detection and inference](detection.md)).  If it guesses wrong, a control-file `segment` line sets the layout.

## Adding a device

To add a part, add a `_define(...)` entry to [`m740recon/devices.py`](../m740recon/devices.py) (optionally inheriting an existing base), plus any `_alias(...)` lines for sibling part numbers that share its register map.  No other code changes are required: the new name becomes a valid `-m` value automatically.  To enable the port-aware signal features for it, also pass `ports=` (each port's data, direction, function and input-latch registers) and, if it has a second address space, `spaces=`; the M50734 entry shows both.
