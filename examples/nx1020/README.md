# Star NX-1020 printer firmware

A complete m740recon example: the firmware of the Star NX-1020, a 9-pin
dot-matrix printer built around a Mitsubishi M50734 (740 family), with the
control file and board description used to study it.

The reverse engineering behind it, with the fonts, the labeled disassembly,
a ROM map and full documentation, is published at
[star-nx1020-re](https://github.com/keithgh1/star-nx1020-re).

The ROM images are not stored here.  Fetch them from star-nx1020-re
(pinned commit, SHA-256 checked) with:

```
python -m m740recon.tests.nx1020_roms
```

## Files

| File | Contents |
|---|---|
| `nx1020_rom1.ic7` (fetched) | ROM1 (128 KB): system code, interrupt handlers and resident fonts.  The CPU sees file offset 0x4000-0x7FFF at 0x4000. |
| `nx1020_rom2_v3.2.ic6` (fetched) | ROM2 (32 KB): main firmware, version 3.2, at 0x8000-0xFFFF. |
| `nx1020.m740` | Control file: memory layout, entry points, labels, comments, jump tables. |
| `nx1020_board.m740` | Board description: what each port pin, gate-array register and RAM flag means.  Included by `nx1020.m740`. |

Paths in the control files are relative to the files themselves, so the
commands below work from any directory.

## Try it

From the top of the repository:

```
m740recon -c examples/nx1020/nx1020.m740 > nx1020.asm
m740recon -c examples/nx1020/nx1020.m740 --signals
m740recon -c examples/nx1020/nx1020.m740 --signal HP
m740recon -c examples/nx1020/nx1020.m740 --routine panel_read
m740recon -c examples/nx1020/nx1020.m740 -j > nx1020.json
```

The listing reassembles byte-exact with as740.  Annotations come from the
board description and are comments only.

`--routine panel_read` prints the front-panel button reader, with what each
port read means:

```
    ;read P3 buttons debounced, AND #0xF8 (P3.3-7 = FONT/PITCH/SET/PF/OL)

panel_read:
    lda P3                  ;ff8f  a5 ee
    ldm #0xff,WDT           ;ff91  3c ff fc
    cmp P3                  ;ff94  c5 ee     reads CR_CMN_HV, LF_CMN_HV, BTN_FONT, BTN_PITCH, BTN_SET, BTN_PF, BTN_OL
    bne panel_read          ;ff96  d0 f7
    and #0xf8               ;ff98  29 f8     reads BTN_FONT, BTN_PITCH, BTN_SET, BTN_PF, BTN_OL
    rts                     ;ff9a  60
```

`--signal HP` shows every place the firmware touches the carriage
home-position sensor:

```
HP (P0.7)  in, high = carriage at home, low = carriage away   [source: schematic]  home-position photo-interrupter
  reset      0x8148  function   HP: port
  reset      0x8150  direction  HP: input
  sub_d0f6   0xd0fb  read       reads HP
  home_seek  0xd842  test       HP: branch if carriage at home
  home_seek  0xd862  test       HP: branch if carriage away
  ...
```

## Lint findings

With the board description loaded, m740recon reports two findings on
stderr.  Both are real properties of the firmware:

- `EE_ORG (P1.3): never read or written by the firmware`.  The EEPROM's
  ORG pin is wired to P1.3, but the firmware leaves it alone after reset.
- `CR_CMN_HV (P3.0): declared out, but the firmware makes it an input at
  0x43b9, 0x4a8c`.  The carriage motor common-voltage line is an output
  most of the time, but the firmware switches it to an input at those
  two sites and back to an output at 0x4af8 and 0x4bc9.

## Zero-config discovery

Without the board description (remove the `include` line from a copy of
`nx1020.m740`), `--signals` lists every port bit the firmware touches,
with directions taken from its direction-register writes, and
`--suggest` turns that into `pin` lines to start a board file from.  The
listing names port bits instead of signals: `panel_read` shows
`reads P3.3-7` where the board description gives the button names.

## Tests

`m740recon/tests/test_realworld_nx1020.py` runs against these files on
every test run.  It checks documented facts about the firmware and
compares output against goldens in `m740recon/tests/golden/nx1020/`.
