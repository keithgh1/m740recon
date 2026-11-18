# Detection and inference

Given only a ROM file, m740recon works out what a control file would otherwise have to say, and says how sure it is.  What it infers appears at the top of the listing, in the JSON model (`detection`) and in the `--suggest` draft.  Anything you state yourself (`-m`, a control file) always wins.

| What | When | How |
|---|---|---|
| **Load address** | a binary without `segment` lines | every `jsr` operand votes for the base that puts its target right after the end of a routine; the true base collects far more votes.  Small, call-light ROMs fall back to the vectors at the top of the image |
| **Device** | no `-m` and no `device` line | the device's vectors must point at code (vectors into a ROM that was not given are left out), then the SFRs the code uses must match; SFRs used as ordinary RAM count against a device |
| **Banks** | a file over 64 KiB | the one programmed 32 KiB bank is used; several stop with `segment` lines to fill in |
| **Another ROM** | calls into memory no file covers | a note, and commented `segment` lines in the draft |
| **Dispatch tables** | always | tables the code proves: a constant table address handed to a search routine, or a table walked by a counted loop.  Handlers are named from the record keys (`tbl_c0d4_E`, `tbl_c063_BEL`) |
| **Code by evidence** | `-A` / `--advanced`, and `--suggest` | likely pointer tables, and routines nobody calls that follow a routine end and call known routines.  Entry points only (they never turn bytes into data or pointers), each marked `;inferred (medium): reason`; entries whose code contradicts the rest are dropped |
| **Memory map, fonts, text** | `--suggest` (and JSON with `-A`) | RAM and I/O pages from how the code uses them, an HD44780 LCD command port, dot-matrix font regions and text runs, offered as `label` and `range` lines; never applied to the listing by themselves |

Confidence uses the same words everywhere:

| Word | Meaning |
|---|---|
| `proven` | follows from the code itself |
| `high` | detected with a wide margin |
| `medium` | detected with a narrow margin, or found by evidence |
| `low` | doubtful; in the `--suggest` draft such lines are commented out |

A note on stderr appears only when a person should look: a close device call, calls into memory no file covers, a banked file, or an image that does not look like 740 code (then `--advanced` is skipped).

On the [NX-1020 example](../examples/nx1020/), given only the memory map (the control file's `segment` lines, because its 128 KiB font ROM is banked) and no other facts, m740recon reaches all the code the hand-written control file reaches and names the dispatch handlers by the same keys (`ctl_BEL` in the control file, `tbl_c091_BEL` detected).  With just the 32 KiB firmware ROM it finds three of the four tables and notes that calls go to a ROM that was not given.
