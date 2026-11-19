# Hardware signals

## Declaring signals

A control file can say what is wired to the chip.  `pin` names a port bit or a range of bits, `bit` names any other bit (an SFR control bit, a RAM flag, or a bit of an external register), and `group` collects related signals for the reports.  A board description shared by several firmware revisions can live in its own file and be pulled in with `include`:

```
include board.m740

pin P0.6 PE     in  high="paper end" low="paper present" source=firmware
pin P1.0 EE_CS  out active=high "EEPROM chip select"
pin P2.0-3 PHASE out "stepper phases"
bit 0x52.7 asf_installed "ASF fitted"
group eeprom EE_CS EE_SK EE_DI EE_DO
```

- A location is `ADDR.BIT` or `ADDR.LO-HI`, where `ADDR` is a number, a device register name (`P0`, `ICON1`) or a `label`.
- `in` / `out` / `bidir` give a pin's direction.  `high=` and `low=` say what each level means, and `active=` says which level is "on".
- `source=schematic|firmware|datasheet|guess` records where a fact came from; a guessed signal prints as `NAME?`.
- `bit` also takes `space=NAME` (see [External registers](#external-registers-and-address-spaces)) and `access=read` or `access=write`, so one register bit can carry a meaning when read and a different one when written.
- A text containing spaces or an `=` sign must be quoted; a quoted token is always a description, never an option.

Signal names are comment-only.  They never become assembler symbols, so an annotated listing still reassembles byte-exact.  With no signals declared, the listing still names the port bits each instruction touches (`reads P3.3-7`, `P0.7 = 1`).  `--no-annotate` turns annotation off and gives exactly the listing m740recon produced before signal support.

## What gets annotated

Every instruction that provably touches a declared signal gets a trailing comment.  These lines are from the Star NX-1020 printer firmware:

```
    bbc 6,P0,lab_848e       ;8485  d7 f6 06  PE: branch if paper present
    bbs 7,mem_0052,lab_7307 ;72f7  e7 52 0d  asf_installed: branch if set
    sta P2                  ;8160  85 f0     P2L_PHASE = 0; P2H_PHASE = 9
    sta P2                  ;5030  85 f0     P2H_PHASE = 0
    and #0xf8               ;ff98  29 f8     reads BTN_FONT, BTN_PITCH, BTN_SET, BTN_PF, BTN_OL
    sta P0DIR               ;8150  85 f7     outputs BUSY_PIN, HEAD_STB, DME;
                                        ;  inputs RELEASE_SW, IN_PRIME, TRACTOR_SW, PE, HP
    jsr \sub_ff6e           ;7724  22 6e     -> EE_CS = 1 (asserted)
```

In order, these are:

- bit instructions: `seb`, `clb`, `bbs` and `bbc` on a declared bit
- whole-register stores of a known value (`lda #0x90` / `sta P2`)
- read-modify-writes (`lda P2` / `and #0x0f` / `sta P2` clears the upper phase field)
- masked reads (`lda P3` ... `and #0xf8` reads the five button bits)
- direction and function register writes, shown in pin terms on devices that describe their ports (M50734, M3886)
- calls to small leaf routines with a fixed effect, which is shown at each call

A load followed by `bbs N,a` is reported as a test of that bit.  Instructions with an indexed operand count when the index register's value is known, and reads of a port's input latch count as reads of its pins.  Long annotations continue on comment-only lines, so every listing line stays within the assembler's input buffer.

## External registers and address spaces

740-family MCUs are often paired with a custom gate array, such as the NEC D65006 in the Star NX-1020, that adds what the chip lacks: more I/O, a latched host interface, lamp and print-head drivers, and memory banking.  m740recon handles its registers like any other hardware.  Declare the pointer the firmware reaches them through and what each bit means, and every access is annotated, reported and checked like a port pin.  Nothing here is specific to one gate array; any external chip reached this way works the same.

Firmware usually reaches such hardware through a zero-page pointer.  `pointer` declares one:

```
pointer 0xae 0x4000 space=dme "gate array base"
bit 0x4003.1 LAMP_ONLINE space=dme access=write "ON LINE lamp"
bit 0x4003.2 LAMP_QUIET  space=dme access=write "QUIET lamp"
```

Each `lda/sta [0xae],y` is then tagged with where it goes:

```
    sta [mem_00ae],y        ;c74e  91 ae     [dme:0x4003] LAMP_QUIET = 1
    sta [mem_00ae],y        ;d9d0  91 ae     [dme:0x4003?] LAMP_ONLINE = 1
    lda [mem_00ae],y        ;ff44  b1 ae     [dme:0x4002|0x4003 Y=2,3] reads
    sta [mem_00ae],y        ;65ee  91 ae     [0x4000, dme off: program space] writes
```

`space=` places the pointer and its registers in a second address space that only pointers reach; direct and absolute operands always address the program space.  When the device describes the space (the M50734 describes its DME data space: enabled by P0FUNC bit 5, reached only by `(zp),Y`), each access through the pointer is checked against the enable bit:

- If the bit is provably on, the access is attributed to the space.
- If it is provably off, the access goes to the program space, as in the last line above.
- If it is unknown, the access is attributed to the space and marked `?`.

When a shared routine is entered with different Y values, as at `0xff44`, the tag lists every register it can reach.

## Reports, discovery and lint

- `-s` / `--signals` prints every declared signal with each access (routine, address, kind and annotation), the routines that can reach a write to it, any pointer summaries, leaf routines with suggested names (never applied), and the lint findings.  `--signal NAME` prints one signal's section:

```
EE_CS (P1.0)  out, active high   [source: schematic]  EEPROM chip select
  reset     0x8154  write      EE_CS = 0 (not asserted)
  reset     0x8158  direction  EE_CS: output
  sub_ff6e  0xff6e  set        EE_CS = 1 (asserted)
  sub_ff71  0xff71  clear      EE_CS = 0 (not asserted)
```

- With no signals declared, `--signals` reports which port bits the firmware touches and their direction instead.  The direction comes from the firmware's own direction-register writes where it makes them, and is otherwise inferred from use and marked `?`.  Writing a whole port register does not count as using a pin that is an input, the same rule the analysis applies to a declared input, so every suggested pin is one the lint will find used.  `--suggest` (or `--suggest=pins` for these lines alone) turns the same bits into `pin` lines to paste in and rename, skipping any already declared:

```
P0.6   in     36 test, 3 read, 1 write     sub_4cd1, sub_4e69, sub_6b95, reset, sub_8404, ctl_FF, +13 more
P1.0   out    1 set, 1 clear, 1 write      reset, sub_ff6e, sub_ff71

pin P0.6   P0_6   in    source=guess   # 36 test, 3 read, 1 write
```

- Lint findings are printed to stderr whenever signals are declared, and appear in the `--signals` report and the JSON:

```
m740recon: lint: EE_ORG (P1.3): never read or written by the firmware
```

A finding is a disagreement between the declarations and the firmware, not necessarily an error in either.  This one is a pin wired to the EEPROM's unused ORG input; a direction finding such as `declared out, but the firmware makes it an input at 0x...` can equally mean a pin the firmware deliberately switches at run time.

A quick start for a new board:

```
$ ./venv/bin/m740recon --suggest firmware.bin > board.m740
$ ./venv/bin/m740recon -c board.m740 --signals firmware.bin
```

Options must come before the binary's file name.

## What the analysis assumes

The signal analysis reports only what it can prove.  When a value is unknown it says so (`writes EE_CS (value unknown)`, `Y unknown`) or says nothing.  It works on straight-line code: what it knows is reset at each branch target and after each call.  The exception is the index register Y and the T flag at a branch target whose predecessors are all known; there it carries the values all of them agree on.

Specific rules:

- Read-modify-write is recognized only where a register reads back what was written.  A bit declared with separate read and write meanings is reported as a separate read and write, and an instruction that reads and rewrites such a register (`seb`, `clb`, `inc`, `com` and the like) is reported as reading its `access=read` signals too.
- A whole-register write does not assign meaning to input pins, since writing an input's latch has no effect outside the chip.  A read-modify-write that changes an input's bit is reported.
- The T flag is assumed clear on entry to a routine, and called routines are assumed to return with it unchanged.  The analysis follows `set`, `clt` and paired `php`/`plp`; while T is set or unknown it records only facts that hold either way, and keeps X and Y known across instructions that do not change them, so every operation redirected to M(X) is attributed.  Only when T is known to be set do operations redirected to M(X) report that access: a read for `cmp`, a write for `lda`, both for `and`, `ora` and the like.
- Leaf summaries cover only routines of at most eight instructions with no calls, no jumps out and no loops other than counted delay loops, so every effect runs exactly once.
- A load followed by `and #mask` reads only the signals inside the mask; signals the mask clears are not reported as read.
- Values do not flow across calls, and the "reached from" lists follow static calls only, so they are a lower bound when the firmware has computed calls.
