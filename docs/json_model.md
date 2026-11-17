# m740recon JSON model (`-j` / `--json`)

`m740recon -j` prints one JSON document describing the traced program instead
of the listing.  The output is deterministic: the same input always produces
byte-identical JSON.  Addresses are strings of the form `"0x8130"`.

The format tag is `meta.format = "m740recon-report/1"`.  Keys marked
*signals* appear only when the control file declares at least one `pin` or
`bit`; without signals the document is exactly as before those features
existed.

## Top level

| Key | Type | Content |
|---|---|---|
| `meta` | object | summary counts, see below |
| `symbols` | array | every symbol: `address`, `name`, `comment`, `weak` (true for automatic names such as `sub_8130`) |
| `vectors` | array | interrupt/reset vectors: `address`, `name`, `target`, `target_name`, `target_is_code` |
| `routines` | array | one entry per routine, in address order, see below |
| `xrefs` | array | `address` and `from` (instruction addresses that reference it, code or data) |
| `signals` | array | *signals*: one entry per declared signal, in declaration order |
| `groups` | array | *signals*: `name`, `description`, `members` (signal names) |
| `lint` | array | *signals*: `rule`, `text` for each lint finding |
| `pointers` | array | present when the control file declares a `pointer`; see below |

## `meta`

| Key | Content |
|---|---|
| `format` | `"m740recon-report/1"` |
| `device` | device name, e.g. `"M50734"` |
| `start`, `length` | image start address and length in bytes |
| `routine_count`, `call_edge_count` | sizes of the call graph |
| `indirect_sites` | computed `jsr`/`jmp` sites, counted but not turned into edges |
| `signal_count`, `signal_access_count` | *signals* |

## `routines[]`

A routine is a call target, an entry point, or a vector handler.  It owns
the addresses from its entry up to the next routine's entry.

| Key | Content |
|---|---|
| `address`, `name` | entry address and its symbol |
| `kind` | any of `subroutine`, `entry`, `vector` |
| `instructions` | decoded instructions in the routine's range |
| `calls` | outgoing edges: `to`, `name`, `type` (`call` or `tailcall`), `site` |
| `called_by` | incoming edges: `from`, `name`, `type`, `site` |
| `signals` | *signals*: `name` and `kinds` (sorted access kinds) per signal the routine touches directly |
| `effect` | *signals*, only for leaf routines with fixed effects: the effect texts in order |
| `suggested_name` | *signals*, only for automatically named leaves whose effect is one signal operation |
| `group_primitive` | *signals*: the group, when every signal the routine touches is in that one group |

## `signals[]`

| Key | Content |
|---|---|
| `name`, `kind` | signal name; `pin` or `bit` |
| `location`, `address`, `bits` | e.g. `"P0.6"`, `"0x00f6"`, `[6, 6]` (low, high bit) |
| `direction` | `in`, `out`, `bidir`, or null |
| `active`, `high`, `low` | polarity and level meanings from the declaration, or null |
| `source` | `schematic`, `firmware`, `datasheet`, `guess`, or null |
| `description`, `group` | from the declaration |
| `space` | the address space the signal lives in, or null for the program space |
| `access` | `read` or `write` when the signal applies to only one kind of access, else null |
| `accesses` | every instruction that accesses the signal, see below |
| `written_by` | routines that write it directly (present only if any) |
| `reached_from` | routines that can call, directly or indirectly, a routine that writes it.  Static calls only, so a lower bound when `meta.indirect_sites` is non-zero |

## `signals[].accesses[]`

| Key | Content |
|---|---|
| `site` | instruction address |
| `routine` | name of the routine containing it, or null |
| `kind` | `test`, `read`, `set`, `clear`, `write`, `toggle`, `direction`, `function` |
| `level` | written value (field value for a multi-bit signal); for `test` the level on which the branch is taken; for `direction` 1 = output, 0 = input; for `function` 1 = special function; null when unknown |
| `bit` | index within a multi-bit field when one bit of it is accessed, else null |
| `confidence` | `exact` (the instruction names the bit, or `ldm`); `derived` (needs straight-line value tracking); `assumed` (through a pointer into a space whose enable bit is not proven set at that point); `path` (the instruction reaches one of several locations depending on the path taken to it, e.g. a shared `sta [zp],y` entered with different Y values).  When both `assumed` and `path` apply, `assumed` is reported |
| `scope` | `bit` (the instruction singles out this bit), `mask` (a mask or read-modify-write selects it), `register` (a whole-register access) |
| `text` | the comment the listing shows for this access |

## `pointers[]`

| Key | Content |
|---|---|
| `address` | the zero-page address of the pointer, e.g. `"0xae"` |
| `target`, `space`, `comment` | from the `pointer` declaration |
| `accesses` | every indirect access through it, see below |

## `pointers[].accesses[]`

| Key | Content |
|---|---|
| `site`, `routine` | instruction address and containing routine |
| `op` | `read` or `write` |
| `state` | `program` (pointer has no space), `declared` (space unknown to the device), `on` (enable proven set), `assumed` (enable state unknown), `off` (enable proven clear: the access reaches the program space), `mode` (the addressing mode does not reach the space: program space) |
| `locations` | list of `space` / `address` it can reach, or null when the index register is unknown |
| `index` | the possible values of the index register, or null |
| `index_register` | `Y` for `[zp],y`; `X` for `[zp,x]`, where X selects the pointer |
| `text` | the bracketed tag the listing shows, e.g. `dme:0x4002\|0x4003 Y=2,3` |
