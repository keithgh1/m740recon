"""Infer facts the user did not give: load address, banks, and device.

Used by the CLI when no control-file memory map / device and no -m are given.
Every result carries a confidence word and a short human-readable reason, so
the listing header and notices can say what was inferred and how sure it is.

Load address (`infer_base`): every `jsr` operand in the image votes for the
base that would put its target right after the end of a routine (rts, rti,
jmp, bra, jmp [zp]); the true base collects far more votes than any other.
When the vote is flat (small or call-light code), the image is tried at the
top of memory, accepted when most of its last six words (the 740 vector
area) point at the image start or at routine starts.

Device (`detect_device`): devices are traced in groups that share a vector
layout and opcode set.  A device fits when its vectors point at decoded
instructions and the five words below its table do not (a too-small table
leaves valid-looking vectors there).  Vectors into a ROM that was not given
are left out rather than counted against.  Among layouts that fit, the
device whose named SFRs the code actually uses wins; a device whose zero-page
SFR addresses the code uses as ordinary RAM (pointers, counters, indexed
bases) is penalised.
"""

from collections import Counter, namedtuple

from m740recon.devices import Devices
from m740recon.tables import AddressModes

BaseGuess = namedtuple("BaseGuess", "base method ratio confidence reason")
DeviceGuess = namedtuple(
    "DeviceGuess", "device confidence vector_fit sfr_match external runner_up fits reason")

BASE_RATIO = 1.5          # best / runner-up votes needed to accept a base
BASE_MIN_VOTES = 10      # fewer aligned call targets is too little evidence
_WRITES = ("sta", "stx", "sty", "ldm", "inc", "dec", "seb", "clb", "asl", "lsr",
           "rol", "ror")


# --------------------------------------------------------------- base

def _jsr_targets(data):
    return [data[i + 1] | (data[i + 2] << 8)
            for i in range(len(data) - 2) if data[i] == 0x20]


def _ends_routine(data, off):
    """True when the bytes just before `off` end a routine."""
    if off >= 1 and data[off - 1] in (0x60, 0x40):            # rts, rti
        return True
    if off >= 3 and data[off - 3] == 0x4C:                    # jmp abs
        return True
    if off >= 2 and data[off - 2] in (0x80, 0xB2):            # bra, jmp [zp]
        return True
    return False


def _vote(data):
    """[(votes, base)] best first, over every base the image fits at."""
    n = len(data)
    ends = [o for o in range(n) if _ends_routine(data, o)]
    votes = Counter()
    for t in _jsr_targets(data):
        for o in ends:
            b = t - o
            if 0 <= b <= 0x10000 - n:
                votes[b] += 1
    return sorted(((c, b) for b, c in votes.items()), reverse=True)


def _vector_fallback(data):
    n = len(data)
    base = 0x10000 - n
    good = 0
    for k in range(6):
        w = data[n - 12 + 2 * k] | (data[n - 11 + 2 * k] << 8)
        if w in (0x0000, 0xFFFF) or not base <= w < 0x10000:
            continue
        if w == base or _ends_routine(data, w - base):
            good += 1
    return good


def infer_base(data):
    """Guess where `data` (at most 64 KiB) sits in the 740's address space."""
    if len(data) == 0x10000:
        return BaseGuess(0, "fills", 0.0, "high", "the image fills the 64 KiB address space")
    ranked = _vote(bytes(data))
    if ranked:
        best_votes, best = ranked[0]
        runner = next((c for c, b in ranked[1:] if abs(b - best) >= 16), 0)
        ratio = best_votes / float(runner) if runner else float(best_votes or 0)
        if best_votes >= BASE_MIN_VOTES and ratio >= BASE_RATIO:
            conf = "high" if ratio >= 3 else "medium"
            return BaseGuess(best, "vote", ratio, conf,
                             "%d call targets line up after routine ends (next best %d)"
                             % (best_votes, runner))
    else:
        ratio = 0.0
    good = _vector_fallback(data)
    if good >= 4:
        base = 0x10000 - len(data)
        return BaseGuess(base, "vectors", ratio, "medium",
                         "%d of 6 vectors point into the image" % good)
    return BaseGuess(None, "none", ratio, "low", "no base stands out")


def split_banks(data, size=0x8000):
    """For an image over 64 KiB: [(offset, bank bytes)] of banks that are not
    entirely erased (0xFF) or blank (0x00)."""
    out = []
    for off in range(0, len(data), size):
        bank = bytes(data[off:off + size])
        if bank.count(0xFF) != len(bank) and bank.count(0x00) != len(bank):
            out.append((off, bank))
    return out


# --------------------------------------------------------------- device

def _signature(dev):
    d = Devices[dev]
    return (tuple(d["vector_table"]), frozenset(s.address for s in d["symbol_table"]))


def _written_pages(mem, lo, hi):
    pages = set()
    for a, inst in mem.iter_instructions():
        r = inst.data_ref_address
        if lo <= a < hi and r is not None and not lo <= r < hi and \
                str(inst).split()[0] in _WRITES:
            pages.add(r >> 8)
    return pages


def _vector_class(mem, addr, lo, hi, ram_span):
    if not lo <= addr < hi - 1:
        return "invalid"
    t = mem.read_word(addr)
    if lo <= t < hi:
        return "valid" if mem.is_instruction_start(t) else "invalid"
    in_ram = ram_span is not None and ram_span[0] <= (t >> 8) <= ram_span[1]
    if t not in (0x0000, 0xFFFF) and t >= 0x0100 and not in_ram:
        return "external"
    return "invalid"


def _vector_fit(mem, vectors, lo, hi, ram_span):
    """(fit, share of vectors pointing outside the image)."""
    vt = sorted(vectors)

    def share(addrs):
        cls = [_vector_class(mem, a, lo, hi, ram_span) for a in addrs]
        known = [c for c in cls if c != "external"]
        valid = sum(1 for c in known if c == "valid") / float(len(known)) if known else 0.0
        return valid, cls.count("external") / float(len(cls))
    inside, ext = share(vt)
    below, _ = share([vt[0] - 2 * (i + 1) for i in range(5)])
    return inside - below, ext


def _touched(mem, lo, hi):
    """Addresses the code uses as RAM / SFR: outside the image, or written."""
    out = set()
    for a, inst in mem.iter_instructions():
        r = inst.data_ref_address
        if lo <= a < hi and r is not None and \
                (not lo <= r < hi or str(inst).split()[0] in _WRITES):
            out.add(r)
    return out


def _ram_like_zp(mem, lo, hi):
    out = set()
    for a, inst in mem.iter_instructions():
        if not lo <= a < hi:
            continue
        zp = getattr(inst, "zp_addr", None)
        if zp is None:
            continue
        text = str(inst)
        mn = text.split()[0]
        if inst.addr_mode in (AddressModes.IndirectX, AddressModes.IndirectY,
                              AddressModes.ZeroPageIndirect):
            out.update((zp, (zp + 1) & 0xFF))
        elif mn in ("inc", "dec") and not text.endswith(" a"):
            out.add(zp)
        elif text.endswith(",x") and mn in ("lda", "sta", "ldy", "sty"):
            out.add(zp)
    return out


def _preferred_name(names):
    """Among indistinguishable devices, name the hand-curated core if present."""
    curated = [n for n in names if n.startswith("M")]
    pool = curated or list(names)
    return sorted(pool, key=lambda n: (len(n), n))[0]


def _placement(data, base, mirror_low):
    img = bytearray(b"\xff" * 0x10000)
    img[base:base + len(data)] = data
    ro = [(base, base + len(data))]
    if mirror_low:                    # 13-bit parts alias their 8 KiB space
        lb = base & 0x1FFF
        img[lb:lb + len(data)] = data
        ro.append((lb, lb + len(data)))
    return bytes(img), ro


def detect_device(data, base, build=None):
    """Pick the device for `data` placed at `base`.  `build` is
    command.build_disassembly (passed in to avoid an import cycle)."""
    if build is None:
        from m740recon.command import build_disassembly as build
    lo, hi = base, base + len(data)
    groups = {}
    for dev, d in Devices.items():
        key = (tuple(d["vector_table"]), d.get("unsupported_opcodes", frozenset()))
        groups.setdefault(key, []).append(dev)
    rows = []
    for (vectors, _), devs in groups.items():
        low = min(vectors) < 0x2000 and hi == 0x10000 and len(data) <= 0x2000
        img, ro = _placement(data, base, low)
        try:
            # vectors and SFR use are enough; the proven-table search is not
            # needed to judge a device and only costs time
            mem, _ = build(img, devs[0], 0, readonly_ranges=ro, proven=False)
        except Exception:
            continue
        mlo, mhi = min(a for a, _ in ro), max(b for _, b in ro)
        wp = _written_pages(mem, lo, hi)
        span = (min(wp), max(wp)) if wp else None
        fit, ext = _vector_fit(mem, vectors, mlo, mhi, span)
        touched = _touched(mem, lo, hi)
        ramlike = _ram_like_zp(mem, lo, hi)
        for dev in devs:
            syms = Devices[dev]["symbol_table"]
            named = {s.address for s in syms if not mlo <= s.address < mhi or s.address < 0x100}
            inter = len(touched & named)
            p = inter / float(len(touched)) if touched else 0.0
            r = inter / float(len(named)) if named else 0.0
            f1 = 2 * p * r / (p + r) if p + r else 0.0
            zsfr = {s.address for s in syms if s.address < 0x100 and not s.weak}
            used = zsfr & (touched | ramlike)
            conflict = len(zsfr & ramlike) / float(len(used)) if used else 0.0
            rows.append(dict(dev=dev, fit=fit, ext=ext, f1=f1,
                             key=(round(fit, 6), round(f1 - 0.5 * conflict, 6))))
    if not rows:
        return DeviceGuess(None, "low", 0.0, 0.0, 0.0, None, False, "no device could be traced")
    rows.sort(key=lambda r: r["key"], reverse=True)
    top = [r for r in rows if r["key"] == rows[0]["key"]]
    best = dict(top[0], dev=_preferred_name([r["dev"] for r in top]))
    sig = _signature(best["dev"])
    rival = next((r for r in rows if _signature(r["dev"]) != sig), None)
    runner = None
    if rival is not None:
        same = [r["dev"] for r in rows if r["key"] == rival["key"]
                and _signature(r["dev"]) == _signature(rival["dev"])]
        runner = _preferred_name(same)
    fits = best["fit"] >= 0.5 or best["ext"] >= 0.5
    # Confidence is about the vector layout, which decides what gets decoded.
    # A sibling with the same layout (e.g. M3886 vs M3807) only changes SFR
    # names; it is reported as the runner-up but does not lower confidence.
    layout = tuple(Devices[best["dev"]]["vector_table"])
    other = next((r for r in rows if tuple(Devices[r["dev"]]["vector_table"]) != layout), None)
    if not fits:
        conf = "low"
    elif (other is None or best["fit"] - other["fit"] >= 0.1
          or best["key"][1] - other["key"][1] >= 0.05):
        conf = "high"
    else:
        conf = "medium"
    reason = "vectors fit %.2f, SFR match %.2f" % (best["fit"], best["f1"])
    if best["ext"] >= 0.5:
        reason += ", %d%% of vectors point outside this image" % round(100 * best["ext"])
    return DeviceGuess(best["dev"], conf, best["fit"], best["f1"], best["ext"], runner, fits, reason)


def unmapped_targets(mem, lo, hi):
    """Pages outside [lo, hi) that code jumps or calls into and never writes:
    likely another ROM.  Returns [(first_page, last_page, count)]."""
    from m740recon.tables import FlowTypes
    written = _written_pages(mem, lo, hi)
    span = (min(written), max(written)) if written else None
    hits = Counter()
    for a, inst in mem.iter_instructions():
        if not lo <= a < hi:
            continue
        t = inst.code_ref_address
        if t is None or lo <= t < hi or inst.flow_type not in (
                FlowTypes.SubroutineCall, FlowTypes.UnconditionalJump):
            continue
        if inst.addr_mode == AddressModes.SpecialPage:
            continue      # special-page calls: the page may alias into the ROM
        page = t >> 8
        if t < 0x100 or (span and span[0] <= page <= span[1]):
            continue
        hits[page] += 1
    runs = []
    for page in sorted(hits):
        if runs and page - runs[-1][1] <= 0x10:
            runs[-1] = [runs[-1][0], page, runs[-1][2] + hits[page]]
        else:
            runs.append([page, page, hits[page]])
    return [tuple(r) for r in runs if r[2] >= 3]
