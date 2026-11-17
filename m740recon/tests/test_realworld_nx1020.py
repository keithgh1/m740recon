"""Real-world tests against the Star NX-1020 printer firmware (M50734).

The control file and board description are in examples/nx1020/ at the top
of the source tree.  The ROM images are downloaded there on first run
(nx1020_roms.py: pinned commit, SHA-256 checked).  The tests skip when the
directory is absent (an installed package with no source tree) or the
download fails.

    M740RECON_REQUIRE_NX1020=1                  (set in CI)
        Fail instead of skipping when the firmware is not available.

    M740RECON_NX1020=/path/to/nx1020.m740       (optional)
        Use another NX-1020 control file instead of the bundled one.  The
        golden-output checks are skipped then: they describe the bundled
        files only.

Two kinds of check:

- Facts.  Expected values come from the NX-1020 project's verified
  documentation (PORT_MAP.md and the annotated disassembly), not from this
  tool's output.
- Goldens (m740recon/tests/golden/nx1020/).  presignal.json holds hashes of
  the output from before signal support existed (commit a3b1c94); with
  signal features off the output must still match it, and it is never
  regenerated.  The other files pin the current signal-aware output;
  after an intended change, regenerate them with
      python -m m740recon.tests.update_nx1020_golden
  and review the diff.
"""

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest

from m740recon import command, control
from m740recon.listing import Printer
from m740recon.tests import asmchain

_HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLED = os.path.normpath(os.path.join(_HERE, "..", "..", "examples",
                                        "nx1020", "nx1020.m740"))
GOLDEN = os.path.join(_HERE, "golden", "nx1020")

CONTROL = os.environ.get("M740RECON_NX1020", "") or BUNDLED
IS_BUNDLED = os.path.normcase(os.path.abspath(CONTROL)) == \
    os.path.normcase(BUNDLED)

REQUIRE = os.environ.get("M740RECON_REQUIRE_NX1020") == "1"

if not os.path.exists(CONTROL):
    _skip_msg = ("NX-1020 example not found at %s (installed package without "
                 "a source tree?)" % CONTROL)
elif IS_BUNDLED:
    from m740recon.tests import nx1020_roms
    _skip_msg = nx1020_roms.ensure()
else:
    _skip_msg = None
_have_fw = _skip_msg is None


def requires_nx1020(cls):
    if _have_fw:
        return cls
    if REQUIRE:
        def setUpClass(c):
            raise AssertionError("M740RECON_REQUIRE_NX1020=1: " + _skip_msg)
        cls.setUpClass = classmethod(setUpClass)
        return cls
    return unittest.skip(_skip_msg)(cls)


def requires_bundled(test):
    return unittest.skipUnless(
        IS_BUNDLED, "golden outputs describe the bundled example only")(test)


def normalized(text):
    """Text with platform line endings removed, for hashing and compare."""
    return "\n".join(text.splitlines()) + "\n"


def digest(text):
    return hashlib.sha256(normalized(text).encode("utf-8")).hexdigest()


def golden_json(name):
    with open(os.path.join(GOLDEN, name), "r") as f:
        return json.load(f)


def golden_text(name):
    with open(os.path.join(GOLDEN, name), "r", newline="") as f:
        return f.read()


def _keep(name, text):
    """Save mismatching output for inspection; return its path."""
    d = tempfile.mkdtemp(prefix="m740recon_nx1020_")
    path = os.path.join(d, name)
    with open(path, "w", newline="") as f:
        f.write(normalized(text))
    return path


_cache = {}


def nx():
    """Load and disassemble the NX-1020 image once per test run."""
    if "cf" not in _cache:
        cf = control.load(CONTROL)
        rom = cf.build_image()
        _cache["cf"] = cf
        _cache["rom"] = rom
    return _cache["cf"], _cache["rom"]


def run_cli(*args):
    """Run the CLI in-process and return stdout."""
    buf = io.StringIO()
    old_out, old_argv = sys.stdout, sys.argv
    sys.stdout = buf
    sys.argv = ["m740recon", "-c", CONTROL] + list(args)
    try:
        command.main()
    finally:
        sys.stdout, sys.argv = old_out, old_argv
    return buf.getvalue()


class _GoldenMixin(object):
    def assertDigest(self, name, text, want):
        got = digest(text)
        if got != want:
            self.fail("%s differs from its golden hash; output saved to %s"
                      % (name, _keep(name, text)))

    def assertGoldenText(self, name, text):
        want = golden_text(name)
        if normalized(text) != normalized(want):
            self.fail("%s differs from %s; output saved to %s"
                      % (name, os.path.join(GOLDEN, name), _keep(name, text)))


@requires_nx1020
class NX1020BaselineTests(_GoldenMixin, unittest.TestCase):
    """With signal features off, output matches the pre-signal reference."""

    @requires_bundled
    def test_listing_unchanged(self):
        self.assertDigest("plain.asm", run_cli("--no-annotate"),
                          golden_json("presignal.json")["plain.asm"])

    @requires_bundled
    def test_analyzed_listing_unchanged(self):
        self.assertDigest("ax.asm", run_cli("--no-annotate", "-a", "-x"),
                          golden_json("presignal.json")["ax.asm"])

    @requires_bundled
    def test_reports_without_signals_unchanged(self):
        # with the board description removed, JSON and call graph match the
        # reference
        want = golden_json("presignal.json")
        self.assertDigest("report.json", run_bare("-j"), want["report.json"])
        self.assertDigest("callgraph.txt", run_bare("-g"),
                          want["callgraph.txt"])


def _lint_text():
    return "".join("%s: %s\n" % f for f in _lint())


# large outputs are pinned by hash in current.json; the rest are stored whole
HASHED = ("annotated.asm", "report.json", "callgraph.txt")


def current_outputs():
    """{golden file name: output} for the signal-aware goldens."""
    return {
        "annotated.asm": _annotated(),
        "report.json": run_cli("-j"),
        "callgraph.txt": run_cli("-g"),
        "signals.txt": run_cli("--signals"),
        "discovery.txt": run_bare("--signals"),
        "suggest.txt": run_bare("--suggest"),
        "lint.txt": _lint_text(),
    }


@requires_nx1020
class NX1020GoldenTests(_GoldenMixin, unittest.TestCase):
    """The current signal-aware output, pinned.  Regenerate with
    python -m m740recon.tests.update_nx1020_golden after an intended
    change."""

    @requires_bundled
    def test_outputs_match_goldens(self):
        hashes = golden_json("current.json")
        outputs = current_outputs()
        self.assertEqual(sorted(hashes), sorted(HASHED))
        for name, text in sorted(outputs.items()):
            if name in HASHED:
                self.assertDigest(name, text, hashes[name])
            else:
                self.assertGoldenText(name, text)


_PORT_REGS = ("P0", "P1", "P2", "P3", "P1IN", "P4IN", "P0DIR", "P1DIR",
              "P2DIR", "P3DIR", "P0FUNC", "P2P3FUNC")


def _annotated():
    if "annotated" not in _cache:
        _cache["annotated"] = run_cli()
    return _cache["annotated"]


def _line_at(listing, address):
    """The listing line at `address`, with any annotation continuation lines
    (long annotations wrap onto comment-only lines) joined back on."""
    from m740recon.listing import _CONTINUATION
    tag = ";%04x  " % address
    lines = listing.splitlines()
    found = [i for i, l in enumerate(lines) if tag in l]
    if len(found) != 1:
        raise AssertionError("no unique listing line at 0x%04x" % address)
    i = found[0]
    text = lines[i]
    while i + 1 < len(lines) and lines[i + 1].startswith(_CONTINUATION):
        i += 1
        text += " " + lines[i][len(_CONTINUATION):]
    return text


def _bit_lines(listing):
    """(line, zp address, bit) for every zero-page bit instruction, decoded
    from the listing's own hexdump column (independent of access.py)."""
    out = []
    for line in listing.splitlines():
        code, sep, rest = line.partition(";")
        parts = code.split()
        if not sep or not parts or parts[0] not in ("seb", "clb", "bbs", "bbc"):
            continue
        if ",a" in parts[1] and parts[1].split(",")[1] == "a":
            continue
        hexbytes = rest[6:15].split()
        opcode, zp = int(hexbytes[0], 16), int(hexbytes[1], 16)
        out.append((line, zp, opcode >> 5, parts[1].split(",")[1]))
    return out


@requires_nx1020
class NX1020BitAnnotationTests(unittest.TestCase):
    """Phase 1: bit-instruction annotations on the real firmware."""

    def setUp(self):
        from m740recon import command
        cf, _ = nx()
        self.smap = command.build_signal_map(cf, cf.device)
        self.assertTrue(self.smap, "NX-1020 control file declares no signals; "
                                   "include the board file")
        self.listing = _annotated()

    def test_port_bit_instruction_count(self):
        # measured on the reference listing: 173 seb/clb/bbs/bbc on port,
        # direction and function registers
        n = sum(1 for _, _, _, reg in _bit_lines(self.listing)
                if reg in _PORT_REGS)
        self.assertEqual(n, 173)

    def test_every_declared_bit_is_annotated_and_no_other(self):
        plain = {l.split(";", 1)[1][:4]: l for l in
                 run_cli("--no-annotate").splitlines() if ";" in l}
        checked = 0
        from m740recon import access
        from m740recon.devices import Devices
        cf, _ = nx()
        shadows = access.port_shadows(Devices[cf.device].get("ports"))
        for line, zp, bit, _ in _bit_lines(self.listing):
            before = plain[line.split(";", 1)[1][:4]]
            sig = self.smap.at(zp, bit)
            if sig is None and zp in shadows and line.split()[0] in ("seb",
                                                                    "clb"):
                # a direction/function register bit: names the pin's signal
                sig = self.smap.at(shadows[zp][0], bit)
            if sig is None:
                self.assertEqual(line, before)
            else:
                self.assertTrue(line.startswith(before + " "), line)
                self.assertIn(sig.name, line[len(before):], line)
                checked += 1
        self.assertGreater(checked, 100)

    def test_paper_end_test_in_main_loop(self):
        # PORT_MAP.md: main_loop @0x8485 does bbc 6,P0 and skips the paper-out
        # handling when P0.6 is clear; P0.6 LOW = paper present
        self.assertTrue(_line_at(self.listing, 0x8485).endswith(
            "PE: branch if paper present"))

    def test_eeprom_chip_select_primitives(self):
        # PORT_MAP.md: sub_ff6e sets CS, sub_ff71 clears CS,
        # sub_ff74 sets DI, sub_ff77 clears DI
        self.assertIn("EE_CS = 1", _line_at(self.listing, 0xff6e))
        self.assertIn("EE_CS = 0", _line_at(self.listing, 0xff71))
        self.assertIn("EE_DI = 1", _line_at(self.listing, 0xff74))
        self.assertIn("EE_DI = 0", _line_at(self.listing, 0xff77))

    def test_eeprom_data_out_sampled_in_read_loops(self):
        # PORT_MAP.md: DO sampled via bbc 4,P1 in the read loops
        lines = [l for l, zp, bit, _ in _bit_lines(self.listing)
                 if zp == 0xf3 and bit == 4]
        self.assertTrue(lines)
        for l in lines:
            self.assertIn("EE_DO: branch if", l)

    def test_ram_flag_asf_installed(self):
        # THEORY_OF_OPERATION.md: mem_0052.7 = ASF installed, gating ~45
        # feed-engine sites
        sites = [l for l, zp, bit, _ in _bit_lines(self.listing)
                 if zp == 0x52 and bit == 7]
        self.assertTrue(40 <= len(sites) <= 50, len(sites))
        for l in sites:
            self.assertIn("asf_installed", l)

    def test_p1_3_never_accessed(self):
        # PORT_MAP.md: firmware never accesses P1.3
        self.assertFalse([l for l, zp, bit, _ in _bit_lines(self.listing)
                          if zp == 0xf3 and bit == 3])

    def test_p3_2_never_accessed(self):
        # PORT_MAP.md: P3.2 unconnected, firmware never accesses it
        self.assertFalse([l for l, zp, bit, _ in _bit_lines(self.listing)
                          if zp == 0xee and bit == 2])


def _model():
    if "model" not in _cache:
        import json
        _cache["model"] = json.loads(run_cli("-j"))
    return _cache["model"]


@requires_nx1020
class NX1020SignalReportTests(unittest.TestCase):
    """Phase 2: signal report and JSON on the real firmware."""

    def setUp(self):
        self.model = _model()
        self.sigs = {s["name"]: s for s in self.model["signals"]}

    def test_home_sensor_only_in_home_seek(self):
        # PORT_MAP.md: HP is polled only by the home-seek routine (0xd840).
        # Polling = bit tests; whole-register reads of P0 elsewhere also
        # carry HP and are not polls of it.
        hp = [a for a in self.sigs["HP"]["accesses"] if a["kind"] == "test"]
        self.assertTrue(hp)
        self.assertEqual({a["routine"] for a in hp}, {"home_seek"})

    def test_p1_3_never_accessed(self):
        # PORT_MAP.md: firmware never accesses P1.3 (left as input by init)
        usage = [a for a in self.sigs["EE_ORG"]["accesses"]
                 if a["kind"] not in ("direction", "function")]
        self.assertEqual(usage, [])
        self.assertIn(";   EE_ORG (P1.3)", run_cli("--signals").splitlines())

    def test_release_and_tractor_switch_sites(self):
        # PORT_MAP.md: the release/tractor pair is checked at ~28 sites
        n = sum(1 for name in ("RELEASE_SW", "TRACTOR_SW")
                for a in self.sigs[name]["accesses"] if a["kind"] == "test")
        self.assertTrue(25 <= n <= 31, n)
        # the documented "not push-tractor" pair at 0x9666 tests both bits
        sites = {a["site"] for name in ("RELEASE_SW", "TRACTOR_SW")
                 for a in self.sigs[name]["accesses"]}
        self.assertTrue(any(0x9660 <= int(s, 16) <= 0x9680 for s in sites))

    def test_in_prime_wait_in_int2_handler(self):
        # PORT_MAP.md: isr_int2 spin-waits on bbc 1,P0 for /IN-PRIME release
        ip = [a for a in self.sigs["IN_PRIME"]["accesses"]
              if a["kind"] == "test"]
        self.assertEqual({a["routine"] for a in ip}, {"isr_int2"})

    def test_json_matches_text_report(self):
        text = run_cli("--signals").splitlines()
        for sig in self.model["signals"]:
            for a in sig["accesses"]:
                want = "  %s  %s  %-9s  %s" % ("", a["site"], a["kind"], a["text"])
                self.assertTrue(
                    any(l.endswith(want[2:]) and l.strip().startswith(a["routine"])
                        for l in text), (sig["name"], a))
        self.assertEqual(self.model["meta"]["signal_access_count"],
                         sum(len(s["accesses"]) for s in self.model["signals"]))

def run_bare(*args):
    """Run the CLI on a copy of the NX-1020 control file with its `include`
    lines (the board description) removed, i.e. with no signals declared."""
    with open(CONTROL) as f:
        text = f.read()
    bare = "\n".join(l for l in text.splitlines()
                     if not l.strip().startswith("include "))
    d = os.path.dirname(os.path.abspath(CONTROL))
    fd, path = tempfile.mkstemp(suffix=".m740", dir=d)
    os.close(fd)
    try:
        with open(path, "w") as f:
            f.write(bare + "\n")
        buf = io.StringIO()
        old_out, old_argv = sys.stdout, sys.argv
        sys.stdout = buf
        sys.argv = ["m740recon", "-c", path] + list(args)
        try:
            command.main()
        finally:
            sys.stdout, sys.argv = old_out, old_argv
        return buf.getvalue()
    finally:
        os.remove(path)


@requires_nx1020
class NX1020BareListingTests(unittest.TestCase):
    """Without the board description the listing names port bits."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.lines = {l.split(";")[1][:4]: l for l in run_bare().splitlines()
                     if l.startswith("    ") and ";" in l}

    def test_panel_read_names_button_bits(self):
        self.assertTrue(self.lines["ff98"].endswith("reads P3.3-7"))

    def test_direction_write_in_pin_terms(self):
        self.assertIn("outputs P0.3-5; inputs P0.0-2, P0.6, P0.7",
                      self.lines["8150"])

    def test_home_sensor_test(self):
        self.assertIn("P0.7: branch if set", self.lines["d842"])


@requires_nx1020
class NX1020DiscoveryTests(unittest.TestCase):
    """Phase 3: zero-config discovery with the board description removed."""

    # PORT_MAP.md init values: P0DIR=0x38, P1DIR=0x07, P2DIR=0xFF,
    # P3DIR=0x03 (1 = output).
    DIR_INIT = {"P0": 0x38, "P1": 0x07, "P2": 0xff, "P3": 0x03}

    def setUp(self):
        self.text = run_bare("--signals")
        rows = lambda text: {l.split()[0]: l.split()[1]
                             for l in text.splitlines()
                             if l[:1] == "P" and "." in l.split()[0]}
        # bits singled out by some instruction (before the whole-register
        # section)
        specific = self.text.split("; touched only by whole-register")[0]
        self.rows = rows(specific)
        self.all_rows = rows(self.text)

    def test_directions_agree_with_firmware_init(self):
        """Every reported direction agrees with the documented init value:
        the init direction itself, or 'bidir' where the firmware also
        writes the other direction at run time.  With M50734 port metadata
        the directions come from direction-register writes, so none is a
        use-based guess."""
        self.assertTrue(self.all_rows)
        for loc, got in self.all_rows.items():
            port, bit = loc.split(".")
            if port not in self.DIR_INIT:
                continue
            want = "out" if self.DIR_INIT[port] >> int(bit) & 1 else "in"
            self.assertIn(got, (want, "bidir"), loc)

    def test_unused_bits_not_touched(self):
        # PORT_MAP.md: P3.2 and P1.3 are never accessed by the firmware
        self.assertNotIn("P3.2", self.rows)
        self.assertNotIn("P1.3", self.rows)

    def test_suggest_round_trips(self):
        out = run_bare("--suggest")
        pins = [l for l in out.splitlines() if l.startswith("pin ")]
        with_direction = [d for d in self.all_rows.values() if d != "-"]
        self.assertEqual(len(pins), len(with_direction))
        control.parse("device M50734\n" + out)


@requires_nx1020
class NX1020RegisterAccessTests(unittest.TestCase):
    """Phase 4: whole-register and masked accesses on the real firmware."""

    def setUp(self):
        self.listing = _annotated()
        self.lines = self.listing.splitlines()

    def test_panel_read_mask(self):
        # PORT_MAP.md: panel_read @0xFF8F reads P3 until two reads match,
        # then AND #0xF8 isolates the 5-bit button field
        self.assertTrue(_line_at(self.listing, 0xff98).endswith(
            "reads BTN_FONT, BTN_PITCH, BTN_SET, BTN_PF, BTN_OL"))

    def test_port_init_decodes(self):
        # PORT_MAP.md init: P2=0x90 (initial phase pattern); P1 bit-bang lines
        # idle low; P3 motor commons start at holding bias
        self.assertTrue(_line_at(self.listing, 0x8160).endswith(
            "P2L_PHASE = 0; P2H_PHASE = 9"))
        self.assertIn("EE_CS = 0 (not asserted)", _line_at(self.listing, 0x8154))
        p3 = _line_at(self.listing, 0x8168)
        self.assertIn("CR_CMN_HV = 0 (+5 V hold)", p3)
        self.assertIn("LF_CMN_HV = 0 (+5 V hold)", p3)
        # writes never assign meaning to input pins (latch writes)
        self.assertNotIn("BTN_", p3)
        self.assertNotIn("PE =", _line_at(self.listing, 0x814c))

    def test_stepper_channel_masked_off(self):
        # isr @0x502c: lda P2 ; and #0x0f ; sta P2 clears the P2H channel
        self.assertTrue(_line_at(self.listing, 0x5030).endswith("P2H_PHASE = 0"))

    def test_no_whole_register_access_dropped(self):
        """Every unindexed load/store/compare of a port register that carries
        a declared signal is annotated, or (for a load) its meaning is
        attributed to the masking or bit-testing instruction that follows."""
        cf, _ = nx()
        from m740recon import command
        smap = command.build_signal_map(cf, cf.device)
        regs = {"P0": 0xf6, "P1": 0xf3, "P2": 0xf0, "P3": 0xee, "P0FUNC": 0xf5}
        checked = 0
        for i, line in enumerate(self.lines):
            code, _, rest = line.partition(";")
            parts = code.split()
            if len(parts) != 2 or parts[0] in ("seb", "clb", "bbs", "bbc"):
                continue
            reg = parts[1]
            if reg not in regs or not smap.on_address(regs[reg]):
                continue
            if parts[0] == "sta" and all(s.direction == "in" for s in
                                         smap.on_address(regs[reg])):
                continue
            checked += 1
            if len(rest) > 16:
                continue                              # annotated itself
            self.assertEqual(parts[0], "lda", line)
            follow = self.lines[i + 1:i + 6]
            # the mask, the A bit test, or (read-modify-write) the store
            # back to the same register carries the meaning
            self.assertTrue(any(len(l.partition(";")[2]) > 16 and
                                (",a," in l or l.split()[0] == "and" or
                                 l.split()[:2] == ["sta", reg])
                                for l in follow), line)
        self.assertGreaterEqual(checked, 15)


@requires_nx1020
class NX1020EffectTests(unittest.TestCase):
    """Phase 5: routine effect summaries on the real firmware."""

    def setUp(self):
        self.model = _model()
        self.routines = {r["name"]: r for r in self.model["routines"]}
        self.sigs = {s["name"]: s for s in self.model["signals"]}

    def test_eeprom_primitives_summarized(self):
        # PORT_MAP.md: sub_ff6e set CS / sub_ff71 clear CS,
        # sub_ff74 set DI / sub_ff77 clear DI
        want = {"sub_ff6e": ("EE_CS = 1", "ee_cs_set"),
                "sub_ff71": ("EE_CS = 0", "ee_cs_clear"),
                "sub_ff74": ("EE_DI = 1", "ee_di_set"),
                "sub_ff77": ("EE_DI = 0", "ee_di_clear")}
        for name, (effect, suggestion) in want.items():
            r = self.routines[name]
            self.assertEqual(len(r["effect"]), 1, name)
            self.assertTrue(r["effect"][0].startswith(effect), name)
            self.assertEqual(r["suggested_name"], suggestion)
            self.assertEqual(r["group_primitive"], "eeprom")

    def test_clock_pulse_summarized(self):
        # PORT_MAP.md: sub_ff7a = one full SK clock pulse (raise, delay, drop)
        r = self.routines["sub_ff7a"]
        self.assertEqual(r["effect"], ["EE_SK = 1", "EE_SK = 0"])
        self.assertEqual(r["suggested_name"], "ee_sk_pulse")

    def test_call_sites_carry_effect(self):
        listing = _annotated()
        calls = [l for l in listing.splitlines()
                 if l.split()[:1] == ["jsr"] and "sub_ff6e" in l]
        self.assertTrue(calls)
        for l in calls:
            self.assertTrue(l.endswith("-> EE_CS = 1 (asserted)"), l)

    def test_eeprom_routines_reach_eeprom_group(self):
        # eeprom_read @0x771D and eeprom_write @0x775D drive the bus
        for sig in ("EE_CS", "EE_DI", "EE_SK"):
            reached = self.sigs[sig]["reached_from"]
            self.assertIn("eeprom_read", reached, sig)
            self.assertIn("eeprom_write", reached, sig)


def _lint(control_path=None):
    """Lint findings for the NX-1020 control file (or a variant of it)."""
    from m740recon import access
    cf = control.load(control_path or CONTROL)
    rom = cf.build_image()
    memory, _ = command.build_disassembly(
        rom, cf.device, 0, **command.control_args(cf, bytearray(rom)))
    smap = command.build_signal_map(cf, cf.device)
    accs = command.signal_accesses(memory, smap, cf.device)
    return command.signal_lint(memory, smap, accs, cf.device)


@requires_nx1020
class NX1020LintTests(unittest.TestCase):
    """Phase 6: port-mode decoding and board lint on the real firmware."""

    # PORT_MAP.md: init writes P0DIR=0x38 @0x8150, P1DIR=0x07 @0x8158,
    # P2DIR=0xFF @0x8164, P3DIR=0x03 @0x816c
    INIT_DIR_SITES = ("0x8150", "0x8158", "0x8164", "0x816c")

    def setUp(self):
        self.findings = _lint()

    def test_init_direction_writes_agree_with_pin_map(self):
        for rule, text in self.findings:
            if rule == "direction":
                for site in self.INIT_DIR_SITES:
                    self.assertNotIn(site, text)

    def test_init_direction_store_decoded(self):
        line = _line_at(_annotated(), 0x8150)
        self.assertTrue(line.endswith(
            "outputs BUSY_PIN, HEAD_STB, DME; inputs RELEASE_SW, IN_PRIME, "
            "TRACTOR_SW, PE, HP"))

    def test_p1_3_wired_but_never_accessed(self):
        # PORT_MAP.md: P1.3 (EEPROM pin 6) is wired but never accessed
        self.assertIn(("unused", "EE_ORG (P1.3): never read or written by "
                                 "the firmware"), self.findings)

    def test_flipped_direction_adds_exactly_one_contradiction(self):
        import re
        import tempfile
        d = os.path.dirname(os.path.abspath(CONTROL))
        pe_in = re.compile(r"^(pin\s+P0\.6\s+PE\s+)in\b", re.M)
        # find the file (the control file or one it includes) declaring PE
        with open(CONTROL) as f:
            ctl = f.read()
        holder, text = None, None
        if pe_in.search(ctl):
            holder, text = CONTROL, ctl
        for inc in re.findall(r"^include\s+(\S+)", ctl, re.M):
            path = os.path.join(d, inc)
            with open(path) as f:
                body = f.read()
            if pe_in.search(body):
                holder, text = path, body
        self.assertIsNotNone(holder, "no 'pin P0.6 PE in' declaration found")
        flipped = pe_in.sub(r"\1out", text, count=1)
        paths = []
        try:
            fd, bpath = tempfile.mkstemp(suffix=".m740", dir=d)
            os.close(fd)
            paths.append(bpath)
            with open(bpath, "w") as f:
                f.write(flipped)
            if holder == CONTROL:
                cpath = bpath
            else:
                fd, cpath = tempfile.mkstemp(suffix=".m740", dir=d)
                os.close(fd)
                paths.append(cpath)
                name = os.path.basename(holder)
                with open(cpath, "w") as f:
                    f.write(re.sub(r"^include\s+" + re.escape(name) + r"\s*$",
                                   "include " + os.path.basename(bpath),
                                   ctl, flags=re.M))
            after = _lint(cpath)
        finally:
            for p in paths:
                os.remove(p)
        before_dir = [t for r, t in self.findings if r == "direction"]
        after_dir = [t for r, t in after if r == "direction"]
        self.assertEqual(len(after_dir), len(before_dir) + 1)
        added = [t for t in after_dir if t not in before_dir]
        self.assertTrue(added[0].startswith("PE (P0.6): declared out, but the "
                                            "firmware makes it an input"))


@requires_nx1020
class NX1020QueryTests(unittest.TestCase):
    """Phase 7: narrow queries on the real firmware."""

    def test_routine_query(self):
        # PORT_MAP.md: panel_read @0xFF8F = read P3 twice, AND #0xF8, return
        out = run_cli("--routine", "panel_read").strip().splitlines()
        code = [l for l in out if l.startswith("    ") and ";" in l
                and not l.lstrip().startswith(";")]
        self.assertEqual([l.split()[0] for l in code],
                         ["lda", "ldm", "cmp", "bne", "and", "rts"])
        self.assertEqual(run_cli("--routine", "0xff8f").strip().splitlines(),
                         out)

    def test_signal_query(self):
        out = run_cli("--signal", "HP")
        self.assertIn("HP (P0.7)", out)
        self.assertIn("home_seek", out)
        self.assertNotIn("PE (P0.6)", out)


@requires_nx1020
class NX1020GateArrayTests(unittest.TestCase):
    """Phase 8: the gate array behind the mem_00ae pointer in the DME data
    space (PORT_MAP.md, "Gate array & hardware output")."""

    def setUp(self):
        self.listing = _annotated()
        self.model = _model()
        ptrs = {p["address"]: p for p in self.model.get("pointers", [])}
        self.assertIn("0xae", ptrs, "board file declares no 0xae pointer")
        self.sites = {int(a["site"], 16): a for a in ptrs["0xae"]["accesses"]}

    def test_every_pointer_access_accounted_for(self):
        lines = [l for l in self.listing.splitlines() if "[mem_00ae]" in l]
        self.assertEqual(len(lines), 48)
        for l in lines:
            self.assertIn(";", l)
            note = l.split(";", 1)[1][15:].strip()
            self.assertTrue(note.startswith("["), l)
        self.assertEqual(len(self.sites), 48)

    def test_io_primitives(self):
        # ff33 read reg2 / ff3d read reg3 share the read at 0xff44;
        # ff4a reg0, ff58 reg1, ff51 reg2, ff61 reg3 share the write at 0xff68
        rd = self.sites[0xff44]
        self.assertEqual([l["address"] for l in rd["locations"]],
                         ["0x4002", "0x4003"])
        self.assertEqual(rd["index"], [2, 3])
        wr = self.sites[0xff68]
        self.assertEqual([l["address"] for l in wr["locations"]],
                         ["0x4000", "0x4001", "0x4002", "0x4003"])
        self.assertTrue(all(l["space"] == "dme" for l in wr["locations"]))

    def test_host_byte_ready_polls(self):
        # reg0 bit 7 = IA7, polled at 6543, 7E82, 94F0, 9550, 956D
        for lda in (0x6543, 0x7e82, 0x94f0, 0x9550, 0x956d):
            self.assertEqual(self.sites[lda]["locations"][0]["address"],
                             "0x4000")
            following = self.listing.split(";%04x  " % lda, 1)[1]
            test = next(l for l in following.splitlines()[1:4]
                        if ",a," in l)
            self.assertIn("HOST_BYTE_READY: branch if", test)

    def test_host_data_reads(self):
        # reg1 read = the latched host data byte (read at 64E7 and 6595)
        for site in (0x64e7, 0x6595):
            self.assertIn("reads HOST_DATA", _line_at(self.listing, site))

    def test_ack_pulse(self):
        # sub_65de pulses reg2 bit 2 (/ACK)
        self.assertTrue(_line_at(self.listing, 0x65e6).endswith("HOST_ACK = 1"))
        self.assertTrue(_line_at(self.listing, 0x65f7).endswith("HOST_ACK = 0"))

    def test_host_interface_enabled_at_837e(self):
        # reg2 bit 0 is set at 0x837E after the reset hold-off window
        self.assertTrue(_line_at(self.listing, 0x837e).endswith(
            "HOST_IF_EN = 1"))

    def test_dme_off_idiom_redirects_to_program_space(self):
        # the DME-off idiom (seb 5,P0 ; clb 5,P0FUNC) at 0x65E8/0x65EA and
        # 0x8380/0x8382: the pointer writes right after it cannot reach the
        # gate array
        for site in (0x65ee, 0x8384):
            self.assertEqual(self.sites[site]["state"], "off")
            self.assertIn("dme off: program space",
                          _line_at(self.listing, site))


@requires_nx1020
class NX1020ReassemblyTests(unittest.TestCase):
    @asmchain.requires_as740
    def test_full_image_reassembles(self):
        cf, rom = nx()
        listing = run_cli()
        self.assertEqual(asmchain.assemble(listing, 0, 0x10000), bytes(rom))


if __name__ == "__main__":
    unittest.main()
