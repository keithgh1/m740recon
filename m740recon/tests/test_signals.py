"""Tests for signal declarations (pin / bit / group) and bit-instruction
annotations.

The golden listing freezes the annotated output of fixtures.signals_image().
Regenerate it intentionally with:
    python -m m740recon.tests.test_signals --update
"""

import io
import os
import sys
import unittest

from m740recon import access, command, control, signals
from m740recon.devices import Devices
from m740recon.tables import Opcodes
from m740recon.tests import asmchain, fixtures

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "golden", "signals_listing.asm")


def _smap(text, device="M50734"):
    cf = control.parse(text)
    return command.build_signal_map(cf, device)


def _produce(annotate=True):
    cf = control.parse(fixtures.SIGNALS_CONTROL)
    return asmchain.disasm_text(fixtures.signals_image(), device="M50734",
                                control=cf, annotate=annotate)


def _line(listing, address):
    tag = ";%04x  " % address
    found = [l for l in listing.splitlines() if tag in l]
    assert len(found) == 1, (address, found)
    return found[0]


class SignalParseTests(unittest.TestCase):
    def test_pin_with_all_options(self):
        cf = control.parse('pin P0.6 PE in active=high high="paper end" '
                           'low="paper present" source=firmware "sensor"\n')
        d = cf.signals[0]
        self.assertEqual((d.kind, d.addr, d.lo, d.hi, d.name), ("pin", "P0", 6, 6, "PE"))
        self.assertEqual(d.direction, "in")
        self.assertEqual(d.active, "high")
        self.assertEqual((d.high, d.low), ("paper end", "paper present"))
        self.assertEqual(d.source, "firmware")
        self.assertEqual(d.description, "sensor")

    def test_numeric_address_and_field_either_order(self):
        cf = control.parse("bit 0x52.7 a\npin 0xf0.3-0 b out\npin 0xf0.4-7 c\n")
        self.assertEqual([(d.addr, d.lo, d.hi) for d in cf.signals],
                         [(0x52, 7, 7), (0xf0, 0, 3), (0xf0, 4, 7)])

    def test_one_word_quoted_description(self):
        cf = control.parse('pin P0.3 LED out "indicator"\n')
        self.assertEqual(cf.signals[0].description, "indicator")

    def test_group_parses_members_and_description(self):
        cf = control.parse('group ee A B "EEPROM"\ngroup g2 C D\n')
        self.assertEqual(cf.groups[0].members, ["A", "B"])
        self.assertEqual(cf.groups[0].description, "EEPROM")
        self.assertEqual(cf.groups[1].members, ["C", "D"])
        self.assertEqual(cf.groups[1].description, "")

    def _bad(self, text, fragment=None):
        with self.assertRaises(control.ControlError) as ctx:
            control.parse(text)
        if fragment:
            self.assertIn(fragment, str(ctx.exception))
        return str(ctx.exception)

    def test_bad_locations(self):
        self._bad("pin P0 X\n", "ADDR.BIT")
        self._bad("pin P0.8 X\n", "out of range")
        self._bad("pin P0.x X\n", "bad bit")
        self._bad("pin .3 X\n", "no address")
        self._bad("pin 0x10000.0 X\n", "out of range")
        self._bad("pin P0.1-2-3 X\n", "bad bit")

    def test_bad_options(self):
        self._bad("pin P0.1 X active=maybe\n", "active=")
        self._bad("pin P0.1 X source=rumor\n", "source=")
        self._bad("pin P0.1 X speed=fast\n", "unknown pin option")
        self._bad("bit 0x10.1 X active=low\n", "unknown bit option")
        self._bad("bit 0x10.1 X out\n")          # bits have no direction
        self._bad("pin P0.1 X high=a high=b\n", "twice")
        self._bad("pin P0.1 9bad\n", "bad signal name")
        self._bad("pin P0.1\n")

    def test_error_carries_line(self):
        msg = self._bad("device M50734\npin P0.9 X\n")
        self.assertIn("line 2", msg)


class SignalMapTests(unittest.TestCase):
    def test_resolves_sfr_and_label_names(self):
        smap = _smap("label 0x40 flags\npin P0.6 PE\nbit flags.2 F\n")
        self.assertEqual(smap.by_name["PE"].address, 0xf6)
        self.assertEqual(smap.by_name["F"].address, 0x40)
        self.assertEqual(smap.by_name["PE"].loc, "P0.6")

    def test_sfr_name_case_insensitive(self):
        self.assertEqual(_smap("pin p0.6 PE\n").by_name["PE"].address, 0xf6)

    def test_lookup_by_bit_and_mask(self):
        smap = _smap("pin P2.0-3 PH\npin P2.4 X\n")
        self.assertIs(smap.at(0xf0, 2), smap.by_name["PH"])
        self.assertIsNone(smap.at(0xf0, 5))
        self.assertEqual([s.name for s in smap.in_mask(0xf0, 0x30)], ["X"])
        self.assertEqual([s.name for s in smap.in_mask(0xf0, 0x11)], ["PH", "X"])

    def _bad(self, text, fragment):
        with self.assertRaises(control.ControlError) as ctx:
            _smap(text)
        self.assertIn(fragment, str(ctx.exception))

    def test_unknown_name(self):
        self._bad("pin PX.1 A\n", "unknown register or label 'PX'")

    def test_automatic_names_not_accepted(self):
        self._bad("bit mem_0052.7 A\n", "unknown register or label")

    def test_duplicate_name(self):
        self._bad("pin P0.1 A\npin P0.2 A\n", "already defined")

    def test_overlap(self):
        self._bad("pin P2.0-3 A\npin P2.3 B\n", "overlaps A")
        self._bad("pin P0.6 A\nbit 0xf6.6 B\n", "overlaps A")

    def test_group_errors(self):
        self._bad("pin P0.1 A\ngroup g A Z\n", "unknown signal Z")
        self._bad("pin P0.1 A\ngroup g A\ngroup h A\n", "already in group g")
        self._bad("pin P0.1 A\ngroup g A\ngroup g A\n", "group g already")

    def test_group_without_signals(self):
        self._bad("group g A\n", "no pin/bit signals")

    def test_group_assignment(self):
        smap = _smap("pin P1.0 CS\npin P1.1 SK\ngroup ee SK CS\n")
        self.assertEqual(smap.by_name["CS"].group, "ee")
        self.assertEqual(smap.groups[0][0], "ee")
        self.assertEqual([s.name for s in smap.groups[0][1]], ["SK", "CS"])

    def test_no_signals_is_empty(self):
        self.assertFalse(_smap("device M50734\n"))


class BitOperationTests(unittest.TestCase):
    def test_all_64_bit_opcodes(self):
        seen = 0
        for number, op in enumerate(Opcodes):
            mnemonic = op.disasm_template.split(" ")[0]
            decoded = access.bit_operation(number)
            if mnemonic not in ("seb", "clb", "bbs", "bbc"):
                self.assertIsNone(decoded, hex(number))
                continue
            seen += 1
            kind, level, bit, on_acc = decoded
            operand = op.disasm_template.split(" ", 1)[1]
            self.assertEqual(bit, int(operand[0]), hex(number))
            self.assertEqual(on_acc, operand.startswith("%d,a" % bit), hex(number))
            want = {"seb": ("set", 1), "clb": ("clear", 0),
                    "bbs": ("test", 1), "bbc": ("test", 0)}[mnemonic]
            self.assertEqual((kind, level), want, hex(number))
        self.assertEqual(seen, 64)


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.smap = _smap(
            'pin P0.6 PE in high="paper end" low="paper present"\n'
            "pin P0.4 STB out active=low\n"
            "pin P1.1 RAW\n"
            "pin P2.0-3 PH\n"
            "bit 0x40.0 G source=guess\n")

    def r(self, name, kind, level, bit=None):
        return access.render(self.smap.by_name[name], kind, level, bit)

    def test_level_text_preferred(self):
        self.assertEqual(self.r("PE", "test", 0), "PE: branch if paper present")
        self.assertEqual(self.r("PE", "set", 1), "PE = 1 (paper end)")

    def test_active_wording(self):
        self.assertEqual(self.r("STB", "clear", 0), "STB = 0 (asserted)")
        self.assertEqual(self.r("STB", "set", 1), "STB = 1 (not asserted)")
        self.assertEqual(self.r("STB", "test", 0), "STB: branch if asserted")

    def test_raw_wording(self):
        self.assertEqual(self.r("RAW", "set", 1), "RAW = 1")
        self.assertEqual(self.r("RAW", "test", 1), "RAW: branch if set")
        self.assertEqual(self.r("RAW", "test", 0), "RAW: branch if clear")

    def test_field_bit(self):
        self.assertEqual(self.r("PH", "set", 1, 2), "PH[2] = 1")
        self.assertEqual(self.r("PH", "test", 0, 3), "PH[3]: branch if clear")

    def test_guess_marked(self):
        self.assertEqual(self.r("G", "set", 1), "G? = 1")


class AnnotatedListingTests(unittest.TestCase):
    def setUp(self):
        self.listing = _produce()

    def test_matches_golden(self):
        self.assertTrue(os.path.exists(GOLDEN), "golden missing; run --update")
        with open(GOLDEN, "r", newline="\n") as f:
            golden = f.read()
        self.assertEqual(self.listing.splitlines(), golden.splitlines())

    def test_expected_annotations(self):
        L = self.listing
        self.assertTrue(_line(L, 0xffc0).endswith("EE_CS = 1 (asserted)"))
        self.assertTrue(_line(L, 0xffc4).endswith("PE: branch if paper present"))
        self.assertTrue(_line(L, 0xffc7).endswith("PE: branch if paper end"))
        self.assertTrue(_line(L, 0xffcc).endswith("STB = 0 (asserted)"))
        self.assertTrue(_line(L, 0xffce).endswith("CR_PHASE[2] = 1"))
        self.assertTrue(_line(L, 0xffd0).endswith("asf_installed: branch if set"))
        self.assertTrue(_line(L, 0xffd3).endswith("pe_detect_off? = 1"))

    def test_undeclared_and_accumulator_forms_untouched(self):
        plain = _produce(annotate=False)
        for addr in (0xffd5, 0xffd7, 0xffd9, 0xffda):
            self.assertEqual(_line(self.listing, addr), _line(plain, addr))

    def test_only_instruction_lines_change(self):
        plain = _produce(annotate=False).splitlines()
        noted = self.listing.splitlines()
        self.assertEqual(len(plain), len(noted))
        for p, n in zip(plain, noted):
            if p != n:
                self.assertTrue(n.startswith(p + " "), (p, n))

    def test_signal_names_never_become_symbols(self):
        for name in ("EE_CS", "PE", "STB", "CR_PHASE", "asf_installed"):
            for line in self.listing.splitlines():
                code = line.split(";", 1)[0]
                self.assertNotIn(name, code)

    @asmchain.requires_as740
    def test_annotated_listing_reassembles(self):
        cf = control.parse(fixtures.SIGNALS_CONTROL)
        asmchain.assert_reassembles(fixtures.signals_image(), device="M50734",
                                    control=cf)


class NoSignalsUnchangedTests(unittest.TestCase):
    def test_control_without_signals_unchanged(self):
        """The same control minus signal lines yields the same listing as
        the annotated one with annotation switched off."""
        text = "\n".join(l for l in fixtures.SIGNALS_CONTROL.splitlines()
                         if l.split(" ")[0] not in ("pin", "bit", "group"))
        cf = control.parse(text + "\n")
        bare = asmchain.disasm_text(fixtures.signals_image(), device="M50734",
                                    control=cf)
        self.assertEqual(bare, _produce(annotate=False))


class CliTests(unittest.TestCase):
    def _run(self, *args):
        import tempfile, shutil
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        rom = os.path.join(d, "rom.bin")
        with open(rom, "wb") as f:
            f.write(fixtures.signals_image())
        ctl = os.path.join(d, "fw.m740")
        with open(ctl, "w") as f:
            f.write(fixtures.SIGNALS_CONTROL)
        buf = io.StringIO()
        old_out, old_argv = sys.stdout, sys.argv
        sys.stdout = buf
        sys.argv = ["m740recon", "-c", ctl] + list(args) + [rom]
        try:
            command.main()
        finally:
            sys.stdout, sys.argv = old_out, old_argv
        return buf.getvalue()

    def test_cli_annotates_by_default(self):
        self.assertIn("PE: branch if paper present", self._run())

    def test_cli_no_annotate(self):
        out = self._run("--no-annotate")
        self.assertNotIn("PE: branch", out)
        self.assertEqual(out, _produce(annotate=False))


def _update():
    with open(GOLDEN, "w", newline="\n") as f:
        f.write(_produce())
    print("wrote", GOLDEN)


if __name__ == "__main__":
    if "--update" in sys.argv:
        _update()
    else:
        unittest.main()
