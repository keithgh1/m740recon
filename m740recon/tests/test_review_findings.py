"""Regression tests for the findings of an adversarial review of the signal
features.  Each test reproduces one reported defect; numbers refer to the
review's findings."""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest

from m740recon import access, command, control, effects, report
from m740recon.tests import asmchain

P0, P1, P1IN, P4IN, P0FUNC = 0xf6, 0xf3, 0xf2, 0xeb, 0xf5


def _image(code, extra=None, base=0x8000):
    rom = bytearray(0x10000)
    rom[base:base + len(code)] = bytes(code)
    for addr, data in (extra or {}).items():
        rom[addr:addr + len(data)] = bytes(data)
    for v in range(0xFFF4, 0x10000, 2):
        rom[v], rom[v + 1] = base & 0xff, base >> 8
    return bytes(rom)


def _analyze(code, text, device="M50734", extra=None):
    rom = _image(code, extra)
    cf = control.parse("device %s\n" % device + text)
    memory, symtab = command.build_disassembly(
        rom, device, 0, **command.control_args(cf, bytearray(rom)))
    smap = command.build_signal_map(cf, device)
    sites = []
    accs = command.signal_accesses(memory, smap, device, sites)
    return memory, symtab, smap, accs, {s.site: s for s in sites}


def _facts(accs, site=None):
    return [(a.address, a.signal.name, a.kind, a.level) for a in accs
            if site is None or a.address == site]


def _cli(rom, control_text=None, *args):
    d = tempfile.mkdtemp()
    try:
        rp = os.path.join(d, "rom.bin")
        with open(rp, "wb") as f:
            f.write(rom)
        argv = ["m740recon", "-m", "M50734"]
        if control_text is not None:
            cp = os.path.join(d, "fw.m740")
            with open(cp, "w") as f:
                f.write(control_text)
            argv += ["-c", cp]
        out, err = io.StringIO(), io.StringIO()
        old = sys.stdout, sys.stderr, sys.argv
        sys.stdout, sys.stderr = out, err
        sys.argv = argv + list(args) + [rp]
        code = 0
        try:
            command.main()
        except SystemExit as e:
            code = e.code
        finally:
            sys.stdout, sys.stderr, sys.argv = old
        return code, out.getvalue(), err.getvalue()
    finally:
        shutil.rmtree(d, True)


class F01LongAnnotationTests(unittest.TestCase):
    TEXT = "".join(
        'pin P1.%d SOL%d out high="select printer head solenoid %d for the '
        'next firing cycle" low="release solenoid %d"\n' % (b, b, b, b)
        for b in range(8))

    def _listing(self):
        rom = _image([0x3c, 0xff, P1, 0x60], base=0xffc0)[0xffc0:]
        cf = control.parse("device M50734\n" + self.TEXT)
        return rom, cf, asmchain.disasm_text(rom, device="M50734", control=cf)

    def test_lines_stay_short(self):
        _, _, listing = self._listing()
        self.assertLessEqual(max(len(l) for l in listing.splitlines()), 132)
        for b in range(8):
            self.assertIn("SOL%d = 1" % b, listing)

    @asmchain.requires_as740
    def test_dense_annotation_reassembles(self):
        rom, cf, _ = self._listing()
        asmchain.assert_reassembles(rom, device="M50734", control=cf)


class F02IncDecAccumulatorTests(unittest.TestCase):
    TEXT = ("pointer 0xae 0x4000\nbit 0x4000.0 R0\nbit 0x4001.0 R1\n"
            "bit 0x50.0-7 V\n")

    def test_inc_a(self):
        # lda #0 ; inc a ; sta $50 ; tay ; sta [$ae],y
        _, _, _, accs, sites = _analyze(
            [0xa9, 0x00, 0x3a, 0x85, 0x50, 0xa8, 0x91, 0xae, 0x60], self.TEXT)
        self.assertIn((0x8003, "V", "write", 1), _facts(accs))
        self.assertEqual(sites[0x8006].locs, [(None, 0x4001)])

    def test_dec_a(self):
        _, _, _, accs, _ = _analyze(
            [0xa9, 0x05, 0x1a, 0x85, 0x50, 0x60], self.TEXT)
        self.assertEqual(_facts(accs), [(0x8003, "V", "write", 4)])


class F03IndexedOperandTests(unittest.TestCase):
    def test_indexed_store_clears_dme(self):
        # seb 5,P0FUNC ; ldx #0 ; lda #0 ; sta P0FUNC,x ; ldy #0 ; sta [$ae],y
        code = [0xaf, P0FUNC, 0xa2, 0x00, 0xa9, 0x00, 0x95, P0FUNC,
                0xa0, 0x00, 0x91, 0xae, 0x60]
        _, _, _, accs, sites = _analyze(
            code, "pointer 0xae 0x4000 space=dme\n"
                  "bit 0x4000.0 GA space=dme\nbit 0x4000.0 ROMBIT\n")
        self.assertEqual(sites[0x800a].state, "off")
        self.assertNotIn("GA", [a.signal.name for a in accs])

    def test_unknown_indexed_store_makes_dme_unknown(self):
        # seb 5,P0FUNC ; ldx $10 ; sta $00,x ; ldy #0 ; sta [$ae],y
        code = [0xaf, P0FUNC, 0xa6, 0x10, 0x95, 0x00, 0xa0, 0x00,
                0x91, 0xae, 0x60]
        _, _, _, _, sites = _analyze(code, "pointer 0xae 0x4000 space=dme\n"
                                           "bit 0x4000.0 GA space=dme\n")
        self.assertEqual(sites[0x8008].state, "assumed")

    def test_indexed_read_seen_by_discovery(self):
        # ldx #0 ; lda P0,x ; and #1 ; rts
        rom = _image([0xa2, 0x00, 0xb5, P0, 0x29, 0x01, 0x60])
        code, out, _ = _cli(rom, None, "--signals")
        self.assertNotIn("no port bit accesses found", out)
        self.assertIn("P0.0", out)


class F04SuggestRoundTripTests(unittest.TestCase):
    def test_input_only_port(self):
        # bbs 3,P4IN,+0 ; rts
        rom = _image([0x67, P4IN, 0x00, 0x60])
        _, out, _ = _cli(rom, None, "--suggest")
        self.assertIn(" in ", out)
        code, listing, err = _cli(rom, "device M50734\n" + out)
        self.assertEqual(code, 0, err)
        self.assertIn("branch if", listing)

    def test_name_already_taken(self):
        # seb 0,P1 ; rts ; with a RAM bit already named P1_0
        rom = _image([0x0f, P1, 0x60])
        base = "device M50734\nbit 0x40.0 P1_0\n"
        _, out, _ = _cli(rom, base, "--suggest")
        code, _, err = _cli(rom, base + out)
        self.assertEqual(code, 0, err)


class F05InputLatchTests(unittest.TestCase):
    def test_discovery_sees_latch_reads(self):
        rom = _image([0x07, P1IN, 0x00, 0x60])            # bbs 0,P1IN,+0
        _, out, _ = _cli(rom, None, "--signals")
        self.assertIn("P1.0", out)

    def test_declared_pin_read_through_latch(self):
        _, _, _, accs, _ = _analyze([0x07, P1IN, 0x00, 0x60],
                                    "pin P1.0 READY in\n")
        self.assertEqual(_facts(accs), [(0x8000, "READY", "test", 1)])


class F06SameAddressTests(unittest.TestCase):
    def test_split_read_write_signals(self):
        # lda $50 ; sta $50
        _, _, _, accs, _ = _analyze(
            [0xa5, 0x50, 0x85, 0x50, 0x60],
            "bit 0x50.0 STATUS access=read\nbit 0x50.0 COMMAND access=write\n")
        kinds = {(n, k) for _, n, k, _ in _facts(accs)}
        self.assertEqual(kinds, {("STATUS", "read"), ("COMMAND", "write")})

    def test_second_store_is_not_another_toggle(self):
        # lda $50 ; eor #1 ; sta $50 ; sta $50
        _, _, _, accs, _ = _analyze(
            [0xa5, 0x50, 0x49, 0x01, 0x85, 0x50, 0x85, 0x50, 0x60],
            "bit 0x50.0 F\n")
        self.assertEqual(_facts(accs), [(0x8004, "F", "toggle", None)])

    def test_other_write_breaks_rmw(self):
        # lda $50 ; ldm #0,$50 ; ora #1 ; sta $50: not a set of one bit on
        # the original contents
        _, _, _, accs, _ = _analyze(
            [0xa5, 0x50, 0x3c, 0x00, 0x50, 0x09, 0x01, 0x85, 0x50, 0x60],
            "bit 0x50.0 F\nbit 0x50.1 G\n")
        g = [f for f in _facts(accs) if f[0] == 0x8007 and f[1] == "G"]
        self.assertEqual(g, [(0x8007, "G", "write", None)])


class F07TransferModeTests(unittest.TestCase):
    TEXT = "bit 0x50.0-7 V\n"

    def test_t_flag_across_branch(self):
        # set ; bra +0 ; lda #1 ; sta $50 ; rts
        _, _, _, accs, _ = _analyze(
            [0x32, 0x80, 0x00, 0xa9, 0x01, 0x85, 0x50, 0x60], self.TEXT)
        self.assertNotIn((0x8005, "V", "write", 1), _facts(accs))

    def test_plp_makes_t_unknown(self):
        # plp ; lda #1 ; sta $50
        _, _, _, accs, _ = _analyze(
            [0x28, 0xa9, 0x01, 0x85, 0x50, 0x60], self.TEXT)
        self.assertNotIn((0x8003, "V", "write", 1), _facts(accs))

    def test_php_plp_pair_keeps_t_clear(self):
        # php ; plp ; lda #1 ; sta $50
        _, _, _, accs, _ = _analyze(
            [0x08, 0x28, 0xa9, 0x01, 0x85, 0x50, 0x60], self.TEXT)
        self.assertIn((0x8004, "V", "write", 1), _facts(accs))


class F08RoutineQueryTests(unittest.TestCase):
    def _rom(self):
        rom = bytearray(0x40)
        code = [0x20, 0xc8, 0xff,        # ffc0 jsr ffc8
                0x4c, 0xd0, 0xff,        # ffc3 jmp ffd0
                0x00, 0x00,
                0x60,                    # ffc8 rts
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0xea, 0x60]              # ffd0 nop ; rts
        rom[0:len(code)] = bytes(code)
        rom[0x3e:0x40] = bytes([0xc0, 0xff])
        return bytes(rom)

    def test_routine_follows_its_own_blocks(self):
        _, out, _ = _cli(self._rom(), None, "--routine", "0xffc0")
        self.assertIn(";ffd0", out)
        self.assertNotIn(";ffc8", out)

    def test_callee_alone(self):
        _, out, _ = _cli(self._rom(), None, "--routine", "0xffc8")
        self.assertIn(";ffc8", out)
        self.assertNotIn(";ffd0", out)
        self.assertNotIn(".byte", out)


class F09LeafLoopTests(unittest.TestCase):
    TEXT = "pin P1.0 CS out\n"

    def _summaries(self, leaf):
        memory, _, _, accs, _ = _analyze([0x20, 0x00, 0x90, 0x60], self.TEXT,
                                         extra={0x9000: leaf})
        return effects.leaf_summaries(memory, accs)

    def test_infinite_loop_blocks_effect(self):
        # sec ; bcs -3 (back to sec) ; seb 0,P1 ; rts
        self.assertNotIn(0x9000, self._summaries(
            [0x38, 0xb0, 0xfd, 0x0f, P1, 0x60]))

    def test_loop_repeats_effect(self):
        # ldx #2 ; seb 0,P1 ; clb 0,P1 ; dex ; bne -7 ; rts
        self.assertNotIn(0x9000, self._summaries(
            [0xa2, 0x02, 0x0f, P1, 0x1f, P1, 0xca, 0xd0, 0xf9, 0x60]))

    def test_counted_delay_loop_still_summarized(self):
        # seb 0,P1 ; ldx #5 ; dex ; bne -3 ; clb 0,P1 ; rts
        self.assertIn(0x9000, self._summaries(
            [0x0f, P1, 0xa2, 0x05, 0xca, 0xd0, 0xfd, 0x1f, P1, 0x60]))


class F10LintMaskWriteTests(unittest.TestCase):
    def test_mask_write_to_input_is_linted(self):
        # lda P0 ; ora #1 ; sta P0
        memory, _, smap, accs, _ = _analyze(
            [0xa5, P0, 0x09, 0x01, 0x85, P0, 0x60], "pin P0.0 READY in\n")
        findings = command.signal_lint(memory, smap, accs, "M50734")
        rules = {r for r, _ in findings}
        self.assertIn("in-written", rules)
        self.assertNotIn("unused", rules)


class F11SignalQueryPointerTests(unittest.TestCase):
    def test_narrow_view_has_no_contradicting_pointer_section(self):
        rom = _image([0xa0, 0x00, 0xa9, 0x01, 0x91, 0xae, 0x60])
        text = ("device M50734\npointer 0xae 0x4000\npointer 0xb0 0x5000\n"
                "bit 0x4000.0 TARGET\n")
        _, full, _ = _cli(rom, text, "--signals")
        self.assertIn("1 access(es)", full)
        _, one, _ = _cli(rom, text, "--signal", "TARGET")
        self.assertNotIn("0 access(es)", one)
        self.assertNotIn("0xb0", one)


class F12AssumedMarkerTests(unittest.TestCase):
    TEXT = "pointer 0xae 0x4000 space=dme\nbit 0x4002.0 R2 space=dme\n" \
           "bit 0x4003.0 R3 space=dme\n"

    def test_unknown_index_keeps_marker(self):
        memory, _, _, accs, sites = _analyze(
            [0xa4, 0x50, 0xb1, 0xae, 0x60], self.TEXT)
        self.assertEqual(sites[0x8002].state, "assumed")
        self.assertIn("?", access.pointer_tag(sites[0x8002]))

    def test_path_does_not_hide_assumed(self):
        # R1: ldy #2 ; bra J   R2: ldy #3 ; J: sta [$ae],y  (DME unknown)
        code = [0x20, 0x00, 0x90, 0x20, 0x04, 0x90, 0x60]
        extra = {0x9000: [0xa0, 0x02, 0x80, 0x02, 0xa0, 0x03,
                          0xa9, 0x01, 0x91, 0xae, 0x60]}
        _, _, _, accs, sites = _analyze(code, self.TEXT, extra=extra)
        self.assertEqual(sites[0x9008].state, "assumed")
        for a in accs:
            if a.address == 0x9008:
                self.assertEqual(a.confidence, "assumed")


class F13QuotedDescriptionTests(unittest.TestCase):
    def test_description_with_equals(self):
        cf = control.parse('pin P0.0 DATA "logic=high means ready"\n')
        self.assertEqual(cf.signals[0].description, "logic=high means ready")

    def test_quoted_direction_word_is_description(self):
        cf = control.parse('pin P0.0 DATA "out"\n')
        self.assertIsNone(cf.signals[0].direction)
        self.assertEqual(cf.signals[0].description, "out")

    def test_pointer_comment_with_equals(self):
        cf = control.parse('pointer 0xae 0x4000 "register=base"\n')
        self.assertEqual(cf.pointers[0].comment, "register=base")

    def test_group_escaped_quote(self):
        cf = control.parse('pin P0.0 A\npin P0.1 B\n'
                           'group g A B "the \\"main\\" bus"\n')
        self.assertEqual(cf.groups[0].description, 'the "main" bus')

    def test_bad_quoting_reports_line(self):
        with self.assertRaises(control.ControlError) as ctx:
            control.parse('device M50734\ngroup g A B "open\n')
        self.assertIn("line 2", str(ctx.exception))


class F14PointerOnlyTests(unittest.TestCase):
    def test_pointer_only_still_runs_discovery(self):
        rom = _image([0x0f, P1, 0x60])
        _, out, _ = _cli(rom, "device M50734\npointer 0xae 0x4000\n",
                         "--signals")
        self.assertIn("port discovery", out)

    def test_pointer_only_json_has_no_signal_sections(self):
        rom = _image([0x0f, P1, 0x60])
        _, out, _ = _cli(rom, "device M50734\npointer 0xae 0x4000\n", "-j")
        model = json.loads(out)
        self.assertNotIn("signals", model)
        self.assertIn("pointers", model)

    def test_pointer_only_no_lint(self):
        rom = _image([0x0f, P1, 0x60])
        _, _, err = _cli(rom, "device M50734\npointer 0xae 0x4000\n")
        self.assertNotIn("lint", err)


class F15IndexedIndirectIndexTests(unittest.TestCase):
    def test_x_reported(self):
        # ldx #2 ; lda [$ac,x]
        _, _, _, _, sites = _analyze([0xa2, 0x02, 0xa1, 0xac, 0x60],
                                     "pointer 0xae 0x4000\n")
        ps = sites[0x8002]
        self.assertEqual(ps.locs, [(None, 0x4000)])
        self.assertEqual(ps.index, [2])
        self.assertEqual(ps.register, "X")


class F16PulseNameTests(unittest.TestCase):
    def test_different_field_bits_not_a_pulse(self):
        memory, _, _, accs, _ = _analyze(
            [0x20, 0x00, 0x90, 0x60], "bit 0x50.0-1 FIELD\n",
            extra={0x9000: [0x0f, 0x50, 0x3f, 0x50, 0x60]})  # seb 0 ; clb 1
        s = effects.leaf_summaries(memory, accs)[0x9000]
        self.assertIsNone(effects.suggested_name(s))

    def test_same_bit_is_a_pulse(self):
        memory, _, _, accs, _ = _analyze(
            [0x20, 0x00, 0x90, 0x60], "bit 0x50.0-1 FIELD\n",
            extra={0x9000: [0x0f, 0x50, 0x1f, 0x50, 0x60]})  # seb 0 ; clb 0
        s = effects.leaf_summaries(memory, accs)[0x9000]
        self.assertEqual(effects.suggested_name(s), "field_pulse")


if __name__ == "__main__":
    unittest.main()


class MaskedOutReadTests(unittest.TestCase):
    TEXT = "bit 0x50.4-7 HI\n"

    def test_mask_excluding_every_signal_reads_none(self):
        # lda $50 ; and #0x0f ; rts
        _, _, _, accs, _ = _analyze([0xa5, 0x50, 0x29, 0x0f, 0x60], self.TEXT)
        self.assertEqual(_facts(accs), [])

    def test_mask_including_a_signal_reads_it_at_the_mask(self):
        # lda $50 ; and #0xf0 ; rts
        _, _, _, accs, _ = _analyze([0xa5, 0x50, 0x29, 0xf0, 0x60], self.TEXT)
        self.assertEqual(_facts(accs), [(0x8002, "HI", "read", None)])


class LintOperationTests(unittest.TestCase):
    def _rules(self, code, text):
        memory, _, smap, accs, _ = _analyze(code, text)
        return command.signal_lint(memory, smap, accs, "M50734")

    def test_write_to_read_only_bit_is_undeclared(self):
        # seb 0,P0 ; rts
        findings = self._rules([0x0f, P0, 0x60],
                               "bit 0xf6.0 SENSE access=read\n")
        self.assertIn("undeclared", {r for r, _ in findings})

    def test_write_to_write_only_bit_is_declared(self):
        findings = self._rules([0x0f, P0, 0x60],
                               "bit 0xf6.0 DRIVE access=write\n")
        self.assertNotIn("undeclared", {r for r, _ in findings})

    def test_test_of_write_only_bit_is_undeclared(self):
        # bbs 0,P0,+0 ; rts
        findings = self._rules([0x07, P0, 0x00, 0x60],
                               "bit 0xf6.0 DRIVE access=write\n")
        self.assertIn("undeclared", {r for r, _ in findings})


class TransferModeIndexTests(unittest.TestCase):
    TEXT = "bit 0x50.0-7 V\nbit 0x51.0-7 W\n"

    def test_every_t_mode_op_writes_m_of_x(self):
        # ldx #$50 ; set ; lda #0 ; ora #8 ; clt ; rts
        _, _, _, accs, _ = _analyze(
            [0xa2, 0x50, 0x32, 0xa9, 0x00, 0x09, 0x08, 0x12, 0x60], self.TEXT)
        facts = _facts(accs)
        self.assertIn((0x8003, "V", "write", None), facts)
        self.assertIn((0x8005, "V", "write", None), facts)

    def test_ldx_immediate_in_t_mode_sets_x(self):
        # ldx #$50 ; set ; ldx #$51 ; lda #0 ; clt ; rts
        _, _, _, accs, _ = _analyze(
            [0xa2, 0x50, 0x32, 0xa2, 0x51, 0xa9, 0x00, 0x12, 0x60],
            self.TEXT)
        self.assertEqual(_facts(accs), [(0x8005, "W", "write", None)])

    def test_inx_in_t_mode_forgets_x(self):
        # ldx #$50 ; set ; inx ; lda #0 ; clt ; rts
        _, _, _, accs, _ = _analyze(
            [0xa2, 0x50, 0x32, 0xe8, 0xa9, 0x00, 0x12, 0x60], self.TEXT)
        self.assertEqual(_facts(accs), [])


class PointerDuplicateSpaceTests(unittest.TestCase):
    def test_space_given_twice_is_an_error(self):
        for text in ("pointer 0xae 0x4000 space=dme space=other\n",
                     "pointer 0xae 0x4000 space=dme space=dme\n"):
            with self.assertRaises(control.ControlError) as cm:
                control.parse("device M50734\n" + text)
            self.assertIn("space", str(cm.exception))


class ReadModifyWriteReadTests(unittest.TestCase):
    SPLIT = ("bit 0x50.0 STATUS access=read\n"
             "bit 0x50.0 CMD access=write\n")

    def test_seb_reads_the_read_side(self):
        # seb 0,$50 ; rts
        _, _, _, accs, _ = _analyze([0x0f, 0x50, 0x60], self.SPLIT)
        facts = _facts(accs)
        self.assertIn((0x8000, "CMD", "set", 1), facts)
        self.assertIn((0x8000, "STATUS", "read", None), facts)

    def test_inc_reads_the_read_side(self):
        # inc $50 ; rts
        _, _, _, accs, _ = _analyze([0xe6, 0x50, 0x60], self.SPLIT)
        facts = _facts(accs)
        self.assertIn((0x8000, "CMD", "write", None), facts)
        self.assertIn((0x8000, "STATUS", "read", None), facts)

    def test_two_way_signal_gets_no_extra_read(self):
        _, _, _, accs, _ = _analyze([0x0f, 0x50, 0x60], "bit 0x50.0 F\n")
        self.assertEqual(_facts(accs), [(0x8000, "F", "set", 1)])


class LatchReadModifyWriteTests(unittest.TestCase):
    # a read-only signal on P1's pins; P1IN is P1's input latch
    TEXT = "bit 0xf3.0 SENSE access=read\n"

    def test_seb_on_latch_reads_the_port_pins(self):
        # seb 0,P1IN ; rts
        _, _, _, accs, _ = _analyze([0x0f, P1IN, 0x60], self.TEXT)
        self.assertIn((0x8000, "SENSE", "read", None), _facts(accs))

    def test_inc_on_latch_reads_the_port_pins(self):
        # inc P1IN ; rts
        _, _, _, accs, _ = _analyze([0xe6, P1IN, 0x60], self.TEXT)
        self.assertIn((0x8000, "SENSE", "read", None), _facts(accs))


class SplitRegisterLeafTests(unittest.TestCase):
    def test_leaf_with_read_modify_write_keeps_its_effect(self):
        # jsr $8004 ; rts ; $8004: seb 0,$50 ; rts
        memory, _, _, accs, _ = _analyze(
            [0x20, 0x04, 0x80, 0x60, 0x0f, 0x50, 0x60],
            "bit 0x50.0 STATUS access=read\nbit 0x50.0 CMD access=write\n")
        summaries = effects.leaf_summaries(memory, accs)
        self.assertIn(0x8004, summaries)
        self.assertEqual([(a.signal.name, a.kind) for a in summaries[0x8004]],
                         [("CMD", "set")])
        notes = effects.call_site_annotations(memory, summaries)
        self.assertEqual(notes[0x8000], "-> CMD = 1")


class IncludeLinkCycleTests(unittest.TestCase):
    def test_include_through_a_linked_directory_is_a_cycle(self):
        d = tempfile.mkdtemp()
        try:
            try:
                os.symlink(d, os.path.join(d, "loop"),
                           target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("cannot create symbolic links here")
            path = os.path.join(d, "fw.m740")
            with open(path, "w") as f:
                f.write("device M50734\ninclude loop/fw.m740\n")
            with self.assertRaises(control.ControlError) as cm:
                control.load(path)
            self.assertIn("include cycle", str(cm.exception))
        finally:
            shutil.rmtree(d, True)


class LongBranchChainTests(unittest.TestCase):
    def test_index_reaches_the_end_of_a_long_chain(self):
        # ldy #0 ; bra +0 (x10) ; sta [$ae],y ; rts
        code = [0xa0, 0x00] + [0x80, 0x00] * 10 + [0x91, 0xae, 0x60]
        _, _, _, accs, _ = _analyze(
            code, "pointer 0xae 0x4000\nbit 0x4000.0-7 R\n")
        self.assertIn((0x8016, "R", "write", None), _facts(accs))


class RegisterPreservingOpsTests(unittest.TestCase):
    TEXT = "bit 0x50.0-7 V\n"

    def _store_at_x(self, op):
        # ldx #$50 ; <op> ; lda #1 ; sta $00,x ; rts
        _, _, _, accs, _ = _analyze(
            [0xa2, 0x50, op, 0xa9, 0x01, 0x95, 0x00, 0x60], self.TEXT)
        return _facts(accs)

    def test_txs_keeps_x(self):
        self.assertIn((0x8005, "V", "write", 1), self._store_at_x(0x9a))

    def test_pla_keeps_x(self):
        self.assertIn((0x8005, "V", "write", 1), self._store_at_x(0x68))

    def test_tsx_forgets_x(self):
        self.assertEqual(self._store_at_x(0xba), [])

    def test_and_from_memory_keeps_y(self):
        # ldy #2 ; lda $10 ; and $11 ; sta [$ae],y ; rts
        _, _, _, accs, _ = _analyze(
            [0xa0, 0x02, 0xa5, 0x10, 0x25, 0x11, 0x91, 0xae, 0x60],
            "pointer 0xae 0x4000\nbit 0x4002.0-7 R2\n")
        self.assertIn((0x8006, "R2", "write", None), _facts(accs))


class TransferModeReadTests(unittest.TestCase):
    TEXT = "pin P3.7 BTN in\n"

    def test_compare_in_t_mode_reads_m_of_x(self):
        # ldx #P3 ; set ; cmp #$80 ; clt ; rts
        _, _, _, accs, _ = _analyze(
            [0xa2, 0xee, 0x32, 0xc9, 0x80, 0x12, 0x60], self.TEXT)
        self.assertIn((0x8003, "BTN", "read", None), _facts(accs))

    def test_unknown_t_reads_nothing_at_m_of_x(self):
        # ldx #P3 ; plp ; cmp #$80 ; rts
        _, _, _, accs, _ = _analyze(
            [0xa2, 0xee, 0x28, 0xc9, 0x80, 0x60], self.TEXT)
        self.assertEqual(_facts(accs), [])


class LabelRangeTests(unittest.TestCase):
    def _build(self, text):
        cf = control.parse("device M50734\n" + text)
        return command.build_signal_map(cf, "M50734")

    def test_oversized_signal_label_is_an_error(self):
        with self.assertRaises(control.ControlError) as cm:
            self._build("label 0x12345 BIG\nbit BIG.0 S\n")
        self.assertIn("out of range", str(cm.exception))

    def test_negative_signal_label_is_an_error(self):
        with self.assertRaises(control.ControlError):
            self._build("label -2 NEG\nbit NEG.0 S\n")

    def test_negative_pointer_label_is_an_error(self):
        with self.assertRaises(control.ControlError):
            self._build("label -2 NEG\npointer NEG 0x4000\nbit 0x4000.0 S\n")

    def test_in_range_label_resolves(self):
        smap = self._build("label 0x50 FLAGS\nbit FLAGS.0 S\n")
        self.assertEqual(smap.signals[0].address, 0x50)


class PinDirectionTwiceTests(unittest.TestCase):
    def test_conflicting_directions_are_an_error(self):
        with self.assertRaises(control.ControlError) as cm:
            control.parse("device M50734\npin P0.1 BUZ in out\n")
        self.assertIn("direction given twice", str(cm.exception))

    def test_quoted_direction_word_is_a_description(self):
        cf = control.parse('device M50734\npin P0.1 BUZ in "out"\n')
        self.assertEqual(cf.signals[0].description, "out")


class RomFetchFailureTests(unittest.TestCase):
    def _fake_urlopen(self, body):
        class R(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return lambda url, timeout=None: R(body)

    def _ensure(self, dest, body):
        import urllib.request
        from m740recon.tests import nx1020_roms
        old = urllib.request.urlopen
        urllib.request.urlopen = self._fake_urlopen(body)
        try:
            return nx1020_roms.ensure(dest)
        finally:
            urllib.request.urlopen = old

    def test_oversized_download_is_refused(self):
        from m740recon.tests import nx1020_roms
        d = tempfile.mkdtemp()
        try:
            err = self._ensure(d, b"\0" * (nx1020_roms.MAX_SIZE + 10))
            self.assertIn("larger than", err)
            self.assertEqual(os.listdir(d), [])
        finally:
            shutil.rmtree(d, True)

    def test_write_failure_is_reported_not_raised(self):
        import hashlib
        from unittest import mock
        from m740recon.tests import nx1020_roms
        body = b"rom"
        want = hashlib.sha256(body).hexdigest()
        d = tempfile.mkdtemp()
        try:
            with mock.patch.dict(nx1020_roms.ROMS, {"x.ic7": want},
                                 clear=True), \
                 mock.patch.object(nx1020_roms.os, "replace",
                                   side_effect=OSError("read-only")):
                err = self._ensure(d, body)
            self.assertIn("cannot write", err)
            self.assertEqual(os.listdir(d), [])
        finally:
            shutil.rmtree(d, True)


class RoutineWithReportTests(unittest.TestCase):
    def test_routine_with_report_is_an_error(self):
        rom = bytearray(0x40)
        rom[0] = 0x60
        rom[0x3e:0x40] = bytes([0xc0, 0xff])
        for opt in ("-j", "-g", "--signals"):
            code, out, err = _cli(bytes(rom), None, opt, "--routine",
                                  "0xffc0")
            self.assertEqual(code, 1, opt)
            self.assertIn("--routine cannot be combined with " + opt, err)
            self.assertEqual(out, "")


class MultiplyDivideReadTests(unittest.TestCase):
    TEXT = "bit 0x40.0-7 LO\nbit 0x41.0-7 HI\n"

    def test_mul_reads_operand(self):
        # ldx #0 ; mul $40,x ; rts
        _, _, _, accs, _ = _analyze([0xa2, 0x00, 0x62, 0x40, 0x60],
                                    self.TEXT)
        self.assertEqual(_facts(accs), [(0x8002, "LO", "read", None)])

    def test_div_reads_both_dividend_bytes(self):
        # ldx #0 ; div $40,x ; rts
        _, _, _, accs, _ = _analyze([0xa2, 0x00, 0xe2, 0x40, 0x60],
                                    self.TEXT)
        self.assertEqual(sorted(_facts(accs)),
                         [(0x8002, "HI", "read", None),
                          (0x8002, "LO", "read", None)])

    def test_div_reads_are_not_path_dependent(self):
        _, _, _, accs, _ = _analyze([0xa2, 0x00, 0xe2, 0x40, 0x60],
                                    self.TEXT)
        self.assertEqual({a.confidence for a in accs}, {"derived"})

    def test_mul_keeps_x(self):
        # ldx #$40 ; mul $00,x ; lda #1 ; sta $01,x ; rts
        _, _, _, accs, _ = _analyze(
            [0xa2, 0x40, 0x62, 0x00, 0xa9, 0x01, 0x95, 0x01, 0x60],
            self.TEXT)
        self.assertIn((0x8006, "HI", "write", 1), _facts(accs))


class BarePortBitAnnotationTests(unittest.TestCase):
    def _rom(self):
        rom = bytearray(0x40)
        # ffc0 lda P0 ; and #2 ; seb 1,P0 ; rts
        code = [0xa5, 0xf6, 0x29, 0x02, 0x2f, 0xf6, 0x60]
        rom[0:len(code)] = bytes(code)
        rom[0x3e:0x40] = bytes([0xc0, 0xff])
        return bytes(rom)

    def _line(self, out, addr):
        return [l for l in out.splitlines() if ";%04x" % addr in l][0]

    def test_listing_names_port_bits_without_control_file(self):
        _, out, _ = _cli(self._rom())
        self.assertTrue(self._line(out, 0xffc2).endswith("reads P0.1"))
        self.assertTrue(self._line(out, 0xffc4).endswith("P0.1 = 1"))

    def test_no_annotate_gives_plain_listing(self):
        _, out, _ = _cli(self._rom(), None, "--no-annotate")
        self.assertNotIn("P0.1", out)

    def test_declared_signals_replace_port_bits(self):
        _, out, _ = _cli(self._rom(), "pin P0.1 LED out\n")
        self.assertIn("reads LED", self._line(out, 0xffc2))
        self.assertNotIn("P0.1", self._line(out, 0xffc2))

    def test_compact_bits(self):
        from m740recon.discover import compact_bits as c
        self.assertEqual(c("reads P3.0, P3.1, P3.2, P3.3"), "reads P3.0-3")
        self.assertEqual(c("inputs P0.0, P0.1, P0.2, P0.6, P0.7"),
                         "inputs P0.0-2, P0.6, P0.7")
        self.assertEqual(c("reads P0.7, P1.0, P1.1, P1.2"),
                         "reads P0.7, P1.0-2")
        self.assertEqual(c("P0.7 = 1"), "P0.7 = 1")


class TransferModeUnknownWriteTests(unittest.TestCase):
    TEXT = "bit 0x50.0-7 V\n"

    def test_unknown_t_after_plp_records_no_write(self):
        # ldx #$50 ; plp ; lda #1 ; rts
        _, _, _, accs, _ = _analyze([0xa2, 0x50, 0x28, 0xa9, 0x01, 0x60],
                                    self.TEXT)
        self.assertEqual(_facts(accs, 0x8003), [])

    def test_unknown_t_at_join_records_no_write(self):
        # ldx #$50 ; lda $10 ; beq +1 ; set ; lda #1 ; rts
        _, _, _, accs, _ = _analyze(
            [0xa2, 0x50, 0xa5, 0x10, 0xf0, 0x01, 0x32, 0xa9, 0x01, 0x60],
            self.TEXT)
        self.assertEqual(_facts(accs, 0x8007), [])

    def test_known_t_records_write(self):
        # ldx #$50 ; set ; lda #1 ; clt ; rts
        _, _, _, accs, _ = _analyze(
            [0xa2, 0x50, 0x32, 0xa9, 0x01, 0x12, 0x60], self.TEXT)
        self.assertEqual([f[2] for f in _facts(accs, 0x8003)], ["write"])


class PointerLabelCaseTests(unittest.TestCase):
    def _build(self, text):
        cf = control.parse("device M50734\n" + text)
        return command.build_signal_map(cf, "M50734")

    def test_case_variant_label_resolves(self):
        smap = self._build("label 0xae ga_ptr\npointer GA_PTR 0x4000\n"
                           "bit 0x4000.0 S\n")
        self.assertIn(0xae, smap.pointers)

    def test_ambiguous_case_variant_is_an_error(self):
        with self.assertRaises(control.ControlError):
            self._build("label 0xae ga_ptr\nlabel 0xb0 GA_Ptr\n"
                        "pointer GA_PTR 0x4000\nbit 0x4000.0 S\n")


class CachedRomSizeTests(unittest.TestCase):
    def test_oversized_cached_file_is_not_hashed(self):
        from unittest import mock
        from m740recon.tests import nx1020_roms
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "x.ic7")
            with open(path, "wb") as f:
                f.write(b"\0" * (nx1020_roms.MAX_SIZE + 1))
            with mock.patch.object(nx1020_roms.hashlib, "sha256") as h:
                self.assertFalse(nx1020_roms._good(path, "0" * 64))
                h.assert_not_called()
        finally:
            shutil.rmtree(d, True)
