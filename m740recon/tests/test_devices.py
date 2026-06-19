"""Tests for the device hierarchy and per-core opcode gating."""

import unittest

from m740recon.devices import Devices
from m740recon.disasm import disassemble


class DeviceResolutionTests(unittest.TestCase):
    """Invariants every resolved device must satisfy."""

    def test_every_device_has_unsupported_set(self):
        for name, dev in Devices.items():
            self.assertIn("unsupported_opcodes", dev)
            self.assertEqual(dev["unsupported_opcodes"], frozenset(),
                             "%s should not gate any opcode by default" % name)


class InheritanceTests(unittest.TestCase):
    def test_7451_inherits_7450_and_overrides(self):
        s7450 = {s.address: s.name for s in Devices["7450"]["symbol_table"]}
        s7451 = {s.address: s.name for s in Devices["7451"]["symbol_table"]}
        self.assertEqual(s7450[0x00d0], s7451[0x00d0])      # inherited (P0)
        self.assertEqual(s7451[0x00d9], "AFD")              # overridden
        self.assertEqual(s7450[0x00d9], "RESERV")           # base value differs

    def test_m380x_share_base_ports(self):
        for dev in ("M3802", "M3807", "M3886"):
            ports = {s.address: s.name for s in Devices[dev]["symbol_table"]}
            self.assertEqual(ports[0x0000], "P0")           # from the _m3800 base
            self.assertEqual(ports[0x000d], "P6D")


class OpcodeGatingTests(unittest.TestCase):
    def test_gated_opcode_decodes_as_data(self):
        mem = [0xEA]                                        # nop
        self.assertEqual(str(disassemble(mem, 0)), "nop")
        gated = disassemble(mem, 0, unsupported=frozenset([0xEA]))
        self.assertEqual(str(gated), ".byte 0xea")
        self.assertTrue(gated.illegal)

    def test_gating_plumbed_through_build(self):
        from m740recon import command
        rom = bytearray(0x10000)
        rom[0x8000:0x8002] = bytes([0xEA, 0x60])            # nop ; rts
        rom[0xFFFE], rom[0xFFFF] = 0x00, 0x80
        Devices["_TESTGATE"] = {
            "vector_table": Devices["M50734"]["vector_table"],
            "symbol_table": [],
            "unsupported_opcodes": frozenset([0xEA]),
        }
        self.addCleanup(lambda: Devices.pop("_TESTGATE", None))
        memory, _ = command.build_disassembly(bytes(rom), "_TESTGATE", 0)
        inst = memory.get_instruction(0x8000)
        self.assertTrue(inst.illegal)                       # nop gated -> data


if __name__ == "__main__":
    unittest.main()
