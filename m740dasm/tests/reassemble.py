"""Reassembly-fidelity helper.

The defining guarantee of m740dasm is that its listing reassembles to a
bit-for-bit copy of the input.  as740 is the ultimate proof of that, but it is
an external tool that is not always present.  This module provides a pure-Python
proxy: it reconstructs the raw image from the classified Memory exactly the way
the listing's bytes would, and checks that the classification tiles the whole
address space with no gaps or overlaps and that every emitted unit's bytes match
the original image.

This catches the failure modes a disassembler can introduce on its own:
mis-sized instructions, off-by-one data regions, table widths that don't divide
their range, and addresses left uncovered.  Instruction *operand* encoding is
covered separately by the per-opcode tests in test_disasm.py.
"""

from m740dasm.memory import LocationTypes


def reconstruct(memory):
    """Rebuild the raw image from the classified Memory.

    Returns a bytearray of len(memory).  Raises AssertionError if the
    classification does not tile the address space exactly or if any decoded
    instruction's bytes disagree with the original image.
    """
    n = len(memory)
    out = bytearray(n)
    covered = bytearray(n)
    a = 0
    while a < n:
        t = memory.types[a]

        if t == LocationTypes.InstructionStart:
            inst = memory.get_instruction(a)
            length = len(inst)
            raw = bytes(memory[a:a + length])
            assert bytes(inst.all_bytes) == raw, (
                "instruction at 0x%04x re-encodes to %s but image has %s"
                % (a, bytes(inst.all_bytes).hex(), raw.hex()))
            for i in range(length):
                expect = (LocationTypes.InstructionStart if i == 0
                          else LocationTypes.InstructionContinuation)
                assert memory.types[a + i] == expect, (
                    "instruction at 0x%04x has bad continuation at 0x%04x"
                    % (a, a + i))
                out[a + i] = raw[i]
                covered[a + i] = 1
            a += length

        elif t in (LocationTypes.VectorStart, LocationTypes.WordStart):
            cont = (LocationTypes.VectorContinuation if t == LocationTypes.VectorStart
                    else LocationTypes.WordContinuation)
            assert memory.types[a + 1] == cont, (
                "2-byte unit at 0x%04x missing continuation" % a)
            out[a] = memory[a]
            out[a + 1] = memory[a + 1]
            covered[a] = covered[a + 1] = 1
            a += 2

        elif t == LocationTypes.TextStart:
            end = a + 1
            while end < n and memory.types[end] == LocationTypes.TextContinuation:
                end += 1
            for i in range(a, end):
                out[i] = memory[i]
                covered[i] = 1
            a = end

        elif t in (LocationTypes.Data, LocationTypes.Unknown):
            out[a] = memory[a]
            covered[a] = 1
            a += 1

        else:
            raise AssertionError(
                "landed on continuation/unknown-start type %r at 0x%04x "
                "(gap or overlap)" % (t, a))

    return out, covered


def assert_roundtrip(memory, original):
    """Assert the classified Memory reconstructs the original image exactly."""
    out, covered = reconstruct(memory)
    for a in range(len(covered)):
        assert covered[a] == 1, "address 0x%04x not covered by any unit" % a
    assert bytes(out) == bytes(original), "reconstructed image differs from input"
