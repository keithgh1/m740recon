"""End-to-end reassembly via the real as740 assembler + aslink linker.

This is the authoritative proof of m740dasm's defining guarantee: that its
listing assembles, bit-for-bit, back to the original image.  It shells out to
the actual ASxxxx tools (as740, aslink), parses the Intel-HEX they emit (so no
dependency on srec_cat), and returns the assembled bytes for comparison.

as740/aslink are located on PATH, with a fallback to ~/bin.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

from m740dasm.disasm import disassemble
from m740dasm.trace import Tracer
from m740dasm.memory import Memory
from m740dasm.listing import Printer
from m740dasm.symbols import SymbolTable
from m740dasm.devices import Devices


class ToolNotFound(Exception):
    pass


def find_tool(name):
    """Locate an ASxxxx tool, raising ToolNotFound if it is not installed."""
    found = shutil.which(name)
    if found:
        return found
    fallback = os.path.join(os.path.expanduser("~"), "bin", name + ".exe")
    if os.path.exists(fallback):
        return fallback
    raise ToolNotFound(
        "%s not found on PATH or in ~/bin -- the end-to-end reassembly check "
        "requires the ASxxxx tools to be installed." % name)


def tools_available():
    try:
        find_tool("as740")
        find_tool("aslink")
        return True
    except ToolNotFound:
        return False


# as740/aslink are NOT distributed with m740dasm.  The end-to-end reassembly
# checks need them, so by default those tests skip when the toolchain is
# absent and the suite still passes.  Set M740_REQUIRE_AS740=1 to turn a
# missing toolchain into a hard failure instead (for a maintainer's CI that
# must never let the reassembly tenet go unverified).
REQUIRE_AS740 = os.environ.get("M740_REQUIRE_AS740", "") not in ("", "0")


def requires_as740(test):
    """Skip a reassembly test when as740/aslink are not installed (unless
    M740_REQUIRE_AS740 is set, in which case it fails instead).  The
    pure-Python structural round-trip (reassemble.py / test_roundtrip) still
    verifies that the listing re-encodes to the original bytes without any
    external assembler."""
    reason = ("as740/aslink not installed; reassembly check skipped "
              "(set M740_REQUIRE_AS740=1 to require it)")
    return unittest.skipUnless(tools_available() or REQUIRE_AS740, reason)(test)


def parse_ihx(text):
    """Parse Intel HEX text into {address: byte}."""
    mem = {}
    base = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] != ":":
            continue
        raw = bytes.fromhex(line[1:])
        count, ah, al, rectype = raw[0], raw[1], raw[2], raw[3]
        addr = (ah << 8) | al
        data = raw[4:4 + count]
        if rectype == 0x00:        # data
            for i, v in enumerate(data):
                mem[base + addr + i] = v
        elif rectype == 0x04:      # extended linear address
            base = ((data[0] << 8) | data[1]) << 16
        elif rectype == 0x02:      # extended segment address
            base = ((data[0] << 8) | data[1]) << 4
        elif rectype == 0x01:      # EOF
            break
    return mem


def assemble(asm_text, org, size):
    """Assemble as740 source text and return `size` bytes based at `org`."""
    as740 = find_tool("as740")
    aslink = find_tool("aslink")
    workdir = tempfile.mkdtemp(prefix="m740e2e_")
    try:
        src = os.path.join(workdir, "u.asm")
        with open(src, "w", newline="\n") as f:
            f.write(asm_text)
        r = subprocess.run([as740, "-l", "-o", "u.asm"], cwd=workdir,
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("as740 failed:\n" + r.stdout + r.stderr)
        r = subprocess.run([aslink, "-i", "u"], cwd=workdir,
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("aslink failed:\n" + r.stdout + r.stderr)
        with open(os.path.join(workdir, "u.ihx")) as f:
            mem = parse_ihx(f.read())
        out = bytearray(size)
        for addr, v in mem.items():
            if org <= addr < org + size:
                out[addr - org] = v
            else:
                raise RuntimeError(
                    "assembled byte at 0x%04x outside [0x%04x, 0x%04x)"
                    % (addr, org, org + size))
        return bytes(out)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def disasm_text(rom, device="M3886", start_address=None, entry_points=(),
                extra_symbols=(), control=None, analyze=False, show_xrefs=False,
                discover_tables=False):
    """Disassemble a raw image and return the as740 listing as text.

    Uses the same build path as the CLI (command.build_disassembly).  A
    ControlFile may be supplied via `control`; otherwise entry_points and
    extra_symbols are applied directly.
    """
    import io
    import sys
    from m740dasm import command

    if start_address is None:
        start_address = 0x10000 - len(rom)
    if control is not None:
        kwargs = command.control_args(control, bytearray(rom))
        comments = command.control_comments(control)
    else:
        kwargs = dict(entry_points=entry_points, extra_symbols=extra_symbols)
        comments = {}
    memory, symtab = command.build_disassembly(rom, device, start_address,
                                               analyze=analyze,
                                               discover_tables=discover_tables,
                                               **kwargs)

    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        Printer(memory, start_address, symtab, comments=comments,
                show_xrefs=show_xrefs).print_listing()
    finally:
        sys.stdout = old
    return buf.getvalue()


def assert_reassembles(rom, device="M3886", start_address=None,
                       entry_points=(), extra_symbols=(), control=None,
                       analyze=False, discover_tables=False):
    """Disassemble `rom`, assemble the listing with as740, assert byte-identical."""
    if start_address is None:
        start_address = 0x10000 - len(rom)
    listing = disasm_text(rom, device, start_address, entry_points, extra_symbols,
                          control=control, analyze=analyze,
                          discover_tables=discover_tables)
    rebuilt = assemble(listing, start_address, len(rom))
    if rebuilt != bytes(rom):
        # find first divergence for a useful message
        for i in range(len(rom)):
            if rebuilt[i] != rom[i]:
                raise AssertionError(
                    "reassembly differs at 0x%04x: got 0x%02x want 0x%02x"
                    % (start_address + i, rebuilt[i], rom[i]))
        raise AssertionError("reassembly length differs")
    return listing
