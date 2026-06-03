"""Synthetic 740 images for the test suite.

These let the tests exercise the disassembler's features (zero-page/equate
handling, dispatch-table decoding, computed-jump analysis, reassembly) without
depending on any particular ROM image.
"""


def _blank():
    return bytearray(0x10000)


def _set_reset(img, addr):
    img[0xFFFE] = addr & 0xFF
    img[0xFFFF] = (addr >> 8) & 0xFF


def zeropage_image():
    """A full 64K image (loads at 0x0000) whose code reads and writes zero
    page, so disassembling it exercises the direct-page equate path that a
    RAM-inclusive image relies on to reassemble correctly."""
    img = _blank()
    code = bytes([
        0xA5, 0x10,         # lda 0x10        (zero page)
        0x85, 0x11,         # sta 0x11        (zero page)
        0xA9, 0x05,         # lda #0x05
        0x8D, 0x00, 0x02,   # sta 0x0200      (absolute)
        0x60,               # rts
    ])
    img[0x8000:0x8000 + len(code)] = code
    _set_reset(img, 0x8000)
    return bytes(img)


def dispatch_image():
    """A 64K image with a [char, lo, hi] 0x00-terminated dispatch table whose
    handlers are reachable only through the table."""
    img = _blank()
    img[0x8000:0x8003] = bytes([0xEA, 0xEA, 0x60])      # reset: nop ; nop ; rts
    # table at 0x8100: 'A' -> 0x8200, 'B' -> 0x8210, then 0x00 terminator
    img[0x8100:0x8106] = bytes([0x41, 0x00, 0x82,
                                0x42, 0x10, 0x82])
    img[0x8106] = 0x00
    img[0x8200:0x8203] = bytes([0xA9, 0xAA, 0x60])      # handler A: lda #0xAA ; rts
    img[0x8210:0x8213] = bytes([0xA9, 0xBB, 0x60])      # handler B: lda #0xBB ; rts
    _set_reset(img, 0x8000)
    return bytes(img)


DISPATCH_CONTROL = (
    "addrtable 0x8100 stride=3 entryoff=1 terminator=0x00 label=h_\n")


def computed_jump_image():
    """A 64K image whose only path to a handler is a constant jmp [zp]."""
    img = _blank()
    img[0x8000:0x800a] = bytes([0xA9, 0x00,   # lda #0x00
                                0x85, 0x10,   # sta 0x10
                                0xA9, 0x90,   # lda #0x90
                                0x85, 0x11,   # sta 0x11
                                0xB2, 0x10])  # jmp [0x10]  -> 0x9000
    img[0x9000:0x9003] = bytes([0xA9, 0x42, 0x60])      # lda #0x42 ; rts
    _set_reset(img, 0x8000)
    return bytes(img)
