# Testing

```
$ ./venv/bin/pytest
```

Every input is a synthetic fixture, the repository's own `testprog.asm`, or the NX-1020 example.  The NX-1020 ROM images are downloaded on first run from [star-nx1020-re](https://github.com/keithgh1/star-nx1020-re) at a pinned commit and checked by SHA-256; without network access those tests skip.  CI sets `M740RECON_REQUIRE_NX1020=1`, which turns that skip into a failure.

`tests/test_realworld_nx1020.py` checks the tool against a real firmware, the Star NX-1020 printer in [`examples/nx1020/`](../examples/nx1020/), whose pin map and behavior have been verified independently.  Most of its checks assert documented facts about the firmware.  The rest compare output against goldens in `m740recon/tests/golden/nx1020/`: with signal features off, the output must still match what m740recon produced before signal support existed; with them on, it must match the pinned current output.  After an intended change, regenerate the current goldens with `python -m m740recon.tests.update_nx1020_golden` and review the diff.

The end-to-end reassembly tests use the real [as740](http://shop-pdp.net/ashtml/as740.htm) + aslink to prove the listing assembles bit-for-bit back to the input, including densely annotated listings.  When that toolchain is not found on `PATH` (or as `<tool>.exe` in `~/bin`) those tests skip and the rest of the suite still passes; the pure-Python structural round-trip (`test_roundtrip`) still checks re-encoding.  Set `M740_REQUIRE_AS740=1` to turn a missing toolchain into a hard failure instead, which CI should do so the reassembly guarantee is always checked.  To run the full check locally, build `as740` and `aslink` from the ASxxxx source and put them on `PATH`.
