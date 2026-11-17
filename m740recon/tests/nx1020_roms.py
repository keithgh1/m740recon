"""Fetch the Star NX-1020 ROM images for examples/nx1020/.

The images are not stored in this repository.  They are downloaded from
the star-nx1020-re project at a pinned commit and checked by SHA-256.

    python -m m740recon.tests.nx1020_roms
"""

import hashlib
import os
import sys

SOURCE = ("https://raw.githubusercontent.com/keithgh1/star-nx1020-re/"
          "ac3426b8e597af996332dab4ae01af3e197f068c/")
ROMS = {
    "nx1020_rom1.ic7":
        "dd67c1fe7d825f165abff7016c8b5687c4a437cd915e157fbe1ee117b4b43d32",
    "nx1020_rom2_v3.2.ic6":
        "fea549727982d3cebedc5d790b50b245422c3c8a97db6787f8303bd0863737a5",
}
MAX_SIZE = 128 * 1024
EXAMPLE_DIR = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "examples",
    "nx1020"))


def _good(path, want):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest() == want
    except OSError:
        return False


def ensure(dest=EXAMPLE_DIR, timeout=30):
    """Make sure both ROM images are in `dest`, downloading any that are
    missing or wrong.  Returns None on success, else the reason it failed."""
    from urllib.request import urlopen
    if not os.path.isdir(dest):
        return "%s not found" % dest
    for name, want in sorted(ROMS.items()):
        path = os.path.join(dest, name)
        if _good(path, want):
            continue
        try:
            with urlopen(SOURCE + name, timeout=timeout) as r:
                data = r.read(MAX_SIZE + 1)
        except Exception as e:
            return "cannot download %s: %s" % (name, e)
        if len(data) > MAX_SIZE:
            return "%s: download is larger than %d bytes" % (name, MAX_SIZE)
        if hashlib.sha256(data).hexdigest() != want:
            return "%s: downloaded file has the wrong SHA-256" % name
        tmp = path + ".part"
        try:
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        except OSError as e:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return "cannot write %s: %s" % (path, e)
    return None


def main():
    err = ensure()
    if err:
        sys.exit("m740recon: " + err)
    print("NX-1020 ROM images ready in %s" % EXAMPLE_DIR)


if __name__ == "__main__":
    main()
