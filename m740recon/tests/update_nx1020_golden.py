"""Regenerate the signal-aware NX-1020 goldens in tests/golden/nx1020/.

    python -m m740recon.tests.update_nx1020_golden

Run from a source checkout after an intended output change, then review
the diff.  presignal.json (output from before signal support) is never
touched: a change there is a regression, not an update.
"""

import json
import os
import sys

from m740recon.tests import test_realworld_nx1020 as nx


def main():
    if not os.path.exists(nx.BUNDLED):
        sys.exit("bundled example not found: %s" % nx.BUNDLED)
    if not nx.IS_BUNDLED:
        sys.exit("unset M740RECON_NX1020: goldens describe the bundled "
                 "example only")
    if not nx._have_fw:
        sys.exit(nx._skip_msg)
    os.makedirs(nx.GOLDEN, exist_ok=True)
    hashes = {}
    for name, text in sorted(nx.current_outputs().items()):
        if name in nx.HASHED:
            hashes[name] = nx.digest(text)
        else:
            with open(os.path.join(nx.GOLDEN, name), "w", newline="") as f:
                f.write(nx.normalized(text))
        print("updated %s" % name)
    with open(os.path.join(nx.GOLDEN, "current.json"), "w",
              newline="") as f:
        json.dump(hashes, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
