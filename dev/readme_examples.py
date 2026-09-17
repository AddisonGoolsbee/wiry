"""Run every Python block in README.md, standalone.

A reader copies one block, not the file. So each is executed in a fresh
namespace: a block that relies on an import from an earlier one fails here, as
it would for them. Two real defects were shipped past the test suite this way,
a missing import and a `conds=` argument that never existed.

Run: python dev/readme_examples.py
"""

import contextlib
import io
import re
import sys
import tempfile
from pathlib import Path

import wiry as W

README = Path(__file__).resolve().parent.parent / "README.md"


def main() -> int:
    blocks = re.findall(r"```python\n(.*?)```", README.read_text(), re.S)
    if not blocks:
        print("no python blocks found in README.md")
        return 1

    work = tempfile.mkdtemp()
    W.wrpcap(
        str(Path(work) / "capture.pcap"),
        [W.Ether() / W.IP() / W.TCP(dport=443), W.Ether() / W.IP() / W.UDP()],
    )

    failures = []
    for i, block in enumerate(blocks, 1):
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                exec(compile(block, f"<README block {i}>", "exec"), {})
        except Exception as exc:  # noqa: BLE001
            failures.append((i, f"{type(exc).__name__}: {exc}", block))

    for i, why, block in failures:
        print(f"  BLOCK {i}  {why}")
        print(f"         {block.strip().splitlines()[0]}")
    print(f"\n{len(blocks) - len(failures)}/{len(blocks)} README examples run")
    return 1 if failures else 0


if __name__ == "__main__":
    import os

    os.chdir(tempfile.mkdtemp())
    W.wrpcap("capture.pcap", [W.Ether() / W.IP() / W.TCP(dport=443)])
    sys.exit(main())
