"""Hold the built engine, not scapy2spec's model of it, to scapy's answers.

Run:  python dev/protogen/engine_check.py scapy.layers.bluetooth [--trials 200]

scapy2spec's verifier decodes a spec in Python the way the engine is meant to.
This dissects and builds with the engine itself: every emitted class over random
inputs, every field compared with scapy's reading, then random assignments
built by both and compared octet for octet. Classes a link type reaches are
also written to one capture and read back through `columns()`, which must
agree with the per-packet reading and with scapy.

A dev oracle, like parity_check.py: it imports scapy, and nothing it prints is
committed as an expectation.
"""

from __future__ import annotations

import argparse
import importlib
import random
import sys
import tomllib
from pathlib import Path

SPECS = Path(__file__).resolve().parent / "specs" / "scapy"

import scapy.all  # noqa: E402,F401  (every binding scapy registers)
import wiry  # noqa: E402
from wiry import _b  # noqa: E402

# Link types whose first layer a converted module defines.
LINKS = {"HCI_Hdr": 187}


def specs_of(modname: str) -> list[dict]:
    short = modname.split(".", 2)[2].replace(".", "_")
    out = []
    for p in sorted((SPECS / short).glob("*.toml")):
        with p.open("rb") as f:
            out.append(tomllib.load(f))
    return out


def norm(v):
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str):
        return v.lower()
    try:
        return int(v)
    except (TypeError, ValueError):
        return str(v).lower()


def scapy_values(sp, names) -> dict:
    return {n: norm(sp.fields[n]) for n in names if n in sp.fields}


def wiry_values(wl, names) -> dict:
    """Through the field lookup itself: a field called `name` would otherwise
    answer with the layer's name, as `pkt.name` does in scapy."""
    out = {}
    for n in names:
        try:
            out[n] = norm(type(wl).__getattr__(wl, n))
        except AttributeError:
            pass
    return out


def random_value(fd: dict, rng: random.Random):
    kind = fd.get("kind", "uint")
    if kind == "mac":
        return ":".join(f"{rng.getrandbits(8):02x}" for _ in range(6))
    if kind == "ipv4":
        return ".".join(str(rng.getrandbits(8)) for _ in range(4))
    if kind in ("uint", "le_uint", "flags", "computed"):
        return rng.getrandbits(fd["len"])
    return None


def dissect_check(s: dict, S, W, rng, trials) -> list[str]:
    names = [fd["name"] for fd in s.get("fields", [])
             if not fd.get("kind", "uint").startswith("var_")]
    bad = []
    base = bytes(S())
    for t in range(trials):
        n = s.get("build_len", 0) + rng.choice([0, 0, 1, 4, 16])
        buf = base if t == 0 else bytes(rng.getrandbits(8) for _ in range(n))
        try:
            sp = S(buf)
        except Exception:  # noqa: BLE001
            continue
        if type(sp) is not S:
            continue
        want = scapy_values(sp, names)
        got = wiry_values(W(buf)[W], want)
        for k in want:
            if got.get(k) != want[k]:
                bad.append(f"{s['name']}.{k} from {buf.hex()}: wiry {got.get(k)!r}, "
                           f"scapy {want[k]!r}")
                return bad
    return bad


def build_check(s: dict, S, W, rng, trials) -> list[str]:
    fds = [fd for fd in s.get("fields", []) if not fd.get("cond") and not fd.get("when")]
    for _ in range(trials):
        kw = {}
        for fd in fds:
            v = random_value(fd, rng)
            if v is not None and rng.random() < 0.8:
                kw[fd["name"]] = v
        try:
            want = bytes(S(**kw))
        except Exception:  # noqa: BLE001
            continue
        try:
            got = bytes(W(**kw))
        except Exception as e:  # noqa: BLE001
            return [f"{s['name']}({kw}): wiry raised {type(e).__name__}: {e}"]
        if got != want:
            return [f"{s['name']}({kw}): wiry {got.hex()}, scapy {want.hex()}"]
    return []


def path_from(root, target, depth=4):
    """The binding chain scapy dissects from `root` to `target`, as
    (class, field values) pairs, or None."""
    todo = [[(root, {})]]
    while todo:
        chain = todo.pop(0)
        cls = chain[-1][0]
        if cls is target:
            return chain
        if len(chain) > depth:
            continue
        for fval, child in getattr(cls, "payload_guess", []):
            if child in (c for c, _ in chain):
                continue
            todo.append(chain[:-1] + [(cls, fval), (child, {})])
    return None


def bulk_check(specs: list[dict], mod, rng, per_class: int) -> list[str]:
    bad = []
    for root, dlt in LINKS.items():
        R = getattr(mod, root, None)
        if R is None:
            continue
        for s in specs:
            S = getattr(mod, s["name"], None)
            chain = path_from(R, S) if S is not None else None
            if not chain:
                continue
            names = [fd["name"] for fd in s.get("fields", [])
                     if fd.get("kind", "uint") in ("uint", "le_uint", "flags", "mac")
                     and not fd.get("cond") and not fd.get("when")]
            if not names:
                continue
            # A column gives a flags field as scapy renders it, not as a number.
            flags = {fd["name"] for fd in s["fields"] if fd.get("kind") == "flags"}
            frames, want, shown = [], [], []
            for _ in range(per_class):
                kw = {fd["name"]: random_value(fd, rng) for fd in s["fields"]
                      if fd["name"] in names}
                pkt = None
                for cls, fval in chain[:-1]:
                    layer = cls(**fval)
                    pkt = layer if pkt is None else pkt / layer
                try:
                    pkt = pkt / S(**kw)
                    raw = bytes(pkt)
                    sp = R(raw)
                except Exception:  # noqa: BLE001
                    continue
                if S not in sp:
                    continue
                frames.append((raw, 0.0, len(raw)))
                want.append(scapy_values(sp[S], names))
                shown.append({n: str(sp[S].fields[n]).lower() for n in flags
                              if n in sp[S].fields})
            if not frames:
                continue
            pl = _b.PktList.from_frames(frames, dlt)
            cols = pl.columns([(s["name"], n) for n in names])
            W = getattr(wiry, s["name"])
            for i, row in enumerate(want):
                wp = getattr(wiry, root)(frames[i][0])
                if W not in wp:
                    bad.append(f"{s['name']}: wiry does not reach it in frame "
                               f"{frames[i][0].hex()} ({' / '.join(wp.layers())})")
                    break
                per = wiry_values(wp[W], names)
                for j, n in enumerate(names):
                    if n not in row:
                        continue
                    col = norm(cols[j][i])
                    if n in flags:
                        ok = col == shown[i][n] and per.get(n) == row[n]
                    else:
                        ok = col == per.get(n) == row[n]
                    if not ok:
                        bad.append(f"{s['name']}.{n} in frame {frames[i][0].hex()}: "
                                   f"columns {col!r}, per-packet {per.get(n)!r}, "
                                   f"scapy {row[n]!r}")
                        break
                else:
                    continue
                break
    return bad


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("modules", nargs="+")
    ap.add_argument("--trials", type=int, default=200)
    a = ap.parse_args(argv)
    rng = random.Random(0x1E)
    failures = 0
    for m in a.modules:
        mod = importlib.import_module(m)
        specs = specs_of(m)
        checked = 0
        for s in specs:
            S, W = getattr(mod, s["name"], None), getattr(wiry, s["name"], None)
            if S is None or W is None:
                continue
            checked += 1
            for line in (dissect_check(s, S, W, rng, a.trials)
                         + build_check(s, S, W, rng, a.trials)):
                failures += 1
                print("  " + line)
        for line in bulk_check(specs, mod, rng, 32):
            failures += 1
            print("  " + line)
        print(f"{m}: {checked} classes checked")
    print(f"{failures} disagreement(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
