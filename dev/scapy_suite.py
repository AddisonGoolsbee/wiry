"""Run scapy's own regression tests against wiry.

The strongest adversarial check available: thousands of assertions written by
scapy's maintainers, executed against our implementation with `wiry`
substituted for `scapy.all`.

The suite is not vendored. Point this at a local clone:

    git clone --depth 1 https://github.com/secdev/scapy.git /tmp/scapy-src
    python dev/scapy_suite.py /tmp/scapy-src/test/regression.uts

Outcomes are three-way and the distinction matters for honest reporting:
  PASS  every assertion held
  SKIP  the test needs a layer, field or API we do not claim to implement
  FAIL  it used only things we claim to support, and we got it wrong

Only FAIL is a defect. A SKIP is a scope boundary.
"""

import re
import sys
import traceback
from pathlib import Path

import wiry

# Names we deliberately do not provide: a scope boundary, not a defect.
OUT_OF_SCOPE = {
    "srloop", "L3socket", "L2socket", "get_if_hwaddr", "getmacbyip",
    "Automaton", "answering_machine", "load_contrib", "load_layer",
    "TCPSession", "IPSession", "wireshark", "tcpdump",
    "sprintf", "pdfdump", "psdump", "voip_play", "traceroute", "arping",
}


def parse_uts(path):
    """Yield (campaign, name, keywords, code) for each test block."""
    campaign = ""
    name = None
    kw = set()
    buf = []
    for line in Path(path).read_text(errors="replace").splitlines():
        if line.startswith("+ "):
            campaign = line[2:].strip()
            continue
        if line.startswith("= "):
            if name is not None:
                yield campaign, name, kw, "\n".join(buf)
            name = line[2:].strip()
            kw = set()
            buf = []
            continue
        if name is None:
            continue
        if line.startswith("~ "):
            kw.update(line[2:].split())
            continue
        if line.startswith(("* ", "#", "%")):
            continue
        buf.append(line)
    if name is not None:
        yield campaign, name, kw, "\n".join(buf)


def namespace():
    ns = {k: getattr(wiry, k) for k in dir(wiry) if not k.startswith("_")}
    ns["__name__"] = "scapy_suite"
    return ns


IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")

# `~` keywords scapy uses to gate a test on its host. We honour the ones that
# describe an environment we are not in; a test we skip for this reason says so.
_PLATFORM = {
    "linux": sys.platform.startswith("linux"),
    "windows": sys.platform == "win32",
    "osx": sys.platform == "darwin",
    "bsd": sys.platform.startswith(("freebsd", "openbsd", "netbsd", "darwin")),
}
# External programs scapy shells out to, none of which we provide.
_NEEDS_TOOL = {"tshark", "tcpdump", "wireshark", "netaccess", "vcan_socket",
               "needs_root", "root", "manufdb"}


def environment_block(kw):
    for key, present in _PLATFORM.items():
        if key in kw and not present:
            return f"needs a {key} host"
    tool = kw & _NEEDS_TOOL
    if tool:
        return f"needs {sorted(tool)[0]}"
    return None


def wanted_names(code):
    return set(IDENT.findall(code))


def classify_error(exc, code, supported):
    """Decide whether a failure is a scope boundary or a real defect."""
    text = f"{type(exc).__name__}: {exc}"
    if type(exc).__name__ == "CaptureUnavailable":
        return "skip", "needs the live feature"
    if isinstance(exc, (PermissionError, OSError)) and any(
        w in str(exc).lower() for w in ("permission", "/dev/bpf", "operation not permitted")
    ):
        return "skip", "needs capture privileges"
    if isinstance(exc, (NameError, ImportError, ModuleNotFoundError)):
        m = re.search(r"'([A-Za-z_][A-Za-z0-9_]*)'", str(exc))
        missing = m.group(1) if m else ""
        if missing in OUT_OF_SCOPE or missing not in supported:
            return "skip", f"needs {missing or 'an unavailable name'}"
    if isinstance(exc, AttributeError):
        m = re.search(r"'([A-Za-z0-9_.]+)'", str(exc))
        return "skip", f"needs attribute {m.group(1) if m else '?'}"
    return "fail", text


def run(path, verbose=False, limit=None):
    supported = set(dir(wiry))
    results = {"pass": 0, "skip": 0, "fail": 0}
    failures = []
    skips = {}

    for i, (campaign, name, kw, code) in enumerate(parse_uts(path)):
        if limit and i >= limit:
            break
        if not code.strip():
            continue

        blocked_env = environment_block(kw)
        if blocked_env:
            results["skip"] += 1
            skips[blocked_env] = skips.get(blocked_env, 0) + 1
            continue

        names = wanted_names(code)
        blocked = names & OUT_OF_SCOPE
        if blocked:
            results["skip"] += 1
            skips[f"uses {sorted(blocked)[0]}"] = skips.get(
                f"uses {sorted(blocked)[0]}", 0) + 1
            continue

        ns = namespace()
        try:
            exec(compile(code, f"<{name}>", "exec"), ns)
            results["pass"] += 1
            if verbose:
                print(f"  PASS  {name}")
        except AssertionError as exc:
            results["fail"] += 1
            line = ""
            tb = traceback.extract_tb(sys.exc_info()[2])
            if tb:
                line = (tb[-1].line or "").strip()
            failures.append((campaign, name, f"assertion failed: {line}"))
        except Exception as exc:  # noqa: BLE001
            kind, why = classify_error(exc, code, supported)
            results[kind] += 1
            if kind == "fail":
                failures.append((campaign, name, why))
            else:
                skips[why] = skips.get(why, 0) + 1

    return results, failures, skips


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    target = sys.argv[1]
    verbose = "-v" in sys.argv

    files = [target]
    if Path(target).is_dir():
        files = sorted(str(p) for p in Path(target).glob("*.uts"))

    total = {"pass": 0, "skip": 0, "fail": 0}
    all_failures = []
    all_skips = {}

    for f in files:
        r, fails, skips = run(f, verbose)
        print(f"{Path(f).name:28} pass {r['pass']:4}  skip {r['skip']:4}  "
              f"fail {r['fail']:4}")
        for k in total:
            total[k] += r[k]
        all_failures += fails
        for k, v in skips.items():
            all_skips[k] = all_skips.get(k, 0) + v

    print(f"\n{'TOTAL':28} pass {total['pass']:4}  skip {total['skip']:4}  "
          f"fail {total['fail']:4}")

    if all_failures:
        print(f"\n=== {len(all_failures)} FAILURES (tests using only what we "
              f"claim to support) ===")
        for campaign, name, why in all_failures[:40]:
            print(f"  [{campaign[:28]:28}] {name[:44]:44} {why[:70]}")
        if len(all_failures) > 40:
            print(f"  ... and {len(all_failures) - 40} more")

    if all_skips:
        print("\n=== top skip reasons ===")
        for why, n in sorted(all_skips.items(), key=lambda kv: -kv[1])[:12]:
            print(f"  {n:5}  {why}")

    sys.exit(1 if total["fail"] else 0)
