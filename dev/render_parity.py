"""Differential check of rendered output against scapy, a development oracle.

Renders the same packets through both libraries and compares the strings
exactly: a corpus sample dissected from bytes, and for every layer wiry knows
that scapy also has, the layer built with defaults (before and after building)
and the octets scapy builds for it dissected back. Like `parity_check.py` this
is not shipped and its output is never committed.

Run: python dev/render_parity.py [pcap] [limit] [-v]
"""

import collections
import contextlib
import io
import re
import sys

import wiry as W

try:
    import scapy.all as S
    from scapy.config import conf as sconf

    sconf.verb = 0
except ImportError:
    sys.exit("scapy not installed; this is a dev-only oracle")


def _show(pkt, built):
    if isinstance(pkt, S.Packet):
        return pkt.show2(dump=True) if built else pkt.show(dump=True)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        (pkt.show2 if built else pkt.show)()
    return buf.getvalue()


SURFACES = {
    "summary": lambda p: p.summary(),
    "repr": repr,
    "str": str,
    "show": lambda p: _show(p, False),
    "show2": lambda p: _show(p, True),
}


def render(pkt, surface):
    try:
        return SURFACES[surface](pkt)
    except Exception as exc:  # a crash is a difference worth reporting
        return f"!!{type(exc).__name__}: {exc}"


def where(a, b):
    """The first line that differs, around its first differing character."""
    la, lb = a.split("\n"), b.split("\n")
    for x, y in zip(la, lb):
        if x != y:
            i = next(k for k in range(min(len(x), len(y)) + 1)
                     if k == min(len(x), len(y)) or x[k] != y[k])
            lo = max(0, i - 30)
            return f"{x[lo:i + 40]!r} vs {y[lo:i + 40]!r}"
    if len(la) != len(lb):
        extra = la[len(lb):] or lb[len(la):]
        return f"line count {len(la)} vs {len(lb)}: {extra[0][:90]!r}"
    return "identical?"


class Tally:
    def __init__(self, label):
        self.label = label
        self.ok = collections.Counter()
        self.total = collections.Counter()
        self.why = collections.defaultdict(collections.Counter)

    def add(self, sp, wp, surfaces, tag=""):
        for s in surfaces:
            want, got = render(sp, s), render(wp, s)
            self.total[s] += 1
            if want == got:
                self.ok[s] += 1
            else:
                self.why[s][(tag + " " if tag else "") + where(want, got)] += 1

    def report(self, verbose):
        print(f"\n=== {self.label}")
        for s in self.total:
            ok, n = self.ok[s], self.total[s]
            print(f"  {s:8s} {ok}/{n} ({100.0 * ok / n:.2f}%)")
            for cat, k in self.why[s].most_common(40 if verbose else 8):
                print(f"      {k:6d}  {cat[:220]}")
        return sum(self.ok.values()), sum(self.total.values())


_LAYER = re.compile(r"<(\w+) ")


def corpus(path, limit, tally, same):
    """`same` tallies only the packets both libraries dissect into the same
    chain of layers, which separates how a layer prints from which layers
    are there."""
    raw = W.rdpcap(path)
    n = min(limit, len(raw))
    stride = max(1, len(raw) // n)
    for i in range(0, stride * n, stride):
        data = raw.raw_at(i)
        sp, wp = S.Ether(data), W.Ether(data)
        tally.add(sp, wp, ("summary", "repr", "show"))
        if _LAYER.findall(render(sp, "repr")) == _LAYER.findall(render(wp, "repr")):
            same.add(sp, wp, ("summary", "repr", "show"))


# Stacks a user types, evaluated in each library's namespace.
STACKS = [
    "Ether()/IP(dst='10.0.0.2')/ICMP()",
    "IP(src='10.0.0.1', dst='10.0.0.2')/ICMP()",
    "IP(src='10.0.0.1', dst='10.0.0.2')/ICMP(type='echo-reply')",
    "IP(src='10.0.0.1', dst='10.0.0.2')/TCP(dport=80, flags='S')",
    "IP(src='10.0.0.1', dst='10.0.0.2')/UDP(sport=1234, dport=53)",
    "IP(src='10.0.0.1', dst='10.0.0.2')/UDP()/DNS(rd=1, qd=DNSQR(qname='example.com'))",
    "Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb')/ARP(pdst='10.0.0.1')",
    "Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb')/ARP(op=2, psrc='10.0.0.1')",
    "Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb')/Dot1Q(vlan=5)/IP(src='1.1.1.1', dst='2.2.2.2')",
    "IPv6(src='::1', dst='::2')/ICMPv6EchoRequest()",
    "IPv6(src='::1', dst='::2')/TCP()",
    "IPv6(src='::1', dst='::2')/UDP()",
    "IP(src='10.0.0.1', dst='10.0.0.2', proto=99)",
    "IP(src='10.0.0.1', dst='10.0.0.2', frag=5)/Raw(b'x')",
    "Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb', type=0x1234)",
    "TCP(sport=1, dport=2, flags='SA')",
    "UDP(sport=67, dport=68)/BOOTP()/DHCP(options=[('message-type', 'discover'), 'end'])",
    "ICMP(type=3, code=1)",
    "ICMP(type=8)",
    "Raw(b'hello')",
]


def constructed(tally, verbose):
    names = []
    for name in W.known_layers():
        sc = getattr(S, name, None)
        wc = getattr(W, name, None)
        if sc is None or wc is None or not isinstance(sc, type):
            continue
        names.append((name, sc, wc))
    for name, sc, wc in names:
        try:
            sp = sc()
            data = bytes(sp)
        except Exception:
            continue
        try:
            wp = wc()
        except Exception as exc:
            tally.total["construct"] += 1
            tally.why["construct"][f"{name}: {type(exc).__name__}: {exc}"] += 1
            continue
        tally.add(sp, wp, ("summary", "repr", "show2"), "[spec " + name + "]")
        try:
            sd = sc(data)
            wd = wc(data)
        except Exception:
            continue
        tally.add(sd, wd, ("summary", "repr", "show"), "[bytes " + name + "]")
    sns = vars(S)
    wns = {k: getattr(W, k) for k in dir(W)}
    for expr in STACKS:
        try:
            sp = eval(expr, dict(sns))
        except Exception as exc:
            print("scapy cannot eval", expr, exc)
            continue
        try:
            wp = eval(expr, dict(wns))
        except Exception as exc:
            tally.total["eval"] += 1
            tally.why["eval"][f"{expr}: {type(exc).__name__}: {exc}"] += 1
            continue
        tally.add(sp, wp, ("summary", "repr", "str", "show", "show2"), "[stack]")
        data = bytes(sp)
        first = expr.split("(")[0]
        try:
            tally.add(getattr(S, first)(data), getattr(W, first)(data),
                      ("summary", "repr", "show"), "[stack bytes]")
        except Exception:
            pass


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    verbose = "-v" in sys.argv
    path = args[0] if args else "/tmp/bigFlows.pcap"
    limit = int(args[1]) if len(args) > 1 else 20000
    a = Tally(f"{path} ({limit} sampled)")
    same = Tally("  of which both dissect into the same layers")
    corpus(path, limit, a, same)
    b = Tally("constructed: every shared layer, plus typed stacks")
    constructed(b, verbose)
    same.report(verbose)
    ok = tot = 0
    for t in (a, b):
        x, y = t.report(verbose)
        ok, tot = ok + x, tot + y
    print(f"\nOVERALL {ok}/{tot} ({100.0 * ok / tot:.2f}%)")


if __name__ == "__main__":
    main()
