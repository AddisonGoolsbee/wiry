# Privileged capture checks

These need root and a real interface, so they are **not** part of `pytest tests/`
and never run in the normal CI job. Same posture as `dev/` and `fuzz/`: the
shipped suite stays unprivileged and green on three platforms.

**Run them.** Live capture needs no build flag any more — libpcap is loaded at
run time — so the only thing standing between this code and a wire is somebody
starting one of these. Two defects lived here until 2026-09-18 because nobody
had: a capture that never reached its own deadline on a silent interface, and a
layer-3 `send` that put `127.0.0.1` in the source address and was dropped before
it left the host. Both were invisible to every offline test and obvious within
one run of `netns_check.py`.

    pip install .        # or: maturin develop --release --features pyo3/extension-module

`python -c "import wiry; print(wiry.capture_backend())"` says which libpcap was
loaded before you start.

## Linux: network namespace (the real test)

A veth pair in a namespace, rather than the host network. Deterministic, isolated,
and free of the background traffic that makes interface tests flaky.

    sudo dev/live/netns.sh setup
    sudo dev/live/netns.sh run
    sudo dev/live/netns.sh teardown

`PYTHON=/path/to/python` overrides the interpreter, for a container or one that
carries `CAP_NET_RAW`.

`run` sends a crafted frame on one end and captures it on the other, asserting
byte-identical receipt, then exercises `sr1`, `AsyncSniffer` start/stop, and a BPF
filter that must exclude the test's own frames. It then runs the active tools
over the pair, where exactly one address exists to answer: `arping` must find the
peer and nobody else, `getmacbyip` must agree with it, `srloop` must collect every
round, and `traceroute` must reach a peer one hop away.

Four of its checks are about a capture that receives **nothing**, which is the
case the offline driver cannot reach and the one that was broken: a deadline, an
unreachable count, `stop()`, and Ctrl-C must each return in seconds over an
interface with no traffic on it. Each runs on a worker with its own deadline,
because a wall-clock assertion made after the call cannot catch a hang.

A privileged Linux container is enough, and is how this was last run:

    docker run --rm --privileged --cap-add=NET_ADMIN --cap-add=NET_RAW ...

## Any host with a network: the active tools

`traceroute`, `arping`, `getmacbyip` and `srloop` against real routers and real
hosts. Everything these tools are *made* of — the TTL sweep, the trace grouping
and its presentation, the CIDR expansion, the multicast mapping — is in
`tests/test_tools.py` and needs no privileges; this is only whether the wire
agrees.

    sudo .venv/bin/python dev/live/tools_check.py [target] [--net 10.0.0.0/24]

`target` defaults to 1.1.1.1 and the sweep to the /24 around the outgoing
interface's address. Unlike the namespace harness this depends on the network it
is run on: a LAN where nothing answers ARP, or a path that drops ICMP, will fail
honestly rather than silently.

## Any host: the sockets a state machine listens on

Every part of an `Automaton` that is logic — states, transitions, timers,
actions, io events, replies — is in `tests/test_automaton.py`, driven from canned
packets through `OfflineSocket` with no privileges. This is only whether
`L2Socket` and `L2ListenSocket` really carry frames, whether a machine's receive
condition fires on one, and whether its threads stop when told. It also compares
what `conf.route` answers against `route -n get` / `ip route get`.

    sudo .venv/bin/python dev/live/automaton_check.py [iface]

`iface` defaults to a loopback interface, which is enough: a frame sent on
loopback comes back.

## macOS: loopback

macOS `lo0` is **DLT_NULL**, not Ethernet, which is exactly the case that
`ProtoId::Null` exists for and the one no Linux run reaches: `lo` there is
Ethernet like everything else.

    sudo dev/live/loopback_check.py

Needs `/dev/bpf*` readable. ChmodBPF, which ships with Wireshark, arranges that;
without it the devices are mode 600 root:wheel and the check stops at
`PermissionError` naming `/dev/bpf0`.

## What is not covered anywhere automated

**Windows.** wiry loads `wpcap.dll` from the Npcap directory the way scapy does,
and that path has never been executed. The Npcap SDK ships no redistributable DLL
and its licence forbids bundling, so CI can neither install nor ship it. Check
manually per release, and treat it as unverified until someone has.
