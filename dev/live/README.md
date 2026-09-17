# Privileged capture checks

These need root and a real interface, so they are **not** part of `pytest tests/`
and never run in the normal CI job. Same posture as `dev/` and `fuzz/`: the
shipped suite stays unprivileged and green on three platforms.

Build with the feature first:

    .venv/bin/maturin develop --release --features pyo3/extension-module,live

## Linux: network namespace (the real test)

A veth pair in a namespace, rather than the host network. Deterministic, isolated,
and free of the background traffic that makes interface tests flaky.

    sudo dev/live/netns.sh setup
    sudo dev/live/netns.sh run
    sudo dev/live/netns.sh teardown

`run` sends a crafted frame on one end and captures it on the other, asserting
byte-identical receipt, then exercises `sr1`, `AsyncSniffer` start/stop, and a BPF
filter that must exclude the test's own frames.

## macOS: loopback

macOS `lo0` is **DLT_NULL**, not Ethernet, which is exactly the case that
`ProtoId::Null` exists for. Needs `/dev/bpf*` readable, which ChmodBPF (shipped with
Wireshark) arranges:

    sudo dev/live/loopback_check.py

## What is not covered anywhere automated

Windows capture. The Npcap SDK ships no redistributable DLL and its licence forbids
bundling, so CI can neither install nor ship it. Check manually per release.
