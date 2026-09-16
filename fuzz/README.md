# Fuzzing

The dissector parses untrusted network data, so "never panics, never hangs" is a
property we test rather than assert.

Two layers of coverage:

- `crates/blitzpkt-core/tests/robustness.rs` runs on stable as part of
  `cargo test --workspace`. Deterministic, seeded, and fast.
- The targets here run under libFuzzer and need nightly.

## Running

```sh
cargo install cargo-fuzz
rustup toolchain install nightly

cargo +nightly fuzz list
cargo +nightly fuzz run dns_records -- -max_total_time=60
```

`dns_records` is the highest-value target: DNS name compression follows
attacker-controlled offsets, so an unbounded walk there is a denial of service.

## Reproducing a crash

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<artifact>
```

Then add the input to `crates/blitzpkt-core/tests/robustness.rs` so the case is
covered on stable.
