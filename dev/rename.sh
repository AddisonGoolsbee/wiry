#!/usr/bin/env bash
# Rename blitzpkt -> packetry across the tree. Run from anywhere; needs a clean
# working tree because it rewrites every tracked file in place.
set -euo pipefail

# git on this machine shims through Xcode, whose licence may be unaccepted.
if [ -d /Library/Developer/CommandLineTools ]; then
  export DEVELOPER_DIR=/Library/Developer/CommandLineTools
fi

cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain)" ]; then
  echo "working tree is dirty; commit or stash first" >&2
  exit 1
fi

echo "== moving directories =="
git mv crates/blitzpkt-core crates/packetry-core
git mv crates/blitzpkt-py   crates/packetry-py
git mv python/blitzpkt      python/packetry

echo "== rewriting identifiers =="
# Compound names first, so they are not half-rewritten by the bare substitution.
for f in $(git ls-files); do
  [ -f "$f" ] || continue
  case "$f" in *.pcap|*.png|*.jpg|fuzz/corpus/*) continue;; esac
  LC_ALL=C sed -i '' \
    -e 's/blitzpkt-core/packetry-core/g' \
    -e 's/blitzpkt-py/packetry-py/g' \
    -e 's/blitzpkt_core/packetry_core/g' \
    -e 's/blitzpkt_py/packetry_py/g' \
    -e 's/_blitzpkt/_packetry/g' \
    -e 's/blitzpkt/packetry/g' \
    -e 's/BLITZPKT/PACKETRY/g' \
    -e 's/Blitzpkt/Packetry/g' \
    "$f"
done

echo "== remaining references =="
git grep -in blitzpkt || echo "  none"
