#!/usr/bin/env bash
# veth pair in a namespace, so capture tests see only their own traffic.
set -euo pipefail

NS=wiry-test
VETH=pkt0
PEER=pkt1

case "${1:-}" in
setup)
  ip netns add "$NS"
  ip link add "$VETH" type veth peer name "$PEER"
  ip link set "$PEER" netns "$NS"
  ip addr add 10.99.0.1/24 dev "$VETH"
  ip link set "$VETH" up
  ip netns exec "$NS" ip addr add 10.99.0.2/24 dev "$PEER"
  ip netns exec "$NS" ip link set "$PEER" up
  ip netns exec "$NS" ip link set lo up
  echo "ready: $VETH on the host, $PEER inside $NS"
  ;;
run)
  exec "$(dirname "$0")/../../.venv/bin/python" "$(dirname "$0")/netns_check.py" "$VETH" "$NS" "$PEER"
  ;;
teardown)
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$VETH" 2>/dev/null || true
  echo "cleaned up"
  ;;
*)
  echo "usage: $0 {setup|run|teardown}" >&2
  exit 2
  ;;
esac
