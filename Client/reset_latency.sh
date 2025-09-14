#!/usr/bin/env bash
set -euo pipefail

# Interface arg ./reset_latency.sh wlp3s0
OUT_IF="${1:-eth0}" 

echo "[*] Cleaning tc setup on ${OUT_IF} and ifb0 ..."

# Ingress
sudo tc qdisc del dev "${OUT_IF}" ingress 2>/dev/null || true
sudo tc filter del dev "${OUT_IF}" parent ffff: 2>/dev/null || true

# IFB device used for ingress shaping
if ip link show ifb0 &>/dev/null; then
  sudo tc qdisc del dev ifb0 root 2>/dev/null || true
  sudo ip link set ifb0 down 2>/dev/null || true
fi

# Egress
if tc qdisc show dev "${OUT_IF}" | grep -q "handle 1:"; then
  sudo tc qdisc del dev "${OUT_IF}" root 2>/dev/null || true
fi

sudo tc qdisc replace dev "${OUT_IF}" root fq_codel
echo "[*] Remaining qdiscs and filters:"
tc qdisc show dev "${OUT_IF}" || true
tc qdisc show dev ifb0 2>/dev/null || true
tc filter show dev "${OUT_IF}" parent 1:0 || true
tc filter show dev "${OUT_IF}" parent ffff: || true
echo "[*] Network latency removed"
