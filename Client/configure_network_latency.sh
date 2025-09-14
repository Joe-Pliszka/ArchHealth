OUT_IF="eth0"
SERVER_IP="10.0.0.100"
LATENCY="300ms"
LATENCY_STDDEV="100ms"

# Egress (to server)
sudo tc qdisc replace dev "${OUT_IF}" root handle 1: prio
sudo tc qdisc replace dev "${OUT_IF}" parent 1:3 handle 30: netem delay "${LATENCY}" "${LATENCY_STDDEV}"
sudo tc filter replace dev "${OUT_IF}" protocol ip parent 1:0 prio 3 u32 match ip dst "${SERVER_IP}/32" flowid 1:3

# Ingress (from server) via IFB
sudo modprobe ifb numifbs=1 || true
sudo ip link set ifb0 up || true
sudo tc qdisc replace dev "${OUT_IF}" ingress
sudo tc filter replace dev "${OUT_IF}" parent ffff: protocol ip prio 3 u32 \
  match ip src "${SERVER_IP}/32" action mirred egress redirect dev ifb0
sudo tc qdisc replace dev ifb0 root handle 40: netem delay "${LATENCY}" "${LATENCY_STDDEV}"
