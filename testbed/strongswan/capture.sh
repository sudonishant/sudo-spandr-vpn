#!/usr/bin/env bash
# Record a labelled PCAP for one scenario and one traffic type through the running testbed.
#   ./capture.sh <scenario> <traffic> [seconds]
#   traffic: voip | video | web | email | chat | icmp | file | ssh | mixed
# Output: pcaps/<scenario>__<traffic>.pcap  +  pcaps/<scenario>__<traffic>.json (ground-truth label)
set -euo pipefail
cd "$(dirname "$0")"
SCEN=${1:?scenario}; TRAFFIC=${2:?traffic}; SECS=${3:-60}
OUT="pcaps/${SCEN}__${TRAFFIC}"
mkdir -p pcaps
echo "[*] waiting for the tunnel to come up"
for i in $(seq 1 30); do
  docker exec xray-moon swanctl --list-sas 2>/dev/null | grep -q ESTABLISHED && break
  docker exec xray-moon swanctl --initiate --child "${SCEN}-child" >/dev/null 2>&1 || true
  sleep 1
done
docker exec xray-moon swanctl --list-sas
echo "[*] capturing ${SECS}s on the WAN segment -> ${OUT}.pcap"
docker exec -d xray-tap sh -c "tcpdump -i eth0 -s 0 -w /pcaps/$(basename "$OUT").pcap 'udp port 500 or udp port 4500 or esp or ah or icmp'"
sleep 1
# force a fresh IKE + Child SA inside the capture window so IKE_SA_INIT and rekeys are recorded
docker exec xray-moon swanctl --terminate --ike "${SCEN}" >/dev/null 2>&1 || true
sleep 1
docker exec xray-moon swanctl --initiate --child "${SCEN}-child" >/dev/null
gen() {  # traffic generators executed on alice (10.1.0.10) towards bob (10.2.0.10)
  case "$1" in
    voip)  docker exec xray-alice sh -c "python3 - <<'PY'
import socket, time, os
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); t0 = time.time(); seq = 0
while time.time() - t0 < ${SECS}-5:
    s.sendto(os.urandom(172), ('10.2.0.10', 16384 + (seq % 2)*2)); seq += 1; time.sleep(0.02)   # G.711 20 ms frames
PY" ;;
    video) docker exec xray-alice sh -c "iperf3 -c 10.2.0.10 -u -b 3M -l 1200 -t $((SECS-5)) >/dev/null" ;;
    web)   docker exec xray-alice sh -c "for i in \$(seq 1 $((SECS/2))); do curl -s -o /dev/null http://10.2.0.10/; sleep 2; done" ;;
    email) docker exec xray-alice sh -c "for i in \$(seq 1 $((SECS/6))); do head -c \$((RANDOM*20)) /dev/urandom | nc -w1 10.2.0.10 25 || true; sleep 6; done" ;;
    chat)  docker exec xray-alice sh -c "python3 - <<'PY'
import socket, time, os, random
t0 = time.time()
while time.time() - t0 < ${SECS}-5:
    s = socket.socket(); s.settimeout(2)
    try: s.connect(('10.2.0.10', 80)); s.send(os.urandom(random.randint(40, 300)))
    except Exception: pass
    s.close(); time.sleep(random.uniform(1, 6))
PY" ;;
    icmp)  docker exec xray-alice sh -c "ping -c $((SECS-5)) -i 1 10.2.0.10 >/dev/null" ;;
    file)  docker exec xray-alice sh -c "iperf3 -c 10.2.0.10 -t $((SECS-5)) >/dev/null" ;;
    ssh)   docker exec xray-alice sh -c "python3 - <<'PY'
import socket, time, random
s = socket.socket(); s.connect(('10.2.0.10', 80)); t0 = time.time()
while time.time() - t0 < ${SECS}-5:
    s.send(b'x' * random.choice([36, 36, 36, 52, 68, 100])); time.sleep(random.uniform(0.05, 0.4))
PY" ;;
    mixed) gen icmp & gen web & gen voip; wait ;;
    *) echo "unknown traffic $1"; exit 1 ;;
  esac
}
gen "$TRAFFIC" || true
sleep 3
docker exec xray-tap pkill -INT tcpdump; sleep 1
# ground-truth label from the running configuration
IKE=$(docker exec xray-moon swanctl --list-sas | grep -m1 -oE '(AES|3DES|CHACHA|NULL)[A-Z0-9_/-]*' || true)
cat > "${OUT}.json" <<JSON
{"scenario": "${SCEN}", "traffic": "${TRAFFIC}", "seconds": ${SECS}, "ike_observed": "${IKE}", "captured": "$(date -Is)",
 "config": "scenarios/${SCEN}/moon.conf"}
JSON
echo "[*] done: ${OUT}.pcap  -> analyze with: python -m ipsec_xray.cli analyze ${OUT}.pcap --profile enterprise --pdf ${OUT}.pdf"
