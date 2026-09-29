#!/usr/bin/env bash
# Docker-free alternative: two strongSwan instances in Linux network namespaces on one machine.
# Needs: root, strongSwan (swanctl/charon) installed on the host, iproute2, tcpdump.
#   sudo ./netns_lab.sh up <scenario>     # builds ns moon/sun with a veth WAN, starts charon in both, brings the tunnel up
#   sudo ./netns_lab.sh capture out.pcap  # tcpdump on the WAN veth (Ctrl-C to stop)
#   sudo ./netns_lab.sh down
set -euo pipefail
cd "$(dirname "$0")"
CMD=${1:-}; ARG=${2:-good_gcm_pfs}
case "$CMD" in
  up)
    ip netns add moon; ip netns add sun
    ip link add wan-moon type veth peer name wan-sun
    ip link set wan-moon netns moon; ip link set wan-sun netns sun
    ip -n moon addr add 192.168.0.1/24 dev wan-moon; ip -n sun addr add 192.168.0.2/24 dev wan-sun
    ip -n moon link set lo up; ip -n sun link set lo up; ip -n moon link set wan-moon up; ip -n sun link set wan-sun up
    # dummy LANs so tunnel-mode traffic selectors have real addresses
    ip -n moon link add lan0 type dummy; ip -n moon addr add 10.1.0.1/16 dev lan0; ip -n moon link set lan0 up
    ip -n sun  link add lan0 type dummy; ip -n sun  addr add 10.2.0.1/16 dev lan0; ip -n sun  link set lan0 up
    for gw in moon sun; do
      mkdir -p /tmp/xray-$gw/swanctl/conf.d /tmp/xray-$gw/swanctl/x509 /tmp/xray-$gw/swanctl/x509ca /tmp/xray-$gw/swanctl/private
      cp scenarios/$ARG/$gw.conf /tmp/xray-$gw/swanctl/conf.d/
      cp pki/caCert.pem /tmp/xray-$gw/swanctl/x509ca/ 2>/dev/null || true
      cp pki/$gw/${gw}Cert.pem /tmp/xray-$gw/swanctl/x509/ 2>/dev/null || true
      cp pki/$gw-key/${gw}Key.pem /tmp/xray-$gw/swanctl/private/ 2>/dev/null || true
      cp strongswan.conf /tmp/xray-$gw/
      ip netns exec $gw env STRONGSWAN_CONF=/tmp/xray-$gw/strongswan.conf SWANCTL_DIR=/tmp/xray-$gw/swanctl \
        sh -c "charon > /tmp/xray-$gw/charon.log 2>&1 &"
    done
    sleep 2
    for gw in moon sun; do ip netns exec $gw env SWANCTL_DIR=/tmp/xray-$gw/swanctl swanctl --load-all; done
    ip netns exec moon env SWANCTL_DIR=/tmp/xray-moon/swanctl swanctl --initiate --child "$ARG-child"
    ip netns exec moon env SWANCTL_DIR=/tmp/xray-moon/swanctl swanctl --list-sas
    echo "tunnel up. generate traffic e.g.: ip netns exec moon ping -I 10.1.0.1 10.2.0.1" ;;
  capture)
    ip netns exec sun tcpdump -i wan-sun -s 0 -w "${ARG:-lab.pcap}" 'udp port 500 or udp port 4500 or esp or ah' ;;
  down)
    pkill -f "/tmp/xray-moon" || true; pkill -f "/tmp/xray-sun" || true
    ip netns del moon 2>/dev/null || true; ip netns del sun 2>/dev/null || true; rm -rf /tmp/xray-moon /tmp/xray-sun ;;
  *) echo "usage: $0 up <scenario> | capture <file.pcap> | down"; exit 1 ;;
esac
