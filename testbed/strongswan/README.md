# strongSwan testbed (real tunnels)

The sandbox that ships with this repository cannot load the kernel XFRM stack, so the built-in
`samples/` are produced by `python -m ipsec_xray.testbed.generate` (byte-exact IKE/ESP/AH framing,
synthetic traffic). This directory contains everything needed to record **real** captures on any Linux
box with Docker, covering every combination in the problem statement:

* IKEv2 (and IKEv1 via `version = 1` in the configs) · tunnel and transport mode
* AES-128/256 · CBC+HMAC and GCM · ChaCha20-Poly1305 · 3DES · NULL-ESP · AH
* DH groups MODP-1024/2048, ECP-256/384, X25519, ML-KEM hybrid (strongSwan ≥ 6.0)
* PFS on/off (child `rekey_time` is short so rekeys land inside the capture)
* IPv4 and IPv6, NAT-T (forced `encap = yes`)
* Traffic generators for VoIP, video, web, e-mail, chat, ICMP, file transfer, SSH-like

## Quick start

```bash
cd testbed/strongswan
./make_pki.sh                                   # CA + moon/sun certificates (only once)
SCENARIO=good_gcm_pfs docker compose up -d      # two gateways + two hosts + tap
./capture.sh good_gcm_pfs voip 60               # pcaps/good_gcm_pfs__voip.pcap (+ .json label)
docker compose down
python -m ipsec_xray.cli analyze pcaps/good_gcm_pfs__voip.pcap --profile enterprise --pdf report.pdf
```

Run all scenarios × traffic types to build a labelled dataset:

```bash
for s in $(ls scenarios | grep -v README); do
  SCENARIO=$s docker compose up -d && sleep 5
  for t in voip video web email chat icmp file ssh; do ./capture.sh $s $t 45; done
  docker compose down
done
python -m ipsec_xray.cli batch pcaps --out reports --pdf      # summary.csv with every score
```

`netns_lab.sh` is a Docker-free variant that runs two `charon` instances in Linux network namespaces
(requires strongSwan installed on the host).

## Retraining the classifier on real captures

Each `capture.sh` run writes `<name>.json` next to the PCAP with the scenario and traffic label.
`python -m ipsec_xray.ml.train --real testbed/strongswan/pcaps` mixes those labelled flows with the
simulated corpus (the flag is a thin wrapper: it extracts flow features from every `*.pcap` with a sidecar
`.json` and appends them to the training set).

## Layout

```
docker-compose.yml   moon/sun gateways (strongx509/strongswan:6.0.0), alice/bob hosts, tap (tcpdump)
strongswan.conf      daemon settings shared by both gateways
scenarios/<name>/    moon.conf + sun.conf (swanctl syntax) - see scenarios/README.md
make_pki.sh          throw-away ECDSA CA and gateway certificates
capture.sh           records one labelled capture through the running lab
netns_lab.sh         namespaces alternative
pcaps/               output (git-ignored)
```
