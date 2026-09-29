#!/usr/bin/env bash
# Generate a throw-away CA + gateway certificates for the testbed (uses the strongSwan `pki` tool inside the image).
set -euo pipefail
cd "$(dirname "$0")"
IMG=strongx509/strongswan:6.0.0
mkdir -p pki/moon pki/moon-key pki/sun pki/sun-key
run() { docker run --rm -v "$PWD/pki:/pki" -w /pki "$IMG" "$@"; }
run pki --gen --type ecdsa --size 384 --outform pem > pki/caKey.pem
run pki --self --ca --lifetime 3650 --in /pki/caKey.pem --type ecdsa --dn "C=IN, O=IPsec X-Ray, CN=X-Ray Testbed CA" --outform pem > pki/caCert.pem
for gw in moon sun; do
  run pki --gen --type ecdsa --size 384 --outform pem > "pki/${gw}-key/${gw}Key.pem"
  run pki --pub --in "/pki/${gw}-key/${gw}Key.pem" --type ecdsa \
    | run pki --issue --lifetime 1200 --cacert /pki/caCert.pem --cakey /pki/caKey.pem \
        --dn "C=IN, O=IPsec X-Ray, CN=${gw}.xray.test" --san "${gw}.xray.test" --flag serverAuth --flag ikeIntermediate --outform pem \
    > "pki/${gw}/${gw}Cert.pem"
done
echo "PKI written to $(pwd)/pki (CA + moon + sun)"
