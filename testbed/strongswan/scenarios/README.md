# Scenario matrix

Each directory holds the `swanctl.conf` fragment for both gateways. `SCENARIO=<name> docker compose up -d` mounts the pair.

| Scenario | What it demonstrates | IKE proposal | ESP/AH proposal | Mode | Auth |
|---|---|---|---|---|---|
| `good_gcm_pfs` | Best practice: IKEv2 AES-256-GCM / SHA-384 PRF / ECP-384, ESP AES-256-GCM, tunnel, PFS ecp384, certificates | `aes256gcm16-prf-hmac-sha384-ecp384` | `aes256gcm16-ecp384` | tunnel | pubkey |
| `good_pqc_hybrid` | PQC-ready: ECP-384 + ML-KEM-1024 hybrid key exchange (strongSwan >= 6.0, ml plugin), AES-256-GCM | `aes256gcm16-prf-hmac-sha384-ecp384-ke1_mlkem1024` | `aes256gcm16-ecp384-ke1_mlkem1024` | tunnel | pubkey |
| `enterprise_cbc_sha256` | Typical enterprise: AES-128-CBC + HMAC-SHA2-256, MODP-2048, PSK, tunnel, no PFS | `aes128-sha256-modp2048` | `aes128-sha256` | tunnel | psk |
| `enterprise_cbc_sha1_pfs` | AES-256-CBC + HMAC-SHA1-96 (SHOULD NOT), MODP-2048, PFS modp2048 | `aes256-sha1-modp2048` | `aes256-sha1-modp2048` | tunnel | psk |
| `transport_chacha` | Host-to-host transport mode with ChaCha20-Poly1305 and X25519 PFS | `chacha20poly1305-prf-hmac-sha256-x25519` | `chacha20poly1305-x25519` | transport | pubkey |
| `legacy_3des_sha1_modp1024` | Legacy: 3DES-CBC + SHA1, MODP-1024 (weakdh), PSK, no PFS - expect grade F | `3des-sha1-modp1024` | `3des-sha1` | tunnel | psk |
| `null_esp_integrity_only` | ESP with NULL encryption + HMAC-SHA2-256 (integrity only) - inner IP visible | `aes128-sha256-modp2048` | `null-sha256` | tunnel | psk |
| `ah_only` | AH (protocol 51) with HMAC-SHA2-256, no confidentiality | `aes128-sha256-modp2048` | `sha256` | tunnel | psk |
| `ipv6_gcm_transport` | IPv6 host-to-host transport mode, AES-128-GCM, ECP-256 PFS (needs the ipv6 compose overlay) | `aes128gcm16-prf-hmac-sha256-ecp256` | `aes128gcm16-ecp256` | transport | pubkey |
| `natt_behind_nat` | Road-warrior style: initiator behind NAT -> UDP 4500 encapsulation, AES-128-GCM, PSK+EAP-MSCHAPv2 style (PSK here) | `aes128gcm16-prf-hmac-sha256-modp2048` | `aes128gcm16-modp2048` | tunnel | psk |
