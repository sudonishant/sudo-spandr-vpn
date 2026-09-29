"""IANA registries (subset) for IKEv1 / IKEv2 / ESP plus strength metadata used by the assessment rules.

Sources: RFC 2407/2408/2409 (IKEv1), RFC 7296 (IKEv2), RFC 8221 / 8247 (algorithm requirements),
RFC 9395 (IKEv1 + legacy algorithm deprecation), RFC 9370 (additional key exchanges), draft-ietf-ipsecme-ikev2-mlkem.
"""
from __future__ import annotations

# --------------------------------------------------------------------------- IKEv2 transform types
IKEV2_TRANSFORM_TYPES = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "KE", 5: "ESN",
                         6: "ADDKE1", 7: "ADDKE2", 8: "ADDKE3", 9: "ADDKE4", 10: "ADDKE5", 11: "ADDKE6", 12: "ADDKE7"}

# name, block size (bytes) for CBC-style padding (4 = only 4-byte alignment), IV size, AEAD ICV size (None if not AEAD),
# RFC 8221/8247 status, security strength (bits, None = key-length dependent), family
IKEV2_ENCR = {
    1: ("DES_IV64", 8, 8, None, "MUST NOT", 56, "legacy"),
    2: ("DES", 8, 8, None, "MUST NOT", 56, "legacy"),
    3: ("3DES", 8, 8, None, "SHOULD NOT", 112, "legacy"),
    4: ("RC5", 8, 8, None, "MUST NOT", None, "legacy"),
    5: ("IDEA", 8, 8, None, "MUST NOT", 128, "legacy"),
    6: ("CAST", 8, 8, None, "MUST NOT", 128, "legacy"),
    7: ("BLOWFISH", 8, 8, None, "MUST NOT", None, "legacy"),
    8: ("3IDEA", 8, 8, None, "MUST NOT", None, "legacy"),
    9: ("DES_IV32", 8, 8, None, "MUST NOT", 56, "legacy"),
    11: ("NULL", 4, 0, None, "MAY (ESP only)", 0, "null"),
    12: ("AES_CBC", 16, 16, None, "MUST", None, "cbc"),
    13: ("AES_CTR", 4, 8, None, "SHOULD", None, "ctr"),
    14: ("AES_CCM_8", 4, 8, 8, "MAY", None, "aead"),
    15: ("AES_CCM_12", 4, 8, 12, "MAY", None, "aead"),
    16: ("AES_CCM_16", 4, 8, 16, "SHOULD", None, "aead"),
    18: ("AES_GCM_8", 4, 8, 8, "MAY", None, "aead"),
    19: ("AES_GCM_12", 4, 8, 12, "MAY", None, "aead"),
    20: ("AES_GCM_16", 4, 8, 16, "MUST", None, "aead"),
    21: ("NULL_AUTH_AES_GMAC", 4, 8, 16, "MAY", 0, "gmac"),
    23: ("CAMELLIA_CBC", 16, 16, None, "MAY", None, "cbc"),
    24: ("CAMELLIA_CTR", 4, 8, None, "MAY", None, "ctr"),
    25: ("CAMELLIA_CCM_8", 4, 8, 8, "MAY", None, "aead"),
    26: ("CAMELLIA_CCM_12", 4, 8, 12, "MAY", None, "aead"),
    27: ("CAMELLIA_CCM_16", 4, 8, 16, "MAY", None, "aead"),
    28: ("CHACHA20_POLY1305", 4, 8, 16, "SHOULD", 256, "aead"),
}

IKEV2_PRF = {
    1: ("HMAC_MD5", "MUST NOT", 64), 2: ("HMAC_SHA1", "MUST-", 80), 3: ("HMAC_TIGER", "MUST NOT", 96),
    4: ("AES128_XCBC", "SHOULD", 128), 5: ("HMAC_SHA2_256", "MUST", 128), 6: ("HMAC_SHA2_384", "SHOULD", 192),
    7: ("HMAC_SHA2_512", "SHOULD", 256), 8: ("AES128_CMAC", "SHOULD", 128),
}

# name, status, ICV bytes, strength bits
IKEV2_INTEG = {
    0: ("NONE", "MUST (AEAD only)", 0, 0),
    1: ("HMAC_MD5_96", "MUST NOT", 12, 64),
    2: ("HMAC_SHA1_96", "MUST-", 12, 80),
    3: ("DES_MAC", "MUST NOT", 8, 56),
    4: ("KPDK_MD5", "MUST NOT", 16, 64),
    5: ("AES_XCBC_96", "SHOULD", 12, 128),
    6: ("HMAC_MD5_128", "MUST NOT", 16, 64),
    7: ("HMAC_SHA1_160", "MUST NOT", 20, 80),
    8: ("AES_CMAC_96", "SHOULD", 12, 128),
    9: ("AES_128_GMAC", "MAY", 16, 128),
    10: ("AES_192_GMAC", "MAY", 16, 192),
    11: ("AES_256_GMAC", "MAY", 16, 256),
    12: ("HMAC_SHA2_256_128", "MUST", 16, 128),
    13: ("HMAC_SHA2_384_192", "SHOULD", 24, 192),
    14: ("HMAC_SHA2_512_256", "SHOULD", 32, 256),
}

# group: name, RFC 8247 status, security strength (bits), public value length (bytes) in KE payload, kind
DH_GROUPS = {
    1: ("MODP-768", "MUST NOT", 56, 96, "modp"),
    2: ("MODP-1024", "SHOULD NOT", 80, 128, "modp"),
    5: ("MODP-1536", "SHOULD NOT", 90, 192, "modp"),
    14: ("MODP-2048", "MUST", 112, 256, "modp"),
    15: ("MODP-3072", "SHOULD", 128, 384, "modp"),
    16: ("MODP-4096", "SHOULD", 152, 512, "modp"),
    17: ("MODP-6144", "MAY", 176, 768, "modp"),
    18: ("MODP-8192", "MAY", 200, 1024, "modp"),
    19: ("ECP-256", "SHOULD", 128, 64, "ecp"),
    20: ("ECP-384", "SHOULD", 192, 96, "ecp"),
    21: ("ECP-521", "MAY", 256, 132, "ecp"),
    22: ("MODP-1024-160", "MUST NOT", 80, 128, "modp"),
    23: ("MODP-2048-224", "SHOULD NOT", 112, 256, "modp"),
    24: ("MODP-2048-256", "SHOULD NOT", 112, 256, "modp"),
    25: ("ECP-192", "MAY", 96, 48, "ecp"),
    26: ("ECP-224", "MAY", 112, 56, "ecp"),
    27: ("BRAINPOOL-224", "MAY", 112, 56, "ecp"),
    28: ("BRAINPOOL-256", "MAY", 128, 64, "ecp"),
    29: ("BRAINPOOL-384", "MAY", 192, 96, "ecp"),
    30: ("BRAINPOOL-512", "MAY", 256, 128, "ecp"),
    31: ("X25519", "SHOULD", 128, 32, "ecp"),
    32: ("X448", "MAY", 224, 56, "ecp"),
    35: ("ML-KEM-512", "PQC", 128, 800, "pqc"),
    36: ("ML-KEM-768", "PQC", 192, 1184, "pqc"),
    37: ("ML-KEM-1024", "PQC", 256, 1568, "pqc"),
}

IKEV2_EXCHANGES = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
                   38: "IKE_SESSION_RESUME", 43: "IKE_INTERMEDIATE", 44: "IKE_FOLLOWUP_KE"}
IKEV1_EXCHANGES = {0: "NONE", 1: "BASE", 2: "MAIN (identity protection)", 3: "AUTH_ONLY", 4: "AGGRESSIVE",
                   5: "INFORMATIONAL", 6: "TRANSACTION (mode-config)", 32: "QUICK_MODE", 33: "NEW_GROUP"}

IKEV2_PAYLOADS = {0: "NONE", 33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ", 39: "AUTH", 40: "Ni/Nr",
                  41: "N", 42: "D", 43: "V", 44: "TSi", 45: "TSr", 46: "SK", 47: "CP", 48: "EAP", 49: "GSPM", 50: "IDg",
                  51: "GSA", 52: "KD", 53: "SKF", 54: "PS"}
IKEV1_PAYLOADS = {0: "NONE", 1: "SA", 2: "P", 3: "T", 4: "KE", 5: "ID", 6: "CERT", 7: "CR", 8: "HASH", 9: "SIG", 10: "NONCE",
                  11: "N", 12: "D", 13: "VID", 14: "ATTR", 15: "NAT-D", 16: "NAT-OA", 20: "NAT-D", 21: "NAT-OA",
                  130: "NAT-D(draft)", 131: "NAT-OA(draft)"}

IKEV2_NOTIFY = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION", 7: "INVALID_SYNTAX",
    9: "INVALID_MESSAGE_ID", 11: "INVALID_SPI", 14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD",
    24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED", 35: "NO_ADDITIONAL_SAS", 36: "INTERNAL_ADDRESS_FAILURE",
    37: "FAILED_CP_REQUIRED", 38: "TS_UNACCEPTABLE", 39: "INVALID_SELECTORS", 43: "TEMPORARY_FAILURE", 44: "CHILD_SA_NOT_FOUND",
    16384: "INITIAL_CONTACT", 16385: "SET_WINDOW_SIZE", 16386: "ADDITIONAL_TS_POSSIBLE", 16387: "IPCOMP_SUPPORTED",
    16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP", 16390: "COOKIE", 16391: "USE_TRANSPORT_MODE",
    16392: "HTTP_CERT_LOOKUP_SUPPORTED", 16393: "REKEY_SA", 16394: "ESP_TFC_PADDING_NOT_SUPPORTED",
    16395: "NON_FIRST_FRAGMENTS_ALSO", 16396: "MOBIKE_SUPPORTED", 16397: "ADDITIONAL_IP4_ADDRESS",
    16398: "ADDITIONAL_IP6_ADDRESS", 16399: "NO_ADDITIONAL_ADDRESSES", 16400: "UPDATE_SA_ADDRESSES",
    16401: "COOKIE2", 16402: "NO_NATS_ALLOWED", 16403: "AUTH_LIFETIME", 16404: "MULTIPLE_AUTH_SUPPORTED",
    16405: "ANOTHER_AUTH_FOLLOWS", 16406: "REDIRECT_SUPPORTED", 16407: "REDIRECT", 16408: "REDIRECTED_FROM",
    16409: "TICKET_LT_OPAQUE", 16410: "TICKET_REQUEST", 16411: "TICKET_ACK", 16412: "TICKET_NACK", 16413: "TICKET_OPAQUE",
    16414: "LINK_ID", 16415: "USE_WESP_MODE", 16416: "ROHC_SUPPORTED", 16417: "EAP_ONLY_AUTHENTICATION",
    16418: "CHILDLESS_IKEV2_SUPPORTED", 16419: "QUICK_CRASH_DETECTION", 16420: "IKEV2_MESSAGE_ID_SYNC_SUPPORTED",
    16421: "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED", 16422: "IKEV2_MESSAGE_ID_SYNC", 16423: "IPSEC_REPLAY_COUNTER_SYNC",
    16424: "SECURE_PASSWORD_METHODS", 16425: "PSK_PERSIST", 16426: "PSK_CONFIRM", 16427: "ERX_SUPPORTED",
    16428: "IFOM_CAPABILITY", 16429: "SENDER_REQUEST_ID", 16430: "IKEV2_FRAGMENTATION_SUPPORTED",
    16431: "SIGNATURE_HASH_ALGORITHMS", 16432: "CLONE_IKE_SA_SUPPORTED", 16433: "CLONE_IKE_SA", 16434: "PUZZLE",
    16435: "USE_PPK", 16436: "PPK_IDENTITY", 16437: "NO_PPK_AUTH", 16438: "INTERMEDIATE_EXCHANGE_SUPPORTED",
    16439: "IP4_ALLOWED", 16440: "IP6_ALLOWED", 16441: "ADDITIONAL_KEY_EXCHANGE", 16442: "USE_AGGFRAG",
}

# --------------------------------------------------------------------------- IKEv1 (RFC 2409 Appendix A)
IKEV1_ATTR = {1: "ENCR", 2: "HASH", 3: "AUTH", 4: "GROUP", 5: "GROUP_TYPE", 11: "LIFE_TYPE", 12: "LIFE_DURATION", 14: "KEY_LENGTH"}
IKEV1_ENCR = {1: ("DES_CBC", 56, "legacy"), 2: ("IDEA_CBC", 128, "legacy"), 3: ("BLOWFISH_CBC", None, "legacy"),
              4: ("RC5_R16_B64_CBC", None, "legacy"), 5: ("3DES_CBC", 112, "legacy"), 6: ("CAST_CBC", 128, "legacy"),
              7: ("AES_CBC", None, "cbc"), 8: ("CAMELLIA_CBC", None, "cbc")}
IKEV1_HASH = {1: ("MD5", 64), 2: ("SHA1", 80), 3: ("TIGER", 96), 4: ("SHA2_256", 128), 5: ("SHA2_384", 192), 6: ("SHA2_512", 256)}
IKEV1_AUTH = {1: "PSK", 2: "DSS_SIG", 3: "RSA_SIG", 4: "RSA_ENC", 5: "RSA_ENC_REVISED", 6: "ECDSA_SIG", 7: "ECDSA_SIG",
              8: "ECDSA_SIG", 9: "ECDSA_256", 10: "ECDSA_384", 11: "ECDSA_521", 64221: "HYBRID_RSA", 65001: "XAUTH_INIT_PSK",
              65002: "XAUTH_RESP_PSK", 65003: "XAUTH_INIT_DSS", 65004: "XAUTH_RESP_DSS", 65005: "XAUTH_INIT_RSA",
              65006: "XAUTH_RESP_RSA"}

# Well-known vendor IDs (prefixes, hex) → product; used for fingerprinting / metadata exposure.
VENDOR_IDS = {
    "4a131c81070358455c5728f20e95452f": "RFC 3947 NAT-T",
    "afcad71368a1f1c96b8696fc77570100": "Dead Peer Detection (RFC 3706)",
    "882fe56d6fd20dbc2251613b2ebe5beb": "strongSwan",
    "4048b7d56ebce88525e7de7f00d6c2d3": "Cisco (fragmentation)",
    "1f07f70eaa6514d3b0fa96542a500100": "Cisco Unity",
    "09002689dfd6b712": "XAUTH",
    "12f5f28c457168a9702d9fe274cc0100": "Cisco Unity / VPN 3000",
    "1e2b516905991c7d7c96fcbfb587e461": "Microsoft Windows",
    "e3a5966a76379fe707228231e5ce8652": "Microsoft (initial contact)",
    "90cb80913ebb696e086381b5ec427b1f": "draft-ietf-ipsec-nat-t-ike-02",
    "cd60464335df21f87cfdb2fc68b6a448": "draft-ietf-ipsec-nat-t-ike-02\\n",
    "7d9419a65310ca6f2c179d9215529d56": "draft-ietf-ipsec-nat-t-ike-03",
    "4485152d18b6bbcd0be8a8469579ddcc": "draft-ietf-ipsec-nat-t-ike-00",
    "f4ed19e0c114eb516faaac0ee37daf2807b4381f": "Libreswan / Openswan",
    "5b362bc820f60007": "Check Point",
    "8299031757a36082c6a621de00000000": "Fortinet FortiGate",
    "4a131c81070358455c5728f20e95452f0000": "RFC 3947",
}

IKE_PORTS = {500, 4500}

# minimal plaintext "anchor" packet sizes (bytes) used by the physics model (RFC 791/793/792 header sizes)
ANCHORS = {
    "tunnel": {40: "IPv4+TCP ACK", 52: "IPv4+TCP ACK (timestamps)", 84: "IPv4 ping (64B payload)", 60: "IPv4+TCP SYN (options) / IPv6+TCP ACK",
               72: "IPv6+TCP ACK (timestamps)", 104: "IPv6 ping (64B payload)", 1500: "IPv4 MTU-size", 1400: "typical inner MSS-limited",
               200: "G.711 RTP 20 ms", 1420: "MSS-limited (VPN MTU)"},
    "transport": {20: "TCP ACK", 32: "TCP ACK (timestamps)", 64: "ICMP echo (56B payload)", 40: "TCP SYN (options)",
                  1480: "MTU-size segment", 180: "G.711 RTP 20 ms (UDP+RTP)"},
}


def encr_name(v2_id: int, keylen: int | None = None) -> str:
    n = IKEV2_ENCR.get(v2_id, (f"ENCR_{v2_id}",))[0]
    return f"{n}-{keylen}" if keylen else n


def dh_name(g: int) -> str:
    return DH_GROUPS.get(g, (f"DH-{g}",))[0]
