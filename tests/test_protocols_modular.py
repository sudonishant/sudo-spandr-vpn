"""Tests for modular protocol dissection components (IKE, ISAKMP, ESP, AH, NAT-T, Replay, DH)."""
import pytest

from ipsec_xray.protocols import (
    AntiReplayWindow,
    ChildSA,
    ESPHeader,
    IKESARecord,
    dh_name,
    dh_security_level,
    esp_length_residue,
    has_non_esp_marker,
    is_nat_keepalive,
    parse_ah,
    parse_esp,
    parse_ike,
    strip_non_esp_marker,
)
from ipsec_xray.protocols.diffie_hellman import dh_security_level
from ipsec_xray.protocols.nat_t import NON_ESP_MARKER


def test_anti_replay_window():
    w = AntiReplayWindow(window_size=64)
    # First packet
    assert w.check_and_update(1) is True
    assert w.highest_seq == 1
    # Duplicate packet rejected
    assert w.check_and_update(1) is False
    assert w.replayed_packets == 1
    # Next packet in order
    assert w.check_and_update(2) is True
    # Packet jumping ahead
    assert w.check_and_update(10) is True
    assert w.gaps_detected == 7  # 3,4,5,6,7,8,9 skipped
    # Out of order packet within window
    assert w.check_and_update(5) is True
    assert w.out_of_order_packets == 1
    # Replay of the out of order packet
    assert w.check_and_update(5) is False
    # Packet sequence 0 illegal
    assert w.check_and_update(0) is False


def test_dh_security_evaluations():
    # Deprecated group 2 (MODP 1024)
    g2 = dh_security_level(2)
    assert g2["status"] == "deprecated"
    assert g2["quantum_safe"] is False

    # Acceptable group 14 (MODP 2048)
    g14 = dh_security_level(14)
    assert g14["status"] == "legacy" or g14["status"] == "acceptable"

    # Acceptable group 19 (ECP 256)
    g19 = dh_security_level(19)
    assert g19["security_bits"] >= 128
    assert g19["status"] == "acceptable"

    # Post-quantum hybrid
    g_pqc = dh_security_level(35)  # ML-KEM-768
    assert g_pqc["quantum_safe"] is True
    assert g_pqc["status"] == "quantum_resistant"


def test_nat_t_helpers():
    keepalive = b"\xff"
    assert is_nat_keepalive(keepalive) is True
    assert is_nat_keepalive(b"\x00\x01\x02") is False

    payload = NON_ESP_MARKER + b"fake_ike_data"
    assert has_non_esp_marker(payload) is True
    assert strip_non_esp_marker(payload) == b"fake_ike_data"
    assert strip_non_esp_marker(b"raw_data") == b"raw_data"


def test_esp_length_residue():
    # Test ESP length residue calculation
    # wire_length = 100, tag_size = 16, block_size = 16
    # esp_overhead = 8 + 16 + 2 = 26
    # (100 - 26) % 16 = 74 % 16 = 10
    res = esp_length_residue(100, block_size=16, tag_size=16)
    assert res == 10


def test_security_association_records():
    sa = IKESARecord(
        spi_i="0102030405060708",
        spi_r="0807060504030201",
        version=2,
        initiator_ip="192.168.1.1",
        responder_ip="192.168.1.2",
    )
    assert sa.id == "01020304:08070605"
    child = ChildSA(spi_in=0x12345678, spi_out=0x87654321, protocol="ESP", mode="tunnel")
    sa.add_child(child)
    assert len(sa.child_sas) == 1
    assert sa.child_sas[0].spi_in == 0x12345678
