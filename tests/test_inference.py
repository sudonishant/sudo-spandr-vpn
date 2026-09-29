"""Ground-truth tests: every generated scenario must be inferred correctly.

The manifest written by ``ipsec_xray.testbed.generate`` is the oracle. If the
samples are missing they are generated on the fly (takes a few seconds).
"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")
MANIFEST = os.path.join(SAMPLES, "manifest.json")
sys.path.insert(0, ROOT)

from ipsec_xray.pipeline import analyze_file, reassess  # noqa: E402


@pytest.fixture(scope="session")
def manifest():
    if not os.path.exists(MANIFEST):
        subprocess.check_call([sys.executable, "-m", "ipsec_xray.testbed.generate"], cwd=ROOT)
    with open(MANIFEST) as fh:
        return json.load(fh)


@pytest.fixture(scope="session")
def results(manifest):
    out = {}
    for name, truth in manifest.items():
        path = os.path.join(SAMPLES, truth.get("file", name + ".pcap"))
        out[name] = analyze_file(path, profile="baseline", name=name)
    return out


def _main_ike(res):
    sas = [i for i in res["facts"]["ike"] if i["complete"]]
    assert sas, "no complete IKE SA"
    return sas[0]


def _main_tunnel(res):
    tunnels = res["facts"]["tunnels"]
    assert tunnels, "no tunnel"
    return max(tunnels, key=lambda t: t["packets"])


def test_all_samples_parse(results, manifest):
    assert set(results) == set(manifest)
    for name, res in results.items():
        cap = res["facts"]["capture"]
        assert cap["packets"] > 0, name
        if name == "replay_flood_anomalies":
            assert cap["parse_errors"] >= 1  # the scenario injects one malformed IKE message on purpose
        else:
            assert cap["parse_errors"] == 0, f"{name}: {cap['parse_errors']} parse errors"


@pytest.mark.parametrize("name", [
    "good_ikev2_gcm_pqc_pfs", "enterprise_cbc_sha256_natt", "legacy_ikev1_aggressive_3des",
    "terrible_ikev1_des_md5_null_esp", "ipv6_natt_chacha_transport", "ah_only_no_confidentiality",
    "replay_flood_anomalies", "hub_three_spokes_mixed_traffic",
])
def test_ike_version_and_grade(results, manifest, name):
    res, truth = results[name], manifest[name]
    ike = _main_ike(res)
    assert ike["version"] == truth["ike_version"]
    assert res["assessment"]["grade"] in truth["expected_grade"], (
        f"{name}: grade {res['assessment']['grade']} not in {truth['expected_grade']} (score {res['assessment']['score']})")


def test_ike_parameters_observed(results):
    good = _main_ike(results["good_ikev2_gcm_pqc_pfs"])
    assert good["encr_aead"] and "GCM" in good["encr_label"]
    assert good["dh"] == "ECP-384" and good["pqc_hybrid"] and "ML-KEM-1024" in good["pqc_groups"]
    legacy = _main_ike(results["legacy_ikev1_aggressive_3des"])
    assert legacy["v1_mode"] == "aggressive" and legacy["encr_label"] == "3DES_CBC"
    assert legacy["dh"] == "MODP-1024" and legacy["auth"]["psk"] is True
    assert legacy["id_plaintext"] and any("@" in i["value"] or "." in i["value"] for i in legacy["ids"])
    terrible = _main_ike(results["terrible_ikev1_des_md5_null_esp"])
    assert terrible["encr_label"].startswith("DES") and "MD5" in terrible["prf"]


def test_esp_framing_inferred(results, manifest):
    for name in ("good_ikev2_gcm_pqc_pfs", "enterprise_cbc_sha256_natt", "legacy_ikev1_aggressive_3des",
                 "ipv6_natt_chacha_transport", "terrible_ikev1_des_md5_null_esp"):
        fr = _main_tunnel(results[name])["framing"]
        key = f"o{fr['overhead']}_b{fr['block']}"
        assert key == manifest[name]["esp_framing"], f"{name}: {key} ({fr['lead_key']}) != {manifest[name]['esp_framing']}"
        assert fr["confidence"] >= 0.5


def test_null_encryption_detected(results):
    t = _main_tunnel(results["terrible_ikev1_des_md5_null_esp"])
    fr = t["framing"]
    assert fr["null_encr"] is True and fr["plaintext_visible"] is True
    # with ENCR_NULL the ESP trailer and inner packet are decoded: mode and application become Observed facts
    assert t["cleartext_inner"]["packets"] > 100
    assert t["mode"]["tier"] == "Observed" and t["mode"]["value"] == "tunnel"
    assert t["traffic"]["tier"] == "Observed"
    assert {c["class"] for c in t["traffic"]["top"]} >= {"icmp", "file"}


def test_ah_icv_observed(results):
    t = _main_tunnel(results["ah_only_no_confidentiality"])
    assert t["protocol"] == "AH" and t["framing"]["tier"] == "Observed"
    assert t["mode"]["tier"] == "Observed" and t["mode"]["value"] == "transport"
    assert t["traffic"]["tier"] == "Observed" and t["traffic"]["class"] == "icmp"
    caps = results["ah_only_no_confidentiality"]["assessment"]
    assert caps["grade_cap"] and "ESP-I-004" in caps["grade_cap"]["reason"]


def test_mode_and_traffic(results, manifest):
    for name, truth in manifest.items():
        if name in ("replay_flood_anomalies", "hub_three_spokes_mixed_traffic"):
            continue
        t = _main_tunnel(results[name])
        assert t["mode"]["value"] == truth["mode"], f"{name}: mode {t['mode']['value']} != {truth['mode']}"
        assert t["traffic"]["class"] in truth["traffic"].split("+"), f"{name}: traffic {t['traffic']['class']} != {truth['traffic']}"


def test_pfs(results, manifest):
    for name in ("good_ikev2_gcm_pqc_pfs", "enterprise_cbc_sha256_natt", "terrible_ikev1_des_md5_null_esp"):
        state = _main_tunnel(results[name])["pfs"]["state"]
        assert state == manifest[name]["pfs"], f"{name}: pfs {state} != {manifest[name]['pfs']}"


def test_ipv6_transport(results):
    res = results["ipv6_natt_chacha_transport"]
    assert res["facts"]["capture"]["ipv6"]
    t = _main_tunnel(res)
    assert t["ipver"] == 6 and t["udp_encap"] and t["mode"]["value"] == "transport"


def test_replay_and_flood_anomalies(results):
    res = results["replay_flood_anomalies"]
    t = _main_tunnel(res)
    assert not t["replay"]["monotonic"] and t["replay"]["duplicates"] > 0
    assert res["facts"]["capture"]["incomplete_sas"] >= 10
    ids = {f["id"] for f in res["assessment"]["findings"]}
    assert "SEQ-001" in ids or "SEQ-002" in ids
    assert "ANOM-001" in ids


def test_hub_has_three_tunnels(results):
    res = results["hub_three_spokes_mixed_traffic"]
    assert res["facts"]["capture"]["tunnel_count"] == 3
    classes = {t["traffic"]["class"] for t in res["facts"]["tunnels"]}
    assert len(classes) >= 2


def test_evidence_tiers_and_unknown_never_penalises(results):
    for res in results.values():
        for f in res["assessment"]["findings"]:
            assert f["tier"] in ("Observed", "Inferred", "Unknown")
            if f["tier"] == "Unknown":
                assert f["penalty"] == 0
            if f["tier"] == "Inferred" and f["severity"] != "info":
                assert f["confidence"] <= 1.0
        tiers = res["assessment"]["tiers"]
        assert tiers["observed_pct"] + tiers["inferred_pct"] + tiers["unknown_pct"] in (99, 100, 101)


def test_profiles_are_monotonic(results):
    res = results["enterprise_cbc_sha256_natt"]
    scores = [reassess(res, p)["assessment"]["score"] for p in ("baseline", "enterprise", "government", "pqc_ready")]
    assert scores[0] >= scores[1] >= scores[2] >= scores[3], scores
    good = results["good_ikev2_gcm_pqc_pfs"]
    assert reassess(good, "pqc_ready")["assessment"]["grade"] in ("A", "A+")
