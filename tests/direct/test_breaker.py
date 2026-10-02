import hashlib
import json
import pytest

MANIFEST = json.dumps({"name": "lodash", "version": "4.17.20"}).encode()
HASH = hashlib.sha256(MANIFEST).hexdigest()
PATH = "2021/05/GHSA-35jh-r3h4-6jhm"
ADVISORY = {"id": "GHSA-35jh-r3h4-6jhm", "summary": "Command Injection in lodash",
            "details": "Versions prior to 4.17.21 allow Command Injection via templates.",
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}


def setup(deploy, vm, alice, warp, commitment=HASH, mask="EXECUTION"):
    c = deploy("contracts/AdvisoryFuse.py")
    vm.sender = alice
    warp(0)
    c.register("fuse", "lodash", "lodash", "a" * 40, commitment, PATH, mask, 120)
    return c


def mocks(vm, advisory=ADVISORY, answer=None, status=200):
    vm.clear_mocks()
    vm.mock_web(r".*aaaa.*/package.json", {"status": 200, "body": MANIFEST})
    vm.mock_web(r".*advisory-database.*", {"status": status, "body": json.dumps(advisory).encode()})
    vm.mock_llm(r"(?s).*Classify the PRIMARY technical consequence.*",
                json.dumps(answer or {"impact": "EXECUTION", "quote": "Command Injection"}))


def scan(c, vm, scan_id="scan", advisory=ADVISORY, answer=None, status=200):
    mocks(vm, advisory, answer, status)
    c.arm_scan("fuse", scan_id)
    c.resolve_scan("fuse", scan_id)
    return json.loads(c.get_fuse("fuse"))


def test_actual_semantic_risk_trips(direct_vm, direct_deploy, direct_alice, warp_time):
    c = setup(direct_deploy, direct_vm, direct_alice, warp_time)
    f = scan(c, direct_vm)
    assert f["state"] == "TRIPPED" and f["latched"]
    assert not c.gate("fuse", f["current_root"])
    r = json.loads(c.get_scan("fuse", "scan"))["report"]
    assert r["advisories"][0]["membership"] == "AFFECTED"
    assert r["advisories"][0]["semantic"]["impact"] == "EXECUTION"


def test_semantic_output_materially_changes_gate(direct_vm, direct_deploy, direct_alice, warp_time):
    c = setup(direct_deploy, direct_vm, direct_alice, warp_time, mask="DISCLOSURE")
    f = scan(c, direct_vm)
    assert f["state"] == "OPEN" and c.gate("fuse", f["current_root"])
    # Impact policy is intentionally not a claim of universal vulnerability safety.


@pytest.mark.parametrize("answer", [{"impact": "UNKNOWN", "quote": ""},
                                    {"impact": "EXECUTION", "quote": "invented source phrase"},
                                    {"impact": "EXECUTION", "quote": "Command Injection", "confidence": 99}])
def test_unknown_or_fabricated_semantics_fail_closed(answer, direct_vm, direct_deploy, direct_alice, warp_time):
    c = setup(direct_deploy, direct_vm, direct_alice, warp_time)
    f = scan(c, direct_vm, answer=answer)
    assert f["state"] == "HELD" and not c.gate("fuse", f["current_root"])


def test_fake_manifest_commitment_fails_closed(direct_vm, direct_deploy, direct_alice, warp_time):
    c = setup(direct_deploy, direct_vm, direct_alice, warp_time, commitment="f" * 64)
    f = scan(c, direct_vm)
    assert f["state"] == "HELD"
    assert not json.loads(c.get_scan("fuse", "scan"))["report"]["manifest_match"]


def test_http_error_fails_closed(direct_vm, direct_deploy, direct_alice, warp_time):
    c = setup(direct_deploy, direct_vm, direct_alice, warp_time)
    assert scan(c, direct_vm, status=503)["state"] == "HELD"


def test_safe_version_evidence_opens(direct_vm, direct_deploy, direct_alice, warp_time):
    c = setup(direct_deploy, direct_vm, direct_alice, warp_time)
    fixed = {**ADVISORY, "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.20"}]}]}]}
    f = scan(c, direct_vm, advisory=fixed)
    assert f["state"] == "OPEN" and c.gate("fuse", f["current_root"])


def test_hysteresis_needs_two_clean_observations(direct_vm, direct_deploy, direct_alice, warp_time):
    c = setup(direct_deploy, direct_vm, direct_alice, warp_time)
    scan(c, direct_vm)
    old = c.get_scan("fuse", "scan")
    clear = {**ADVISORY, "withdrawn": "2026-10-02T00:00:00Z"}
    warp_time(60)
    f = scan(c, direct_vm, "clear1", clear)
    assert f["state"] == "RECOVERY_PENDING" and f["latched"]
    assert not c.gate("fuse", f["current_root"])
    warp_time(120)
    f = scan(c, direct_vm, "clear2", clear)
    assert f["state"] == "OPEN" and not f["latched"]
    assert c.get_scan("fuse", "scan") == old


def test_uncertainty_resets_recovery_not_latch(direct_vm, direct_deploy, direct_alice, warp_time):
    c = setup(direct_deploy, direct_vm, direct_alice, warp_time)
    scan(c, direct_vm)
    warp_time(60)
    scan(c, direct_vm, "clear", {**ADVISORY, "withdrawn": "2026-10-02T00:00:00Z"})
    warp_time(120)
    f = scan(c, direct_vm, "uncertain", status=503)
    assert f["latched"] and f["clean_at"] == 0 and f["state"] == "HELD"


def test_replay_and_cross_fuse_resolution_rejected(direct_vm, direct_deploy, direct_alice, warp_time):
    c = setup(direct_deploy, direct_vm, direct_alice, warp_time)
    scan(c, direct_vm)
    with direct_vm.expect_revert("terminal"):
        c.resolve_scan("fuse", "scan")
    warp_time(60)
    with direct_vm.expect_revert("reused"):
        c.arm_scan("fuse", "scan")
    c.register("other", "lodash", "lodash", "a" * 40, HASH, PATH, "EXECUTION", 120)
    with direct_vm.expect_revert("wrong fuse"):
        c.resolve_scan("other", "scan")


def test_freshness_and_root_substitution(direct_vm, direct_deploy, direct_alice, warp_time):
    c = setup(direct_deploy, direct_vm, direct_alice, warp_time, mask="DISCLOSURE")
    f = scan(c, direct_vm)
    assert not c.gate("fuse", "f" * 64)
    warp_time(119)
    assert c.gate("fuse", f["current_root"])
    warp_time(120)
    assert not c.gate("fuse", f["current_root"])


def test_arm_closes_previous_open_before_consensus(direct_vm, direct_deploy, direct_alice, warp_time):
    c = setup(direct_deploy, direct_vm, direct_alice, warp_time, mask="DISCLOSURE")
    f = scan(c, direct_vm)
    warp_time(60)
    c.arm_scan("fuse", "pending")
    assert not c.gate("fuse", f["current_root"])
    assert json.loads(c.get_fuse("fuse"))["state"] == "SCANNING"


def test_permissionless_recovery_after_scan_expiry(direct_vm, direct_deploy, direct_alice, direct_bob, warp_time):
    c = setup(direct_deploy, direct_vm, direct_alice, warp_time)
    c.arm_scan("fuse", "abandoned")
    warp_time(300)
    with direct_vm.expect_revert("expired"):
        c.resolve_scan("fuse", "abandoned")
    direct_vm.sender = direct_bob
    f = scan(c, direct_vm, "recovered")
    assert f["state"] == "TRIPPED"


def test_no_mutable_source_or_policy_overwrite(direct_vm, direct_deploy, direct_alice, warp_time):
    c = setup(direct_deploy, direct_vm, direct_alice, warp_time)
    with direct_vm.expect_revert("duplicate"):
        c.register("fuse", "lodash", "lodash", "b" * 40, HASH, PATH, "DISCLOSURE", 120)
