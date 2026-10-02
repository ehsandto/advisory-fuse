import ast
from pathlib import Path
import re
import pytest


def policy():
    module = ast.parse(Path("contracts/AdvisoryFuse.py").read_text(encoding="utf8"))
    nodes = [node for node in module.body if isinstance(node, (ast.FunctionDef, ast.Assign)) and
             (isinstance(node, ast.Assign) or node.name in
              ("version", "affected", "normalize_semantics", "fuse_decision", "report_matches", "transition"))]
    ns = {"re": re}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "policy", "exec"), ns)
    return ns


def advisory(events, kind="ECOSYSTEM"):
    return {"affected": [{"package": {"ecosystem": "npm", "name": "x"},
                           "ranges": [{"type": kind, "events": events}]}]}


def test_exact_threshold_boundary():
    p = policy()
    a = advisory([{"introduced": "0"}, {"fixed": "4.17.21"}])
    assert p["affected"](a, "x", "4.17.20") == "AFFECTED"
    assert p["affected"](a, "x", "4.17.21") == "UNAFFECTED"
    assert p["affected"](a, "y", "4.17.20") == "UNRELATED"


@pytest.mark.parametrize("a", [advisory([{"introduced": "0"}], "GIT"),
                              advisory([{"introduced": "1.0.0"}, {"fixed": "0.9.0"}]),
                              advisory([{"fixed": "1.0.0"}]), advisory([])])
def test_unsupported_or_broken_ranges_never_clear(a):
    with pytest.raises(ValueError):
        policy()["affected"](a, "x", "1.0.0")


@pytest.mark.parametrize("v", ["1.0", "1.0.0-beta", "01.0.0", "*", "v1.0.0"])
def test_version_parser_fail_closed(v):
    with pytest.raises(ValueError):
        policy()["version"](v)


def test_contradictory_decision_vector_and_hash_disagreement_rejected():
    equal = policy()["report_matches"]
    r = {"decision": "TRIP", "advisories": [{"impact": "EXECUTION"}], "sha256": "a"}
    assert equal(r, r.copy())
    for field, replacement in (("decision", "CLEAN"), ("advisories", [{"impact": "UNKNOWN"}]), ("sha256", "b")):
        assert not equal({**r, field: replacement}, r)


def test_decision_is_reconstructed_not_supplied_by_ai():
    p = policy()
    records = [{"membership": "AFFECTED", "semantic": {"impact": "EXECUTION"}},
               {"membership": "UNKNOWN", "semantic": {"impact": "UNKNOWN"}}]
    assert p["fuse_decision"](records, ["EXECUTION"]) == "TRIP"
    assert p["fuse_decision"](records, ["DISCLOSURE"]) == "UNKNOWN"
    assert p["fuse_decision"]([], ["EXECUTION"]) == "UNKNOWN"
