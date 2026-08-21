#!/usr/bin/env python3
"""Regression tests for target-bound validation and final certification."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import validate_hunt as vh  # noqa: E402


def evidence(name: str) -> dict[str, str]:
    return {"method": "connector", "source": f"live:{name}", "artifact": f"artifacts/{name}.json"}


def target() -> dict:
    return {
        "schema_version": 2,
        "target_id": "h1-elastic-fleet-8f9e6bb",
        "platform": "hackerone",
        "route_type": "bounty",
        "asset_type": "repository",
        "program": "elastic",
        "asset": "Fleet Server",
        "repository": "github.com/elastic/fleet-server",
        "commit": "8f9e6bb",
        "operating_mode": "SOURCE_ONLY",
        "scope": {
            "status": "eligible", "asset_identifier": "Fleet Server", "max_severity": "critical",
            "checked_at": "2026-08-20T03:00:00Z", "reason": "", "evidence": evidence("scope"),
        },
        "proof_policy": {
            "status": "checked", "accepted_proof_types": ["executable-local-exact-path", "regression-test"],
            "quote": "Our code is open so use that to your advantage!",
            "checked_at": "2026-08-20T03:02:00Z", "reason": "", "evidence": evidence("policy"),
        },
        "saturation": {
            "status": "checked", "asset_resolved_count": 6, "discloses_reports": True,
            "checked_at": "2026-08-20T03:04:00Z", "reason": "", "evidence": evidence("saturation"),
            "rationale": "Six asset-level resolved reports and a searchable disclosure feed.",
        },
        "decision": {
            "disposition": "SELECTED", "gate": "selection", "rotation_basis": None,
            "alternative_target": "", "missing_evidence": [], "evidence": evidence("selection"),
            "reason": "Eligible with compatible proof route and acceptable asset-level contestability.",
            "decided_at": "2026-08-20T03:05:00Z",
        },
    }


def candidate_binding(t: dict) -> dict:
    return {
        "target_ledger_id": t["target_id"],
        "target": {
            "platform": t["platform"], "route_type": t["route_type"], "asset_type": t["asset_type"],
            "program": t["program"], "asset": t["asset"], "repository": t["repository"],
            "commit": t["commit"], "operating_mode": t["operating_mode"],
            "scope_checked_at": t["scope"]["checked_at"],
            "scope_evidence": "live:scope (artifacts/scope.json)",
            "saturation": {"discloses_reports": t["saturation"]["discloses_reports"]},
        },
    }


def review_document(verdict: str = "NO_REPORTABLE_FINDING") -> dict:
    return {
        "decision": {"verdict": verdict, "decided_at": "2026-08-20T04:05:00Z"},
        "adversarial_review": {
            "reviewer": {
                "mode": "independent_agent", "id": "reviewer-1",
                "reviewed_at": "2026-08-20T04:00:00Z", "artifact": "reviews/H-1.json",
                "fresh_context": True,
            },
            "cold_verify": {
                "verdict": "DISPROVED", "rederived_severity": "n/a: load-bearing link failed",
                "killed_subclaim": "tenant predicate blocks the requested row",
                "subclaims": [
                    {"claim": "attacker controls id", "status": "supported", "evidence": "routes.py:14"},
                    {"claim": "id bypasses tenant scope", "status": "unsupported", "evidence": "controller.py:22"},
                ],
            },
        },
        "closure_review": {
            "verdict": "DEPTH_SUFFICIENT",
            "closures_challenged": [{
                "hypothesis": "H-1", "closure": "KILL @ reachability",
                "challenge": "re-derived public ingress and tenant lookup",
                "evidence": "reviews/H-1.json#reachability",
            }],
            "probe_assessment": {"sufficient": True, "waived": False, "waiver_reason": "", "evidence": "artifacts/probe.txt"},
            "coverage_gaps": [], "remaining_high_value_hypotheses": ["H-2 remains queued"],
        },
        "exhaustion": {"probes": [{
            "hypothesis": "cross-tenant read", "command": "./probe.sh",
            "would_fire_if_vulnerable": "tenant-B canary returned", "observed": "404",
            "result": "negative", "origin": "researcher_adversarial",
        }]},
    }


def errors_for_target(doc: dict) -> list[str]:
    errors: list[str] = []
    vh.validate_target(doc, errors)
    return errors


def assert_reject(doc: dict, message: str) -> None:
    errors = errors_for_target(doc)
    assert any(message in error for error in errors), errors


def test_target_decisions() -> None:
    assert not errors_for_target(target())

    doc = target()
    doc["scope"]["status"] = "ineligible"
    assert_reject(doc, "may be SELECTED only")

    doc = target()
    doc["proof_policy"]["accepted_proof_types"] = ["program-hosted-owned-account"]
    assert_reject(doc, "compatible with operating_mode")

    doc = target()
    doc["decision"].update({"disposition": "ROTATED", "gate": "selection", "rotation_basis": None})
    assert_reject(doc, "structured decision.rotation_basis")

    doc = target()
    doc["scope"]["status"] = "ineligible"
    doc["decision"].update({
        "disposition": "ROTATED", "gate": "scope", "rotation_basis": "scope_ineligible",
        "reason": "Live scope excludes the asset.", "evidence": copy.deepcopy(doc["scope"]["evidence"]),
    })
    assert not errors_for_target(doc)

    doc = target()
    doc["decision"].update({
        "disposition": "HOLD", "gate": "proof_policy", "rotation_basis": None,
        "missing_evidence": ["Policy fetch failed; retry live retrieval."],
    })
    assert not errors_for_target(doc)


def test_live_evidence_and_asset_types() -> None:
    doc = target()
    doc["scope"]["checked_at"] = "yesterday"
    assert_reject(doc, "ISO-8601")

    doc = target()
    doc["saturation"]["asset_resolved_count"] = -1
    assert_reject(doc, "non-negative integer")

    doc = target()
    doc.update({"asset_type": "api", "asset": "api.example.test", "repository": None, "commit": None,
                "operating_mode": "PROGRAM_HOSTED"})
    doc["proof_policy"]["accepted_proof_types"] = ["program-hosted-owned-account"]
    assert not errors_for_target(doc)

    doc = target()
    doc.update({"platform": "upstream", "route_type": "upstream-advisory", "asset_type": "library",
                "program": "upstream-org/archive-lib", "asset": "archive-lib"})
    doc["scope"].update({"status": "not_applicable", "reason": "Coordinated upstream disclosure."})
    doc["proof_policy"]["accepted_proof_types"] = ["maintainer-fix-or-cve"]
    assert not errors_for_target(doc)


def test_candidate_binding_and_contract() -> None:
    t = target()
    c = candidate_binding(t)
    errors: list[str] = []
    vh.validate_candidate_target_binding(c, t, errors)
    assert not errors, errors

    drifted = copy.deepcopy(c)
    drifted["target"]["asset"] = "Other asset"
    errors = []
    vh.validate_candidate_target_binding(drifted, t, errors)
    assert any("candidate.target.asset" in error for error in errors), errors

    rotated = target()
    rotated["scope"]["status"] = "ineligible"
    rotated["decision"].update({
        "disposition": "ROTATED", "gate": "scope", "rotation_basis": "scope_ineligible",
        "reason": "Excluded", "evidence": copy.deepcopy(rotated["scope"]["evidence"]),
    })
    errors = []
    vh.validate_candidate_target_binding(c, rotated, errors)
    assert any("SELECTED" in error for error in errors), errors

    report = copy.deepcopy(c)
    report["proof"] = {"type": "live-two-identity"}
    report["route"] = {"type": "program"}
    errors = []
    vh.validate_report_target_contract(report, t, errors)
    assert any("proof.type" in error for error in errors), errors


def test_reviewer_and_closure() -> None:
    doc = review_document()
    errors: list[str] = []
    assert vh.validate_review_attestation(doc, errors, allow_owed=False) == "independent_agent"
    vh.validate_closure_review(doc, errors, provisional=False)
    vh.validate_final_review_order(doc, errors)
    assert not errors, errors

    bad = review_document()
    bad["adversarial_review"]["reviewer"] = "fresh reviewer, trust me"
    errors = []
    vh.validate_review_attestation(bad, errors, allow_owed=False)
    assert errors

    bad = review_document()
    bad["adversarial_review"]["reviewer"]["mode"] = "owed"
    errors = []
    vh.validate_review_attestation(bad, errors, allow_owed=False)
    assert any("final report stage" in error for error in errors), errors

    bad = review_document()
    bad["adversarial_review"]["cold_verify"]["verdict"] = "UNCERTAIN"
    errors = []
    vh.validate_closure_review(bad, errors, provisional=False)
    assert any("DISPROVED" in error for error in errors), errors

    bad = review_document()
    bad["closure_review"]["closures_challenged"] = []
    errors = []
    vh.validate_closure_review(bad, errors, provisional=False)
    assert any("closures_challenged" in error for error in errors), errors

    report = review_document("REPORTABLE")
    report["hardening"] = {"completed_at": "2026-08-20T04:01:00Z"}
    errors = []
    vh.validate_final_review_order(report, errors)
    assert any("after hardening" in error for error in errors), errors


def test_probe_warning() -> None:
    doc = review_document()
    warnings: list[str] = []
    vh.validate_probe_shapes(doc, warnings)
    assert not warnings, warnings
    doc["exhaustion"]["probes"] = [{"command": "echo hello"}]
    warnings = []
    vh.validate_probe_shapes(doc, warnings)
    assert warnings


def test_closure_coverage_warning() -> None:
    doc = review_document()
    errors: list[str] = []
    warnings: list[str] = []
    vh.validate_closure_review(doc, errors, provisional=False, warnings=warnings)
    assert not errors, errors
    assert not warnings, warnings

    doc["closure_review"]["coverage_gaps"] = []
    doc["closure_review"]["remaining_high_value_hypotheses"] = []
    warnings = []
    vh.validate_closure_review(doc, errors, provisional=False, warnings=warnings)
    assert not errors, errors
    assert any("no coverage gaps" in warning for warning in warnings), warnings

    provisional_doc = review_document()
    provisional_doc["closure_review"]["verdict"] = "UNREVIEWED"
    warnings = []
    vh.validate_closure_review(provisional_doc, [], provisional=True, warnings=warnings)
    assert not warnings, warnings


def test_caveat_ledger() -> None:
    doc: dict = {"decision": {"verdict": "REPORTABLE"}}
    errors: list[str] = []
    vh.validate_caveat_ledger(doc, errors)
    assert any("caveats[]" in error for error in errors), errors

    doc["caveats"] = "none"
    errors = []
    vh.validate_caveat_ledger(doc, errors)
    assert any("caveats[]" in error for error in errors), errors

    doc["caveats"] = []
    errors = []
    vh.validate_caveat_ledger(doc, errors)
    assert not errors, errors

    doc["caveats"] = [{"quote": "only one endpoint tested", "classification": "ordinary", "justification": "constrains severity, not the boundary"}]
    errors = []
    vh.validate_caveat_ledger(doc, errors)
    assert not errors, errors

    doc["caveats"] = [{"quote": "does not prove production exposure", "classification": "load_bearing", "justification": ""}]
    errors = []
    vh.validate_caveat_ledger(doc, errors)
    assert any("load-bearing caveat forbids REPORTABLE" in error for error in errors), errors
    assert any("justification" in error for error in errors), errors

    doc["caveats"] = [{"quote": "", "classification": "fatal", "justification": ""}]
    errors = []
    vh.validate_caveat_ledger(doc, errors)
    assert len(errors) >= 3, errors

    killed = {"decision": {"verdict": "KILL"}, "caveats": [{"quote": "q", "classification": "load_bearing", "justification": "j"}]}
    errors = []
    vh.validate_caveat_ledger(killed, errors)
    assert not errors, errors


def test_target_cli_labels() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "target.json"
        for disposition, expected in (("SELECTED", "TARGET SELECTED"), ("HOLD", "TARGET HOLD")):
            doc = target()
            if disposition == "HOLD":
                doc["decision"].update({
                    "disposition": "HOLD", "gate": "proof_policy", "rotation_basis": None,
                    "missing_evidence": ["Retry policy pull."],
                })
            path.write_text(json.dumps(doc), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(HERE / "validate_hunt.py"), "--stage", "target", str(path)],
                capture_output=True, text=True,
            )
            assert proc.returncode == 0, proc.stderr
            assert expected in proc.stdout, proc.stdout


def test_start_candidate() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target_path = root / "target.json"
        candidate_path = root / "candidate.json"
        target_path.write_text(json.dumps(target()), encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable, str(HERE / "start_candidate.py"),
                "--target-ledger", str(target_path),
                "--template", str(HERE.parent / "assets" / "candidate.template.json"),
                "--output", str(candidate_path),
            ],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0, proc.stderr
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        assert candidate["target_ledger_id"] == target()["target_id"]
        assert candidate["target"]["asset"] == "Fleet Server"
        errors: list[str] = []
        vh.validate_candidate_target_binding(candidate, target(), errors)
        assert not errors, errors


def main() -> int:
    tests = [
        test_target_decisions,
        test_live_evidence_and_asset_types,
        test_candidate_binding_and_contract,
        test_reviewer_and_closure,
        test_probe_warning,
        test_closure_coverage_warning,
        test_caveat_ledger,
        test_target_cli_labels,
        test_start_candidate,
    ]
    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {test.__name__}: {exc}")
        else:
            print(f"[PASS] {test.__name__}")
    print(f"\n{len(tests) - failed}/{len(tests)} test groups passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
