#!/usr/bin/env python3
"""Behavioral tests for the schema-3 campaign and target layer."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
import validate_hunt as vh  # noqa: E402
from hunt_validation.target import target_fingerprint  # noqa: E402

NOW = datetime.now(UTC).replace(microsecond=0)


def stamp(*, minutes_ago: int = 0, days_ago: int = 0, minutes_ahead: int = 0) -> str:
    value = NOW - timedelta(days=days_ago, minutes=minutes_ago) + timedelta(minutes=minutes_ahead)
    return value.isoformat().replace("+00:00", "Z")


def evidence(name: str) -> dict[str, str]:
    return {"method": "connector", "source": f"live:{name}", "artifact": f"artifacts/{name}.json"}


def target() -> dict:
    checked = stamp(minutes_ago=10)
    return {
        "schema_version": 3,
        "target_id": "h1-example-asset",
        "platform": "hackerone",
        "route_type": "bounty",
        "asset_type": "repository",
        "program": "example",
        "asset": "Example Server",
        "repository": "github.com/example/server",
        "commit": "0123456789abcdef",
        "operating_mode": "SOURCE_ONLY",
        "scope": {
            "status": "eligible", "asset_identifier": "Example Server", "max_severity": "high",
            "checked_at": checked, "reason": "", "evidence": evidence("scope"),
        },
        "proof_policy": {
            "status": "checked", "accepted_proof_types": ["executable-local-exact-path"],
            "supporting_evidence_types": ["static-source-trace"],
            "quote": "Local exact-path proof accepted.", "checked_at": checked, "reason": "",
            "evidence": evidence("policy"),
        },
        "contestability": {
            "status": "checked", "basis": "platform_count", "count": 6,
            "discloses_reports": True, "checked_at": checked, "reason": "",
            "evidence": evidence("contestability"), "rationale": "Asset-level count is visible.",
        },
        "prior_outcomes": {
            "status": "assessed", "summary": "One related class was informative; no private IDs available.",
            "outcomes": [{"class": "authz", "outcome": "informative", "evidence": "public disclosure feed"}],
            "checked_at": checked, "evidence": evidence("prior-outcomes"),
        },
        "coverage_delta": {
            "status": "assessed", "previously_audited": ["legacy API"],
            "new_or_uncovered": ["queue consumer"], "changed_since_last_review": ["commit 0123456"],
            "checked_at": checked, "evidence": evidence("coverage"),
        },
        "architecture_boundary_map": {
            "boundaries": [{
                "boundary_id": "B-001", "name": "request to tenant record",
                "entrypoints": ["GET /records/{id}"], "trust_transition": "untrusted caller to tenant data",
                "evidence": evidence("boundary-001"),
            }],
        },
        "hypothesis_lifecycle": [{
            "hypothesis_id": "H-001", "boundary_id": "B-001",
            "statement": "Record lookup may omit tenant authorization.", "priority": "high",
            "status": "investigating",
        }, {
            "hypothesis_id": "H-002", "boundary_id": "B-001",
            "statement": "Cache key may cross tenant boundaries.", "priority": "medium",
            "status": "queued",
        }],
        "campaign": {
            "campaign_id": "C-001", "mode": "bounded", "status": "open",
            "stop_condition": "Stop after the two mapped hypotheses reach terminal evidence.",
        },
        "decision": {
            "disposition": "SELECTED", "gate": "selection", "rotation_basis": None,
            "alternative_target": "", "missing_evidence": [],
            "reason": "Scope, proof, contestability, and campaign state are recorded.",
            "decided_at": stamp(minutes_ago=5), "evidence": evidence("selection"),
        },
    }


def errors_for(document: dict) -> list[str]:
    errors: list[str] = []
    vh.validate_target(document, errors)
    return errors


def assert_reject(document: dict, fragment: str) -> None:
    errors = errors_for(document)
    assert any(fragment in error for error in errors), errors


def test_schema3_campaign_target_is_valid() -> None:
    assert not errors_for(target())


def test_contestability_requires_truthful_basis() -> None:
    document = target()
    document["contestability"].update({"basis": "platform_count", "count": 0})
    assert not errors_for(document), errors_for(document)

    document = target()
    document["contestability"].update({"basis": "public_history", "count": None})
    assert not errors_for(document), errors_for(document)

    document = target()
    document["contestability"].update({
        "basis": "public_history", "count": None, "discloses_reports": None,
    })
    assert_reject(document, "discloses_reports must be a boolean for bounty/VDP")

    document = target()
    document["contestability"].update({
        "basis": "private_unavailable", "count": 0,
        "reason": "The private duplicate pool is not exposed to this role.",
    })
    assert_reject(document, "count must be omitted or null")

    document = target()
    document["contestability"].update({"basis": "not_applicable", "count": 3})
    assert_reject(document, "count must be omitted or null")

    document = target()
    document["contestability"].update({"basis": "platform_count", "count": -1})
    assert_reject(document, "non-negative integer")

    document = target()
    document["contestability"].update({
        "status": "not_applicable", "basis": "not_applicable", "count": None,
        "discloses_reports": None, "reason": "not applicable",
    })
    assert_reject(document, "selected bounty/VDP targets require checked contestability")


def test_scope_rotation_does_not_require_campaign_modeling() -> None:
    document = target()
    document["scope"].update({
        "status": "ineligible", "max_severity": "", "reason": "The exact asset is excluded.",
    })
    document["decision"].update({
        "disposition": "ROTATED", "gate": "scope", "rotation_basis": "scope_ineligible",
        "reason": "Live scope excludes the exact asset.", "evidence": copy.deepcopy(document["scope"]["evidence"]),
    })
    for key in (
        "proof_policy", "contestability", "prior_outcomes", "coverage_delta",
        "architecture_boundary_map", "hypothesis_lifecycle", "campaign",
    ):
        document.pop(key)
    assert not errors_for(document), errors_for(document)


def test_static_source_trace_is_supporting_only() -> None:
    document = target()
    document["proof_policy"]["accepted_proof_types"] = ["static-source-trace"]
    assert_reject(document, "supporting evidence only")

    document = target()
    document["proof_policy"]["supporting_evidence_types"] = ["unknown"]
    assert_reject(document, "supporting_evidence_types contains an invalid")


def test_target_evidence_order_and_freshness() -> None:
    document = target()
    document["decision"]["decided_at"] = "2026-08-30"
    assert_reject(document, "explicit timezone")

    document = target()
    document["scope"]["checked_at"] = stamp(minutes_ahead=10)
    assert_reject(document, "must not be in the future")

    document = target()
    document["scope"]["checked_at"] = stamp(minutes_ago=1)
    assert_reject(document, "must be no later than decision.decided_at")

    document = target()
    document["proof_policy"]["checked_at"] = stamp(days_ago=100)
    assert_reject(document, "older than the allowed freshness window")

    document = target()
    document["decision"]["decided_at"] = stamp(minutes_ahead=10)
    assert_reject(document, "decision.decided_at must not be in the future")


def test_campaign_lifecycle_and_closure() -> None:
    document = target()
    document["campaign"].update({"status": "closed", "closed_at": stamp(minutes_ago=1)})
    assert_reject(document, "remaining high-value hypotheses")

    document = target()
    document["campaign"].update({"status": "closed", "closed_at": stamp(minutes_ago=1)})
    for item in document["hypothesis_lifecycle"]:
        item.update({
            "status": "closed",
            "candidate_id": f"candidate-{item['hypothesis_id']}",
            "candidate_sha256": "a" * 64,
            "terminal_verdict": "NO_REPORTABLE_FINDING",
            "closed_at": stamp(minutes_ago=2),
            "evidence": f"candidates/{item['hypothesis_id']}.json",
        })
    assert not errors_for(document), errors_for(document)

    document = target()
    document["campaign"]["mode"] = "invalid"
    assert_reject(document, "campaign.mode must be one of")

    document = target()
    document["campaign"]["stop_condition"] = ""
    assert_reject(document, "campaign.stop_condition must be a non-empty string")


def test_start_candidate_binds_campaign_and_hypothesis() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        target_path = root / "target.json"
        candidate_path = root / "candidate.json"
        target_path.write_text(json.dumps(target()), encoding="utf-8")
        process = subprocess.run([
            sys.executable, str(SCRIPTS / "start_candidate.py"),
            "--target-ledger", target_path, "--hypothesis-id", "H-001",
            "--template", ROOT / "assets" / "candidate.template.json", "--output", candidate_path,
        ], cwd=ROOT, capture_output=True, text=True)
        assert process.returncode == 0, process.stderr
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        assert candidate["campaign_id"] == "C-001"
        assert candidate["target_fingerprint"] == target_fingerprint(target())
        assert candidate["boundary_id"] == "B-001"
        assert candidate["hypothesis_id"] == "H-001"

        document = copy.deepcopy(target())
        document["hypothesis_lifecycle"][0]["status"] = "queued"
        target_path.write_text(json.dumps(document), encoding="utf-8")
        failed = subprocess.run([
            sys.executable, str(SCRIPTS / "start_candidate.py"),
            "--target-ledger", target_path, "--hypothesis-id", "H-001",
            "--template", ROOT / "assets" / "candidate.template.json", "--output", root / "other.json",
        ], cwd=ROOT, capture_output=True, text=True)
        assert failed.returncode != 0
        assert "investigating" in failed.stderr


def test_open_campaign_does_not_block_selected_target() -> None:
    document = target()
    document["campaign"]["status"] = "open"
    document["hypothesis_lifecycle"][1]["priority"] = "high"
    assert not errors_for(document), errors_for(document)


def main() -> int:
    tests = [
        test_schema3_campaign_target_is_valid,
        test_contestability_requires_truthful_basis,
        test_scope_rotation_does_not_require_campaign_modeling,
        test_static_source_trace_is_supporting_only,
        test_target_evidence_order_and_freshness,
        test_campaign_lifecycle_and_closure,
        test_start_candidate_binds_campaign_and_hypothesis,
        test_open_campaign_does_not_block_selected_target,
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
    print(f"\n{len(tests) - failed}/{len(tests)} campaign test groups passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
