#!/usr/bin/env python3
"""Integration-level validation regressions for the simplified workflow."""
from __future__ import annotations

import copy

from hunt_validation.candidate import validate_candidate
from hunt_validation.target import target_fingerprint, validate_campaign, validate_target
from test_fixtures import valid_campaign, valid_candidate, valid_target


def test_target_hold_is_explicit_missing_evidence_not_campaign_state() -> None:
    target = valid_target()
    target["scope"]["status"] = "unknown"
    target["scope"]["max_severity"] = ""
    target["scope"]["reason"] = "Scope connector unavailable."
    target["decision"] = {
        "disposition": "HOLD",
        "gate": "scope",
        "rotation_basis": None,
        "alternative_target": "",
        "missing_evidence": ["Current scope eligibility."],
        "reason": "Cannot select until live scope is known.",
        "evidence": {"method": "", "source": "", "artifact": ""},
    }
    errors: list[str] = []
    validate_target(target, errors)
    assert not errors, errors


def test_proof_route_rotation_must_be_evidence_backed() -> None:
    target = valid_target()
    target["proof_policy"] = {
        "status": "unavailable",
        "accepted_proof_types": [],
        "quote": "",
        "checked_at": target["scope"]["checked_at"],
        "reason": "Program policy page is unavailable.",
        "evidence": {"method": "connector", "source": "live:policy", "artifact": "policy-failure.json"},
    }
    target["decision"] = {
        "disposition": "ROTATED",
        "gate": "proof_policy",
        "rotation_basis": "proof_route_unavailable",
        "alternative_target": "",
        "missing_evidence": [],
        "reason": "No accepted proof route can currently be established.",
        "evidence": copy.deepcopy(target["proof_policy"]["evidence"]),
    }
    errors: list[str] = []
    validate_target(target, errors)
    assert not errors, errors

    target["decision"]["evidence"]["artifact"] = "invented.json"
    errors = []
    validate_target(target, errors)
    assert any("must match proof_policy.evidence" in error for error in errors), errors


def test_candidate_does_not_require_campaign() -> None:
    target = valid_target()
    candidate = valid_candidate()
    errors: list[str] = []
    validate_candidate(candidate, target, "report", errors, campaign=None)
    assert not errors, errors


def test_campaign_binding_is_optional_but_strict_when_supplied() -> None:
    target = valid_target()
    campaign = valid_campaign()
    candidate = valid_candidate(campaign=True)
    errors: list[str] = []
    validate_campaign(campaign, errors)
    validate_candidate(candidate, target, "report", errors, campaign=campaign)
    assert not errors, errors

    campaign["hypotheses"][0]["status"] = "queued"
    errors = []
    validate_campaign(campaign, errors)
    validate_candidate(candidate, target, "report", errors, campaign=campaign)
    assert any("investigating or closed" in error for error in errors), errors


def test_closed_hypothesis_can_bind_exact_terminal_candidate_without_hash_bookkeeping() -> None:
    target = valid_target()
    campaign = valid_campaign()
    campaign["hypotheses"][0].update({
        "status": "closed",
        "candidate_id": "C-001",
        "verdict": "REPORTABLE",
        "reason": "Exact cross-tenant read was demonstrated.",
    })
    candidate = valid_candidate(campaign=True)
    errors: list[str] = []
    validate_campaign(campaign, errors)
    validate_candidate(candidate, target, "report", errors, campaign=campaign)
    assert not errors, errors
    assert "candidate_sha256" not in campaign["hypotheses"][0]
    assert "closed_at" not in campaign["hypotheses"][0]


def test_target_refresh_preserves_candidate_only_when_identity_is_stable() -> None:
    target = valid_target()
    candidate = valid_candidate()
    refreshed = copy.deepcopy(target)
    refreshed["scope"]["checked_at"] = target["proof_policy"]["checked_at"]
    refreshed["scope"]["evidence"]["artifact"] = "new-scope.json"
    # Mutable evidence refresh does not change target fingerprint.
    assert target_fingerprint(refreshed) == candidate["target_fingerprint"]

    changed = copy.deepcopy(target)
    changed["commit"] = "new-revision"
    assert target_fingerprint(changed) != candidate["target_fingerprint"]


def main() -> int:
    tests = [
        test_target_hold_is_explicit_missing_evidence_not_campaign_state,
        test_proof_route_rotation_must_be_evidence_backed,
        test_candidate_does_not_require_campaign,
        test_campaign_binding_is_optional_but_strict_when_supplied,
        test_closed_hypothesis_can_bind_exact_terminal_candidate_without_hash_bookkeeping,
        test_target_refresh_preserves_candidate_only_when_identity_is_stable,
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
    print(f"{len(tests) - failed}/{len(tests)} hunt integration groups passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
