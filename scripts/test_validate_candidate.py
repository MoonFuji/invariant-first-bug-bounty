#!/usr/bin/env python3
"""Focused regressions for the lean schema-7 candidate gates."""
from __future__ import annotations

import copy

from hunt_validation.candidate import validate_candidate
from hunt_validation.target import validate_target
from test_fixtures import valid_candidate, valid_target


def errors_for(candidate: dict, *, stage: str = "report", target: dict | None = None) -> list[str]:
    t = target or valid_target()
    errors: list[str] = []
    validate_target(t, errors)
    validate_candidate(candidate, t, stage, errors)
    return errors


def assert_reject(candidate: dict, fragment: str, *, target: dict | None = None) -> None:
    errors = errors_for(candidate, target=target)
    assert any(fragment in error for error in errors), errors


def test_reportable_candidate_accepts() -> None:
    assert not errors_for(valid_candidate())


def test_capability_delta_is_load_bearing() -> None:
    doc = valid_candidate()
    doc["attacker_model"]["capability_after"] = doc["attacker_model"]["capability_before"]
    doc["claim"]["capability"] = doc["attacker_model"]["capability_after"]
    assert_reject(doc, "new attacker capability")


def test_terminal_refutation_cannot_be_rubber_stamped() -> None:
    doc = valid_candidate()
    doc["strongest_refutation"]["kind"] = "target_does_not_own_security_property"
    assert_reject(doc, "terminal refutation cannot be marked refuted")


def test_unresolved_refutation_blocks_reporting() -> None:
    doc = valid_candidate()
    doc["strongest_refutation"]["result"] = "unresolved"
    assert_reject(doc, "requires strongest_refutation.result refuted")


def test_proof_must_reach_executable_boundary() -> None:
    doc = valid_candidate()
    doc["proof"]["level"] = "primitive"
    assert_reject(doc, "proof.level executable or boundary")


def test_operator_weakened_config_blocks_reporting() -> None:
    doc = valid_candidate()
    doc["proof"]["config_dependency"] = {
        "kind": "operator_weakened",
        "evidence": "operator disabled tenant middleware",
        "precondition_grants_effect": True,
    }
    assert_reject(doc, "operator_weakened")


def test_narrow_preserves_smaller_valid_claim() -> None:
    doc = valid_candidate()
    doc["recovery"] = {
        "status": "narrow",
        "next_action": "submit only the demonstrated cross-tenant read",
        "required_artifact": "",
        "unsupported_claims": ["write access was not demonstrated"],
    }
    assert not errors_for(doc)


def test_recover_and_operator_required_block_reporting() -> None:
    for status in ("recover", "operator_required"):
        doc = valid_candidate()
        doc["recovery"] = {
            "status": status,
            "next_action": "obtain hosted proof",
            "required_artifact": "owned test account",
            "unsupported_claims": [],
        }
        assert_reject(doc, f"recovery.status {status} forbids REPORTABLE")


def test_novelty_requires_issue_and_pr_channels() -> None:
    doc = valid_candidate()
    doc["novelty"]["searches"] = [
        item for item in doc["novelty"]["searches"]
        if item["source"] != "upstream_pull_requests"
    ]
    assert_reject(doc, "upstream_pull_requests")


def test_private_collision_uncertainty_needs_differentiator() -> None:
    doc = valid_candidate()
    doc["novelty"]["private_duplicate_risk"] = "unknown"
    doc["novelty"]["collision_differentiator"] = ""
    assert_reject(doc, "collision_differentiator")


def test_fixed_current_state_blocks_reporting() -> None:
    doc = valid_candidate()
    doc["novelty"]["current_state"]["result"] = "fixed"
    assert_reject(doc, "current_state not fixed")


def test_target_binding_catches_revision_drift() -> None:
    doc = valid_candidate()
    doc["target"]["commit"] = "different"
    assert_reject(doc, "must match target ledger commit")


def test_target_policy_must_accept_proof() -> None:
    target = valid_target()
    target["proof_policy"]["accepted_proof_types"] = ["regression-test"]
    doc = valid_candidate()
    doc["target_fingerprint"] = __import__("hunt_validation.target", fromlist=["target_fingerprint"]).target_fingerprint(target)
    assert_reject(doc, "proof.type is not accepted", target=target)


def test_target_severity_cap_blocks_overclaim() -> None:
    target = valid_target()
    target["scope"]["max_severity"] = "low"
    doc = valid_candidate()
    doc["target_fingerprint"] = __import__("hunt_validation.target", fromlist=["target_fingerprint"]).target_fingerprint(target)
    assert_reject(doc, "exceeds target.scope.max_severity", target=target)


def test_reportable_claim_matches_capability_delta() -> None:
    doc = valid_candidate()
    doc["claim"]["capability"] = "full database takeover"
    assert_reject(doc, "must exactly match attacker_model.capability_after")


def test_hold_can_stop_before_report_only_gates() -> None:
    doc = valid_candidate()
    doc["decision"] = {
        "verdict": "HOLD",
        "gate": "proof",
        "failed_gates": [],
        "missing_evidence": ["Need exact runtime reproduction."],
        "reason": "Static trace is promising but proof is incomplete.",
    }
    doc["proof"]["level"] = "primitive"
    errors = errors_for(doc, stage="decision")
    assert not [error for error in errors if "REPORTABLE" in error], errors


def main() -> int:
    tests = [
        test_reportable_candidate_accepts,
        test_capability_delta_is_load_bearing,
        test_terminal_refutation_cannot_be_rubber_stamped,
        test_unresolved_refutation_blocks_reporting,
        test_proof_must_reach_executable_boundary,
        test_operator_weakened_config_blocks_reporting,
        test_narrow_preserves_smaller_valid_claim,
        test_recover_and_operator_required_block_reporting,
        test_novelty_requires_issue_and_pr_channels,
        test_private_collision_uncertainty_needs_differentiator,
        test_fixed_current_state_blocks_reporting,
        test_target_binding_catches_revision_drift,
        test_target_policy_must_accept_proof,
        test_target_severity_cap_blocks_overclaim,
        test_reportable_claim_matches_capability_delta,
        test_hold_can_stop_before_report_only_gates,
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
    print(f"{len(tests) - failed}/{len(tests)} candidate groups passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
