#!/usr/bin/env python3
"""Regression tests for optional campaign mode and lean target selection."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from hunt_validation.target import validate_campaign, validate_target
from test_fixtures import valid_campaign, valid_target


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def target_errors(document: dict) -> list[str]:
    errors: list[str] = []
    validate_target(document, errors)
    return errors


def campaign_errors(document: dict) -> list[str]:
    errors: list[str] = []
    validate_campaign(document, errors)
    return errors


def test_lean_target_accepts_without_campaign_metadata() -> None:
    target = valid_target()
    assert set(target).isdisjoint({
        "campaign", "hypothesis_lifecycle", "architecture_boundary_map",
        "coverage_delta", "prior_outcomes", "contestability",
    })
    assert not target_errors(target)


def test_target_selection_requires_live_scope_and_proof_policy() -> None:
    target = valid_target()
    target["scope"]["status"] = "unknown"
    assert any("scope.status eligible" in error for error in target_errors(target))

    target = valid_target()
    target["proof_policy"]["status"] = "unavailable"
    assert any("proof_policy.status checked" in error for error in target_errors(target))


def test_scope_rotation_can_happen_without_campaign_modeling() -> None:
    target = valid_target()
    target["scope"].update({
        "status": "ineligible",
        "max_severity": "",
        "reason": "Exact asset is excluded.",
    })
    target["decision"].update({
        "disposition": "ROTATED",
        "gate": "scope",
        "rotation_basis": "scope_ineligible",
        "reason": "Current scope excludes the exact asset.",
        "evidence": copy.deepcopy(target["scope"]["evidence"]),
    })
    assert not target_errors(target), target_errors(target)


def test_campaign_is_optional_and_small() -> None:
    campaign = valid_campaign()
    assert not campaign_errors(campaign)
    assert set(campaign) == {
        "schema_version", "campaign_id", "target_id", "mode",
        "status", "stop_condition", "hypotheses",
    }
    assert set(campaign["hypotheses"][0]) == {
        "hypothesis_id", "boundary", "statement", "priority", "status",
        "candidate_id", "verdict", "reason",
    }


def test_closed_campaign_cannot_have_investigating_work() -> None:
    campaign = valid_campaign()
    campaign["status"] = "closed"
    assert any("cannot contain investigating" in error for error in campaign_errors(campaign))


def test_first_finding_closure_requires_reportable() -> None:
    campaign = valid_campaign()
    campaign["mode"] = "first_finding"
    campaign["status"] = "closed"
    campaign["hypotheses"][0].update({
        "status": "closed",
        "candidate_id": "C-001",
        "verdict": "KILL",
        "reason": "Invariant held.",
    })
    assert any("requires a REPORTABLE" in error for error in campaign_errors(campaign))


def test_exhaustive_closure_requires_every_hypothesis_closed() -> None:
    campaign = valid_campaign()
    campaign["mode"] = "exhaustive"
    campaign["status"] = "closed"
    campaign["hypotheses"][0].update({
        "status": "closed",
        "candidate_id": "C-001",
        "verdict": "KILL",
        "reason": "Invariant held.",
    })
    assert any("every hypothesis closed" in error for error in campaign_errors(campaign))


def test_default_start_candidate_needs_no_campaign() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        target_path = root / "target.json"
        output = root / "candidate.json"
        target_path.write_text(json.dumps(valid_target()), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(HERE / "start_candidate.py"),
                "--target-ledger", str(target_path),
                "--candidate-id", "C-default",
                "--template", str(ROOT / "assets" / "candidate.template.json"),
                "--output", str(output),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        candidate = json.loads(output.read_text(encoding="utf-8"))
        assert candidate["campaign_id"] is None
        assert candidate["hypothesis_id"] is None


def test_campaign_start_requires_open_investigating_hypothesis() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        target_path = root / "target.json"
        campaign_path = root / "campaign.json"
        target_path.write_text(json.dumps(valid_target()), encoding="utf-8")

        campaign = valid_campaign()
        campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
        output = root / "candidate.json"
        ok = subprocess.run(
            [
                sys.executable, str(HERE / "start_candidate.py"),
                "--target-ledger", str(target_path),
                "--campaign-ledger", str(campaign_path),
                "--hypothesis-id", "H-001",
                "--candidate-id", "C-001",
                "--template", str(ROOT / "assets" / "candidate.template.json"),
                "--output", str(output),
            ],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert ok.returncode == 0, ok.stderr

        closed = valid_campaign()
        closed["status"] = "closed"
        closed["hypotheses"][0].update({
            "status": "closed", "candidate_id": "C-old",
            "verdict": "REPORTABLE", "reason": "Found one.",
        })
        campaign_path.write_text(json.dumps(closed), encoding="utf-8")
        blocked = subprocess.run(
            [
                sys.executable, str(HERE / "start_candidate.py"),
                "--target-ledger", str(target_path),
                "--campaign-ledger", str(campaign_path),
                "--hypothesis-id", "H-002",
                "--candidate-id", "C-002",
                "--template", str(ROOT / "assets" / "candidate.template.json"),
                "--output", str(root / "candidate-2.json"),
            ],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert blocked.returncode != 0
        assert "campaign.status open" in blocked.stderr


def main() -> int:
    tests = [
        test_lean_target_accepts_without_campaign_metadata,
        test_target_selection_requires_live_scope_and_proof_policy,
        test_scope_rotation_can_happen_without_campaign_modeling,
        test_campaign_is_optional_and_small,
        test_closed_campaign_cannot_have_investigating_work,
        test_first_finding_closure_requires_reportable,
        test_exhaustive_closure_requires_every_hypothesis_closed,
        test_default_start_candidate_needs_no_campaign,
        test_campaign_start_requires_open_investigating_hypothesis,
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
    print(f"{len(tests) - failed}/{len(tests)} target/campaign groups passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
