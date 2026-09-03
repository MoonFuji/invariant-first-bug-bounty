#!/usr/bin/env python3
"""Command-line smoke coverage for the simplified default and campaign flows."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hunt_validation.common import sha256_file
from test_fixtures import evidence, report_for, valid_campaign, valid_candidate, valid_target


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
VALIDATE = HERE / "validate_hunt.py"
START_CANDIDATE = HERE / "start_candidate.py"
START_SUBMISSION = HERE / "start_submission.py"


def run(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *[str(arg) for arg in args]],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def assert_ok(result: subprocess.CompletedProcess[str], marker: str) -> None:
    assert result.returncode == 0, result.stderr
    assert marker in result.stdout, result.stdout


def stamp(minutes_ago: int) -> str:
    return (
        datetime.now(UTC) - timedelta(minutes=minutes_ago)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main() -> int:
    checks = 0
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        target = valid_target()
        target_path = root / "target.json"
        target_path.write_text(json.dumps(target, indent=2) + "\n", encoding="utf-8")

        result = run(VALIDATE, "--stage", "target", target_path)
        assert_ok(result, "TARGET SELECTED")
        checks += 1

        # Default mode is intentionally campaign-free.
        candidate_path = root / "C-001.json"
        result = run(
            START_CANDIDATE,
            "--target-ledger", target_path,
            "--candidate-id", "C-001",
            "--template", ROOT / "assets" / "candidate.template.json",
            "--output", candidate_path,
        )
        assert_ok(result, "Default mode")
        generated = json.loads(candidate_path.read_text(encoding="utf-8"))
        assert generated["campaign_id"] is None
        checks += 1

        # Use a complete synthetic candidate for the readiness gate.
        candidate = valid_candidate()
        candidate_path.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
        result = run(
            VALIDATE,
            "--stage", "report",
            "--target-ledger", target_path,
            candidate_path,
        )
        assert_ok(result, "CANDIDATE READY TO DRAFT")
        checks += 1

        report_path = root / "report-source.md"
        report_path.write_text(report_for(candidate), encoding="utf-8")
        submission_path = root / "bundle" / "submission.json"
        result = run(
            START_SUBMISSION,
            "--candidate", candidate_path,
            "--report", report_path,
            "--output", submission_path,
            "--submission-id", "S-001",
        )
        assert_ok(result, "SUBMISSION BUNDLE CREATED")
        checks += 1

        submission = json.loads(submission_path.read_text(encoding="utf-8"))
        submission["preflight"]["scope"].update({
            "status": "eligible",
            "asset_identifier": target["scope"]["asset_identifier"],
            "max_severity": "high",
            "checked_at": stamp(3),
            "evidence": evidence("final-scope"),
        })
        submission["preflight"]["proof_policy"].update({
            "status": "checked",
            "accepted_proof_types": ["executable-local-exact-path"],
            "checked_at": stamp(3),
            "evidence": evidence("final-policy"),
        })
        submission["prepared_at"] = stamp(2)
        submission_path.write_text(json.dumps(submission, indent=2) + "\n", encoding="utf-8")

        bundle = submission_path.parent
        review_path = bundle / "final-review.json"
        review = {
            "schema_version": 2,
            "review_type": "final_submission",
            "reviewer": {
                "mode": "independent_agent",
                "id": "fresh-cli-review",
                "reviewed_at": stamp(1),
                "fresh_context": True,
            },
            "verdict": "SUBMISSION_READY",
            "submission": {"path": "submission.json", "sha256": sha256_file(submission_path)},
            "candidate": submission["files"]["candidate"],
            "report": submission["files"]["report"],
            "attachments": submission["files"]["attachments"],
        }
        review_path.write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8")

        result = run(
            VALIDATE,
            "--stage", "submission",
            "--target-ledger", target_path,
            "--candidate", bundle / "candidate.json",
            "--final-review", review_path,
            submission_path,
        )
        assert_ok(result, "SUBMISSION READY FOR FINAL CHECK")
        checks += 1

        # Fresh live scope must be able to lower a stale campaign-time cap.
        submission["preflight"]["scope"]["max_severity"] = "low"
        submission_path.write_text(json.dumps(submission, indent=2) + "\n", encoding="utf-8")
        review["submission"]["sha256"] = sha256_file(submission_path)
        review_path.write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8")
        blocked = run(
            VALIDATE,
            "--stage", "submission",
            "--target-ledger", target_path,
            "--candidate", bundle / "candidate.json",
            "--final-review", review_path,
            submission_path,
        )
        assert blocked.returncode != 0
        assert "fresh submission scope.max_severity" in blocked.stderr
        checks += 1

        # Campaign mode is opt-in and validates independently.
        campaign = valid_campaign()
        campaign_path = root / "campaign.json"
        campaign_path.write_text(json.dumps(campaign, indent=2) + "\n", encoding="utf-8")
        result = run(
            VALIDATE,
            "--stage", "campaign",
            "--target-ledger", target_path,
            campaign_path,
        )
        assert_ok(result, "CAMPAIGN READY")
        checks += 1

        closed = valid_campaign()
        closed["status"] = "closed"
        closed["hypotheses"][0].update({
            "status": "closed",
            "candidate_id": "C-old",
            "verdict": "REPORTABLE",
            "reason": "First finding completed.",
        })
        closed["hypotheses"][1]["status"] = "queued"
        closed["mode"] = "first_finding"
        campaign_path.write_text(json.dumps(closed, indent=2) + "\n", encoding="utf-8")
        result = run(
            START_CANDIDATE,
            "--target-ledger", target_path,
            "--campaign-ledger", campaign_path,
            "--hypothesis-id", "H-002",
            "--candidate-id", "C-002",
            "--template", ROOT / "assets" / "candidate.template.json",
            "--output", root / "C-002.json",
        )
        assert result.returncode != 0
        assert "campaign.status open" in result.stderr
        checks += 1

    print(f"{checks}/{checks} CLI workflow checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
