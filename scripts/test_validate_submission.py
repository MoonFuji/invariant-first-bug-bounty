#!/usr/bin/env python3
"""Regression tests for the minimal schema-2 final bundle and one exact final review."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hunt_validation.common import sha256_file
from hunt_validation.submission import validate_final_review, validate_submission
from test_fixtures import evidence, report_for, valid_candidate, valid_target


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
NOW = datetime.now(UTC).replace(microsecond=0)


def stamp(*, minutes_ago: int = 0, days_ago: int = 0, minutes_ahead: int = 0) -> str:
    value = NOW - timedelta(days=days_ago, minutes=minutes_ago) + timedelta(minutes=minutes_ahead)
    return value.isoformat().replace("+00:00", "Z")


def file_ref(path: Path, root: Path) -> dict[str, str]:
    return {"path": str(path.relative_to(root)), "sha256": sha256_file(path)}


def fixture() -> tuple[Path, dict, dict, dict[str, Path]]:
    root = Path(tempfile.mkdtemp(prefix="ibb-submission-"))
    candidate = valid_candidate()
    target = valid_target()
    candidate_path = root / "candidate.json"
    report_path = root / "report.md"
    attachment = root / "attachments" / "transcript.txt"
    attachment.parent.mkdir(parents=True, exist_ok=True)
    candidate_path.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
    report_path.write_text(report_for(candidate) + "\nAttachment: transcript.txt\n", encoding="utf-8")
    attachment.write_text("control denied\nexploit returned canary\n", encoding="utf-8")
    submission = {
        "schema_version": 2,
        "submission_id": "S-001",
        "candidate_id": candidate["candidate_id"],
        "target_id": target["target_id"],
        "files": {
            "candidate": file_ref(candidate_path, root),
            "report": file_ref(report_path, root),
            "attachments": [{**file_ref(attachment, root), "role": "control-and-exploit-transcript"}],
        },
        "preflight": {
            "scope": {
                "status": "eligible",
                "asset_identifier": target["scope"]["asset_identifier"],
                "max_severity": "high",
                "checked_at": stamp(minutes_ago=30),
                "evidence": evidence("final-scope"),
            },
            "proof_policy": {
                "status": "checked",
                "accepted_proof_types": ["executable-local-exact-path"],
                "checked_at": stamp(minutes_ago=30),
                "evidence": evidence("final-proof-policy"),
            },
        },
        "prepared_at": stamp(minutes_ago=20),
    }
    submission_path = root / "submission.json"
    submission_path.write_text(json.dumps(submission, indent=2) + "\n", encoding="utf-8")
    paths = {
        "candidate": candidate_path,
        "report": report_path,
        "attachment": attachment,
        "submission": submission_path,
    }
    return root, target, candidate, submission, paths


def final_review(root: Path, submission: dict, paths: dict[str, Path]) -> dict:
    return {
        "schema_version": 2,
        "review_type": "final_submission",
        "reviewer": {
            "mode": "independent_agent",
            "id": "fresh-review-session",
            "reviewed_at": stamp(minutes_ago=10),
            "fresh_context": True,
        },
        "verdict": "SUBMISSION_READY",
        "submission": file_ref(paths["submission"], root),
        "candidate": submission["files"]["candidate"],
        "report": submission["files"]["report"],
        "attachments": submission["files"]["attachments"],
    }


def submission_errors(root: Path, target: dict, candidate: dict, submission: dict) -> list[str]:
    errors: list[str] = []
    validate_submission(submission, root / "submission.json", candidate, target, errors, now=NOW)
    return errors


def test_minimal_bundle_accepts_without_duplicate_semantic_fields() -> None:
    root, target, candidate, submission, paths = fixture()
    assert set(submission).isdisjoint({"title", "weakness", "severity", "cvss", "demonstrated", "reproduction"})
    assert not submission_errors(root, target, candidate, submission)


def test_report_must_carry_bounded_candidate_claim() -> None:
    root, target, candidate, submission, paths = fixture()
    text = paths["report"].read_text(encoding="utf-8").replace(candidate["claim"]["impact"], "different impact")
    paths["report"].write_text(text, encoding="utf-8")
    submission["files"]["report"]["sha256"] = sha256_file(paths["report"])
    errors = submission_errors(root, target, candidate, submission)
    assert any("candidate.claim.impact" in error for error in errors), errors


def test_report_and_attachment_byte_drift_are_rejected() -> None:
    root, target, candidate, submission, paths = fixture()
    paths["report"].write_text(paths["report"].read_text(encoding="utf-8") + "drift\n", encoding="utf-8")
    errors = submission_errors(root, target, candidate, submission)
    assert any("report" in error and "sha-256" in error for error in errors), errors

    root, target, candidate, submission, paths = fixture()
    paths["attachment"].write_text("drift", encoding="utf-8")
    errors = submission_errors(root, target, candidate, submission)
    assert any("attachment" in error and "sha-256" in error for error in errors), errors


def test_fresh_preflight_owns_current_severity_cap() -> None:
    root, target, candidate, submission, paths = fixture()
    # The long-lived target may still say high. The final live preflight now says low.
    submission["preflight"]["scope"]["max_severity"] = "low"
    errors = submission_errors(root, target, candidate, submission)
    assert any("fresh submission scope.max_severity" in error for error in errors), errors


def test_preflight_must_be_recent() -> None:
    root, target, candidate, submission, paths = fixture()
    submission["preflight"]["scope"]["checked_at"] = stamp(days_ago=8)
    errors = submission_errors(root, target, candidate, submission)
    assert any("stale" in error for error in errors), errors


def test_hosted_proof_uses_policy_vocabulary_mapping() -> None:
    root, target, candidate, submission, paths = fixture()
    target["operating_mode"] = "PROGRAM_HOSTED"
    target["proof_policy"]["accepted_proof_types"] = ["program-hosted-owned-account"]
    candidate["target"]["operating_mode"] = "PROGRAM_HOSTED"
    candidate["proof"]["type"] = "live-two-identity"
    from hunt_validation.target import target_fingerprint
    candidate["target_fingerprint"] = target_fingerprint(target)
    paths["candidate"].write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
    submission["files"]["candidate"]["sha256"] = sha256_file(paths["candidate"])
    submission["preflight"]["proof_policy"]["accepted_proof_types"] = ["program-hosted-owned-account"]
    assert not submission_errors(root, target, candidate, submission), submission_errors(root, target, candidate, submission)


def test_one_final_review_binds_all_exact_files() -> None:
    root, target, candidate, submission, paths = fixture()
    review = final_review(root, submission, paths)
    errors: list[str] = []
    validate_final_review(review, root / "final-review.json", submission, paths["submission"], errors, now=NOW)
    assert not errors, errors

    review["report"]["sha256"] = "0" * 64
    errors = []
    validate_final_review(review, root / "final-review.json", submission, paths["submission"], errors, now=NOW)
    assert any("report" in error and ("sha-256" in error or "exactly match" in error) for error in errors), errors


def test_negative_final_review_never_produces_ready_state() -> None:
    root, target, candidate, submission, paths = fixture()
    review = final_review(root, submission, paths)
    review["verdict"] = "NOT_READY"
    errors: list[str] = []
    validate_final_review(review, root / "final-review.json", submission, paths["submission"], errors, now=NOW)
    assert any("affirm SUBMISSION_READY" in error for error in errors), errors


def test_start_submission_creates_small_non_destructive_bundle() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        candidate = valid_candidate()
        candidate_path = root / "source-candidate.json"
        report_path = root / "source-report.md"
        candidate_path.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
        report_path.write_text(report_for(candidate), encoding="utf-8")
        output = root / "bundle" / "submission.json"
        result = subprocess.run(
            [
                sys.executable, str(HERE / "start_submission.py"),
                "--candidate", str(candidate_path),
                "--report", str(report_path),
                "--output", str(output),
                "--submission-id", "S-002",
            ],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr
        created = json.loads(output.read_text(encoding="utf-8"))
        assert set(created).isdisjoint({"title", "cvss", "severity", "demonstrated"})
        assert (output.parent / "candidate.json").is_file()
        assert (output.parent / "report.md").is_file()

        again = subprocess.run(
            [
                sys.executable, str(HERE / "start_submission.py"),
                "--candidate", str(candidate_path),
                "--report", str(report_path),
                "--output", str(output),
                "--submission-id", "S-003",
            ],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert again.returncode != 0
        assert "refusing to overwrite" in again.stderr


def main() -> int:
    tests = [
        test_minimal_bundle_accepts_without_duplicate_semantic_fields,
        test_report_must_carry_bounded_candidate_claim,
        test_report_and_attachment_byte_drift_are_rejected,
        test_fresh_preflight_owns_current_severity_cap,
        test_preflight_must_be_recent,
        test_hosted_proof_uses_policy_vocabulary_mapping,
        test_one_final_review_binds_all_exact_files,
        test_negative_final_review_never_produces_ready_state,
        test_start_submission_creates_small_non_destructive_bundle,
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
    print(f"{len(tests) - failed}/{len(tests)} submission groups passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
