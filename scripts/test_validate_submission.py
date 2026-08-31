#!/usr/bin/env python3
"""Focused acceptance tests for the v0.8 submission boundary.

These tests are intentionally written before the implementation.  They model
the final handoff as files on disk rather than as an embedded report string:
the report, candidate, and every attachment must be the exact bytes reviewed.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from hunt_validation.submission import (  # noqa: E402
    sha256_file,
    validate_candidate_review_sidecar,
    validate_submission,
    validate_submission_review_sidecar,
)


NOW = datetime.now(UTC).replace(microsecond=0)


def stamp(*, minutes_ago: int = 0, days_ago: int = 0, minutes_ahead: int = 0) -> str:
    value = NOW - timedelta(days=days_ago, minutes=minutes_ago) + timedelta(minutes=minutes_ahead)
    return value.isoformat().replace("+00:00", "Z")


STAMP = stamp(minutes_ago=60)


def write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evidence(name: str) -> dict[str, str]:
    return {"method": "live_connector", "source": f"live:{name}", "artifact": f"evidence/{name}.json"}


def candidate_document() -> dict:
    return {
        "schema_version": 6,
        "candidate_id": "C-001",
        "campaign_id": "campaign-example-2026-08",
        "target": {"asset": "Example API", "commit": "1.4.2"},
        "claim_scope": {
            "highest_proven_rung": "demonstrated_impact",
            "demonstrated_capability": "read another tenant's report",
            "demonstrated_impact": "confidentiality of another tenant's report",
            "unsupported_extensions": [],
            "severity_ceiling": "high",
        },
        "decision": {"verdict": "REPORTABLE", "decided_at": stamp(minutes_ago=65)},
    }


def _file_ref(path: Path, base: Path) -> dict[str, str]:
    return {"path": str(path.relative_to(base)), "sha256": digest(path)}


def fixture() -> tuple[Path, dict, dict]:
    root = Path(tempfile.mkdtemp(prefix="submission-fixture-"))
    candidate_path = root / "candidate.json"
    report_path = root / "report.md"
    attachment_path = root / "proof" / "transcript.txt"
    write(candidate_path, json.dumps(candidate_document(), indent=2) + "\n")
    write(
        report_path,
        "# Cross-tenant report read through export endpoint\n\n"
        "Run `python3 proof/reproduce.py` and compare the captured `transcript.txt`.\n",
    )
    write(attachment_path, "control: tenant A denied\nexploit: tenant B canary returned\n")

    submission = {
        "schema_version": 1,
        "submission_id": "S-001",
        "campaign_id": "campaign-example-2026-08",
        "candidate_id": "C-001",
        "asset": "Example API",
        "version": "1.4.2",
        "title": "Cross-tenant report read through export endpoint",
        "weakness": "CWE-639",
        "severity": "high",
        "cvss": {
            "score": 8.1,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        },
        "demonstrated": {
            "capability": "read another tenant's report",
            "impact": "confidentiality of another tenant's report",
        },
        "reproduction": {"commands": ["python3 proof/reproduce.py"]},
        "report": _file_ref(report_path, root),
        "attachments": [{**_file_ref(attachment_path, root), "role": "control-and-exploit-transcript"}],
        "preflight": {
            "scope": {"status": "eligible", "asset_identifier": "Example API", "checked_at": STAMP, "evidence": evidence("scope")},
            "proof_policy": {"status": "accepted", "accepted_proof_type": "executable-local-exact-path", "checked_at": STAMP, "evidence": evidence("proof-policy")},
        },
        "candidate_artifact": _file_ref(candidate_path, root),
        "prepared_at": stamp(minutes_ago=30),
    }
    return root, submission, {"candidate": candidate_path, "report": report_path, "attachment": attachment_path}


def candidate_review(root: Path, paths: dict[str, Path]) -> dict:
    candidate = paths["candidate"]
    return {
        "schema_version": 1,
        "review_type": "candidate",
        "reviewer": {
            "mode": "independent_agent",
            "id": "reviewer-session-1",
            "reviewed_at": STAMP,
            "fresh_context": True,
        },
        "verdict": "REPORTABLE",
        "candidate": _file_ref(candidate, root),
    }


def submission_review(root: Path, submission_path: Path, paths: dict[str, Path], submission: dict) -> dict:
    return {
        "schema_version": 1,
        "review_type": "submission",
        "reviewer": {
            "mode": "independent_agent",
            "id": "submission-reviewer-1",
            "reviewed_at": stamp(minutes_ago=15),
            "fresh_context": True,
        },
        "verdict": "SUBMISSION_READY",
        "submission": _file_ref(submission_path, root),
        "candidate": _file_ref(paths["candidate"], root),
        "report": _file_ref(paths["report"], root),
        "attachments": [
            {**_file_ref(paths["attachment"], root), "role": submission["attachments"][0]["role"]}
        ],
    }


def errors_for_submission(root: Path, submission: dict) -> list[str]:
    errors: list[str] = []
    validate_submission(submission, root / "submission.json", errors, now=NOW)
    return errors


def test_valid_submission_and_generic_reviews() -> None:
    root, submission, paths = fixture()
    submission_path = root / "submission.json"
    write(submission_path, json.dumps(submission, indent=2) + "\n")
    assert sha256_file(paths["report"]) == digest(paths["report"])
    assert not errors_for_submission(root, submission)

    candidate_errors: list[str] = []
    validate_candidate_review_sidecar(
        candidate_review(root, paths), root / "candidate-review.json", candidate_errors,
        candidate_path=paths["candidate"], now=NOW,
    )
    assert not candidate_errors, candidate_errors

    killed = candidate_document()
    killed["decision"]["verdict"] = "KILL"
    write(paths["candidate"], json.dumps(killed, indent=2) + "\n")
    killed_review = candidate_review(root, paths)
    killed_review["verdict"] = "KILL"
    killed_errors: list[str] = []
    validate_candidate_review_sidecar(
        killed_review, root / "candidate-review.json", killed_errors,
        candidate_path=paths["candidate"], now=NOW,
    )
    assert not killed_errors, killed_errors

    write(paths["candidate"], json.dumps(candidate_document(), indent=2) + "\n")

    review_errors: list[str] = []
    validate_submission_review_sidecar(
        submission_review(root, submission_path, paths, submission),
        root / "submission-review.json",
        review_errors,
        submission=submission,
        submission_path=submission_path,
        now=NOW,
    )
    assert not review_errors, review_errors


def test_byte_drift_and_missing_attachment_are_rejected() -> None:
    root, submission, paths = fixture()
    write(root / "submission.json", json.dumps(submission, indent=2) + "\n")

    paths["report"].write_text(paths["report"].read_text(encoding="utf-8") + "drift\n", encoding="utf-8")
    errors = errors_for_submission(root, submission)
    assert any("report" in error and "sha-256" in error for error in errors), errors

    paths["attachment"].unlink()
    errors = errors_for_submission(root, submission)
    assert any("attachment" in error and "not found" in error for error in errors), errors


def test_candidate_scope_and_report_interface_are_enforced() -> None:
    root, submission, paths = fixture()
    write(root / "submission.json", json.dumps(submission, indent=2) + "\n")

    overclaim = copy.deepcopy(submission)
    overclaim["impact"] = "full database takeover"
    overclaim["demonstrated"]["impact"] = "full database takeover"
    assert any("claim_scope" in error for error in errors_for_submission(root, overclaim)), errors_for_submission(root, overclaim)

    malformed = copy.deepcopy(submission)
    malformed.pop("report")
    malformed["body"] = "embedded body must not replace report.md"
    errors = errors_for_submission(root, malformed)
    assert any("report" in error and "required" in error for error in errors), errors


def test_compact_v08_claim_scope_binds_capability_impact_and_severity() -> None:
    root, submission, paths = fixture()
    compact = candidate_document()
    write(paths["candidate"], json.dumps(compact, indent=2) + "\n")
    submission["candidate_artifact"]["sha256"] = digest(paths["candidate"])
    write(root / "submission.json", json.dumps(submission, indent=2) + "\n")
    assert not errors_for_submission(root, submission)

    narrower = copy.deepcopy(submission)
    narrower["severity"] = "critical"
    errors = errors_for_submission(root, narrower)
    assert any("severity exceeds candidate.claim_scope" in error for error in errors), errors


def test_preflight_and_review_temporal_gates_are_strict() -> None:
    root, submission, paths = fixture()
    write(root / "submission.json", json.dumps(submission, indent=2) + "\n")

    future = copy.deepcopy(submission)
    future["preflight"]["scope"]["checked_at"] = stamp(minutes_ahead=10)
    assert any("future" in error for error in errors_for_submission(root, future)), errors_for_submission(root, future)

    stale = copy.deepcopy(submission)
    stale["preflight"]["scope"]["checked_at"] = stamp(days_ago=100)
    assert any("stale" in error for error in errors_for_submission(root, stale)), errors_for_submission(root, stale)

    review = submission_review(root, root / "submission.json", paths, submission)
    review["reviewer"]["reviewed_at"] = stamp(minutes_ago=45)
    review_errors: list[str] = []
    validate_submission_review_sidecar(
        review, root / "submission-review.json", review_errors,
        submission=submission, submission_path=root / "submission.json", now=NOW,
    )
    assert any("after prepared_at" in error for error in review_errors), review_errors

    review["reviewer"]["reviewed_at"] = stamp(minutes_ahead=10)
    review_errors = []
    validate_submission_review_sidecar(
        review, root / "submission-review.json", review_errors,
        submission=submission, submission_path=root / "submission.json", now=NOW,
    )
    assert any("future" in error for error in review_errors), review_errors


def test_submission_review_binds_every_digest() -> None:
    root, submission, paths = fixture()
    submission_path = root / "submission.json"
    write(submission_path, json.dumps(submission, indent=2) + "\n")
    review = submission_review(root, submission_path, paths, submission)
    review["candidate"]["sha256"] = "0" * 64
    errors: list[str] = []
    validate_submission_review_sidecar(
        review, root / "submission-review.json", errors,
        submission=submission, submission_path=submission_path, now=NOW,
    )
    assert any("candidate" in error and "sha-256" in error for error in errors), errors


def test_start_submission_creates_self_contained_bundle() -> None:
    root, _submission, paths = fixture()
    candidate = candidate_document()
    write(paths["candidate"], json.dumps(candidate, indent=2) + "\n")
    candidate_review_path = root / "candidate-review.json"
    write(candidate_review_path, json.dumps(candidate_review(root, paths), indent=2) + "\n")
    output = root / "bundle" / "submission.json"
    result = subprocess.run(
        [
            sys.executable, str(HERE / "start_submission.py"),
            "--candidate", str(paths["candidate"]),
            "--candidate-review", str(candidate_review_path),
            "--report", str(paths["report"]),
            "--output", str(output),
            "--submission-id", "S-001",
            "--title", "Cross-tenant report read through export endpoint",
            "--weakness", "CWE-639",
            "--severity", "high",
            "--cvss-score", "8.1",
            "--cvss-vector", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "--command", "python3 attachments/reproduce.py",
            "--attachment", f"{paths['attachment']}=control-and-exploit-transcript",
        ],
        cwd=HERE.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "SUBMISSION BUNDLE CREATED" in result.stdout, result.stdout
    created = json.loads(output.read_text(encoding="utf-8"))
    assert created["candidate_artifact"]["path"] == "candidate.json"
    assert created["report"]["path"] == "report.md"
    assert (output.parent / created["attachments"][0]["path"]).is_file()
    assert (output.parent / "candidate-review.json").is_file()


def test_start_submission_missing_attachment_leaves_existing_files_unchanged() -> None:
    root, _submission, paths = fixture()
    candidate_review_path = root / "candidate-review.json"
    write(candidate_review_path, json.dumps(candidate_review(root, paths), indent=2) + "\n")
    bundle = root / "bundle"
    write(bundle / "candidate.json", "sentinel candidate\n")
    write(bundle / "report.md", "sentinel report\n")
    write(bundle / "candidate-review.json", "sentinel review\n")
    result = subprocess.run(
        [
            sys.executable, str(HERE / "start_submission.py"),
            "--candidate", str(paths["candidate"]), "--candidate-review", str(candidate_review_path),
            "--report", str(paths["report"]), "--output", str(bundle / "submission.json"),
            "--submission-id", "S-002", "--title", "Example", "--weakness", "CWE-20",
            "--severity", "low", "--cvss-score", "3.1", "--cvss-vector", "CVSS:3.1/example",
            "--command", "python3 reproduce.py",
            "--attachment", f"{root / 'missing.txt'}=transcript",
        ],
        cwd=HERE.parent, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2, result.stderr
    assert (bundle / "candidate.json").read_text(encoding="utf-8") == "sentinel candidate\n"
    assert (bundle / "report.md").read_text(encoding="utf-8") == "sentinel report\n"
    assert (bundle / "candidate-review.json").read_text(encoding="utf-8") == "sentinel review\n"
    assert not (bundle / "submission.json").exists()


def main() -> int:
    tests = [
        test_valid_submission_and_generic_reviews,
        test_byte_drift_and_missing_attachment_are_rejected,
        test_candidate_scope_and_report_interface_are_enforced,
        test_compact_v08_claim_scope_binds_capability_impact_and_severity,
        test_preflight_and_review_temporal_gates_are_strict,
        test_submission_review_binds_every_digest,
        test_start_submission_creates_self_contained_bundle,
        test_start_submission_missing_attachment_leaves_existing_files_unchanged,
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
    print(f"{len(tests) - failed}/{len(tests)} submission test groups passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
