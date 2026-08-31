#!/usr/bin/env python3
"""Exercise the public target-bound command-line entry points.

The unit-style regression suite imports validator functions directly. These
smoke tests make sure the documented wrappers keep enforcing the boundary:
candidate stages require a target ledger, incomplete ledgers cannot generate a
candidate, and failures do not leave a misleading output artifact behind.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hunt_validation.common import sha256_file
from hunt_validation.target import target_fingerprint
from test_validate_campaign import target as valid_target
from test_validate_candidate import baseline_v6

ROOT = Path(__file__).resolve().parents[1]
VALIDATE = ROOT / "scripts" / "validate_hunt.py"
LEGACY_VALIDATE = ROOT / "scripts" / "validate-candidate.py"
START = ROOT / "scripts" / "start_candidate.py"
START_SUBMISSION = ROOT / "scripts" / "start_submission.py"
TARGET_TEMPLATE = ROOT / "assets" / "target.template.json"
CANDIDATE_TEMPLATE = ROOT / "assets" / "candidate.template.json"


def run(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *(str(arg) for arg in args)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def require(
    condition: bool,
    message: str,
    process: subprocess.CompletedProcess[str] | None = None,
) -> None:
    if condition:
        return
    detail = ""
    if process is not None:
        detail = (
            f"\nreturncode={process.returncode}"
            f"\nstdout={process.stdout.strip()}"
            f"\nstderr={process.stderr.strip()}"
        )
    raise AssertionError(message + detail)


def main() -> int:
    checks = 0

    legacy = run(LEGACY_VALIDATE, CANDIDATE_TEMPLATE, "--stage", "report")
    require(
        legacy.returncode == 2
        and "import-only" in legacy.stderr
        and "REPORT READY" not in legacy.stdout,
        "legacy candidate CLI must fail closed and direct callers to validate_hunt.py",
        legacy,
    )
    checks += 1

    help_result = run(VALIDATE, "--help")
    require(help_result.returncode == 0, "validate_hunt --help failed", help_result)
    require(
        "--target-ledger" in help_result.stdout,
        "wrapper help omitted --target-ledger",
        help_result,
    )
    checks += 1

    no_ledger = run(VALIDATE, "--stage", "model", CANDIDATE_TEMPLATE)
    require(
        no_ledger.returncode != 0,
        "candidate model stage accepted no target ledger",
        no_ledger,
    )
    checks += 1

    incomplete_target = run(VALIDATE, "--stage", "target", TARGET_TEMPLATE)
    require(
        incomplete_target.returncode != 0,
        "blank target template validated as selected",
        incomplete_target,
    )
    checks += 1

    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "candidate.json"
        start_result = run(
            START,
            "--target-ledger",
            TARGET_TEMPLATE,
            "--output",
            output,
        )
        require(
            start_result.returncode != 0,
            "candidate generated from an incomplete target",
            start_result,
        )
        require(
            not output.exists(),
            "failed candidate generation left an output artifact",
            start_result,
        )
        checks += 1

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        target = valid_target()
        target_path = root / "target.json"
        target_path.write_text(json.dumps(target, indent=2) + "\n", encoding="utf-8")

        candidate = baseline_v6()
        candidate.update({
            "candidate_id": "candidate-001",
            "target_ledger_id": target["target_id"],
            "campaign_id": target["campaign"]["campaign_id"],
            "target_fingerprint": target_fingerprint(target),
            "boundary_id": "B-001",
            "hypothesis_id": "H-001",
        })
        candidate["target"].update({
            key: target[key]
            for key in ("platform", "route_type", "asset_type", "program", "asset", "repository", "commit", "operating_mode")
        })
        candidate["target"]["scope_checked_at"] = target["scope"]["checked_at"]
        candidate["target"]["scope_evidence"] = "live:scope (artifacts/scope.json)"
        candidate["hardening"]["completed_at"] = "2026-08-30T11:00:00Z"
        candidate["decision"]["decided_at"] = "2026-08-30T11:05:00Z"
        candidate_path = root / "candidate-source.json"
        candidate_path.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
        target["hypothesis_lifecycle"][0].update({
            "status": "closed",
            "candidate_id": candidate["candidate_id"],
            "candidate_sha256": sha256_file(candidate_path),
            "terminal_verdict": "REPORTABLE",
            "closed_at": "2026-08-30T11:06:00Z",
            "evidence": "candidate-source.json",
        })
        target_path.write_text(json.dumps(target, indent=2) + "\n", encoding="utf-8")
        candidate_review_path = root / "candidate-review.json"
        candidate_review = {
            "schema_version": 1,
            "review_type": "candidate",
            "reviewer": {
                "mode": "independent_agent", "id": "reviewer-cli-1",
                "reviewed_at": "2026-08-30T11:10:00Z", "fresh_context": True,
            },
            "verdict": "REPORTABLE",
            "candidate": {"path": "candidate-source.json", "sha256": sha256_file(candidate_path)},
        }
        candidate_review_path.write_text(json.dumps(candidate_review, indent=2) + "\n", encoding="utf-8")

        report_result = run(
            VALIDATE, "--stage", "report", "--target-ledger", target_path,
            "--candidate-review", candidate_review_path, candidate_path,
        )
        require(
            report_result.returncode == 0 and "CANDIDATE REPORTABLE" in report_result.stdout,
            "report stage did not require and honor the exact candidate review",
            report_result,
        )
        checks += 1

        report_path = root / "draft.md"
        report_path.write_text(
            "# Bounded cross-tenant report read\n\nRun `python3 reproduce.py`.\n",
            encoding="utf-8",
        )
        bundle = root / "bundle"
        submission_path = bundle / "submission.json"
        start = run(
            START_SUBMISSION,
            "--candidate", candidate_path,
            "--candidate-review", candidate_review_path,
            "--report", report_path,
            "--output", submission_path,
            "--submission-id", "submission-001",
            "--title", "Bounded cross-tenant report read",
            "--weakness", "CWE-639",
            "--severity", "high",
            "--cvss-score", "8.1",
            "--cvss-vector", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "--command", "python3 reproduce.py",
        )
        require(start.returncode == 0, "start_submission did not create the bundle", start)
        submission = json.loads(submission_path.read_text(encoding="utf-8"))
        now = datetime.now(UTC)
        checked = (now - timedelta(minutes=3)).isoformat()
        prepared = (now - timedelta(minutes=2)).isoformat()
        reviewed = (now - timedelta(minutes=1)).isoformat()
        submission["preflight"]["scope"].update({
            "status": "eligible", "asset_identifier": target["scope"]["asset_identifier"],
            "checked_at": checked, "evidence": {"method": "connector", "source": "live:scope", "artifact": "evidence/scope.json"},
        })
        submission["preflight"]["proof_policy"].update({
            "status": "accepted", "accepted_proof_type": candidate["proof"]["type"],
            "checked_at": checked, "evidence": {"method": "connector", "source": "live:policy", "artifact": "evidence/policy.json"},
        })
        submission["prepared_at"] = prepared
        submission_path.write_text(json.dumps(submission, indent=2) + "\n", encoding="utf-8")

        bundled_candidate = bundle / "candidate.json"
        bundled_candidate_review_path = bundle / "candidate-review.json"
        bundled_candidate_review = {
            **candidate_review,
            "candidate": {"path": "candidate.json", "sha256": sha256_file(bundled_candidate)},
        }
        bundled_candidate_review_path.write_text(json.dumps(bundled_candidate_review, indent=2) + "\n", encoding="utf-8")
        submission_review_path = bundle / "submission-review.json"
        submission_review = {
            "schema_version": 1,
            "review_type": "submission",
            "reviewer": {
                "mode": "independent_agent", "id": "reviewer-cli-2",
                "reviewed_at": reviewed, "fresh_context": True,
            },
            "verdict": "SUBMISSION_READY",
            "submission": {"path": "submission.json", "sha256": sha256_file(submission_path)},
            "candidate": submission["candidate_artifact"],
            "report": submission["report"],
            "attachments": submission["attachments"],
        }
        submission_review_path.write_text(json.dumps(submission_review, indent=2) + "\n", encoding="utf-8")

        submission_result = run(
            VALIDATE, "--stage", "submission", "--target-ledger", target_path,
            "--candidate", bundled_candidate,
            "--candidate-review", bundled_candidate_review_path,
            "--submission-review", submission_review_path,
            submission_path,
        )
        require(
            submission_result.returncode == 0
            and "SUBMISSION READY FOR FINAL CHECK" in submission_result.stdout,
            "submission stage did not validate the exact reviewed bundle",
            submission_result,
        )
        checks += 1

        target["scope"]["max_severity"] = "low"
        target_path.write_text(json.dumps(target, indent=2) + "\n", encoding="utf-8")
        capped = run(
            VALIDATE, "--stage", "submission", "--target-ledger", target_path,
            "--candidate", bundled_candidate,
            "--candidate-review", bundled_candidate_review_path,
            "--submission-review", submission_review_path,
            submission_path,
        )
        require(
            capped.returncode != 0 and "exceeds target.scope.max_severity" in capped.stderr,
            "submission bypassed the live target severity cap",
            capped,
        )
        checks += 1
        target["scope"]["max_severity"] = "high"
        target_path.write_text(json.dumps(target, indent=2) + "\n", encoding="utf-8")

        submission_review["verdict"] = "NOT_READY"
        submission_review_path.write_text(json.dumps(submission_review, indent=2) + "\n", encoding="utf-8")
        rejected = run(
            VALIDATE, "--stage", "submission", "--target-ledger", target_path,
            "--candidate", bundled_candidate,
            "--candidate-review", bundled_candidate_review_path,
            "--submission-review", submission_review_path,
            submission_path,
        )
        require(
            rejected.returncode != 0 and "affirm verdict SUBMISSION_READY" in rejected.stderr,
            "negative final review incorrectly produced a readiness result",
            rejected,
        )
        checks += 1

    print(f"{checks}/{checks} target-bound CLI smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
