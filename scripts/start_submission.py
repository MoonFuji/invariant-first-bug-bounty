#!/usr/bin/env python3
"""Create a self-contained submission bundle from a reportable candidate."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from hunt_validation.common import ValidationError, load_json, sha256_file, text
from hunt_validation.submission import validate_candidate_review_sidecar


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--candidate-review", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True, help="finished Markdown report")
    parser.add_argument("--output", type=Path, required=True, help="new submission.json path")
    parser.add_argument("--submission-id", required=True)
    parser.add_argument("--title", required=True)
    parser.add_argument("--weakness", required=True)
    parser.add_argument("--severity", choices=("informational", "low", "medium", "high", "critical"), required=True)
    parser.add_argument("--cvss-score", type=float, required=True)
    parser.add_argument("--cvss-vector", required=True)
    parser.add_argument("--command", action="append", required=True, help="repeat for each reproduction command")
    parser.add_argument(
        "--attachment", action="append", default=[], metavar="PATH=ROLE",
        help="copy an attachment into the bundle; repeat as needed",
    )
    return parser.parse_args()


def fail(message: str) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return 2


def copy_artifact(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def main() -> int:
    args = parse_args()
    if args.output.exists():
        return fail(f"refusing to overwrite existing output: {args.output}")
    if not args.report.is_file() or args.report.suffix.casefold() != ".md":
        return fail("--report must be an existing Markdown file")
    if not 0 <= args.cvss_score <= 10:
        return fail("--cvss-score must be between 0 and 10")
    try:
        candidate = load_json(args.candidate)
        candidate_review = load_json(args.candidate_review)
    except ValidationError as exc:
        return fail(str(exc))
    if candidate.get("schema_version") != 6:
        return fail("start-submission requires a schema-6 candidate")
    decision = candidate.get("decision") if isinstance(candidate.get("decision"), dict) else {}
    if decision.get("verdict") != "REPORTABLE":
        return fail("start-submission requires candidate decision.verdict REPORTABLE")
    review_errors: list[str] = []
    validate_candidate_review_sidecar(
        candidate_review,
        args.candidate_review,
        review_errors,
        candidate_path=args.candidate,
    )
    if candidate_review.get("verdict") != "REPORTABLE":
        review_errors.append("candidate review must affirm REPORTABLE")
    if review_errors:
        for error in dict.fromkeys(review_errors):
            print(f"ERROR: {error}", file=sys.stderr)
        return 2
    claim = candidate.get("claim_scope") if isinstance(candidate.get("claim_scope"), dict) else {}
    for key in ("demonstrated_capability", "demonstrated_impact", "severity_ceiling"):
        if not text(claim.get(key)):
            return fail(f"candidate.claim_scope.{key} must be complete")

    # Validate every input and destination before creating any bundle file.
    # A malformed or missing attachment must not partially replace an existing
    # candidate, report, or review sidecar.
    attachment_inputs: list[tuple[Path, str]] = []
    names: set[str] = set()
    for raw in args.attachment:
        source_text, separator, role = raw.partition("=")
        source = Path(source_text)
        if not separator or not text(role):
            return fail(f"attachment must use PATH=ROLE: {raw}")
        if not source.is_file():
            return fail(f"attachment file not found: {source}")
        if source.name in names:
            return fail(f"duplicate attachment filename: {source.name}")
        names.add(source.name)
        attachment_inputs.append((source.resolve(), role.strip()))

    root = args.output.resolve().parent
    candidate_copy = root / "candidate.json"
    report_copy = root / "report.md"
    candidate_review_copy = root / "candidate-review.json"
    destinations = [args.output.resolve(), candidate_copy, report_copy, candidate_review_copy]
    destinations.extend(root / "attachments" / source.name for source, _ in attachment_inputs)
    existing = [path for path in destinations if path.exists()]
    if existing:
        return fail("refusing to overwrite existing bundle artifact: " + ", ".join(str(path) for path in existing))

    copy_artifact(args.candidate.resolve(), candidate_copy)
    copy_artifact(args.report.resolve(), report_copy)
    candidate_review["candidate"] = {
        "path": "candidate.json",
        "sha256": sha256_file(candidate_copy),
    }
    candidate_review_copy.write_text(
        json.dumps(candidate_review, indent=2) + "\n",
        encoding="utf-8",
    )

    attachments: list[dict[str, object]] = []
    for source, role in attachment_inputs:
        destination = root / "attachments" / source.name
        copy_artifact(source, destination)
        attachments.append({
            "path": str(destination.relative_to(root)),
            "sha256": sha256_file(destination),
            "role": role,
        })

    target = candidate.get("target") if isinstance(candidate.get("target"), dict) else {}
    document = {
        "schema_version": 1,
        "submission_id": args.submission_id,
        "campaign_id": candidate.get("campaign_id", ""),
        "candidate_id": candidate.get("candidate_id", ""),
        "asset": target.get("asset", ""),
        "version": target.get("commit", ""),
        "title": args.title,
        "weakness": args.weakness,
        "severity": args.severity,
        "cvss": {"score": args.cvss_score, "vector": args.cvss_vector},
        "demonstrated": {
            "capability": claim.get("demonstrated_capability", ""),
            "impact": claim.get("demonstrated_impact", ""),
        },
        "reproduction": {"commands": args.command},
        "report": {"path": "report.md", "sha256": sha256_file(report_copy)},
        "attachments": attachments,
        "preflight": {
            "scope": {"status": "unassessed", "asset_identifier": "", "checked_at": "", "evidence": {"method": "", "source": "", "artifact": ""}},
            "proof_policy": {"status": "unassessed", "accepted_proof_type": "", "checked_at": "", "evidence": {"method": "", "source": "", "artifact": ""}},
        },
        "candidate_artifact": {"path": "candidate.json", "sha256": sha256_file(candidate_copy)},
        "prepared_at": "",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"SUBMISSION BUNDLE CREATED: {args.output}")
    print("Complete the live preflight and prepared_at fields, then obtain submission-review.json.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
