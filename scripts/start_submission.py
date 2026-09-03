#!/usr/bin/env python3
"""Create a self-contained final bundle from a reportable candidate and Markdown report."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from hunt_validation.common import ValidationError, load_json, sha256_file, text


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new submission.json path")
    parser.add_argument("--submission-id", required=True)
    parser.add_argument(
        "--attachment",
        action="append",
        default=[],
        metavar="PATH=ROLE",
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
    try:
        candidate = load_json(args.candidate)
    except ValidationError as exc:
        return fail(str(exc))
    if candidate.get("schema_version") != 7:
        return fail("start-submission requires a schema-7 candidate")
    decision = candidate.get("decision") if isinstance(candidate.get("decision"), dict) else {}
    if decision.get("verdict") != "REPORTABLE":
        return fail("start-submission requires candidate decision.verdict REPORTABLE")

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
    destinations = [args.output.resolve(), candidate_copy, report_copy]
    destinations.extend(root / "attachments" / source.name for source, _ in attachment_inputs)
    existing = [path for path in destinations if path.exists()]
    if existing:
        return fail("refusing to overwrite existing bundle artifact: " + ", ".join(str(path) for path in existing))

    copy_artifact(args.candidate.resolve(), candidate_copy)
    copy_artifact(args.report.resolve(), report_copy)

    attachments: list[dict[str, str]] = []
    for source, role in attachment_inputs:
        destination = root / "attachments" / source.name
        copy_artifact(source, destination)
        attachments.append({
            "path": str(destination.relative_to(root)),
            "sha256": sha256_file(destination),
            "role": role,
        })

    document = {
        "schema_version": 2,
        "submission_id": args.submission_id,
        "candidate_id": candidate.get("candidate_id", ""),
        "target_id": candidate.get("target_ledger_id", ""),
        "files": {
            "candidate": {"path": "candidate.json", "sha256": sha256_file(candidate_copy)},
            "report": {"path": "report.md", "sha256": sha256_file(report_copy)},
            "attachments": attachments,
        },
        "preflight": {
            "scope": {
                "status": "unassessed",
                "asset_identifier": "",
                "max_severity": "",
                "checked_at": "",
                "evidence": {"method": "", "source": "", "artifact": ""},
            },
            "proof_policy": {
                "status": "unassessed",
                "accepted_proof_types": [],
                "checked_at": "",
                "evidence": {"method": "", "source": "", "artifact": ""},
            },
        },
        "prepared_at": "",
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"SUBMISSION BUNDLE CREATED: {args.output}")
    print("Complete the live preflight and prepared_at, then obtain one final-review.json over the exact bundle.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
