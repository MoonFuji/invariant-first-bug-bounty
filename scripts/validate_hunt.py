#!/usr/bin/env python3
"""Authoritative validator for target, optional campaign, candidate, and final submission state."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from hunt_validation.candidate import validate_candidate
from hunt_validation.common import ValidationError, emit_messages, load_json
from hunt_validation.submission import validate_final_review, validate_submission
from hunt_validation.target import validate_campaign, validate_target


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("document", type=Path)
    parser.add_argument(
        "--stage",
        choices=("target", "campaign", "model", "decision", "report", "submission"),
        required=True,
    )
    parser.add_argument("--target-ledger", type=Path)
    parser.add_argument("--campaign-ledger", type=Path)
    parser.add_argument("--candidate", type=Path, help="exact candidate.json for submission stage")
    parser.add_argument("--final-review", type=Path, help="exact final-review.json for submission stage")
    return parser.parse_args()


def read(path: Path, errors: list[str]) -> dict:
    try:
        return load_json(path)
    except ValidationError as exc:
        errors.append(str(exc))
        return {}


def main() -> int:
    args = parse_args()
    errors: list[str] = []
    document = read(args.document, errors)
    if errors:
        emit_messages("ERROR", errors)
        return 2

    if args.stage == "target":
        validate_target(document, errors)
        if errors:
            emit_messages("ERROR", errors)
            return 2
        disposition = document.get("decision", {}).get("disposition")
        print(f"TARGET {disposition}: {args.document}")
        return 0

    if args.target_ledger is None:
        print("ERROR: --target-ledger is required outside target stage", file=sys.stderr)
        return 2
    target = read(args.target_ledger, errors)
    validate_target(target, errors)

    if args.stage == "campaign":
        validate_campaign(document, errors)
        if document.get("target_id") != target.get("target_id"):
            errors.append("campaign.target_id must match target.target_id")
        if errors:
            emit_messages("ERROR", errors)
            return 2
        print(f"CAMPAIGN READY: {args.document}")
        return 0

    campaign = None
    if args.campaign_ledger is not None:
        campaign = read(args.campaign_ledger, errors)
        validate_campaign(campaign, errors)
        if campaign.get("target_id") != target.get("target_id"):
            errors.append("campaign.target_id must match target.target_id")

    if args.stage in {"model", "decision", "report"}:
        validate_candidate(document, target, args.stage, errors, campaign=campaign)
        if errors:
            emit_messages("ERROR", errors)
            return 2
        labels = {
            "model": "MODEL READY",
            "decision": "DECISION READY",
            "report": "CANDIDATE READY TO DRAFT",
        }
        print(f"{labels[args.stage]}: {args.document}")
        return 0

    if args.candidate is None:
        errors.append("submission stage requires --candidate")
        candidate = {}
    else:
        candidate = read(args.candidate, errors)
    if args.final_review is None:
        errors.append("submission stage requires --final-review")
        review = {}
    else:
        review = read(args.final_review, errors)

    if candidate:
        validate_candidate(candidate, target, "report", errors, campaign=campaign)
    validate_submission(document, args.document, candidate, target, errors)
    if args.final_review is not None:
        validate_final_review(review, args.final_review, document, args.document, errors)

    files = document.get("files") if isinstance(document.get("files"), dict) else {}
    candidate_ref = files.get("candidate") if isinstance(files.get("candidate"), dict) else {}
    if args.candidate is not None and isinstance(candidate_ref.get("path"), str):
        referenced = (args.document.resolve().parent / candidate_ref["path"]).resolve()
        if referenced != args.candidate.resolve():
            errors.append("--candidate must be the exact candidate file referenced by submission.files.candidate")

    if errors:
        emit_messages("ERROR", errors)
        return 2

    print(f"SUBMISSION READY FOR FINAL CHECK: {args.document}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
