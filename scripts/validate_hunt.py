#!/usr/bin/env python3
"""Validate target selection and candidate state as one bound workflow."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from hunt_validation.candidate import (
    load_candidate_validator,
    run_candidate_validator,
    validate_candidate_target_binding,
    validate_closure_review,
    validate_final_review_order,
    validate_probe_shapes,
    validate_report_target_contract,
    validate_review_attestation,
)
from hunt_validation.common import ValidationError, emit_messages, load_json
from hunt_validation.target import canonical_target_value, scope_evidence_summary, validate_target

# Re-export helpers used by start_candidate.py and regression tests.
__all__ = [
    "ValidationError", "canonical_target_value", "scope_evidence_summary", "emit_messages", "load_json",
    "validate_candidate_target_binding", "validate_closure_review",
    "validate_final_review_order", "validate_probe_shapes", "validate_report_target_contract",
    "validate_review_attestation", "validate_target",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate target selection and candidate state as one bound workflow."
    )
    parser.add_argument(
        "document", type=Path,
        help="target.json for target stage, otherwise candidate.json",
    )
    parser.add_argument(
        "--stage", choices=("target", "model", "decision", "report"), required=True,
    )
    parser.add_argument(
        "--target-ledger", type=Path,
        help="Validated target.json; required for model, decision, and report stages",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        document = load_json(args.document)
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    errors: list[str] = []
    warnings: list[str] = []

    if args.stage == "target":
        validate_target(document, errors)
        if errors:
            emit_messages("ERROR", errors)
            return 2
        disposition = document["decision"]["disposition"]
        print(f"TARGET {disposition}: {args.document}")
        return 0

    if args.target_ledger is None:
        print("ERROR: --target-ledger is required for candidate stages", file=sys.stderr)
        return 2
    try:
        target = load_json(args.target_ledger)
        module = load_candidate_validator()
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    validate_target(target, errors)
    validate_candidate_target_binding(document, target, errors)
    run_candidate_validator(module, document, args.stage, errors)

    decision = document.get("decision")
    verdict = decision.get("verdict") if isinstance(decision, dict) else None
    reviewer_mode = ""
    if verdict in {"REPORTABLE", "NO_REPORTABLE_FINDING"}:
        reviewer_mode = validate_review_attestation(
            document, errors, allow_owed=args.stage == "decision"
        )
        if verdict == "NO_REPORTABLE_FINDING":
            validate_closure_review(document, errors, provisional=reviewer_mode == "owed")
        if reviewer_mode != "owed":
            validate_final_review_order(document, errors)

    if verdict == "REPORTABLE":
        validate_report_target_contract(document, target, errors)

    proof = document.get("proof")
    if (
        args.stage == "report" and isinstance(proof, dict)
        and proof.get("config_dependency") == "unknown"
    ):
        errors.append("report stage requires proof.config_dependency to be assessed, not unknown")

    if errors:
        emit_messages("ERROR", errors)
        return 2

    if hasattr(module, "collect_warnings"):
        warnings.extend(module.collect_warnings(document))
    validate_probe_shapes(document, warnings)
    emit_messages("WARN", warnings)

    labels = {
        "model": "MODEL READY",
        "decision": "DECISION READY",
        "report": "REPORT READY",
    }
    label = labels[args.stage]
    if reviewer_mode == "owed":
        label = "DECISION PROVISIONAL -- INDEPENDENT REVIEW OWED"
    print(f"{label}: {args.document}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
