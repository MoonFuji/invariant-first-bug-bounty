#!/usr/bin/env python3
"""Validate target selection and candidate state as one bound workflow."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from hunt_validation.candidate import (
    load_candidate_validator,
    run_candidate_validator,
    validate_candidate_schema,
    validate_candidate_target_binding,
    validate_caveat_ledger,
    validate_claim_scope_and_recovery,
    validate_closure_review,
    validate_candidate_timestamps,
    validate_probe_shapes,
    validate_report_target_contract,
)
from hunt_validation.common import ValidationError, emit_messages, load_json, sha256_file
from hunt_validation.submission import (
    validate_candidate_review_sidecar,
    validate_submission,
    validate_submission_review_sidecar,
)
from hunt_validation.target import (
    canonical_target_value,
    scope_evidence_summary,
    target_fingerprint,
    validate_target,
)

# Re-export helpers used by start_candidate.py and regression tests.
__all__ = [
    "ValidationError", "canonical_target_value", "scope_evidence_summary", "target_fingerprint",
    "emit_messages", "load_json",
    "validate_candidate_target_binding", "validate_caveat_ledger", "validate_closure_review",
    "validate_candidate_schema", "validate_claim_scope_and_recovery", "validate_candidate_timestamps",
    "validate_probe_shapes", "validate_report_target_contract", "validate_target",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate target selection and candidate state as one bound workflow."
    )
    parser.add_argument(
        "document", type=Path,
        help="target.json, candidate.json, or submission.json for the selected stage",
    )
    parser.add_argument(
        "--stage", choices=("target", "model", "decision", "report", "submission"), required=True,
    )
    parser.add_argument(
        "--target-ledger", type=Path,
        help="Validated target.json; required for every candidate and submission stage",
    )
    parser.add_argument("--candidate", type=Path, help="candidate.json; required for submission stage")
    parser.add_argument(
        "--candidate-review", type=Path,
        help="digest-bound candidate review; required for report and submission stages",
    )
    parser.add_argument(
        "--submission-review", type=Path,
        help="digest-bound final bundle review; required for submission stage",
    )
    return parser.parse_args()


def validate_candidate_workflow(
    candidate: dict[str, Any],
    candidate_path: Path,
    target: dict[str, Any],
    stage: str,
    candidate_review_path: Path | None,
    module: Any,
    errors: list[str],
    warnings: list[str],
) -> bool:
    validate_candidate_schema(candidate, errors)
    validate_candidate_target_binding(candidate, target, errors)
    run_candidate_validator(module, candidate, stage, errors)
    validate_claim_scope_and_recovery(candidate, errors)
    validate_candidate_timestamps(candidate, errors)

    decision = candidate.get("decision")
    verdict = decision.get("verdict") if isinstance(decision, dict) else None
    terminal_verdicts = {"REPORTABLE", "KILL", "ROUTE_ELSEWHERE", "NO_REPORTABLE_FINDING"}
    if stage in {"decision", "report", "submission"} and verdict in terminal_verdicts:
        lifecycle = target.get("hypothesis_lifecycle")
        matches = [
            hypothesis for hypothesis in lifecycle
            if isinstance(hypothesis, dict)
            and hypothesis.get("hypothesis_id") == candidate.get("hypothesis_id")
        ] if isinstance(lifecycle, list) else []
        if len(matches) == 1:
            hypothesis = matches[0]
            if hypothesis.get("status") != "closed":
                errors.append("terminal candidate decision requires the bound target hypothesis status closed")
            if hypothesis.get("candidate_sha256") != sha256_file(candidate_path):
                errors.append("closed target hypothesis candidate_sha256 must match the exact candidate bytes")
    independently_reviewed = False
    if candidate_review_path is not None:
        try:
            review = load_json(candidate_review_path)
        except ValidationError as exc:
            errors.append(str(exc))
        else:
            validate_candidate_review_sidecar(
                review,
                candidate_review_path,
                errors,
                candidate_path=candidate_path,
            )
            if review.get("verdict") != verdict:
                errors.append("candidate review verdict must affirm candidate.decision.verdict")
            else:
                independently_reviewed = True
    elif stage in {"report", "submission"}:
        errors.append(f"{stage} stage requires --candidate-review bound to the exact candidate bytes")

    if verdict == "NO_REPORTABLE_FINDING":
        validate_closure_review(
            candidate,
            errors,
            provisional=not independently_reviewed,
            warnings=warnings,
        )
        lifecycle = target.get("hypothesis_lifecycle")
        expected_remaining = {
            hypothesis.get("hypothesis_id")
            for hypothesis in lifecycle
            if isinstance(hypothesis, dict)
            and hypothesis.get("priority") == "high"
            and hypothesis.get("status") in {"queued", "investigating"}
            and hypothesis.get("hypothesis_id") != candidate.get("hypothesis_id")
        } if isinstance(lifecycle, list) else set()
        closure = candidate.get("closure_review") if isinstance(candidate.get("closure_review"), dict) else {}
        recorded = closure.get("remaining_high_value_hypotheses")
        recorded_set = set(recorded) if isinstance(recorded, list) and all(isinstance(item, str) for item in recorded) else set()
        if recorded_set != expected_remaining:
            errors.append(
                "closure_review.remaining_high_value_hypotheses must exactly match the target's "
                "remaining high-priority hypothesis IDs"
            )
    if verdict == "REPORTABLE":
        validate_caveat_ledger(candidate, errors)
        validate_report_target_contract(candidate, target, errors)

    proof = candidate.get("proof")
    if stage in {"report", "submission"} and isinstance(proof, dict):
        dependency = proof.get("config_dependency")
        if isinstance(dependency, dict) and dependency.get("kind") == "unknown":
            errors.append(f"{stage} stage requires proof.config_dependency.kind to be assessed")

    if hasattr(module, "collect_warnings"):
        warnings.extend(module.collect_warnings(candidate))
    validate_probe_shapes(candidate, warnings)
    return independently_reviewed


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
        print("ERROR: --target-ledger is required for candidate and submission stages", file=sys.stderr)
        return 2
    try:
        target = load_json(args.target_ledger)
        module = load_candidate_validator()
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    validate_target(target, errors)

    if args.stage == "submission":
        if args.candidate is None:
            errors.append("submission stage requires --candidate")
            candidate = {}
        else:
            try:
                candidate = load_json(args.candidate)
            except ValidationError as exc:
                errors.append(str(exc))
                candidate = {}
        if args.submission_review is None:
            errors.append("submission stage requires --submission-review")
            submission_review = {}
        else:
            try:
                submission_review = load_json(args.submission_review)
            except ValidationError as exc:
                errors.append(str(exc))
                submission_review = {}

        if args.candidate is not None:
            validate_candidate_workflow(
                candidate,
                args.candidate,
                target,
                "submission",
                args.candidate_review,
                module,
                errors,
                warnings,
            )
        validate_submission(document, args.document, errors)
        candidate_artifact = document.get("candidate_artifact")
        if args.candidate is not None and isinstance(candidate_artifact, dict):
            artifact_path = candidate_artifact.get("path")
            if isinstance(artifact_path, str) and artifact_path.strip():
                manifest_candidate = (args.document.resolve().parent / artifact_path).resolve()
                if manifest_candidate != args.candidate.resolve():
                    errors.append(
                        "--candidate must be the exact candidate_artifact referenced by submission.json"
                    )

        target_scope = target.get("scope") if isinstance(target.get("scope"), dict) else {}
        preflight = document.get("preflight") if isinstance(document.get("preflight"), dict) else {}
        submission_scope = preflight.get("scope") if isinstance(preflight.get("scope"), dict) else {}
        if submission_scope.get("asset_identifier") != target_scope.get("asset_identifier"):
            errors.append("submission.preflight.scope.asset_identifier must match the live target scope")
        severity_rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        target_max = target_scope.get("max_severity")
        submission_severity = document.get("severity")
        if target_max in severity_rank and submission_severity in severity_rank:
            if severity_rank[submission_severity] > severity_rank[target_max]:
                errors.append("submission severity exceeds target.scope.max_severity")
        policy = preflight.get("proof_policy") if isinstance(preflight.get("proof_policy"), dict) else {}
        candidate_proof = candidate.get("proof") if isinstance(candidate.get("proof"), dict) else {}
        if policy.get("accepted_proof_type") != candidate_proof.get("type"):
            errors.append("submission.preflight.proof_policy.accepted_proof_type must match candidate proof.type")

        if args.submission_review is not None:
            validate_submission_review_sidecar(
                submission_review,
                args.submission_review,
                errors,
                submission=document,
                submission_path=args.document,
            )
            if submission_review.get("verdict") != "SUBMISSION_READY":
                errors.append("submission review must affirm verdict SUBMISSION_READY")
    else:
        independently_reviewed = validate_candidate_workflow(
            document,
            args.document,
            target,
            args.stage,
            args.candidate_review,
            module,
            errors,
            warnings,
        )

    if errors:
        emit_messages("ERROR", errors)
        return 2

    emit_messages("WARN", warnings)

    labels = {
        "model": "MODEL READY",
        "decision": "DECISION READY",
        "report": "CANDIDATE REPORTABLE",
        "submission": "SUBMISSION READY FOR FINAL CHECK",
    }
    label = labels[args.stage]
    if args.stage == "decision" and not independently_reviewed:
        label = "DECISION PROVISIONAL -- INDEPENDENT REVIEW OWED"
    print(f"{label}: {args.document}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
