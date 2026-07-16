#!/usr/bin/env python3
"""Validate durable bug-bounty candidate state before recon or reporting."""

import argparse
import json
import sys
from pathlib import Path


VERDICTS = {
    "REPORTABLE",
    "HOLD",
    "KILL",
    "ROUTE_ELSEWHERE",
    "NO_REPORTABLE_FINDING",
}
REFUTATION_RESULTS = {"refuted", "confirmed", "unresolved"}
PROOF_TYPES = {
    "none",
    "live-two-identity",
    "live-deployed",
    "executable-local-exact-path",
    "regression-test",
    "maintainer-fix-or-cve",
    "hardware-reproduction",
}
ROUTE_TYPES = {"none", "program", "upstream-advisory", "ibb", "vendor"}
PRIVATE_DUPLICATE_RISKS = {"unknown", "low", "medium", "high"}


def value_at(document, dotted_path):
    value = document
    for part in dotted_path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def require_text(document, path, errors):
    value = value_at(document, path)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path} must be a non-empty string")


def require_list(document, path, errors, *, nonempty=False):
    value = value_at(document, path)
    if not isinstance(value, list):
        errors.append(f"{path} must be an array")
    elif nonempty and not value:
        errors.append(f"{path} must contain at least one item")


def require_bool(document, path, errors, *, expected=None):
    value = value_at(document, path)
    if not isinstance(value, bool):
        errors.append(f"{path} must be a boolean")
    elif expected is not None and value is not expected:
        errors.append(f"{path} must be {str(expected).lower()}")


def validate_common(document, errors):
    if value_at(document, "schema_version") != 1:
        errors.append("schema_version must be 1")

    verdict = value_at(document, "decision.verdict")
    if verdict not in VERDICTS:
        errors.append(
            "decision.verdict must be one of " + ", ".join(sorted(VERDICTS))
        )

    require_list(document, "decision.failed_gates", errors)
    require_list(document, "decision.missing_evidence", errors)
    require_list(document, "decision_history", errors)
    require_text(document, "decision.reason", errors)

    failed_gates = value_at(document, "decision.failed_gates")
    missing_evidence = value_at(document, "decision.missing_evidence")
    if verdict == "HOLD" and isinstance(missing_evidence, list) and not missing_evidence:
        errors.append("HOLD requires decision.missing_evidence")
    if verdict == "KILL" and isinstance(failed_gates, list) and not failed_gates:
        errors.append("KILL requires decision.failed_gates")
    if verdict == "ROUTE_ELSEWHERE":
        require_text(document, "route.submission_target", errors)
        require_text(document, "route.owner_evidence", errors)
        require_bool(document, "route.owner_verified", errors, expected=True)


def validate_model(document, errors):
    validate_common(document, errors)

    for path in (
        "candidate_id",
        "target.program",
        "target.asset",
        "target.repository",
        "target.commit",
        "target.scope_evidence",
        "target.scope_checked_at",
        "model.security_invariant",
    ):
        require_text(document, path, errors)

    for path in (
        "model.principals",
        "model.protected_assets",
        "model.trust_boundaries",
        "model.state_stores",
        "model.enforcement_points",
    ):
        require_list(document, path, errors, nonempty=True)


def validate_decision(document, errors):
    validate_model(document, errors)

    for path in (
        "trace.entrypoint",
        "trace.attacker_input",
        "trace.validation_path",
        "trace.authorization_path",
        "trace.state_transition",
        "trace.persistence_path",
        "trace.observable_effect",
        "threat_model.attacker_starting_access",
        "threat_model.attacker_controls",
        "threat_model.victim_action",
        "threat_model.capability_before",
        "threat_model.capability_after",
        "threat_model.asset_owned_boundary",
        "threat_model.strongest_refutation",
        "decision.decided_at",
    ):
        require_text(document, path, errors)

    require_list(document, "trace.sibling_paths", errors, nonempty=True)

    refutation_result = value_at(document, "threat_model.refutation_result")
    if refutation_result not in REFUTATION_RESULTS:
        errors.append(
            "threat_model.refutation_result must be one of "
            + ", ".join(sorted(REFUTATION_RESULTS))
        )

    verdict = value_at(document, "decision.verdict")
    if verdict in {"KILL", "NO_REPORTABLE_FINDING"} and refutation_result == "unresolved":
        errors.append(
            f"{verdict} requires threat_model.refutation_result to be confirmed or refuted"
        )


def validate_report(document, errors):
    validate_decision(document, errors)

    if value_at(document, "decision.verdict") != "REPORTABLE":
        errors.append("decision.verdict must be REPORTABLE for report stage")

    for path in (
        "proof.artifact",
        "proof.command",
        "proof.observed_result",
        "proof.production_relevance",
        "route.owning_project",
        "route.owner_evidence",
        "route.submission_target",
        "route.proof_acceptance_evidence",
        "novelty.root_cause_fingerprint",
        "novelty.checked_at",
        "novelty.semantic_delta",
    ):
        require_text(document, path, errors)

    require_list(document, "proof.negative_controls", errors, nonempty=True)
    for path in (
        "novelty.own_reports",
        "novelty.program_reports",
        "novelty.upstream_history",
        "novelty.recent_advisories",
    ):
        require_list(document, path, errors)

    before = value_at(document, "threat_model.capability_before")
    after = value_at(document, "threat_model.capability_after")
    if (
        isinstance(before, str)
        and isinstance(after, str)
        and before.strip()
        and after.strip()
        and before.strip() == after.strip()
    ):
        errors.append(
            "threat_model.capability_after must differ from capability_before"
        )

    refutation_result = value_at(document, "threat_model.refutation_result")
    if refutation_result in REFUTATION_RESULTS and refutation_result != "refuted":
        errors.append("threat_model.refutation_result must be refuted for report stage")

    proof_type = value_at(document, "proof.type")
    if proof_type not in PROOF_TYPES:
        errors.append("proof.type must be one of " + ", ".join(sorted(PROOF_TYPES)))
    elif proof_type == "none":
        errors.append("proof.type must not be none for report stage")

    route_type = value_at(document, "route.type")
    if route_type not in ROUTE_TYPES:
        errors.append("route.type must be one of " + ", ".join(sorted(ROUTE_TYPES)))
    elif route_type == "none":
        errors.append("route.type must not be none for report stage")

    private_risk = value_at(document, "novelty.private_duplicate_risk")
    if private_risk not in PRIVATE_DUPLICATE_RISKS:
        errors.append(
            "novelty.private_duplicate_risk must be one of "
            + ", ".join(sorted(PRIVATE_DUPLICATE_RISKS))
        )

    fingerprint = value_at(document, "novelty.root_cause_fingerprint")
    if isinstance(fingerprint, str) and fingerprint.strip():
        parts = [part.strip() for part in fingerprint.split("|")]
        if len(parts) != 4 or any(not part for part in parts):
            errors.append(
                "novelty.root_cause_fingerprint must contain four non-empty pipe-separated parts"
            )

    for path in (
        "route.owner_verified",
        "route.proof_type_accepted",
        "route.scope_verified",
    ):
        require_bool(document, path, errors, expected=True)

    failed_gates = value_at(document, "decision.failed_gates")
    missing_evidence = value_at(document, "decision.missing_evidence")
    if isinstance(failed_gates, list) and failed_gates:
        errors.append("REPORTABLE requires decision.failed_gates to be empty")
    if isinstance(missing_evidence, list) and missing_evidence:
        errors.append("REPORTABLE requires decision.missing_evidence to be empty")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate a bug-bounty candidate before recon or report writing."
    )
    parser.add_argument("candidate", type=Path, help="Path to candidate JSON")
    parser.add_argument(
        "--stage",
        choices=("model", "decision", "report"),
        required=True,
        help="Validation strictness",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        document = json.loads(args.candidate.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"ERROR: candidate file not found: {args.candidate}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as error:
        print(f"ERROR: invalid JSON: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"ERROR: cannot read candidate: {error}", file=sys.stderr)
        return 2

    if not isinstance(document, dict):
        print("ERROR: candidate root must be a JSON object", file=sys.stderr)
        return 2

    errors = []
    if args.stage == "model":
        validate_model(document, errors)
    elif args.stage == "decision":
        validate_decision(document, errors)
    else:
        validate_report(document, errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 2

    labels = {
        "model": "MODEL READY",
        "decision": "DECISION READY",
        "report": "REPORT READY",
    }
    label = labels[args.stage]
    print(f"{label}: {args.candidate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
