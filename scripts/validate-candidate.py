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
GATES = {
    "scope",
    "route",
    "model",
    "relevance",
    "reachability",
    "capability_delta",
    "refutation",
    "proof",
    "ownership",
    "novelty",
    "reportability",
}
OPERATING_MODES = {"SOURCE_ONLY", "PROGRAM_HOSTED"}
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
NOVELTY_SOURCES = {
    "own_reports",
    "program_disclosures",
    "upstream_history",
    "recent_advisories",
}
NOVELTY_CHECK_RESULTS = {"checked", "no_match", "unavailable"}
NOVELTY_CLASSIFICATIONS = {"duplicate", "distinct", "uncertain"}
PRIVATE_DUPLICATE_RISKS = {"unknown", "low", "medium", "high"}

GATE_ORDER = [
    "scope",
    "model",
    "relevance",
    "reachability",
    "capability_delta",
    "refutation",
    "proof",
    "ownership",
    "novelty",
    "reportability",
]


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


def require_texts(document, paths, errors):
    for path in paths:
        require_text(document, path, errors)


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


def validate_fingerprint(value, path, errors):
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path} must be a non-empty string")
        return
    parts = [part.strip() for part in value.split("|")]
    if len(parts) != 4 or any(not part for part in parts):
        errors.append(f"{path} must contain four non-empty pipe-separated parts")


def validate_common(document, errors):
    if value_at(document, "schema_version") != 3:
        errors.append("schema_version must be 3")

    verdict = value_at(document, "decision.verdict")
    gate = value_at(document, "decision.gate")
    if verdict not in VERDICTS:
        errors.append("decision.verdict must be one of " + ", ".join(sorted(VERDICTS)))
    if gate not in GATES:
        errors.append("decision.gate must be one of " + ", ".join(sorted(GATES)))

    require_list(document, "decision.failed_gates", errors)
    require_list(document, "decision.missing_evidence", errors)
    require_list(document, "decision_history", errors)
    require_text(document, "candidate_id", errors)
    require_text(document, "decision.reason", errors)

    operating_mode = value_at(document, "target.operating_mode")
    if operating_mode not in OPERATING_MODES:
        errors.append(
            "target.operating_mode must be one of "
            + ", ".join(sorted(OPERATING_MODES))
        )

    failed_gates = value_at(document, "decision.failed_gates")
    missing_evidence = value_at(document, "decision.missing_evidence")
    if isinstance(failed_gates, list):
        invalid = [item for item in failed_gates if item not in GATES]
        if invalid:
            errors.append("decision.failed_gates contains an invalid gate")
        if verdict == "KILL" and gate in GATES and gate not in failed_gates:
            errors.append("KILL requires decision.gate in decision.failed_gates")
        if verdict != "KILL" and failed_gates:
            errors.append(f"{verdict} requires decision.failed_gates to be empty")

    if isinstance(missing_evidence, list):
        if any(not isinstance(item, str) or not item.strip() for item in missing_evidence):
            errors.append("decision.missing_evidence items must be non-empty strings")
        if verdict == "HOLD" and not missing_evidence:
            errors.append("HOLD requires decision.missing_evidence")
        if verdict != "HOLD" and missing_evidence:
            errors.append(f"{verdict} requires decision.missing_evidence to be empty")

    allowed_gates = {
        "REPORTABLE": {"reportability"},
        "NO_REPORTABLE_FINDING": {"refutation"},
        "ROUTE_ELSEWHERE": {"route", "ownership"},
    }
    if verdict in allowed_gates and gate not in allowed_gates[verdict]:
        choices = ", ".join(sorted(allowed_gates[verdict]))
        errors.append(f"{verdict} requires decision.gate to be one of {choices}")


def validate_target_fields(document, errors):
    require_texts(
        document,
        (
            "target.program",
            "target.asset",
            "target.repository",
            "target.commit",
            "target.scope_evidence",
            "target.scope_checked_at",
        ),
        errors,
    )


def validate_model_fields(document, errors):
    require_text(document, "model.security_invariant", errors)
    for path in (
        "model.principals",
        "model.protected_assets",
        "model.trust_boundaries",
        "model.state_stores",
        "model.enforcement_points",
    ):
        require_list(document, path, errors, nonempty=True)


def validate_relevance_fields(document, errors):
    require_texts(
        document,
        (
            "threat_model.attacker_starting_access",
            "threat_model.attacker_controls",
            "threat_model.capability_before",
            "threat_model.capability_after",
            "threat_model.asset_owned_boundary",
        ),
        errors,
    )


def validate_reachability_fields(document, errors):
    require_texts(
        document,
        (
            "trace.entrypoint",
            "trace.attacker_input",
            "trace.validation_path",
            "trace.authorization_path",
        ),
        errors,
    )


def validate_capability_fields(document, errors):
    require_texts(
        document,
        (
            "trace.state_transition",
            "trace.persistence_path",
            "trace.observable_effect",
            "threat_model.victim_action",
        ),
        errors,
    )


def validate_refutation_fields(document, errors):
    require_list(document, "trace.sibling_paths", errors, nonempty=True)
    require_text(document, "threat_model.strongest_refutation", errors)
    result = value_at(document, "threat_model.refutation_result")
    if result not in REFUTATION_RESULTS:
        errors.append(
            "threat_model.refutation_result must be one of "
            + ", ".join(sorted(REFUTATION_RESULTS))
        )


def validate_proof_fields(document, errors):
    require_texts(
        document,
        (
            "proof.artifact",
            "proof.command",
            "proof.observed_result",
            "proof.production_relevance",
        ),
        errors,
    )
    require_list(document, "proof.negative_controls", errors, nonempty=True)
    proof_type = value_at(document, "proof.type")
    if proof_type not in PROOF_TYPES:
        errors.append("proof.type must be one of " + ", ".join(sorted(PROOF_TYPES)))
    elif proof_type == "none":
        errors.append("proof.type must not be none once the proof gate is complete")


def validate_route_fields(document, errors, *, report_ready, owner_required=True):
    require_texts(
        document,
        ("route.owning_project", "route.owner_evidence", "route.submission_target"),
        errors,
    )
    route_type = value_at(document, "route.type")
    if route_type not in ROUTE_TYPES:
        errors.append("route.type must be one of " + ", ".join(sorted(ROUTE_TYPES)))
    elif route_type == "none" and owner_required:
        errors.append("route.type must not be none once the route gate is complete")
    require_bool(
        document,
        "route.owner_verified",
        errors,
        expected=True if owner_required else None,
    )
    if report_ready:
        require_text(document, "route.proof_acceptance_evidence", errors)
        require_bool(document, "route.proof_type_accepted", errors, expected=True)
        require_bool(document, "route.scope_verified", errors, expected=True)


def validate_closest_match(match, path, errors, *, four_axis=False):
    if not isinstance(match, dict):
        errors.append(f"{path} must be an object")
        return
    identifier = match.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        errors.append(f"{path}.id must be a non-empty string")
    validate_fingerprint(match.get("fingerprint"), f"{path}.fingerprint", errors)
    comparison = match.get("comparison")
    if four_axis:
        if not isinstance(comparison, dict):
            errors.append(f"{path}.comparison must be an object")
        else:
            for axis in ("boundary", "primitive", "invariant", "effect"):
                value = comparison.get(axis)
                if not isinstance(value, str) or not value.strip():
                    errors.append(
                        f"{path}.comparison.{axis} must be a non-empty string"
                    )
    elif not isinstance(comparison, str) or not comparison.strip():
        errors.append(f"{path}.comparison must be a non-empty string")


def validate_novelty_fields(document, errors):
    validate_fingerprint(
        value_at(document, "novelty.root_cause_fingerprint"),
        "novelty.root_cause_fingerprint",
        errors,
    )
    require_text(document, "novelty.semantic_delta", errors)

    classification = value_at(document, "novelty.classification")
    if classification not in NOVELTY_CLASSIFICATIONS:
        errors.append(
            "novelty.classification must be one of "
            + ", ".join(sorted(NOVELTY_CLASSIFICATIONS))
        )
    private_risk = value_at(document, "novelty.private_duplicate_risk")
    if private_risk not in PRIVATE_DUPLICATE_RISKS:
        errors.append(
            "novelty.private_duplicate_risk must be one of "
            + ", ".join(sorted(PRIVATE_DUPLICATE_RISKS))
        )

    checks = value_at(document, "novelty.checks")
    if not isinstance(checks, list):
        errors.append("novelty.checks must be an array")
        return

    sources = []
    completed = 0
    matched_sources = {}
    for index, check in enumerate(checks):
        path = f"novelty.checks[{index}]"
        if not isinstance(check, dict):
            errors.append(f"{path} must be an object")
            continue
        source = check.get("source")
        result = check.get("result")
        if source not in NOVELTY_SOURCES:
            errors.append(f"{path}.source is invalid")
        else:
            sources.append(source)
        for key in ("query", "checked_at"):
            value = check.get(key)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{path}.{key} must be a non-empty string")
        if result not in NOVELTY_CHECK_RESULTS:
            errors.append(f"{path}.result is invalid")
            continue
        if result in {"checked", "no_match"}:
            completed += 1
        closest_match = check.get("closest_match")
        if result == "checked":
            if isinstance(closest_match, dict):
                matched_sources[source] = (
                    closest_match.get("id"),
                    closest_match.get("fingerprint"),
                )
            validate_closest_match(closest_match, f"{path}.closest_match", errors)
        elif closest_match is not None:
            errors.append(f"{path}.closest_match must be null for {result}")
        if result == "unavailable":
            reason = check.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                errors.append(f"{path}.reason must explain why the source is unavailable")

    if len(checks) != len(NOVELTY_SOURCES) or set(sources) != NOVELTY_SOURCES:
        errors.append("novelty.checks must contain each required source exactly once")
    if completed == 0:
        errors.append("novelty.checks requires at least one checked or no_match source")

    closest = value_at(document, "novelty.closest_known_match")
    if matched_sources:
        validate_closest_match(
            closest, "novelty.closest_known_match", errors, four_axis=True
        )
        if isinstance(closest, dict):
            source = closest.get("source")
            if source not in matched_sources:
                errors.append(
                    "novelty.closest_known_match.source must identify a checked source"
                )
            elif (closest.get("id"), closest.get("fingerprint")) != matched_sources[source]:
                errors.append(
                    "novelty.closest_known_match must select that source's recorded closest match"
                )
    elif closest is not None:
        errors.append("novelty.closest_known_match must be null when no check found a match")


def validate_through(document, errors, gate):
    validate_common(document, errors)
    if gate is None:
        return
    validate_target_fields(document, errors)
    if gate == "scope":
        return
    if gate == "route":
        validate_route_fields(
            document, errors, report_ready=False, owner_required=False
        )
        return
    validate_model_fields(document, errors)
    if gate == "model":
        return
    if gate == "relevance":
        return
    validate_relevance_fields(document, errors)
    validate_reachability_fields(document, errors)
    if gate == "reachability":
        return
    validate_capability_fields(document, errors)
    if gate == "capability_delta":
        return
    validate_refutation_fields(document, errors)
    if gate == "refutation":
        return
    validate_proof_fields(document, errors)
    if gate == "proof":
        return
    validate_route_fields(document, errors, report_ready=True)
    if gate == "ownership":
        return
    validate_novelty_fields(document, errors)


def validate_model(document, errors):
    validate_through(document, errors, "model")


def prior_gate(gate):
    if gate in {"scope", "route"}:
        return None if gate == "scope" else "scope"
    index = GATE_ORDER.index(gate)
    return GATE_ORDER[index - 1]


def require_equal_capabilities(document, errors, verdict):
    before = value_at(document, "threat_model.capability_before")
    after = value_at(document, "threat_model.capability_after")
    if (
        isinstance(before, str)
        and isinstance(after, str)
        and before.strip()
        and after.strip()
        and before.strip() != after.strip()
    ):
        errors.append(f"{verdict} at this gate requires equal before/after capability")


def require_capability_delta(document, errors):
    before = value_at(document, "threat_model.capability_before")
    after = value_at(document, "threat_model.capability_after")
    if (
        isinstance(before, str)
        and isinstance(after, str)
        and before.strip()
        and after.strip()
        and before.strip() == after.strip()
    ):
        errors.append("REPORTABLE requires capability_after to differ from capability_before")


def validate_decision(document, errors):
    verdict = value_at(document, "decision.verdict")
    gate = value_at(document, "decision.gate")

    if verdict == "HOLD" and gate in GATES:
        validate_through(document, errors, prior_gate(gate))
    elif verdict == "KILL" and gate == "ownership":
        validate_through(document, errors, "proof")
        validate_route_fields(
            document, errors, report_ready=False, owner_required=False
        )
    elif verdict == "KILL" and gate in GATES:
        validate_through(document, errors, gate)
    elif verdict == "ROUTE_ELSEWHERE":
        validate_through(document, errors, "route")
        validate_route_fields(document, errors, report_ready=False)
    elif verdict == "NO_REPORTABLE_FINDING":
        validate_through(document, errors, "refutation")
    elif verdict == "REPORTABLE":
        validate_through(document, errors, "reportability")
    else:
        validate_common(document, errors)

    require_text(document, "decision.decided_at", errors)

    if verdict == "KILL":
        if gate in {"relevance", "capability_delta"}:
            if gate == "relevance":
                validate_relevance_fields(document, errors)
            require_equal_capabilities(document, errors, "KILL")
        if gate == "refutation" and value_at(
            document, "threat_model.refutation_result"
        ) != "confirmed":
            errors.append("KILL at refutation requires refutation_result confirmed")
        if gate == "novelty" and value_at(
            document, "novelty.classification"
        ) != "duplicate":
            errors.append("KILL at novelty requires novelty.classification duplicate")
        if gate == "reportability" and value_at(
            document, "novelty.classification"
        ) != "distinct":
            errors.append("KILL at reportability requires novelty.classification distinct")
    elif verdict == "NO_REPORTABLE_FINDING":
        if value_at(document, "threat_model.refutation_result") != "confirmed":
            errors.append("NO_REPORTABLE_FINDING requires refutation_result confirmed")
        require_equal_capabilities(document, errors, "NO_REPORTABLE_FINDING")
    elif verdict == "REPORTABLE":
        require_capability_delta(document, errors)
        if value_at(document, "threat_model.refutation_result") != "refuted":
            errors.append("REPORTABLE requires refutation_result refuted")
        if value_at(document, "novelty.classification") != "distinct":
            errors.append("REPORTABLE requires novelty.classification distinct")
        if value_at(document, "novelty.private_duplicate_risk") == "unknown":
            errors.append("REPORTABLE requires assessed private_duplicate_risk")


def validate_report(document, errors):
    validate_decision(document, errors)
    if value_at(document, "decision.verdict") != "REPORTABLE":
        errors.append("decision.verdict must be REPORTABLE for report stage")


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
        for error in dict.fromkeys(errors):
            print(f"ERROR: {error}", file=sys.stderr)
        return 2

    labels = {
        "model": "MODEL READY",
        "decision": "DECISION READY",
        "report": "REPORT READY",
    }
    print(f"{labels[args.stage]}: {args.candidate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
