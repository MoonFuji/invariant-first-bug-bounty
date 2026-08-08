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
SUPPORTED_SCHEMA_VERSIONS = {3, 4}
# A refutation's `kind`. Every kind except non_terminal invalidates the
# candidate's own security model: it says the objection is not an ordinary
# counter-argument but a statement that the target does not own the boundary.
# Such a refutation cannot be "refuted" by pointing at a third party that
# misuses the component; if it is genuinely defeated by target-owned evidence,
# the honest kind is non_terminal.
REFUTATION_KINDS = {
    "non_terminal",
    "owned_boundary_absent",
    "capability_already_possessed",
    "required_precondition_already_grants_effect",
    "behavior_is_documented_contract",
    "target_does_not_own_security_property",
    "unreachable_under_supported_contract",
}
TERMINAL_REFUTATION_KINDS = REFUTATION_KINDS - {"non_terminal"}
RESOLUTION_SOURCES = {"target_owned", "third_party", "none"}
# Channels that make up the upstream-repository novelty search. git log alone
# (the `commits` channel) is not a substitute for the issue/PR search.
REQUIRED_UPSTREAM_CHANNELS = {"commits", "issues", "pull_requests"}
UPSTREAM_CHANNELS = REQUIRED_UPSTREAM_CHANNELS | {"releases"}
# Where a confirmed terminal refutation sends the candidate.
TERMINAL_KIND_GATES = {
    "owned_boundary_absent": {"relevance", "ownership"},
    "capability_already_possessed": {"capability_delta"},
    "required_precondition_already_grants_effect": {"capability_delta"},
    "behavior_is_documented_contract": {"refutation"},
    "target_does_not_own_security_property": {"ownership", "route"},
    "unreachable_under_supported_contract": {"reachability"},
}
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


def refutation_view(document):
    """Normalize threat_model.strongest_refutation (legacy string or v4 object)."""
    node = value_at(document, "threat_model.strongest_refutation")
    if isinstance(node, dict):
        return {
            "is_object": True,
            "claim": node.get("claim"),
            "kind": node.get("kind"),
            "evidence": node.get("evidence"),
            "resolution": node.get("resolution"),
            "resolution_source": node.get("resolution_source"),
            "result": node.get("result"),
        }
    return {
        "is_object": False,
        "claim": node if isinstance(node, str) else None,
        "kind": None,
        "evidence": None,
        "resolution": None,
        "resolution_source": None,
        "result": value_at(document, "threat_model.refutation_result"),
    }


def require_evidence(obj, path, errors):
    """A novelty check/channel that was executed must carry an auditable artifact."""
    ev = obj.get("evidence") if isinstance(obj, dict) else None
    if not isinstance(ev, dict):
        errors.append(f"{path}.evidence must be an object with method, query, artifact")
        return
    for key in ("method", "query", "artifact"):
        value = ev.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{path}.evidence.{key} must be a non-empty string")


def validate_common(document, errors):
    if value_at(document, "schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        errors.append("schema_version must be 3 or 4")

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
    view = refutation_view(document)
    node = value_at(document, "threat_model.strongest_refutation")
    if view["is_object"]:
        if not isinstance(view["claim"], str) or not view["claim"].strip():
            errors.append("threat_model.strongest_refutation.claim must be a non-empty string")
        if view["kind"] not in REFUTATION_KINDS:
            errors.append(
                "threat_model.strongest_refutation.kind must be one of "
                + ", ".join(sorted(REFUTATION_KINDS))
            )
        source = view["resolution_source"]
        if source is not None and source not in RESOLUTION_SOURCES:
            errors.append(
                "threat_model.strongest_refutation.resolution_source must be one of "
                + ", ".join(sorted(RESOLUTION_SOURCES))
            )
        # A terminal refutation asserts the target does not own the boundary.
        # It cannot be marked refuted; a third party misusing the component does
        # not move the owned boundary. If target-owned evidence genuinely defeats
        # the objection, the honest kind is non_terminal.
        if view["kind"] in TERMINAL_REFUTATION_KINDS and view["result"] == "refuted":
            errors.append(
                "a terminal refutation cannot be marked refuted; downstream misuse does "
                "not move the owned boundary (use kind non_terminal only when target-owned "
                "evidence defeats the objection)"
            )
    elif not isinstance(node, str) or not node.strip():
        errors.append(
            "threat_model.strongest_refutation must be a non-empty string or a structured object"
        )
    if view["result"] not in REFUTATION_RESULTS:
        errors.append(
            "threat_model refutation result must be one of " + ", ".join(sorted(REFUTATION_RESULTS))
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

    # Collect every closest_match (check-level and upstream channel-level) and
    # validate upstream channel shape.
    matches = []
    for index, check in enumerate(checks):
        if not isinstance(check, dict):
            continue
        cpath = f"novelty.checks[{index}]"
        if isinstance(check.get("closest_match"), dict):
            matches.append((cpath, check["closest_match"]))
        channels = check.get("channels")
        if channels is None:
            continue
        if not isinstance(channels, list):
            errors.append(f"{cpath}.channels must be an array")
            continue
        for cidx, channel in enumerate(channels):
            chpath = f"{cpath}.channels[{cidx}]"
            if not isinstance(channel, dict):
                errors.append(f"{chpath} must be an object")
                continue
            if channel.get("channel") not in UPSTREAM_CHANNELS:
                errors.append(
                    f"{chpath}.channel must be one of " + ", ".join(sorted(UPSTREAM_CHANNELS))
                )
            if channel.get("result") not in NOVELTY_CHECK_RESULTS:
                errors.append(f"{chpath}.result is invalid")
            if isinstance(channel.get("closest_match"), dict):
                matches.append((chpath, channel["closest_match"]))

    # `distinct` is the claim that cost real submissions when asserted without an
    # executed upstream issue/PR search. Require auditable search artifacts.
    if classification == "distinct":
        for index, check in enumerate(checks):
            if isinstance(check, dict) and check.get("result") in {"checked", "no_match"}:
                require_evidence(check, f"novelty.checks[{index}]", errors)

        upstream = next(
            (c for c in checks if isinstance(c, dict) and c.get("source") == "upstream_history"),
            None,
        )
        covered = set()
        if isinstance(upstream, dict) and isinstance(upstream.get("channels"), list):
            for channel in upstream["channels"]:
                if not isinstance(channel, dict):
                    continue
                name = channel.get("channel")
                if name not in UPSTREAM_CHANNELS:
                    continue
                if channel.get("result") in {"checked", "no_match"}:
                    require_evidence(
                        channel, "novelty.checks(upstream_history).channels", errors
                    )
                    covered.add(name)
                elif channel.get("result") == "unavailable":
                    reason = channel.get("reason")
                    if not isinstance(reason, str) or not reason.strip():
                        errors.append(
                            "novelty upstream channel marked unavailable requires a reason"
                        )
                    covered.add(name)
        if not REQUIRED_UPSTREAM_CHANNELS.issubset(covered):
            errors.append(
                "distinct requires upstream_history channels covering commits, issues, "
                "pull_requests with search artifacts (git log alone is insufficient)"
            )

        root_fp = value_at(document, "novelty.root_cause_fingerprint")
        for path, match in matches:
            if isinstance(root_fp, str) and match.get("fingerprint") == root_fp:
                errors.append(
                    f"{path} closest_match fingerprint identical to root_cause_fingerprint "
                    "forbids distinct (classify as duplicate)"
                )
            if match.get("establishes_by_design") is True:
                errors.append(
                    f"{path} establishes_by_design; feed it into the refutation "
                    "(KILL @ refutation) rather than a distinct or REPORTABLE finding"
                )


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
        if gate == "refutation" and refutation_view(document)["result"] != "confirmed":
            errors.append("KILL at refutation requires refutation result confirmed")
        if gate == "novelty" and value_at(
            document, "novelty.classification"
        ) != "duplicate":
            errors.append("KILL at novelty requires novelty.classification duplicate")
        if gate == "reportability" and value_at(
            document, "novelty.classification"
        ) != "distinct":
            errors.append("KILL at reportability requires novelty.classification distinct")
    elif verdict == "NO_REPORTABLE_FINDING":
        if refutation_view(document)["result"] != "confirmed":
            errors.append("NO_REPORTABLE_FINDING requires refutation result confirmed")
        require_equal_capabilities(document, errors, "NO_REPORTABLE_FINDING")
    elif verdict == "REPORTABLE":
        require_capability_delta(document, errors)
        view = refutation_view(document)
        if not view["is_object"]:
            errors.append(
                "REPORTABLE requires a structured strongest_refutation object "
                "(claim, kind, evidence, resolution, resolution_source, result)"
            )
        else:
            if view["result"] != "refuted":
                errors.append("REPORTABLE requires strongest_refutation.result refuted")
            if view["kind"] in TERMINAL_REFUTATION_KINDS:
                gates = ", ".join(sorted(TERMINAL_KIND_GATES.get(view["kind"], set())))
                errors.append(
                    f"terminal refutation kind '{view['kind']}' cannot be REPORTABLE; "
                    f"KILL at {gates}"
                )
            if not isinstance(view["resolution"], str) or not view["resolution"].strip():
                errors.append(
                    "REPORTABLE requires strongest_refutation.resolution stating the "
                    "target-owned finding that defeats the claim"
                )
            if not isinstance(view["evidence"], str) or not view["evidence"].strip():
                errors.append(
                    "REPORTABLE requires strongest_refutation.evidence, an independent "
                    "artifact backing the resolution"
                )
            if view["resolution_source"] != "target_owned":
                errors.append(
                    "REPORTABLE requires strongest_refutation.resolution_source target_owned; "
                    "a third_party or none resolution cannot defeat a refutation about the "
                    "target's own boundary"
                )
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
