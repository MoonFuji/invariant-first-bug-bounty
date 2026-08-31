"""Gate-aware target-ledger and campaign validation."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from .common import (
    parse_timestamp,
    require_evidence,
    require_not_future,
    require_text,
    text,
)

TARGET_SCHEMA_VERSION = 3
TARGET_DISPOSITIONS = {"SELECTED", "ROTATED", "HOLD"}
TARGET_GATES = {"scope", "proof_policy", "route", "contestability", "selection"}
ROTATION_BASES = {
    "scope_ineligible",
    "proof_route_unavailable",
    "route_unavailable",
    "contestability",
    "payout_unavailable",
    "user_directed",
}
OPERATING_MODES = {"SOURCE_ONLY", "PROGRAM_HOSTED"}
PLATFORMS = {
    "hackerone", "bugcrowd", "intigriti", "yeswehack",
    "upstream", "ibb", "vendor", "other",
}
ROUTE_TYPES = {"bounty", "vdp", "upstream-advisory", "ibb", "vendor"}
ASSET_TYPES = {
    "repository", "library", "cli", "sdk", "hosted-app", "api",
    "mobile", "firmware", "ai-mcp", "other",
}
SCOPE_STATUSES = {"eligible", "ineligible", "not_applicable", "unknown"}
MAX_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
EVIDENCE_STATUSES = {"checked", "unavailable", "not_applicable", "unassessed"}
ACCEPTED_PROOF_TYPES = {
    "executable-local-exact-path", "regression-test",
    "researcher-owned-deployment", "program-hosted-owned-account",
    "maintainer-fix-or-cve", "hardware-reproduction",
}
SUPPORTING_EVIDENCE_TYPES = {"static-source-trace"}
SOURCE_ONLY_PROOF_TYPES = {
    "executable-local-exact-path", "regression-test",
    "researcher-owned-deployment", "maintainer-fix-or-cve", "hardware-reproduction",
}
PROGRAM_HOSTED_PROOF_TYPES = {
    "program-hosted-owned-account", "researcher-owned-deployment",
    "executable-local-exact-path", "regression-test",
}
CONTESTABILITY_BASIS = {
    "platform_count", "public_history", "private_unavailable", "not_applicable",
}
CONTESTABILITY_COUNT_BASES = {"platform_count"}
ASSESSMENT_STATUSES = {"assessed", "unavailable", "not_applicable", "unassessed"}
CAMPAIGN_MODES = {"first_finding", "bounded", "exhaustive"}
CAMPAIGN_STATUSES = {"open", "closed"}
HYPOTHESIS_STATUSES = {"queued", "investigating", "closed", "parked"}
HYPOTHESIS_PRIORITIES = {"high", "medium", "low"}
TERMINAL_CANDIDATE_VERDICTS = {
    "REPORTABLE", "KILL", "ROUTE_ELSEWHERE", "NO_REPORTABLE_FINDING",
}

# Scope and policy are mutable platform facts. A 90-day window prevents an old
# target decision from being presented as live while allowing a campaign to be
# resumed without turning every run into a clock race. A small skew handles
# clock differences between a connector and the local validator.
MUTABLE_EVIDENCE_MAX_AGE = timedelta(days=90)


def _now() -> datetime:
    return datetime.now(UTC)


def _future_error(value: Any, path: str, errors: list[str]) -> datetime | None:
    return require_not_future(value, path, errors)


def _validate_mutable_freshness(value: Any, path: str, errors: list[str]) -> None:
    parsed = _future_error(value, path, errors)
    if parsed is None:
        return
    if _now() - parsed > MUTABLE_EVIDENCE_MAX_AGE:
        errors.append(
            f"{path} is older than the allowed freshness window ({MUTABLE_EVIDENCE_MAX_AGE.days} days); "
            "refresh the live scope or proof-policy evidence"
        )


def validate_target_identity(document: dict[str, Any], errors: list[str]) -> None:
    if document.get("schema_version") != TARGET_SCHEMA_VERSION:
        errors.append(f"target.schema_version must be {TARGET_SCHEMA_VERSION}")
    require_text(document, "target_id", "target", errors)
    require_text(document, "program", "target", errors)
    require_text(document, "asset", "target", errors)

    platform = document.get("platform")
    if platform not in PLATFORMS:
        errors.append("target.platform must be one of " + ", ".join(sorted(PLATFORMS)))
    route_type = document.get("route_type")
    if route_type not in ROUTE_TYPES:
        errors.append("target.route_type must be one of " + ", ".join(sorted(ROUTE_TYPES)))
    asset_type = document.get("asset_type")
    if asset_type not in ASSET_TYPES:
        errors.append("target.asset_type must be one of " + ", ".join(sorted(ASSET_TYPES)))
    mode = document.get("operating_mode")
    if mode not in OPERATING_MODES:
        errors.append("target.operating_mode must be one of " + ", ".join(sorted(OPERATING_MODES)))

    if "saturation" in document:
        errors.append("target.saturation is obsolete; replace it with target.contestability")

    if asset_type in {"repository", "library", "cli", "sdk"}:
        require_text(document, "repository", "target", errors)
        require_text(document, "commit", "target", errors)
    else:
        for key in ("repository", "commit"):
            value = document.get(key)
            if value is not None and not isinstance(value, str):
                errors.append(f"target.{key} must be a string or null for {asset_type}")


def validate_scope(document: dict[str, Any], errors: list[str]) -> None:
    scope = document.get("scope")
    if not isinstance(scope, dict):
        errors.append("target.scope must be an object")
        return
    status = scope.get("status")
    if status not in SCOPE_STATUSES:
        errors.append("scope.status must be one of " + ", ".join(sorted(SCOPE_STATUSES)))
        return
    require_text(scope, "asset_identifier", "scope", errors)
    max_severity = scope.get("max_severity")
    if status == "eligible" and max_severity not in MAX_SEVERITIES:
        errors.append("scope.max_severity must be informational, low, medium, high, or critical for an eligible asset")
    elif text(max_severity) and max_severity not in MAX_SEVERITIES:
        errors.append("scope.max_severity must be informational, low, medium, high, or critical when provided")
    _validate_mutable_freshness(scope.get("checked_at"), "scope.checked_at", errors)
    if status in {"eligible", "ineligible"}:
        require_evidence(scope.get("evidence"), "scope.evidence", errors)
    elif status in {"not_applicable", "unknown"}:
        require_text(scope, "reason", "scope", errors)
        if status == "unknown":
            require_evidence(scope.get("evidence"), "scope.evidence", errors, attempted=True)


def validate_proof_policy(document: dict[str, Any], errors: list[str]) -> None:
    policy = document.get("proof_policy")
    if not isinstance(policy, dict):
        errors.append("target.proof_policy must be an object")
        return
    status = policy.get("status")
    if status not in EVIDENCE_STATUSES:
        errors.append("proof_policy.status must be one of " + ", ".join(sorted(EVIDENCE_STATUSES)))
        return
    if status == "checked":
        require_text(policy, "quote", "proof_policy", errors)
        _validate_mutable_freshness(policy.get("checked_at"), "proof_policy.checked_at", errors)
        require_evidence(policy.get("evidence"), "proof_policy.evidence", errors)
        accepted = policy.get("accepted_proof_types")
        if not isinstance(accepted, list) or not accepted:
            errors.append("proof_policy.accepted_proof_types must contain at least one proof type")
        else:
            if "static-source-trace" in accepted:
                errors.append(
                    "proof_policy.static-source-trace is supporting evidence only; "
                    "put it in supporting_evidence_types and name an executable or hosted proof type"
                )
            invalid = [item for item in accepted if item not in ACCEPTED_PROOF_TYPES]
            if invalid:
                errors.append(
                    "proof_policy.accepted_proof_types contains an invalid final proof type: "
                    + ", ".join(str(item) for item in invalid)
                )
        supporting = policy.get("supporting_evidence_types", [])
        if not isinstance(supporting, list):
            errors.append("proof_policy.supporting_evidence_types must be an array")
        else:
            invalid_supporting = [item for item in supporting if item not in SUPPORTING_EVIDENCE_TYPES]
            if invalid_supporting:
                errors.append(
                    "proof_policy.supporting_evidence_types contains an invalid supporting type: "
                    + ", ".join(str(item) for item in invalid_supporting)
                )
    elif status == "unavailable":
        require_text(policy, "reason", "proof_policy", errors)
        _validate_mutable_freshness(policy.get("checked_at"), "proof_policy.checked_at", errors)
        require_evidence(policy.get("evidence"), "proof_policy.evidence", errors, attempted=True)
    elif status == "not_applicable":
        require_text(policy, "reason", "proof_policy", errors)
    elif status == "unassessed":
        # The blank template is intentionally not a selected target. If a
        # caller supplies a timestamp while still unassessed, validate it
        # rather than silently accepting an invalid value.
        if text(policy.get("checked_at")):
            _future_error(policy.get("checked_at"), "proof_policy.checked_at", errors)


def validate_contestability(document: dict[str, Any], errors: list[str]) -> None:
    contestability = document.get("contestability")
    if not isinstance(contestability, dict):
        errors.append("target.contestability must be an object")
        return
    status = contestability.get("status")
    if status not in EVIDENCE_STATUSES:
        errors.append("contestability.status must be one of " + ", ".join(sorted(EVIDENCE_STATUSES)))
        return
    basis = contestability.get("basis")
    if status in {"checked", "unavailable", "not_applicable"} and basis not in CONTESTABILITY_BASIS:
        errors.append(
            "contestability.basis must be one of " + ", ".join(sorted(CONTESTABILITY_BASIS))
            + " once contestability is assessed"
        )
    if status == "checked":
        if basis in CONTESTABILITY_COUNT_BASES:
            count = contestability.get("count")
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                errors.append(
                    "contestability.count must be a non-negative integer for "
                    f"basis {basis}"
                )
        elif contestability.get("count") is not None:
            errors.append(
                "contestability.count must be omitted or null for basis "
                f"{basis}; a numeric count is not available"
            )
        if basis == "private_unavailable":
            require_text(contestability, "reason", "contestability", errors)
        if basis == "not_applicable":
            require_text(contestability, "reason", "contestability", errors)
        if document.get("route_type") in {"bounty", "vdp"} and not isinstance(
            contestability.get("discloses_reports"), bool
        ):
            errors.append("contestability.discloses_reports must be a boolean for bounty/VDP targets")
        elif not isinstance(contestability.get("discloses_reports"), bool) and basis == "platform_count":
            errors.append("contestability.discloses_reports must be a boolean for platform_count")
        elif contestability.get("discloses_reports") is not None and not isinstance(contestability.get("discloses_reports"), bool):
            errors.append("contestability.discloses_reports must be a boolean or null")
        _future_error(contestability.get("checked_at"), "contestability.checked_at", errors)
        require_evidence(contestability.get("evidence"), "contestability.evidence", errors)
        require_text(contestability, "rationale", "contestability", errors)
    elif status == "unavailable":
        require_text(contestability, "reason", "contestability", errors)
        _future_error(contestability.get("checked_at"), "contestability.checked_at", errors)
        require_evidence(contestability.get("evidence"), "contestability.evidence", errors, attempted=True)
        require_text(contestability, "rationale", "contestability", errors)
        if contestability.get("count") is not None:
            errors.append("contestability.count must be omitted or null when contestability is unavailable")
    elif status == "not_applicable":
        if basis != "not_applicable":
            errors.append("contestability.status not_applicable requires basis not_applicable")
        require_text(contestability, "reason", "contestability", errors)
        if contestability.get("count") is not None:
            errors.append("contestability.count must be omitted or null for a not_applicable basis")
    elif status == "unassessed":
        if text(contestability.get("checked_at")):
            _future_error(contestability.get("checked_at"), "contestability.checked_at", errors)


def _validate_assessment_block(
    document: dict[str, Any],
    key: str,
    errors: list[str],
) -> None:
    block = document.get(key)
    if not isinstance(block, dict):
        errors.append(f"target.{key} must be an object")
        return
    status = block.get("status")
    if status not in ASSESSMENT_STATUSES:
        errors.append(f"{key}.status must be one of " + ", ".join(sorted(ASSESSMENT_STATUSES)))
        return
    if status == "assessed":
        if key == "prior_outcomes":
            require_text(block, "summary", key, errors)
        _future_error(block.get("checked_at"), f"{key}.checked_at", errors)
        require_evidence(block.get("evidence"), f"{key}.evidence", errors)
    elif status == "unavailable":
        require_text(block, "reason", key, errors)
        _future_error(block.get("checked_at"), f"{key}.checked_at", errors)
        require_evidence(block.get("evidence"), f"{key}.evidence", errors, attempted=True)
    elif status == "not_applicable":
        require_text(block, "reason", key, errors)
    elif status == "unassessed" and text(block.get("checked_at")):
        _future_error(block.get("checked_at"), f"{key}.checked_at", errors)

    if key == "prior_outcomes":
        outcomes = block.get("outcomes")
        if not isinstance(outcomes, list):
            errors.append("prior_outcomes.outcomes must be an array (it may be empty when none are known)")
        else:
            for index, outcome in enumerate(outcomes):
                path = f"prior_outcomes.outcomes[{index}]"
                if not isinstance(outcome, dict):
                    errors.append(f"{path} must be an object; private report IDs are optional")
                    continue
                require_text(outcome, "class", path, errors)
                require_text(outcome, "outcome", path, errors)
    else:
        for array_key in ("previously_audited", "new_or_uncovered", "changed_since_last_review"):
            values = block.get(array_key)
            if not isinstance(values, list) or any(not text(value) for value in values):
                errors.append(f"coverage_delta.{array_key} must be an array of non-empty strings")


def validate_prior_outcomes(document: dict[str, Any], errors: list[str]) -> None:
    _validate_assessment_block(document, "prior_outcomes", errors)


def validate_coverage_delta(document: dict[str, Any], errors: list[str]) -> None:
    _validate_assessment_block(document, "coverage_delta", errors)


def validate_architecture_and_hypotheses(document: dict[str, Any], errors: list[str]) -> None:
    architecture = document.get("architecture_boundary_map")
    if not isinstance(architecture, dict):
        errors.append("target.architecture_boundary_map must be an object")
        boundaries: list[Any] = []
    else:
        boundaries = architecture.get("boundaries")
        if not isinstance(boundaries, list) or not boundaries:
            errors.append("architecture_boundary_map.boundaries must contain at least one boundary")
            boundaries = []

    boundary_ids: set[str] = set()
    for index, boundary in enumerate(boundaries):
        path = f"architecture_boundary_map.boundaries[{index}]"
        if not isinstance(boundary, dict):
            errors.append(f"{path} must be an object")
            continue
        for field in ("boundary_id", "name", "trust_transition"):
            require_text(boundary, field, path, errors)
        boundary_id = boundary.get("boundary_id")
        if text(boundary_id):
            if boundary_id in boundary_ids:
                errors.append(f"{path}.boundary_id duplicates another boundary")
            boundary_ids.add(boundary_id)
        entrypoints = boundary.get("entrypoints")
        if not isinstance(entrypoints, list) or not entrypoints or any(not text(item) for item in entrypoints):
            errors.append(f"{path}.entrypoints must contain at least one non-empty entrypoint")
        require_evidence(boundary.get("evidence"), f"{path}.evidence", errors)

    lifecycle = document.get("hypothesis_lifecycle")
    if not isinstance(lifecycle, list) or not lifecycle:
        errors.append("target.hypothesis_lifecycle must contain at least one hypothesis")
        lifecycle = []
    hypothesis_ids: set[str] = set()
    for index, hypothesis in enumerate(lifecycle):
        path = f"hypothesis_lifecycle[{index}]"
        if not isinstance(hypothesis, dict):
            errors.append(f"{path} must be an object")
            continue
        for field in ("hypothesis_id", "boundary_id", "statement"):
            require_text(hypothesis, field, path, errors)
        priority = hypothesis.get("priority")
        if priority not in HYPOTHESIS_PRIORITIES:
            errors.append(f"{path}.priority must be one of " + ", ".join(sorted(HYPOTHESIS_PRIORITIES)))
        status = hypothesis.get("status")
        if status not in HYPOTHESIS_STATUSES:
            errors.append(f"{path}.status must be one of " + ", ".join(sorted(HYPOTHESIS_STATUSES)))
        elif status == "closed":
            require_text(hypothesis, "candidate_id", path, errors)
            digest = hypothesis.get("candidate_sha256")
            if not isinstance(digest, str) or len(digest) != 64:
                errors.append(f"{path}.candidate_sha256 must be a 64-character hexadecimal SHA-256")
            else:
                try:
                    int(digest, 16)
                except ValueError:
                    errors.append(f"{path}.candidate_sha256 must be hexadecimal")
            if hypothesis.get("terminal_verdict") not in TERMINAL_CANDIDATE_VERDICTS:
                errors.append(
                    f"{path}.terminal_verdict must be one of "
                    + ", ".join(sorted(TERMINAL_CANDIDATE_VERDICTS))
                )
            _future_error(hypothesis.get("closed_at"), f"{path}.closed_at", errors)
            require_text(hypothesis, "evidence", path, errors)
        elif status == "parked":
            require_text(hypothesis, "park_reason", path, errors)
            require_text(hypothesis, "evidence", path, errors)
        elif status == "queued" and text(hypothesis.get("candidate_id")):
            errors.append(f"{path}.candidate_id must be empty until the hypothesis is investigated")
        hypothesis_id = hypothesis.get("hypothesis_id")
        if text(hypothesis_id):
            if hypothesis_id in hypothesis_ids:
                errors.append(f"{path}.hypothesis_id duplicates another hypothesis")
            hypothesis_ids.add(hypothesis_id)
        if text(hypothesis.get("boundary_id")) and hypothesis.get("boundary_id") not in boundary_ids:
            errors.append(f"{path}.boundary_id must reference an architecture boundary")


def validate_campaign(document: dict[str, Any], errors: list[str]) -> None:
    campaign = document.get("campaign")
    if not isinstance(campaign, dict):
        errors.append("target.campaign must be an object")
        return
    require_text(campaign, "campaign_id", "campaign", errors)
    mode = campaign.get("mode")
    if mode not in CAMPAIGN_MODES:
        errors.append("campaign.mode must be one of " + ", ".join(sorted(CAMPAIGN_MODES)))
    status = campaign.get("status")
    if status not in CAMPAIGN_STATUSES:
        errors.append("campaign.status must be one of " + ", ".join(sorted(CAMPAIGN_STATUSES)))
    require_text(campaign, "stop_condition", "campaign", errors)
    if status == "closed":
        _future_error(campaign.get("closed_at"), "campaign.closed_at", errors)
        lifecycle = document.get("hypothesis_lifecycle")
        if isinstance(lifecycle, list):
            remaining = [
                item.get("hypothesis_id", f"index {index}")
                for index, item in enumerate(lifecycle)
                if isinstance(item, dict)
                and item.get("priority") == "high"
                and item.get("status") in {"queued", "investigating"}
            ]
            if remaining:
                errors.append(
                    "campaign closure cannot succeed with remaining high-value hypotheses "
                    f"queued or investigating: {', '.join(str(item) for item in remaining)}; "
                    "close, park, or continue them before setting campaign.status closed"
                )
            closed = [item for item in lifecycle if isinstance(item, dict) and item.get("status") == "closed"]
            if mode == "first_finding" and not any(
                item.get("terminal_verdict") == "REPORTABLE" for item in closed
            ):
                errors.append("first_finding campaign closure requires a closed REPORTABLE hypothesis")
            if mode == "exhaustive" and any(
                isinstance(item, dict) and item.get("status") != "closed" for item in lifecycle
            ):
                errors.append("exhaustive campaign closure requires every hypothesis to be closed")
    elif text(campaign.get("closed_at")):
        _future_error(campaign.get("closed_at"), "campaign.closed_at", errors)


def same_evidence(left: Any, right: Any) -> bool:
    if not isinstance(left, dict) or not isinstance(right, dict):
        return False
    return all(left.get(key) == right.get(key) for key in ("method", "source", "artifact"))


def compatible_proof_types(document: dict[str, Any]) -> set[str]:
    policy = document.get("proof_policy")
    if not isinstance(policy, dict) or policy.get("status") != "checked":
        return set()
    accepted = policy.get("accepted_proof_types")
    if not isinstance(accepted, list):
        return set()
    permitted = SOURCE_ONLY_PROOF_TYPES if document.get("operating_mode") == "SOURCE_ONLY" else PROGRAM_HOSTED_PROOF_TYPES
    return {item for item in accepted if item in permitted}


def validate_target_decision(document: dict[str, Any], errors: list[str]) -> None:
    decision = document.get("decision")
    if not isinstance(decision, dict):
        errors.append("target.decision must be an object")
        return
    disposition = decision.get("disposition")
    if disposition not in TARGET_DISPOSITIONS:
        errors.append("decision.disposition must be SELECTED, ROTATED, or HOLD")
        return
    gate = decision.get("gate")
    if gate not in TARGET_GATES:
        errors.append("decision.gate must be one of " + ", ".join(sorted(TARGET_GATES)))
    require_text(decision, "reason", "decision", errors)
    _future_error(decision.get("decided_at"), "decision.decided_at", errors)
    missing = decision.get("missing_evidence")
    if not isinstance(missing, list) or any(not text(item) for item in missing):
        errors.append("decision.missing_evidence must be an array of non-empty strings")

    scope = document.get("scope") if isinstance(document.get("scope"), dict) else {}
    policy = document.get("proof_policy") if isinstance(document.get("proof_policy"), dict) else {}
    contestability = document.get("contestability") if isinstance(document.get("contestability"), dict) else {}
    route_type = document.get("route_type")

    if disposition == "SELECTED":
        if gate != "selection":
            errors.append("SELECTED requires decision.gate selection")
        if decision.get("rotation_basis") not in (None, ""):
            errors.append("SELECTED requires decision.rotation_basis null")
        if route_type in {"bounty", "vdp"} and scope.get("status") != "eligible":
            errors.append("a bounty/VDP target may be SELECTED only when scope.status is eligible")
        if route_type not in {"bounty", "vdp"} and scope.get("status") not in {"eligible", "not_applicable"}:
            errors.append("a non-bounty target may be SELECTED only when scope is eligible or not_applicable")
        # Selection means the route can eventually produce an accepted artifact.
        # Require this for every route, including upstream/vendor disclosure: a
        # target with no known acceptable proof rail is HOLD, not SELECTED.
        if policy.get("status") != "checked":
            errors.append("SELECTED targets require a checked proof_policy")
        elif not compatible_proof_types(document):
            errors.append("SELECTED requires at least one accepted proof type compatible with operating_mode")
        # Dedup/contestability matters for every selected target. For upstream
        # routes this can be advisory/issue history rather than platform reports,
        # but it still needs a checked artifact rather than an assumed quiet lane.
        if route_type in {"bounty", "vdp"} and contestability.get("status") != "checked":
            errors.append(
                "selected bounty/VDP targets require checked contestability; use private_unavailable "
                "when the private report pool cannot be inspected"
            )
        elif contestability.get("status") not in {"checked", "not_applicable"}:
            errors.append(
                "SELECTED targets require assessed contestability with a truthful basis "
                "(or an explicit not_applicable decision)"
            )
        for key in ("prior_outcomes", "coverage_delta"):
            block = document.get(key) if isinstance(document.get(key), dict) else {}
            if block.get("status") != "assessed":
                errors.append(
                    f"SELECTED targets require {key}.status assessed; record the known history "
                    "and state unavailable private records without inventing identifiers"
                )
        if isinstance(decision.get("missing_evidence"), list) and decision["missing_evidence"]:
            errors.append("SELECTED requires decision.missing_evidence empty")

    elif disposition == "ROTATED":
        basis = decision.get("rotation_basis")
        if basis not in ROTATION_BASES:
            errors.append("ROTATED requires a structured decision.rotation_basis")
        require_evidence(decision.get("evidence"), "decision.evidence", errors)
        if isinstance(decision.get("missing_evidence"), list) and decision["missing_evidence"]:
            errors.append("ROTATED requires decision.missing_evidence empty")
        expected_gate = {
            "scope_ineligible": "scope",
            "proof_route_unavailable": "proof_policy",
            "route_unavailable": "route",
            "contestability": "contestability",
            "payout_unavailable": "route",
            "user_directed": "selection",
        }.get(basis)
        if expected_gate is not None and gate != expected_gate:
            errors.append(f"rotation basis {basis} requires decision.gate {expected_gate}")
        if basis == "scope_ineligible":
            if scope.get("status") != "ineligible":
                errors.append("scope_ineligible rotation requires scope.status ineligible")
            if not same_evidence(decision.get("evidence"), scope.get("evidence")):
                errors.append("scope_ineligible rotation decision.evidence must match scope.evidence")
        if basis == "proof_route_unavailable":
            if not same_evidence(decision.get("evidence"), policy.get("evidence")):
                errors.append("proof_route_unavailable decision.evidence must match proof_policy.evidence")
            if policy.get("status") == "checked" and compatible_proof_types(document):
                errors.append("proof_route_unavailable contradicts an accepted proof type compatible with operating_mode")
            if policy.get("status") not in {"checked", "unavailable"}:
                errors.append("proof_route_unavailable requires a checked or attempted-and-unavailable proof policy")
        if basis == "contestability":
            if contestability.get("status") != "checked":
                errors.append("contestability rotation requires contestability.status checked")
            if not same_evidence(decision.get("evidence"), contestability.get("evidence")):
                errors.append("contestability rotation decision.evidence must match contestability.evidence")
            require_text(decision, "alternative_target", "decision", errors)

    else:  # HOLD
        if decision.get("rotation_basis") not in (None, ""):
            errors.append("HOLD requires decision.rotation_basis null")
        missing = decision.get("missing_evidence")
        if not isinstance(missing, list) or not missing or any(not text(item) for item in missing):
            errors.append("HOLD requires non-empty decision.missing_evidence")


def validate_target(document: dict[str, Any], errors: list[str]) -> None:
    validate_target_identity(document, errors)
    validate_scope(document, errors)
    decision = document.get("decision") if isinstance(document.get("decision"), dict) else {}
    disposition = decision.get("disposition")
    basis = decision.get("rotation_basis")
    gate = decision.get("gate")

    # Deep campaign state is owed only after selection. Early rotations and
    # holds validate the block that supports their gate without demanding an
    # architecture map for a target that was already ruled out.
    if disposition == "SELECTED":
        validate_proof_policy(document, errors)
        validate_contestability(document, errors)
        validate_prior_outcomes(document, errors)
        validate_coverage_delta(document, errors)
        validate_architecture_and_hypotheses(document, errors)
        validate_campaign(document, errors)
    else:
        if basis == "proof_route_unavailable" or gate == "proof_policy":
            validate_proof_policy(document, errors)
        if basis == "contestability" or gate == "contestability":
            validate_contestability(document, errors)
    validate_target_decision(document, errors)
    validate_target_evidence_order(document, errors)


def validate_target_evidence_order(document: dict[str, Any], errors: list[str]) -> None:
    """Keep mutable evidence coherent with the target decision timestamp."""
    decision = document.get("decision")
    decided_at = parse_timestamp(decision.get("decided_at")) if isinstance(decision, dict) else None
    if decided_at is None:
        return
    for key in ("scope", "proof_policy", "contestability", "prior_outcomes", "coverage_delta"):
        block = document.get(key)
        checked_at = block.get("checked_at") if isinstance(block, dict) else None
        checked = parse_timestamp(checked_at)
        if checked is not None and checked > decided_at:
            errors.append(f"{key}.checked_at must be no later than decision.decided_at")


def target_fingerprint(target: dict[str, Any]) -> str:
    """Return a stable fingerprint for the selected target identity.

    Campaign queue state and evidence timestamps are intentionally excluded:
    promoting or closing a hypothesis must not invalidate candidates already
    bound to the same repository/revision and route.
    """
    identity = {
        key: canonical_target_value(target, key)
        for key in (
            "target_id", "platform", "route_type", "asset_type", "program",
            "asset", "repository", "commit", "operating_mode",
        )
    }
    scope = target.get("scope")
    if isinstance(scope, dict):
        identity["scope_asset_identifier"] = scope.get("asset_identifier")
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def scope_evidence_summary(target: dict[str, Any]) -> str:
    """Return the exact scope provenance copied into legacy candidate fields."""
    scope = target.get("scope") if isinstance(target.get("scope"), dict) else {}
    evidence = scope.get("evidence") if isinstance(scope.get("evidence"), dict) else {}
    source = evidence.get("source")
    artifact = evidence.get("artifact")
    if text(source) and text(artifact):
        return f"{source.strip()} ({artifact.strip()})"
    status = scope.get("status", "unknown")
    reason = scope.get("reason")
    if text(reason):
        return f"{status}: {reason.strip()}"
    return str(status)


def canonical_target_value(target: dict[str, Any], key: str) -> Any:
    value = target.get(key)
    if key in {"repository", "commit"} and not text(value):
        return f"not_applicable:{target.get('asset_type', 'asset')}"
    return value
