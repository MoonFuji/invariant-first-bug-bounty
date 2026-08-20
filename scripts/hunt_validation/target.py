"""Gate-aware target-ledger validation."""
from __future__ import annotations

from typing import Any

from .common import require_evidence, require_iso, require_text, text

TARGET_SCHEMA_VERSION = 2
TARGET_DISPOSITIONS = {"SELECTED", "ROTATED", "HOLD"}
TARGET_GATES = {"scope", "proof_policy", "route", "saturation", "selection"}
ROTATION_BASES = {
    "scope_ineligible",
    "proof_route_unavailable",
    "route_unavailable",
    "saturation",
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
EVIDENCE_STATUSES = {"checked", "unavailable", "not_applicable", "unassessed"}
ACCEPTED_PROOF_TYPES = {
    "static-source-trace", "executable-local-exact-path", "regression-test",
    "researcher-owned-deployment", "program-hosted-owned-account",
    "maintainer-fix-or-cve", "hardware-reproduction",
}
SOURCE_ONLY_PROOF_TYPES = {
    "executable-local-exact-path", "regression-test",
    "researcher-owned-deployment", "maintainer-fix-or-cve", "hardware-reproduction",
}
PROGRAM_HOSTED_PROOF_TYPES = {
    "program-hosted-owned-account", "researcher-owned-deployment",
    "executable-local-exact-path", "regression-test",
}


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
    require_iso(scope.get("checked_at"), "scope.checked_at", errors)
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
        require_iso(policy.get("checked_at"), "proof_policy.checked_at", errors)
        require_evidence(policy.get("evidence"), "proof_policy.evidence", errors)
        accepted = policy.get("accepted_proof_types")
        if not isinstance(accepted, list) or not accepted:
            errors.append("proof_policy.accepted_proof_types must contain at least one proof type")
        else:
            invalid = [item for item in accepted if item not in ACCEPTED_PROOF_TYPES]
            if invalid:
                errors.append("proof_policy.accepted_proof_types contains an invalid proof type")
    elif status == "unavailable":
        require_text(policy, "reason", "proof_policy", errors)
        require_iso(policy.get("checked_at"), "proof_policy.checked_at", errors)
        require_evidence(policy.get("evidence"), "proof_policy.evidence", errors, attempted=True)
    elif status == "not_applicable":
        require_text(policy, "reason", "proof_policy", errors)


def validate_saturation(document: dict[str, Any], errors: list[str]) -> None:
    sat = document.get("saturation")
    if not isinstance(sat, dict):
        errors.append("target.saturation must be an object")
        return
    status = sat.get("status")
    if status not in EVIDENCE_STATUSES:
        errors.append("saturation.status must be one of " + ", ".join(sorted(EVIDENCE_STATUSES)))
        return
    if status == "checked":
        count = sat.get("asset_resolved_count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            errors.append("saturation.asset_resolved_count must be a non-negative integer")
        if not isinstance(sat.get("discloses_reports"), bool):
            errors.append("saturation.discloses_reports must be a boolean")
        require_iso(sat.get("checked_at"), "saturation.checked_at", errors)
        require_evidence(sat.get("evidence"), "saturation.evidence", errors)
        require_text(sat, "rationale", "saturation", errors)
    elif status == "unavailable":
        require_text(sat, "reason", "saturation", errors)
        require_iso(sat.get("checked_at"), "saturation.checked_at", errors)
        require_evidence(sat.get("evidence"), "saturation.evidence", errors, attempted=True)
        require_text(sat, "rationale", "saturation", errors)
    elif status == "not_applicable":
        require_text(sat, "reason", "saturation", errors)


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
    require_iso(decision.get("decided_at"), "decision.decided_at", errors)
    missing = decision.get("missing_evidence")
    if not isinstance(missing, list) or any(not text(item) for item in missing):
        errors.append("decision.missing_evidence must be an array of non-empty strings")

    scope = document.get("scope") if isinstance(document.get("scope"), dict) else {}
    policy = document.get("proof_policy") if isinstance(document.get("proof_policy"), dict) else {}
    sat = document.get("saturation") if isinstance(document.get("saturation"), dict) else {}
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
        if sat.get("status") != "checked":
            errors.append("SELECTED targets require checked asset-level saturation")
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
            "saturation": "saturation",
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
        if basis == "saturation":
            if sat.get("status") != "checked":
                errors.append("saturation rotation requires saturation.status checked")
            if not same_evidence(decision.get("evidence"), sat.get("evidence")):
                errors.append("saturation rotation decision.evidence must match saturation.evidence")
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
    validate_proof_policy(document, errors)
    validate_saturation(document, errors)
    validate_target_decision(document, errors)


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

