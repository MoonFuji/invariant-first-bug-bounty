"""Lean target validation plus optional campaign-mode bookkeeping."""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from typing import Any

from .common import (
    require_evidence,
    require_not_future,
    require_string_list,
    require_text,
    text,
)

TARGET_SCHEMA_VERSION = 4
CAMPAIGN_SCHEMA_VERSION = 1

TARGET_DISPOSITIONS = {"SELECTED", "ROTATED", "HOLD"}
TARGET_GATES = {"scope", "proof_policy", "route", "selection"}
ROTATION_BASES = {
    "scope_ineligible",
    "proof_route_unavailable",
    "route_unavailable",
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
SCOPE_STATUSES = {"eligible", "ineligible", "unknown", "not_applicable"}
MAX_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
PROOF_POLICY_STATUSES = {"checked", "unavailable", "unassessed", "not_applicable"}
ACCEPTED_PROOF_TYPES = {
    "executable-local-exact-path",
    "regression-test",
    "researcher-owned-deployment",
    "program-hosted-owned-account",
    "maintainer-fix-or-cve",
    "hardware-reproduction",
}
SOURCE_ONLY_PROOF_TYPES = {
    "executable-local-exact-path",
    "regression-test",
    "researcher-owned-deployment",
    "maintainer-fix-or-cve",
    "hardware-reproduction",
}
PROGRAM_HOSTED_PROOF_TYPES = {
    "program-hosted-owned-account",
    "researcher-owned-deployment",
    "executable-local-exact-path",
    "regression-test",
}
TARGET_EVIDENCE_MAX_AGE = timedelta(days=90)

CAMPAIGN_MODES = {"first_finding", "bounded", "exhaustive"}
CAMPAIGN_STATUSES = {"open", "closed"}
HYPOTHESIS_STATUSES = {"queued", "investigating", "closed", "parked"}
HYPOTHESIS_PRIORITIES = {"high", "medium", "low"}
TERMINAL_VERDICTS = {"REPORTABLE", "KILL", "ROUTE_ELSEWHERE"}


def canonical_target_value(target: dict[str, Any], key: str) -> Any:
    value = target.get(key)
    if key in {"repository", "commit"} and not text(value):
        return f"not_applicable:{target.get('asset_type', 'asset')}"
    return value


def target_fingerprint(target: dict[str, Any]) -> str:
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


def compatible_proof_types(target: dict[str, Any]) -> set[str]:
    policy = target.get("proof_policy")
    if not isinstance(policy, dict) or policy.get("status") != "checked":
        return set()
    accepted = policy.get("accepted_proof_types")
    if not isinstance(accepted, list):
        return set()
    mode = target.get("operating_mode")
    allowed = SOURCE_ONLY_PROOF_TYPES if mode == "SOURCE_ONLY" else PROGRAM_HOSTED_PROOF_TYPES
    return set(accepted).intersection(allowed)


def validate_target_identity(target: dict[str, Any], errors: list[str]) -> None:
    if target.get("schema_version") != TARGET_SCHEMA_VERSION:
        errors.append(f"target.schema_version must be {TARGET_SCHEMA_VERSION}")
    for key in ("target_id", "program", "asset"):
        require_text(target, key, "target", errors)
    if target.get("platform") not in PLATFORMS:
        errors.append("target.platform is invalid")
    if target.get("route_type") not in ROUTE_TYPES:
        errors.append("target.route_type is invalid")
    if target.get("asset_type") not in ASSET_TYPES:
        errors.append("target.asset_type is invalid")
    if target.get("operating_mode") not in OPERATING_MODES:
        errors.append("target.operating_mode must be SOURCE_ONLY or PROGRAM_HOSTED")

    if target.get("asset_type") in {"repository", "library", "cli", "sdk"}:
        require_text(target, "repository", "target", errors)
        require_text(target, "commit", "target", errors)
    else:
        for key in ("repository", "commit"):
            value = target.get(key)
            if value is not None and not isinstance(value, str):
                errors.append(f"target.{key} must be a string or null")


def validate_scope(target: dict[str, Any], errors: list[str]) -> None:
    scope = target.get("scope")
    if not isinstance(scope, dict):
        errors.append("target.scope must be an object")
        return
    status = scope.get("status")
    if status not in SCOPE_STATUSES:
        errors.append("scope.status is invalid")
        return
    require_text(scope, "asset_identifier", "scope", errors)
    max_severity = scope.get("max_severity")
    if status == "eligible" and max_severity not in MAX_SEVERITIES:
        errors.append("scope.max_severity must be informational, low, medium, high, or critical for eligible scope")
    elif text(max_severity) and max_severity not in MAX_SEVERITIES:
        errors.append("scope.max_severity is invalid when provided")

    if status in {"eligible", "ineligible", "unknown"}:
        require_not_future(
            scope.get("checked_at"),
            "scope.checked_at",
            errors,
            max_age=TARGET_EVIDENCE_MAX_AGE,
        )
        require_evidence(scope.get("evidence"), "scope.evidence", errors)
    if status in {"ineligible", "unknown", "not_applicable"}:
        require_text(scope, "reason", "scope", errors)


def validate_proof_policy(target: dict[str, Any], errors: list[str]) -> None:
    policy = target.get("proof_policy")
    if not isinstance(policy, dict):
        errors.append("target.proof_policy must be an object")
        return
    status = policy.get("status")
    if status not in PROOF_POLICY_STATUSES:
        errors.append("proof_policy.status is invalid")
        return
    if status == "checked":
        require_text(policy, "quote", "proof_policy", errors)
        require_not_future(
            policy.get("checked_at"),
            "proof_policy.checked_at",
            errors,
            max_age=TARGET_EVIDENCE_MAX_AGE,
        )
        require_evidence(policy.get("evidence"), "proof_policy.evidence", errors)
        accepted = require_string_list(
            policy.get("accepted_proof_types"),
            "proof_policy.accepted_proof_types",
            errors,
            nonempty=True,
        )
        invalid = [item for item in accepted if item not in ACCEPTED_PROOF_TYPES]
        if invalid:
            errors.append(
                "proof_policy.accepted_proof_types contains invalid final proof types: "
                + ", ".join(invalid)
            )
    elif status == "unavailable":
        require_text(policy, "reason", "proof_policy", errors)
        require_not_future(
            policy.get("checked_at"),
            "proof_policy.checked_at",
            errors,
            max_age=TARGET_EVIDENCE_MAX_AGE,
        )
        require_evidence(policy.get("evidence"), "proof_policy.evidence", errors)
    elif status == "not_applicable":
        require_text(policy, "reason", "proof_policy", errors)


def _same_evidence(left: Any, right: Any) -> bool:
    return (
        isinstance(left, dict)
        and isinstance(right, dict)
        and all(left.get(key) == right.get(key) for key in ("method", "source", "artifact"))
    )


def validate_target_decision(target: dict[str, Any], errors: list[str]) -> None:
    decision = target.get("decision")
    if not isinstance(decision, dict):
        errors.append("target.decision must be an object")
        return
    disposition = decision.get("disposition")
    if disposition not in TARGET_DISPOSITIONS:
        errors.append("decision.disposition must be SELECTED, ROTATED, or HOLD")
        return
    gate = decision.get("gate")
    if gate not in TARGET_GATES:
        errors.append("decision.gate is invalid")
    require_text(decision, "reason", "decision", errors)
    missing = require_string_list(decision.get("missing_evidence"), "decision.missing_evidence", errors)
    scope = target.get("scope") if isinstance(target.get("scope"), dict) else {}
    policy = target.get("proof_policy") if isinstance(target.get("proof_policy"), dict) else {}

    if disposition == "SELECTED":
        if scope.get("status") != "eligible":
            errors.append("SELECTED requires scope.status eligible")
        if policy.get("status") != "checked":
            errors.append("SELECTED requires proof_policy.status checked")
        elif not compatible_proof_types(target):
            errors.append("SELECTED requires at least one accepted proof type compatible with operating_mode")
        if missing:
            errors.append("SELECTED requires decision.missing_evidence empty")
        if decision.get("rotation_basis") is not None:
            errors.append("SELECTED requires decision.rotation_basis null")

    elif disposition == "ROTATED":
        basis = decision.get("rotation_basis")
        if basis not in ROTATION_BASES:
            errors.append("ROTATED requires a supported decision.rotation_basis")
            return
        require_evidence(decision.get("evidence"), "decision.evidence", errors)
        if basis == "scope_ineligible":
            if scope.get("status") != "ineligible":
                errors.append("scope_ineligible rotation requires scope.status ineligible")
            if not _same_evidence(decision.get("evidence"), scope.get("evidence")):
                errors.append("scope_ineligible decision.evidence must match scope.evidence")
        elif basis == "proof_route_unavailable":
            if policy.get("status") not in {"checked", "unavailable"}:
                errors.append("proof_route_unavailable requires checked or unavailable proof policy")
            if policy.get("status") == "checked" and compatible_proof_types(target):
                errors.append("proof_route_unavailable contradicts a compatible accepted proof type")
            if not _same_evidence(decision.get("evidence"), policy.get("evidence")):
                errors.append("proof_route_unavailable decision.evidence must match proof_policy.evidence")
        else:
            require_text(decision, "alternative_target", "decision", errors)

    else:
        if not missing:
            errors.append("HOLD requires decision.missing_evidence")


def validate_target(target: dict[str, Any], errors: list[str]) -> None:
    validate_target_identity(target, errors)
    validate_scope(target, errors)
    validate_proof_policy(target, errors)
    validate_target_decision(target, errors)


def validate_campaign(campaign: dict[str, Any], errors: list[str]) -> None:
    """Validate optional orchestration state. This never determines candidate truth."""
    if campaign.get("schema_version") != CAMPAIGN_SCHEMA_VERSION:
        errors.append(f"campaign.schema_version must be {CAMPAIGN_SCHEMA_VERSION}")
    for key in ("campaign_id", "target_id", "stop_condition"):
        require_text(campaign, key, "campaign", errors)
    mode = campaign.get("mode")
    if mode not in CAMPAIGN_MODES:
        errors.append("campaign.mode must be first_finding, bounded, or exhaustive")
    status = campaign.get("status")
    if status not in CAMPAIGN_STATUSES:
        errors.append("campaign.status must be open or closed")

    hypotheses = campaign.get("hypotheses")
    if not isinstance(hypotheses, list) or not hypotheses:
        errors.append("campaign.hypotheses must contain at least one hypothesis")
        return

    ids: set[str] = set()
    for index, item in enumerate(hypotheses):
        path = f"campaign.hypotheses[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{path} must be an object")
            continue
        hypothesis_id = require_text(item, "hypothesis_id", path, errors)
        require_text(item, "boundary", path, errors)
        require_text(item, "statement", path, errors)
        if hypothesis_id:
            if hypothesis_id in ids:
                errors.append(f"{path}.hypothesis_id duplicates another hypothesis")
            ids.add(hypothesis_id)
        if item.get("priority") not in HYPOTHESIS_PRIORITIES:
            errors.append(f"{path}.priority must be high, medium, or low")
        hypothesis_status = item.get("status")
        if hypothesis_status not in HYPOTHESIS_STATUSES:
            errors.append(f"{path}.status is invalid")
        elif hypothesis_status == "closed":
            require_text(item, "candidate_id", path, errors)
            if item.get("verdict") not in TERMINAL_VERDICTS:
                errors.append(f"{path}.verdict must be REPORTABLE, KILL, or ROUTE_ELSEWHERE")
            require_text(item, "reason", path, errors)
        elif hypothesis_status == "parked":
            require_text(item, "reason", path, errors)

    if status == "closed":
        investigating = [
            item.get("hypothesis_id", "?")
            for item in hypotheses
            if isinstance(item, dict) and item.get("status") == "investigating"
        ]
        if investigating:
            errors.append("closed campaign cannot contain investigating hypotheses")
        closed = [item for item in hypotheses if isinstance(item, dict) and item.get("status") == "closed"]
        if mode == "first_finding" and not any(item.get("verdict") == "REPORTABLE" for item in closed):
            errors.append("closed first_finding campaign requires a REPORTABLE hypothesis")
        if mode == "exhaustive" and any(
            isinstance(item, dict) and item.get("status") != "closed" for item in hypotheses
        ):
            errors.append("closed exhaustive campaign requires every hypothesis closed")


def find_campaign_hypothesis(campaign: dict[str, Any], hypothesis_id: str) -> dict[str, Any] | None:
    hypotheses = campaign.get("hypotheses")
    if not isinstance(hypotheses, list):
        return None
    matches = [
        item for item in hypotheses
        if isinstance(item, dict) and item.get("hypothesis_id") == hypothesis_id
    ]
    return matches[0] if len(matches) == 1 else None
