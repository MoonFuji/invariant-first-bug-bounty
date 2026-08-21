"""Candidate binding, reviewer attestation, and clean-review validation."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

from .common import ValidationError, normalized, parse_iso, require_iso, require_text, text
from .target import canonical_target_value, scope_evidence_summary

FINAL_REVIEW_MODES = {"independent_agent", "human"}
REVIEW_MODES = FINAL_REVIEW_MODES | {"self", "owed"}
CAVEAT_CLASSIFICATIONS = {"load_bearing", "ordinary"}


def load_candidate_validator() -> ModuleType:
    path = Path(__file__).resolve().parent.parent / "validate-candidate.py"
    spec = importlib.util.spec_from_file_location("candidate_validator", path)
    if spec is None or spec.loader is None:
        raise ValidationError(f"cannot load candidate validator: {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (OSError, ImportError, SyntaxError) as exc:
        raise ValidationError(f"cannot load candidate validator {path}: {exc}") from exc
    return module


def review_attestation(document: dict[str, Any]) -> dict[str, Any] | None:
    review = document.get("adversarial_review")
    if not isinstance(review, dict):
        return None
    reviewer = review.get("reviewer")
    if isinstance(reviewer, dict):
        return reviewer
    # Legacy string form is normalized here so old candidates fail clearly or
    # remain provisional instead of silently passing as independent.
    if isinstance(reviewer, str):
        mode = normalized(reviewer)
        return {"mode": mode, "id": reviewer.strip()}
    return None


def validate_review_attestation(
    document: dict[str, Any],
    errors: list[str],
    *,
    allow_owed: bool,
) -> str:
    reviewer = review_attestation(document)
    if reviewer is None:
        errors.append("adversarial_review.reviewer must be a structured review attestation")
        return ""
    mode = normalized(reviewer.get("mode"))
    if mode not in REVIEW_MODES:
        errors.append("adversarial_review.reviewer.mode must be self, owed, independent_agent, or human")
        return mode
    if mode in FINAL_REVIEW_MODES:
        require_text(reviewer, "id", "adversarial_review.reviewer", errors)
        require_iso(reviewer.get("reviewed_at"), "adversarial_review.reviewer.reviewed_at", errors)
        require_text(reviewer, "artifact", "adversarial_review.reviewer", errors)
        if mode == "independent_agent" and reviewer.get("fresh_context") is not True:
            errors.append("independent_agent review requires reviewer.fresh_context true")
    elif mode == "self":
        errors.append("REPORTABLE/NO_REPORTABLE_FINDING may not be self-certified")
    elif mode == "owed" and not allow_owed:
        errors.append("final report stage requires completed independent review; use decision stage for provisional output")
    return mode


def validate_caveat_ledger(document: dict[str, Any], errors: list[str]) -> None:
    """Every hedge surfaced by the one-sentence attacker-model test must be
    recorded and classified. Classification stays a judgment; the ledger makes
    it explicit and auditable instead of silent. A self-classified
    load-bearing caveat forbids REPORTABLE until evidence removes it."""
    decision = document.get("decision") if isinstance(document.get("decision"), dict) else {}
    if decision.get("verdict") != "REPORTABLE":
        return
    caveats = document.get("caveats")
    if not isinstance(caveats, list):
        errors.append(
            "REPORTABLE requires a caveats[] ledger with one {quote, classification, justification} "
            "entry per hedge surfaced by the attacker-model test"
        )
        return
    for index, caveat in enumerate(caveats):
        path = f"caveats[{index}]"
        if not isinstance(caveat, dict):
            errors.append(f"{path} must be an object")
            continue
        for key in ("quote", "classification", "justification"):
            if not text(caveat.get(key)):
                errors.append(f"{path}.{key} must be a non-empty string")
        classification = normalized(caveat.get("classification"))
        if classification and classification not in CAVEAT_CLASSIFICATIONS:
            errors.append(f"{path}.classification must be load_bearing or ordinary")
    if any(
        isinstance(caveat, dict) and normalized(caveat.get("classification")) == "load_bearing"
        for caveat in caveats
    ):
        errors.append(
            "a load-bearing caveat forbids REPORTABLE: remove it with evidence and record that "
            "evidence in the justification, narrow the claim to what survived, or decide HOLD/KILL"
        )


def validate_closure_review(
    document: dict[str, Any],
    errors: list[str],
    *,
    provisional: bool,
    warnings: list[str] | None = None,
) -> None:
    clean = document.get("closure_review")
    if not isinstance(clean, dict):
        errors.append("NO_REPORTABLE_FINDING requires a closure_review block")
        return
    if provisional:
        if clean.get("verdict") not in {"UNREVIEWED", "OWED"}:
            errors.append("provisional closure_review.verdict must be UNREVIEWED or OWED")
        return
    if clean.get("verdict") != "DEPTH_SUFFICIENT":
        errors.append("final NO_REPORTABLE_FINDING requires closure_review.verdict DEPTH_SUFFICIENT")

    cold = document.get("adversarial_review", {}).get("cold_verify") if isinstance(document.get("adversarial_review"), dict) else None
    if not isinstance(cold, dict):
        errors.append("final NO_REPORTABLE_FINDING requires adversarial_review.cold_verify")
    else:
        if cold.get("verdict") != "DISPROVED":
            errors.append("final NO_REPORTABLE_FINDING requires cold_verify.verdict DISPROVED; UNCERTAIN is HOLD")
        if not text(cold.get("rederived_severity")):
            errors.append("DISPROVED clean closure requires cold_verify.rederived_severity (usually an evidenced n/a)")
        if not text(cold.get("killed_subclaim")):
            errors.append("DISPROVED clean closure requires cold_verify.killed_subclaim")
        subclaims = cold.get("subclaims")
        unsupported = False
        if not isinstance(subclaims, list) or len(subclaims) < 2:
            errors.append("DISPROVED clean closure requires at least two cold_verify.subclaims")
        else:
            for index, subclaim in enumerate(subclaims):
                path = f"adversarial_review.cold_verify.subclaims[{index}]"
                if not isinstance(subclaim, dict):
                    errors.append(f"{path} must be an object")
                    continue
                for key in ("claim", "status", "evidence"):
                    if not text(subclaim.get(key)):
                        errors.append(f"{path}.{key} must be a non-empty string")
                status = normalized(subclaim.get("status"))
                if status not in {"supported", "unsupported"}:
                    errors.append(f"{path}.status must be supported or unsupported")
                if status == "unsupported":
                    unsupported = True
            if not unsupported:
                errors.append("DISPROVED clean closure requires at least one unsupported subclaim")

    closures = clean.get("closures_challenged")
    if not isinstance(closures, list) or not closures:
        errors.append("closure_review.closures_challenged must contain at least one challenged closure")
    else:
        for index, closure in enumerate(closures):
            path = f"closure_review.closures_challenged[{index}]"
            if not isinstance(closure, dict):
                errors.append(f"{path} must be an object")
                continue
            for key in ("hypothesis", "closure", "challenge", "evidence"):
                if not text(closure.get(key)):
                    errors.append(f"{path}.{key} must be a non-empty string")

    probe = clean.get("probe_assessment")
    if not isinstance(probe, dict):
        errors.append("closure_review.probe_assessment must be an object")
    else:
        sufficient = probe.get("sufficient")
        waived = probe.get("waived") is True
        if sufficient is not True and not waived:
            errors.append("closure_review requires a sufficient adversarial probe or an evidenced waiver")
        require_text(probe, "evidence", "closure_review.probe_assessment", errors)
        if waived:
            require_text(probe, "waiver_reason", "closure_review.probe_assessment", errors)

    # These arrays feed the next campaign step. A candidate-level
    # NO_REPORTABLE_FINDING may close while other hypotheses remain; silently
    # erasing them would recreate the stop-after-one-candidate failure.
    for key in ("coverage_gaps", "remaining_high_value_hypotheses"):
        value = clean.get(key)
        if not isinstance(value, list):
            errors.append(f"closure_review.{key} must be an array")
        elif any(not text(item) for item in value):
            errors.append(f"closure_review.{key} items must be non-empty strings")

    if (
        warnings is not None
        and clean.get("verdict") == "DEPTH_SUFFICIENT"
        and not clean.get("coverage_gaps")
        and not clean.get("remaining_high_value_hypotheses")
    ):
        warnings.append(
            "clean closure claims no coverage gaps and no remaining high-value hypotheses; "
            "ensure the exhaustion record genuinely supports a fully covered target"
        )


def validate_probe_shapes(document: dict[str, Any], warnings: list[str]) -> None:
    if document.get("decision", {}).get("verdict") != "NO_REPORTABLE_FINDING":
        return
    probes = document.get("exhaustion", {}).get("probes") if isinstance(document.get("exhaustion"), dict) else None
    required = {
        "hypothesis", "command", "would_fire_if_vulnerable",
        "observed", "result", "origin",
    }
    good = False
    if isinstance(probes, list):
        for probe in probes:
            if (
                isinstance(probe, dict)
                and all(text(probe.get(key)) for key in required)
                and normalized(probe.get("result")) == "negative"
                and normalized(probe.get("origin")) == "researcher_adversarial"
            ):
                good = True
                break
    closure = document.get("closure_review")
    assessment = closure.get("probe_assessment") if isinstance(closure, dict) else None
    waived = (
        isinstance(assessment, dict)
        and assessment.get("waived") is True
        and text(assessment.get("waiver_reason"))
        and text(assessment.get("evidence"))
    )
    if not good and not waived:
        warnings.append(
            "NO_REPORTABLE_FINDING has no fully recorded researcher-designed adversarial probe; each "
            "probe needs hypothesis, command, would_fire_if_vulnerable, observed, result=negative, "
            "and origin=researcher_adversarial (or an independently evidenced waiver)"
        )


def validate_candidate_target_binding(
    candidate: dict[str, Any],
    target: dict[str, Any],
    errors: list[str],
) -> None:
    decision = target.get("decision") if isinstance(target.get("decision"), dict) else {}
    if decision.get("disposition") != "SELECTED":
        errors.append("candidate stages require a target ledger whose decision.disposition is SELECTED")

    if candidate.get("target_ledger_id") != target.get("target_id"):
        errors.append("candidate.target_ledger_id must match target.target_id")

    ctarget = candidate.get("target") if isinstance(candidate.get("target"), dict) else {}
    for candidate_key, target_key in (
        ("platform", "platform"),
        ("route_type", "route_type"),
        ("asset_type", "asset_type"),
        ("program", "program"),
        ("asset", "asset"),
        ("repository", "repository"),
        ("commit", "commit"),
        ("operating_mode", "operating_mode"),
    ):
        if ctarget.get(candidate_key) != canonical_target_value(target, target_key):
            errors.append(f"candidate.target.{candidate_key} must match target ledger {target_key}")

    scope = target.get("scope") if isinstance(target.get("scope"), dict) else {}
    if ctarget.get("scope_checked_at") != scope.get("checked_at"):
        errors.append("candidate.target.scope_checked_at must match target.scope.checked_at")
    expected_scope_evidence = scope_evidence_summary(target)
    if ctarget.get("scope_evidence") != expected_scope_evidence:
        errors.append("candidate.target.scope_evidence must identify the target ledger scope artifact")

    csat = ctarget.get("saturation") if isinstance(ctarget.get("saturation"), dict) else {}
    tsat = target.get("saturation") if isinstance(target.get("saturation"), dict) else {}
    if tsat.get("status") == "checked" and csat.get("discloses_reports") != tsat.get("discloses_reports"):
        errors.append("candidate.target.saturation.discloses_reports must match the target ledger")


def validate_final_review_order(document: dict[str, Any], errors: list[str]) -> None:
    """Catch obvious review-before-final-artifact and post-review decision drift."""
    reviewer = review_attestation(document)
    if not isinstance(reviewer, dict) or normalized(reviewer.get("mode")) not in FINAL_REVIEW_MODES:
        return
    reviewed_at = parse_iso(reviewer.get("reviewed_at"))
    decided_at = parse_iso(document.get("decision", {}).get("decided_at") if isinstance(document.get("decision"), dict) else None)
    if reviewed_at is not None and decided_at is not None and reviewed_at > decided_at:
        errors.append("adversarial review must be completed before decision.decided_at")

    if document.get("decision", {}).get("verdict") == "REPORTABLE":
        hardening = document.get("hardening") if isinstance(document.get("hardening"), dict) else {}
        require_iso(hardening.get("completed_at"), "hardening.completed_at", errors)
        hardened_at = parse_iso(hardening.get("completed_at"))
        if reviewed_at is not None and hardened_at is not None and reviewed_at < hardened_at:
            errors.append("final adversarial review must run after hardening.completed_at")


PROOF_TYPE_TO_LEDGER_TYPES = {
    "live-two-identity": {"program-hosted-owned-account"},
    "live-deployed": {"researcher-owned-deployment", "program-hosted-owned-account"},
    "executable-local-exact-path": {"executable-local-exact-path"},
    "regression-test": {"regression-test"},
    "maintainer-fix-or-cve": {"maintainer-fix-or-cve"},
    "hardware-reproduction": {"hardware-reproduction"},
}
ROUTE_TYPE_TO_CANDIDATE = {
    "bounty": "program",
    "vdp": "program",
    "upstream-advisory": "upstream-advisory",
    "ibb": "ibb",
    "vendor": "vendor",
}


def validate_report_target_contract(
    candidate: dict[str, Any],
    target: dict[str, Any],
    errors: list[str],
) -> None:
    """Bind the final report's route and proof type to the selected ledger."""
    policy = target.get("proof_policy") if isinstance(target.get("proof_policy"), dict) else {}
    accepted = policy.get("accepted_proof_types")
    accepted_set = set(accepted) if isinstance(accepted, list) else set()
    proof = candidate.get("proof") if isinstance(candidate.get("proof"), dict) else {}
    proof_type = proof.get("type")
    mapped = PROOF_TYPE_TO_LEDGER_TYPES.get(proof_type, set())
    if not mapped.intersection(accepted_set):
        errors.append(
            "candidate proof.type is not one of the proof routes accepted by the selected target ledger"
        )

    route = candidate.get("route") if isinstance(candidate.get("route"), dict) else {}
    expected_route = ROUTE_TYPE_TO_CANDIDATE.get(target.get("route_type"))
    if expected_route is not None and route.get("type") != expected_route:
        errors.append(
            f"REPORTABLE candidate route.type must be {expected_route} for target route_type "
            f"{target.get('route_type')}"
        )


def run_candidate_validator(
    module: ModuleType,
    document: dict[str, Any],
    stage: str,
    errors: list[str],
) -> None:
    if stage == "model":
        module.validate_model(document, errors)
    elif stage == "decision":
        module.validate_decision(document, errors)
    else:
        module.validate_report(document, errors)

