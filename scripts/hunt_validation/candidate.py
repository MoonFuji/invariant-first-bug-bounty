"""Candidate binding, claim scope, and clean-review validation."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

from .common import (
    ValidationError,
    normalized,
    require_not_future,
    require_ordered,
    require_text,
    require_timestamp,
    text,
)
from .target import canonical_target_value, scope_evidence_summary, target_fingerprint

CAVEAT_CLASSIFICATIONS = {"load_bearing", "ordinary"}
CANDIDATE_SCHEMA_VERSION = 6
RECOVERY_CLASSES = {"NONE", "RECOVER", "NARROW", "OPERATOR_REQUIRED"}
CLAIM_RUNGS = (
    "none",
    "primitive",
    "exact_executable",
    "owned_boundary",
    "demonstrated_impact",
    "severity",
)
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def validate_candidate_schema(document: dict[str, Any], errors: list[str]) -> None:
    if document.get("schema_version") != CANDIDATE_SCHEMA_VERSION:
        errors.append(
            f"candidate.schema_version must be {CANDIDATE_SCHEMA_VERSION}; "
            "older candidates require deliberate review and manual upgrade"
        )
    for key in (
        "candidate_id",
        "campaign_id",
        "target_fingerprint",
        "boundary_id",
        "hypothesis_id",
    ):
        require_text(document, key, "candidate", errors)


def validate_claim_scope_and_recovery(document: dict[str, Any], errors: list[str]) -> None:
    proof = document.get("proof") if isinstance(document.get("proof"), dict) else {}
    supporting = proof.get("supporting_evidence_types")
    if not isinstance(supporting, list):
        errors.append("proof.supporting_evidence_types must be an array")
    elif any(item != "static-source-trace" for item in supporting):
        errors.append("proof.supporting_evidence_types only accepts static-source-trace")
    if proof.get("type") == "static-source-trace":
        errors.append(
            "proof.type static-source-trace cannot be final proof; record it as supporting evidence "
            "and prove the exact executable or hosted path"
        )

    claim = document.get("claim_scope")
    if not isinstance(claim, dict):
        errors.append("candidate.claim_scope must be an object")
        return
    rung = claim.get("highest_proven_rung")
    if rung not in CLAIM_RUNGS:
        errors.append("claim_scope.highest_proven_rung must be one of " + ", ".join(CLAIM_RUNGS))
    for key in ("demonstrated_capability", "demonstrated_impact", "severity_ceiling"):
        if not isinstance(claim.get(key), str):
            errors.append(f"claim_scope.{key} must be a string")
    unsupported = claim.get("unsupported_extensions")
    if not isinstance(unsupported, list) or any(not text(item) for item in unsupported):
        errors.append("claim_scope.unsupported_extensions must be an array of non-empty strings")

    recovery = document.get("recovery")
    if not isinstance(recovery, dict):
        errors.append("candidate.recovery must be an object")
        return
    classification = recovery.get("classification")
    if classification not in RECOVERY_CLASSES:
        errors.append("recovery.classification must be one of " + ", ".join(sorted(RECOVERY_CLASSES)))
        return
    verdict = document.get("decision", {}).get("verdict") if isinstance(document.get("decision"), dict) else None
    if verdict == "REPORTABLE":
        for key in ("demonstrated_capability", "demonstrated_impact"):
            if not text(claim.get(key)):
                errors.append(f"REPORTABLE requires non-empty claim_scope.{key}")
        if claim.get("severity_ceiling") not in SEVERITY_RANK:
            errors.append(
                "REPORTABLE requires claim_scope.severity_ceiling informational, low, medium, high, or critical"
            )
        if rung not in CLAIM_RUNGS[2:]:
            errors.append("REPORTABLE requires at least an exact_executable highest_proven_rung")
    if classification == "NONE":
        return
    failed_rung = recovery.get("failed_rung")
    if failed_rung not in CLAIM_RUNGS[1:]:
        errors.append("recovery.failed_rung must identify a concrete claim rung")
    require_text(recovery, "next_action", "recovery", errors)
    if classification in {"RECOVER", "OPERATOR_REQUIRED"}:
        require_text(recovery, "required_artifact", "recovery", errors)
        if verdict == "REPORTABLE":
            errors.append(f"recovery.classification {classification} forbids REPORTABLE until resolved")
    elif classification == "NARROW":
        require_text(recovery, "surviving_claim", "recovery", errors)
        if not unsupported:
            errors.append("NARROW requires claim_scope.unsupported_extensions to record dropped claims")
        if rung in {"none", "primitive"} and verdict == "REPORTABLE":
            errors.append("NARROW cannot be REPORTABLE without at least an exact executable claim")


def validate_candidate_timestamps(document: dict[str, Any], errors: list[str]) -> None:
    decision = document.get("decision") if isinstance(document.get("decision"), dict) else {}
    require_not_future(decision.get("decided_at"), "decision.decided_at", errors)
    hardening = document.get("hardening") if isinstance(document.get("hardening"), dict) else {}
    if hardening.get("status") == "done":
        require_not_future(hardening.get("completed_at"), "hardening.completed_at", errors)
        require_ordered(
            hardening.get("completed_at"),
            "hardening.completed_at",
            decision.get("decided_at"),
            "decision.decided_at",
            errors,
        )


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

    version = candidate.get("schema_version")
    if version == CANDIDATE_SCHEMA_VERSION:
        campaign = target.get("campaign") if isinstance(target.get("campaign"), dict) else {}
        if candidate.get("campaign_id") != campaign.get("campaign_id"):
            errors.append("candidate.campaign_id must match target.campaign.campaign_id")
        if candidate.get("target_fingerprint") != target_fingerprint(target):
            errors.append(
                "candidate.target_fingerprint does not match the stable target identity; "
                "create a new candidate when the asset, revision, route, or operating mode changes"
            )
        lifecycle = target.get("hypothesis_lifecycle")
        matches = [
            hypothesis for hypothesis in lifecycle
            if isinstance(hypothesis, dict)
            and hypothesis.get("hypothesis_id") == candidate.get("hypothesis_id")
        ] if isinstance(lifecycle, list) else []
        if len(matches) != 1:
            errors.append("candidate.hypothesis_id must identify exactly one target hypothesis")
        else:
            hypothesis = matches[0]
            if hypothesis.get("boundary_id") != candidate.get("boundary_id"):
                errors.append("candidate.boundary_id must match the bound target hypothesis")
            if hypothesis.get("status") not in {"investigating", "closed"}:
                errors.append(
                    "candidate hypothesis must be investigating or closed; "
                    "queued or parked hypotheses cannot validate this candidate"
                )
            if hypothesis.get("status") == "closed":
                if hypothesis.get("candidate_id") != candidate.get("candidate_id"):
                    errors.append("closed hypothesis candidate_id must match the candidate")
                verdict = candidate.get("decision", {}).get("verdict") if isinstance(candidate.get("decision"), dict) else None
                if hypothesis.get("terminal_verdict") != verdict:
                    errors.append("closed hypothesis terminal_verdict must match candidate.decision.verdict")

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

    # Schema 6 binds the immutable identity above. Mutable scope and
    # contestability evidence may be refreshed in the target ledger without
    # invalidating a technically unchanged candidate. Legacy records retain
    # their exact copied-evidence checks when these helpers are imported.
    if version != CANDIDATE_SCHEMA_VERSION:
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

    scope = target.get("scope") if isinstance(target.get("scope"), dict) else {}
    claim = candidate.get("claim_scope") if isinstance(candidate.get("claim_scope"), dict) else {}
    target_max = scope.get("max_severity")
    candidate_ceiling = claim.get("severity_ceiling")
    if target_max in SEVERITY_RANK and candidate_ceiling in SEVERITY_RANK:
        if SEVERITY_RANK[candidate_ceiling] > SEVERITY_RANK[target_max]:
            errors.append("candidate.claim_scope.severity_ceiling exceeds target.scope.max_severity")

    contestability = target.get("contestability") if isinstance(target.get("contestability"), dict) else {}
    novelty = candidate.get("novelty") if isinstance(candidate.get("novelty"), dict) else {}
    private_context = (
        contestability.get("basis") == "private_unavailable"
        or contestability.get("discloses_reports") is False
        or (
            target.get("route_type") in {"bounty", "vdp"}
            and contestability.get("discloses_reports") is not True
        )
    )
    risk = novelty.get("private_duplicate_risk")
    if private_context and risk == "low":
        errors.append(
            "an invisible private report pool cannot support low private_duplicate_risk; "
            "assess medium/high and state the uncertainty"
        )
    if private_context or risk == "high":
        require_text(novelty, "collision_differentiator", "novelty", errors)


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
