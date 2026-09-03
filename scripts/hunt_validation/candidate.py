"""Lean per-invariant candidate validation."""
from __future__ import annotations
from typing import Any
from .common import require_search_evidence, require_string_list, require_text, text
from .target import MAX_SEVERITIES, canonical_target_value, find_campaign_hypothesis, target_fingerprint

CANDIDATE_SCHEMA_VERSION = 7
VERDICTS = {"REPORTABLE", "HOLD", "KILL", "ROUTE_ELSEWHERE"}
GATES = {"model", "reachability", "capability_delta", "refutation", "proof", "ownership", "novelty", "reportability", "route"}
PROOF_LEVELS = {"primitive", "executable", "boundary"}
PROOF_TYPES = {"none", "live-two-identity", "live-deployed", "executable-local-exact-path", "regression-test", "maintainer-fix-or-cve", "hardware-reproduction"}
FINAL_PROOF_TYPES = PROOF_TYPES - {"none"}
CONFIG_DEPENDENCIES = {"none", "program_shipped_default", "supported_option", "operator_weakened", "test_only", "unknown"}
REFUTATION_RESULTS = {"refuted", "confirmed", "unresolved"}
REFUTATION_KINDS = {"non_terminal", "owned_boundary_absent", "capability_already_possessed", "required_precondition_already_grants_effect", "behavior_is_documented_contract", "target_does_not_own_security_property", "unreachable_under_supported_contract"}
TERMINAL_REFUTATION_KINDS = REFUTATION_KINDS - {"non_terminal"}
ROUTE_TYPES = {"program", "upstream-advisory", "ibb", "vendor"}
RECOVERY_STATUSES = {"ready", "recover", "narrow", "operator_required"}
NOVELTY_CLASSIFICATIONS = {"distinct", "duplicate", "uncertain"}
SEARCH_RESULTS = {"checked", "no_match", "unavailable"}
REQUIRED_COMMON_SEARCHES = {"own_reports", "program_disclosures", "recent_advisories"}
REQUIRED_REPOSITORY_SEARCHES = {"upstream_commits", "upstream_issues", "upstream_pull_requests"}
CURRENT_STATE_RESULTS = {"vulnerable", "fixed", "unavailable"}
PRIVATE_DUPLICATE_RISKS = {"unknown", "low", "medium", "high"}
PROOF_TYPE_TO_TARGET_POLICY = {"live-two-identity": {"program-hosted-owned-account"}, "live-deployed": {"researcher-owned-deployment", "program-hosted-owned-account"}, "executable-local-exact-path": {"executable-local-exact-path"}, "regression-test": {"regression-test"}, "maintainer-fix-or-cve": {"maintainer-fix-or-cve"}, "hardware-reproduction": {"hardware-reproduction"}}
ROUTE_TYPE_TO_CANDIDATE = {"bounty": "program", "vdp": "program", "upstream-advisory": "upstream-advisory", "ibb": "ibb", "vendor": "vendor"}
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def validate_candidate_schema(candidate: dict[str, Any], errors: list[str]) -> None:
    if candidate.get("schema_version") != CANDIDATE_SCHEMA_VERSION: errors.append(f"candidate.schema_version must be {CANDIDATE_SCHEMA_VERSION}; older records need deliberate migration")
    require_text(candidate, "candidate_id", "candidate", errors); require_text(candidate, "target_ledger_id", "candidate", errors); require_text(candidate, "target_fingerprint", "candidate", errors)
    for optional in ("campaign_id", "hypothesis_id"):
        value = candidate.get(optional)
        if value is not None and not text(value): errors.append(f"candidate.{optional} must be a non-empty string or null")


def validate_candidate_target_binding(candidate: dict[str, Any], target: dict[str, Any], errors: list[str]) -> None:
    decision = target.get("decision") if isinstance(target.get("decision"), dict) else {}
    if decision.get("disposition") != "SELECTED": errors.append("candidate stages require target decision.disposition SELECTED")
    if candidate.get("target_ledger_id") != target.get("target_id"): errors.append("candidate.target_ledger_id must match target.target_id")
    if candidate.get("target_fingerprint") != target_fingerprint(target): errors.append("candidate.target_fingerprint does not match the target identity; start a new candidate after asset/revision/route changes")
    bound = candidate.get("target")
    if not isinstance(bound, dict): errors.append("candidate.target must be an object"); return
    for key in ("platform", "route_type", "asset_type", "program", "asset", "repository", "commit", "operating_mode"):
        if bound.get(key) != canonical_target_value(target, key): errors.append(f"candidate.target.{key} must match target ledger {key}")


def validate_campaign_binding(candidate: dict[str, Any], campaign: dict[str, Any] | None, errors: list[str]) -> None:
    campaign_id = candidate.get("campaign_id"); hypothesis_id = candidate.get("hypothesis_id")
    if campaign is None:
        if campaign_id is not None or hypothesis_id is not None: errors.append("candidate campaign_id/hypothesis_id require --campaign-ledger")
        return
    if campaign.get("target_id") != candidate.get("target_ledger_id"): errors.append("campaign.target_id must match candidate.target_ledger_id")
    if campaign_id != campaign.get("campaign_id"): errors.append("candidate.campaign_id must match campaign.campaign_id")
    if not text(hypothesis_id): errors.append("campaign-bound candidate requires hypothesis_id"); return
    hypothesis = find_campaign_hypothesis(campaign, hypothesis_id)
    if hypothesis is None: errors.append("candidate.hypothesis_id must identify exactly one campaign hypothesis"); return
    if hypothesis.get("status") not in {"investigating", "closed"}: errors.append("candidate hypothesis must be investigating or closed")
    if hypothesis.get("status") == "closed":
        if hypothesis.get("candidate_id") != candidate.get("candidate_id"): errors.append("closed campaign hypothesis candidate_id must match candidate")
        verdict = candidate.get("decision", {}).get("verdict") if isinstance(candidate.get("decision"), dict) else None
        if hypothesis.get("verdict") != verdict: errors.append("closed campaign hypothesis verdict must match candidate decision")


def validate_model(candidate: dict[str, Any], errors: list[str]) -> None:
    require_text(candidate, "invariant", "candidate", errors)
    attacker = candidate.get("attacker_model")
    if not isinstance(attacker, dict): errors.append("candidate.attacker_model must be an object"); return
    for key in ("starting_access", "controls", "boundary", "capability_before", "capability_after"): require_text(attacker, key, "attacker_model", errors)


def validate_trace(candidate: dict[str, Any], errors: list[str]) -> None:
    trace = candidate.get("trace")
    if not isinstance(trace, dict): errors.append("candidate.trace must be an object"); return
    for key in ("entrypoint", "security_check", "effect", "sibling_checked"): require_text(trace, key, "trace", errors)


def validate_refutation(candidate: dict[str, Any], errors: list[str]) -> None:
    ref = candidate.get("strongest_refutation")
    if not isinstance(ref, dict): errors.append("candidate.strongest_refutation must be an object"); return
    require_text(ref, "claim", "strongest_refutation", errors); require_text(ref, "evidence", "strongest_refutation", errors)
    kind = ref.get("kind"); result = ref.get("result")
    if kind not in REFUTATION_KINDS: errors.append("strongest_refutation.kind is invalid")
    if result not in REFUTATION_RESULTS: errors.append("strongest_refutation.result must be refuted, confirmed, or unresolved")
    if kind in TERMINAL_REFUTATION_KINDS and result == "refuted": errors.append("a terminal refutation cannot be marked refuted; only a non_terminal objection can be defeated by evidence")


def validate_proof(candidate: dict[str, Any], errors: list[str]) -> None:
    proof = candidate.get("proof")
    if not isinstance(proof, dict): errors.append("candidate.proof must be an object"); return
    if proof.get("level") not in PROOF_LEVELS: errors.append("proof.level must be primitive, executable, or boundary")
    if proof.get("type") not in PROOF_TYPES: errors.append("proof.type is invalid")
    for key in ("command", "artifact", "observed_result", "negative_control", "production_relevance"): require_text(proof, key, "proof", errors)
    config = proof.get("config_dependency")
    if not isinstance(config, dict): errors.append("proof.config_dependency must be an object"); return
    kind = config.get("kind")
    if kind not in CONFIG_DEPENDENCIES: errors.append("proof.config_dependency.kind is invalid")
    if kind in {"program_shipped_default", "supported_option"}:
        require_text(config, "evidence", "proof.config_dependency", errors)
        if config.get("precondition_grants_effect") is not False: errors.append(f"proof.config_dependency {kind} requires precondition_grants_effect false")


def validate_route(candidate: dict[str, Any], errors: list[str]) -> None:
    route = candidate.get("route")
    if not isinstance(route, dict): errors.append("candidate.route must be an object"); return
    for key in ("owner", "destination", "owner_evidence", "proof_acceptance_evidence"): require_text(route, key, "route", errors)
    if route.get("type") not in ROUTE_TYPES: errors.append("route.type is invalid")
    if route.get("verified") is not True: errors.append("route.verified must be true")
    if route.get("proof_type_accepted") is not True: errors.append("route.proof_type_accepted must be true")


def validate_novelty(candidate: dict[str, Any], errors: list[str]) -> None:
    novelty = candidate.get("novelty")
    if not isinstance(novelty, dict): errors.append("candidate.novelty must be an object"); return
    require_text(novelty, "root_cause_fingerprint", "novelty", errors)
    classification = novelty.get("classification")
    if classification not in NOVELTY_CLASSIFICATIONS: errors.append("novelty.classification must be distinct, duplicate, or uncertain")
    if novelty.get("private_duplicate_risk") not in PRIVATE_DUPLICATE_RISKS: errors.append("novelty.private_duplicate_risk must be unknown, low, medium, or high")
    if classification == "distinct": require_text(novelty, "semantic_delta", "novelty", errors)
    searches = novelty.get("searches")
    if not isinstance(searches, list): errors.append("novelty.searches must be an array"); searches = []
    seen: set[str] = set()
    for i, search in enumerate(searches):
        path = f"novelty.searches[{i}]"
        if not isinstance(search, dict): errors.append(f"{path} must be an object"); continue
        source = require_text(search, "source", path, errors)
        if source:
            if source in seen: errors.append(f"{path}.source duplicates another novelty search")
            seen.add(source)
        require_text(search, "query", path, errors)
        result = search.get("result")
        if result not in SEARCH_RESULTS: errors.append(f"{path}.result must be checked, no_match, or unavailable")
        if result == "unavailable": require_text(search, "reason", path, errors)
        require_search_evidence(search.get("evidence"), f"{path}.evidence", errors)
    target = candidate.get("target") if isinstance(candidate.get("target"), dict) else {}
    required = set(REQUIRED_COMMON_SEARCHES)
    if target.get("asset_type") in {"repository", "library", "cli", "sdk"}: required.update(REQUIRED_REPOSITORY_SEARCHES)
    missing = sorted(required - seen)
    if missing: errors.append("novelty.searches is missing required channels: " + ", ".join(missing))
    current = novelty.get("current_state")
    if not isinstance(current, dict): errors.append("novelty.current_state must be an object")
    else:
        require_text(current, "ref", "novelty.current_state", errors)
        if current.get("result") not in CURRENT_STATE_RESULTS: errors.append("novelty.current_state.result must be vulnerable, fixed, or unavailable")
        if current.get("result") == "unavailable": require_text(current, "reason", "novelty.current_state", errors)
        require_search_evidence(current.get("evidence"), "novelty.current_state.evidence", errors)


def validate_claim_and_recovery(candidate: dict[str, Any], errors: list[str]) -> None:
    claim = candidate.get("claim")
    if not isinstance(claim, dict): errors.append("candidate.claim must be an object"); return
    require_text(claim, "capability", "claim", errors); require_text(claim, "impact", "claim", errors)
    if claim.get("severity_ceiling") not in MAX_SEVERITIES: errors.append("claim.severity_ceiling must be informational, low, medium, high, or critical")
    require_string_list(claim.get("limitations"), "claim.limitations", errors)
    recovery = candidate.get("recovery")
    if not isinstance(recovery, dict): errors.append("candidate.recovery must be an object"); return
    status = recovery.get("status")
    if status not in RECOVERY_STATUSES: errors.append("recovery.status must be ready, recover, narrow, or operator_required"); return
    unsupported = require_string_list(recovery.get("unsupported_claims"), "recovery.unsupported_claims", errors)
    if status == "ready" and unsupported: errors.append("recovery.status ready requires unsupported_claims empty")
    elif status != "ready": require_text(recovery, "next_action", "recovery", errors)
    if status in {"recover", "operator_required"}: require_text(recovery, "required_artifact", "recovery", errors)
    if status == "narrow" and not unsupported: errors.append("recovery.status narrow requires unsupported_claims")


def validate_hardening(candidate: dict[str, Any], errors: list[str]) -> None:
    hardening = candidate.get("hardening")
    if not isinstance(hardening, dict): errors.append("candidate.hardening must be an object"); return
    for key in ("scope_checked", "severity_reassessed", "proof_strengthened"): require_text(hardening, key, "hardening", errors)


def validate_decision(candidate: dict[str, Any], errors: list[str]) -> None:
    decision = candidate.get("decision")
    if not isinstance(decision, dict): errors.append("candidate.decision must be an object"); return
    verdict = decision.get("verdict"); gate = decision.get("gate")
    if verdict not in VERDICTS: errors.append("decision.verdict must be REPORTABLE, HOLD, KILL, or ROUTE_ELSEWHERE"); return
    if gate not in GATES: errors.append("decision.gate is invalid")
    require_text(decision, "reason", "decision", errors)
    failed = require_string_list(decision.get("failed_gates"), "decision.failed_gates", errors); missing = require_string_list(decision.get("missing_evidence"), "decision.missing_evidence", errors)
    if any(item not in GATES for item in failed): errors.append("decision.failed_gates contains invalid gates")
    if verdict == "REPORTABLE":
        if gate != "reportability": errors.append("REPORTABLE requires decision.gate reportability")
        if failed or missing: errors.append("REPORTABLE requires failed_gates and missing_evidence empty")
    elif verdict == "HOLD":
        if not missing: errors.append("HOLD requires decision.missing_evidence")
        if failed: errors.append("HOLD requires decision.failed_gates empty")
    elif verdict == "KILL":
        if gate not in failed: errors.append("KILL requires decision.gate in decision.failed_gates")
        if missing: errors.append("KILL requires decision.missing_evidence empty")
    elif verdict == "ROUTE_ELSEWHERE":
        if gate not in {"route", "ownership"}: errors.append("ROUTE_ELSEWHERE requires gate route or ownership")
        if failed or missing: errors.append("ROUTE_ELSEWHERE requires failed_gates and missing_evidence empty")


def validate_reportable(candidate: dict[str, Any], errors: list[str]) -> None:
    decision = candidate.get("decision") if isinstance(candidate.get("decision"), dict) else {}
    if decision.get("verdict") != "REPORTABLE": errors.append("report stage requires decision.verdict REPORTABLE"); return
    attacker = candidate.get("attacker_model") if isinstance(candidate.get("attacker_model"), dict) else {}
    if text(attacker.get("capability_before")) and attacker.get("capability_before") == attacker.get("capability_after"): errors.append("REPORTABLE requires a new attacker capability")
    ref = candidate.get("strongest_refutation") if isinstance(candidate.get("strongest_refutation"), dict) else {}
    if ref.get("result") != "refuted": errors.append("REPORTABLE requires strongest_refutation.result refuted")
    proof = candidate.get("proof") if isinstance(candidate.get("proof"), dict) else {}
    if proof.get("level") not in {"executable", "boundary"}: errors.append("REPORTABLE requires proof.level executable or boundary")
    if proof.get("type") not in FINAL_PROOF_TYPES: errors.append("REPORTABLE requires an executable or authorized hosted proof type")
    config = proof.get("config_dependency") if isinstance(proof.get("config_dependency"), dict) else {}
    if config.get("kind") in {"operator_weakened", "test_only", "unknown"}: errors.append(f"proof.config_dependency {config.get('kind')} forbids REPORTABLE at the supported target boundary")
    novelty = candidate.get("novelty") if isinstance(candidate.get("novelty"), dict) else {}
    if novelty.get("classification") != "distinct": errors.append("REPORTABLE requires novelty.classification distinct")
    current = novelty.get("current_state") if isinstance(novelty.get("current_state"), dict) else {}
    if current.get("result") == "fixed": errors.append("REPORTABLE requires current_state not fixed")
    if novelty.get("private_duplicate_risk") in {"medium", "high", "unknown"}: require_text(novelty, "collision_differentiator", "novelty", errors)
    recovery = candidate.get("recovery") if isinstance(candidate.get("recovery"), dict) else {}
    if recovery.get("status") in {"recover", "operator_required"}: errors.append(f"recovery.status {recovery.get('status')} forbids REPORTABLE")
    if recovery.get("status") not in {"ready", "narrow"}: errors.append("REPORTABLE requires recovery.status ready or narrow")
    claim = candidate.get("claim") if isinstance(candidate.get("claim"), dict) else {}
    if text(attacker.get("capability_after")) and claim.get("capability") != attacker.get("capability_after"): errors.append("claim.capability must exactly match attacker_model.capability_after")


def validate_candidate_target_contract(candidate: dict[str, Any], target: dict[str, Any], errors: list[str]) -> None:
    proof = candidate.get("proof") if isinstance(candidate.get("proof"), dict) else {}
    accepted = target.get("proof_policy", {}).get("accepted_proof_types"); accepted_set = set(accepted) if isinstance(accepted, list) else set()
    if not PROOF_TYPE_TO_TARGET_POLICY.get(proof.get("type"), set()).intersection(accepted_set): errors.append("candidate proof.type is not accepted by the selected target proof policy")
    route = candidate.get("route") if isinstance(candidate.get("route"), dict) else {}
    if route.get("type") != ROUTE_TYPE_TO_CANDIDATE.get(target.get("route_type")): errors.append("candidate route.type does not match target route_type")
    claim = candidate.get("claim") if isinstance(candidate.get("claim"), dict) else {}; target_max = target.get("scope", {}).get("max_severity"); candidate_max = claim.get("severity_ceiling")
    if target_max in SEVERITY_RANK and candidate_max in SEVERITY_RANK and SEVERITY_RANK[candidate_max] > SEVERITY_RANK[target_max]: errors.append("candidate claim.severity_ceiling exceeds target.scope.max_severity")


def validate_candidate(candidate: dict[str, Any], target: dict[str, Any], stage: str, errors: list[str], *, campaign: dict[str, Any] | None = None) -> None:
    validate_candidate_schema(candidate, errors); validate_candidate_target_binding(candidate, target, errors); validate_campaign_binding(candidate, campaign, errors); validate_model(candidate, errors)
    if stage == "model": return
    validate_trace(candidate, errors); validate_refutation(candidate, errors); validate_proof(candidate, errors); validate_route(candidate, errors); validate_novelty(candidate, errors); validate_claim_and_recovery(candidate, errors); validate_decision(candidate, errors)
    if stage == "decision": return
    validate_hardening(candidate, errors); validate_reportable(candidate, errors); validate_candidate_target_contract(candidate, target, errors)
