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
SUPPORTED_SCHEMA_VERSIONS = {3, 4, 5}
# Schema 5 process-evidence blocks (ideation + adversarial self-review). The
# report-stage gates below apply only when schema_version >= 5; legacy schema-3/4
# candidates still validate at non-report stages, matching the skill's
# "migrate before REPORTABLE" rule.
INTENT_MATCHES = {"none", "intentional", "acknowledged"}
COLD_VERIFY_VERDICTS = {"CONFIRMED", "DISPROVED", "UNCERTAIN"}
SUBCLAIM_STATUSES = {"supported", "unsupported"}
CONFIG_DEPENDENCIES = {"none", "default_only", "requires_insecure_config"}
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
CURRENT_UPSTREAM_RESULTS = {"vulnerable", "fixed", "unavailable"}
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
        errors.append("schema_version must be 3, 4, or 5")

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
        repo = value_at(document, "target.repository")
        is_github = isinstance(repo, str) and "github.com/" in repo
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
                    if is_github and name in {"issues", "pull_requests"}:
                        # These searches exist on GitHub: `unavailable` must mean
                        # attempted-and-failed (with an artifact) and never counts
                        # as coverage, so `unavailable` cannot stand in for a search.
                        ev = channel.get("evidence")
                        if not isinstance(ev, dict) or not all(
                            isinstance(ev.get(k), str) and ev.get(k).strip()
                            for k in ("method", "query", "artifact")
                        ):
                            errors.append(
                                f"GitHub {name} channel marked unavailable must record an "
                                "attempted-search artifact (evidence.method, query, artifact)"
                            )
                    else:
                        covered.add(name)
        if not REQUIRED_UPSTREAM_CHANNELS.issubset(covered):
            errors.append(
                "distinct requires upstream_history channels covering commits, issues, "
                "pull_requests with search artifacts (git log alone is insufficient)"
            )

        # The current default branch must be confirmed still vulnerable; a stale
        # checkout can be vulnerable while `main` is already fixed.
        cus = value_at(document, "novelty.current_upstream_state")
        if not isinstance(cus, dict):
            errors.append(
                "distinct requires novelty.current_upstream_state confirming the current "
                "default branch is still vulnerable, with a fetch artifact"
            )
        else:
            cres = cus.get("result")
            if cres not in CURRENT_UPSTREAM_RESULTS:
                errors.append(
                    "novelty.current_upstream_state.result must be one of "
                    + ", ".join(sorted(CURRENT_UPSTREAM_RESULTS))
                )
            elif cres == "fixed":
                errors.append(
                    "novelty.current_upstream_state result fixed forbids distinct; KILL @ novelty "
                    "or route as a historical/advisory finding"
                )
            elif cres == "unavailable":
                errors.append(
                    "novelty.current_upstream_state unavailable -> HOLD @ novelty; cannot claim distinct"
                )
            else:  # vulnerable
                require_evidence(cus, "novelty.current_upstream_state", errors)
                for key in ("ref", "path", "checked_at"):
                    value = cus.get(key)
                    if not isinstance(value, str) or not value.strip():
                        errors.append(
                            f"novelty.current_upstream_state.{key} must be a non-empty string"
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


def validate_exhaustion(document, errors):
    """Schema-5 NO_REPORTABLE_FINDING must carry a checkable exhaustion record.

    "The invariant held" is the weakest terminal to fake: the prior gates accept
    plausible prose, so an agent under token pressure can skim, restate intent as a
    confirmed refutation, and declare clean. Requiring the concrete record the Depth
    contract already names -- what was tried, and the five clean-repository fields --
    does not *prove* exhaustion (prose is still prose), but it raises the floor from a
    bare verdict to an articulated, auditable one, symmetric with how REPORTABLE must
    articulate its evidence. Only applies to schema >= 5; the honesty-critical check
    belongs in low-freedom structure, not only a KEEP-GOING prose list.
    """
    version = value_at(document, "schema_version")
    if not isinstance(version, int) or version < 5:
        return
    exhaustion = value_at(document, "exhaustion")
    if not isinstance(exhaustion, dict):
        errors.append(
            "schema 5 NO_REPORTABLE_FINDING requires an exhaustion block (tried[], depth_contract) "
            "-- a clean conclusion is a claim that owes the same articulated evidence as a report"
        )
        return
    tried = exhaustion.get("tried")
    if (
        not isinstance(tried, list)
        or not tried
        or any(not isinstance(item, str) or not item.strip() for item in tried)
    ):
        errors.append(
            "NO_REPORTABLE_FINDING requires exhaustion.tried to list the concrete avenues "
            "investigated (non-empty strings); document the work, do not assert it"
        )
    depth = exhaustion.get("depth_contract")
    depth_fields = (
        "entrypoint",
        "invariant_enforcement",
        "trace",
        "sibling_checked",
        "defeated_counterexample",
    )
    if not isinstance(depth, dict):
        errors.append(
            "NO_REPORTABLE_FINDING requires exhaustion.depth_contract with the five clean-repository "
            "records (" + ", ".join(depth_fields) + ")"
        )
    else:
        for field in depth_fields:
            value = depth.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"exhaustion.depth_contract.{field} must be a non-empty string")


def require_intent_corpus_present(document, errors):
    """Schema-5: the intent corpus (workflow step 1) must exist by the time a 'clean'
    conclusion is reached, not be back-filled at report time. Requiring it for
    NO_REPORTABLE_FINDING means the by-design question was confronted early -- where a
    match is a KILL @ refutation -- rather than as a report-stage retrofit."""
    version = value_at(document, "schema_version")
    if not isinstance(version, int) or version < 5:
        return
    intent = value_at(document, "intent_corpus")
    if not isinstance(intent, dict):
        errors.append(
            "schema 5 NO_REPORTABLE_FINDING requires an intent_corpus, built in step 1, not back-filled"
        )
        return
    checked_at = intent.get("checked_at")
    if not isinstance(checked_at, str) or not checked_at.strip():
        errors.append("NO_REPORTABLE_FINDING requires intent_corpus.checked_at (the corpus is owed by step 1)")
    sources = intent.get("sources")
    if not isinstance(sources, list) or not sources:
        errors.append("NO_REPORTABLE_FINDING requires intent_corpus.sources (record what you read)")


def novelty_has_positive_signal(document):
    """True if any novelty check or upstream channel surfaced a closest_match. Absence of
    any match is the *weakest* evidence about the invisible private-duplicate pool, not the
    strongest -- so an all-clean public search cannot support a low private-duplicate risk."""
    checks = value_at(document, "novelty.checks")
    if not isinstance(checks, list):
        return False
    for check in checks:
        if not isinstance(check, dict):
            continue
        if isinstance(check.get("closest_match"), dict):
            return True
        channels = check.get("channels")
        if isinstance(channels, list):
            for channel in channels:
                if isinstance(channel, dict) and isinstance(channel.get("closest_match"), dict):
                    return True
    return False


def validate_saturation_present(document, errors):
    """Schema-5 model stage: assess dedup visibility BEFORE the deep trace. Duplicates are decided
    at selection, not at proof, so target.saturation.discloses_reports is owed by the model gate --
    a swarmed / non-disclosing program should be confronted before hours are invested in a trace."""
    version = value_at(document, "schema_version")
    if not isinstance(version, int) or version < 5:
        return
    sat = value_at(document, "target.saturation")
    if not isinstance(sat, dict) or not isinstance(sat.get("discloses_reports"), bool):
        errors.append(
            "schema 5 requires target.saturation.discloses_reports (a boolean) by the model stage -- "
            "assess whether the program is dedupable before investing the trace; dupes are decided at selection"
        )


def validate_saturation_for_report(document, errors):
    """Schema-5 REPORTABLE: duplicates are the dominant failure and they are decided at
    target selection, not at proof. In the mined history every adjudicated duplicate sat on
    a marquee/high-volume or *non-disclosing* program where the private pool could not be
    deduped. Require the dedup-visibility assessment, and make a non-disclosing program --
    which gives zero public dedup signal -- carry high private-duplicate risk by construction.
    """
    version = value_at(document, "schema_version")
    if not isinstance(version, int) or version < 5:
        return
    sat = value_at(document, "target.saturation")
    if not isinstance(sat, dict):
        errors.append(
            "schema 5 REPORTABLE requires a target.saturation assessment carrying discloses_reports "
            "(can you dedup against the program's public reports?); duplicates are decided at target selection"
        )
        return
    discloses = sat.get("discloses_reports")
    if not isinstance(discloses, bool):
        errors.append(
            "target.saturation.discloses_reports must be a boolean -- can you dedup against the "
            "program's public reports, or is the private pool invisible?"
        )
    risk = value_at(document, "novelty.private_duplicate_risk")
    if discloses is False and risk == "low":
        errors.append(
            "a non-disclosing program gives zero public dedup signal, so a low private_duplicate_risk "
            "cannot be claimed -- assess it medium or high; a bespoke, low-collision finding may still "
            "be medium, but never low where you cannot dedup at all"
        )
    # When dedup visibility is poor -- high private-dup risk, a non-disclosing program, or a hot
    # class-cluster -- an honest risk label is not enough (the mined losses were labelled high and
    # shipped anyway). REPORTABLE then requires an articulated collision differentiator: why THIS
    # finding is low-collision despite the swarm (a Tier-3 cross-layer / no-advisory / bespoke vein).
    # This does not hard-block a high-risk finding -- that would kill the Tier-3 wins that pay on
    # swarmed programs -- but it forces the win-vs-dupe distinction the data turns on.
    hot = sat.get("hot_cluster")
    if risk == "high" or discloses is False or hot is True:
        differentiator = value_at(document, "novelty.collision_differentiator")
        if not isinstance(differentiator, str) or not differentiator.strip():
            errors.append(
                "high private-duplicate context (risk high, non-disclosing program, or hot cluster) "
                "requires novelty.collision_differentiator: the articulated reason this specific finding "
                "is low-collision despite the swarm (a cross-layer / no-advisory / bespoke Tier-3 vein); "
                "an honest 'high' label alone did not stop a duplicate historically"
            )


def validate_schema5_report_gates(document, errors):
    """Hard REPORTABLE gates introduced with schema 5. Applies only to schema >= 5.

    A schema-5 REPORTABLE candidate must have run the intent-corpus and adversarial
    self-review passes *with their substantive fields filled*: the finding cannot match a
    documented intentional behavior; the Advocate must have walked the protection layers,
    stated the strongest defense, and not itself concluded the finding is blocked; the cold
    verifier must have CONFIRMED it with a re-derived severity and no killed subclaim; and
    every false-positive-pattern hit the Advocate raised must carry a written, evidenced
    rebuttal. Filling a block with empty or contradictory fields does not satisfy the gate —
    that is the same "field satisfiable without the work" failure schema 4 closed for the
    refutation and novelty blocks.
    """
    version = value_at(document, "schema_version")
    if not isinstance(version, int) or version < 5:
        return

    intent = value_at(document, "intent_corpus")
    if not isinstance(intent, dict):
        errors.append("schema 5 REPORTABLE requires an intent_corpus block")
    else:
        match = intent.get("finding_match")
        if match not in INTENT_MATCHES:
            errors.append(
                "intent_corpus.finding_match must be one of " + ", ".join(sorted(INTENT_MATCHES))
            )
        elif match == "intentional":
            errors.append(
                "intent_corpus.finding_match intentional forbids REPORTABLE; the behavior is a "
                "documented contract (KILL @ refutation, behavior_is_documented_contract)"
            )
        checked_at = intent.get("checked_at")
        if not isinstance(checked_at, str) or not checked_at.strip():
            errors.append(
                "schema 5 REPORTABLE requires intent_corpus.checked_at recording when the "
                "project's own docs were read; an empty corpus pass does not satisfy the gate"
            )
        sources = intent.get("sources")
        if not isinstance(sources, list) or not sources:
            errors.append(
                "schema 5 REPORTABLE requires intent_corpus.sources listing the target-authored "
                "documents checked; record what you read even when it carries no by-design note"
            )

    review = value_at(document, "adversarial_review")
    if not isinstance(review, dict):
        errors.append("schema 5 REPORTABLE requires an adversarial_review block")
        return

    advocate = review.get("advocate")
    if not isinstance(advocate, dict):
        errors.append("schema 5 REPORTABLE requires an adversarial_review.advocate block")
    else:
        layers = advocate.get("layers_checked")
        if not isinstance(layers, list) or not layers:
            errors.append(
                "REPORTABLE requires adversarial_review.advocate.layers_checked to record the "
                "protection layers the Advocate searched; an empty list means the pass did not run"
            )
        defense = advocate.get("strongest_defense")
        if not isinstance(defense, str) or not defense.strip():
            errors.append(
                "REPORTABLE requires adversarial_review.advocate.strongest_defense; state the "
                "best benign case built against the finding even if it does not hold"
            )
        if advocate.get("blocks") is True:
            errors.append(
                "adversarial_review.advocate.blocks is true; the Advocate built a defense that "
                "blocks the finding, which forbids REPORTABLE (resolve it with evidence or KILL)"
            )

    verdict = value_at(document, "adversarial_review.cold_verify.verdict")
    if verdict not in COLD_VERIFY_VERDICTS:
        errors.append(
            "adversarial_review.cold_verify.verdict must be one of "
            + ", ".join(sorted(COLD_VERIFY_VERDICTS))
        )
    elif verdict != "CONFIRMED":
        errors.append(
            "REPORTABLE requires adversarial_review.cold_verify.verdict CONFIRMED "
            f"(got {verdict}); a DISPROVED or UNCERTAIN cold verification cannot be reported"
        )
    else:
        severity = value_at(document, "adversarial_review.cold_verify.rederived_severity")
        if not isinstance(severity, str) or not severity.strip():
            errors.append(
                "a CONFIRMED cold_verify requires a non-empty rederived_severity; severity is "
                "re-derived from MEDIUM, not carried over from the draft"
            )
        if value_at(document, "adversarial_review.cold_verify.killed_subclaim") is not None:
            errors.append(
                "adversarial_review.cold_verify.verdict CONFIRMED contradicts a non-null "
                "killed_subclaim; a killed subclaim is a DISPROVED or UNCERTAIN result"
            )
        # Persist the decomposition the cold verifier is told to build (claim -> A: attacker
        # controls X, B: X reaches Y unsanitized, C: Y causes effect Z). Forcing the explicit
        # decomposition *before* a CONFIRMED verdict is what turns a self-graded checkbox into
        # work with a cost: an unsupported link contradicts the verdict. Self-preference bias in
        # self-evaluation is strongest exactly when the trace is subtly wrong, and an explicit
        # pre-verdict decomposition is the documented mitigation.
        subclaims = value_at(document, "adversarial_review.cold_verify.subclaims")
        if not isinstance(subclaims, list) or len(subclaims) < 2:
            errors.append(
                "a CONFIRMED cold_verify requires cold_verify.subclaims to record the decomposition "
                "(>= 2, e.g. attacker controls X; X reaches Y unsanitized; Y causes effect Z); a bare "
                "verdict without the decomposition is a self-signed certificate"
            )
        else:
            for sindex, subclaim in enumerate(subclaims):
                spath = f"adversarial_review.cold_verify.subclaims[{sindex}]"
                if not isinstance(subclaim, dict):
                    errors.append(f"{spath} must be an object with claim and status")
                    continue
                claim = subclaim.get("claim")
                if not isinstance(claim, str) or not claim.strip():
                    errors.append(f"{spath}.claim must be a non-empty string")
                status = subclaim.get("status")
                if status not in SUBCLAIM_STATUSES:
                    errors.append(
                        f"{spath}.status must be one of " + ", ".join(sorted(SUBCLAIM_STATUSES))
                    )
                elif status != "supported":
                    errors.append(
                        f"{spath} is not supported; an unsupported sub-claim contradicts a CONFIRMED "
                        "verdict (the finding fails at that link -> DISPROVED/HOLD, not REPORTABLE)"
                    )
                evidence = subclaim.get("evidence")
                if not isinstance(evidence, str) or not evidence.strip():
                    errors.append(
                        f"{spath}.evidence must cite a locator (path:line, artifact, or script output) "
                        "grounding this link -- a bare claim + status is still a self-signed decomposition"
                    )

    hits = value_at(document, "adversarial_review.advocate.fp_pattern_hits")
    if hits is None:
        hits = []
    if not isinstance(hits, list):
        errors.append("adversarial_review.advocate.fp_pattern_hits must be an array")
    else:
        for index, hit in enumerate(hits):
            path = f"adversarial_review.advocate.fp_pattern_hits[{index}]"
            if not isinstance(hit, dict):
                errors.append(f"{path} must be an object with pattern, rebuttal, evidence")
                continue
            rebuttal = hit.get("rebuttal")
            if not isinstance(rebuttal, str) or not rebuttal.strip():
                errors.append(
                    f"{path} is an unrebutted false-positive-pattern hit; write a rebuttal "
                    "(with evidence) or take the implied KILL"
                )
            evidence = hit.get("evidence")
            if not isinstance(evidence, str) or not evidence.strip():
                errors.append(
                    f"{path} rebuttal needs evidence: a file:line control, artifact, or policy "
                    "citation that grounds it -- prose alone does not clear the pattern"
                )

    # The demonstrated-impact bar for the informative class: a finding that manifests only in a
    # default/dev config a real deployment overrides, or that needs an insecure config no real
    # deployment uses (operator config, not attacker input), is not reportable. Lab-reproduced
    # source-only findings are config_dependency "none" and unaffected.
    config_dep = value_at(document, "proof.config_dependency")
    if config_dep not in CONFIG_DEPENDENCIES:
        errors.append(
            "REPORTABLE requires proof.config_dependency assessed (one of "
            + ", ".join(sorted(CONFIG_DEPENDENCIES)) + ")"
        )
    elif config_dep != "none":
        errors.append(
            f"proof.config_dependency {config_dep} forbids REPORTABLE: the effect appears only in a "
            "default/dev config a real deployment overrides, or requires an insecure config no real "
            "deployment uses (operator config is not attacker input) -- HOLD or KILL, not report"
        )

    # Self-certification is banned for a REPORTABLE: self-review over-rates its own findings (measured
    # -- even a genuine self red-team over-rated reachability). Require an independent reviewer, or an
    # explicit "owed" that hands the finding to the user as provisional.
    reviewer = review.get("reviewer") if isinstance(review, dict) else None
    if reviewer in (None, "", "self"):
        errors.append(
            "REPORTABLE may not be self-certified: adversarial_review.reviewer must name an independent "
            "reviewer (a fresh-context agent given only the artifact), or be 'owed' and handed to the "
            "user as provisional -- do not submit a self-graded finding"
        )

    # Reports ship weak -- require a completed hardening pass before REPORTABLE.
    hardening = value_at(document, "hardening")
    if not isinstance(hardening, dict) or hardening.get("status") != "done":
        errors.append(
            "REPORTABLE requires a completed hardening pass (hardening.status 'done'): widen the blast "
            "radius, reassess severity on the evidence, and deepen the PoC before submitting"
        )
    else:
        for field in ("widened_radius", "escalated_severity", "deepened_poc"):
            value = hardening.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(
                    f"hardening.{field} must record what the pass attempted (or an explicit 'n/a: <reason>'); "
                    "escalated_severity records a severity re-assessment -- raise it only on evidence, "
                    "and hold or lower it when the evidence does not support a higher score"
                )


def collect_warnings(document):
    """Non-blocking advisories for the warn-only schema-5 process steps.

    Ideation and variant discovery are recorded but never block a verdict; a
    missing creativity signal or an unrecorded variant sweep is a note, not an error.
    """
    warnings = []
    version = value_at(document, "schema_version")
    if not isinstance(version, int) or version < 5:
        return warnings

    queue = value_at(document, "hypothesis_queue")
    if not isinstance(queue, list) or not queue:
        warnings.append(
            "hypothesis_queue is empty; on a large or unfamiliar target run one ideation pass "
            "(references/hypothesis-generation.md) and rank the surface before concluding it is covered"
        )
    else:
        for index, item in enumerate(queue):
            signal = item.get("creativity_signal") if isinstance(item, dict) else None
            if not isinstance(signal, str) or not signal.strip():
                warnings.append(
                    f"hypothesis_queue[{index}] has no creativity_signal; weigh its novelty and "
                    "duplicate risk -- an obvious sink can still be reachable and worth tracing, but "
                    "is likelier already reported, so rank it by expected value, do not auto-drop it"
                )

    if value_at(document, "decision.verdict") == "REPORTABLE":
        sweep = value_at(document, "variant_sweep")
        recorded = isinstance(sweep, dict) and (
            (isinstance(sweep.get("flow_shape"), str) and sweep["flow_shape"].strip())
            or sweep.get("variants_found")
            or sweep.get("siblings_checked")
            or sweep.get("alternate_transports_checked")
        )
        if not recorded:
            warnings.append(
                "variant_sweep is unrecorded on a REPORTABLE finding; a variant is a second "
                "submission left on the table -- sweep siblings and alternate transports"
            )

    # PROVISIONAL: an owed independent review means the verdict is not final.
    if value_at(document, "adversarial_review.reviewer") == "owed":
        warnings.append(
            "PROVISIONAL: adversarial_review.reviewer is 'owed' -- an independent agent (or the user) "
            "must verify before this verdict is final; do not self-certify"
        )

    verdict = value_at(document, "decision.verdict")
    # A 'clean' verdict from static reading alone is the low-trust pattern (measured: ~half of clean
    # verdicts had no executed probe). Static reading is not probing. Key this on a recorded probe
    # under exhaustion.probes -- not proof.type, which a clean verdict never validates and can inherit
    # populated from a dropped report draft (making a static read look dynamically tested).
    if verdict == "NO_REPORTABLE_FINDING":
        probes = value_at(document, "exhaustion.probes")
        has_probe = isinstance(probes, list) and any(
            isinstance(p, dict) and isinstance(p.get("command"), str) and p["command"].strip()
            for p in probes
        )
        if not has_probe:
            warnings.append(
                "NO_REPORTABLE_FINDING with no executed probe (exhaustion.probes empty) rests on static "
                "reading; record a probe that would have fired if the bug existed -- its command and the "
                "observed result -- before trusting 'clean'"
            )
    # A hardening pass by the same author catches less than a fresh-context agent.
    if verdict == "REPORTABLE" and value_at(document, "hardening.reviewer") in (None, "", "self"):
        warnings.append(
            "hardening.reviewer is self -- a widen/escalate/deepen pass by a fresh-context agent "
            "catches more than the author re-reading their own finding"
        )
    return warnings


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
    validate_saturation_present(document, errors)
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

    # A confirmed terminal refutation must land at the gate its kind implies.
    rv = refutation_view(document)
    if rv["kind"] in TERMINAL_REFUTATION_KINDS and rv["result"] == "confirmed":
        allowed = TERMINAL_KIND_GATES.get(rv["kind"], set())
        if verdict in {"KILL", "ROUTE_ELSEWHERE"} and gate not in allowed:
            errors.append(
                f"confirmed terminal refutation '{rv['kind']}' requires decision.gate in "
                + ", ".join(sorted(allowed))
            )

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
        validate_exhaustion(document, errors)
        require_intent_corpus_present(document, errors)
        # A "clean" verdict may not be self-certified -- it is the verdict least trusted, and a
        # self-graded depth audit is worth little. Require an independent reviewer (a fresh-context
        # agent given only the artifact), or an explicit "owed" that signals the user (provisional).
        version = value_at(document, "schema_version")
        if isinstance(version, int) and version >= 5:
            reviewer = value_at(document, "adversarial_review.reviewer")
            if reviewer in (None, "", "self"):
                errors.append(
                    "NO_REPORTABLE_FINDING may not be self-certified: an independent agent must audit "
                    "the depth (adversarial_review.reviewer = its id), or set reviewer 'owed' and signal "
                    "the user (provisional) -- a self-graded 'clean' is the verdict that is not trusted"
                )
            # Coherence: a clean verdict cannot carry an adversarial review that CONFIRMED the
            # finding. A CONFIRMED cold_verify says the vulnerability holds -- the opposite of
            # NO_REPORTABLE_FINDING. This catches a stale REPORTABLE-era review left on the
            # candidate when the decision was flipped to clean (the review must audit the clean
            # conclusion, not a finding that no longer stands).
            if value_at(document, "adversarial_review.cold_verify.verdict") == "CONFIRMED":
                errors.append(
                    "NO_REPORTABLE_FINDING contradicts adversarial_review.cold_verify.verdict CONFIRMED: "
                    "a confirmed finding is not a clean verdict -- the review must audit the clean "
                    "conclusion (DISPROVED/UNCERTAIN), not carry a stale CONFIRMED from a dropped report"
                )
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
        if (
            value_at(document, "novelty.private_duplicate_risk") == "low"
            and not novelty_has_positive_signal(document)
        ):
            errors.append(
                "REPORTABLE with every public novelty check clean cannot claim low "
                "private_duplicate_risk; absence of public matches is not evidence about the "
                "invisible private pool -- assess it medium or high"
            )
        validate_saturation_for_report(document, errors)
        validate_schema5_report_gates(document, errors)


def validate_report(document, errors):
    validate_decision(document, errors)
    if value_at(document, "decision.verdict") != "REPORTABLE":
        errors.append("decision.verdict must be REPORTABLE for report stage")
    # A report must carry the schema-5 ideation and self-review evidence. A
    # legacy schema-3/4 candidate validates at model/decision stages but cannot
    # reach a submission-ready report without migrating, so the intent-corpus and
    # adversarial self-review gates below actually apply.
    version = value_at(document, "schema_version")
    if not isinstance(version, int) or version < 5:
        errors.append(
            "report stage requires schema_version >= 5; migrate the candidate to schema 5 so "
            "the intent-corpus and adversarial self-review gates apply before REPORTABLE"
        )


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

    for warning in dict.fromkeys(collect_warnings(document)):
        print(f"WARN: {warning}", file=sys.stderr)

    labels = {
        "model": "MODEL READY",
        "decision": "DECISION READY",
        "report": "REPORT READY",
    }
    label = labels[args.stage]
    # An owed independent review is not a final verdict: the candidate is structurally valid but
    # not yet certified. Print a distinct provisional label so exit 0 does not read as "submit" --
    # the report/decision is provisional until an independent agent (or the user) verifies it.
    if value_at(document, "adversarial_review.reviewer") == "owed":
        label = {
            "report": "REPORT PROVISIONAL -- INDEPENDENT REVIEW OWED",
            "decision": "DECISION PROVISIONAL -- INDEPENDENT REVIEW OWED",
        }.get(args.stage, label)
    print(f"{label}: {args.candidate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
