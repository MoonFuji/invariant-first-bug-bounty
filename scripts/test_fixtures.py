"""Synthetic fixtures for the v0.8 simplified-core regression suites."""
from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

from hunt_validation.target import target_fingerprint


def stamp(*, minutes_ago: int = 5, days_ago: int = 0, minutes_ahead: int = 0) -> str:
    value = datetime.now(UTC) - timedelta(days=days_ago, minutes=minutes_ago) + timedelta(minutes=minutes_ahead)
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def evidence(name: str) -> dict[str, str]:
    return {"method": "connector", "source": f"live:{name}", "artifact": f"evidence/{name}.json"}


def search_evidence(name: str) -> dict[str, str]:
    return {"method": "search", "query": f"query:{name}", "artifact": f"evidence/{name}.txt"}


def valid_target() -> dict:
    checked = stamp(minutes_ago=10)
    return {
        "schema_version": 4,
        "target_id": "target-example-server",
        "platform": "hackerone",
        "route_type": "bounty",
        "asset_type": "repository",
        "program": "example",
        "asset": "Example Server",
        "repository": "github.com/example/server",
        "commit": "0123456789abcdef",
        "operating_mode": "SOURCE_ONLY",
        "scope": {
            "status": "eligible",
            "asset_identifier": "Example Server",
            "max_severity": "high",
            "checked_at": checked,
            "reason": "",
            "evidence": evidence("scope"),
        },
        "proof_policy": {
            "status": "checked",
            "accepted_proof_types": ["executable-local-exact-path", "regression-test"],
            "quote": "Local exact-path proof is accepted.",
            "checked_at": checked,
            "reason": "",
            "evidence": evidence("proof-policy"),
        },
        "decision": {
            "disposition": "SELECTED",
            "gate": "selection",
            "rotation_basis": None,
            "alternative_target": "",
            "missing_evidence": [],
            "reason": "Current scope and a compatible proof route are confirmed.",
            "evidence": evidence("selection"),
        },
    }


def valid_campaign() -> dict:
    return {
        "schema_version": 1,
        "campaign_id": "campaign-example",
        "target_id": "target-example-server",
        "mode": "bounded",
        "status": "open",
        "stop_condition": "Investigate the two highest-value mapped invariants.",
        "hypotheses": [
            {
                "hypothesis_id": "H-001",
                "boundary": "HTTP request -> tenant record",
                "statement": "Record lookup may omit tenant authorization.",
                "priority": "high",
                "status": "investigating",
                "candidate_id": None,
                "verdict": None,
                "reason": "",
            },
            {
                "hypothesis_id": "H-002",
                "boundary": "cache key -> tenant record",
                "statement": "Cache key may omit tenant identity.",
                "priority": "medium",
                "status": "queued",
                "candidate_id": None,
                "verdict": None,
                "reason": "",
            },
        ],
    }


def valid_candidate(*, campaign: bool = False) -> dict:
    target = valid_target()
    candidate = {
        "schema_version": 7,
        "candidate_id": "C-001",
        "target_ledger_id": target["target_id"],
        "target_fingerprint": target_fingerprint(target),
        "campaign_id": "campaign-example" if campaign else None,
        "hypothesis_id": "H-001" if campaign else None,
        "target": {
            key: target[key]
            for key in (
                "platform", "route_type", "asset_type", "program", "asset",
                "repository", "commit", "operating_mode",
            )
        },
        "invariant": "A tenant-scoped caller must not read another tenant's report.",
        "attacker_model": {
            "starting_access": "authenticated tenant A member",
            "controls": "report identifier supplied to GET /reports/{id}",
            "boundary": "tenant A request crosses into tenant B report storage",
            "capability_before": "read reports owned by tenant A",
            "capability_after": "read a report owned by another tenant",
        },
        "trace": {
            "entrypoint": "GET /reports/{id}",
            "security_check": "lookup by report id omits tenant_id before serialization",
            "effect": "tenant B canary report is returned to tenant A",
            "sibling_checked": "list endpoint correctly scopes by tenant_id",
        },
        "strongest_refutation": {
            "claim": "report identifiers may be intentionally global and public",
            "kind": "non_terminal",
            "result": "refuted",
            "evidence": "docs/authorization.md states reports are tenant-confidential",
        },
        "proof": {
            "level": "boundary",
            "type": "executable-local-exact-path",
            "command": "python3 reproduce.py",
            "artifact": "proof/transcript.txt",
            "observed_result": "tenant A receives tenant B canary",
            "negative_control": "tenant-scoped list endpoint does not expose tenant B canary",
            "production_relevance": "same pinned request handler and shipped authorization middleware",
            "config_dependency": {
                "kind": "none",
                "evidence": "not applicable",
                "precondition_grants_effect": False,
            },
        },
        "route": {
            "type": "program",
            "owner": "Example Server",
            "destination": "Example HackerOne program",
            "verified": True,
            "owner_evidence": "repository ships the vulnerable handler",
            "proof_type_accepted": True,
            "proof_acceptance_evidence": "current program policy accepts local exact-path proof",
        },
        "novelty": {
            "root_cause_fingerprint": "tenant-boundary|id-lookup|missing-tenant-filter|cross-tenant-read",
            "classification": "distinct",
            "semantic_delta": "closest public issue concerns list filtering, not direct report lookup",
            "closest_match": None,
            "private_duplicate_risk": "medium",
            "collision_differentiator": "direct object lookup omits tenant predicate on current default branch",
            "searches": [
                {"source": source, "query": f"query:{source}", "result": "no_match", "reason": "", "evidence": search_evidence(source)}
                for source in (
                    "own_reports",
                    "program_disclosures",
                    "upstream_commits",
                    "upstream_issues",
                    "upstream_pull_requests",
                    "recent_advisories",
                )
            ],
            "current_state": {
                "ref": "main@0123456789abcdef",
                "result": "vulnerable",
                "reason": "",
                "evidence": search_evidence("current-state"),
            },
        },
        "claim": {
            "capability": "read a report owned by another tenant",
            "impact": "cross-tenant disclosure of a confidential report",
            "severity_ceiling": "high",
            "limitations": [],
        },
        "recovery": {
            "status": "ready",
            "next_action": "",
            "required_artifact": "",
            "unsupported_claims": [],
        },
        "hardening": {
            "scope_checked": "confirmed exact asset and affected revision",
            "severity_reassessed": "high ceiling retained; no write or admin capability shown",
            "proof_strengthened": "added tenant-scoped negative control",
        },
        "decision": {
            "verdict": "REPORTABLE",
            "gate": "reportability",
            "failed_gates": [],
            "missing_evidence": [],
            "reason": "Exact cross-tenant read is reproduced and distinct.",
        },
    }
    return copy.deepcopy(candidate)


def report_for(candidate: dict) -> str:
    lines = [
        f"# {candidate['invariant']}",
        "",
        candidate["claim"]["capability"],
        "",
        candidate["claim"]["impact"],
        "",
        f"Reproduce with `{candidate['proof']['command']}`.",
    ]
    for limitation in candidate["claim"].get("limitations", []):
        lines.extend(["", limitation])
    for unsupported in candidate["recovery"].get("unsupported_claims", []):
        lines.extend(["", unsupported])
    return "\n".join(lines) + "\n"
