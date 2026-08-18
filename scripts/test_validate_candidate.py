#!/usr/bin/env python3
"""Acceptance tests for validate-candidate.py (skill v0.4.1 / schema 5).

Reproduces the two failure shapes that reached HackerOne as Informative:
  - a terminal refutation marked `refuted` with no resolution attacking the
    owned boundary (Vertex model-route escape / #3858135);
  - a `distinct` novelty claim backed only by `git log`, skipping the upstream
    issue/PR search (marcel #153 live dup; activeresource #358 by-design).

Schema-5 cases (K-W) cover the report-stage process gates: report stage now
requires schema_version >= 5 (Q), and a finding matching a documented intentional
behavior, a cold verification that did not CONFIRM, an Advocate whose own defense
blocks the finding, a CONFIRMED verdict contradicted by a killed subclaim or an
empty re-derived severity, an Advocate that searched no layers, an empty intent
corpus, and an FP-pattern rebuttal with no evidence each forbid REPORTABLE. The
report-stage accepts are migrated to schema 5; legacy schema-3/4 candidates still
validate at the model and decision stages (legacy, G-J).

Cases XA-XF cover the v0.4.3 additions: a schema-5 NO_REPORTABLE_FINDING requires a
checkable exhaustion record (tried[] + the five depth_contract fields), and a CONFIRMED
cold_verify requires a persisted sub-claim decomposition with every link supported.

Run: python3 scripts/test_validate_candidate.py
Exit 0 = all cases behaved as specified.
"""

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
VALIDATOR = HERE / "validate-candidate.py"


def run(document, stage):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(document, handle)
        path = handle.name
    try:
        proc = subprocess.run(
            [sys.executable, str(VALIDATOR), path, "--stage", stage],
            capture_output=True,
            text=True,
        )
    finally:
        Path(path).unlink(missing_ok=True)
    return proc.returncode, proc.stderr


def evidence(method, artifact):
    return {"method": method, "query": "q", "artifact": artifact}


def novelty_check(source, result="no_match"):
    check = {
        "source": source,
        "query": "q",
        "checked_at": "2026-08-08",
        "result": result,
        "closest_match": None,
        "evidence": evidence(f"{source}_search", f"https://example/{source}"),
    }
    if result == "unavailable":
        check["reason"] = "not applicable"
        check.pop("evidence", None)
    return check


def upstream_channels(results=("no_match", "no_match", "no_match")):
    names = ("commits", "issues", "pull_requests")
    channels = []
    for name, result in zip(names, results):
        channel = {
            "channel": name,
            "query": f"{name} q",
            "result": result,
            "closest_match": None,
            "evidence": evidence(f"github_{name}_search", f"https://github.com/o/r/{name}"),
        }
        channels.append(channel)
    return channels


def baseline():
    """A fully valid schema-4 REPORTABLE candidate: the golden ACCEPT."""
    upstream = novelty_check("upstream_history")
    upstream["channels"] = upstream_channels()
    return {
        "schema_version": 4,
        "candidate_id": "test-baseline",
        "decision_history": [],
        "target": {
            "operating_mode": "SOURCE_ONLY",
            "program": "p",
            "asset": "a",
            "repository": "github.com/o/r",
            "commit": "abc",
            "scope_evidence": "e",
            "scope_checked_at": "2026-08-08",
        },
        "model": {
            "principals": ["x"],
            "protected_assets": ["x"],
            "trust_boundaries": ["x"],
            "state_stores": ["x"],
            "security_invariant": "inv",
            "enforcement_points": ["x"],
        },
        "trace": {
            "entrypoint": "e",
            "attacker_input": "i",
            "validation_path": "v",
            "authorization_path": "a",
            "state_transition": "s",
            "persistence_path": "p",
            "observable_effect": "o",
            "sibling_paths": ["s"],
        },
        "threat_model": {
            "attacker_starting_access": "low",
            "attacker_controls": "input",
            "victim_action": "runs",
            "capability_before": "cannot X",
            "capability_after": "can X",
            "asset_owned_boundary": "b",
            "strongest_refutation": {
                "claim": "maybe attacker already controls the sink",
                "kind": "non_terminal",
                "evidence": "the sink looks caller-influenced",
                "resolution": "the target derives the sink server-side; caller cannot set it",
                "resolution_source": "target_owned",
                "result": "refuted",
            },
        },
        "proof": {
            "type": "executable-local-exact-path",
            "artifact": "poc.py",
            "command": "python poc.py",
            "observed_result": "boundary crossed",
            "negative_controls": ["benign stays put"],
            "production_relevance": "real path",
        },
        "route": {
            "owning_project": "o/r",
            "owner_evidence": "in-repo",
            "submission_target": "program",
            "type": "program",
            "owner_verified": True,
            "proof_type_accepted": True,
            "proof_acceptance_evidence": "source program accepts local proof",
            "scope_verified": True,
        },
        "novelty": {
            "root_cause_fingerprint": "boundary|primitive|invariant|effect",
            "checks": [
                novelty_check("own_reports"),
                novelty_check("program_disclosures"),
                upstream,
                novelty_check("recent_advisories"),
            ],
            "closest_known_match": None,
            "semantic_delta": "new root cause",
            "classification": "distinct",
            "private_duplicate_risk": "medium",
            "current_upstream_state": {
                "ref": "main@abc123",
                "checked_at": "2026-08-08",
                "path": "lib/x.rb:1",
                "result": "vulnerable",
                "evidence": evidence("gh_api_contents", "https://github.com/o/r/blob/main/lib/x.rb#L1"),
            },
        },
        "decision": {
            "verdict": "REPORTABLE",
            "gate": "reportability",
            "failed_gates": [],
            "missing_evidence": [],
            "reason": "all gates cleared",
            "decided_at": "2026-08-08",
        },
    }


def v5_process_blocks():
    """The schema-5 ideation + self-review blocks in their REPORTABLE-passing state."""
    return {
        "hypothesis_queue": [
            {"id": "H-01", "title": "cross-mode chain", "creativity_signal": "non-obvious"}
        ],
        "intent_corpus": {
            "checked_at": "2026-08-08",
            "sources": ["SECURITY.md"],
            "intentional_behaviors": [],
            "acknowledged_risks": [{"quote": "auth bypass is in scope", "source": "SECURITY.md"}],
            "finding_match": "none",
        },
        "adversarial_review": {
            "advocate": {
                "layers_checked": ["framework", "application"],
                "fp_pattern_hits": [],
                "strongest_defense": "no layer blocks the traced path",
                "blocks": False,
            },
            "cold_verify": {
                "verdict": "CONFIRMED",
                "rederived_severity": "high",
                "killed_subclaim": None,
                "subclaims": [
                    {"claim": "attacker controls the report id", "status": "supported"},
                    {"claim": "id reaches the query with no tenant filter", "status": "supported"},
                    {"claim": "the row is returned cross-tenant", "status": "supported"},
                ],
            },
            "causal": [
                {
                    "protection": "input length clamp",
                    "intervention": "removing it still reaches the sink",
                    "counterfactual": "never triggered by normal traffic",
                    "confounder": "in reviewed code, not upstream",
                    "fragility": "fragile",
                }
            ],
        },
        "variant_sweep": {
            "flow_shape": "request -> join -> sql",
            "grep_artifact": "/tmp/sweep.txt",
            "siblings_checked": ["cleanup path"],
            "alternate_transports_checked": ["grpc", "queue"],
            "variants_found": [],
        },
        "patch_bypass": {"base_fix_ref": "", "vectors": {}},
    }


def baseline_v5():
    """A schema-5 REPORTABLE candidate with the process gates satisfied: the golden v5 ACCEPT."""
    doc = baseline()
    doc["schema_version"] = 5
    doc.update(v5_process_blocks())
    return doc


def baseline_nrf():
    """A schema-5 NO_REPORTABLE_FINDING candidate with a full exhaustion record: golden ACCEPT."""
    doc = baseline_v5()
    doc["threat_model"]["capability_before"] = "cannot read other tenants"
    doc["threat_model"]["capability_after"] = "cannot read other tenants"
    doc["threat_model"]["strongest_refutation"] = {
        "claim": "the handler scopes the query to the caller's tenant",
        "kind": "non_terminal",
        "evidence": "ReportController#show applies .where(org_id: current_user.org_id)",
        "resolution": "",
        "resolution_source": "none",
        "result": "confirmed",
    }
    doc["exhaustion"] = {
        "tried": [
            "traced GET /reports/:id end to end",
            "checked the destroy sibling sharing the scope",
            "grepped the flow shape repo-wide",
        ],
        "untried_closed": [],
        "depth_contract": {
            "entrypoint": "GET /api/reports/:id",
            "invariant_enforcement": "ReportController#show tenant scope",
            "trace": "params[:id] -> Report.where(org_id:).find -> render",
            "sibling_checked": "destroy action shares the same scope",
            "defeated_counterexample": "cross-tenant id returns 404 under the tenant filter",
        },
    }
    doc["decision"] = {
        "verdict": "NO_REPORTABLE_FINDING",
        "gate": "refutation",
        "failed_gates": [],
        "missing_evidence": [],
        "reason": "tenant scope holds on the traced path and its sibling",
        "decided_at": "2026-08-18",
    }
    return doc


def case_2_accept():
    # the golden report accept is now schema 5 (schema 4 cannot reach report stage)
    return baseline_v5(), "report", 0


def case_5_accept():
    # same as baseline_v5: commits + issues + PRs evidenced, distinct
    return baseline_v5(), "report", 0


def case_1_reject():
    # refuted but resolution empty -> reject
    doc = baseline_v5()
    doc["threat_model"]["strongest_refutation"]["resolution"] = ""
    return doc, "report", 2


def case_1b_reject():
    # refuted but resolution has no independent evidence artifact
    doc = baseline_v5()
    doc["threat_model"]["strongest_refutation"]["evidence"] = ""
    return doc, "report", 2


def case_3_reject():
    # terminal kind owned_boundary_absent, "resolved" by third-party misuse
    doc = baseline_v5()
    doc["threat_model"]["strongest_refutation"] = {
        "claim": "the SDK model field is not an authorization policy",
        "kind": "owned_boundary_absent",
        "evidence": "SDK exposes model as caller-controlled config and documents caller as responsible",
        "resolution": "a third-party proxy forwards untrusted model, so it is exploitable",
        "resolution_source": "third_party",
        "result": "refuted",
    }
    return doc, "report", 2


def case_4_reject():
    # distinct claimed but upstream_history has no issue/PR channels (git log only)
    doc = baseline_v5()
    for check in doc["novelty"]["checks"]:
        if check["source"] == "upstream_history":
            check.pop("channels", None)
            check["evidence"] = evidence("git_log", "/tmp/git-log.txt")
    return doc, "report", 2


def case_5b_accept():
    # explicit: commits+issues+PRs each evidenced -> accept
    doc = baseline_v5()
    for check in doc["novelty"]["checks"]:
        if check["source"] == "upstream_history":
            check["channels"] = upstream_channels(("no_match", "no_match", "no_match"))
    return doc, "report", 0


def case_6_reject():
    # a checked PR channel exposes a match whose fingerprint == root cause, yet distinct
    doc = baseline_v5()
    fp = doc["novelty"]["root_cause_fingerprint"]
    for check in doc["novelty"]["checks"]:
        if check["source"] == "upstream_history":
            channels = upstream_channels(("no_match", "no_match", "checked"))
            channels[2]["closest_match"] = {
                "id": "PR#153",
                "fingerprint": fp,
                "comparison": "same fix already open",
            }
            check["channels"] = channels
    return doc, "report", 2


def case_7_reject():
    # upstream issue establishes by-design; candidate still claims REPORTABLE
    doc = baseline_v5()
    for check in doc["novelty"]["checks"]:
        if check["source"] == "upstream_history":
            channels = upstream_channels(("no_match", "checked", "no_match"))
            channels[1]["closest_match"] = {
                "id": "issue#358",
                "fingerprint": "boundary|primitive|invariant|by-design",
                "comparison": "maintainer says current behavior is intended",
                "establishes_by_design": True,
            }
            check["channels"] = channels
    return doc, "report", 2


def case_7b_accept():
    # correct handling of the by-design issue: KILL @ refutation, decision stage
    doc = baseline()
    doc["threat_model"]["strongest_refutation"] = {
        "claim": "behavior is the documented contract",
        "kind": "behavior_is_documented_contract",
        "evidence": "upstream issue #358: maintainer states current behavior is intended",
        "resolution": "",
        "resolution_source": "none",
        "result": "confirmed",
    }
    doc["decision"] = {
        "verdict": "KILL",
        "gate": "refutation",
        "failed_gates": ["refutation"],
        "missing_evidence": [],
        "reason": "upstream issue establishes documented-contract behavior",
        "decided_at": "2026-08-08",
    }
    return doc, "decision", 0


def legacy_backward_compat_accept():
    # schema 3, legacy string refutation, HOLD @ route (non-distinct path) still validates
    doc = baseline()
    doc["schema_version"] = 3
    doc["threat_model"]["strongest_refutation"] = "attacker may already control the peer"
    doc["threat_model"]["refutation_result"] = "unresolved"
    doc["route"]["scope_verified"] = False
    doc["route"]["type"] = "none"
    doc["route"]["owner_verified"] = False
    for check in doc["novelty"]["checks"]:
        check.pop("evidence", None)
        check.pop("channels", None)
    doc["novelty"]["classification"] = "uncertain"
    doc["decision"] = {
        "verdict": "HOLD",
        "gate": "route",
        "failed_gates": [],
        "missing_evidence": ["confirm program scope covers this repo"],
        "reason": "scope unverified",
        "decided_at": "2026-08-08",
    }
    return doc, "decision", 0


# (label, builder, required stderr substring for the REJECT reason)
def case_A_reject():
    # stale checkout vulnerable, but current main is fixed -> distinct rejected
    doc = baseline_v5()
    doc["novelty"]["current_upstream_state"]["result"] = "fixed"
    return doc, "report", 2


def case_B_accept():
    # current main still vulnerable with a fetch artifact -> distinct accepted
    return baseline_v5(), "report", 0


def case_C_reject():
    # GitHub PR channel unavailable with only a prose reason (no attempt artifact)
    doc = baseline_v5()
    for check in doc["novelty"]["checks"]:
        if check["source"] == "upstream_history":
            channels = upstream_channels(("no_match", "no_match", "unavailable"))
            channels[2].pop("evidence", None)
            channels[2]["reason"] = "PR search unavailable"
            check["channels"] = channels
    return doc, "report", 2


def case_D_reject():
    # GitHub PR search attempted, tool failed, artifact present, but still claims distinct
    doc = baseline_v5()
    for check in doc["novelty"]["checks"]:
        if check["source"] == "upstream_history":
            channels = upstream_channels(("no_match", "no_match", "unavailable"))
            channels[2]["reason"] = "GitHub API returned 403"
            channels[2]["evidence"] = evidence("gh_pr_search", "/tmp/gh-pr-403.txt")
            check["channels"] = channels
    return doc, "report", 2


def case_E_accept():
    # non-GitHub upstream with no PR concept -> unavailable channels accepted
    doc = baseline_v5()
    doc["target"]["repository"] = "git.launchpad.net/o/r"
    doc["route"]["owning_project"] = "o/r"
    for check in doc["novelty"]["checks"]:
        if check["source"] == "upstream_history":
            channels = upstream_channels(("no_match", "unavailable", "unavailable"))
            channels[1]["reason"] = "no issue tracker on this forge"
            channels[1].pop("evidence", None)
            channels[2]["reason"] = "no pull-request concept on this forge"
            channels[2].pop("evidence", None)
            check["channels"] = channels
    return doc, "report", 0


def case_F_reject():
    # confirmed terminal kind but KILL at the wrong gate
    doc = baseline()
    doc["threat_model"]["strongest_refutation"] = {
        "claim": "the caller already holds this capability",
        "kind": "capability_already_possessed",
        "evidence": "the attacker principal already has the grant",
        "resolution": "",
        "resolution_source": "none",
        "result": "confirmed",
    }
    doc["decision"] = {
        "verdict": "KILL",
        "gate": "refutation",
        "failed_gates": ["refutation"],
        "missing_evidence": [],
        "reason": "kind is capability_already_possessed",
        "decided_at": "2026-08-08",
    }
    return doc, "decision", 2


def case_G_accept():
    # confirmed terminal kind, KILL at its mapped gate
    doc = baseline()
    doc["threat_model"]["capability_before"] = "can already do X"
    doc["threat_model"]["capability_after"] = "can already do X"
    doc["threat_model"]["strongest_refutation"] = {
        "claim": "the caller already holds this capability",
        "kind": "capability_already_possessed",
        "evidence": "the attacker principal already has the grant",
        "resolution": "",
        "resolution_source": "none",
        "result": "confirmed",
    }
    doc["decision"] = {
        "verdict": "KILL",
        "gate": "capability_delta",
        "failed_gates": ["capability_delta"],
        "missing_evidence": [],
        "reason": "capability unchanged; caller already possessed it",
        "decided_at": "2026-08-08",
    }
    return doc, "decision", 0


TDNO = {
    "claim": "the target does not own this security property",
    "kind": "target_does_not_own_security_property",
    "evidence": "the defective boundary is defined and enforced by a different project",
    "resolution": "",
    "resolution_source": "none",
    "result": "confirmed",
}


def case_H_accept():
    # target_does_not_own + confirmed -> KILL @ ownership (nobody eligible owns it here)
    doc = baseline()
    doc["threat_model"]["strongest_refutation"] = dict(TDNO)
    doc["decision"] = {
        "verdict": "KILL",
        "gate": "ownership",
        "failed_gates": ["ownership"],
        "missing_evidence": [],
        "reason": "no bounty-eligible owner for this boundary in the target",
        "decided_at": "2026-08-08",
    }
    return doc, "decision", 0


def case_I_accept():
    # target_does_not_own + confirmed -> ROUTE_ELSEWHERE @ route (another project owns it)
    doc = baseline()
    doc["threat_model"]["strongest_refutation"] = dict(TDNO)
    doc["route"]["owning_project"] = "other-org/other-repo"
    doc["route"]["owner_evidence"] = "the defective boundary is implemented in other-org/other-repo"
    doc["route"]["submission_target"] = "upstream advisory to other-org/other-repo"
    doc["route"]["type"] = "upstream-advisory"
    doc["route"]["owner_verified"] = True
    doc["decision"] = {
        "verdict": "ROUTE_ELSEWHERE",
        "gate": "route",
        "failed_gates": [],
        "missing_evidence": [],
        "reason": "another project owns the defective boundary",
        "decided_at": "2026-08-08",
    }
    return doc, "decision", 0


def case_J_reject():
    # target_does_not_own + confirmed but KILL at the wrong gate
    doc = baseline()
    doc["threat_model"]["capability_before"] = "same capability"
    doc["threat_model"]["capability_after"] = "same capability"
    doc["threat_model"]["strongest_refutation"] = dict(TDNO)
    doc["decision"] = {
        "verdict": "KILL",
        "gate": "capability_delta",
        "failed_gates": ["capability_delta"],
        "missing_evidence": [],
        "reason": "killed at the wrong gate on purpose",
        "decided_at": "2026-08-08",
    }
    return doc, "decision", 2


def case_K_accept():
    # schema-5 with intent corpus clean + cold verify CONFIRMED + no FP hits -> accept
    return baseline_v5(), "report", 0


def case_L_reject():
    # finding matches a documented intentional behavior -> forbid REPORTABLE
    doc = baseline_v5()
    doc["intent_corpus"]["finding_match"] = "intentional"
    return doc, "report", 2


def case_M_reject():
    # cold verifier did not CONFIRM -> forbid REPORTABLE
    doc = baseline_v5()
    doc["adversarial_review"]["cold_verify"]["verdict"] = "DISPROVED"
    return doc, "report", 2


def case_N_reject():
    # an FP-pattern hit with no rebuttal -> forbid REPORTABLE
    doc = baseline_v5()
    doc["adversarial_review"]["advocate"]["fp_pattern_hits"] = [
        {"pattern": "same-origin confusion", "rebuttal": ""}
    ]
    return doc, "report", 2


def case_O_accept():
    # same FP-pattern hit, now rebutted with a grounded evidence locator -> accept
    doc = baseline_v5()
    doc["adversarial_review"]["advocate"]["fp_pattern_hits"] = [
        {
            "pattern": "same-origin confusion",
            "rebuttal": "cross-tenant: attacker A reads tenant B",
            "evidence": "ReportController#show loads Report.find(id) with no org filter (app/controllers/report_controller.rb:12)",
        }
    ]
    return doc, "report", 0


def case_P_reject():
    # schema-5 REPORTABLE missing the adversarial_review block entirely -> reject
    doc = baseline_v5()
    del doc["adversarial_review"]
    return doc, "report", 2


def case_Q_reject():
    # a fully valid schema-4 REPORTABLE cannot reach report stage; migrate to schema 5
    return baseline(), "report", 2


def case_R_reject():
    # cold_verify CONFIRMED but the Advocate's own defense blocks the finding -> reject
    doc = baseline_v5()
    doc["adversarial_review"]["advocate"]["blocks"] = True
    return doc, "report", 2


def case_S_reject():
    # cold_verify CONFIRMED contradicts a non-null killed_subclaim -> reject
    doc = baseline_v5()
    doc["adversarial_review"]["cold_verify"]["killed_subclaim"] = "sub-claim B never proven"
    return doc, "report", 2


def case_T_reject():
    # cold_verify CONFIRMED with an empty rederived_severity -> reject
    doc = baseline_v5()
    doc["adversarial_review"]["cold_verify"]["rederived_severity"] = ""
    return doc, "report", 2


def case_U_reject():
    # Advocate recorded no protection layers searched -> the pass did not run -> reject
    doc = baseline_v5()
    doc["adversarial_review"]["advocate"]["layers_checked"] = []
    return doc, "report", 2


def case_V_reject():
    # intent corpus with no sources listed -> an empty corpus pass -> reject
    doc = baseline_v5()
    doc["intent_corpus"]["sources"] = []
    return doc, "report", 2


def case_W_reject():
    # FP-pattern hit rebutted in prose but with no evidence locator -> reject
    doc = baseline_v5()
    doc["adversarial_review"]["advocate"]["fp_pattern_hits"] = [
        {"pattern": "framework-protection blindness", "rebuttal": "the ORM does not parameterize this call"}
    ]
    return doc, "report", 2


def case_XA_accept():
    # schema-5 NO_REPORTABLE_FINDING with a full exhaustion record -> accept
    return baseline_nrf(), "decision", 0


def case_XB_reject():
    # NO_REPORTABLE_FINDING with the exhaustion block removed -> reject
    doc = baseline_nrf()
    del doc["exhaustion"]
    return doc, "decision", 2


def case_XC_reject():
    # NO_REPORTABLE_FINDING with an incomplete depth_contract -> reject
    doc = baseline_nrf()
    doc["exhaustion"]["depth_contract"]["trace"] = ""
    return doc, "decision", 2


def case_XD_reject():
    # NO_REPORTABLE_FINDING with an empty tried[] -> reject
    doc = baseline_nrf()
    doc["exhaustion"]["tried"] = []
    return doc, "decision", 2


def case_XE_reject():
    # CONFIRMED cold_verify with no sub-claim decomposition -> reject
    doc = baseline_v5()
    doc["adversarial_review"]["cold_verify"]["subclaims"] = []
    return doc, "report", 2


def case_XF_reject():
    # CONFIRMED cold_verify but one sub-claim is unsupported -> reject
    doc = baseline_v5()
    doc["adversarial_review"]["cold_verify"]["subclaims"] = [
        {"claim": "attacker controls X", "status": "supported"},
        {"claim": "X reaches the sink unsanitized", "status": "unsupported"},
    ]
    return doc, "report", 2


CASES = [
    ("2  resolution attacks same boundary -> ACCEPT", case_2_accept, None),
    ("K  schema-5 process gates satisfied -> ACCEPT", case_K_accept, None),
    ("O  FP-pattern hit rebutted -> ACCEPT", case_O_accept, None),
    ("L  intent match intentional -> REJECT", case_L_reject, "intentional forbids REPORTABLE"),
    ("M  cold verify not CONFIRMED -> REJECT", case_M_reject, "cold_verify.verdict CONFIRMED"),
    ("N  unrebutted FP-pattern hit -> REJECT", case_N_reject, "unrebutted"),
    ("P  schema-5 missing adversarial_review -> REJECT", case_P_reject, "requires an adversarial_review block"),
    ("Q  schema-4 at report stage -> REJECT", case_Q_reject, "schema_version >= 5"),
    ("R  advocate blocks the finding, yet REPORTABLE -> REJECT", case_R_reject, "advocate.blocks is true"),
    ("S  cold_verify CONFIRMED + killed_subclaim -> REJECT", case_S_reject, "killed_subclaim"),
    ("T  cold_verify CONFIRMED, empty severity -> REJECT", case_T_reject, "rederived_severity"),
    ("U  advocate searched no layers -> REJECT", case_U_reject, "layers_checked"),
    ("V  intent corpus with no sources -> REJECT", case_V_reject, "intent_corpus.sources"),
    ("W  FP rebuttal with no evidence locator -> REJECT", case_W_reject, "needs evidence"),
    ("XA NO_REPORTABLE_FINDING + exhaustion record -> ACCEPT", case_XA_accept, None),
    ("XB NO_REPORTABLE_FINDING, no exhaustion block -> REJECT", case_XB_reject, "requires an exhaustion block"),
    ("XC NO_REPORTABLE_FINDING, incomplete depth_contract -> REJECT", case_XC_reject, "depth_contract.trace"),
    ("XD NO_REPORTABLE_FINDING, empty tried[] -> REJECT", case_XD_reject, "exhaustion.tried"),
    ("XE CONFIRMED cold_verify, no subclaims -> REJECT", case_XE_reject, "cold_verify.subclaims"),
    ("XF CONFIRMED cold_verify, unsupported subclaim -> REJECT", case_XF_reject, "not supported"),
    ("5  commits+issues+PRs evidenced -> ACCEPT", case_5_accept, None),
    ("5b upstream channels explicit -> ACCEPT", case_5b_accept, None),
    ("7b by-design -> KILL@refutation -> ACCEPT", case_7b_accept, None),
    ("legacy schema-3 HOLD@route -> ACCEPT", legacy_backward_compat_accept, None),
    ("1  refuted, empty resolution -> REJECT", case_1_reject, "resolution"),
    ("1b refuted, no evidence artifact -> REJECT", case_1b_reject, "evidence"),
    ("3  terminal kind resolved by third-party -> REJECT", case_3_reject, "terminal refutation"),
    ("4  distinct via git log only, no issue/PR -> REJECT", case_4_reject, "channels covering"),
    ("6  checked match == root fingerprint yet distinct -> REJECT", case_6_reject, "identical to root_cause_fingerprint"),
    ("7  by-design issue but still REPORTABLE -> REJECT", case_7_reject, "establishes_by_design"),
    ("B  current main vulnerable + fetch artifact -> ACCEPT", case_B_accept, None),
    ("E  non-github upstream, unavailable PR/issues -> ACCEPT", case_E_accept, None),
    ("G  terminal kind + KILL at mapped gate -> ACCEPT", case_G_accept, None),
    ("A  stale checkout, current main fixed -> REJECT", case_A_reject, "fixed forbids distinct"),
    ("C  github PR unavailable, prose only -> REJECT", case_C_reject, "attempted-search artifact"),
    ("D  github PR unavailable w/ artifact, distinct -> REJECT", case_D_reject, "channels covering"),
    ("F  terminal kind + KILL at wrong gate -> REJECT", case_F_reject, "requires decision.gate"),
    ("H  target_does_not_own + KILL@ownership -> ACCEPT", case_H_accept, None),
    ("I  target_does_not_own + ROUTE_ELSEWHERE@route -> ACCEPT", case_I_accept, None),
    ("J  target_does_not_own + KILL@capability_delta -> REJECT", case_J_reject, "requires decision.gate"),
]


def main():
    failures = 0
    for label, builder, substr in CASES:
        doc, stage, expected = builder()
        code, stderr = run(doc, stage)
        ok = code == expected
        # For REJECT cases, require the rejection to cite the intended rule,
        # not an incidental schema error.
        if ok and expected == 2 and substr and substr not in stderr:
            ok = False
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        print(f"[{status}] {label}  (stage={stage} expected={expected} got={code})")
        if not ok and stderr.strip():
            for line in stderr.strip().splitlines()[:3]:
                print(f"         stderr: {line}")
    print(f"\n{len(CASES) - failures}/{len(CASES)} cases behaved as specified")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
