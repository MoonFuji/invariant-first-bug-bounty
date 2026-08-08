#!/usr/bin/env python3
"""Acceptance tests for validate-candidate.py (skill v0.3.1 / schema 4).

Reproduces the two failure shapes that reached HackerOne as Informative:
  - a terminal refutation marked `refuted` with no resolution attacking the
    owned boundary (an anonymized model-routing case / case B);
  - a `distinct` novelty claim backed only by `git log`, skipping the upstream
    issue/PR search (marcel #153 live dup; activeresource #358 by-design).

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


def case_2_accept():
    return baseline(), "report", 0


def case_5_accept():
    # same as baseline: commits + issues + PRs evidenced, distinct
    return baseline(), "report", 0


def case_1_reject():
    # refuted but resolution empty -> reject
    doc = baseline()
    doc["threat_model"]["strongest_refutation"]["resolution"] = ""
    return doc, "report", 2


def case_1b_reject():
    # refuted but resolution has no independent evidence artifact
    doc = baseline()
    doc["threat_model"]["strongest_refutation"]["evidence"] = ""
    return doc, "report", 2


def case_3_reject():
    # terminal kind owned_boundary_absent, "resolved" by third-party misuse
    doc = baseline()
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
    doc = baseline()
    for check in doc["novelty"]["checks"]:
        if check["source"] == "upstream_history":
            check.pop("channels", None)
            check["evidence"] = evidence("git_log", "/tmp/git-log.txt")
    return doc, "report", 2


def case_5b_accept():
    # explicit: commits+issues+PRs each evidenced -> accept
    doc = baseline()
    for check in doc["novelty"]["checks"]:
        if check["source"] == "upstream_history":
            check["channels"] = upstream_channels(("no_match", "no_match", "no_match"))
    return doc, "report", 0


def case_6_reject():
    # a checked PR channel exposes a match whose fingerprint == root cause, yet distinct
    doc = baseline()
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
    doc = baseline()
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
    doc = baseline()
    doc["novelty"]["current_upstream_state"]["result"] = "fixed"
    return doc, "report", 2


def case_B_accept():
    # current main still vulnerable with a fetch artifact -> distinct accepted
    return baseline(), "report", 0


def case_C_reject():
    # GitHub PR channel unavailable with only a prose reason (no attempt artifact)
    doc = baseline()
    for check in doc["novelty"]["checks"]:
        if check["source"] == "upstream_history":
            channels = upstream_channels(("no_match", "no_match", "unavailable"))
            channels[2].pop("evidence", None)
            channels[2]["reason"] = "PR search unavailable"
            check["channels"] = channels
    return doc, "report", 2


def case_D_reject():
    # GitHub PR search attempted, tool failed, artifact present, but still claims distinct
    doc = baseline()
    for check in doc["novelty"]["checks"]:
        if check["source"] == "upstream_history":
            channels = upstream_channels(("no_match", "no_match", "unavailable"))
            channels[2]["reason"] = "GitHub API returned 403"
            channels[2]["evidence"] = evidence("gh_pr_search", "/tmp/gh-pr-403.txt")
            check["channels"] = channels
    return doc, "report", 2


def case_E_accept():
    # non-GitHub upstream with no PR concept -> unavailable channels accepted
    doc = baseline()
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


CASES = [
    ("2  resolution attacks same boundary -> ACCEPT", case_2_accept, None),
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
