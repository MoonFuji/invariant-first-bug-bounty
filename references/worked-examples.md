# Worked Examples

## Contents
- Example 1 — the subtle KILL: owned boundary vs. integrator misuse (`KILL @ refutation`)
- Example 2 — a clean REPORTABLE: cross-tenant read (`REPORTABLE @ reportability`)
- Example 3 — HOLD: proof stuck at primitive fidelity (`HOLD @ proof`)
- Example 4 — ROUTE_ELSEWHERE: the fix belongs upstream (`ROUTE_ELSEWHERE @ route`)
- Calibration from real informatives — the caveat is the verdict

Four candidates walked to a terminal verdict, showing the decisive `candidate.json` fields
(not the whole file — see `assets/candidate.template.json` for the full shape). Copy the
*shape of the reasoning*, not the specifics. The point of each is the gate where it lands and
why.

## Example 1 — the subtle KILL: owned boundary vs. integrator misuse

**Situation.** `querykit` is an in-scope query-builder library with its own bounty program.
Its `build_where(field, value)` concatenates `value` into SQL unescaped. A popular integrator,
`shopflow`, calls `build_where("email", request.form["email"])`, so an attacker hitting
`shopflow` injects SQL. The tempting move is to report SQLi to `querykit` and attach the
`shopflow` path as proof.

**Why it is not a `querykit` finding.** Read `querykit`'s contract first (Workflow step 1, intent
corpus). Its README documents `build_where` as a *raw* builder: the caller must pre-sanitize;
a separate `bind()` API parameterizes. So the unescaped concatenation is **documented behavior**,
not a violated invariant `querykit` owns. `shopflow` fed request input into a raw builder — that
is `shopflow`'s missing validation. The downstream PoC proves the *integrator* is exploitable,
not that `querykit` broke a promise (rationalizations table: "But a real integrator forwards
untrusted input into this").

**Decisive fields.**

```jsonc
"intent_corpus": {
  "checked_at": "2026-08-18",
  "sources": ["README.md", "build_where docstring"],
  "intentional_behaviors": [
    { "quote": "build_where is a raw builder; callers must pass sanitized values. Use bind() to parameterize.",
      "source": "README.md#raw-builders" }
  ],
  "finding_match": "intentional"
},
"threat_model": {
  "strongest_refutation": {
    "claim": "querykit's build_where is a raw builder whose documented contract delegates escaping to the caller",
    "kind": "behavior_is_documented_contract",
    "evidence": "README.md#raw-builders states callers must sanitize; bind() is the parameterizing API",
    "resolution": "",
    "resolution_source": "none",
    "result": "confirmed"
  }
},
"decision": {
  "verdict": "KILL",
  "gate": "refutation",
  "failed_gates": ["refutation"],
  "missing_evidence": [],
  "reason": "unescaped concat is querykit's documented raw-builder contract; the bug is shopflow's missing validation",
  "decided_at": "2026-08-18"
}
```

`intent_corpus.finding_match: "intentional"` and the terminal refutation kind both forbid
`REPORTABLE`; the validator lands it at `KILL @ refutation`. If `querykit` instead presented
`build_where` as a normal, safe method (no trusted-input contract), the honest kind would be
`non_terminal` and the finding could proceed — with a `querykit`-only PoC, never `shopflow`'s
code. Route the real issue to `shopflow`; a hardening suggestion to `querykit` is not a bounty.

## Example 2 — a clean REPORTABLE: cross-tenant read

**Situation.** `acme-saas` is an in-scope hosted product backed by public source. The invariant:
a user reads only records in their own tenant. `GET /api/reports/:id` loads by primary key with
no tenant predicate, so tenant A reads tenant B's report.

**Why it clears every gate.** Two owned test tenants in a local deployment (`PROGRAM_HOSTED` not
needed — reproduced on a researcher-owned instance) show tenant A retrieving tenant B's uniquely
tagged record, with an anonymous control returning 401 and a same-tenant control returning the
row. The strongest refutation — "maybe the id is unguessable / maybe middleware scopes it" — is
defeated by target-owned evidence: ids are sequential and the handler has no tenant filter.
Novelty search (own reports, program disclosures, upstream issues/PRs, current branch) finds no
match; the current default branch still carries the flaw.

**Decisive fields.**

```jsonc
"threat_model": {
  "capability_before": "tenant A reads only tenant A records",
  "capability_after": "tenant A reads any tenant's report by id",
  "strongest_refutation": {
    "claim": "the report id may be unguessable or middleware may scope the query to the tenant",
    "kind": "non_terminal",
    "evidence": "ids are sequential integers; ReportController#show has no org_id/tenant filter",
    "resolution": "the handler loads Report.find(params[:id]) with no tenant predicate; A retrieves B's tagged record",
    "resolution_source": "target_owned",
    "result": "refuted"
  }
},
"proof": {
  "type": "executable-local-exact-path",
  "artifact": "poc.sh",
  "command": "./poc.sh (tenant-A token GETs tenant-B report id)",
  "observed_result": "200 with tenant-B's canary field; anon control 401; same-tenant control 200",
  "negative_controls": ["anonymous request returns 401", "nonexistent id returns 404"],
  "production_relevance": "same handler and route ship in the hosted product"
},
"adversarial_review": {
  "advocate": { "layers_checked": ["framework","application","middleware"], "fp_pattern_hits": [], "blocks": false },
  "cold_verify": { "verdict": "CONFIRMED", "rederived_severity": "high", "killed_subclaim": null }
},
"novelty": { "classification": "distinct", "private_duplicate_risk": "medium" },
"decision": {
  "verdict": "REPORTABLE",
  "gate": "reportability",
  "failed_gates": [],
  "missing_evidence": [],
  "reason": "cross-tenant read reproduced on the exact shipped path with controls; distinct and still live",
  "decided_at": "2026-08-18"
}
```

The refutation is `non_terminal` with a `target_owned` resolution and its own evidence;
capability changed; proof exercises the exact shipped path with a negative control;
`cold_verify` is `CONFIRMED`; novelty is `distinct`. `--stage report` exits 0 and the report may
be drafted.

## Example 3 — HOLD: proof stuck at primitive fidelity

**Situation.** SSRF candidate in `acme-gateway`. The trace is complete, the capability delta is
real, and the strongest refutation is resolved — but the only PoC runs against a substitute HTTP
client that copies the vulnerable lines, not the exact shipped executable through its real request
path. Rent is due and a novelty window is closing.

**Why it holds, not reports.** Everything through the `refutation` gate is evidenced, so this is
not a `KILL`. But `proof` needs the exact shipped path (Workflow step 8): a substitute client is
primitive fidelity only. Pressure is not evidence (Red flags — STOP). The honest verdict is
`HOLD` with the one missing artifact named — a success, and a to-do, not a report.

```jsonc
"proof": {
  "type": "none",
  "artifact": "poc_substitute_client.py",
  "command": "python poc_substitute_client.py",
  "observed_result": "substitute client follows the attacker URL — primitive fidelity only",
  "negative_controls": [],
  "production_relevance": "not yet established through the shipped path"
},
"decision": {
  "verdict": "HOLD",
  "gate": "proof",
  "failed_gates": [],
  "missing_evidence": [
    "invoke the exact pinned acme-gateway binary through its real request handler; capture the listener hit, version/command artifacts, exit status, and a negative control that a blocked URL fails"
  ],
  "reason": "trace and refutation complete; proof is primitive-only, exact shipped path not yet exercised",
  "decided_at": "2026-08-18"
}
```

`HOLD` requires an empty `failed_gates` and a non-empty `missing_evidence`; the validator checks
the evidence accumulated through the gate *before* `proof`. Build the real path next; the finding
either upgrades to `REPORTABLE` or dies at `KILL @ reachability` when a guard neutralizes it.

## Example 4 — ROUTE_ELSEWHERE: the fix belongs upstream

**Situation.** A path-traversal bug reproduces in `acme-app`, but the flaw lives entirely in an
open-source archive-extraction library `acme-app` bundles unmodified. `acme-app` neither wrote nor
can fix the defective code; the upstream library owns the boundary and would ship the fix.

**Why it routes.** The bug is real and reproduced, so it is not a `KILL @ reachability`. But
`acme-app`'s program does not own the faulty code (Workflow step 9). The strongest refutation is a
confirmed `target_does_not_own_security_property`; a confirmed terminal refutation of that kind
lands at `ownership|route`. Here another project owns and can fix it, so route it upstream (advisory
/ its own program), not to `acme-app`.

```jsonc
"threat_model": {
  "strongest_refutation": {
    "claim": "the traversal is implemented in the bundled upstream library, which owns and enforces this boundary",
    "kind": "target_does_not_own_security_property",
    "evidence": "the vulnerable extract() ships verbatim from upstream vX.Y; acme-app calls it unmodified",
    "resolution": "",
    "resolution_source": "none",
    "result": "confirmed"
  }
},
"route": {
  "owning_project": "upstream-org/archive-lib",
  "owner_evidence": "the defective extract() is defined and shipped by upstream-org/archive-lib vX.Y",
  "submission_target": "upstream advisory to upstream-org/archive-lib (or its bounty program)",
  "type": "upstream-advisory",
  "owner_verified": true
},
"decision": {
  "verdict": "ROUTE_ELSEWHERE",
  "gate": "route",
  "failed_gates": [],
  "missing_evidence": [],
  "reason": "real traversal, but the faulty code is owned and fixed by the upstream library, not acme-app",
  "decided_at": "2026-08-18"
}
```

Filing this against `acme-app`'s program because it has a payout is venue-shopping; the fix — and
the valid disclosure — belongs where the code lives.

## Calibration from real informatives — the caveat is the verdict

Every finding below was a **real code defect, competently proven** — and closed **Informative**.
In each, the hunter *wrote the disqualifying sentence into its own report*, then submitted as if
that sentence were a footnote. It is not a footnote; **it is the verdict. A hedge you write about
your own impact is a kill-condition, not a disclosure.** If a draft contains "does not prove
production exposure", "does not bypass authentication", "requires control of env/config", "no
production path is required for the demonstrated case", or "may be treated as non-core/beta", that
clause forbids `REPORTABLE` until it is removed by *evidence*, not by argument. This is the mirror
of the "doubt must be evidenced" rule (`adversarial-self-review.md`), pointed at self-hedges about
*impact* instead of *mitigations* — and it is a **reading discipline**, not a field: no validator
can smell an informative, so you must catch your own hedge.

**The one-sentence test.** Before `REPORTABLE`, write exactly: *"The attacker, who already holds
X, crosses boundary Y to gain capability Z they could not do before."* If you cannot write it
without a hedge, the verdict is `KILL`/`HOLD`. Four kill-questions, each anchored to a finding that
was really submitted and really closed informative:

| Kill-question | Real informative | The self-caveat it *contained* (verbatim) | Lands at |
|---|---|---|---|
| **Boundary** — do attacker and victim differ, or is it the same realm/principal? | `@exodus/keychain` key-leak (#3948361) | *"No production IPC path is required for this demonstrated capability change"* — the recovering caller is the **same principal** already holding the signer; the cross-realm sink is asserted, never shown | `KILL @ reachability` |
| **Precondition** — does what the attacker must already hold already grant the effect? | anthropic `_require_https` cleartext-token (#3858135) | *"Gated behind attacker influence over `base_url` via env/config"* — writing the victim's env is already ≥ the stolen token; also flagged *"may be treated as non-core"* (beta) | `KILL @ capability_delta` |
| **Deployment** — an insecure default a real deployment overrides, undemonstrated live? | lightspark QueryNodes default-config (#3852098) | *"this draft does not prove live production deployment exposure … Do not submit as High"* — manifests only under a shipped default (`service_authz: disabled`) real deployments override with VPC/allowlist | `HOLD @ proof` (config-dependency) |
| **Control class** — is the bypassed thing an authz boundary, or defense-in-depth/UX? | crypto.com MCP safety-tier (#3857707) | *"It does not bypass API-key authentication"* — the "control" is an agent acknowledgement prompt; the credential-holder could already make the call | `KILL @ capability_delta` |

The unifying test: a real defect is not a finding until it grants a **new** capability to an
**attacker-reachable** actor across a **crossed boundary** in a **real** deployment. Absent that it
is `HOLD`/`KILL`, never a submission — even when the code is genuinely wrong.

The `default_only` / `requires_insecure_config` cases also map to the checkable field
`proof.config_dependency` (both forbid `REPORTABLE`; a lab-reproduced source-only finding is `none`).
The boundary and precondition cases are `reachability` / `capability_delta` judgments the validator
cannot make for you — which is exactly why the hedge-is-the-verdict rule is a discipline you run by
hand, on your own draft, before `--stage report`.
