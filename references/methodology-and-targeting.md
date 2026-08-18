# Methodology and Targeting

## Contents

1. Target and route selection
2. Invariant-first source review
3. Discovery techniques
4. Contestability and duplicate risk
5. Threat model and proof requirements
6. Routing, severity, and report structure
7. Terminal decisions

## 1. Target and route selection

Select for **provability, ownership, and contestability**, not headline severity.

Before auditing, record in `candidate.json`:

- The declared operating mode (`SOURCE_ONLY` by default, or explicitly authorized `PROGRAM_HOSTED`) in `target.operating_mode`, with its authorization basis in `target.scope_evidence`.
- Current program status, asset, accepted bug classes, and scope evidence.
- Exact repository and commit/release actually shipped or accepted by the program.
- Whether a hosted instance, owned accounts, local deployment, device, or upstream advisory route is available.
- The project that owns the suspected code and would ship its fix.
- Payout eligibility and whether the payout rail is usable.

Score candidates 1–5 on each axis:

| Axis | Weight | 5 | 1 |
|---|---:|---|---|
| Exact proof available | ×3 | Live/real path and safe controls available | Only a statement-level trace |
| Route ownership | ×3 | Destination clearly owns code and proof class | Dependency/ownership ambiguous |
| Low contestability | ×3 | Product-specific invariant in under-reviewed code | Famous component or fresh-advisory hotspot |
| Security-model leverage | ×2 | Stateful authz/logic/identity boundary | Generic isolated sink |
| Stack fit | ×1 | Runtime and tests can be exercised | Unfamiliar/unbuildable target |
| Payout reliability | ×1 | Paying, responsive, accessible | VDP, blocked rail, or unstable scope |

A recent advisory is a **contestability penalty** unless the candidate proves a different semantic invariant, enforcement path, or affected asset. Fresh feature code and newly added scope can be attractive; a famous fresh CVE is usually crowded.

Route classes:

- **Hosted/grey-box:** use only in `PROGRAM_HOSTED`; read source to locate the invariant, then use explicitly permitted owned accounts/data or an owned deployment.
- **Source-code program:** reproduce the exact shipped code path and verify the program accepts local/source evidence.
- **Upstream library/SDK:** report to the project that owns the code; obtain a fix/advisory/CVE when required, then use IBB only if eligible.
- **Black-box:** reconstruct principals, objects, state transitions, and authorization from owned-account behavior before testing.

## 2. Invariant-first source review

Selective comprehension is mandatory. Do not read every file, but read enough connected code to explain the security state machine.

### 2.1 Build the model

Record:

| Element | Questions |
|---|---|
| Principals | Who acts: anonymous, user, tenant admin, service, peer, tool, device? |
| Protected assets | What data, money, identity, execution, quota, or integrity state is protected? |
| Trust boundaries | Which actor-to-actor or component-to-component transition must be isolated? |
| State stores | Which DB constraint, cache key, filesystem path, token store, queue, or device state enforces it? |
| Enforcement points | Where are authentication, authorization, canonicalization, uniqueness, and state transitions checked? |
| Invariant | What must remain true across every path? |

Good invariants are falsifiable:

- A verification identifier can be consumed once across all equivalent encodings.
- A tenant can read or mutate only objects it owns or was explicitly granted.
- A denied/ask tool event cannot execute a consequential local tool.
- Internal-only RPC methods cannot be reached through a public listener.
- A caller cannot redirect a victim-owned credential to an attacker endpoint.

### 2.2 Trace end to end

Follow this spine:

```text
attacker-controlled representation
  → parser / transport / entrypoint
  → authentication
  → normalization or canonicalization
  → authorization or validation
  → lookup / state read
  → mutation / external action
  → persistence / uniqueness / cache
  → observable security effect
```

Explicitly mark `not applicable` where a stage truly does not exist. Do not leave a load-bearing stage implicit.

Trace at least one sibling:

- create/read/update/delete/list/export/preview/share
- v1/v2, web/mobile, sync/async, public/internal
- SDKs in different languages
- check/read path versus write/conflict path
- released branch versus main/fix branch

The sibling is evidence only after explaining why the difference changes enforcement. A missing call or different regex is not automatically a vulnerability.

### 2.3 High-yield invariant lenses

Apply lenses only when the architecture contains the primitive:

- **Representation asymmetry:** validation canonicalizes but storage, uniqueness, ACL, cache, idempotency, or rate-limit keys use a raw form.
- **Confused object identity:** authorize the URL object but act on a body object, alias, foreign key, or resolved sibling.
- **Enforcement split:** UI/public/v2 path checks a restriction while API/internal/v1/import/export path omits it.
- **State-machine gap:** a transition is legal from an impossible state, repeated, reordered, or raced.
- **Trust-mode mismatch:** a public/untrusted caller reaches an internal/trusted path or toggles the trust bit.
- **TOCTOU/uniqueness:** check-then-write or read-then-act leaves a concurrency window not closed by the authoritative constraint.
- **Parser differential:** security validation and the consuming parser disagree on the same bytes or representation.

Mine a confirmed invariant across meaningful siblings before rotating. Do not rotate merely to sample another class.

## 3. Discovery techniques

Choose techniques after the model identifies relevant primitives:

- **Authz trace:** follow one protected resource through every operation and identity source.
- **State transition audit:** derive allowed states, then test repeat, reorder, cancellation, retry, and race behavior.
- **Security-test gap:** compare security tests with reachable siblings and missing negative cases.
- **Fix-diff analysis:** extract the invariant a patch intended to restore, then inspect uncovered siblings and mirrors. Treat the hotspot as highly contested.
- **Variant analysis:** after confirming one causal pattern, encode semantic source/flow/sink or structural enforcement differences with CodeQL/Semgrep.
- **Sensitive-operation search:** use only when the model exposes a relevant attacker-controlled source and boundary. Trace every hit to effect.
- **History analysis:** inspect blame, changelog, branches, releases, open/closed PRs, issues, advisories, and `git log -p` around the enforcement point.

Broad recon is coverage, not discovery proof. Run `scripts/recon-sweep.sh` only with a model-ready candidate.

## 4. Contestability and duplicate risk

Private duplicate pools cannot be queried. Deduplication is probability management, not proof of uniqueness.

### 4.1 Fingerprint root cause

Use:

```text
boundary | primitive | invariant | effect
```

Example:

```text
tenant A→tenant B | global-id lookup | owner-only read | private invoice disclosure
```

Compare semantics, not titles or CWE labels.

### 4.2 Search in this order

1. **Your own outcomes:** inventory valid, duplicate, informative, and routed reports. Record fingerprints and duplicate references.
2. **Program history:** disclosed reports for the component, invariant, endpoint, and effect.
3. **Cross-program history:** search the primitive and invariant to estimate how automated/crowded the class is.
4. **Upstream truth:** GHSA/CVE, security advisories, issue/PR history, changelog, release notes, branches, and exact-line history.
5. **Sibling implementations:** language SDKs, old APIs, forks, and mirror repos may show an existing fix or common backend ownership.

For each required novelty source (`own_reports`, `program_disclosures`, `upstream_history`, and `recent_advisories`), store the query, check time, and exactly one result:

- `checked`: a close match was opened; record its identifier, fingerprint, and comparison.
- `no_match`: the source was searched and returned no relevant match.
- `unavailable`: the source could not be searched; record why.

Rank close matches across sources. Store one globally `closest_known_match`, compare its boundary, primitive, invariant, and effect separately, then write one candidate-level semantic delta. Do not treat four source-specific “different” claims as a substitute for selecting the strongest comparison.

### 4.3 Interpret results

- Exact same boundary, primitive, invariant, and effect: probable coverage; `KILL` unless authoritative evidence proves separation.
- Same component but different invariant/effect: document the semantic delta; do not assume either duplicate or novelty.
- No public match: record `private_duplicate_risk`; never call it novel solely from absence.
- Fresh public advisory/famous fix: default risk `high` until a distinct invariant and unaffected fix path are proven.
- Wrong project owns fix: `ROUTE_ELSEWHERE`, even if the product delegates to the vulnerable dependency.
- Known matching root cause: classify `duplicate` and `KILL @ novelty`.
- Incomplete or unavailable comparison evidence: classify `uncertain` and `HOLD @ novelty`.
- Report-stage evidence supports a distinct root cause: classify `distinct`; this still does not reveal private duplicates.

## 5. Threat model and proof requirements

### 5.1 Capability delta

Write four sentences:

1. The attacker starts with `<access/capability>`.
2. The attacker controls `<specific input/state>`.
3. The asset performs `<security-relevant action>`.
4. The attacker gains `<new data/state/execution>`.

If sentence 4 equals sentence 1, there is no demonstrated security gain.

For every proposed attacker route, name the target-supported ingress and the evidence that the actor can reach it. “Compromised storage,” “leaked credential,” “over-permissioned backend,” and “MITM under weak configuration” are scenario assumptions, not source provenance. Determine whether the program treats that component as adversarial, whether a less-trusted principal can influence it through an owned path, and what authority the assumed compromise already grants.

### 5.2 Strongest refutation

Actively test the explanation most likely to kill the report:

- The attacker already controls the endpoint, peer, config, host, or secret.
- The allegedly private object is shared/public by contract.
- Production enables a control absent from templates/tests.
- The service never emits the fabricated event shape.
- A safe authoritative layer rechecks before state changes.
- The dangerous behavior requires downstream misuse or a caller already violating the API contract.
- The project explicitly assigns the boundary to the deployer/caller.
- Target-authored policy, documentation, README text, or prior issue history declares the relevant input, peer, or behavior trusted or by design.

Quote the strongest target-authored statement and resolve its exact scope against the claimed effect. A statement that trusts source-generated SQL on the destination does not automatically settle whether the source may read the migration client's filesystem; conversely, a contract that clearly assigns the entire peer or protocol to the caller is terminal counterevidence. Do not paraphrase a narrow statement into either a broader exemption or a narrower one.

Record one of:

- `refuted`: independent evidence disproves the benign explanation.
- `confirmed`: the explanation defeats or materially downgrades the candidate.
- `unresolved`: more evidence is required; verdict must remain `HOLD`.

### 5.3 Proof quality

Proof must exercise the exact load-bearing behavior and capture an observable effect.

Keep three proof levels separate:

1. **Primitive fidelity:** a compatible parser, client, runtime, or helper containing copied target lines demonstrates that the underlying mechanism can produce the effect. This supports a hypothesis but does not establish the target path.
2. **Executable fidelity:** the exact pinned/shipped executable is invoked through the target's real command/configuration builder and produces the effect. Record the version, generated command or config, observable artifact, negative control, and exit status.
3. **Boundary fidelity:** the actor allowed by the program can supply the exact representation through the product-facing interface, every validation/storage/serialization step preserves the load-bearing bytes or semantics, and the effect crosses a target-owned boundary.

Clear the level required by the claimed destination and impact. Do not use primitive fidelity to claim executable fidelity, or executable fidelity to claim a managed-service boundary. Product documentation showing that customers provide a hostname, username, URI, schema, archive, or similar field is a surface anchor only; it does not prove that control characters, encodings, alternate representations, or other load-bearing values survive the control plane.

For a managed product backed by public source, trace this carrier explicitly:

```text
customer-controlled representation
  → public API/CLI/console contract
  → request validation and normalization
  → persistence or task payload
  → serialization / environment / generated config
  → shipped executable invocation
  → target-owned observable effect
```

If any load-bearing transition is unavailable, use `HOLD @ reachability` or `HOLD @ proof` and name it. Do not fill the gap with an assumption about an internal deployment.

Acceptable proof varies by route:

- Hosted app/API: in `PROGRAM_HOSTED`, two owned identities or an owned instance, planted marker/state change, and anonymous/nonexistent controls when explicitly permitted and relevant.
- Source-code program: executable exact path using shipped configuration, plus evidence that the destination treats that path as its boundary.
- Library/SDK: realistic caller contract and executable regression; upstream fix/advisory/CVE may be the accepted proof rail.
- Parser/CLI: real parser/runtime and a file, process, or state effect—not only acceptance of an option.
- Firmware/hardware: real device/emulator/enforcement behavior accepted by the program.
- AI/MCP: authentic reachable event and consequential tool effect; synthetic service/model output alone proves only unsafe handling of fabricated input.

Every proof needs a negative control that would fail if the claimed root cause were wrong.

Trace each claimed effect independently. A write path, copy path, cleanup path, and delete path may contain the same join or sink while consuming values from different sources. Do not transfer taint, reachability, or capability from one sibling to another without its own source-to-effect trace.

A nonzero process exit does not erase an effect that completed and was independently captured before the failure. Preserve the exit code and ordering evidence, explain the fixture limitation, and scope the claim to the completed effect. Do not call a partial protocol fixture a successful end-to-end product workflow.

## 6. Routing, severity, and report structure

### 6.1 Route ownership

Before reporting, answer:

- Which repository contains the faulty implementation?
- Which maintainer would change it?
- Which release would carry the fix?
- Does the destination list that asset or dependency?
- Does the destination accept the available proof type?

Delegation is not ownership. A wrapper around a vulnerable dependency does not automatically make the wrapper's program the correct route.

### 6.2 Severity

Score the reproduced capability, not the bug class or theoretical maximum.

- Record attacker privileges and non-default requirements honestly.
- Use confidentiality/integrity/availability effects actually captured.
- Treat races, victim action, deployment configuration, and unusual preconditions as complexity/requirements.
- Do not raise severity because a stronger unproven chain might exist.
- Separate impact statements into `demonstrated` and `conditional`. A local canary can demonstrate the executable's file-read capability; it does not by itself demonstrate managed-host reachability, cloud credentials, cross-tenant data, or another target-owned sensitive asset. Conditional consequences may guide the next proof, but they do not determine the submitted severity.
- Separate attacker control over a path from permission to modify that path. Record the runtime UID/GID, container or sandbox boundary, filesystem permissions, capabilities, and the exact execution trigger before claiming arbitrary write, privileged overwrite, or RCE. A constrained privileged subprocess elevates only that subprocess and its accepted arguments; it does not retroactively elevate earlier file operations.

### 6.3 Report structure

Generate a report only after:

```bash
python scripts/validate-candidate.py --stage report candidate.json
```

Use:

```markdown
# [Class] in [component] allows [attacker] to [reproduced impact]

**Asset/version:** <exact scope asset and commit/release>
**Route:** <program/upstream/IBB and why it owns the fix>
**Severity:** <rating, CWE/VRT, vector and short justification>

## Summary
What invariant fails, for which attacker, with what captured effect.

## Security invariant and root cause
Show the complete source-to-enforcement trace with file:line evidence.

## Threat model
Starting access, controlled value, capability before/after, victim action, and owned boundary.

## Reproduction
Minimal setup, exact trigger, observed effect, artifact, and negative controls.

## Novelty and semantic delta
Root-cause fingerprint, searches performed, close matches, and the exact difference.

## Impact
Only the reproduced consequence.

## Limitations
What was not tested, unresolved input-carrier or deployment assumptions, process failures after the captured effect, and residual private-duplicate risk.

## Remediation
Fix the authoritative enforcement point and add the demonstrated regression control.
```

**Report hygiene (self-contained rule).** The report must stand alone: a triager understands the vulnerability, trace, impact, and reproduction without opening any working file. Ban pointer phrases ("see the draft/notes", "for the full trace see …") and internal identifiers (`candidate_id`, gate/stage tags) — inline the content instead. Pin every repository link to the exact commit **SHA**, never a branch like `main`, so it stays stable. Distinguish observed behavior (from a captured evidence artifact) from inferred impact. Embed the smallest snippet that proves the bug. Never write that a PoC executed unless an artifact shows it — otherwise label it theoretical or blocked with the reason.

## 7. Terminal decisions

After setting any verdict, validate the evidence appropriate to where research ended:

```bash
python scripts/validate-candidate.py --stage decision candidate.json
```

- **REPORTABLE @ reportability:** full trace, proof, route, and novelty validation passes with real artifacts.
- **HOLD:** record the current gate and concrete missing evidence; do not invent current or downstream fields.
- **KILL:** record the failed gate and evidence through that gate; do not continue only to fill later fields.
- **ROUTE_ELSEWHERE:** name the correct owner and route evidence.
- **NO_REPORTABLE_FINDING:** preserve the completed safe trace so future agents do not repeat it.

Before changing a verdict, append the prior decision and the evidence that changed it to `decision_history`. Do not transform a non-reportable verdict into REPORTABLE by changing wording. Only new independent evidence may change a gate.
