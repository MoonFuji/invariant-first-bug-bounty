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

- **Hosted/grey-box:** read source to locate the invariant, then prove it with owned accounts/data or an owned deployment.
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

### 4.3 Interpret results

- Exact same boundary, primitive, invariant, and effect: probable coverage; `KILL` unless authoritative evidence proves separation.
- Same component but different invariant/effect: document the semantic delta; do not assume either duplicate or novelty.
- No public match: record `private_duplicate_risk`; never call it novel solely from absence.
- Fresh public advisory/famous fix: default risk `high` until a distinct invariant and unaffected fix path are proven.
- Wrong project owns fix: `ROUTE_ELSEWHERE`, even if the product delegates to the vulnerable dependency.

## 5. Threat model and proof requirements

### 5.1 Capability delta

Write four sentences:

1. The attacker starts with `<access/capability>`.
2. The attacker controls `<specific input/state>`.
3. The asset performs `<security-relevant action>`.
4. The attacker gains `<new data/state/execution>`.

If sentence 4 equals sentence 1, there is no demonstrated security gain.

### 5.2 Strongest refutation

Actively test the explanation most likely to kill the report:

- The attacker already controls the endpoint, peer, config, host, or secret.
- The allegedly private object is shared/public by contract.
- Production enables a control absent from templates/tests.
- The service never emits the fabricated event shape.
- A safe authoritative layer rechecks before state changes.
- The dangerous behavior requires downstream misuse or a caller already violating the API contract.
- The project explicitly assigns the boundary to the deployer/caller.

Record one of:

- `refuted`: independent evidence disproves the benign explanation.
- `confirmed`: the explanation defeats or materially downgrades the candidate.
- `unresolved`: more evidence is required; verdict must remain `HOLD`.

### 5.3 Proof quality

Proof must exercise the exact load-bearing behavior and capture an observable effect.

Acceptable proof varies by route:

- Hosted app/API: two owned identities or owned instance, planted marker/state change, anonymous and nonexistent controls when relevant.
- Source-code program: executable exact path using shipped configuration, plus evidence that the destination treats that path as its boundary.
- Library/SDK: realistic caller contract and executable regression; upstream fix/advisory/CVE may be the accepted proof rail.
- Parser/CLI: real parser/runtime and a file, process, or state effect—not only acceptance of an option.
- Firmware/hardware: real device/emulator/enforcement behavior accepted by the program.
- AI/MCP: authentic reachable event and consequential tool effect; synthetic service/model output alone proves only unsafe handling of fabricated input.

Every proof needs a negative control that would fail if the claimed root cause were wrong.

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
What was not tested, deployment assumptions, and residual private-duplicate risk.

## Remediation
Fix the authoritative enforcement point and add the demonstrated regression control.
```

## 7. Terminal decisions

After setting any verdict, require a complete trace:

```bash
python scripts/validate-candidate.py --stage decision candidate.json
```

- **REPORTABLE:** report validation passes with real artifacts.
- **HOLD:** list concrete missing evidence; do not draft a report.
- **KILL:** name the disproven gate or authoritative coverage.
- **ROUTE_ELSEWHERE:** name the correct owner and route evidence.
- **NO_REPORTABLE_FINDING:** preserve the completed safe trace so future agents do not repeat it.

Before changing a verdict, append the prior decision and the evidence that changed it to `decision_history`. Do not transform a non-reportable verdict into REPORTABLE by changing wording. Only new independent evidence may change a gate.
