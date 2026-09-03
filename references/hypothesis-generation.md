# Hypothesis generation

Use this reference when a target is large or unfamiliar and the most valuable
invariant is not obvious.

Hypothesis generation widens what you consider. It never lowers evidence gates.

In default mode, keep ideas in working notes and select one invariant.

In broad autonomous work, store the durable queue in optional `campaign.json`.
The target and candidate schemas do not require a queue.

## Hypothesis record

Keep each entry terse:

- id;
- boundary;
- falsifiable statement;
- priority;
- status: `queued`, `investigating`, `closed`, or `parked`;
- candidate id/verdict/reason once closed.

Useful private working-note fields may include suspected entrypoint, sink,
preconditions, attack class, and why a shallow grep would miss it. They do not
need to become schema fields.

Rank by expected value:

```text
reachability × owned-boundary confidence × impact × proofability ÷ duplicate pressure
```

Creativity is a ranking signal, not an admission gate. A simple reachable
authorization bug outranks a speculative chain.

## High-value mismatch archetype

Look for one security-relevant value represented differently across layers,
especially at identity, uniqueness, authorization, replay, or cache boundaries.

Examples:

- normalized for validation but raw for storage;
- canonical ID in one sibling and alias/raw ID in another;
- signed representation differs from consumed representation;
- policy checks a URL parser that disagrees with the actual client.

A sibling path already using the safer representation is useful intent evidence.

## Eight attack modes

### 1. Chaining

Combine individually limited primitives across a target-owned boundary. Every
link still needs evidence; extra links are extra assumptions.

### 2. Business logic

Look for sequences of legitimate operations that reach forbidden state:
negative/refund behavior, role/self-invite transitions, quota/accounting gaps,
undo/rollback restoring revoked privilege.

### 3. Race / TOCTOU

Find check-then-act or read-then-write sequences whose authoritative constraint
does not close the window.

### 4. Second-order / stored

Input is accepted safely in one context and later consumed in a more dangerous
one: stored SSRF/XSS/SSTI, filename-to-shell, delayed parser interpretation.

### 5. Trust-boundary confusion

One component trusts identity/assertions from another without re-verification,
or an internal/trusted mode becomes reachable from a less-trusted principal.

### 6. Parser / protocol differential

Two components interpret the same bytes differently: duplicate keys, URL
authority/backslashes, path normalization, SAML namespaces, request framing,
content-type mismatches.

### 7. State machine

Replay, reorder, skip, race, or reverse transitions: one-time token reuse,
cancelled→pending, OAuth step replay, async invalidation windows.

### 8. Supply-chain interaction

A dependency gadget matters only when the reviewed product reaches it through a
supported caller contract. Trace the product-facing ingress and ownership.

## Pre-mortem

Assume the exact system is already breached. Write concrete target-specific
outcomes, then reason backward:

```text
forbidden capability
→ required state
→ operation producing that state
→ attacker-controlled input/action
→ supported entrypoint
```

If the chain ends at a precondition the attacker does not hold, it is not a
finding. Do not fill the gap with "assume compromised backend" or "assume leaked
credential".

## Defensive code as a symptom

For each guard, clamp, retry, fallback, assertion, sanitizer, or recovery path,
ask:

- what danger motivated it?
- do alternate/fallback paths enforce the same property?
- does downstream code assume the happy-path guard ran?
- which representation variants might bypass the intended defense?

Defensive code is a lead, not proof.

## Contradiction / tension scan

Security gaps often appear where engineering resolves tension:

- compatibility → legacy/lenient path;
- performance → skipped checks/caching;
- convenience → insecure default/auto-config;
- completeness → edge path handled elsewhere;
- async behavior → validation and action see different state.

## Adaptive attacker framing

Ask what repeated interaction reveals:

- response/timing oracle;
- rate-limit/counter behavior;
- incremental state accumulation;
- cross-user side effects;
- retry/idempotency asymmetry.

If a sequence of individually allowed actions reaches forbidden state, model
that sequence as one invariant about the final state.

## Campaign discipline

When campaign mode is active:

```text
queued → investigating → closed
                     ↘ parked
```

Promote one hypothesis at a time. After a terminal verdict, close it with the
candidate id, verdict, and short reason, then continue according to the campaign
stop condition.

Do not call hypothesis volume "coverage". An exhaustive campaign is only as good
as its boundary inventory and the depth of the traces actually closed.

See `references/campaign-mode.md`.
