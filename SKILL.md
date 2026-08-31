---
name: invariant-first-bug-bounty
description: >-
  Performs evidence-gated, authorized security research for bug bounties and coordinated disclosure across source repositories, hosted applications, APIs, mobile apps, firmware, libraries, CLIs, SDKs, and AI/MCP systems. Use for target selection, source review, dynamic validation, routing, deduplication, or report preparation. Not for general code review, feature work, refactoring, or unauthorized testing.
---

# Invariant-First Bug Bounty

## Core principle

A hunt is a **campaign over many hypotheses, validated one at a time**. Map the target, rank candidate invariants, then take one hypothesis through a complete source-to-effect trace and a terminal decision. A candidate verdict closes that hypothesis, never the target.

The objective is ground truth, not a report:

- Persist through difficult traces and build the exact proof the claim requires.
- Kill, hold, or route a candidate when the evidence says so.
- Continue with the ranked queue after every candidate-level terminal verdict.
- Call a target clean only after the high-value boundary inventory and queue are exhausted with evidence.

## Authorization modes

Record one operating mode in the target ledger:

- **`SOURCE_ONLY`**: inspect public source and documentation; build and run code locally; use controlled fixtures, containers, databases, listeners, owned test data, and researcher-owned deployments. Do not send validation traffic to production or third parties, use discovered credentials, or touch data you do not own.
- **`PROGRAM_HOSTED`**: interact only with the exact assets, accounts, methods, data, and rates explicitly permitted by current program rules. Use owned accounts and data.

`SOURCE_ONLY` is an authorization boundary, not a static-analysis mode. Runtime-only classes such as races, replay, state-machine flaws, parser differentials, and consequential agent/tool execution require a running proof.

## 0. Select or rotate the target on live evidence

Create the lightweight target ledger before deep reading:

```bash
cp assets/target.template.json <hunt-dir>/target.json
python scripts/validate_hunt.py --stage target <hunt-dir>/target.json
```

The ledger is the authoritative campaign record. It stores:

- target identity, platform, route, asset type, exact repository/revision when applicable, and operating mode;
- live scope status with a retrieval artifact;
- the exact current proof-policy quote plus accepted proof types;
- truthful contestability evidence (`platform_count`, `public_history`, `private_unavailable`, or `not_applicable`); never turn unavailable private data into zero;
- assessed prior outcomes and the coverage delta from earlier reviews;
- an architecture boundary map and hypothesis lifecycle;
- campaign mode (`first_finding`, `bounded`, or `exhaustive`) and stop condition;
- a gate-aware decision: `SELECTED`, `ROTATED`, or `HOLD`.

A rotation is a terminal target decision. It needs a structured basis and evidence, not “too hard,” remembered policy, or a guessed saturation label. When live evidence is unavailable, use `HOLD` and name what is missing.

Target stages print one of:

```text
TARGET SELECTED
TARGET ROTATED
TARGET HOLD
```

Only a `SELECTED` ledger may produce candidates.

All workflow ordering fields are timezone-bearing ISO-8601 timestamps. Future times fail. Mutable scope and proof-policy evidence must be refreshed when stale; pinned source revisions do not expire. Repeat the live scope and proof-policy preflight within seven days of the submission handoff.

Scale the process to the target. Do not cargo-cult empty process blocks onto a toy target, and do not skip gates on a large one because the trace is tiring.

## 1. Start a candidate from the selected target

Generate the candidate so target identity cannot drift:

```bash
python scripts/start_candidate.py \
  --target-ledger <hunt-dir>/target.json \
  --hypothesis-id H-001 \
  --output <hunt-dir>/candidates/H-001.json
```

The hypothesis must already be `investigating`. The candidate binds its campaign, stable target fingerprint, boundary, and hypothesis without copying the target-wide queue. A later refresh of mutable scope evidence does not invalidate an unchanged candidate; changing the asset, revision, route, or operating mode does.

Validate every later stage through the bound wrapper:

```bash
python scripts/validate_hunt.py \
  --stage model \
  --target-ledger <hunt-dir>/target.json \
  <hunt-dir>/candidates/H-001.json
```

`validate-candidate.py` is import-only and fails on direct execution. Run `validate_hunt.py` for every stage.

## 2. Orient before anchoring

Record:

- principals and roles;
- protected assets;
- trust boundaries;
- state stores;
- authoritative authentication, authorization, canonicalization, uniqueness, and transition checks;
- all meaningful entrypoints: HTTP, RPC, GraphQL, WebSocket, queue/cron, CLI, webhook/callback, file/parser, and agent/tool paths.

Build an invariant space before selecting one invariant. Broad grep output is not a security model.

## 3. Generate and rank hypotheses

For large or unfamiliar targets, load `references/hypothesis-generation.md`. Store a durable queue with lifecycle states:

```text
queued → investigating → closed
                     ↘ parked
```

Rank by expected value:

```text
reachability × owned-boundary confidence × impact × proofability ÷ contestability
```

Creativity is a ranking signal, not an admission gate. A simple, clearly reachable authorization bug outranks a speculative multi-stage chain. Never delete a rejected idea from history; close it with the evidence-backed reason.

Build the intent corpus lazily as you go: quote each documented or intentional security behavior you rely on with its source, and mark whether the finding matches intent. Keep it small — it exists to stop you killing a real bug as “documented behavior” from memory, not to document the target.

Promote one hypothesis at a time into `model.security_invariant`. Open hypotheses do not block a proven candidate from advancing; they block only a campaign-wide clean/exhausted conclusion.

## 4. Trace the invariant completely

Follow:

```text
attacker-controlled representation
→ transport/parser/entrypoint
→ authentication
→ normalization/canonicalization
→ authorization/validation
→ lookup/state read
→ mutation or external effect
→ persistence/uniqueness/cache
→ observable security effect
```

Trace every claim-critical link from source, not from training priors. Check at least one meaningful sibling or alternate version and re-derive attacker control for each sibling independently.

A dead end is a pivot, not an excuse to stop the target. Close the current hypothesis only after the relevant path is complete enough to prove why the capability delta cannot exist.

## 5. State the capability delta

Write four concrete statements:

1. The attacker starts with `<access>`.
2. The attacker controls `<input or state>`.
3. The target performs `<security-relevant action>`.
4. The attacker gains `<new capability>`.

If statement 4 is already granted by statement 1, the candidate dies at `capability_delta`.

For filesystem and process claims, record the runtime principal, permissions, sandbox/container boundary, exact path, and execution trigger. Path control is not permission bypass, and a later privileged helper does not retroactively elevate an earlier operation.

## 6. Attempt the strongest refutation

Test the best benign explanation before proof:

- the input is trusted deployer/operator configuration;
- the caller already owns the endpoint, peer, secret, host, or capability;
- production adds an authoritative re-check;
- the path is unreachable under the supported contract;
- the behavior is explicitly documented by design;
- the defect exists only in a downstream integrator;
- another project owns the security property and fix.

Persist one structured strongest refutation. Terminal refutations cannot be relabeled or waved past to reach a report.

### A load-bearing caveat determines the gate

Before `REPORTABLE`, write:

> The attacker, who already holds X, crosses boundary Y to gain capability Z they could not exercise before.

A caveat is **load-bearing** when it negates the attacker-controlled source, crossed boundary, new capability, target-owned property, accepted proof/deployment route, or security-enforcing nature of the control. That caveat determines `HOLD` or `KILL` until evidence removes it.

Examples:

- “requires control of the victim’s environment” may mean the precondition already grants the effect;
- “does not prove the product-facing input reaches this executable” is a proof gap;
- “does not bypass authentication” may be fatal when the claimed control is only a confirmation prompt, but it is not fatal to an authenticated cross-tenant authorization bug;
- “source-only proof is not accepted” is fatal only when the current policy and route actually require a hosted proof.

Non-load-bearing limitations remain in the report and constrain scope or severity. Do not hide honest limitations merely because a prior draft used a fatal hedge.

Record every hedge the test surfaces in the candidate's `caveats` ledger — one entry per hedge, quoting your own draft wording:

```jsonc
"caveats": [
  {
    "quote": "does not prove the product-facing input reaches this executable",
    "classification": "load_bearing",
    "justification": "why this hedge is or is not fatal to the claimed boundary"
  }
]
```

Classification stays a judgment, but it must be explicit and auditable. **A load-bearing hedge controls the gate; an ordinary limitation controls scope or severity.** Remove a load-bearing hedge with evidence, narrow to the claim that survived, or decide `HOLD`/`KILL`. An empty ledger claims the draft contains no hedges; re-run the test before asserting it.

### Recover or narrow before killing a viable finding

Record the highest proven rung in `claim_scope`:

```text
primitive → exact_executable → owned_boundary → demonstrated_impact → severity
```

Use `recovery.classification` to force the next honest action:

- `RECOVER`: a safe, available check can repair the missing rung; name the next action and required artifact;
- `NARROW`: a lower security-relevant claim is proven; record the unsupported extension and advance only the surviving claim;
- `OPERATOR_REQUIRED`: the required evidence needs an account, platform, device, or environment not currently available;
- `NONE`: no unresolved claim-recovery work remains.

`RECOVER` and `OPERATOR_REQUIRED` cannot be `REPORTABLE`. `NARROW` may be reportable at `exact_executable` or higher when the demonstrated effect is itself in scope, security-relevant, reproducible, and novel. Do not keep a finished narrow finding in indefinite `HOLD` merely because a stronger deployment story remains unproven.

Read `references/worked-examples.md` for calibrated synthetic examples, including cases where a load-bearing hedge defeats the claimed boundary.

## 7. Shape the proof with a self-run adversarial pass

Before proof, run the Advocate, Cold verifier, and Causal challenger from `references/adversarial-self-review.md` yourself. This is preparation only. It identifies what evidence a skeptic would demand and can lower confidence or kill the candidate.

Do not set final reviewer identity during this pass.

## 8. Prove the exact boundary

Keep three levels distinct:

1. **Primitive fidelity**: the underlying mechanism can produce the effect.
2. **Executable fidelity**: the exact pinned/shipped method or binary, real invocation, and shipped configuration produce it.
3. **Boundary fidelity**: an actor permitted by the program can supply the exploit-critical representation through the product-facing path and cross a target-owned boundary.

Use the level required by the destination and claimed impact. Capture:

- exact version/revision;
- setup and command/configuration;
- observable effect artifact;
- exit status and ordering when relevant;
- at least one negative control;
- production or destination relevance.

`static-source-trace` is supporting evidence, not final proof. Store it in `proof.supporting_evidence_types`; the final proof type must establish the exact executable or authorized hosted path.

Treat configuration as a claim precondition, not an automatic rejection. A target-shipped default or supported option may remain reportable when the target owns that condition, evidence records it, and the condition does not already grant the claimed effect. Operator-weakened and test-only configurations do not establish the supported product boundary.

For a clean candidate, add a researcher-designed adversarial probe to `exhaustion.probes` with:

```text
hypothesis
command
would_fire_if_vulnerable
observed
result
```

Running only the target’s existing positive tests is not an adversarial probe.

## 9. Verify route ownership

Confirm which project owns the faulty implementation, would ship the fix, and accepts the available proof type. A wrapper or product that bundles an unmodified vulnerable dependency does not automatically own the bug.

Use `ROUTE_ELSEWHERE` when another disclosure rail owns the fix.

## 10. Measure novelty and contestability

Fingerprint the root cause:

```text
boundary | primitive | invariant | effect
```

Search:

1. your own outcomes;
2. program disclosures;
3. upstream commits, open/closed issues, and pull requests;
4. current default-branch state;
5. recent advisories and close semantic matches.

A clean public search does not prove novelty. On GitHub, issue and PR searches plus a current-branch fetch are mandatory for `distinct`; `git log` alone is insufficient.

In high-duplicate contexts, record a concrete collision differentiator. Do not submit merely because the defect is valid.

## 11. Harden, decide, then review the exact candidate bytes

For a reportable candidate, harden the final claim and record `hardening.completed_at`:

- **widen**: affected assets, versions, siblings, and transports;
- **reassess severity**: raise, hold, or lower it based on demonstrated evidence;
- **deepen proof**: remove remaining ambiguity and improve controls.

Write the candidate decision after hardening. Then give a fresh-context reviewer only the repository and finished candidate file, not the author’s prosecution narrative. Store the result separately as `candidate-review.json`:

```json
{
  "schema_version": 1,
  "review_type": "candidate",
  "reviewer": {
    "mode": "independent_agent",
    "id": "review-session-id",
    "reviewed_at": "2026-08-20T04:10:00Z",
    "fresh_context": true
  },
  "verdict": "REPORTABLE|KILL|ROUTE_ELSEWHERE|NO_REPORTABLE_FINDING|NOT_READY|REJECTED",
  "candidate": {"path": "candidate.json", "sha256": "..."}
}
```

`human` is also valid. Ordering is `hardening.completed_at <= decision.decided_at <= review.reviewed_at`. Editing the candidate invalidates the review digest. The digest identifies the exact bytes reviewed; it does not prove the reviewer’s independence or the truth of the finding.

Without the sidecar, decision stage remains provisional. Report stage requires an affirmative review bound to the exact candidate.

### Final candidate-closure review

A final candidate-level `NO_REPORTABLE_FINDING` additionally requires `closure_review`:

- `verdict: DEPTH_SUFFICIENT`;
- at least one verdict-critical closure challenged with evidence;
- a sufficient adversarial probe, or a narrowly evidenced waiver;
- explicit `coverage_gaps` and `remaining_high_value_hypotheses` arrays.

Those last two arrays are continuation inputs, not permission to erase unfinished work. A candidate may close while the campaign still has H-002, H-003, or an uncovered boundary; preserve them and continue at step 12. An `UNCERTAIN` reviewer result about the current closure is `HOLD`, not `NO_REPORTABLE_FINDING`. One candidate-level closure never certifies that the target is clean.

## 12. Decide, validate, and continue

After writing a terminal candidate decision, close its target hypothesis with the matching candidate ID, verdict, evidence path, timestamp, and SHA-256. Then validate the decision:

```bash
python scripts/validate_hunt.py \
  --stage decision \
  --target-ledger <hunt-dir>/target.json \
  <hunt-dir>/candidates/H-001.json
```

Technical candidate readiness:

```bash
python scripts/validate_hunt.py \
  --stage report \
  --target-ledger <hunt-dir>/target.json \
  --candidate-review <hunt-dir>/reviews/H-001-candidate-review.json \
  <hunt-dir>/candidates/H-001.json
```

Success prints `CANDIDATE REPORTABLE`. This means the technical candidate passed; it does not certify a report written later.

Prepare the exact report bundle:

```bash
python scripts/start_submission.py \
  --candidate <hunt-dir>/candidates/H-001.json \
  --candidate-review <hunt-dir>/reviews/H-001-candidate-review.json \
  --report <hunt-dir>/report.md \
  --output <hunt-dir>/submission/submission.json \
  --submission-id S-001 \
  --title "..." --weakness "..." --severity high \
  --cvss-score 8.1 --cvss-vector "..." \
  --command "python3 reproduce.py" \
  --attachment <hunt-dir>/proof.txt=proof-transcript
```

The bundle copies the affirmed candidate review, candidate, Markdown report, and attachments and records exact SHA-256 digests. Complete its live scope/proof-policy preflight and `prepared_at`, then copy `assets/submission-review.template.json` into the bundle and obtain a second fresh review over `submission.json`, `report.md`, the candidate, and every attachment. Validate the handoff:

```bash
python scripts/validate_hunt.py \
  --stage submission \
  --target-ledger <hunt-dir>/target.json \
  --candidate <hunt-dir>/submission/candidate.json \
  --candidate-review <hunt-dir>/submission/candidate-review.json \
  --submission-review <hunt-dir>/submission/submission-review.json \
  <hunt-dir>/submission/submission.json
```

Only an affirmative, digest-matched final review prints `SUBMISSION READY FOR FINAL CHECK`. Re-check the live platform form and attachments before the user submits. This status is not `SUBMITTED` and never authorizes an external click.

After every terminal candidate verdict:

1. update the queue entry in place;
2. preserve the candidate artifact and decision history;
3. promote the next highest-value queued hypothesis;
4. continue until the target’s high-value boundaries are covered or the request explicitly limits the campaign to first-finding mode.

## Candidate verdicts

| Verdict | Meaning |
|---|---|
| `REPORTABLE` | The bounded technical candidate cleared trace, proof, route, novelty, hardening, and exact-file candidate review |
| `HOLD` | A named artifact or gate remains unresolved |
| `KILL` | A gate is disproven, capability is unchanged, behavior is intended, or the candidate is covered/fixed |
| `ROUTE_ELSEWHERE` | Another project or disclosure rail owns the fix |
| `NO_REPORTABLE_FINDING` | This investigated invariant held after a complete trace, adversarial probe/waiver, and final closure review |

None of these verdicts alone means the target is clean.

`HOLD` is scoped to its layer: a *target* HOLD governs selection (step 0, `TARGET HOLD`); a *candidate* HOLD governs this hypothesis's decision; a *closure* HOLD means the clean exit is unproven. None of them licenses stopping the campaign.

## Depth contract

Do not rotate because a trace is difficult or slow. Rotate when evidence shows the primitive is absent, the path is complete and safe, the route is dead, or a documented higher-EV hypothesis dominates.

Before closing an invariant as clean, preserve:

- entrypoint and attacker-controlled value;
- invariant and authoritative enforcement point;
- complete source-to-effect trace;
- sibling or alternate version checked;
- strongest counterexample and why it failed;
- adversarial probe or evidenced waiver.

## Red flags

Stop and return to the named gate when you notice:

- drafting before report-stage validation;
- claiming impact not reproduced;
- substituting copied code or a compatible client for the exact path;
- changing a JSON conclusion instead of collecting evidence;
- relabeling a terminal refutation;
- rotating a target from memory or paraphrased policy;
- treating a load-bearing caveat as a harmless footnote;
- calling a target clean while queued high-value hypotheses remain.

Keep going when you notice:

- stopping because the work is unfamiliar or fiddly;
- treating `HOLD` as an exit rather than the next evidence task;
- concluding a runtime-only class from static reading;
- trusting the target’s own tests as the only clean proof;
- closing one candidate and forgetting the rest of the queue.

## Rationalizations

| Thought | Reality |
|---|---|
| “The ledger and paperwork take too long.” | The ledger is shorter than one wrong target. Select or rotate on evidence, then move. |
| “It’s just a caveat footnote.” | A load-bearing hedge controls the gate; an ordinary limitation controls scope or severity. |
| “I generated many hypotheses, so coverage is good.” | Volume is not depth. The queue matters only when entries reach terminal evidence. |
| “This KILL was hard-won; I did enough.” | Concluding costs the same evidence as reporting. The documented exhaustion is the verdict, not the feeling. |
| “The validator passed, so the report is strong.” | Validators check structure and recorded evidence, not truth. Gates are floors, not certification. |
| “One more hour of reading instead of building the PoC.” | Static certainty never crosses a runtime boundary. Build the probe. |

## References and tools

| Resource | Use when |
|---|---|
| `references/methodology-and-targeting.md` | Targeting, proof standards, routing, severity, and report structure |
| `references/hypothesis-generation.md` | Architecture-specific hypothesis generation and ranking |
| `references/adversarial-self-review.md` | Preparation and final independent-review procedure |
| `references/worked-examples.md` | Gate-calibrated examples, including load-bearing versus ordinary caveats |
| `references/bug-class-taxonomy.md` | Relevant class-specific source/sink and confirmation patterns |
| `references/grey-box-dynamic-testing.md` | Authorized live/owned-account testing |
| `references/emerging-surfaces-and-techniques.md` | AI/MCP, CI/CD, supply-chain, cloud, auth, parser, variant, and history surfaces |
| `references/platform-operations.md` | Scope, safe harbor, proof policy, KYC, payout, and platform operations |
| `assets/target.template.json` | Gate-aware target selection/rotation ledger |
| `assets/candidate.template.json` | One invariant’s durable evidence and decision state |
| `assets/submission.template.json` | Exact report-and-attachment handoff manifest |
| `assets/candidate-review.template.json` | Digest-bound candidate review sidecar |
| `assets/submission-review.template.json` | Exact final bundle review sidecar |
| `scripts/validate_hunt.py` | Authoritative target-bound validator |
| `scripts/start_candidate.py` | Generate a candidate from a selected target ledger |
| `scripts/start_submission.py` | Create a self-contained report bundle from a reportable candidate |
| `scripts/validate-candidate.py` | Import-only candidate core used by `validate_hunt.py` |
| `scripts/recon-sweep.sh` | Secondary model-gated sink and variant triage |

Stay within current scope and safe harbor. Use owned accounts and data, minimize impact, and never use exposed credentials or pivot into third-party systems.
