---
name: invariant-first-bug-bounty
description: >-
  Performs evidence-gated, authorized vulnerability research for bug bounties
  and coordinated disclosure. Use for source review, dynamic validation,
  deduplication, routing, or report preparation. Not for general code review,
  feature work, refactoring, or unauthorized testing.
---

# Invariant-First Bug Bounty

## Core principle

Investigate **one security invariant completely** before accepting or rejecting it.

Do not confuse one rejected candidate with a clean target. Continue to additional
hypotheses when the user's requested scope requires broad coverage. Use the
optional campaign ledger only for multi-hypothesis work such as "audit this
repository", "find multiple bugs", "keep going", or "exhaust this target".

The objective is ground truth:

- prove an attacker-controlled source reaches a target-owned security effect;
- state the capability gained, not just the suspicious primitive;
- try the strongest benign explanation before promotion;
- reproduce the exact executable or authorized hosted path;
- verify who owns the fix and where the report belongs;
- search seriously for duplicates and current fixes;
- narrow a real finding instead of killing it because a stronger extension failed;
- give the **final report bundle** one fresh review before submission.

## Authorization modes

Record one operating mode in `target.json`:

- `SOURCE_ONLY`: inspect public source/docs; build and run code locally; use
  controlled fixtures, containers, databases, listeners, owned test data, and
  researcher-owned deployments. Do not send validation traffic to production or
  third parties, use discovered credentials, or touch data you do not own.
- `PROGRAM_HOSTED`: interact only with assets, accounts, methods, data, and rates
  explicitly permitted by current program rules. Use owned accounts and data.

`SOURCE_ONLY` is an authorization boundary, not a static-analysis mode. Runtime
claims still require a running proof.

## Default workflow

```text
current scope + accepted proof route
              |
          target.json
              |
       one invariant
              |
 source-to-effect trace
              |
 capability delta + strongest refutation
              |
 exact proof + owner + novelty
              |
 bounded claim / narrow / recover
              |
   CANDIDATE READY TO DRAFT
              |
 report.md + candidate + attachments
              |
 fresh scope/proof preflight
              |
 one exact final review
              |
 SUBMISSION READY FOR FINAL CHECK
```

### 1. Confirm the target

Start from:

```bash
cp assets/target.template.json <hunt>/target.json
python scripts/validate_hunt.py --stage target <hunt>/target.json
```

`target.json` is deliberately small. It owns only:

- stable target identity and operating mode;
- current scope eligibility and severity ceiling;
- current accepted proof routes;
- `SELECTED`, `HOLD`, or `ROTATED`.

Do not put architecture maps, prior outcomes, hypothesis queues, duplicate
statistics, or campaign bookkeeping into the default target gate.

A target may be selected only from current evidence. `HOLD` names missing
evidence. `ROTATED` requires an evidence-backed reason such as exact scope
ineligibility or no compatible proof route; difficulty alone is not a reason.

### 2. Choose one invariant and bind a candidate

Default mode needs no campaign:

```bash
python scripts/start_candidate.py \
  --target-ledger <hunt>/target.json \
  --candidate-id C-001 \
  --output <hunt>/C-001.json
```

Fill one concrete invariant. For example:

> A tenant-scoped caller must not read another tenant's report.

For broad autonomous work, use optional campaign mode as described below.

### 3. Trace the invariant and state the capability delta

Trace the claim-critical path:

```text
attacker-controlled representation
→ parser/transport/entrypoint
→ authentication
→ normalization
→ authorization/validation
→ lookup/state transition
→ persistence/external effect
→ observable security effect
```

Record:

- attacker starting access;
- exact input/state controlled;
- target-owned boundary crossed;
- capability before;
- capability after;
- one meaningful sibling or alternate path.

If `capability_after` is already included in `capability_before`, the candidate
does not become reportable.

For filesystem/process claims, include runtime principal, permissions,
sandbox/container boundary, exact path, and execution trigger. Path control is
not permission bypass.

### 4. Attempt the strongest refutation

Before promotion, test the best benign explanation:

- caller already owns the capability;
- input is trusted operator/deployer configuration;
- production adds an authoritative re-check;
- path is unreachable under the supported contract;
- behavior is explicitly documented by design;
- another project owns the security property;
- the precondition itself already grants the claimed effect.

Store one `strongest_refutation`. A terminal refutation cannot be waved away or
relabelled as defeated. Only a genuinely non-terminal objection can be
`refuted` by evidence.

### 5. Prove the exact boundary

Keep proof levels distinct:

- `primitive`: mechanism can produce the effect;
- `executable`: exact pinned/shipped method or binary produces it;
- `boundary`: an allowed actor supplies the exploit-critical input through the
  product-facing path and crosses the target-owned boundary.

`REPORTABLE` requires at least `executable`.

Capture:

- exact version/revision;
- command/setup;
- observable result;
- a negative control;
- production/destination relevance.

Static source trace is supporting evidence, not final proof.

Configuration is a claim precondition. A shipped default or supported option may
remain reportable when evidence shows the target owns that condition and the
condition does not itself grant the effect. Operator-weakened, test-only, and
unknown configuration dependencies do not clear `REPORTABLE`.

### 6. Verify owner, novelty, and the bounded claim

Verify which project ships the vulnerable implementation and would ship the fix.
Use `ROUTE_ELSEWHERE` when another project/disclosure rail owns it.

Fingerprint novelty around:

```text
boundary | primitive | invariant | effect
```

For repository-backed targets, a `distinct` claim requires searches across:

- your own prior reports/outcomes;
- program disclosures;
- upstream commits;
- upstream issues;
- upstream pull requests;
- recent advisories;
- current default-branch state.

`git log` alone is not a duplicate check. An unavailable source must be recorded
as unavailable with attempted-search evidence, not silently treated as empty.

Then bound the claim:

- exact new capability;
- demonstrated impact;
- severity ceiling;
- honest limitations.

Use `recovery.status`:

- `ready`: no unresolved claim-recovery work;
- `recover`: a safe available check can repair the missing evidence;
- `narrow`: a lower security-relevant claim survives; record dropped extensions;
- `operator_required`: the next required artifact needs an account/device/
  environment that is not currently available.

`recover` and `operator_required` cannot be `REPORTABLE`. `narrow` can.

For a reportable candidate, perform a small hardening pass: re-check scope,
reassess severity, and strengthen the proof. Then run:

```bash
python scripts/validate_hunt.py \
  --stage report \
  --target-ledger <hunt>/target.json \
  <hunt>/C-001.json
```

Success prints:

```text
CANDIDATE READY TO DRAFT
```

That means the technical candidate is ready to become a report. It is **not**
independent certification and it does not authorize submission.

### 7. Draft once, then review the final bytes once

Prepare the bundle after the report is finished:

```bash
python scripts/start_submission.py \
  --candidate <hunt>/C-001.json \
  --report <hunt>/report.md \
  --output <hunt>/submission/submission.json \
  --submission-id S-001 \
  --attachment <hunt>/proof.txt=proof-transcript
```

`submission.json` is intentionally a file manifest, not a second copy of the
report. It does **not** duplicate title, weakness, CVSS, severity, impact, or
reproduction fields.

The Markdown report is the semantic submission artifact. It must contain the
candidate's bounded invariant, capability, impact, proof command, limitations,
and unsupported extensions.

Before final review, refresh the live preflight in `submission.json`:

- exact asset is still eligible;
- current `max_severity`;
- current accepted proof types;
- fresh evidence and timezone-bearing timestamps.

The final preflight must be no older than seven days. It owns the current
severity ceiling and proof-policy truth; a months-old target record cannot
override it.

Copy `assets/final-review.template.json` to the bundle and give a fresh-context
reviewer the exact final bundle. The reviewer checks the actual report, candidate,
manifest, and attachments. SHA-256 binds reviewed bytes; it does not prove the
evidence is true or the reviewer is independent.

Validate:

```bash
python scripts/validate_hunt.py \
  --stage submission \
  --target-ledger <hunt>/target.json \
  --candidate <hunt>/submission/candidate.json \
  --final-review <hunt>/submission/final-review.json \
  <hunt>/submission/submission.json
```

Only an affirmative exact-file review prints:

```text
SUBMISSION READY FOR FINAL CHECK
```

The tooling never performs an external submission.

## Optional campaign mode

Use campaign state only when the requested task needs durable multi-hypothesis
coverage.

Start from:

```bash
cp assets/campaign.template.json <hunt>/campaign.json
python scripts/validate_hunt.py \
  --stage campaign \
  --target-ledger <hunt>/target.json \
  <hunt>/campaign.json
```

A campaign stores only:

- `mode`: `first_finding`, `bounded`, or `exhaustive`;
- stop condition;
- hypotheses with `id`, boundary, statement, priority, status, candidate id,
  terminal verdict, and reason.

Lifecycle:

```text
queued → investigating → closed
                     ↘ parked
```

No candidate hashes, transition timestamps, architecture inventories, prior
outcome ledgers, or coverage-delta forms are required.

Create a campaign-bound candidate only from an open campaign and an
`investigating` hypothesis:

```bash
python scripts/start_candidate.py \
  --target-ledger <hunt>/target.json \
  --campaign-ledger <hunt>/campaign.json \
  --hypothesis-id H-001 \
  --candidate-id C-001 \
  --output <hunt>/C-001.json
```

A closed campaign cannot start new candidate work. Closing one candidate never
means the target is clean. `exhaustive` campaign closure requires every tracked
hypothesis closed; `first_finding` closure requires a reportable finding.

See `references/campaign-mode.md` for ranking and broad-coverage guidance.

## Verdicts

| Verdict | Meaning |
|---|---|
| `REPORTABLE` | Exact bounded candidate cleared trace, refutation, proof, owner, novelty, claim and hardening gates |
| `HOLD` | Named evidence is still missing |
| `KILL` | A gate is disproven or the capability does not exist |
| `ROUTE_ELSEWHERE` | Another project or disclosure rail owns the fix |

There is intentionally no candidate-level `NO_REPORTABLE_FINDING` verdict. A
dead invariant is not a clean target. Clean/exhausted conclusions belong to
campaign scope.

## Red flags

Return to the relevant gate if you notice:

- drafting from a suspicious sink before proving a capability delta;
- claiming impact not reproduced;
- replacing the exact path with copied code or a compatible client;
- changing JSON to satisfy a validator instead of collecting evidence;
- relabelling a terminal refutation;
- treating an unavailable duplicate source as zero results;
- hiding a limitation because it weakens severity;
- stopping a broad audit after one dead hypothesis.

Validators check structure and recorded evidence. They are floors, not proof of
truth.

## References and tools

- `references/methodology-and-targeting.md` — targeting, routing, severity, report structure
- `references/hypothesis-generation.md` — architecture-specific ideation and ranking
- `references/adversarial-self-review.md` — self-skepticism and final fresh review
- `references/campaign-mode.md` — optional long-running multi-hypothesis workflow
- `references/worked-examples.md` — calibrated examples
- `references/bug-class-taxonomy.md` — class-specific source/sink patterns
- `references/grey-box-dynamic-testing.md` — authorized owned-account testing
- `references/emerging-surfaces-and-techniques.md` — AI/MCP, supply-chain, auth, parser, cloud surfaces
- `references/platform-operations.md` — scope, safe harbor, proof policy, payout/platform operations
- `scripts/validate_hunt.py` — only validator CLI
- `scripts/start_candidate.py` — create a target-bound candidate
- `scripts/start_submission.py` — create the final exact-file bundle

Stay within current scope and safe harbor. Use owned accounts and data, minimize
impact, and never use exposed credentials or pivot into third-party systems.
