# Invariant-First Bug Bounty

A portable Agent Skill for evidence-gated, authorized vulnerability research.

The default workflow is intentionally small: verify the target, investigate one
security invariant completely, prove the exact boundary, check ownership and
novelty, bound the claim, then review the **final** report bundle once.

Campaign bookkeeping is optional and activates only for broad multi-hypothesis
work.

## What it prevents

AI-assisted hunts commonly fail by:

- stopping at a suspicious source/sink without proving attacker capability;
- reporting a primitive whose precondition already grants the effect;
- treating an unresolved or terminal refutation as defeated;
- killing a real narrow finding because a stronger extension failed;
- using `git log` as a substitute for issue/PR duplicate search;
- relying on stale scope or proof-policy memory;
- calling one dead hypothesis a clean target;
- reviewing an early draft and later submitting different bytes.

## Default flow

```text
target.json
   ↓
one invariant
   ↓
trace → capability delta → strongest refutation
   ↓
exact proof → owner → novelty → bounded claim
   ↓
CANDIDATE READY TO DRAFT
   ↓
report.md + candidate + attachments
   ↓
fresh scope/proof preflight
   ↓
one exact final review
   ↓
SUBMISSION READY FOR FINAL CHECK
```

### 1. Target

```bash
cp assets/target.template.json /path/to/hunt/target.json
python scripts/validate_hunt.py --stage target /path/to/hunt/target.json
```

`target.json` owns only stable identity, authorization mode, current scope,
current accepted proof routes, and `SELECTED`/`HOLD`/`ROTATED`.

### 2. Candidate

```bash
python scripts/start_candidate.py \
  --target-ledger /path/to/hunt/target.json \
  --candidate-id C-001 \
  --output /path/to/hunt/C-001.json
```

Fill the invariant, attacker model, trace, strongest refutation, proof, route,
novelty, bounded claim, recovery state, hardening pass, and decision.

```bash
python scripts/validate_hunt.py \
  --stage report \
  --target-ledger /path/to/hunt/target.json \
  /path/to/hunt/C-001.json
```

Success prints `CANDIDATE READY TO DRAFT`.

### 3. Final bundle and one final review

```bash
python scripts/start_submission.py \
  --candidate /path/to/hunt/C-001.json \
  --report /path/to/hunt/report.md \
  --output /path/to/hunt/submission/submission.json \
  --submission-id S-001
```

The manifest records only exact file references and a fresh live preflight. It
does not duplicate report semantics such as title, CVSS, severity, or impact.

Copy `assets/final-review.template.json` into the bundle, obtain one fresh review
over the exact candidate/report/manifest/attachments, then run:

```bash
python scripts/validate_hunt.py \
  --stage submission \
  --target-ledger /path/to/hunt/target.json \
  --candidate /path/to/hunt/submission/candidate.json \
  --final-review /path/to/hunt/submission/final-review.json \
  /path/to/hunt/submission/submission.json
```

Only an affirmative digest-matched review prints
`SUBMISSION READY FOR FINAL CHECK`. The tooling never submits externally.

## Optional campaign mode

Use `campaign.json` only for requests such as "audit the whole repo", "find
multiple bugs", "keep going", or "exhaust this target".

```bash
cp assets/campaign.template.json /path/to/hunt/campaign.json

python scripts/validate_hunt.py \
  --stage campaign \
  --target-ledger /path/to/hunt/target.json \
  /path/to/hunt/campaign.json
```

Campaign mode keeps a small hypothesis queue with
`queued → investigating → closed/parked`. It deliberately does not duplicate
architecture inventories, prior-outcome ledgers, candidate hashes, or transition
timestamps.

A campaign-bound candidate is created with:

```bash
python scripts/start_candidate.py \
  --target-ledger /path/to/hunt/target.json \
  --campaign-ledger /path/to/hunt/campaign.json \
  --hypothesis-id H-001 \
  --candidate-id C-001 \
  --output /path/to/hunt/C-001.json
```

Closed campaigns cannot start new candidate work.

## Core gates kept strict

- current scope and authorization;
- concrete security invariant;
- attacker-controlled source and full source-to-effect trace;
- capability before vs. capability after;
- strongest refutation;
- executable/authorized proof with a negative control;
- fix ownership and route;
- serious novelty search, including upstream issues/PRs for repositories;
- bounded claim and honest limitations;
- `narrow` instead of killing a valid smaller finding;
- one fresh final review over the exact submission bytes;
- no target-wide clean conclusion from a single dead invariant.

## Files

```text
SKILL.md
assets/
  target.template.json
  campaign.template.json
  candidate.template.json
  submission.template.json
  final-review.template.json
references/
  campaign-mode.md
  ...
scripts/
  validate_hunt.py
  start_candidate.py
  start_submission.py
  hunt_validation/
    common.py
    target.py
    candidate.py
    submission.py
```

`scripts/validate_hunt.py` is the only validator CLI.

## Validation

```bash
python -m compileall -q scripts
python scripts/test_validate_candidate.py
python scripts/test_validate_campaign.py
python scripts/test_validate_hunt.py
python scripts/test_validate_submission.py
python scripts/test_validate_hunt_cli.py
```

GitHub Actions runs the same checks.

## Trust boundary

Validators check structure, bindings, recorded evidence, freshness, and exact
bytes. They do not prove that evidence is true, that a reviewer is independent,
or that a vulnerability will be accepted by a program.

Stay within current scope and safe harbor. Use owned accounts and data, minimize
impact, and never use exposed credentials or pivot into third-party systems.
