# Invariant-First Bug Bounty

[![Agent Skill](https://img.shields.io/badge/Agent%20Skill-compatible-111827)](https://agentskills.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A portable Agent Skill for evidence-gated, authorized vulnerability research. It treats a hunt as a campaign over many hypotheses, binds every candidate to a live-evidence target ledger, and blocks report-ready output until the final candidate clears proof, routing, novelty, hardening, and independent-review gates.

## What it prevents

AI-assisted hunts commonly fail in opposite directions:

- they stop after the first dead hypothesis and call the target clean;
- they promote a real code defect without proving a new attacker capability;
- they rotate away from viable targets based on remembered or paraphrased policy;
- they submit valid but high-collision findings to invisible duplicate pools;
- they certify their own analysis or review an early draft rather than the final claim.

This skill makes those decisions explicit and auditable.

## Install

```bash
npx skills add MoonFuji/invariant-first-bug-bounty
```

Common manual locations:

```text
~/.agents/skills/invariant-first-bug-bounty
~/.claude/skills/invariant-first-bug-bounty
```

## Use

```text
Use $invariant-first-bug-bounty to run an authorized security campaign against
this target. Create and validate the live-evidence target ledger first, map the
surface, rank hypotheses, investigate one invariant at a time, continue after
each candidate verdict, and do not draft a report until the target-bound report
validator says REPORT READY.
```

## Workflow

```text
live scope + policy + asset saturation
                  |
            target.json
          SELECTED/HOLD/ROTATED
                  |
       candidate generated from target
                  |
       architecture + hypothesis queue
                  |
       one invariant traced end to end
                  |
       capability delta + refutation
                  |
       exact proof + controls + route
                  |
       novelty + collision assessment
                  |
       hardening + final fresh review
                  |
       candidate verdict; continue queue
```

## Mechanical gates

### 1. Select or rotate the target

```bash
cp assets/target.template.json /path/to/hunt/target.json
python scripts/validate_hunt.py --stage target /path/to/hunt/target.json
```

The target ledger records live scope evidence, exact proof-policy text and accepted proof types, asset-level dedup visibility, and a structured `SELECTED`, `ROTATED`, or `HOLD` decision.

### 2. Generate the candidate from the selected ledger

```bash
python scripts/start_candidate.py \
  --target-ledger /path/to/hunt/target.json \
  --output /path/to/hunt/candidates/H-001.json
```

This copies target identity and binds the candidate through `target_ledger_id`.

### 3. Validate model, decision, and report stages

```bash
python scripts/validate_hunt.py \
  --stage model \
  --target-ledger /path/to/hunt/target.json \
  /path/to/hunt/candidates/H-001.json

python scripts/validate_hunt.py \
  --stage decision \
  --target-ledger /path/to/hunt/target.json \
  /path/to/hunt/candidates/H-001.json

python scripts/validate_hunt.py \
  --stage report \
  --target-ledger /path/to/hunt/target.json \
  /path/to/hunt/candidates/H-001.json
```

A nonzero report-stage exit forbids drafting. `reviewer.mode: owed` is accepted only as a provisional decision; final report stage requires a completed independent or human review.

## Target decisions are gate-aware

A rotation cannot be justified by “too hard” or remembered policy. It carries a structured basis such as:

```text
scope_ineligible
proof_route_unavailable
route_unavailable
saturation
payout_unavailable
user_directed
```

When evidence cannot be retrieved, use `HOLD` and record the missing artifact.

## A load-bearing caveat determines the gate

Before reporting, state:

> The attacker, who already holds X, crosses boundary Y to gain capability Z they could not exercise before.

A caveat is fatal only when it negates the attacker-controlled source, crossed boundary, new capability, target-owned property, accepted proof route, or security-enforcing nature of the control. Ordinary limitations remain in the report and constrain scope or severity. This avoids both submitting informatives and deleting honest limitations merely because they sound cautious.

## Independent review

The author may run an adversarial self-pass to shape the proof, but final certification happens after proof, novelty, and a timestamped hardening pass. The reviewer attestation records mode, identifier, timestamp, artifact, and fresh-context status; the validator rejects review-before-hardening and decision-before-review ordering.

A final candidate-level `NO_REPORTABLE_FINDING` also requires `closure_review` to challenge the closure and assess the adversarial probe or waiver. Its coverage-gap and remaining-hypothesis arrays are preserved as campaign continuation inputs; they are not required to be empty, and one closed candidate never certifies that the target is clean.

## Files

```text
SKILL.md                         Core campaign controller
agents/openai.yaml               Skill-list metadata and campaign prompt
assets/target.template.json      Live-evidence target selection ledger
assets/candidate.template.json   Bound per-invariant evidence state
references/                      Methodology, hypothesis, review, and bug-class guidance
scripts/validate_hunt.py         Authoritative target-bound validator
scripts/start_candidate.py       Generate a candidate from a selected target
scripts/validate-candidate.py    Candidate-core validator
scripts/test_validate_hunt.py    Target/binding/review regression tests
scripts/test_validate_candidate.py Existing candidate-gate regression suite
scripts/recon-sweep.sh           Optional model-gated sink/variant triage
```

## Testing

```bash
python -m compileall -q scripts
python scripts/test_validate_candidate.py
python scripts/test_validate_hunt.py
```

GitHub Actions runs the same checks on pushes and pull requests.

## Limits

The validators enforce structure and consistency; they cannot prove that a quoted policy, reviewer identity, or evidence artifact is truthful. Inspect the artifacts and reproduce the boundary before submission. A candidate verdict closes one hypothesis, not the target.

## Authorized research only

Use this skill only on systems you own or assets covered by current scope and safe-harbor terms. Use owned accounts and data, minimize impact, and never use exposed credentials or pivot into unrelated systems.

Do not publish private program material or undisclosed vulnerability details in issues, pull requests, examples, or changelogs.

## License

MIT. See [LICENSE](LICENSE).
