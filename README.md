# Invariant-First Bug Bounty

[![Agent Skill](https://img.shields.io/badge/Agent%20Skill-compatible-111827)](https://agentskills.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A portable Agent Skill for evidence-gated, authorized vulnerability research. It separates campaign coverage, technical candidate validity, and final submission readiness so agents neither stop at shallow source smells nor leave a proven narrow report unfinished.

## What it prevents

AI-assisted hunts commonly fail in opposite directions:

- they stop after the first dead hypothesis and call the target clean;
- they promote a real code defect without proving a new attacker capability;
- they rotate away from viable targets based on remembered or paraphrased policy;
- they submit valid but high-collision findings to invisible duplicate pools;
- they keep recoverable or narrower findings in indefinite `HOLD`;
- they review an early candidate or report and then submit changed bytes.

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
validator says CANDIDATE REPORTABLE. Prepare the exact report bundle and stop at
SUBMISSION READY FOR FINAL CHECK for my final platform review.
```

## Workflow

```text
live scope + policy + contestability + prior outcomes
                  |
      target.json (campaign state)
          SELECTED/HOLD/ROTATED
                  |
       candidate generated from target
                  |
       architecture + hypothesis lifecycle
                  |
       one invariant traced end to end
                  |
       capability delta + refutation
                  |
       exact proof + controls + route
                  |
       novelty + collision assessment
                  |
       bounded claim + recovery decision
                  |
       hardening + exact candidate review
                  |
        CANDIDATE REPORTABLE
                  |
 submission.json + report.md + attachments
                  |
       exact final bundle review
                  |
 SUBMISSION READY FOR FINAL CHECK
```

## Mechanical gates

### 1. Select or rotate the target

```bash
cp assets/target.template.json /path/to/hunt/target.json
python scripts/validate_hunt.py --stage target /path/to/hunt/target.json
```

The target ledger records live scope, accepted proof routes, truthful contestability, prior outcomes, coverage delta, architecture boundaries, the hypothesis lifecycle, and a structured `SELECTED`, `ROTATED`, or `HOLD` decision.

### 2. Generate the candidate from the selected ledger

```bash
python scripts/start_candidate.py \
  --target-ledger /path/to/hunt/target.json \
  --hypothesis-id H-001 \
  --output /path/to/hunt/candidates/H-001.json
```

This binds one `investigating` hypothesis to the campaign, stable target fingerprint, and architecture boundary. The campaign queue stays in `target.json`.

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
  --candidate-review /path/to/hunt/reviews/H-001.json \
  /path/to/hunt/candidates/H-001.json
```

Decision stage can remain provisional. Report stage requires an affirmative sidecar review bound to the exact candidate bytes and prints `CANDIDATE REPORTABLE`.

### 4. Prepare and validate the exact submission

```bash
python scripts/start_submission.py \
  --candidate /path/to/hunt/candidates/H-001.json \
  --candidate-review /path/to/hunt/reviews/H-001.json \
  --report /path/to/hunt/report.md \
  --output /path/to/hunt/submission/submission.json \
  --submission-id S-001 \
  --title "..." --weakness "..." --severity high \
  --cvss-score 8.1 --cvss-vector "..." \
  --command "python3 reproduce.py"

cp assets/submission-review.template.json \
  /path/to/hunt/submission/submission-review.json

python scripts/validate_hunt.py \
  --stage submission \
  --target-ledger /path/to/hunt/target.json \
  --candidate /path/to/hunt/submission/candidate.json \
  --candidate-review /path/to/hunt/submission/candidate-review.json \
  --submission-review /path/to/hunt/submission/submission-review.json \
  /path/to/hunt/submission/submission.json
```

The final stage rechecks live scope/proof policy, candidate/report/attachment digests, claim bounds, severity ceiling, and both affirmative reviews. It prints `SUBMISSION READY FOR FINAL CHECK`; it does not submit anything.

## Target decisions are gate-aware

A rotation cannot be justified by “too hard” or remembered policy. It carries a structured basis such as:

```text
scope_ineligible
proof_route_unavailable
route_unavailable
contestability
payout_unavailable
user_directed
```

When evidence cannot be retrieved, use `HOLD` and record the missing artifact.

## A load-bearing caveat determines the gate

Before reporting, state:

> The attacker, who already holds X, crosses boundary Y to gain capability Z they could not exercise before.

A caveat is fatal only when it negates the attacker-controlled source, crossed boundary, new capability, target-owned property, accepted proof/deployment route, or security-enforcing nature of the control. Ordinary limitations remain in the report and constrain scope or severity. This avoids both submitting informatives and deleting honest limitations merely because they sound cautious.

Record every hedge the attacker-model test surfaces in the candidate's `caveats` ledger. A load-bearing hedge controls the gate; an ordinary limitation controls scope or severity. When only a stronger extension fails, `NARROW` preserves an exact, security-relevant claim instead of trapping it in indefinite `HOLD`.

## Independent review

The author may run an adversarial self-pass to shape the proof. Final candidate review is a separate sidecar over the exact candidate digest after hardening and decision. Final submission review binds the exact manifest, report, candidate, and every attachment. A digest proves which bytes were reviewed, not that a claim is true or a reviewer is independent.

A final candidate-level `NO_REPORTABLE_FINDING` also requires `closure_review` to challenge the closure and assess the adversarial probe or waiver. Its coverage-gap and remaining-hypothesis arrays are preserved as campaign continuation inputs; they are not required to be empty, and one closed candidate never certifies that the target is clean.

## Files

```text
SKILL.md                         Core campaign controller
agents/openai.yaml               Skill-list metadata and campaign prompt
assets/target.template.json      Live-evidence target selection ledger
assets/candidate.template.json   Bound per-invariant evidence state
assets/submission.template.json  Final report/attachment manifest
assets/candidate-review.template.json Candidate review sidecar
assets/submission-review.template.json Final bundle review sidecar
references/                      Methodology, hypothesis, review, and bug-class guidance
scripts/validate_hunt.py         Authoritative target-bound validator
scripts/start_candidate.py       Generate a candidate from a selected target
scripts/start_submission.py      Create a self-contained final report bundle
scripts/validate-candidate.py    Import-only candidate core
scripts/test_validate_hunt.py    Target/binding/review regression tests
scripts/test_validate_candidate.py Existing candidate-gate regression suite
scripts/test_validate_campaign.py Campaign-state regression suite
scripts/test_validate_submission.py Exact-bundle regression suite
scripts/recon-sweep.sh           Optional model-gated sink/variant triage
```

## Testing

```bash
python -m compileall -q scripts
python scripts/test_validate_candidate.py
python scripts/test_validate_hunt.py
python scripts/test_validate_campaign.py
python scripts/test_validate_submission.py
python scripts/test_validate_hunt_cli.py
```

GitHub Actions runs the same checks on pushes and pull requests.

## Limits

The validators enforce structure and consistency; they cannot prove that a quoted policy, reviewer identity, or evidence artifact is truthful. Inspect the artifacts and reproduce the boundary before submission. A candidate verdict closes one hypothesis, not the target.

## Authorized research only

Use this skill only on systems you own or assets covered by current scope and safe-harbor terms. Use owned accounts and data, minimize impact, and never use exposed credentials or pivot into unrelated systems.

Do not publish private program material or undisclosed vulnerability details in issues, pull requests, examples, or changelogs.

## License

MIT. See [LICENSE](LICENSE).
