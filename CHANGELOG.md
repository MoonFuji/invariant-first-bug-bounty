# Changelog

## v0.4.1 — self-review guardrails

Documentation-only refinements to the v0.4.0 self-review and ideation steps; no
validator or schema change (the suite is unchanged at 27/27).

- `references/adversarial-self-review.md`: **symmetry rule** — the self-review must
  not become a false-negative engine. Every downgrade / `UNCERTAIN` / `DISPROVED`
  must cite code-grounded evidence for the doubt; an invented or theoretical
  mitigation (a hidden WAF, unlisted middleware, assumed production hardening) may
  not defeat a real finding, mirroring the workflow's existing ban on unevidenced
  attacker preconditions. Also clarifies that `fp_pattern_hits` are the eight
  patterns against the single candidate (at most a handful), never one per grep
  line — a large recon hit list is a discovery list for the variant sweep.
- `references/hypothesis-generation.md`: dropping an unsupported hypothesis is the
  queue working, not a failed target — pivot to the next; a hypothesis is not a
  candidate, so nothing gates on it.
- `SKILL.md`: variant sweep prioritizes the highest-likelihood siblings and records
  leads rather than exhaustively tracing every one, stopping when the abstraction
  ladder's false-positive rate climbs.

Deliberately not adopted: a filesystem/mtime artifact check on `cold_verify` (still
gameable, and an mtime window would break the skill's cross-session persistence and
determinism), and a hard numeric cap on variant siblings (conflicts with the
systemic-finding value; the abstraction ladder already governs when to stop).

## v0.4.0 — discovery front-end and adversarial self-review

Grafts a hypothesis-generation and structured self-challenge front-end onto the
existing gate machinery, ported selectively from the `piolium` audit engine. The
guiding rule: piolium's outputs are hypotheses that still owe every gate, never
verdicts. No new terminal verdicts; the volume/consolidated-report orientation of
an audit tool is deliberately not adopted.

### Controller and references

- New `references/hypothesis-generation.md`: eight attack modes with a mandatory
  creativity signal, pre-mortem backward chaining, defensive-code-as-symptom, TRIZ
  tension scan, and adaptive-attacker framing. Produces a ranked queue; a hypothesis
  becomes a candidate only after relevance plus a first trace.
- New `references/adversarial-self-review.md`: a solo role rotation — Advocate (the
  eight false-positive patterns), zero-context Cold verifier, and Causal challenger
  — run before proof. It can only lower confidence or KILL; it never clears a gate.
- `SKILL.md`: an intent corpus in step 1, an ideation step 3 and a self-review step 7
  (workflow renumbered to 11 steps), a variant sweep in the depth contract, three new
  rationalizations, and two reference rows.
- `references/emerging-surfaces-and-techniques.md`: 1G AI-agent CI vectors
  (A/C/E/F/G/H/I), a seven-vector patch-bypass table (2B), the variant abstraction
  ladder and class-expansion checklist (2C), and 2G history mining / silent-fix
  detection.
- `references/bug-class-taxonomy.md`: section 20, cross-cutting analysis lenses —
  authorization guard matrix with the outlier-sibling heuristic, state/concurrency
  enumeration, cross-service taint, fail-open vs fail-secure, and misuse-resistance
  footguns.
- `references/methodology-and-targeting.md`: a self-contained report-hygiene lint.

### Candidate schema 5

- Five optional blocks record the new process: `hypothesis_queue`, `intent_corpus`,
  `adversarial_review`, `variant_sweep`, `patch_bypass`.
- Hard REPORTABLE gates (schema >= 5 only): `intent_corpus.finding_match` must not be
  `intentional`; `adversarial_review.cold_verify.verdict` must be `CONFIRMED`; every
  `advocate.fp_pattern_hits[]` entry must carry a written rebuttal.
- Warn-only (non-blocking `WARN:` lines, exit 0): a hypothesis with no creativity
  signal, and an unrecorded variant sweep on a REPORTABLE finding.
- Legacy schema-3/4 candidates still validate at non-report stages. Seven new
  acceptance cases (K–P); the suite is 27/27.

## v0.3.2 — regression fixtures

No validator behavior change. Pins the `target_does_not_own_security_property`
routing (confirmed terminal refutation lands `KILL @ ownership` or
`ROUTE_ELSEWHERE @ route`, never `REPORTABLE`) as three acceptance cases in
`scripts/test_validate_candidate.py` (H, I, J), so a future edit that regresses
the routing fails the suite. `scripts/validate-candidate.py` is byte-identical
to v0.3.1.

## v0.3.1 — candidate schema 4

Driven by two live failures where the schema stored a verdict but not the
evidence that justifies it, letting a filled candidate pass while violating the
gate's intended meaning:

- **Refutation without a resolution.** A candidate could set
  `refutation_result: "refuted"` while the strongest refutation was an
  intended-usage / owned-boundary argument, then reach `REPORTABLE`. This closed
  HackerOne #3925350 (Vertex model-route escape) and #3858135 as Informative.
- **Novelty asserted from `git log` alone.** `upstream_history` was one coarse
  source, so a `git log` check satisfied it while the GitHub issue/PR search was
  never run — missing a live duplicate PR (marcel #153) and a by-design issue
  (activeresource #358).

### Changes

- `threat_model.strongest_refutation` is now a structured object
  `{claim, kind, evidence, resolution, resolution_source, result}`. A terminal
  `kind` cannot be `refuted` and cannot reach `REPORTABLE`; `REPORTABLE` requires
  a `resolution`, an independent `evidence` artifact, and
  `resolution_source: "target_owned"`.
- `novelty.checks[]` carry `evidence: {method, query, artifact}`, required for
  executed results once `classification` is `distinct`. The `upstream_history`
  check carries `channels` (commits, issues, pull_requests), each with its own
  search artifact. A match whose fingerprint equals `root_cause_fingerprint`, or
  a match flagged `establishes_by_design`, blocks `distinct`/`REPORTABLE`.
- `schema_version` accepts `3` or `4`. Legacy schema-3 candidates still validate
  at non-report stages; a candidate must be migrated to schema 4 to pass
  `--stage report`.

Follow-up enforcement (closing three "field satisfiable without the work" gaps
found in review of the first cut):

- `novelty.current_upstream_state` makes the "current default branch still
  vulnerable" check mechanical. `distinct` requires `result: "vulnerable"` with
  a fetch artifact; `fixed` forbids `distinct`; `unavailable` caps at
  `HOLD @ novelty`. Previously this was prose only.
- On a `github.com/` repository, `issues` and `pull_requests` channels marked
  `unavailable` must carry an attempted-search artifact and never count as
  coverage for `distinct`, so "unavailable" can no longer stand in for "didn't
  search." Non-GitHub upstreams keep the generic `unavailable` semantics.
- A confirmed terminal refutation must land at the gate its `kind` implies
  (`TERMINAL_KIND_GATES`), not merely avoid `REPORTABLE`.

### Tests

`scripts/test_validate_candidate.py` reproduces every failure shape as an
acceptance case (18 total: reject cases assert the intended rule, plus accept,
legacy backward-compat, and the reviewer's A–G current-branch / GitHub-channel /
terminal-gate scenarios).
