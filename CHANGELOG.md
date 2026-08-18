# Changelog

## v0.4.4 — commitment binding and second-wave review items

Second wave from the same adversarial review. v0.4.3 took its two flagship points; this pass takes
the strongest remaining ones — the pattern is the same throughout: an existing prose device becomes
a checkable one (degrees-of-freedom rule), and the skill's own stated epistemics become validator
rules. Suite 40 → 45; schema 5, `commit` block added; no new terminal verdicts.

Commitment binding (review #3 — "commit-before-hunt does not bind"; correct, the sharpest deferred
item). "Commit before you hunt" told the agent to "write into candidate.json" a commitment, but
there was no block to write it to and nothing checked it — an announcement, not a binding.

- New `commit` block: the immutable pre-hunt snapshot `{mode, invariant, expected_delta,
  committed_at, superseded_by}`. Every schema-5 candidate must carry it at decision/report.
- The **silent reframe** the review names as "the common failure" is now caught: if
  `commit.invariant` differs from `model.security_invariant` with no `decision_history` entry and no
  `commit.superseded_by`, the validator rejects it. Switching to a different bug than the one you
  committed to is no longer invisible.

Intent corpus owed early (review #4a). A schema-5 `NO_REPORTABLE_FINDING` now requires a present
`intent_corpus` (`checked_at` + `sources`), not only `REPORTABLE`. The by-design question is
confronted where a match is a `KILL @ refutation`, not back-filled as `finding_match: none` at report
polish time.

Private-duplicate honesty (review #6). The validator already rejected `private_duplicate_risk ==
"unknown"` at `REPORTABLE`; it now also rejects `low` when **every** public novelty check came back
clean. Absence of public matches is the weakest evidence about the invisible private pool, not the
strongest — so an all-clean search cannot be labelled low private-duplicate risk. This encodes the
skill's own line ("no public match is weak evidence") as a check.

Process scaling and EV rotation (reviews #4b, #5 — prose, no schema):

- `SKILL.md` **Scale the process to the target**: the full stack fits a large product; on a small
  single-surface `SOURCE_ONLY` library the ideation queue / variant sweep / patch-bypass are often a
  one-line "n/a" while the core gates (capability delta, refutation, proof, novelty) always hold.
  Answers the "heavy stack → cargo-cult on toy targets, skip on hard ones" critique.
- Depth contract sharpened: EV-based rotation (proven low-value, with a higher-EV item queued) is
  legitimate **only when the rationale is recorded**; difficulty-based rotation is the sunk-cost
  failure the STOP flags name. `hypothesis_queue` entries gain a `parked` status + `park_reason` so an
  EV-park is durable and auditable, never "too hard."

Still deferred (recorded, not re-litigated): #4c a stage→requirement table (it would duplicate the
validator, the single source of truth, and drift from it); the #2 independent-verifier marker (the
prose already recommends one, and a warn on every self-rotated REPORTABLE would be noise); #8
description rewrite (it passes both metadata validators and triggers correctly); #10 a hard ideation
cap (an arbitrary N; "promote exactly one, no second until terminal" already bounds it).

## v0.4.3 — checkable exhaustion and cold-verify decomposition

Answers a fourth, adversarial review. Two of its points were the load-bearing ones — they decide
whether the honesty philosophy is enforced or merely literary — and both are adopted; the rest are
triaged below (some already handled, some deferred, one overstated). Suite 34 → 40; schema 5,
report gates extended; no new terminal verdicts.

The design rule throughout is Anthropic's own: match the *degree of freedom* to the *fragility* of
the step — low-freedom scripts/validation for consistency-critical operations, high-freedom prose
for open-ended ones. Terminal honesty is fragile and consistency-critical, so it moves out of the
KEEP-GOING prose list and into checkable schema.
(https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview)

Checkable exhaustion (review #1 — "'exhaust before you conclude' is unenforced theater"; correct):

- `NO_REPORTABLE_FINDING` was the weakest terminal to fake — it required only a confirmed refutation
  and equal capabilities, with the five Depth-contract records living in prose. A schema-5
  `NO_REPORTABLE_FINDING` now requires an `exhaustion` block: a non-empty `tried[]` and all five
  `depth_contract` fields (`entrypoint`, `invariant_enforcement`, `trace`, `sibling_checked`,
  `defeated_counterexample`). This does not *prove* exhaustion — prose is still prose — but it raises
  the floor from a bare verdict to an articulated, auditable one, symmetric with how `REPORTABLE`
  must articulate its evidence. Grounding: agents skip needed work and ignore evidence under
  pressure (ToolFailBench, arXiv 2607.04686, "Tool-Skip"/"Result-Ignore"), and long-horizon
  benchmarks grade dense sub-tasks precisely because a final self-report hides intermediate work
  (Long-Horizon-Terminal-Bench, arXiv 2607.08964).

Cold-verify decomposition (review #2 — "CONFIRMED is a self-signed certificate"; sharpest point):

- A `REPORTABLE` `cold_verify.verdict == "CONFIRMED"` now requires a persisted `subclaims[]`
  decomposition (≥2, each `{claim, status}`, every link `supported`) — the A/B/C chain the cold
  verifier is already told to build (attacker controls X; X reaches Y unsanitized; Y causes Z).
  Grounding: self-preference bias is real (Panickssery et al., arXiv 2404.13076) and, critically,
  *worst exactly when the model's own output is wrong* — "stronger models struggle more to
  recognize when they are wrong" — while "generating a long Chain-of-Thought before evaluation
  effectively reduces the harmful self-preference" (Chen et al., arXiv 2504.03846). So the fix is to
  force the explicit decomposition *before* the verdict, and to keep clearing gates by artifacts and
  the deterministic validator, not the self-grade — an external check makes the bias vanish (Guey &
  Bougault, arXiv 2606.20093). The effect is also partly confounded by evaluator quality, so this is
  a structural mitigation, not a claim of "narcissism" (Roytburg et al., arXiv 2601.22548).
- `references/adversarial-self-review.md` updated: persist `subclaims`, and the sourced rationale
  that an independent verifier / the validator removes the bias the self-grade cannot.

Worked-examples count (review #7 — correct, a credibility nick): the v0.4.1 entry said "two"
worked examples; the file has four (`KILL`, `REPORTABLE`, `HOLD`, `ROUTE_ELSEWHERE`). Entry fixed.

Triage of the remaining review points (recorded so they are not re-litigated):

- **Already handled — #5 "hard is not dead vs EV rotation."** The Depth contract already permits
  rotation "when contestability makes the expected value poor." "Hard is not dead" bars *difficulty*
  as a rotation trigger, not *EV* — they are not in conflict. No change; the review missed the
  existing EV exit.
- **Already partly gated — #6 novelty/private-duplicate.** The validator already rejects
  `private_duplicate_risk == "unknown"` at `REPORTABLE`. Forcing `>= medium` whenever every public
  check is `no_match` is a reasonable further tightening but P2 — deferred.
- **Deferred (P2/P3, real but lower-leverage; batching now would bloat the schema):** #3 persist a
  commit snapshot and diff the invariant string to catch silent reframes; #4 a stage-timing table
  and moving the intent-corpus requirement earlier than report; #8 lead the description with trigger
  conditions over the asset taxonomy; #10 a hard ideation cap. Each is a candidate for a later pass.

## v0.4.2 — campaign continuation and self-review anti-gaming

Answers two external design reviews. Their shared diagnosis is correct and adopted: the skill was
optimized hard to *reject* bad findings but only weakly to *keep discovering*, so an agent could
kill one candidate and treat the target as finished ("one invariant had become one hunt"), and the
schema-5 self-review blocks were satisfiable without doing the work. Their prescribed cure — turn
the portable skill into a Claude-Code plugin with Stop hooks, subagents, `hunt-state.json`, a
campaign validator, a repo mapper, a 3-skill split, and a behavioral eval suite — is largely
declined (see "Deliberately not adopted"); the fixes below deliver the same intent at the skill's
actual abstraction level.

Validator hardening (`scripts/validate-candidate.py`; suite 27 → 34):

- **Report stage now requires `schema_version >= 5`.** A schema-4 candidate validated at report
  stage, bypassing every schema-5 gate while the skill told agents to "migrate before REPORTABLE."
  The rule is now mechanical; legacy schema-3/4 still validate at model/decision stages. (case Q)
- **Shallow schema-5 self-review no longer passes.** The `REPORTABLE` gate previously ignored most
  fields. It now rejects: `advocate.blocks == true` (R), `cold_verify` CONFIRMED with a non-null
  `killed_subclaim` (S) or an empty `rederived_severity` (T), an empty `advocate.layers_checked`
  (U) or `strongest_defense`, an `intent_corpus` with no `checked_at`/`sources` (V), and an
  `fp_pattern_hits[]` rebuttal with no `evidence` locator (W) — the same "field satisfiable without
  the work" failure schema 4 closed for refutation and novelty.
- Warn-only: an empty `hypothesis_queue` now warns (the ideation front-end was skippable silently);
  the missing-`creativity_signal` warning was reworded from "drop it" to "rank by expected value,"
  matching the calibration fix below.

Campaign continuation (the core behavioral fix — Anthropic's long-running-harness guidance keeps
unfinished work visibly pending rather than letting a later step declare done):

- `SKILL.md` **Core principle** reframed: a hunt is a *campaign over many hypotheses, validated one
  at a time*. A terminal verdict closes that hypothesis, **not the target**; the target is clean
  only when the ranked queue is exhausted with documented coverage.
- New workflow **step 12, "Continue the campaign"**: after a terminal verdict, update the queue
  entry's status and promote the next hypothesis; a `KILL`/`HOLD`/`NO_REPORTABLE_FINDING` is never
  the end of the hunt on its own. Checklist extended to 12.
- Workflow **step 2/3 ordering fixed** (they were contradictory — step 2 committed "one invariant,"
  step 3 generated hypotheses "before committing the invariant"). Step 2 now enumerates the
  *invariant space* and orients across the whole request surface (§20A) without anchoring; step 3
  ranks and promotes exactly one.
- `hypothesis_queue` is now the durable **campaign ledger** with a per-entry `status`
  (`queued → investigating → closed`) and `closed_verdict` (`references/hypothesis-generation.md`),
  resolving the "queue has no lifecycle / which copy is authoritative" smell without new machinery.
- `NO_REPORTABLE_FINDING` sharpened to candidate scope in the terminal-verdicts table; Depth
  contract now states target-clean is a higher bar than invariant-clean.

Calibration (stop the discovery front-end from suppressing valid findings or over-claiming):

- Creativity signal is a **ranking input, not an admission gate**: do not discard a reachable,
  high-impact, owned-boundary hypothesis for being an "obvious" sink (`hypothesis-generation.md`,
  `SKILL.md` step 3). Cross-mode chains no longer auto-rank highest — rank by expected value; a
  simple reachable authz bug can outrank a speculative chain. "A guard is *proof*" softened to
  "a guard is *evidence* worth investigating."
- `bug-class-taxonomy.md` §20: two categorical statements ("pre-auth sink is one band higher,"
  "a webhook without idempotency is itself a finding") softened to hypotheses that still owe the
  trace and proof — consistent with the file's own signal → hypothesis → verdict rule.
- `adversarial-self-review.md`: solo role rotation is the **portable floor**; when the harness can
  spawn a genuinely independent verifier (fresh context, only the artifact, no prosecution
  narrative), use it for the cold-verify role — it is strictly stronger, and the main agent may not
  author its verdict.
- `agents/openai.yaml` default prompt is now campaign-oriented (map, rank a queue, one invariant at
  a time, continue until the queue is exhausted) instead of "model one invariant."

Dynamic-proof emphasis (answering a third review's "source-only blindspot" point — its headline
that the skill is static-only is false: `SOURCE_ONLY` already permits containers/DBs/listeners,
the validation hierarchy lists them, and the proof gate mandates executable proof. But the name
primes a static reading and no line said runtime-only classes need runtime proof, so):

- `SOURCE_ONLY` is clarified as an **authorization scope, not a static-analysis mode** — running
  the code (container, seeded DB, real CI workflow or MCP server, concurrent script) is expected;
  a static trace is the hypothesis, the local execution is the proof.
- Validation hierarchy now states "least impact" means least *impact*, not least *effort*: a static
  trace does not conclusively establish a race/TOCTOU, idempotency/replay, state-machine,
  parser-differential, or AI-agent/MCP execution flaw — advance to a running level for those.
- New Red-flags-KEEP-GOING entry: declaring a race/replay/state-machine/CI-agent flaw proven from a
  static read alone is a proof gap; stand up the container, seed the state, run the PoC.

Deliberately not adopted (diagnosis accepted, prescription declined — recorded so it is not
re-litigated):

- **Claude-Code plugin harness** (`.claude-plugin/plugin.json`, Stop hooks, `stop-gate.py`,
  mapper/tracer/verifier subagents, `hunt-state.json`, `validate-hunt.py`, splitting into three
  skills). The skill is deliberately portable and agent-agnostic (ships via `npx skills` and
  `agents/openai.yaml`); these are Claude-Code-only and would fork it into two products. A
  mechanical anti-stop hook also induces hypothesis-padding (the "twelve nonsense hypotheses"
  failure the review itself warns of) and fights the honesty ethic that an evidenced early `KILL`
  is a success. The continuation behavior is delivered in prose + the existing queue instead.
- **Behavioral eval suite.** The user has validated the skill with and without it across many real
  reports and explicitly declined building evals; that instruction stands.
- **`map-repository.py`** deterministic architecture extractor. A robust polyglot mapper is brittle;
  the agent's own step-2 reading is a more flexible mapper. Step 2's prose was strengthened instead.
- **Renaming the `NO_REPORTABLE_FINDING` verdict and `recon-sweep.sh`.** Broad churn for low
  behavioral gain once the definitions and campaign framing are sharpened; deferred.
- **A hard `patch_bypass` validator.** It applies only to patch-derived findings; the "the fix
  exists, so it's handled" rationalization already covers it in prose. Deferred.

## v0.4.1 — discipline hardening and self-review guardrails

Documentation-only refinements to the v0.4.0 workflow; no validator or schema
change (the suite is unchanged at 27/27).

Discipline enforcement (agents are not disciplined by default; these raise
compliance the way the persuasion-principles research predicts — commitment,
self-recognition, and worked examples):

- `SKILL.md` **Commit before you hunt**: announce the operating mode, the one
  invariant, and the expected capability delta before recon, and the terminal
  verdict + gate at the end — a spoken commitment makes a silent slide from HOLD
  toward REPORTABLE visible.
- `SKILL.md` **Red flags — STOP**: names the symptoms of an about-to-fail moment
  (drafting before the validator passes, claiming unreproduced impact, reaching
  for a substitute client, editing a field to pass the gate, submitting under
  rent/sunk-cost pressure) so the agent catches itself, complementing the reactive
  rationalizations table.
- New `references/worked-examples.md`: four candidates walked to a terminal verdict
  with decisive fields — a subtle `KILL @ refutation` (owned boundary vs. integrator
  misuse), a clean `REPORTABLE` (cross-tenant read), a `HOLD @ proof` (primitive
  fidelity), and a `ROUTE_ELSEWHERE @ route` (upstream owns the fix) — because a
  concrete pattern teaches the discipline better than rules alone.

Self-review guardrails:

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

Effort discipline (anti-premature-termination; 2026 research shows long-horizon
agents settle early and defend it, overestimate completion, and that verifiers
themselves induce early exit — arXiv 2606.22936, 2607.01793, 2605.23574):

- `SKILL.md` core principle now qualifies HOLD/KILL/NO_REPORTABLE_FINDING as
  successes only when reached after *exhausting* the investigation, not by
  stopping early.
- New `SKILL.md` "Exhaust before you conclude": hard is not dead; a wall is a
  redirect not an exit; the hard proof is the job; give-up is a claim that needs
  documented exhaustion — with the unifying frame "hustle toward the truth, not
  toward a report" so effort and the honesty gates never conflict.
- New `SKILL.md` "Red flags — KEEP GOING": the mirror of the STOP flags — symptoms
  of quitting too soon (concluding clean after a skim, rotating off a hard target,
  taking the easy substitute, reading "the gates let me stop" as "I should stop").
- Depth contract: difficulty is never a rotation trigger — rotate on proof of
  death, not on how hard the trace is.

Creative discipline — the attacker's imagination bounded by the researcher's
ethics (motivated by the July 2026 incident where a frontier model breached its
evaluation sandbox to steal the benchmark answer key rather than do the task:
creativity aimed at gaming a metric, not at the truth — the anti-pattern this
skill must foreclose while keeping the inventive "figure it out" instinct):

- New `SKILL.md` "Think like an attacker, act within scope": read the target with
  unbounded adversarial imagination (chain issues, weaponize intended features,
  the unvalidated input, resourceful proof) while holding scope, safe-harbor, and
  the agent's own sandbox as absolute — and aim the creativity at the truth, never
  at a passing result (a fabricated PoC, an out-of-scope "win", or an unproven
  claim is gaming the metric, the same failure as cheating a benchmark).

Authoring hygiene (from an agent-skill best-practices review): added a table of
contents to the two reference files over 100 lines (`hypothesis-generation.md`,
`adversarial-self-review.md`) so partial reads still see full scope, and a negative
trigger to the description ("Not for general code review, feature development,
refactoring, or test-writing") to prevent false activation on non-security tasks.
Metadata passes both the mgechev and skill-creator validators.

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
