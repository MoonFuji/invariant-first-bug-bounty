# Changelog

## Unreleased — target-bound integrity pass (PR #1 review fixes)

Review of `fix/target-ledger-integrity` against the v0.6.0 design intents produced five corrections:

1. **Caveat ledger with mechanical teeth.** The load-bearing/ordinary caveat refinement was
   semantically sound but fail-open: the submitting agent self-classified its own hedge at the
   moment of maximum motivated reasoning, with zero structural friction. New `caveats[]` ledger
   (`{quote, classification, justification}`) is required on every `REPORTABLE`; a `load_bearing`
   classification rejects the stage until evidence removes the hedge, the claim is narrowed, or
   the candidate is decided `HOLD`/`KILL`. Classification stays a judgment — no tooling pretends
   to smell an informative — but it is now explicit and auditable instead of silent.
2. **Anonymized-but-concrete calibration restored.** The four real informative case studies
   (near-verbatim submitted hedges anchored to the gates they should have died at) are back in
   `references/worked-examples.md` §7 without program names, products, or report identifiers.
   Fully generic examples alone were the abstraction level that had already failed before v0.6.0.
3. **Anti-laziness and anti-bureaucracy prose restored**: the scale-to-target guard (step 0), a
   compact Rationalizations table, the lazy intent-corpus instruction (step 3), and a scoped-HOLD
   note distinguishing target/candidate/closure HOLDs.
4. **Terminology discipline**: "load-bearing" now means caveats only — closures are
   "verdict-critical", links "claim-critical", representations "exploit-critical"; the dangling
   schema-5 reference in step 1 was rewritten to state the actual bypass risk.
5. **Closure honesty warning**: a final clean closure claiming both empty `coverage_gaps` and
   empty `remaining_high_value_hypotheses` emits a warning — a fully-covered-target claim must
   survive its own exhaustion record.

## v0.6.0 — govern the pre-candidate layer: the caveat is the verdict + the target ledger

Driven by reading a full real hunting session (9 hunts, Aug-17→20) and the user's duplicate-origin
audit of 24 HackerOne dupes — not reviewer theory. Two findings reshaped the skill:

1. **The dupes split ~evenly.** 37% (9/24) were collisions with an original that was *itself*
   `informative`/`not-applicable` — the class was pre-rejected; these were never payout-worthy. 42%
   were genuine near-misses (original `resolved`/`triaged`). So "dup driver = saturation" was half
   wrong: half the losses were **finding-quality**, not selection.
2. **Reading the six directly-informative reports** (exodus keychain #3948361, anthropic
   `_require_https` #3858135 and Vertex #3925350, lightspark QueryNodes #3852098, crypto.com
   safety-tier #3857707, rails `allowed_uri` #3857547) showed one thread: each was a real, competently
   proven code defect that **stated its own disqualifier in its own words** — *"does not bypass
   authentication," "does not prove production exposure," "no production IPC path is required for the
   demonstrated case,"* — and was submitted anyway.

### The caveat is the verdict (judgment, not tooling)
No validator can smell an informative — this is a reading discipline. `references/worked-examples.md`
now teaches it concretely: the meta-rule (**a hedge you write about your own impact is a
kill-condition, not a disclosure**), a one-sentence attacker-model test (*"the attacker, who already
holds X, crosses boundary Y to gain capability Z"*), and four kill-questions each anchored to a real
informative with its verbatim self-caveat and the gate it should have died at (boundary / precondition
/ deployment / control-class). SKILL step 6 carries the rule; new STOP flag and two rationalization
rows enforce it in the moment. Deliberately **no** substate-lookup gate — the user's point stands
that tooling cannot make a finding informative-aware.

### Target ledger (`--stage target`) — govern entry and exit
Both persistent losses (a viable target skipped as "source-only is N/A" on a *paraphrased* policy the
live text contradicted — matomo; deep findings filed on saturated assets) happen **before a candidate
exists**, in the layer the skill didn't govern. New lightweight `assets/target.template.json` +
`validate_target` + `--stage target`, created first for every target selected *or* rejected. It gates
on live-pulled facts: `scope.eligible_for_bounty` (from a live `GetProgramScopeDetail` pull, never
memory), a **verbatim** `poc_policy.quote` (you cannot decide source-viability in either direction on
a paraphrase), asset-level `saturation`, and a `disposition` — where **`ROTATED` is a terminal verdict
owed the same live evidence as a `KILL`.** Being light, it is also the upfront checkpoint the heavy
`candidate.json` wasn't (which the session showed getting back-filled at report time).

Includes all v0.5.1 fixes below. Suite 58 → 65 (7 target-ledger cases). SKILL.md 304 lines.
Memory `reference_bounty_failure_distribution` corrected: the dup driver is ~half impact-bar, not
mostly saturation.

**Not built (rejected with reasons):** a `duplicate_information.substate` novelty gate (tooling can't
judge informative-ness — the user's call); a review-to-candidate digest (unverifiable); a `hunt.json`
state machine / campaign-stop (the ledger is entry/exit only); a native H1 draft-intake signal
(MCP-dependent, not confirmed live).

## v0.5.1 — correctness holes in the independence spine

A research-tight re-review of v0.5.0 found that the new independence machinery, while directionally
right, had holes the validator did not catch — two of them demonstrated by the skill's own golden
fixtures. These are the fixes; verified against the code before implementing, and the unsound
proposals rejected with reasons.

- **A clean verdict can no longer carry a confirmed finding.** `baseline_nrf` (the golden
  `NO_REPORTABLE_FINDING` accept) was built from the `REPORTABLE` fixture and inherited its
  `cold_verify.verdict: "CONFIRMED"`, its cross-tenant-read subclaims, *and* a proof of "boundary
  crossed" — while declaring the target clean. The NRF branch never inspected `cold_verify`, so a
  clean verdict could carry an independent reviewer that said the bug was real. Now a schema-5
  `NO_REPORTABLE_FINDING` with `cold_verify.verdict == "CONFIRMED"` is **rejected** (the review must
  audit the clean conclusion — `DISPROVED`/`UNCERTAIN`), and the fixture is rewritten coherently.
  (new case AF.)
- **`owed` prints `PROVISIONAL`, not `READY`.** An owed independent review exited 0 with the normal
  `REPORT READY` label, so the skill's "nonzero forbids drafting" rule read the provisional state as
  submit-ready. The validator now prints `REPORT PROVISIONAL -- INDEPENDENT REVIEW OWED` (and the
  decision-stage equivalent); still exit 0 so a harness that cannot spawn an agent is not deadlocked,
  but the label no longer says "ready".
- **The static-clean warning moved off `proof.type`.** It keyed on `proof.type`, which a clean
  verdict never validates and can inherit populated from a dropped report draft — so it never fired
  on the golden clean fixture. It now keys on a recorded `exhaustion.probes[]` entry (command +
  observed result). New optional `exhaustion.probes` block; the golden clean fixture carries a real
  negative probe. Still warn-only, per the earlier warn-only choice.
- **Certify last, on the finished candidate.** The independent review was placed *before* proof and
  hardening (reference + step 7), so it never saw the final claim the hardening pass may have widened
  or re-scored — a TOCTOU on the artifact under review. The self-run rotation is now explicitly
  *preparation* (step 7, shapes the proof, never sets `reviewer`), and the independent
  *certification* runs on the finished candidate after proof and hardening (step 11). Doc-level: a
  static per-candidate validator cannot verify order-of-operations, so this is enforced by the
  workflow, not the JSON.
- **`hot_cluster` defaults to `null`, not `false`.** The template shipped `false`, contradicting the
  skill's "never guess these — leave null" rule and silently disabling the collision brake (which
  only fires on `hot_cluster: true`, high risk, or a non-disclosing program). Now `null`.
- **"stop early" is gone.** Step 4 still literally said "If no meaningful capability change is
  possible, stop early" — the exact phrase tied to the give-up-too-soon complaint, and a direct
  contradiction of the KEEP-GOING rule ("trace first, then judge"). Rewritten to trace-then-close-
  the-hypothesis, never the target.
- **Severity reassessment, not escalation.** The hardening leg said "escalate severity", a
  directional nudge against the skill's own anti-inflation stance. Reworded (SKILL + validator
  message) to reassess on evidence — raise only when supported, hold or lower otherwise. Field name
  `escalated_severity` kept (a rename would ripple for marginal gain).
- **`config_dependency` clarified, not split.** A vendor-shipped default that real deployments run
  *unchanged* is the base case `none`, not `default_only` (which means a dev/template default a real
  deployment replaces). One clarifying clause — the reviewer's proposed enum split was rejected
  (it risks re-admitting the operator-config informatives the gate exists to stop; the good case is
  already expressible as `none`).

**Rejected, with reasons:** binding the review to a self-computed candidate digest (the agent writes
its own hash — presence-not-truth, unverifiable, heavy); a mechanical campaign-stop / queue-lifecycle
gate (a per-candidate validator structurally cannot see the campaign; warn-only was the deliberate
choice); and a portable proof of reviewer independence (impossible without harness cooperation —
already caveated honestly).

Suite 57 → 58 (case AF added). Still owed: the empirical re-mine after more hunts.

## v0.5.0 — trustworthy depth: independence over self-certification

A direction change, driven by two things the earlier analysis missed. First, the user pointed out
that the 37-report failure distribution was **submitted-only** — it never looked at the hunts that
produced nothing. Mining **247 local candidate.jsons** filled that gap and corrected the picture:
the agent is not lazy about breadth-of-guesses (it fans out to 40–79 hypotheses per hunt), but a
"clean" verdict **rests on static reading, not probing** — ~half of `NO_REPORTABLE_FINDING`s ran no
executed probe, several concluding "clean" by trusting the *target's own tests*. And the one deep,
trustworthy clean verdict in the corpus (`exodus_hunt/crypto-audit`) is the exemplar: multiple
hypotheses each killed with executed evidence and a real causal red-team. Second, the user's
standing needs: they don't trust a self-reported "no finding," their reports come out weak and get
manually hardened in a fresh session, and they want adversarial review done by an *independent*
agent, not self-graded.

So this release reverses the prior "prune the depth machinery" instinct — that machinery is the fix,
it was just barely deployed (18 of 247 files) and self-certified. The spine of v0.5.0 is:
**self-certification is banned.**

- **Independent review, not self-review.** `adversarial_review.reviewer` records who ran the review.
  A `REPORTABLE` or `NO_REPORTABLE_FINDING` with `reviewer: "self"` is **rejected**; it must name an
  independent fresh-context agent (given only the artifact) or be `"owed"` — which is accepted as
  **provisional** and prints a signal for the user. Portable: works as an instruction whether or not
  the harness can spawn subagents. (cases AA/AD reject self; AB/AE accept owed.)
- **Hardening pass before a report.** A `REPORTABLE` now requires `hardening.status: "done"` — a
  widen-blast-radius / escalate-severity / deepen-PoC pass (ideally by a fresh agent) — because the
  reports ship weak (all 21 in the corpus self-rated dup-risk ≥ medium or severity ≤ Low). (case AC.)
- **Static reading is not probing (warn).** A `NO_REPORTABLE_FINDING` with no executed probe warns
  that the verdict rests on a static read; per the user's choice this is a nudge, not a block — the
  trust comes from the independent reviewer, not a hard proof-type gate. New Exhaust-section line.
- **Cuts folded in (the conservative first subtractive pass):** the `commit` block (guarded a
  silent-reframe failure the data never shows, and needed two prior fixes) and the `patch_bypass`
  block (shipped as seven `"n/a"` strings, and steered toward the dup-trap the §2B tiers warn about)
  are removed; the §2B incomplete-fix tier *prose* stays. Two duplicate rationalization rows dropped.

Suite 58 → 57 (six commit cases removed, five independence/hardening cases added). `adversarial-self-
review.md` reframed to independent-first. Deferred (per the user's warn-only choice): a hard
executed-probe gate on clean verdicts. Still owed: the empirical re-mine after more hunts to see
whether trust and report strength actually improve.

## v0.4.7 — agentic-execution refinements (metadata honesty, lazy intent corpus)

Answers a review on agentic-execution physics (state / context / metadata). Two of its four points
were sound and are implemented as prose; two were declined after code-checking their premises. No
validator or schema change; suite unchanged at 58/58.

- **Don't guess market volume (the metadata trap).** `target.saturation.discloses_reports` is a
  *structural, verifiable* fact (does the program publish a disclosed-reports feed?) — read from the
  live page or HackerOne MCP. `reports_last_90d` and `hot_cluster` are market dynamics training data
  cannot know — fill them from HackerOne MCP (`GetProgramDisclosedReports`/stats) or leave null,
  never guess. The validator already never required `reports_last_90d`; this closes the prose that
  invited estimating it. (`SKILL.md` step 1, `methodology` §1.)
- **Lazy-load the intent corpus (context starvation).** Read only the cheap, high-signal top-level
  security docs upfront (`SECURITY.md`, README security notes, a `THREAT_MODEL` summary); defer
  voluminous ADRs and the full pragma sweep to the doc relevant to the *promoted hypothesis*
  (step 3), rather than reading everything before any code is read — which starves the context on a
  large target. (`SKILL.md` step 1.)

Declined after checking against the code (recorded so they are not re-litigated):

- **Mechanize the incomplete-fix tiers via file-path distance.** The validator has *no tier gate* to
  game (the tiers are `emerging-surfaces` §2B prose), and the fix is unsound: a Tier-3 finding has
  *no public patch* to measure path-distance from, and path-distance is a weak proxy for a cross-layer
  semantic desync. Kept the prose tiers; `collision_differentiator` remains articulation, not a hard
  gate (acknowledged in v0.4.6).
- **Shard the state file into markdown scratchpads.** The template is 199 lines, not 500, and markdown
  cannot be schema-validated — full sharding would *remove* the exhaustion / intent / subclaim gates
  built in v0.4.3–v0.4.6. Kept the single validated `candidate.json`; targeted-edit tools handle
  mutation. Revisit if real state corruption is observed.

## v0.4.6 — behavioral brakes on the two live loss modes

Answers a research-tight review of v0.4.5 whose central point was correct and code-verified: R1 made
duplicate risk *honest* but not *binding* — `private_duplicate_risk: high` + `distinct` still exited 0,
and the mined losses were labelled high and shipped anyway. Two design forks were chosen jointly (soft
brake, not hard block; targeted field, not broad enum) to avoid regressing the skill's own strengths.
Suite 52 → 58.

- **Collision-differentiator brake (the 23/23 lever, now behavioral).** In a **high-dup context** —
  `private_duplicate_risk: high`, a non-disclosing program, or `target.saturation.hot_cluster` —
  REPORTABLE now requires `novelty.collision_differentiator`: the articulated reason *this* finding is
  low-collision despite the swarm (a Tier-3 cross-layer / no-advisory / bespoke vein). It is a **soft**
  brake, not a hard block on high risk — a hard block would kill the Tier-3 findings that pay on
  swarmed programs (the TFH win) — but it forces the win-vs-dupe distinction the data turns on. (ZH/ZI)
- **Saturation assessment moved to selection time.** `target.saturation.discloses_reports` is now owed
  by the **model stage**, not only at report — dedup visibility is confronted before the deep trace is
  invested. (ZL/ZM)
- **`proof.config_dependency` closes the informative class.** `none | default_only |
  requires_insecure_config`; REPORTABLE requires `none`. A finding that manifests only in a default/dev
  config a real deployment overrides (`default_only`, the Lightspark informative) or needs an insecure
  config no real deployment uses (`requires_insecure_config`, operator-config-as-attacker-input) is
  `HOLD`/`KILL`. A lab-reproduced source-only finding is `none` and unaffected — the targeted field was
  chosen over a broad `deployment_impact` enum precisely to avoid blocking source-only lab proof. (ZJ)
- **Per-subclaim evidence.** A CONFIRMED `cold_verify` now needs a locator (`path:line`, artifact, or
  script output) on each `subclaims[]` link — shrinks pure-prose gaming of the decomposition. (ZK)
- **Honesty caveats (prose).** `methodology` §1 now states the saturation finding is *one hunter's H1
  distribution (n=37), not a universal law* — re-mine for other platforms — and that on a non-disclosing
  program `distinct` means *distinct-from-public-only*; the collision_differentiator, not `distinct`, is
  what carries a high-dup-context finding.

Held the line the data drew (unchanged, not re-litigated): no reframe to "only chase non-obvious," the
incomplete-fix vein stays (re-aimed by the §2B tiers), and no reputation-panic (dupe/informative do not
lower Signal). Still deferred: tool-derived artifacts required in `exhaustion.tried[]` (would false-
negative legitimate source-only-reading clean conclusions); a re-mine after 15–20 new adjudications to
measure whether the dupe rate actually moved.

## v0.4.5 — data-driven selection: the duplicate problem

The first release tuned to the hunter's **real failure distribution** rather than reviews or theory.
Mining 37 adjudicated HackerOne reports (via `GetMyHackerOneReports` + the on-disk writeups and
memory) found **29 of 37 were regrets: 23 duplicate, 6 informative; 2 paid, 6 live** — so the skill
had been hardening against *bad* reports while the actual losses were valid, reproduced, well-scoped
findings that someone else already had. Suite 45 → 48.

The mining was run adversarially and **corrected the leading hypothesis** ("we're not creative
enough"). Findings:

- **Program/cluster saturation, not obviousness, is the dominant duplicate driver (HIGH confidence).**
  All 23 duplicates sat on a marquee/high-volume or *non-disclosing* program where the private pool
  could not be deduped; ~30% were genuinely non-obvious/deep and duped anyway (one was *deliberately
  engineered* orthogonal to a 30-GHSA cluster and still duped). Obviousness (~65%) only amplifies.
- **The private-duplicate pool is invisible on non-disclosing/swarmed programs** — public search
  clean, private pool had it, on every dupe that recorded dedup. The risk was often *predicted at
  submission and submitted anyway*.
- **Incomplete-fix of a fresh, marquee CVE is a duplicate trap.** All 5 fresh-2026-CVE incomplete-fixes
  duped (the embargo crowd swept them); the only live incomplete-fix is of a *2020* CVE on a
  peripheral gem. The skill's own §2A called incomplete-fix "the cheapest fresh-bug source" with no
  dup caveat — the data caught the skill's guidance being net-negative on hot targets.
- **The 2 payouts were a bespoke cross-layer invariant with an in-repo correctness oracle** (a
  nullifier canonicalized at the proof layer but deduped in raw hex at the DB constraint; the same
  repo's v4 path already stored it canonically → provable "oversight, not by-design"). On the *same
  saturated program*, every obvious-class finding duped. Novelty was the tie-breaker within a target.
- **Informatives (5/6) are "real defect, no new attacker capability / no demonstrated real-deployment
  impact"** — gates that already exist but were talked past (the canonical case flagged its own
  disqualifier pre-submit and shipped). The meta-lesson: lessons written to memory are re-learned each
  quarter, not internalized — hence encoding them as *binding* checks.

Changes:

- **R1 — program-saturation / dedup-visibility gate (highest leverage; the 23/23 lever).** New
  `target.saturation` block (`reports_last_90d`, `discloses_reports`, `hot_cluster`), required on a
  schema-5 `REPORTABLE`. A non-disclosing program (`discloses_reports: false` — zero public dedup
  signal) forces `private_duplicate_risk: high`. New "Dedup visibility / saturation ×3" axis in
  `methodology-and-targeting.md` §1 and the data note that saturation, not obviousness, drives dupes;
  `SKILL.md` step 1 records it. Cases ZA-ZC.
- **R2 — incomplete-fix rebalanced on CVE-age × component-saturation** (`emerging-surfaces` §2A/§2B):
  fresh + marquee CVE incomplete-fix carries `private_duplicate_risk: high` by construction — pursue
  only with a *distinct semantic invariant or unaffected asset*; incomplete-fix is EV-positive mainly
  on old CVEs in cold components. The vein is re-aimed, not removed.
- **R3 — informative calibration** (prose, no new gate — the gates exist): FP-pattern 6 in
  `adversarial-self-review.md` sharpened to catch operator/deployer config mis-cast as attacker input
  (the most common informative), and a "Calibration from real informatives" set added to
  `worked-examples.md` (operator-config → `KILL @ capability_delta`; default-config-only →
  `HOLD @ proof`; owned-boundary-no-sink → `KILL @ reachability`).
- **R4 — the winning archetype promoted** in `hypothesis-generation.md`: hunt a cross-layer
  representational mismatch with an in-repo correctness oracle; the mirror-image losing profile is a
  named-class hardening/missing-sibling finding already hedged to Low.
- **R5 — pre-flight** in `platform-operations.md` §0: resolved-count ≠ saturation; read your own
  recent dupes first; non-disclosing → `high` and prefer a disclosing target.
- Also fixed a stale "two candidates" count in `worked-examples.md` itself (four + the calibration set).

What the data said NOT to do (recorded so it is not re-litigated):

- **Do not reframe the skill as "only chase non-obvious."** Target/dedup selection is the lever;
  novelty is the tie-breaker *within* a well-chosen target. An obvious-class finding on a disclosing,
  low-volume program is fine. (This also walks back part of the instinct behind the v0.4.2 creativity
  softening: on a *saturated* target the creativity weight rises toward a gate; on a disclosing one it
  does not.)
- **Do not delete the incomplete-fix / patch-bypass vein** — it is net-negative only on fresh/marquee
  CVEs and still produced a live finding on a cold CVE. Re-aim (R2), don't remove.
- **Do not add reputation-panic language** — duplicate and informative do not lower Signal (only N/A
  does); the cost is wasted effort and free disclosure, so the fix is the *pre-investment* filter, not
  fear at submission.

Deferred: a structured `proof.deployment_impact` enum (`real_managed` required for REPORTABLE) to make
the demonstrated-impact bar checkable for the informative class — the R3 prose + existing gates cover
the calibration for now; revisit if informatives persist.

Pre-release hardening (an independent adversarial code review + a second data-mine of the paying vs.
duping incomplete-fixes; suite 48 → 52):

- **Fixed a blocker in the v0.4.4 commit gate.** It required `commit.invariant` on *every* schema-5
  decision, but a `KILL @ scope` (the most common outcome) dies before an invariant is promoted —
  forcing fabrication. `commit.invariant` is now required only once a model exists; `mode`/`committed_at`
  stay required early, resolving the SKILL "before recon" vs. step-3 contradiction. (case ZD)
- **Closed the silent-reframe bypass.** The reframe check was disabled by any unrelated
  `decision_history` entry; it now requires `commit.superseded_by` specifically. (case ZE)
- **`commit.mode` now earns its place** — diffed against `target.operating_mode` so a silent mode
  switch is rejected; the unused `commit.expected_delta` was dropped per the skill's own anti-cargo-cult
  rule. (case ZF)
- **Non-disclosing program → `private_duplicate_risk` ≥ `medium`** (was: exactly `high`). Forcing
  `high` mis-stamped genuinely-novel findings on legitimate private programs; a bespoke low-collision
  finding may be `medium`. (cases ZB/ZC/ZG)
- **Incomplete-fix variant-character tiers** (`emerging-surfaces` §2B). The v0.4.5 age×saturation rule
  mis-predicted the wins (a fresh, no-CVE bug on a *saturated marquee* program paid $7k). Mining wins
  vs. duped incomplete-fixes found the load-bearing axis is variant *character*: Tier 1 (patch-diff-obvious)
  and Tier 2 (unpatched surface — high-dup even when Critical/PoC'd) dupe; Tier 3 (cross-layer / no-advisory
  desync) can pay even on a swarmed program. Corrected two claims: an in-repo oracle defeats an *Informative*
  close but not *dup* risk (`hypothesis-generation`), and severity/PoC quality were *counter-correlated*
  with paying. The "collision rate > program saturation" nuance (`methodology` §1) answers the swarmed
  landscape: when you cannot out-select saturation, out-create it with a Tier-3 finding.

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
