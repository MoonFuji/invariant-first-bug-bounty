---
name: invariant-first-bug-bounty
description: >-
  Performs evidence-gated security research for bug bounties and coordinated disclosure. Use when selecting or auditing an in-scope source repository, hosted application, API, mobile app, firmware, library, CLI, SDK, AI/LLM/MCP system, or when validating, routing, deduplicating, scoring, or writing a vulnerability report for HackerOne, Bugcrowd, Intigriti, YesWeHack, huntr, an upstream advisory, or the Internet Bug Bounty. Not for general code review, feature development, refactoring, or test-writing — only authorized security-vulnerability research and disclosure.
---

# Invariant-First Bug Bounty

## Core principle

Model one security invariant before searching for violations. Trace it through the real entrypoint, validation, authorization, state transition, persistence, and observable effect. Prefer one complete causal trace over many grep hits.

The task does not require a finding. `HOLD`, `KILL`, `ROUTE_ELSEWHERE`, and `NO_REPORTABLE_FINDING` are successful outcomes when supported by evidence **and reached after exhausting the investigation** — never when reached by stopping early. Restraint means not over-claiming; it is not permission to under-investigate (see "Exhaust before you conclude").

## Commit before you hunt

State out loud, and write into `candidate.json`, three things before recon: the operating mode, the one security invariant you will test, and the specific capability delta you expect an attacker to gain. State the terminal verdict and `decision.gate` out loud at the end. Announcing them commits you: an abandoned invariant or a silent slide from `HOLD` toward `REPORTABLE` becomes visible instead of quiet. You do not get to change a declared verdict without appending to `decision_history` and saying why.

## Exhaust before you conclude

The gates in this skill stop you from over-claiming. They are not permission to under-invest. Long-horizon agents fail *quietly*: they settle on a reading early and defend it, overestimate how much they have done, and terminate before the work is finished. A `HOLD`, `KILL`, or `NO_REPORTABLE_FINDING` reached by stopping early is that failure wearing restraint's clothes — so concluding costs the same evidence as reporting.

- **Hard is not dead.** Rotate off an invariant only when it is proven dead (primitive absent, trace complete and safe, route dead), never because it is difficult. "This is fiddly / would take more hours" describes the work; it is not a reason to quit it.
- **A wall is a redirect, not an exit.** When a trace dead-ends, pivot to another sink, hypothesis, or transport from the queue and keep going. Uncertainty is a cue to investigate, not to hand back.
- **The hard proof is the job.** Building the exact shipped path, standing up the real instance, tracing the fifth sibling — that is the work, not an optional extra. The easy substitute chosen to avoid it is both a false proof and a dodge.
- **Give-up is a claim; prove it.** To stop, record what you tried, what remains untried, and why each closed avenue is genuinely dead. "I did enough" is not a verdict; the documented exhaustion is.

**Hustle toward the truth, not toward a report.** Spend maximum effort reaching ground truth — a real finding *or* a genuinely clean result — and let the gates keep whatever you find honest. The two never conflict: you grind to prove or disprove, and you never let the grind become a reason to over-claim.

## Think like an attacker, act within scope

Read the target the way a determined attacker would, not the way a checklist would. Assume the system *can* be broken and hunt for how: chain low-severity issues into high-severity ones, weaponize intended features, feed the input nobody validates, take the path the designers assumed no one would. The findings that pay and survive dedup are the ones a scanner and a cautious reviewer both miss — so be creative, lateral, and relentless in generating and chasing hypotheses (`references/hypothesis-generation.md`), and be resourceful in proof: build the exact executable, stand up the environment, reverse the binary, diff the patch, read the closed issues and the project's own security vocabulary.

Two boundaries, held in opposite hands:

- **Toward the target: unbounded imagination.** No idea is too devious to *consider*; the threat model has no ceiling. This is where the "figure it out" instinct belongs — spend it here without limit.
- **Toward yourself: absolute discipline.** Scope, safe-harbor, and your own sandbox are lines you never cross. Reason about breaking the target; only *act* within the authorization you actually hold (Operating mode). Reaching out of scope, using a found credential, or touching an unauthorized system is not brilliance — it is the finding thrown away and the researcher exposed.

And aim the ingenuity at the **truth, not the score**. Never game the objective: a fabricated PoC, an out-of-scope "win", or a bug claimed but not proven satisfies a metric while defeating the point — the same failure as a system that cheats a benchmark instead of solving it. The cleverest shortcut to a passing result is still a failure if it did not do the work. Spend the creativity on finding and *proving* what is real.

## Operating mode

Declare one mode before investigation. Store it in `target.operating_mode` and record its authorization basis in `target.scope_evidence`:

- **`SOURCE_ONLY` (default):** inspect the repository and public documentation; build and run code locally; use local fixtures, containers, accounts, listeners, and test data. Do not send validation traffic to production or third-party systems, use discovered credentials, access another person's data, or extend access beyond the controlled environment.
- **`PROGRAM_HOSTED`:** interact only with the exact hosted assets, accounts, data, methods, and rates explicitly permitted by current program rules. Use accounts and data you own. A repository being public or listed in scope does not by itself authorize hosted testing.

Reason about realistic consequences in either mode, but execute only actions permitted by the declared mode. When authorization is unclear, remain in `SOURCE_ONLY` or set `HOLD`; do not infer permission.

## Validation hierarchy

Use the least-impact artifact that conclusively establishes the security boundary:

1. Complete static source trace.
2. Focused unit or regression test.
3. Isolated local process.
4. Disposable local container.
5. Researcher-owned self-hosted deployment.
6. Program-hosted owned account or instance, only in `PROGRAM_HOSTED` when explicitly authorized.

Do not advance when a lower-impact level already establishes the capability delta required by the destination. Reproduce sensitive effects with controlled equivalents: unique canaries instead of real secrets, benign files instead of system data, and local listeners instead of third-party or privileged services.

## Mandatory candidate state

Persist every candidate outside the conversation so later sessions cannot silently override a failed gate:

```bash
cp assets/candidate.template.json <hunt-dir>/candidate.json
python scripts/validate-candidate.py --stage model <hunt-dir>/candidate.json
```

Fill `target` and `model` before broad recon. Update the same file as evidence changes; do not create a cleaner replacement that omits an earlier failed gate.

**Schema 4 (v0.3.1) — two blocks are structured, not free text:**

- `threat_model.strongest_refutation` is an object `{claim, kind, evidence, resolution, resolution_source, result}`. `kind` is `non_terminal` for an ordinary counter-argument, or a terminal kind: `owned_boundary_absent`, `capability_already_possessed`, `required_precondition_already_grants_effect`, `behavior_is_documented_contract`, `target_does_not_own_security_property`, `unreachable_under_supported_contract`. A terminal kind can never be `result: "refuted"` and can never reach `REPORTABLE` — if target-owned evidence genuinely defeats the objection, the honest `kind` is `non_terminal`. `REPORTABLE` additionally requires a non-empty `resolution` (the target-owned finding that defeats the claim), non-empty `evidence` (an independent artifact for it), and `resolution_source: "target_owned"`. A third party misusing the component is `resolution_source: "third_party"` and never clears the gate.
- each `novelty.checks[]` carries `evidence: {method, query, artifact}`, required for every `checked`/`no_match` result once `classification` is `distinct`; the `upstream_history` check carries a `channels` array covering `commits`, `issues`, and `pull_requests`, each with its own executed-search `evidence`. On a `github.com/` repository, `issues` and `pull_requests` cannot be `unavailable` to reach `distinct`: an `unavailable` GitHub issue/PR channel must carry an attempted-search artifact (it means tried-and-failed, e.g. an API error), and it never counts as coverage — so a real search is required. A closest match whose `fingerprint` equals `root_cause_fingerprint`, or any match flagged `establishes_by_design`, blocks `distinct`/`REPORTABLE`.
- `novelty.current_upstream_state` (`{ref, checked_at, path, result, evidence}`) records whether the current default branch still carries the flaw. `distinct` requires `result: "vulnerable"` with a fetch artifact; `fixed` forbids `distinct` (the old checkout is stale — `KILL @ novelty` or route as historical/advisory); `unavailable` caps the verdict at `HOLD @ novelty`.
- a confirmed terminal refutation must land at the gate its `kind` implies (`TERMINAL_KIND_GATES`): e.g. `capability_already_possessed` → `KILL @ capability_delta`, `behavior_is_documented_contract` → `KILL @ refutation`, `target_does_not_own_security_property` → `KILL/ROUTE_ELSEWHERE @ ownership|route`.

**Schema 5 (v0.4.0) — process evidence for ideation and self-review.** Adds five optional blocks: `hypothesis_queue` (ranked ideas, each with a `creativity_signal`), `intent_corpus` (quoted `intentional_behaviors`/`acknowledged_risks` with a `finding_match`), `adversarial_review` (`advocate` with the eight FP-pattern hits, `cold_verify` verdict, and the `causal` challenge results), `variant_sweep` (flow shape, siblings and alternate transports checked, variants found), and `patch_bypass` (the seven bypass vectors against a known fix). At `REPORTABLE`, a schema-5 candidate additionally requires `intent_corpus.finding_match != "intentional"`, `adversarial_review.cold_verify.verdict == "CONFIRMED"`, and a written `rebuttal` for every `advocate.fp_pattern_hits[]` entry.

Legacy schema-3/4 candidates still validate at non-report stages; migrate a candidate to schema 5 before a REPORTABLE report so the ideation and self-review gates apply.

After setting any terminal verdict, validate the evidence accumulated through its terminal gate:

```bash
python scripts/validate-candidate.py --stage decision <hunt-dir>/candidate.json
```

Before changing a prior verdict, append its decision object to `decision_history` with the evidence that changed it. Never delete history entries.

Before writing any submission-ready report, run:

```bash
python scripts/validate-candidate.py --stage report <hunt-dir>/candidate.json
```

**A nonzero exit forbids report drafting.** Do not rewrite uncertain claims merely to satisfy the validator. Collect the named evidence, change the route, or keep the non-reportable verdict.

## Workflow

1. **Verify target, mode, and route.** Record the operating mode, exact program, asset, repository, commit/release, scope evidence, bounty eligibility, and when scope was checked. A listed or public repository is not proof the exact asset is bounty-eligible or that source-only proof is accepted — verify eligibility and the PoC policy live before investing, since some programs auto-N/A source-only analysis (`references/platform-operations.md` §0). Identify the project that owns the vulnerable code and would ship the fix. Build a small **intent corpus**: read `SECURITY.md`, `THREAT_MODEL`, ADRs, `CONTRIBUTING`, README security notes, and inline `# nosec` / `# SECURITY:` pragmas, and quote (never paraphrase) two lists into `candidate.json.intent_corpus` — `intentional_behaviors` (what the project explicitly calls by-design / not-a-vuln / out-of-scope / accepted-risk) and `acknowledged_risks` (classes it explicitly treats as in-scope). A finding matching an intentional_behavior is `KILL @ refutation` (`behavior_is_documented_contract`); one matching an acknowledged_risk is strengthened. Do not infer from absence.
2. **Build the security model.** Record principals, protected assets, trust boundaries, state stores, enforcement points, and one invariant. Read selectively until these are concrete; grep output is not a model.
3. **Generate hypotheses before committing the invariant (bounded).** On a large or unfamiliar target where the highest-value invariant is not obvious, run one ideation pass (`references/hypothesis-generation.md`): cycle the attack modes, run a pre-mortem specific to this system, and ask of every defensive construct "what did the author fear?" Each hypothesis carries a **creativity signal** — one line on why a scanner would miss it; discard any that lacks one. This yields a ranked queue in `candidate.json.hypothesis_queue`, not candidates. Promote exactly one to the invariant and continue; keep the rest as the reinvestment queue. Skip this step when the invariant is already obvious from step 2.
4. **Test relevance, then trace.** State a provisional security boundary and plausible new capability. If no meaningful capability change is possible, stop early. Otherwise follow untrusted input through validation/canonicalization, authorization, mutation/read, persistence or external effect, and at least one safe or parallel sibling. When source code is used by a managed product, separately trace the product-facing input through control-plane validation, storage, serialization, and runtime configuration; product documentation proves that a field exists, not that an attacker-controlled representation reaches the cited code unchanged. Re-trace source provenance for every sibling effect; similar sinks do not inherit attacker control from the original path.
5. **Find the capability delta.** State what the test principal can do before and after the complete trace. Equal capabilities mean no security impact. For filesystem or process claims, record the exact runtime principal and permissions at the sink: path selection is not permission bypass, and a later privileged helper does not elevate an earlier operation.
6. **Attempt the strongest refutation.** Test the best benign explanation: intended sharing, attacker already controls the secret/config/peer, production hardening, safe caller contract, unreachable event shape, or downstream misuse. Treat “compromised backend,” “leaked privileged credential,” and “MITM under weak configuration” as unevidenced preconditions until a target-owned path or policy establishes a less-trusted actor who can reach them. An unresolved refutation means `HOLD`; a confirmed refutation means `KILL` or honest downgrade. **Terminal refutations cannot be waved past.** If the best benign explanation is any of these, the verdict is `KILL @ refutation` (or `KILL @ capability_delta`) regardless of how clean the reproduction is: (a) the input is developer/operator-controlled configuration at the owned boundary, not attacker input (the component is not the authorization policy); (b) the new capability requires a precondition the attacker does not already hold and the owned boundary does not grant; (c) the effect only appears when a *third party* misuses the component, so the fix is defense-in-depth in the dependency, not a vulnerability in the owned code. Finding an integrator who misuses the component does **not** move the owned boundary and does **not** refute (a)–(c). You may not set `refutation_result: "refuted"` on a terminal refutation to proceed to `REPORTABLE`; write it into `strongest_refutation` and stop.
7. **Adversarial self-review (role rotation, single agent).** Before proof, run the three-role rotation in `references/adversarial-self-review.md` against your own finding, writing each role's output before reading the next: as **Advocate**, build the strongest defense across all five protection layers and check the eight false-positive patterns; as **Cold verifier**, restate the claim from scratch without re-reading your trace, re-derive severity from MEDIUM, and reject the five rationalizations; as **Causal challenger**, run intervention/counterfactual/confounder on every protection you rely on. This pass can only lower confidence or set `KILL`; it never clears the `refutation` or `novelty` gates. Write the result into `candidate.json.adversarial_review`.
8. **Prove the exact boundary.** Distinguish three claims: the primitive works, the exact shipped executable path works, and the program-owned deployment is reachable. A substitute client/runtime or helper that copies the cited lines clears only the first claim. Use the real method/entrypoint, exact pinned binary, generated invocation, and shipped configuration for the second; trace the accepted external input into that invocation for the third. Capture an observable side effect, version and command/config artifacts, exit status, and a negative control. A side effect completed before a later fixture failure may still prove the narrow effect, but disclose the failure and never describe the whole workflow as successful.
9. **Route before reporting.** Verify that the destination owns the faulty code and accepts this proof class. A real bug in a dependency may require an upstream advisory rather than the product's bounty program.
10. **Measure contestability.** Fingerprint the root cause as `boundary|primitive|invariant|effect`; record a query and outcome for your own reports, program disclosures, upstream history, and recent advisories. Select one globally closest known match and compare all four fingerprint axes.
11. **Decide and persist.** Set exactly one terminal verdict and `decision.gate` in `candidate.json`, name failed gates or missing evidence, then run `--stage decision`.

Copy this checklist into your working notes and check off each gate only when an artifact in `candidate.json` backs it — never tick a box you cannot defend:

```
- [ ] 1.  Target, mode, route, intent corpus recorded ............ scope
- [ ] 2.  Security model + one declared invariant ............... model
- [ ] 3.  Hypotheses generated, one promoted (creativity signal). (ideation)
- [ ] 4.  Relevance tested; source-to-effect trace complete ..... relevance/reachability
- [ ] 5.  Capability delta stated: before ≠ after ............... capability_delta
- [ ] 6.  Strongest refutation attempted and resolved ........... refutation
- [ ] 7.  Adversarial self-review: advocate + cold-verify + causal (refutation)
- [ ] 8.  Exact shipped-path proof + negative control captured .. proof
- [ ] 9.  Route ownership verified .............................. route/ownership
- [ ] 10. Root-cause fingerprint + novelty search → distinct .... novelty
- [ ] 11. One terminal verdict + gate persisted; validator run .. reportability
```

## Depth contract

Do not rotate merely to make a hunt look broad. Continue while the selected invariant has untraced enforcement points or meaningful siblings. Rotate only when the primitive is absent, the trace is complete and safe, the route is dead, or contestability makes the expected value poor. Difficulty is never a rotation trigger: rotate on proof of death, not on how hard or slow the trace is.

Before claiming a repository is clean for an invariant, record:

- The entrypoint and attacker-controlled value.
- The intended invariant and authoritative enforcement point.
- The complete source-to-effect trace.
- At least one sibling or alternate version checked.
- The strongest attempted counterexample and why it failed.

Broad sink recon is a secondary coverage tool. Run it only after model validation:

```bash
bash scripts/recon-sweep.sh --candidate <hunt-dir>/candidate.json <repo-dir> [output-dir]
```

Never promote a regex hit directly to a candidate. Attach it to an invariant and complete the trace first.

**Variant sweep on any confirmed root cause.** The moment a trace confirms a violation, before writing the report, sweep for the same root cause (not the same syntax): (a) grep the exact flow shape `source-type → transform → sink-type` repo-wide; (b) check sibling components sharing the trust boundary, data-flow pattern, framework idiom, or dependency; (c) check **alternate transports** for the same logic — HTTP, WebSocket, gRPC, GraphQL resolvers, CLI subcommands, and queue/cron consumers. Each variant is its own candidate with its own trace; a variant does not inherit the original's proof. Record the sweep in `candidate.json.variant_sweep` even when it finds nothing — an unsearched sweep is a second submission left on the table. Prioritize the highest-likelihood siblings and record confirmed variants as their own candidates rather than fully tracing every one in this pass; a representative sweep of the most probable siblings is enough to move on. Stop widening when the abstraction ladder's false-positive rate climbs (`references/emerging-surfaces-and-techniques.md` §2C) — do not chase every superficially similar endpoint.

## Proof and routing matrix

| Asset/destination | Minimum persuasive proof |
|---|---|
| Hosted product/API | In `PROGRAM_HOSTED` only: owned accounts or owned instance; comparison-account marker/state change plus anonymous/nonexistent controls where relevant |
| Source-code program | Exact pinned executable and generated invocation using shipped behavior; if claiming managed-product impact, trace the external input through platform validation/configuration into that invocation; confirm the program accepts local/source proof |
| Library/SDK/upstream | Executable regression test, realistic caller contract, and usually maintainer fix/advisory/CVE for upstream routing |
| Parser/CLI/firmware/hardware | Executable artifact on the real parser/runtime/device or an exact enforcement model accepted by the destination |
| AI/agent/MCP | Authentic reachable event/tool path and consequential side effect; fabricated model/service output alone is insufficient |

Read `references/grey-box-dynamic-testing.md` when a live instance exists. Read `references/methodology-and-targeting.md` for route selection, contestability, proof details, severity, and report structure.

## Duplicate-risk protocol

When HackerOne MCP is available, begin with your own outcomes, then search the target:

1. `mcp__hackerone__GetMyHackerOneReports` — extract root-cause fingerprints from duplicates and valid reports.
2. `mcp__hackerone__GetProgramDisclosedReports` — inspect the program's disclosed component/class history.
3. `mcp__hackerone__SearchDisclosedReports` — search the invariant, component, primitive, and effect across programs.
4. `mcp__hackerone__GetHackerOneReportByID` — open close matches instead of comparing titles only.
5. Check GHSA/CVE, changelog, branches, releases, and `git log -p` for the exact enforcement path.
6. **Search the owning repo's open AND closed issues/PRs — this is mandatory, not prose.** `git log` and advisories are not a substitute: a live PR or a closed "by-design" issue is invisible to them. Run and paste the actual output (commands + hit URLs) into the candidate, e.g. `gh pr list --repo <owner/repo> --state all --search "<class terms>"` and `gh search issues --repo <owner/repo> "<invariant/component terms>"`. A closed issue that requests the *opposite* of your fix (users wanting the current behavior) is by-design evidence and downgrades the finding.
7. **Confirm the current default branch is still vulnerable** before claiming `distinct`: fetch the exact line on `main`/`master` (`gh api repos/<owner/repo>/contents/<path>`), or the finding may already be fixed upstream.

For each source, persist the query, check time, and one result: `checked` with its closest match, `no_match`, or `unavailable` with a reason. `no_match` on the issue/PR and current-branch sources (6–7) requires the pasted command/URL that produced it — a prose `no_match` without an executed-search artifact is treated as **not searched**, which forbids `distinct` and caps the verdict at `HOLD @ novelty`. Do not use an empty array to blur “not searched” into “no result.” Rank the retrieved matches, store one `closest_known_match`, compare its boundary, primitive, invariant, and effect, then set `novelty.classification` to `duplicate`, `distinct`, or `uncertain`.

No public match is weak evidence, not proof of novelty; private duplicate pools remain invisible. A recent advisory or famous component raises contestability. `REPORTABLE` requires `distinct`; a known matching root cause is `KILL @ novelty`; unresolved comparison evidence is `HOLD @ novelty`.

Cross-model agreement is hypothesis prioritization, not validation. Models share training data, public advisories, and prompt framing. Only independent artifacts can clear a gate.

## Terminal verdicts

| Verdict | Meaning |
|---|---|
| `REPORTABLE` | Every report-stage field is evidenced and the validator passes |
| `HOLD` | The invariant violation is plausible, but named proof, threat-model, route, or novelty evidence is missing |
| `KILL` | A gate is disproven, impact is unchanged, the behavior is intended, or the candidate is covered/fixed |
| `ROUTE_ELSEWHERE` | The bug may be real, but another project or disclosure rail owns the fix |
| `NO_REPORTABLE_FINDING` | The investigated invariant held after a complete trace and refutation attempt |

`decision.gate` records where research ended: `scope`, `route`, `model`, `relevance`, `reachability`, `capability_delta`, `refutation`, `proof`, `ownership`, `novelty`, or `reportability`. `HOLD` requires completed prerequisite evidence plus the specific missing item. `KILL` requires evidence through the failed gate, not fabricated downstream fields. `ROUTE_ELSEWHERE` requires verified ownership and routing evidence. Full trace, proof, route, and novelty evidence remain mandatory for `REPORTABLE`; a complete trace and refutation remain mandatory for `NO_REPORTABLE_FINDING`.

## Red flags — STOP

These are the symptoms of an about-to-fail moment. The instant you notice yourself doing any of them, stop and return to the named gate — the urge itself is the signal that the discipline is being skipped:

- Opening a report draft or writing a summary before `--stage report` exited 0. → run the validator first; a nonzero exit forbids drafting.
- Naming an impact you have not reproduced — cloud secrets, cross-tenant data, RCE, "P1". → claim only the captured effect at the `capability_delta` gate.
- Reaching for a substitute client, copied lines, or a helper "because the real path is fiddly." → that is primitive evidence only; the `proof` gate needs the exact shipped executable path.
- Editing a `candidate.json` field to make the validator pass instead of collecting the evidence it names. → add evidence, not assertions; preserve the failed gate.
- Marking a refutation `refuted`, or relabeling a terminal kind as `non_terminal`, so you can proceed. → write it into `strongest_refutation` and take the `KILL`.
- Calling a repository clean without the five Depth-contract records. → you have skimmed, not looked; produce the entrypoint, invariant, trace, sibling, and defeated counterexample.
- Treating another model's agreement, a CVE precedent, a famous component, or a closing novelty window as if it cleared a gate. → none of them clear a gate; only an independent artifact does.
- Feeling the pull to submit *because* rent is due, hours are sunk, or the program "clearly wants a finding." → pressure is not evidence; it is the exact condition under which the gates must hold.

If you cannot proceed without doing one of these, the honest verdict is `HOLD` with the missing evidence named — that is a success, not a failure.

## Red flags — KEEP GOING

The mirror of the flags above. These are the symptoms of quitting too soon; a verifier-driven early exit is a measured failure mode, not diligence. Noticing any means the work is not done — do not stop:

- Concluding "clean" or "no findings" after reading a handful of files, without the five Depth-contract records. → you skimmed; produce them.
- Rotating off a target because it is hard, slow, or unfamiliar rather than proven dead. → hard is not dead.
- Reaching for the easy substitute PoC, or a "theoretical" impact, to avoid building the real path. → build the real path.
- Saying "no meaningful capability change" without having traced. → trace first, then judge.
- Stopping at the first `HOLD` instead of collecting the evidence it names. → the `HOLD` is your next task, not the exit.
- Reading "the gates let me stop" as "I should stop." → the gates cap over-claiming, not effort.

Concluding is a claim like any other: it needs the documented exhaustion, not "I did enough."

## Rationalizations to reject

| Rationalization | Required response |
|---|---|
| “The primitive is obviously dangerous.” | Show the attacker capability delta and owned boundary. |
| “The local PoC works.” | Prove the event/config/caller exists in the accepted threat model. |
| “A compatible substitute client reproduced it.” | Treat that as primitive evidence only; run the exact pinned executable through the product-generated invocation. |
| “I copied the vulnerable lines verbatim into the PoC.” | That proves language/library semantics, not the target path. Invoke the real method or entrypoint with its actual surrounding controls. |
| “The product docs expose the same field.” | Docs anchor the surface, not byte-level reachability. Trace validation, storage, serialization, and runtime delivery of the exact representation. |
| “The canary file was read, so cloud secrets and cross-tenant data are P1.” | Claim only the reproduced file-read effect. Stronger assets and severity require evidence that the managed boundary is reachable and target-owned sensitive data is exposed. |
| “The path escapes the root, so this is arbitrary write and RCE.” | Path control is not a permission bypass. Prove the runtime principal can write the chosen target and that the written artifact reaches an execution trigger. |
| “A later step invokes `sudo`, so the whole workflow is privileged.” | Privilege is operation-specific. Trace the exact privileged command, arguments, policy, and whether it applies to the claimed sink. |
| “The same join appears in cleanup, so delete is attacker-controlled too.” | Re-trace that sibling's source. A similar sink with locally generated state does not inherit taint from a manifest or request. |
| “Other products assigned a CVE to this class.” | Precedent shows plausibility, not this target's actor, trust contract, reachability, or impact. Clear those gates independently. |
| “Public search is clean.” | Record private-duplicate risk and the semantic delta from nearby work. |
| “Another frontier model confirmed it.” | Treat agreement as prioritization; require an independent artifact. |
| “The novelty window may close.” | Scarcity never lowers proof, ownership, or routing gates. |
| “I will draft now and validate later.” | Stop. Report-stage validation must pass before drafting. |
| “I can edit the candidate until it passes.” | Add evidence, not assertions. Preserve earlier failed gates and decision history in the same artifact. |
| “But a real integrator forwards untrusted input into this.” | Their missing validation is the bug; the owned boundary treats this input as trusted config. Terminal refutation → `KILL`. |
| “I marked the refutation `refuted`, so it's cleared.” | Only non-terminal refutations clear. Intended-usage / owned-boundary / attacker-already-holds-precondition refutations are `KILL`, not `refuted`. |
| “I checked `git log`, so it's novel.” | `git log` misses live PRs and closed by-design issues. Run the issue/PR search + current-branch check and paste the output, or the verdict caps at `HOLD @ novelty`. |
| “A tool or another agent already marked it VALID.” | That is consensus, not evidence. The hypothesis owes the same trace, capability-delta, refutation, and novelty gates as any other. |
| “I generated many hypotheses, so coverage is good.” | Volume is not depth. Rank by creativity signal, promote one, and complete its trace before spawning the next. |
| “The fix commit exists, so this class is handled.” | A fix can be partial. Run the 7-vector bypass check and the sibling sweep against the *patched* path before calling it dead. |

## References and tools

| Resource | Load or run when |
|---|---|
| `references/methodology-and-targeting.md` | Target/route selection, invariant modeling, contestability, proof standards, CVSS, report template |
| `references/hypothesis-generation.md` | Large/unfamiliar target where the highest-value invariant is not obvious — attack modes, pre-mortem, TRIZ, adaptive-attacker ideation |
| `references/adversarial-self-review.md` | Before proof — Advocate (8 FP patterns) / Cold-verifier / Causal-challenger role rotation against your own finding |
| `references/worked-examples.md` | Need a concrete pattern — four candidates walked to a terminal verdict (`KILL @ refutation`, `REPORTABLE`, `HOLD @ proof`, `ROUTE_ELSEWHERE @ route`) with decisive fields |
| `references/bug-class-taxonomy.md` | After choosing an invariant, for relevant source/sink and confirmation patterns |
| `references/grey-box-dynamic-testing.md` | Live instance, two-account identity diff, control tests, safe-harbor proof |
| `references/emerging-surfaces-and-techniques.md` | The architecture exposes AI/MCP, CI/CD, supply-chain, cloud, auth, or parser boundaries |
| `references/platform-operations.md` | Before testing/submitting: scope, platform, KYC, payout, safe-harbor |
| `assets/candidate.template.json` | Start every candidate and persist cross-session decisions |
| `scripts/validate-candidate.py` | Enforce model, terminal-decision, and report readiness |
| `scripts/recon-sweep.sh` | Secondary, model-gated coverage and variant discovery |

Stay within program scope and safe harbor. Use owned accounts/data, local clones, and the least harmful proof that establishes the boundary. Never use exposed credentials or pivot into third-party systems.
