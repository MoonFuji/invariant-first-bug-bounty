---
name: invariant-first-bug-bounty
description: >-
  Performs evidence-gated security research for bug bounties and coordinated disclosure. Use when selecting or auditing an in-scope source repository, hosted application, API, mobile app, firmware, library, CLI, SDK, AI/LLM/MCP system, or when validating, routing, deduplicating, scoring, or writing a vulnerability report for HackerOne, Bugcrowd, Intigriti, YesWeHack, huntr, an upstream advisory, or the Internet Bug Bounty.
---

# Invariant-First Bug Bounty

## Core principle

Model one security invariant before searching for violations. Trace it through the real entrypoint, validation, authorization, state transition, persistence, and observable effect. Prefer one complete causal trace over many grep hits.

The task does not require a finding. `HOLD`, `KILL`, `ROUTE_ELSEWHERE`, and `NO_REPORTABLE_FINDING` are successful outcomes when supported by evidence.

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
- each `novelty.checks[]` carries `evidence: {method, query, artifact}`, required for every `checked`/`no_match` result once `classification` is `distinct`; the `upstream_history` check carries a `channels` array covering `commits`, `issues`, and `pull_requests`, each with its own executed-search `evidence`. A closest match whose `fingerprint` equals `root_cause_fingerprint`, or any match flagged `establishes_by_design`, blocks `distinct`/`REPORTABLE`. Legacy schema-3 candidates still validate at non-report stages; migrate a candidate to schema 4 before a REPORTABLE report.

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

1. **Verify target, mode, and route.** Record the operating mode, exact program, asset, repository, commit/release, scope evidence, bounty eligibility, and when scope was checked. Identify the project that owns the vulnerable code and would ship the fix.
2. **Build the security model.** Record principals, protected assets, trust boundaries, state stores, enforcement points, and one invariant. Read selectively until these are concrete; grep output is not a model.
3. **Test relevance, then trace.** State a provisional security boundary and plausible new capability. If no meaningful capability change is possible, stop early. Otherwise follow untrusted input through validation/canonicalization, authorization, mutation/read, persistence or external effect, and at least one safe or parallel sibling.
4. **Find the capability delta.** State what the test principal can do before and after the complete trace. Equal capabilities mean no security impact.
5. **Attempt the strongest refutation.** Test the best benign explanation: intended sharing, attacker already controls the secret/config/peer, production hardening, safe caller contract, unreachable event shape, or downstream misuse. An unresolved refutation means `HOLD`; a confirmed refutation means `KILL` or honest downgrade. **Terminal refutations cannot be waved past.** If the best benign explanation is any of these, the verdict is `KILL @ refutation` (or `KILL @ capability_delta`) regardless of how clean the reproduction is: (a) the input is developer/operator-controlled configuration at the owned boundary, not attacker input (the component is not the authorization policy); (b) the new capability requires a precondition the attacker does not already hold and the owned boundary does not grant; (c) the effect only appears when a *third party* misuses the component, so the fix is defense-in-depth in the dependency, not a vulnerability in the owned code. Finding an integrator who misuses the component does **not** move the owned boundary and does **not** refute (a)–(c). You may not set `refutation_result: "refuted"` on a terminal refutation to proceed to `REPORTABLE`; write it into `strongest_refutation` and stop.
6. **Prove the exact boundary.** Use the proof type the destination accepts. Capture an observable side effect and negative controls, not only a status code, callback, code trace, or fabricated impossible input.
7. **Route before reporting.** Verify that the destination owns the faulty code and accepts this proof class. A real bug in a dependency may require an upstream advisory rather than the product's bounty program.
8. **Measure contestability.** Fingerprint the root cause as `boundary|primitive|invariant|effect`; record a query and outcome for your own reports, program disclosures, upstream history, and recent advisories. Select one globally closest known match and compare all four fingerprint axes.
9. **Decide and persist.** Set exactly one terminal verdict and `decision.gate` in `candidate.json`, name failed gates or missing evidence, then run `--stage decision`.

## Depth contract

Do not rotate merely to make a hunt look broad. Continue while the selected invariant has untraced enforcement points or meaningful siblings. Rotate only when the primitive is absent, the trace is complete and safe, the route is dead, or contestability makes the expected value poor.

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

## Proof and routing matrix

| Asset/destination | Minimum persuasive proof |
|---|---|
| Hosted product/API | In `PROGRAM_HOSTED` only: owned accounts or owned instance; comparison-account marker/state change plus anonymous/nonexistent controls where relevant |
| Source-code program | Exact executable path using shipped behavior; prove production relevance and confirm the program accepts local/source proof |
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

## Rationalizations to reject

| Rationalization | Required response |
|---|---|
| “The primitive is obviously dangerous.” | Show the attacker capability delta and owned boundary. |
| “The local PoC works.” | Prove the event/config/caller exists in the accepted threat model. |
| “Public search is clean.” | Record private-duplicate risk and the semantic delta from nearby work. |
| “Another frontier model confirmed it.” | Treat agreement as prioritization; require an independent artifact. |
| “The novelty window may close.” | Scarcity never lowers proof, ownership, or routing gates. |
| “I will draft now and validate later.” | Stop. Report-stage validation must pass before drafting. |
| “I can edit the candidate until it passes.” | Add evidence, not assertions. Preserve earlier failed gates and decision history in the same artifact. |
| “But a real integrator forwards untrusted input into this.” | Their missing validation is the bug; the owned boundary treats this input as trusted config. Terminal refutation → `KILL`. |
| “I marked the refutation `refuted`, so it's cleared.” | Only non-terminal refutations clear. Intended-usage / owned-boundary / attacker-already-holds-precondition refutations are `KILL`, not `refuted`. |
| “I checked `git log`, so it's novel.” | `git log` misses live PRs and closed by-design issues. Run the issue/PR search + current-branch check and paste the output, or the verdict caps at `HOLD @ novelty`. |

## References and tools

| Resource | Load or run when |
|---|---|
| `references/methodology-and-targeting.md` | Target/route selection, invariant modeling, contestability, proof standards, CVSS, report template |
| `references/bug-class-taxonomy.md` | After choosing an invariant, for relevant source/sink and confirmation patterns |
| `references/grey-box-dynamic-testing.md` | Live instance, two-account identity diff, control tests, safe-harbor proof |
| `references/emerging-surfaces-and-techniques.md` | The architecture exposes AI/MCP, CI/CD, supply-chain, cloud, auth, or parser boundaries |
| `references/platform-operations.md` | Before testing/submitting: scope, platform, KYC, payout, safe-harbor |
| `assets/candidate.template.json` | Start every candidate and persist cross-session decisions |
| `scripts/validate-candidate.py` | Enforce model, terminal-decision, and report readiness |
| `scripts/recon-sweep.sh` | Secondary, model-gated coverage and variant discovery |

Stay within program scope and safe harbor. Use owned accounts/data, local clones, and the least harmful proof that establishes the boundary. Never use exposed credentials or pivot into third-party systems.
