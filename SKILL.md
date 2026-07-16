---
name: invariant-first-bug-bounty
description: >-
  Performs evidence-gated security research for bug bounties and coordinated disclosure. Use when selecting or auditing an in-scope source repository, hosted application, API, mobile app, firmware, library, CLI, SDK, AI/LLM/MCP system, or when validating, routing, deduplicating, scoring, or writing a vulnerability report for HackerOne, Bugcrowd, Intigriti, YesWeHack, huntr, an upstream advisory, or the Internet Bug Bounty.
---

# Invariant-First Bug Bounty

## Core principle

Model one security invariant before searching for violations. Trace it through the real entrypoint, validation, authorization, state transition, persistence, and observable effect. Prefer one complete causal trace over many grep hits.

The task does not require a finding. `HOLD`, `KILL`, `ROUTE_ELSEWHERE`, and `NO_REPORTABLE_FINDING` are successful outcomes when supported by evidence.

## Mandatory candidate state

Persist every candidate outside the conversation so later sessions cannot silently override a failed gate:

```bash
cp assets/candidate.template.json <hunt-dir>/candidate.json
python scripts/validate-candidate.py --stage model <hunt-dir>/candidate.json
```

Fill `target` and `model` before broad recon. Update the same file as evidence changes; do not create a cleaner replacement that omits an earlier failed gate.

After setting any terminal verdict, validate the completed trace:

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

1. **Verify target and route.** Record the exact program, asset, repository, commit/release, scope evidence, bounty eligibility, and when scope was checked. Identify the project that owns the vulnerable code and would ship the fix.
2. **Build the security model.** Record principals, protected assets, trust boundaries, state stores, enforcement points, and one invariant. Read selectively until these are concrete; grep output is not a model.
3. **Trace the invariant.** Follow attacker input through validation/canonicalization, authorization, mutation/read, persistence or external effect, and at least one safe or parallel sibling.
4. **Find the capability delta.** State what the attacker can do before and after. Equal capabilities mean no security impact.
5. **Attempt the strongest refutation.** Test the best benign explanation: intended sharing, attacker already controls the secret/config/peer, production hardening, safe caller contract, unreachable event shape, or downstream misuse. An unresolved refutation means `HOLD`; a confirmed refutation means `KILL` or honest downgrade.
6. **Prove the exact boundary.** Use the proof type the destination accepts. Capture an observable side effect and negative controls, not only a status code, callback, code trace, or fabricated impossible input.
7. **Route before reporting.** Verify that the destination owns the faulty code and accepts this proof class. A real bug in a dependency may require an upstream advisory rather than the product's bounty program.
8. **Measure contestability.** Fingerprint the root cause as `boundary|primitive|invariant|effect`; compare it with your own reports, program disclosures, upstream history, recent advisories, and sibling implementations.
9. **Decide and persist.** Set exactly one terminal verdict in `candidate.json`, name failed gates or missing evidence, then run `--stage decision`.

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
| Hosted product/API | Live owned accounts or owned instance; victim marker/state change plus anonymous/nonexistent controls where relevant |
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
5. Check GHSA/CVE, issue/PR history, changelog, branches, releases, and `git log -p` for the exact enforcement path.

No public match is weak evidence, not proof of novelty; private duplicate pools remain invisible. A recent advisory or famous component raises contestability. Continue only when the candidate has a precise semantic delta from nearby work.

Cross-model agreement is hypothesis prioritization, not validation. Models share training data, public advisories, and prompt framing. Only independent artifacts can clear a gate.

## Terminal verdicts

| Verdict | Meaning |
|---|---|
| `REPORTABLE` | Every report-stage field is evidenced and the validator passes |
| `HOLD` | The invariant violation is plausible, but named proof, threat-model, route, or novelty evidence is missing |
| `KILL` | A gate is disproven, impact is unchanged, the behavior is intended, or the candidate is covered/fixed |
| `ROUTE_ELSEWHERE` | The bug may be real, but another project or disclosure rail owns the fix |
| `NO_REPORTABLE_FINDING` | The investigated invariant held after a complete trace and refutation attempt |

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
