# Invariant-First Bug Bounty

[![Agent Skill](https://img.shields.io/badge/Agent%20Skill-compatible-111827)](https://agentskills.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An Agent Skill that makes AI-assisted bug-bounty research earn a report before writing one.

Coding agents often find a dangerous function, build a local proof-of-concept, and jump to a polished report. That skips the questions triagers use to reject or duplicate submissions:

- Can an attacker reach the path under the accepted threat model?
- Does the behavior give the attacker a new capability?
- Does the target own the faulty code and accept this proof type?
- How does the root cause differ from prior reports and upstream work?

This skill requires one security invariant, a complete source-to-effect trace, the strongest benign explanation, negative controls, route ownership, and semantic duplicate analysis. It stores those decisions in `candidate.json` and blocks report drafting until deterministic validation passes.

## Install

Use the open Agent Skills installer with Codex, Claude Code, Cursor, OpenCode, or another supported agent:

```bash
npx skills add MoonFuji/invariant-first-bug-bounty
```

List what the installer detects without installing it:

```bash
npx skills add MoonFuji/invariant-first-bug-bounty --list
```

For a manual installation, clone the repository into the skills directory used by your agent. The directory name must remain `invariant-first-bug-bounty`:

```bash
git clone https://github.com/MoonFuji/invariant-first-bug-bounty.git invariant-first-bug-bounty
```

Common user-level locations include `~/.agents/skills/invariant-first-bug-bounty` for Codex-compatible setups and `~/.claude/skills/invariant-first-bug-bounty` for Claude Code.

## Use it

Ask your agent to invoke the skill explicitly on a program-authorized target:

```text
Use $invariant-first-bug-bounty to audit this in-scope source repository.
Model one security invariant before broad recon. Persist the candidate state,
trace the deepest reachable path, and return an evidence-backed terminal verdict.
```

The skill treats these as valid outcomes:

| Verdict | Meaning |
|---|---|
| `REPORTABLE` | The candidate cleared the report-stage evidence gates |
| `HOLD` | A named threat-model, proof, routing, or novelty artifact is missing |
| `KILL` | A gate failed or the alleged impact does not change attacker capability |
| `ROUTE_ELSEWHERE` | Another project or disclosure channel owns the fix |
| `NO_REPORTABLE_FINDING` | The selected invariant held after a complete trace and refutation attempt |

## How it changes the hunt

```text
scope and route
      |
security invariant
      |
source-to-effect trace + sibling path
      |
capability delta + strongest refutation
      |
accepted proof + negative controls
      |
root-cause fingerprint + route ownership
      |
persisted verdict
```

Broad regex recon sits behind the model gate. A suspicious sink cannot become a candidate until the agent records principals, protected assets, trust boundaries, state stores, enforcement points, and an invariant.

## The mechanical gates

Start a candidate:

```bash
cp assets/candidate.template.json /path/to/hunt/candidate.json
python scripts/validate-candidate.py --stage model /path/to/hunt/candidate.json
```

Record a terminal decision after completing the trace:

```bash
python scripts/validate-candidate.py --stage decision /path/to/hunt/candidate.json
```

Before drafting a submission-ready report:

```bash
python scripts/validate-candidate.py --stage report /path/to/hunt/candidate.json
```

A nonzero report-stage exit means the report remains blocked. The correct response is to collect the named evidence, change the route, or preserve the non-reportable verdict. Editing unsupported assertions to satisfy the validator violates the workflow.

The model-gated coverage sweep is optional:

```bash
bash scripts/recon-sweep.sh \
  --candidate /path/to/hunt/candidate.json \
  /path/to/in-scope-repository \
  /tmp/recon-output
```

It writes search results to the chosen output directory. It does not verify vulnerabilities.

## What is included

```text
SKILL.md                         Core invariant-first controller
agents/openai.yaml               Skill-list metadata
assets/candidate.template.json   Durable candidate and decision state
references/                      Proof, targeting, testing, and bug-class guidance
scripts/validate-candidate.py    Model, decision, and report gates
scripts/recon-sweep.sh           Optional model-gated source coverage
```

The core controller stays concise. Agents load detailed references only when the target architecture or proof route requires them.

## Why duplicate analysis is different

The skill fingerprints a candidate as:

```text
boundary|primitive|invariant|effect
```

Agents compare that fingerprint with the researcher's reports, program disclosures, upstream issues and patches, recent advisories, and sibling implementations. A clean public search does not prove novelty because private duplicate pools remain invisible. A recent advisory increases contestability instead of creating a novelty bonus.

When HackerOne MCP tools are available, `SKILL.md` defines the order for checking the researcher's reports, program disclosures, cross-program search, and close report matches.

## Limits

This skill does not guarantee a vulnerability, novelty, bounty eligibility, severity, or acceptance. Its regex sweep is not a security scanner. The validator checks whether required evidence fields exist and agree with the verdict; it cannot prove that the evidence is true.

An agent can still reason badly. Inspect the trace, reproduce the claimed boundary, and read the program policy before submission.

## Authorized research only

Use this skill only on assets covered by a program's scope and safe-harbor terms or on systems you own. Use owned accounts and data, minimize impact, and stop when proof would expose or alter third-party data. Never use discovered credentials or pivot into unrelated systems.

Do not place live credentials, private program material, or undisclosed vulnerability details in public issues or pull requests.

## License

MIT. See [LICENSE](LICENSE).
