# Adversarial Review — preparation and final certification

## Purpose

The strongest-refutation gate tests the single best benign explanation. This review is a broader process control against confirmation bias, unsupported mitigations, and weak proof.

It runs twice:

1. **Preparation** — the author runs the roles before proof to discover what evidence a skeptic would require. This pass may shape or kill the candidate, but it never certifies a final verdict.
2. **Certification** — a fresh-context agent or human reviews the finished candidate after proof, novelty, and timestamped hardening. This pass rewrites the review fields and records the reviewer attestation; `reviewed_at` must be at or after `hardening.completed_at` and before `decision.decided_at`.

A reviewer must receive the repository and final candidate artifact, not the author’s prosecution narrative.

## Reviewer attestation

Use the structured object in `candidate.json`:

```jsonc
"reviewer": {
  "mode": "independent_agent|human|self|owed",
  "id": "review-session-or-human-id",
  "reviewed_at": "2026-08-20T04:00:00Z",
  "artifact": "reviews/H-001.json",
  "fresh_context": true
}
```

Rules:

- `self` is preparation only and never final certification.
- `independent_agent` requires `fresh_context: true`.
- `human` is valid final certification.
- `owed` means provisional. It may support decision-stage output but never final report readiness.

## Role 1 — Advocate

Build the strongest evidence-backed case that the candidate is not a vulnerability.

Check five protection layers:

```text
language
framework
middleware
application
policy/deployment
```

For each, state whether it blocks the exact path rather than merely reducing risk.

Check these false-positive patterns:

1. Unsafe-looking code without attacker-source tracing.
2. Validation or authorization hidden in a helper, parent caller, or router composition.
3. Framework protection already neutralizes the primitive.
4. Same-realm behavior presented as a crossed trust boundary.
5. Dependency advisory without shipped-path reachability.
6. Operator/deployer configuration presented as attacker input.
7. Test, example, migration, or development-only code presented as production behavior.
8. The same root cause counted again through another surface.

Every recorded pattern needs both:

```json
{
  "pattern": "framework-protection blindness",
  "rebuttal": "The raw query API bypasses ORM parameterization.",
  "evidence": "app/reports.rb:42 and artifacts/poc.txt"
}
```

An unrebutted pattern blocks `REPORTABLE`.

## Role 2 — Cold verifier

Re-derive the claim from source and evidence rather than validating the author’s prose.

Decompose it into load-bearing subclaims, for example:

```text
A. the attacker controls X
B. X reaches Y in the load-bearing representation
C. no authoritative control blocks Y
D. Y causes effect Z
E. Z is a new capability across a target-owned boundary
```

Persist each link:

```json
{
  "claim": "tenant A controls the report id",
  "status": "supported",
  "evidence": "routes.rb:14"
}
```

`REPORTABLE` requires every load-bearing link to be supported. One unsupported link means `DISPROVED` or `UNCERTAIN`, never `CONFIRMED`.

Reassess severity from the demonstrated effect. Starting at MEDIUM is a useful anti-inflation discipline, not a forced final score.

Reject these rationalizations:

- “The author already verified it.”
- “The code looks vulnerable even though the exact path did not reproduce.”
- “It probably works in some deployment.”
- “This class is usually High/Critical.”
- “The defense is weaker than the prosecution.”

## Role 3 — Causal challenger

For every claimed protection or blocker, test:

- **Intervention:** removing it changes the result?
- **Counterfactual:** normal traffic exercises it?
- **Confounder:** it lives in the reviewed target rather than an assumed WAF, proxy, gateway, or deployment?

Classify surviving protections as `fragile`, `moderate`, or `robust` with evidence.

A speculative mitigation cannot kill a candidate. Doubt must be grounded just as attacker preconditions must be grounded.

## A load-bearing caveat determines the gate

Review the candidate’s own limitations. A caveat is load-bearing when it negates one of:

- attacker-controlled source;
- crossed trust boundary;
- new capability;
- target-owned security property;
- accepted proof or deployment route;
- security-enforcing nature of the bypassed control.

That caveat determines `HOLD` or `KILL` until evidence removes it. Ordinary limitations remain in the report and constrain impact or severity.

Do not reward deletion of honest caveats. Reward correctly classifying them.

## Final report certification

A final report review must cover the finished candidate, including:

- exact proof and negative controls;
- production or destination relevance;
- route ownership and accepted proof type;
- novelty searches and current-branch state;
- collision differentiator where required;
- hardening results and final severity.

The validator requires a final reviewer attestation plus the populated Advocate and Cold-verifier fields.

## Final candidate-closure certification

A candidate-level `NO_REPORTABLE_FINDING` is not merely the inverse of a report. The reviewer must audit whether this hypothesis was closed too early without pretending that one closure exhausts the target.

Populate `closure_review`:

```jsonc
"closure_review": {
  "verdict": "DEPTH_SUFFICIENT",
  "closures_challenged": [
    {
      "hypothesis": "H-001",
      "closure": "KILL @ reachability",
      "challenge": "Re-derived every public ingress and checked the alternate worker path.",
      "evidence": "reviews/H-001.json#reachability"
    }
  ],
  "probe_assessment": {
    "sufficient": true,
    "waived": false,
    "waiver_reason": "",
    "evidence": "artifacts/probe.txt"
  },
  "coverage_gaps": ["WebSocket transport remains untraced"],
  "remaining_high_value_hypotheses": ["H-002: async worker loses tenant identity"]
}
```

A final candidate-level `NO_REPORTABLE_FINDING` requires:

- `DEPTH_SUFFICIENT`;
- at least one load-bearing closure challenged with evidence;
- a sufficient researcher-designed adversarial probe, or a narrowly evidenced waiver;
- explicit coverage-gap and remaining-hypothesis arrays.

Nonempty arrays do not invalidate this candidate closure. They are mandatory continuation signals for the campaign. The reviewer must never turn them into empty arrays merely to make the current artifact look final.

An `UNCERTAIN` closure review is `HOLD`, not a final clean verdict.
