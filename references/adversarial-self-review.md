# Adversarial review — preparation and one final exact-file review

## Purpose

The strongest-refutation gate tests the single best benign explanation. A wider
adversarial pass catches confirmation bias, unsupported mitigations, weak proof,
severity inflation, and report drift.

There are two different activities:

1. **Self-skepticism while researching** — the author uses the roles below to
   discover what evidence a skeptic would require. This is reasoning guidance,
   not a durable candidate form and never certifies a verdict.
2. **One final review** — after `report.md` and the submission bundle are
   finished, a fresh-context agent or human reviews the exact candidate, report,
   manifest, and attachments. This is the only review sidecar.

Do not make an early candidate review and then review the report again. Review
the artifact that is actually about to be submitted.

## Self-skeptic role 1 — Advocate

Build the strongest evidence-backed case that the candidate is not a
vulnerability.

Check:

- attacker source may not reach the claimed representation;
- a helper/parent/router may enforce the missing check;
- framework protection may neutralize the primitive;
- capability may remain in the same trust realm;
- a dependency may not be reachable through the shipped path;
- operator configuration may be mistaken for attacker input;
- the code may be test/example/migration-only;
- another project may own the security property;
- the same root cause may already be known.

A blocker needs evidence. A speculative mitigation cannot kill a candidate.

## Self-skeptic role 2 — Cold verifier

Re-derive the claim from source/evidence:

```text
A. attacker controls X
B. X reaches Y in the exploit-critical representation
C. no authoritative control blocks Y
D. Y causes effect Z
E. Z is a new capability across a target-owned boundary
```

If a claim-critical link is unsupported, the finding is unresolved or dead.
Do not compensate with stronger prose.

Reassess severity from the demonstrated effect, not the vulnerability class.

## Self-skeptic role 3 — Causal challenger

For every claimed protection or blocker, ask:

- **Intervention:** would removing it change the result?
- **Counterfactual:** does normal traffic exercise it?
- **Confounder:** is it in the reviewed target rather than an assumed WAF,
  proxy, gateway, or deployment?

Doubt must be grounded just as attacker preconditions must be grounded.

## Limitations and narrowing

Review the candidate's `claim.limitations` and `recovery.unsupported_claims`.

A limitation is load-bearing when it negates:

- attacker-controlled source;
- crossed trust boundary;
- new capability;
- target-owned property;
- accepted proof route;
- security-enforcing nature of the control.

If the stronger claim fails but a lower security-relevant claim survives, use
`recovery.status: narrow` and report only that surviving claim.

## Final review

Only after the report and bundle are complete, copy
`assets/final-review.template.json` into the bundle.

The final reviewer should receive enough context to re-derive the claim, but not
the author's prosecution narrative as a substitute for evidence. Review:

- exact target/revision and current scope;
- attacker model and capability delta;
- complete claim-critical trace;
- strongest refutation and evidence;
- exact proof, negative control, and configuration dependency;
- owner and route;
- duplicate searches and current state;
- bounded capability, impact, severity ceiling, limitations, and narrowing;
- the actual `report.md`;
- every attachment;
- fresh submission-time scope severity cap and accepted proof policy.

The sidecar is:

```json
{
  "schema_version": 2,
  "review_type": "final_submission",
  "reviewer": {
    "mode": "independent_agent",
    "id": "review-session-id",
    "reviewed_at": "2026-09-03T20:00:00Z",
    "fresh_context": true
  },
  "verdict": "SUBMISSION_READY",
  "submission": {"path": "submission.json", "sha256": "..."},
  "candidate": {"path": "candidate.json", "sha256": "..."},
  "report": {"path": "report.md", "sha256": "..."},
  "attachments": []
}
```

`human` is also valid. An independent agent requires `fresh_context: true`.

A digest proves only which bytes were reviewed. It does not prove evidence truth
or reviewer independence.

If any reviewed file changes, obtain a new final review.

## Broad clean/exhausted conclusions

There is no candidate-level `NO_REPORTABLE_FINDING`. One dead invariant is a
`KILL`, not a clean target.

For target-wide coverage conclusions use optional exhaustive campaign mode and
review the coverage argument separately. See `references/campaign-mode.md`.
