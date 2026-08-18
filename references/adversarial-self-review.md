# Adversarial Self-Review (solo role rotation)

## Contents
- Role 1 — Advocate (five protection layers, the eight false-positive patterns)
- Role 2 — Cold verifier (zero-context re-derivation, five rejected rationalizations)
- Role 3 — Causal challenger (intervention / counterfactual / confounder, fragility)
- Symmetry: doubt must be evidenced too
- Output contract

The strongest refutation (SKILL step 6, methodology §5.2) tests *the* best benign explanation.
This file is the complementary *process* control: a structured self-challenge run by rotating
three roles in sequence and **writing each role's output to the candidate before reading the
next**. The point is separation — the mind that imagined the attack is not, in the same pass, the
mind that validates it. That is what removes confirmation bias; the discipline is the ordering,
not any tooling.

Run this pass after the strongest-refutation attempt and before proof. It can only lower
confidence or set `KILL`; it never clears the `refutation` or `novelty` gates. Record the result
in `candidate.json.adversarial_review`.

## Role 1 — Advocate (build the strongest defense)

Construct the strongest possible case that this is **not** a vulnerability, even for a finding
that looks obviously valid. Inability to build a credible defense is itself the strongest evidence
the bug is real. "The framework probably handles this" is not a defense — name the specific
middleware, function, and configuration, or it does not count. Do not invent protections that are
not in the code.

Search five protection layers and, for each, state whether it **blocks the specific attack path**
(not merely "reduces risk"): Language · Framework · Middleware · Application · Documentation/
deployment.

Then check the eight false-positive patterns explicitly. Any match downgrades or kills the
finding; each maps onto an existing gate or terminal refutation kind.

1. **Unsafe-looking code without path tracing** — is attacker input *confirmed* to reach it, or
   assumed? (unconfirmed → `reachability`)
2. **Phantom validation bypass** — is the "missing" validation actually in a helper, middleware,
   or parent caller you did not read?
3. **Framework-protection blindness** — ORM parameterization, template auto-escaping, CSRF
   middleware, etc. already neutralize it?
4. **Same-origin confusion** — is this actually cross-trust-boundary, or same-origin/same-session
   dressed up as cross-boundary? (→ `owned_boundary_absent`)
5. **Dependency CVE without reachability** — is the vulnerable function called with attacker input
   on a runtime path that ships? (→ `reachability`)
6. **Config-as-vulnerability** — does exploitation require admin to set an insecure config, or a
   non-default config no real deployment uses? (→ `required_precondition_already_grants_effect`
   or `behavior_is_documented_contract`)
7. **Test/example code** — does the vulnerable code ship to production, or is it a fixture/doc/
   dev script?
8. **Double-counting** — is this the same root cause as another finding under a different surface?

Record which layers were searched, the strongest defense you could build, and any FP-pattern
hits, in `adversarial_review.advocate`. An unrebutted FP-pattern hit forbids `REPORTABLE` — write
the rebuttal (with evidence) or take the implied `KILL`. These are the eight patterns assessed
against the **single candidate under review**, so `fp_pattern_hits` holds at most a handful of
entries — one per pattern that actually matches, never one per grep line. If a recon sweep
returned dozens of syntactic hits, that is a discovery list, not a finding: they belong in the
variant sweep, not here, and are rebutted by structural class, not line by line.

## Role 2 — Cold verifier (zero-context re-derivation)

Re-verify as if you had never seen your own analysis:

- Do **not** re-read your own trace or notes; trace from source yourself.
- Restate the claim and decompose into testable sub-claims: A (attacker controls X),
  B (X reaches Y unsanitized), C (Y causes effect Z). If any sub-claim is incoherent or
  unsupported when stated precisely → `DISPROVED`. (Half of false positives die here.)
- Write a prosecution brief and a defense brief independently — neither may cite the other.
- Re-derive severity from scratch, **starting at MEDIUM**, ignoring whatever the draft says
  (methodology §6.2 governs the final score).
- `UNCERTAIN` is a first-class, honest outcome; an honest `UNCERTAIN` beats a dishonest
  `CONFIRMED` and maps to `HOLD`.
- Staleness check: if any code citation no longer resolves on the current default branch, the
  finding is `DISPROVED` until re-anchored — this is the same signal as
  `novelty.current_upstream_state: fixed`.

Five rationalizations that are auto-`DISPROVED` signals:

1. "The first pass already verified this."
2. "I can't reproduce it, but the code looks vulnerable." (failed repro without a documented
   blocker is a disproof signal, not a hold)
3. "Probably exploitable in some configuration." (theoretical ≠ confirmed)
4. "The severity feels right for this bug class." (severity is from evidence, not class default)
5. "The defense brief is weaker than the prosecution." (a plausible defense demands reproduction
   before you confirm)

Record `adversarial_review.cold_verify = {verdict, rederived_severity, killed_subclaim}`. A
`DISPROVED` verdict forbids `REPORTABLE`.

## Role 3 — Causal challenger (test every protection you rely on)

For each protection you claim blocks the attack, run three checks before trusting it:

- **Intervention** — if I forcibly removed this protection, does input still reach the sink? If
  yes, the protection is not causally necessary and something else is really deciding the outcome.
- **Counterfactual** — does normal traffic ever trigger this protection? If no, it is dormant and
  never battle-tested — treat as fragile.
- **Confounder** — is the protection in the reviewed code, or upstream (WAF/proxy/gateway)? If
  upstream, are there paths that skip the upstream — direct IP, internal service-to-service, a
  background worker, a non-default deployment?

Score each surviving protection **Fragile / Moderate / Robust**. A finding blocked only by a
Fragile protection is worth re-investigating from a different entrypoint rather than killing.

Record `adversarial_review.causal[]` with one entry per protection.

## Symmetry: doubt must be evidenced too

This review exists to kill false positives, but it must not become a false-*negative* engine. A
risk-averse pass will reach for an imagined mitigation — "there is probably a WAF", "some
middleware likely re-checks this", "production surely disables the debug route" — and downgrade a
real finding to `UNCERTAIN` on speculation. That is the mirror image of the inflation the main
workflow already forbids (SKILL step 6 rejects unevidenced *preconditions* that help the
attacker), and it is equally banned here: an unevidenced *mitigation* that kills the finding is
just as invalid.

Rule: **every downgrade, `UNCERTAIN`, or `DISPROVED` must cite code-grounded evidence for the
doubt** — a specific file:line control, a documented deployment default, a real config — not an
invented or theoretical protection. If the only reason a finding is not `CONFIRMED` is a mitigation
you cannot point to in the codebase, config, or program policy, that is not doubt; the honest
verdict is `CONFIRMED` and the speculation belongs in `## Limitations`, not in the verdict. A real
upstream protection (WAF/proxy) does not settle it either way until the confounder check finds it
in evidence *and* fails to find a path that skips it.

## Output contract

```jsonc
"adversarial_review": {
  "advocate":   { "layers_checked": [...], "fp_pattern_hits": [{ "pattern": "", "rebuttal": "" }],
                  "strongest_defense": "", "blocks": false },
  "cold_verify":{ "verdict": "CONFIRMED|DISPROVED|UNCERTAIN", "rederived_severity": "",
                  "killed_subclaim": null },
  "causal":     [{ "protection": "", "intervention": "", "counterfactual": "", "confounder": "",
                   "fragility": "fragile|moderate|robust" }]
}
```

At `REPORTABLE`, the report-stage validator requires `cold_verify.verdict == "CONFIRMED"` and
every `advocate.fp_pattern_hits[]` entry to carry a non-empty `rebuttal`.
