# Changelog

This changelog records public behavior and schema changes only. Private program
material, report identifiers, researcher account details, and undisclosed
findings are intentionally excluded.

## Unreleased — v0.8.0 candidate

- Breaking: target schema 3 owns architecture boundaries, campaign mode,
  hypothesis lifecycle, prior outcomes, coverage delta, and truthful
  contestability; candidate schema 6 binds one hypothesis and stable target
  fingerprint. Old records require deliberate manual review.
- Added bounded claim/recovery states so repairable gaps remain actionable and
  narrower exact findings can advance without unsupported extensions.
- Made static source traces supporting evidence, distinguished shipped from
  operator-weakened configuration, and enforced timezone-bearing timestamps.
- Disabled direct execution of the candidate core; `validate_hunt.py` is the
  only readiness entrypoint.
- Separated `CANDIDATE REPORTABLE` from final submission readiness. Exact
  candidate, Markdown report, manifest, and attachment bytes are reviewed via
  SHA-256 sidecars before `SUBMISSION READY FOR FINAL CHECK`.
- Added self-contained bundle creation and live submission-time scope and proof
  policy preflight. The tooling never performs the external submission.

## v0.7.1 — reference drift fix (2026-08-21)

- Updated remaining documentation examples to use the target-bound
  `validate_hunt.py` entrypoint.

## v0.7.0 — target-bound validation architecture (2026-08-21)

- Added `scripts/validate_hunt.py` as the documented validator entrypoint.
- Added schema-2 target ledgers with `SELECTED`, `ROTATED`, and `HOLD`
  dispositions.
- Added `scripts/start_candidate.py` to generate candidates from selected target
  ledgers.
- Bound candidate identity, revision, scope provenance, and disclosure
  visibility to the selected target.
- Added structured final-review attestations, review ordering, caveat ledgers,
  and final clean-candidate closure review.
- Added target-bound unit and CLI regression coverage.

## v0.6.0 — target selection and caveat discipline (2026-08-20)

- Added an initial target ledger covering live scope, proof policy, saturation,
  and selection or rotation.
- Distinguished load-bearing caveats from ordinary limitations.
- Added gate-calibrated synthetic worked examples.

## v0.5.1 — final-review correctness (2026-08-20)

- Rejected clean verdicts carrying a contradictory confirmed finding.
- Made owed review explicitly provisional.
- Moved static-clean warnings to recorded adversarial probes.
- Required final certification after proof and hardening.
- Clarified severity reassessment and configuration-dependency semantics.

## v0.5.0 — independent certification (2026-08-19)

- Disallowed self-certification of final reportable and clean-candidate
  verdicts.
- Added report hardening and independent-review state.
- Added warnings for clean conclusions lacking executed adversarial probes.

## v0.4.7 — execution guidance (2026-08-19)

- Clarified that dynamic market fields must be retrieved or left unknown.
- Made intent-corpus loading progressive for large targets.

## v0.4.6 — submission-loss brakes (2026-08-19)

- Added collision-differentiator, deployment-configuration, and per-subclaim
  evidence guidance.

## v0.4.5 — contestability-aware selection (2026-08-18)

- Moved dedup visibility into early target assessment.
- Added high-duplicate-context differentiation requirements.

## v0.4.4 — commitment binding (2026-08-18)

- Tightened durable candidate state and process ordering.

## v0.4.3 — exhaustion and cold verification (2026-08-18)

- Added checkable clean-candidate exhaustion records.
- Added cold-verifier subclaim decomposition.

## v0.4.2 — dynamic proof and campaign continuation (2026-08-18)

- Added dynamic-proof emphasis for runtime-only claims.
- Required campaign continuation after candidate-level decisions.

## v0.4.1 — discipline hardening (2026-08-18)

- Added workflow checks, rationalization warnings, and worked examples.

## v0.4.0 — hypothesis generation and adversarial review (2026-08-18)

- Added architecture-aware hypothesis generation.
- Added Advocate, Cold verifier, and Causal challenger review roles.
- Introduced candidate schema 5.

## v0.3.2 — ownership routing correction (2026-08-08)

- Pinned target-ownership refutations to the correct terminal route.

## v0.3.1 — evidence-state semantics (2026-08-08)

- Structured strongest-refutation evidence.
- Required explicit upstream issue and pull-request novelty channels.

## v0.3.0 — durable evidence gates (2026-08-08)

- Added structured evidence states for reportability decisions.

## v0.2.1 — operating-mode persistence (2026-08-08)

- Added durable `SOURCE_ONLY` and `PROGRAM_HOSTED` operating modes.

## v0.2.0 — authorized validation modes (2026-08-08)

- Added mode-aware proof and testing guidance.

## v0.1.0 — initial release (2026-07-16)

- Published the invariant-first, evidence-gated research workflow.
