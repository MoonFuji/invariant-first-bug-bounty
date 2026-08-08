# Changelog

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
