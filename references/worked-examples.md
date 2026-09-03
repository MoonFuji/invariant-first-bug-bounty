# Worked examples

These examples are synthetic and calibrate gates. They are not real report
provenance.

## 1. Cross-tenant direct-object read — REPORTABLE

**Invariant:** a tenant-scoped caller must not read another tenant's report.

**Trace:** authenticated tenant A controls `/reports/{id}`; the direct lookup
fetches by report id without tenant predicate; serialization returns tenant B's
canary. The list sibling correctly scopes by tenant id.

**Capability delta:** before, tenant A reads its own reports. After, tenant A
reads a tenant B report.

**Strongest refutation:** "report ids are intentionally globally readable."
Target docs state reports are tenant-confidential, so the objection is
non-terminal and refuted.

**Proof:** exact pinned handler reproduces the cross-tenant canary and a
tenant-scoped sibling acts as negative control.

**Novelty:** commits, issues, PRs, disclosures, advisories and current branch are
searched. Closest public issue concerns list filtering, not direct-object
lookup.

**Claim:** cross-tenant read only; no write/admin extension.

**Decision:** `REPORTABLE`.

## 2. Exact parser crash with unproven product ingress — NARROW

A parser executable crashes on a crafted owned fixture.

The stronger claim says a supported product-facing request reaches that exact
parser representation and causes a service outage. The product ingress has not
been demonstrated.

Do not either:

- inflate the report to a remote outage; or
- kill the exact executable effect merely because the stronger chain failed.

If the exact executable itself is in scope and security-relevant, use:

```json
{
  "recovery": {
    "status": "narrow",
    "next_action": "Report only the exact executable effect.",
    "required_artifact": "",
    "unsupported_claims": [
      "supported product ingress was not demonstrated",
      "automatic restart or repeated outage was not demonstrated"
    ]
  }
}
```

The candidate claim and severity must stay inside the surviving effect.

## 3. Operator-disabled authorization — KILL/HOLD, not report

Source shows an endpoint without its normal authorization middleware only when
an operator explicitly disables that middleware.

If disabling the control already grants the capability being claimed,
`proof.config_dependency.kind` is `operator_weakened`.

That does not establish a supported target boundary. Do not report the normal
behavior as an auth bypass.

Use `KILL` when the supported contract is clear. Use `HOLD` if evidence about
the shipped/supported configuration is still missing.

## 4. Git log clean, issue already covers root cause — duplicate

A candidate finds a path canonicalization discrepancy. `git log` has no obvious
fix, so a shallow search says "new."

An upstream closed issue describes the same:

```text
boundary | primitive | invariant | effect
```

The payload differs, but the root cause and security effect do not.

`novelty.classification` is `duplicate`; the candidate does not become
reportable. This is why repository novelty requires issue and PR searches in
addition to commit history.

## 5. Hosted proof vocabulary — valid mapping

The program policy says it accepts proof using a
`program-hosted-owned-account`.

The candidate proof records the concrete technique as `live-two-identity`.

These are intentionally different vocabularies: one is the destination's
accepted proof category, the other is the candidate's executed proof shape.

The final submission preflight records the policy category and the validator
maps `live-two-identity → program-hosted-owned-account`. Raw string equality
would reject a valid hosted proof.

## 6. Current severity cap changed during the hunt

At target selection the asset allows `high`.

Five weeks later, the technical candidate is still valid, but the program now
caps that asset at `low`.

The final preflight records the current `max_severity: low`. A candidate with a
`high` severity ceiling cannot reach submission readiness until it is reassessed
and bounded to the current cap.

The old target value does not win.

## 7. One dead candidate is not a clean target

H-001 traces a suspected cache-key confusion and dies because tenant identity is
present in the authoritative key.

Default mode simply records a `KILL` for H-001.

If the user's request was "audit the whole repo," optional campaign mode
continues to H-002/H-003 according to priority. There is no candidate-level
`NO_REPORTABLE_FINDING` verdict that can accidentally certify the whole target.

An exhaustive target conclusion belongs to a closed exhaustive campaign.

## 8. Final report changed after review

A technically valid candidate is drafted into `report.md`. A reviewer approves
the exact final bundle.

If the author edits the report, candidate, submission manifest, or any attachment
afterward, the SHA-256 reference no longer matches and submission readiness
fails.

There is only one review layer: review the actual final bundle rather than
certifying an intermediate candidate and later reviewing a second semantic copy.
