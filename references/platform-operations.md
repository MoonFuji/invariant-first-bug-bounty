# Platform operations — scope, policy, payout, safe harbor

Technical validity and platform eligibility are different questions. Treat
scope, proof policy, payout, and submission mechanics as live state.

## Before investing

Verify at the current destination:

- exact asset is in scope;
- whether it is bounty-eligible or VDP-only;
- maximum accepted severity for that asset;
- accepted proof/testing route;
- whether hosted testing is permitted and under which accounts/data;
- payout/KYC constraints relevant to the researcher.

A public repository is not automatically bounty-eligible. A source-level bug is
not automatically submittable to a program that requires a hosted proof.

`target.json` records only the live technical eligibility needed to select the
target: scope and accepted proof routes. Payout friction and duplicate pressure
remain ranking/operational considerations rather than target-schema gates.

## Re-check before submission

Programs change while a hunt is in progress.

The final `submission.json` preflight must refresh within seven days:

- scope remains `eligible`;
- exact `asset_identifier`;
- current `max_severity`;
- current `accepted_proof_types`;
- evidence and timestamps.

The fresh preflight owns submission-time truth. A stale target record cannot
override a new lower severity cap or changed proof requirement.

## HackerOne

- Re-read the program page and exact asset before submission.
- Treat submission form state and current rate/signal limits as live platform
  behavior rather than fixed constants.
- Map weakness/CWE and severity to the demonstrated effect.
- A clean public search does not reveal the private duplicate pool.

## Bugcrowd

- Confirm the exact target and current VRT category.
- Identity/KYC requirements may gate submission or payout.
- Use current platform flows; do not work around account verification or rate
  controls.
- VRT/reward mapping should follow the reproduced capability, not inflated
  theoretical impact.

## YesWeHack / Intigriti

- Confirm the program is paid rather than VDP-only.
- Check current KYC/SCA/payout requirements before assuming a report can be
  rewarded.
- Verify the exact asset and proof route at submission time.

## OSS / upstream routes

For an upstream advisory or vendor route, verify:

- project owns the faulty implementation;
- maintainers would ship the fix;
- current branch/release state;
- advisory/issue/PR submission route;
- whether an external bounty program actually covers that upstream component.

A product bundling an unmodified dependency does not automatically own the
dependency's security property.

## Payout rails

Do not generalize payout compatibility from another researcher, country, bank,
or program. Check the current account-specific rail.

Common blockers include:

- KYC/identity verification;
- withdrawal verification;
- SCA/phone requirements;
- unsupported bank/region;
- minimum withdrawal thresholds.

These affect expected value, not vulnerability truth.

## Safe harbor and responsible testing

Program rules override hunting enthusiasm.

- Stay within current scope and safe harbor.
- Prefer local clones, owned deployments, and owned test accounts/data.
- Never pivot with exposed production credentials. Report exposure without
  using the credential to access unrelated data.
- Do not perform volumetric/DoS testing on live systems unless a program
  explicitly authorizes the exact method.
- Minimize data access and side effects.
- Do not evade rate limits, submission limits, KYC, authentication, or platform
  controls with alternate accounts or out-of-band workarounds.
- State honestly in the report what was local, read-only, planted, or not
  accessed.

## Submission ownership

The skill prepares evidence and a final reviewed bundle. It does not perform an
external submission. The account holder handles platform form review,
authentication approvals, identity verification, and the final send action.
