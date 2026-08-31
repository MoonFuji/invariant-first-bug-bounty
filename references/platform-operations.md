# Platform Operations — submission mechanics, caps, payout rails, safe-harbor

The technical references cover vulnerability research. This file covers submission and platform operations: scope, eligibility, reputation, disclosure, and payout constraints that can determine whether a technically valid result is accepted. Read only the section for the destination you are using.

## Contents
0. Scope & eligibility — verify before you invest
1. HackerOne
2. Bugcrowd
3. YesWeHack
4. Intigriti
5. huntr (AI/ML)
6. Payout rails — get this right before you invest
7. Safe-harbor & responsible-testing rules (all platforms)

---

## 0. Scope & eligibility — verify before you invest

Scope, eligibility, PoC policy, and payout are **live state**. Verify them at the destination at hunt start — not from a cached list or from memory. Getting this wrong wastes an entire hunt on a finding that was never submittable.

- **Listed ≠ eligible.** A repository being public, or named somewhere in scope, does not mean the exact asset is marked *eligible for bounty*. Confirm the specific asset is both in-scope and bounty-eligible in the current program policy before investing.
- **PoC policy can auto-N/A a valid finding.** Some programs ban source-only analysis or require a running-instance / live PoC. A technically correct source-only finding is auto-N/A there regardless of quality. Read the PoC/testing rules first; if source-only proof is not accepted and you cannot reach a live instance within policy, the honest early verdict is `HOLD` or a rotation, not a submission.
- **Advertised max ≠ real payout.** The headline maximum is not the typical award; some fields are known to misreport. Check average/recent bounty amounts — a low-signal or effectively-unpaid asset may not justify the hunt.
- **Re-verify live.** Programs change scope, eligibility, and policy without notice. A cached scope file is a discovery hint, not authorization or eligibility — re-check the live program page before you clone or invest.
- **Assess contestability before investing.** A low `resolved_report_count` is not proof of a quiet target. Review disclosed reports, public issues and pull requests, recent advisories, and authorized prior outcomes when available. On a **non-disclosing** program, the private pool cannot be searched; record `private_unavailable` rather than inventing a count (`references/methodology-and-targeting.md` §1).

## 1. HackerOne
- **Account submission limits.** Limits vary with account and program state. Read the current platform response rather than assuming a fixed quota or reset interval. There is no legitimate bypass: do not use alternate accounts, out-of-band contact, or off-platform submission to evade a limit. Stage hardened drafts locally or choose another eligible program.
- **Treat form state as live state.** A submission can invalidate another staged form. Reload the program's submit page and re-check every field and attachment before the next submission.
- **Signal is the currency.** N/A and Spam closures lower Signal and tighten the cap; resolved reports raise it. This is the mechanical reason honest scoping (don't submit theoretical/OOS junk) is the scarcest asset — every bad report makes the next one harder to file.
- **Weakness mapping:** pick the precise CWE; it routes triage and sets baseline severity. Provide a CVSS vector.

## 2. Bugcrowd
- **Login:** `bugcrowd.com/user/sign_in` (Okta OAuth). Other paths (`/login`, `/h/auth/sign_in`) are wrong/404. The SPA can render poorly in accessibility snapshots, so verify the actual DOM when necessary. **2FA is controlled by the account holder**; request a current code only at the visible authentication prompt.
- **Identity verification can gate submission**, not just withdrawal. A draft may be saved before verification, but the account holder must complete KYC personally. Never enter, store, or transmit another person's government-ID data.
- **Submission form fields:** `submission[terms_and_conditions]` checkbox is **required** (a "Terms and conditions must be accepted" error means you forgot it). Target is a `submission_target_id` SELECT (pick the in-scope asset). Weakness uses the **VRT typeahead** (`vrt-form-input`) — map precisely (e.g. `broken_access_control.privilege_escalation`). Other fields: `submission_caption` (title), `submission_description`, `submission_bug_url`.
- **VRT → reward.** The VRT category maps to the program's reward table. The right category at honest severity pays correctly; inflating it gets the report downgraded on triage.

## 3. YesWeHack
- **Payout/withdrawal may be gated by KYC + SCA.** Verify the current identity, phone/SCA, and payout requirements for the researcher's account. If the platform rejects an otherwise valid verification step, use its support channel rather than attempting a workaround.
- KYC may be incomplete — check before assuming a submission will pay out.
- Programs include Sovereign Tech / EU-funded OSS scopes (good code-audit targets).

## 4. Intigriti
- European platform, KYC + bank/IBAN payout. Strong for web/API and EU OSS scope. VDP vs paid programs are clearly marked — confirm cash before hunting. Same honest-scoping/Signal dynamics as the others.

## 5. huntr (AI/ML)
- Focused on ML/AI OSS (model frameworks, serving, vector stores, agent libraries). These targets attract parallel review; confirm that the specific package, root cause, and sink are not already covered before investing. Novelty and an executable PoC matter heavily. Insecure model deserialization remains a recurring class, not automatic evidence of a reportable bug.

## 6. Payout rails — get this right before you invest
- Do not generalize payout compatibility from another researcher, country, bank, or platform. Verify the current rail and account requirements directly.
- Common blockers include **identity/KYC**, withdrawal verification, and SCA/phone requirements. Verify the *specific* gate for the *specific* platform before auditing — a perfect report you cannot submit or be paid for is wasted effort.
- Prefer lanes whose rail the researcher has completed end-to-end over an untested one.

## 7. Safe-harbor & responsible-testing rules (all platforms)
These protect the researcher and preserve platform standing. They override hunting enthusiasm.
- **Stay within the program's stated scope and safe-harbor.** Out-of-scope testing can void legal protection regardless of how good the bug is.
- **Test on a local clone / your own test accounts**, not production, wherever possible. Source-code analysis on a local checkout touches nothing of theirs.
- **Never pivot with a live credential.** If you find a working prod secret, report the *exposure* — do not use the key to access prod data to "prove" it. Validate minimally and within policy, or not at all.
- **No volumetric/DoS testing** on live systems (also usually OOS — see methodology §3.2).
- **The account holder performs submissions, identity verification, and authentication approvals.** Do not act outside the authorization explicitly provided for the current operation.
- In the report, state honestly what was read-only / local / not exfiltrated — it builds triager trust and documents responsible conduct.
