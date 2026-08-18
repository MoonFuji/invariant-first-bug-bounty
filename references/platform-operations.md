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

## 1. HackerOne
- **Trial-report cap (account-wide).** New / low-Signal accounts are capped on the number of reports they can have open at once (platform-defined). Once hit, further submissions are blocked until reports resolve or **Signal/Reputation rises** (subject to current platform rules). There is **NO legitimate bypass** — alternate accounts, out-of-band contact, or off-platform submission all violate HackerOne policy and risk a ban. If capped: stage hardened drafts locally and wait, or pivot to another platform (Bugcrowd/YWH). Do not try to route around it.
- **"One draft per program" consumption.** Submitting your first report against a program can consume a shared draft and 404 the *second* staged report for the same program. Fix: after the first submit, **reload the program's submit page and re-stage** the next report from scratch. Expect this; don't panic at the 404.
- **Signal is the currency.** N/A and Spam closures lower Signal and tighten the cap; resolved reports raise it. This is the mechanical reason honest scoping (don't submit theoretical/OOS junk) is the scarcest asset — every bad report makes the next one harder to file.
- **Weakness mapping:** pick the precise CWE; it routes triage and sets baseline severity. Provide a CVSS vector.

## 2. Bugcrowd
- **Login:** `bugcrowd.com/user/sign_in` (Okta OAuth). Other paths (`/login`, `/h/auth/sign_in`) are wrong/404. The SPA renders blank to a snapshot — read the DOM via `browser_evaluate` rather than relying on the accessibility snapshot. **2FA is TOTP** — ask the account holder for the current code when prompted (don't assume; codes rotate ~30s).
- **Identity verification (gov-ID KYC) gates SUBMISSION on many programs**, not just withdrawal. You can fill and **save a draft** before KYC, but the final submit is blocked until the account holder completes KYC. Don't burn time polishing if KYC isn't done — confirm it first. **The account holder completes KYC personally; never enter another person's government-ID data.**
- **Submission form fields:** `submission[terms_and_conditions]` checkbox is **required** (a "Terms and conditions must be accepted" error means you forgot it). Target is a `submission_target_id` SELECT (pick the in-scope asset). Weakness uses the **VRT typeahead** (`vrt-form-input`) — map precisely (e.g. `broken_access_control.privilege_escalation`). Other fields: `submission_caption` (title), `submission_description`, `submission_bug_url`.
- **VRT → reward.** The VRT category maps to the program's reward table. The right category at honest severity pays correctly; inflating it gets the report downgraded on triage.

## 3. YesWeHack
- **Payout/withdrawal gated by KYC + SCA.** The blocker observed was **NOT the bank** — bank-transfer availability varies by account and region — it was the **account-specific identity or authentication requirements**. If verification or authentication is unavailable, withdrawal may require platform support. Confirm the researcher's KYC + phone/SCA status *before* investing a hunt here.
- Use the researcher's authorized YWH account; KYC may be incomplete — check before assuming a submission will pay out.
- Programs include Sovereign Tech / EU-funded OSS scopes (good code-audit targets).

## 4. Intigriti
- European platform, KYC + bank/IBAN payout. Strong for web/API and EU OSS scope. VDP vs paid programs are clearly marked — confirm cash before hunting. Same honest-scoping/Signal dynamics as the others.

## 5. huntr (AI/ML)
- Focused on ML/AI OSS (model frameworks, serving, vector stores, agent libs). Lanes saturate fast — parallel review is common; confirm the specific package/sink isn't already a closed report before investing. Bounties are per-CVE-ish; novelty + a working PoC matter heavily. Insecure model deserialization (pickle-backed formats) is a recurring live lane.

## 6. Payout rails — get this right before you invest
- A **bank transfer with an IBAN works almost everywhere** (availability is account- and region-specific). So the bank is rarely the blocker.
- The real blockers are **identity/KYC** (Bugcrowd: can gate submission; YWH/Intigriti: gates withdrawal) and **SCA/phone-country** (YWH). Verify the *specific* gate for the *specific* platform before auditing — a perfect report you can't get paid for is wasted effort.
- Prefer lanes whose rail the researcher has completed end-to-end over an untested one.

## 7. Safe-harbor & responsible-testing rules (all platforms)
These protect the researcher and preserve platform standing. They override hunting enthusiasm.
- **Stay within the program's stated scope and safe-harbor.** Out-of-scope testing can void legal protection regardless of how good the bug is.
- **Test on a local clone / your own test accounts**, not production, wherever possible. Source-code analysis on a local checkout touches nothing of theirs.
- **Never pivot with a live credential.** If you find a working prod secret, report the *exposure* — do not use the key to access prod data to "prove" it. Validate minimally and within policy, or not at all.
- **No volumetric/DoS testing** on live systems (also usually OOS — see methodology §3.2).
- **The account holder performs submissions and KYC**; ask for TOTP/2FA codes when needed; don't act outside the authorization explicitly provided for the current operation.
- In the report, state honestly what was read-only / local / not exfiltrated — it builds triager trust and documents responsible conduct.
