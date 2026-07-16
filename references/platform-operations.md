# Platform Operations — submission mechanics, caps, payout rails, safe-harbor

The technical references cover *finding* bugs. This file covers *getting paid for them without burning yourself* — the operational realities of each platform that, when ignored, cost time, Signal, or a payout. Read the section for the platform you're submitting to. These are hard-won; treat them as load-bearing.

## Contents
1. HackerOne
2. Bugcrowd
3. YesWeHack
4. Intigriti
5. huntr (AI/ML)
6. Payout rails — get this right before you invest
7. Safe-harbor & responsible-testing rules (all platforms)

---

## 1. HackerOne
- **Trial-report cap (account-wide).** New / low-Signal accounts are capped on the number of reports they can have open at once (observed: **4**). Once hit, further submissions are blocked until reports resolve or **Signal/Reputation rises** (~30-day regen window in practice). There is **NO legitimate bypass** — alternate accounts, out-of-band contact, or off-platform submission all violate HackerOne policy and risk a ban. If capped: stage hardened drafts locally and wait, or pivot to another platform (Bugcrowd/YWH). Do not try to route around it.
- **"One draft per program" consumption.** Submitting your first report against a program can consume a shared draft and 404 the *second* staged report for the same program. Fix: after the first submit, **reload the program's submit page and re-stage** the next report from scratch. Expect this; don't panic at the 404.
- **Signal is the currency.** N/A and Spam closures lower Signal and tighten the cap; resolved reports raise it. This is the mechanical reason honest scoping (don't submit theoretical/OOS junk) is the scarcest asset — every bad report makes the next one harder to file.
- **Weakness mapping:** pick the precise CWE; it routes triage and sets baseline severity. Provide a CVSS vector.

## 2. Bugcrowd
- **Login:** `bugcrowd.com/user/sign_in` (Okta OAuth). Other paths (`/login`, `/h/auth/sign_in`) are wrong/404. The SPA renders blank to a snapshot — read the DOM via `browser_evaluate` rather than relying on the accessibility snapshot. **2FA is TOTP** — ask the user for the current code when prompted (don't assume; codes rotate ~30s).
- **Identity verification (gov-ID KYC) gates SUBMISSION on many programs**, not just withdrawal. You can fill and **save a draft** before KYC, but the final submit is blocked until the user completes KYC. Don't burn time polishing if KYC isn't done — confirm it first. **The user does their own KYC; never enter their gov-ID.**
- **Submission form fields:** `submission[terms_and_conditions]` checkbox is **required** (a "Terms and conditions must be accepted" error means you forgot it). Target is a `submission_target_id` SELECT (pick the in-scope asset). Weakness uses the **VRT typeahead** (`vrt-form-input`) — map precisely (e.g. `broken_access_control.privilege_escalation`). Other fields: `submission_caption` (title), `submission_description`, `submission_bug_url`.
- **VRT → reward.** The VRT category maps to the program's reward table. The right category at honest severity pays correctly; inflating it gets the report downgraded on triage.

## 3. YesWeHack
- **Payout/withdrawal gated by KYC + SCA.** The blocker observed was **NOT the bank** — a Swiss IBAN works — it was the **SMS/SCA step rejecting a blocked phone country code**. If the user's country code is blocked, withdrawal stalls even with a valid IBAN; a support ticket is the path. Confirm the user's KYC + phone/SCA status *before* investing a hunt here.
- Login with the user's YWH credentials; KYC may be incomplete — check before assuming a submission will pay out.
- Programs include Sovereign Tech / EU-funded OSS scopes (good code-audit targets).

## 4. Intigriti
- European platform, KYC + bank/IBAN payout. Strong for web/API and EU OSS scope. VDP vs paid programs are clearly marked — confirm cash before hunting. Same honest-scoping/Signal dynamics as the others.

## 5. huntr (AI/ML)
- Focused on ML/AI OSS (model frameworks, serving, vector stores, agent libs). Lanes saturate fast — several were burned this period (keras/onnx/faiss/h5py picked over); confirm the specific package/sink isn't already a closed report before investing. Bounties are per-CVE-ish; novelty + a working PoC matter heavily. Insecure model deserialization (pickle-backed formats) is a recurring live lane.

## 6. Payout rails — get this right before you invest
- A **bank transfer with an IBAN works almost everywhere** (the user has a Swiss Dukascopy IBAN). So the bank is rarely the blocker.
- The real blockers are **identity/KYC** (Bugcrowd: can gate submission; YWH/Intigriti: gates withdrawal) and **SCA/phone-country** (YWH). Verify the *specific* gate for the *specific* platform before auditing — a perfect report you can't get paid for is wasted effort.
- Prefer lanes whose rail you (the user) have actually completed end-to-end over an untested one.

## 7. Safe-harbor & responsible-testing rules (all platforms)
These protect the user legally and protect Signal. They override hunting enthusiasm.
- **Stay within the program's stated scope and safe-harbor.** Out-of-scope testing can void legal protection regardless of how good the bug is.
- **Test on a local clone / your own test accounts**, not production, wherever possible. Source-code analysis on a local checkout touches nothing of theirs.
- **Never pivot with a live credential.** If you find a working prod secret, report the *exposure* — do not use the key to access prod data to "prove" it. Validate minimally and within policy, or not at all.
- **No volumetric/DoS testing** on live systems (also usually OOS — see methodology §3.2).
- **The user performs submissions and KYC**; ask for TOTP/2FA codes when needed; don't act outside the authorization the user has actually given.
- In the report, state honestly what was read-only / local / not exfiltrated — it builds triager trust and documents responsible conduct.
