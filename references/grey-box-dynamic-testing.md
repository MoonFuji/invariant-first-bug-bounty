# Grey-box dynamic testing — controlled running-instance validation

Read this when the selected proof level includes a running instance. In `SOURCE_ONLY`, use an isolated local process, disposable container, or self-hosted deployment you control. In `PROGRAM_HOSTED`, use only an owned instance or account explicitly covered by current program rules. A genuinely non-runnable library, CLI, SDK, or parser may instead require an executable test or exact source-level enforcement model accepted by the destination.

**Authorization first:** stay within the declared operating mode and current program scope. Never test another tenant's instance, account, or data. Treat mutating requests against shared infrastructure as higher-impact validation actions requiring explicit permission and an owned disposable object. Prefer source inspection or a controlled local reproduction when it establishes the same boundary. A WAF, CAPTCHA, rate limit, or other blocking control ends that automated path; return to source analysis rather than trying to defeat it.

## 0. Proving you own the tested instance (ownership attestation — pre-empts the #1 managed-program triage question)
On a managed/SaaS program the first triage question for any live PoC is *"prove this is YOUR instance, not another customer's."* Put the attestation **in the report** so it's never asked:
- Your account/org id + the instance hostname/UUID from your dashboard (screenshot), its creation timestamp, and a **unique benign marker you planted** (a value only your account would set).
- For a two-account authorization proof, show **both** comparison accounts are yours. Never use another customer's account or data.
- If you spun up a throwaway account/org for the test, say so and name it — this is normal and accepted (the disclosed Aiven Kafka-Connect RCE reporter made a fresh account precisely to prove ownership).

## 1. Controlled reproduction recipe
Use this only at the lowest proof level that can establish the boundary.
```
1. STAND UP   run the exact affected version in an isolated local environment; record the version and container/process identity
2. BASELINE   send one benign request and one known-negative request; record their observable effects
3. REPRODUCE  make the crafted input and its delivery vector explicit; use a harmless deterministic action appropriate to the primitive
4. VERIFY     inspect the side effect, not only HTTP status: unique marker file, controlled listener receipt, owned test record, or browser execution flag
5. COMPARE    rerun the benign and negative controls; classify as CONFIRMED, PARTIAL, or NOT_REPRODUCED
6. CLEAN UP   remove containers, volumes, test accounts/data, markers, and helper listeners
```
For command or code execution, create a uniquely named marker inside the disposable environment and verify it directly. For outbound-request behavior, use a local controlled listener. For data-boundary behavior, use uniquely tagged records belonging to accounts you own. The proof is the verified side effect, not the response code. Keep a missing-input gap separate from a missing-delivery-vector gap.

Delivery details remain load-bearing. For Spring Cloud Function SpEL, for example, the expression and the `spring.cloud.function.routing-expression` header on `/functionRouter` are separate requirements. `Runtime.exec` returns a `Process`, not command output, so verify a local marker rather than expecting reflection. Keep that class distinct from Spring4Shell (CVE-2022-22965), which requires JDK 9+ and a WAR deployment on Tomcat rather than the default embedded Spring Boot JAR. Use `curl --path-as-is` when the exact path representation is part of the tested invariant.

## 2. FP-disproof control tests — run BEFORE writing (each kills a specific fake-bug shape)
The validation gate (§4.5) says "prove impact"; these say *how to disprove the look-alike*. Run the matching one the moment a finding "looks real." (Soundness is first-principles; the source repo self-graded these against its own lab — trust the logic, not the score.)

| Looks like | Control test that settles it | Kill condition |
|---|---|---|
| **IDOR** (200 with an id) | Does the body contain the *other actor's* data, or just echo your input? | echoes your own/again-public data → **not a leak** |
| **Blind SSRF/XXE/RCE** (URL reflected in a response/error) | In a local environment, point it at a unique path on your controlled listener; in `PROGRAM_HOSTED`, use an explicitly permitted researcher-owned listener | 0 callbacks → **no outbound request** (a reflected URL proves nothing) |
| **Reflected/stored XSS** | Inject a **unique random marker** (generic words collide w/ page text); then inject `<x9>` and check raw vs `&lt;x9&gt;` | returned encoded → **reflection ≠ execution → kill** |
| **File/user existence oracle** ("blocked"/"exists") | Re-probe a **guaranteed-garbage** input of the same shape (`garbage-<rand>.asmx`) | identical response → **blanket policy, not a state oracle** |
| **User enumeration / "same = no bug"** | **Body-diff byte-by-byte** (never status codes); two 401s can differ in body | identical bodies → no enum; differing → real |
| **Timing oracle** | n≥10 **interleaved** trials + Welch t-statistic > 3 (or non-overlapping CIs) | single-shot delta / t<2 / overlapping CIs → **noise** |
| **Any "blind" claim** | **Re-fire**; compare to a known-negative input | byte-identical to the negative → it did nothing |

## 3. Authz identity-diff matrix — the IDOR/BOLA N/A-killer
For the highest-EV class (authz), run the **same request** under multiple identities on your provisioned instance (2 accounts you own: A, B), then classify by *which combination reproduces*:

| Reproduces under | Verdict |
|---|---|
| session A reads/acts on **B's** object | **IDOR / BOLA** (the bug) |
| low-priv reads/does what a higher role should | **privilege escalation** |
| works with **no auth at all** | **missing authentication** (a *different*, often higher, bug — reframe) |
| works for A, **stops after logout / for anon** | **the access control is WORKING — NOT a bug** (this is the FP that eats report slots) |

Always demonstrate with B's *distinct, uniquely-tagged* data echoed back to A (so it can't be your own or public data). Keep creds out of logs (`session_id = sha256(headers)[:12]`; diff `user-a.json` vs `user-b.json` by hash).

## 4. Browser-execution verification (don't trust server-side acceptance)
**Server-accept ≠ browser-navigation — they are two separate gates.** A server `startswith()`/`==` that accepts your `redirect_uri` does NOT mean the browser navigates there. Before writing OAuth→ATO or DOM-XSS, headless-test the *final navigation/execution*:
- Stored XSS: set a persistent `window.__xss=true` and read it via `page.evaluate` *after* navigation (survives reloads).
- Reflected XSS: attach a dialog/`alert` listener.
- WHATWG URL truth: `@` *after* the first `/` is a path char (not exploitable); `@` *before* any `/` puts the attacker host in the authority (exploitable). Test the actual parse.

## 5. Fingerprint before you assume (classes are version-gated)
Don't assume a class is live (or dead) from a generic payload — **fingerprint the running version first**, then reach for the class's `Confirm:` step in `bug-class-taxonomy.md`. Version-dependent traps: XML parsers (defused / `LIBXML_NOENT` toggles whether XXE fires), request-smuggling (front/back proxy versions — CL.TE is often mitigated on recent nginx, so try H2.CL/H2.TE), SameSite/cookie defaults, JWT `alg` handling. Two non-obvious tips: GraphQL **alias-batching runs serially** (won't win a race — pair it with parallel HTTP); test cloud against **LocalStack, never a real tenant**.

## Tooling for this lane
- **caido-mcp** (community Caido MCP) — conditional ADOPT, **claims unverified**: it *claims* to be **read-from-proxy-history** (reads what *your own* browsing did; sends no autonomous traffic) and to **auto-redact `Authorization`/`Cookie`/`Set-Cookie`/API-key** before returning to the model. **Verify both claims before trusting it** — if they hold, it's safe-harbor-compatible grey-box visibility with no creds leaking into context.
- **IGNORE** burp-mcp for autonomous use (advertises send-requests + Collaborator, no redaction stated, clobbers `~/.claude/settings.json`), and any nuclei/dalfox "full hunt" except as **regression against your own lab** (scanner output on a live target = the dup AI-slop programs auto-close).
