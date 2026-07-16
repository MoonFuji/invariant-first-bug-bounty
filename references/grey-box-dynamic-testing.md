# Grey-box dynamic testing — running-instance discipline (read ONLY when you have a live instance)

Read this for the **grey-box default** — any target you can stand up yourself (vulhub/docker, a self-hosted OSS deploy, or an instance you provisioned on a managed program and **proved you own**). This is the lane to grow into: white-box-only is an easy habit, not an obligation, and it's where reports die as "theoretical." The *narrower fallback* is a genuinely **non-runnable asset** — a library/CLI/SDK with no instance to stand up, or the upstream-CVE→IBB rail — where you can't run the dynamic tests below and instead prove the claim from the code (methodology §4.1 + the evidence-grounding rule in §4.5). For anything runnable, don't settle for source-only: stand it up and prove it live.

**Safe-harbor first (non-negotiable):** stay inside the program's stated scope — test a **self-provisioned/self-hosted instance** OR **your own account & data on the program's hosted in-scope app**; never another tenant's instance, account, or data (the Aiven corpus rule: *"only services you create yourself are in scope"* — prove ownership of whatever you test). Read-only verbs by default — treat **POST/PUT/DELETE/PATCH as requiring deliberate care** (a mutating request against shared infra can destroy data or breach scope). For every "offensive action," prefer the **static-in-the-clone equivalent**: prove a rate-limit reads a spoofable header by *grepping the limiter*, not by firing 100 requests; prove CI-injection by *reading the workflow YAML*, not POSTing the payload to a real org. A blocking control (WAF/captcha/429) is the program saying *stop the automated path* — pivot to reading code, never defeat it. (Provenance: distilled from community bug-bounty harness repos; their live-fire / autopilot / credential-brute / WAF-bypass behaviors are deliberately excluded as safe-harbor risks.)

## 0. Proving you own the tested instance (ownership attestation — pre-empts the #1 managed-program triage question)
On a managed/SaaS program the first triage question for any live PoC is *"prove this is YOUR instance, not another customer's."* Put the attestation **in the report** so it's never asked:
- Your account/org id + the instance hostname/UUID from your dashboard (screenshot), its creation timestamp, and a **unique benign marker you planted** (a value only your account would set).
- For a two-account authz PoC, show **both** accounts are yours (both dashboards) — provision your own second account/org for the "victim" side; never use a real other tenant.
- If you spun up a throwaway account/org for the test, say so and name it — this is normal and accepted (the disclosed Aiven Kafka-Connect RCE reporter made a fresh account precisely to prove ownership).

## 1. Live-PoC reproduction recipe (the "prove it on an instance you provisioned" engine)
This is how you produce the *running PoC* the demonstrated-impact bar demands (methodology §4.0), and the engine for the upstream-CVE→IBB and grey-box lanes.
```
1. STANDUP   git clone vulhub (or the OSS repo) → docker compose up -d; remap the port off 8080 (dodge your own proxy)
2. BASELINE  curl -sI → confirm the EXACT vulnerable version (patch boundaries decide validity); run one benign request; note the container name
3. EXPLOIT   make BOTH explicit: the payload AND its delivery vector (these are separate gaps — you may know SpEL→Runtime.exec but not that the vector is the `spring.cloud.function.routing-expression` HEADER on /functionRouter). curl quirks: --path-as-is; Runtime.exec(String[]) to dodge shell-quoting. `exec(cmd)` returns a **Process, not a String** — a bare `exec("id")` reflects nothing, so confirm via an OOB curl *inside* the payload, not by expecting stdout. And keep Spring4Shell (CVE-2022-22965) distinct from spring-cloud-function SpEL: 22965 needs **JDK 9+ AND a WAR-on-Tomcat deploy** — it does NOT fire on the default embedded-jar Spring Boot, so kill that claim unless the deploy actually matches.
4. VERIFY    the SIDE-EFFECT, never trust HTTP 200/500: `docker exec <c> ls -la /tmp/pwned` (planted root-owned file) · the leaked secret's *content* in the body · `id`/`uname` output · the other actor's actual data · real DOM execution
5. VERDICT   PASS-live | PARTIAL | HONEST-NEGATIVE. Severity = MAX reachable impact, not the average
6. CLEANUP   docker compose down -v; pkill the helpers
```
The proof is the **verified side-effect**, not the response code. Separate a *missing-payload* gap (you don't know the exploit string) from a *missing-delivery-vector* gap (you know the string, not where it goes) — budget discovery time for the vector even when the payload is obvious.

## 2. FP-disproof control tests — run BEFORE writing (each kills a specific fake-bug shape)
The validation gate (§4.5) says "prove impact"; these say *how to disprove the look-alike*. Run the matching one the moment a finding "looks real." (Soundness is first-principles; the source repo self-graded these against its own lab — trust the logic, not the score.)

| Looks like | Control test that settles it | Kill condition |
|---|---|---|
| **IDOR** (200 with an id) | Does the body contain the *other actor's* data, or just echo your input? | echoes your own/again-public data → **not a leak** |
| **Blind SSRF/XXE/RCE** (URL reflected in a response/error) | Point it at a **unique-marker host → your own OOB listener** | 0 callbacks → **no SSRF** (a reflected URL is nothing) |
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
