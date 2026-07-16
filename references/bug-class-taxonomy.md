# Bug-Class Taxonomy — signals, sinks, and payout bands

This file maps 19 bug classes to the architecture where each primitive lives, source/sink signals, confirmation requirements, and realistic payout bands. Load only the entries relevant to the security invariant and enforcement path already recorded in `candidate.json`; do not choose a class merely for novelty or breadth.

## Contents

1. Injection — SQL/NoSQL
2. OS command injection
3. Code injection / SSTI
4. Insecure deserialization
5. SSRF (incl. cloud/IMDS)
6. Authorization — IDOR / BOLA / broken access control / multi-tenancy
7. Broken authentication / session / password-reset
8. JWT / OAuth / SAML / OIDC flaws
9. Prototype pollution (JS)
10. XXE
11. Path traversal / LFI / zip-slip / arbitrary file write
12. Open redirect / SSRF-adjacent URL parsing
13. XSS (reflected/stored/DOM) & client-side
14. CSRF / SameSite / state-changing GET
15. Request smuggling / parser differentials / cache poisoning
16. Race conditions / TOCTOU
17. Business-logic & workflow flaws
18. GraphQL-specific
19. Secrets exposure & weak cryptography

Payout bands are rough public-program medians; impact and program tier shift them a lot.

---

## 1. Injection — SQL/NoSQL
**Where:** any query built by string concatenation/format rather than parameterization; ORM "raw" escape hatches; dynamic `ORDER BY`/column names (params don't cover identifiers); NoSQL operator injection from JSON bodies.
**Signals:**
- PHP/Laravel: `DB::raw`, `->whereRaw(`, `->orderByRaw(`, `->selectRaw(`, `\DB::statement(`, `$request->` interpolated into a query string. Eloquent is safe *unless* raw or `whereRaw` with concatenation.
- JS/TS: template literals into `query(`, `sequelize.query(`, `knex.raw(`, Mongo `find(req.body)` allowing `{$gt:""}`/`$where`.
- Python: f-string/`%`/`.format` into `cursor.execute`, `text()` in SQLAlchemy with interpolation, Django `.extra(`/`.raw(`/`RawSQL`.
- Go: `fmt.Sprintf` into `db.Query/Exec`; `db.Raw` (GORM) with interpolation.
**Confirm:** boolean/time-based differential, or error-based. For NoSQL, operator injection that changes result set.
**Band:** $$–$$$$ (auth bypass / data dump = high). Heavily scanner-camped on web; far less so in libraries and ORMs' raw paths.

## 2. OS command injection
**Where:** anywhere user input reaches a shell.
**Signals:** PHP `exec/system/shell_exec/passthru/proc_open/popen` + var; JS `child_process.exec(`/`execSync(` (vs the safer `execFile` with arg array); Python `os.system`, `subprocess.*(…, shell=True)`, `os.popen`; Go `exec.Command("sh","-c", userStr)` or `"bash","-c"`.
**Confirm:** inject `;id`/`$(id)`/backticks/`|`; blind via timing (`sleep`) or OOB DNS.
**Band:** $$$–$$$$ (often RCE).

## 3. Code injection / SSTI
**Where:** templating engines fed user input as *template* not *data*; `eval`-family.
**Signals:** Python `render_template_string(`, `Template(user).render(`, Jinja `{{ }}` from input, `eval(`/`exec(`; JS `eval(`, `new Function(`, `vm.runInNewContext`, template libs (Handlebars/Pug/EJS) compiling user strings; Ruby ERB; Java/Spring SpEL `#{}`, Thymeleaf, Velocity, FreeMarker; Go `text/template`.Parse(user).
**Confirm:** polyglot `${7*7}`/`{{7*7}}`/`#{7*7}` → `49`; escalate to RCE per engine. Fingerprint the engine before picking a gadget: `{{7*'7'}}` → `7777777` = Jinja2 (Python string-repeat) vs `49` = Twig (numeric coercion); `${7*7}`→`49` = Freemarker/Velocity/**Mako**.
**Band:** $$$–$$$$.

## 4. Insecure deserialization
**Where:** untrusted bytes into a native object deserializer.
**Signals:** PHP `unserialize(` (+ POP-chain gadgets; `phar://` stream triggers it), Laravel `decrypt()` misuse; Python `pickle.load(s)`, `yaml.load(` without `SafeLoader`, `yaml.unsafe_load`, `jsonpickle`, `dill`, `shelve`, `numpy.load(allow_pickle=True)`; JS `node-serialize`, untrusted input to a deserializer with `_$$ND_FUNC$$_`; Java `ObjectInputStream.readObject`, XMLDecoder, fastjson/Jackson polymorphic typing; Ruby `Marshal.load`, YAML `Psych.load`; .NET `BinaryFormatter`.
**Confirm:** gadget chain (ysoserial / ysoserial.net / phpggc) or, minimally, prove the deserializer runs on attacker bytes.
**Band:** $$$–$$$$ (RCE-class). Library-rich; confirm a realistic untrusted-input caller.

## 5. SSRF (incl. cloud/IMDS)
**Where:** server fetches a user-supplied URL — webhooks, link-preview/unfurl, PDF/HTML render, image fetch, SSO metadata URL, "import from URL," SSRF via redirect.
**Signals:** JS `axios/fetch/got/request(userURL)`; Python `requests.get(userURL)`, `urllib`, `httpx`; Go `http.Get(userURL)`; PHP `file_get_contents($url)`, cURL with user URL; any HTML/PDF renderer (wkhtmltopdf, Puppeteer) fed user HTML/URL.
**Confirm:** OOB callback (Burp Collaborator/your DNS); escalate to cloud metadata `169.254.169.254` (AWS IMDSv1), GCP `metadata.google.internal` (needs `Metadata-Flavor` header), Azure IMDS; internal port scan; `file://`/`gopher://` where the client allows.
**Pitfalls:** allow-list bypass via DNS rebinding, decimal/octal/IPv6 encodings, `[::]`, redirect-to-internal, `@`-userinfo tricks. Check whether the client *follows redirects* (most do) — a public URL that 302s to `169.254.169.254` beats an allow-list.
**Payout reality — the loot ladder (only the top rungs pay; from disclosed corpus):** stolen internal token/header > reflected *internal* response body > metadata/localhost *content* > **distinct-error oracle** > timing port-scan > bare DNS/HTTP ping (this last alone is routinely closed Informative — "my server got a request" is not impact). Always capture *something from inside* the boundary.
- **Header-injection SSRF:** an endpoint that proxies on a user-controlled `Host`/URL can leak the *reverse-proxy's* injected auth header (e.g. `X-*-Access-Token`) to your listener — always diff the outbound request headers, not just whether it connected.
- **Blind → proof via error oracle:** when responses aren't reflected, paste the *distinct* error/timing for localhost vs a closed port vs `169.254.169.254` to prove internal reach; screenshot any internal app you actually rendered. That converts a blind SSRF from Informative to paid.
- **Escalate blind → credentials** with protocol smuggling: `file://`, `gopher://`, and Windows UNC `\\attacker\share` (SMB → NTLM-hash leak, as in Apache CVE-2024-38472).
**Band:** $$$–$$$$ when it reaches metadata/internal/credentials; $$ blind-with-oracle; ~N/A bare-ping-only.

## 6. Authorization — IDOR / BOLA / broken access control / multi-tenancy
**Where:** the single highest-EV, lowest-dup web class. Any handler taking an object/tenant id; multi-tenant SaaS isolation; admin-only routes; the **list/export/bulk** variants of an otherwise-scoped resource.
**Signals (read, don't just grep):** `findById(req.params.id)` / `Model.objects.get(pk=request.GET[...])` / `repo.findByX(name)` with **no owner/tenant predicate**; authz that checks the *caller's* role but loads the *target* by a global key; middleware applied to some routes but not a sibling; `tenantId` taken from the request body instead of the principal; mass-assignment that lets a user set `role`/`tenantId`/`isAdmin`.
**Confirm:** two accounts (or two tenants) — access A's object as B. **With a live instance, run the identity-diff matrix (`grey-box-dynamic-testing.md` §3): the same request under A / B / anon / stale, then classify — A-reads-B = IDOR, low-reads-high = priv-esc, works-with-no-auth = missing-auth (a *different* bug), stops-after-logout = the control is WORKING (NOT a bug, the FP that eats slots).** For tenant bugs, trace one resource through **create/read/update/delete/list/export** and find the path missing the tenant filter (canonical shape: user-management loads the target by global username while the resource controllers are correctly `(id, tenantId)`-scoped — the one unscoped lookup is the bug).
**Pitfalls:** UUIDs don't make it safe (they leak); "horizontal" (peer) vs "vertical" (privilege) — both count. Function-level access control (a hidden admin endpoint reachable by a normal user) is the vertical variant.
**Band:** $$–$$$$ (cross-tenant PII/takeover = critical). Scanners can't find these; humans must reason about the model.

## 7. Broken authentication / session / password-reset
**Where:** login, MFA, session lifecycle, "forgot password," account-link/unlink, email-change.
**Signals:** predictable/weak reset tokens (see §19 weak randomness); reset token not invalidated after use or not bound to the user; host-header poisoning in reset links (`Host: attacker` → poisoned link); response/redirect that leaks the token; OTP without rate-limit *and* without lockout (single-request logic flaw, not just volumetric); session fixation (session id not rotated on login); JWT/session not invalidated on logout/password-change; email-change without re-auth.
**Confirm:** end-to-end takeover of a second test account you own.
**Band:** $$$–$$$$ (ATO).

## 8. JWT / OAuth / SAML / OIDC flaws
**Where:** any token-based auth.
**Signals:** JWT `alg:none` accepted; `jwt.verify(token, key)` **without** an `algorithms:` allow-list (RS256→HS256 confusion using the public key as HMAC secret); secret weak/guessable; `kid` path-traversal/SQLi; missing `exp`/`aud`/`iss` checks. OAuth: `redirect_uri` not strictly validated (open redirect → code/token theft), missing/limp `state` (CSRF on the callback → account linking), `response_type=token` leaking via referrer, PKCE absent on public clients, authorization-code injection, scope upgrade. SAML: signature not verified / XML signature wrapping (XSW) / comment-truncation (`admin@company.com<!---->.evil.com` — C14N strips the comment *before* the signature digest so the sig covers the full string, but the app reads the text node only up to the comment = `admin@company.com`; canonical case CVE-2017-11428 Ruby-SAML), `IsPassive`/recipient confusion.
**Confirm:** forge/replay a token that the server accepts as another user.
**Band:** $$$–$$$$.

## 9. Prototype pollution (JS)
**Where:** recursive merge/clone/set of attacker-controlled JSON.
**Signals:** `_.merge`/`_.defaultsDeep`/`_.set`, `Object.assign` deep variants, `lodash.merge`, `deepmerge`, `set(obj, userPath, val)`, query-string parsers; `obj[a][b]=c` where `a` can be `__proto__`/`constructor`/`prototype`.
**Confirm:** pollute `({}).polluted` then show a *gadget* — DoS, property injection that flips an auth/`isAdmin` check, or chain to RCE/SSTI/XSS in the same app. A pollution with **no demonstrated gadget** is usually closed as informational — find the sink.
**Band:** $$–$$$$ (gadget-dependent).

## 10. XXE
**Where:** XML parsers with external entities enabled (often default-on in older libs).
**Signals:** PHP `simplexml_load_*`/`DOMDocument->loadXML` (pre-libxml2.9 or with `LIBXML_NOENT`); Python `xml.etree`/`lxml`/`minidom` without `defusedxml`; Java `DocumentBuilder`/SAX/XMLInputFactory without `disallow-doctype-decl`; .NET `XmlDocument` with a resolver. Also SVG/DOCX/XLSX upload (zip-of-XML), SOAP, SAML.
**Confirm:** file read via entity, or blind/OOB XXE (parameter entities → external DTD) when output isn't reflected. Often chains to SSRF.
**Band:** $$$.

## 11. Path traversal / LFI / zip-slip / arbitrary file write
**Where:** filename/path from user input joined to a base dir; archive extraction; template/include selection; file download/upload.
**Signals:** `../` reaching `open`/`readFile`/`sendFile`/`include`/`require`; `os.path.join(base, userName)` / `filepath.Join(dst, hdr.Name)` (zip-slip — `Clean` does NOT stop an *absolute* `hdr.Name` escaping, validate the joined result is within `dst`); `extractall(` (Python zip/tar slip); PHP `include`/`require`/`fopen` with input, `php://filter`, `phar://`; download endpoints echoing a path param.
**Confirm:** read `/etc/passwd` or app secrets; a bare `php://filter` *read* primitive escalates to **RCE with no upload and no writable file** via a PHP filter-chain (chained `iconv` conversions forge an in-memory PHP payload — Synacktiv 2022); the most-missed LFI escalation on PHP targets. For write, drop a file outside the intended dir (e.g. a build/SBOM tool that names an output file from an attacker-controlled manifest field — a target name like `../../../tmp/x` escaping via a path-join/`with_file_name`). Note the suffix/extension constraints honestly — arbitrary-*location* vs arbitrary-*content* matters for severity.
**Band:** $$–$$$$ (read of secrets / write→RCE = high).

## 12. Open redirect / URL-parse confusion
**Where:** `redirect`/`Location` from a user param; "next"/"returnUrl"/"callback".
**Signals:** `res.redirect(req.query.url)`, `header("Location: ".$_GET)`, `RedirectResponse(userUrl)`; naive validation startswith/contains a trusted host (`//evil.com`, `https:evil.com`, `trusted.com.evil.com`, `\/\/`, backslash tricks, `@`-userinfo).
**Confirm:** redirect off-domain. Low on its own; **chain** it — OAuth token theft (§8), SSRF (§5), or to bump a phishing report.
**Band:** $ alone; $$$ chained.

## 13. XSS & client-side
**Where:** reflected (input echoed), stored (persisted then rendered), DOM (client sink).
**Signals:** server: unescaped output — Blade `{!! !!}`, Django `|safe`/`mark_safe`, Jinja `|safe`, ERB `raw`/`html_safe`, React `dangerouslySetInnerHTML`, Angular `bypassSecurityTrust*`, Vue `v-html`. DOM: `innerHTML`/`outerHTML`/`document.write`/`insertAdjacentHTML`/`$(...).html()` (bundled **jQuery < 3.5.0** + `.html()`/`.append()` on attacker markup = CVE-2020-11022/11023 htmlPrefilter self-closing-tag DOM-XSS — grep the bundled version, a very common real-world root), `location`/`location.hash` → sink, `eval`/`setTimeout(str)`, `postMessage` handler without origin check, `window.name`. Other client-side: open `addEventListener('message')` with no `event.origin` check; DOM clobbering; `target=_blank` w/o `noopener` (reverse tabnabbing — low).
**Confirm:** script execution in the victim's origin; show impact (session/CSRF-token theft, action). Self-XSS alone is out of scope on most programs.
**Band:** $$ (reflected/DOM) – $$$ (stored, privileged context). Very scanner-camped; favor stored/DOM in complex SPAs where scanners are weak.

## 14. CSRF / SameSite / state-changing GET
**Where:** state-changing requests without anti-CSRF protection.
**Signals:** POST/PUT/DELETE with no CSRF token and `SameSite=None`/absent on the session cookie; state change via GET; CORS `Access-Control-Allow-Origin` reflecting the Origin **with** `Allow-Credentials:true` (CSRF-equivalent read). JSON endpoints that also accept `text/plain`/form content-types.
**Confirm:** cross-site form/`fetch` performs the action as the victim. Modern frameworks + SameSite=Lax defaults kill most classic CSRF — check the actual cookie attributes before claiming it.
**Band:** $–$$$ (impact-scaled).

## 15. Request smuggling / parser differentials / cache poisoning
**Where:** front-end proxy + back-end disagree on request boundaries; caches keyed wrong.
**Signals:** CL.TE/TE.CL/TE.TE handling differences; obscure headers reflected unkeyed into cached responses (web cache poisoning / cache deception); host-header injection; HTTP/2 downgrade desync. Mostly black-box, but the *config* (nginx/Apache/HAProxy/Varnish + app server) hints at it.
**Confirm:** Burp HTTP Request Smuggler; demonstrate a poisoned/queued response affecting another user.
**Band:** $$$–$$$$. Specialist class; requires an exact multi-hop parser/proxy model.

## 16. Race conditions / TOCTOU
**Where:** check-then-act on shared state without a lock/transaction — balance/credit, coupon/voucher redemption, invite/seat limits, "claim once," idempotency gaps, file create-then-chmod.
**Signals:** read-modify-write without DB transaction/row lock/atomic op; uniqueness enforced in app code not a DB constraint; `if exists … then create`.
**Confirm:** fire N concurrent requests (Burp single-packet attack / Turbo Intruder) → limit exceeded once (double-spend, multi-redeem).
**Band:** $$–$$$$ (financial = high). Require an authoritative state transition and captured effect.

## 17. Business-logic & workflow flaws
**Where:** the rules of the app, not a code sink — price/quantity manipulation, negative amounts, currency rounding, skipping a workflow step, replaying a one-time action, parameter tampering on multi-step flows, coupon stacking, free-trial abuse with real impact.
**Signals:** none greppable — read the domain. Ask "what invariant does this flow assume, and can I break it from the client?"
**Confirm:** end-to-end demonstration of the broken invariant (got the thing for less/free, escalated, bypassed a gate).
**Band:** $$–$$$$. Pure human edge; zero scanner overlap.

## 18. GraphQL-specific
**Where:** GraphQL endpoints.
**Signals:** introspection enabled in prod; field-level authz missing (object-level checked, field not); batching/aliasing to bypass rate-limits or brute-force (100 aliased `login` in one request); deeply-nested query DoS; mutation IDOR; `__schema` leaking internal types; injection through resolvers.
**Confirm:** introspect, then craft a query that reads/writes beyond your role, or a batched auth-bypass.
**Band:** $$–$$$$.

## 19. Secrets exposure & weak cryptography
**Where:** committed secrets; predictable tokens; misused crypto.
**Signals:**
- Secrets: API keys/tokens/private keys in repo, in git *history*, in force-pushed/deleted commits, in client bundles, in `.env`/CI logs/Docker layers. Tools: trufflehog, gitleaks, `git log -p`, GitHub code search.
- Weak randomness for security tokens: `Math.random()`, `mt_rand/rand/uniqid` (PHP), `random.` (Python — must be `secrets`), `math/rand` (Go — must be `crypto/rand`). Used for reset tokens / session ids / API keys → predictable → ATO.
- Crypto misuse: ECB mode, static/hardcoded IV or key, non-constant-time secret compare (`==`/`String.equals`/`bytes.Equal` instead of `hmac.compare_digest`/`subtle.ConstantTimeCompare`/`hash_equals`), MD5/SHA1 for passwords (vs bcrypt/argon2), missing signature verification, padding oracles, JWT secrets (→ §8).
**Confirm:** for a live secret, *do not* use it against prod — report the exposure and (if policy allows) prove validity minimally/with the program's blessing. For weak tokens, demonstrate predictability/recovery.
**Band:** $–$$$$ (a live high-priv key or predictable reset token = critical; an expired/test key = low/N/A).

---

## How to use this file in the loop

1. Select the class whose primitive exists in the recorded invariant and architecture.
2. Use that class's signals to locate relevant enforcement points, not to generate findings directly.
3. For each hit, trace to a reachable attacker source and confirm with the class's "Confirm" method.
4. Map the reproduced capability to the band, then score honestly (`methodology-and-targeting.md` §6). Generic web classes are highly automated on mature programs; prefer product-specific authz, identity, state, logic, race, parser, or deserialization invariants when the architecture supports them.
