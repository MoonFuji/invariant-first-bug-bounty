# Bug-Class Taxonomy — analysis and controlled-validation patterns

This file maps 19 bug classes to the architecture where each primitive lives, source/sink signals, controlled confirmation methods, false-positive checks, and realistic impact. Load only the entries relevant to the security invariant and enforcement path already recorded in `candidate.json`; these are investigative possibilities, not a checklist.

In `SOURCE_ONLY`, reproduce sensitive effects with controlled local equivalents. A cloud metadata service, internal admin service, credential-bearing endpoint, sensitive system file, or another person's data is an **impact model**, not an instruction to contact or retrieve it. In `PROGRAM_HOSTED`, perform only the actions explicitly permitted by current program rules. Preserve the distinction between confirming a primitive and demonstrating its strongest authorized consequence.

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
20. Cross-cutting analysis lenses (authz matrix · state/concurrency · cross-service taint · fail-open · footguns)

Impact bands are rough public-program patterns; demonstrated capability and program policy matter more than the label.

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
**Confirm:** in a disposable local environment, use the minimum syntax needed to create a unique benign marker or produce a short deterministic delay; verify against a known-negative input. Do not use external callbacks when a local side effect is sufficient.
**Band:** $$$–$$$$ (often RCE).

## 3. Code injection / SSTI
**Where:** templating engines fed user input as *template* not *data*; `eval`-family.
**Signals:** Python `render_template_string(`, `Template(user).render(`, Jinja `{{ }}` from input, `eval(`/`exec(`; JS `eval(`, `new Function(`, `vm.runInNewContext`, template libs (Handlebars/Pug/EJS) compiling user strings; Ruby ERB; Java/Spring SpEL `#{}`, Thymeleaf, Velocity, FreeMarker; Go `text/template`.Parse(user).
**Confirm:** begin with a harmless arithmetic expression such as `${7*7}`/`{{7*7}}`/`#{7*7}` and fingerprint the engine from its result. `{{7*'7'}}` producing `7777777` suggests Jinja2 string repetition, while `49` suggests Twig numeric coercion; `${7*7}` can identify FreeMarker, Velocity, or Mako families. If code execution is required to establish impact, use a unique marker in a disposable local environment rather than an external connection or sensitive command.
**Band:** $$$–$$$$.

## 4. Insecure deserialization
**Where:** untrusted bytes into a native object deserializer.
**Signals:** PHP `unserialize(` (+ POP-chain gadgets; `phar://` stream triggers it), Laravel `decrypt()` misuse; Python `pickle.load(s)`, `yaml.load(` without `SafeLoader`, `yaml.unsafe_load`, `jsonpickle`, `dill`, `shelve`, `numpy.load(allow_pickle=True)`; JS `node-serialize`, untrusted input to a deserializer with `_$$ND_FUNC$$_`; Java `ObjectInputStream.readObject`, XMLDecoder, fastjson/Jackson polymorphic typing; Ruby `Marshal.load`, YAML `Psych.load`; .NET `BinaryFormatter`.
**Confirm:** first prove that untrusted bytes reach the deserializer. When a gadget is required to establish impact, use a controlled local environment and a harmless deterministic side effect; known gadget-chain tools are analysis resources, not instructions to run against hosted systems.
**Band:** $$$–$$$$ (RCE-class). Library-rich; confirm a realistic untrusted-input caller.

## 5. SSRF (incl. cloud/IMDS)
**Where:** server fetches a user-supplied URL — webhooks, link-preview/unfurl, PDF/HTML render, image fetch, SSO metadata URL, "import from URL," SSRF via redirect.
**Signals:** JS `axios/fetch/got/request(userURL)`; Python `requests.get(userURL)`, `urllib`, `httpx`; Go `http.Get(userURL)`; PHP `file_get_contents($url)`, cURL with user URL; any HTML/PDF renderer (wkhtmltopdf, Puppeteer) fed user HTML/URL.
**Confirm:** use two controlled local listeners: one permitted baseline destination and one destination representing the restricted boundary. Record the outbound request, redirects, headers, response reflection, and negative controls. In `PROGRAM_HOSTED`, use only a researcher-owned listener explicitly permitted by the program.
**Pitfalls:** allow-list bypass families include DNS changes, alternate IP encodings, IPv6 forms, redirects, and user-info parsing differences. Check redirect behavior with a controlled redirector that points to the local restricted listener; treat real metadata addresses as impact models.
**Impact models:** restricted service content or server-held authentication material > reflected restricted response > demonstrated access to a protected destination > reliable reachability oracle > timing-only inference > bare callback. Under `SOURCE_ONLY`, model metadata services, localhost services, internal ports, credential-bearing responses, and alternate protocols with controlled listeners and canary values.
- **Architecture-specific impact knowledge:** AWS IMDSv1 uses the link-local metadata address; GCP metadata normally requires `Metadata-Flavor`; Azure has its own metadata contract. Preserve these distinctions when reasoning about production relevance, but reproduce them with a local metadata-shaped service in `SOURCE_ONLY`.
- **Header-injection SSRF:** an endpoint that proxies on a user-controlled `Host`/URL can leak the *reverse-proxy's* injected auth header (e.g. `X-*-Access-Token`) to your listener — always diff the outbound request headers, not just whether it connected.
- **Blind proof via controlled oracle:** when responses are not reflected, compare distinct errors or timing across a responding local listener, a closed local port, and the controlled restricted listener. Interleave repeated trials and retain negative controls.
- **Protocol impact models:** `file://`, `gopher://`, and Windows UNC handling can change the reachable capability, including credential relay in some architectures. Establish protocol acceptance locally; do not solicit credentials or connect to third-party systems.
**Band:** $$$–$$$$ when it reaches metadata/internal/credentials; $$ blind-with-oracle; ~N/A bare-ping-only.

## 6. Authorization — IDOR / BOLA / broken access control / multi-tenancy
**Where:** the single highest-EV, lowest-dup web class. Any handler taking an object/tenant id; multi-tenant SaaS isolation; admin-only routes; the **list/export/bulk** variants of an otherwise-scoped resource.
**Signals (read, don't just grep):** `findById(req.params.id)` / `Model.objects.get(pk=request.GET[...])` / `repo.findByX(name)` with **no owner/tenant predicate**; authz that checks the *caller's* role but loads the *target* by a global key; middleware applied to some routes but not a sibling; `tenantId` taken from the request body instead of the principal; mass-assignment that lets a user set `role`/`tenantId`/`isAdmin`.
**Confirm:** use two accounts or tenants you own in a local deployment, or in `PROGRAM_HOSTED` when explicitly permitted. Run the same request under A / B / anonymous / stale states, then classify the capability delta. For tenant bugs, trace one owned test resource through create/read/update/delete/list/export and identify the path missing the tenant filter.
**Pitfalls:** UUIDs don't make it safe (they leak); "horizontal" (peer) vs "vertical" (privilege) — both count. Function-level access control (a hidden admin endpoint reachable by a normal user) is the vertical variant.
**Band:** $$–$$$$ (cross-tenant PII/takeover = critical). Scanners can't find these; humans must reason about the model.

## 7. Broken authentication / session / password-reset
**Where:** login, MFA, session lifecycle, "forgot password," account-link/unlink, email-change.
**Signals:** predictable/weak reset tokens (see §19 weak randomness); reset token not invalidated after use or not bound to the user; host-header poisoning in reset links (`Host: attacker` → poisoned link); response/redirect that leaks the token; OTP without rate-limit *and* without lockout (single-request logic flaw, not just volumetric); session fixation (session id not rotated on login); JWT/session not invalidated on logout/password-change; email-change without re-auth.
**Confirm:** reproduce the unauthorized authentication-state transition using a second test account you own, locally by default or in `PROGRAM_HOSTED` when permitted.
**Band:** $$$–$$$$ (ATO).

## 8. JWT / OAuth / SAML / OIDC flaws
**Where:** any token-based auth.
**Signals:** JWT `alg:none` accepted; `jwt.verify(token, key)` **without** an `algorithms:` allow-list (RS256→HS256 confusion using the public key as HMAC secret); secret weak/guessable; `kid` path-traversal/SQLi; missing `exp`/`aud`/`iss` checks. OAuth: `redirect_uri` not strictly validated (open redirect → code/token theft), missing/limp `state` (CSRF on the callback → account linking), `response_type=token` leaking via referrer, PKCE absent on public clients, authorization-code injection, scope upgrade. SAML: signature not verified / XML signature wrapping (XSW) / comment-truncation (`admin@company.com<!---->.evil.com` — C14N strips the comment *before* the signature digest so the sig covers the full string, but the app reads the text node only up to the comment = `admin@company.com`; canonical case CVE-2017-11428 Ruby-SAML), `IsPassive`/recipient confusion.
**Confirm:** in a controlled environment, show that a modified or replayed token is accepted as an owned comparison identity despite the intended token invariant.
**Band:** $$$–$$$$.

## 9. Prototype pollution (JS)
**Where:** recursive merge/clone/set of attacker-controlled JSON.
**Signals:** `_.merge`/`_.defaultsDeep`/`_.set`, `Object.assign` deep variants, `lodash.merge`, `deepmerge`, `set(obj, userPath, val)`, query-string parsers; `obj[a][b]=c` where `a` can be `__proto__`/`constructor`/`prototype`.
**Confirm:** in a disposable local environment, demonstrate pollution and a consequential application gadget using owned test state or a benign marker. Pollution without a reachable security effect is not enough.
**Band:** $$–$$$$ (gadget-dependent).

## 10. XXE
**Where:** XML parsers with external entities enabled (often default-on in older libs).
**Signals:** PHP `simplexml_load_*`/`DOMDocument->loadXML` (pre-libxml2.9 or with `LIBXML_NOENT`); Python `xml.etree`/`lxml`/`minidom` without `defusedxml`; Java `DocumentBuilder`/SAX/XMLInputFactory without `disallow-doctype-decl`; .NET `XmlDocument` with a resolver. Also SVG/DOCX/XLSX upload (zip-of-XML), SOAP, SAML.
**Confirm:** use a benign local canary file or a controlled local listener to establish entity expansion. Treat sensitive file access and reachability of protected services as impact models unless reproduced inside the disposable environment.
**Band:** $$$.

## 11. Path traversal / LFI / zip-slip / arbitrary file write
**Where:** filename/path from user input joined to a base dir; archive extraction; template/include selection; file download/upload.
**Signals:** `../` reaching `open`/`readFile`/`sendFile`/`include`/`require`; `os.path.join(base, userName)` / `filepath.Join(dst, hdr.Name)` (zip-slip — `Clean` does NOT stop an *absolute* `hdr.Name` escaping, validate the joined result is within `dst`); `extractall(` (Python zip/tar slip); PHP `include`/`require`/`fopen` with input, `php://filter`, `phar://`; download endpoints echoing a path param.
**Confirm:** place a unique benign canary outside the intended base directory in a disposable environment, then prove unauthorized read or write of that canary. Treat system files, application secrets, PHP filter-chain code execution, and writes to executable locations as impact models unless the same consequence must be reproduced locally to establish severity. A PHP `php://filter` read primitive can sometimes reach code execution through chained `iconv` conversions without an upload or writable file; evaluate that architecture locally rather than erasing it from the impact analysis. Note suffix and extension constraints honestly: arbitrary location and arbitrary content are different capabilities.
**Band:** $$–$$$$ (read of secrets / write→RCE = high).

## 12. Open redirect / URL-parse confusion
**Where:** `redirect`/`Location` from a user param; "next"/"returnUrl"/"callback".
**Signals:** `res.redirect(req.query.url)`, `header("Location: ".$_GET)`, `RedirectResponse(userUrl)`; naive validation startswith/contains a trusted host (`//evil.com`, `https:evil.com`, `trusted.com.evil.com`, `\/\/`, backslash tricks, `@`-userinfo).
**Confirm:** redirect off-domain. Low on its own; **chain** it — OAuth token theft (§8), SSRF (§5), or to bump a phishing report.
**Band:** $ alone; $$$ chained.

## 13. XSS & client-side
**Where:** reflected (input echoed), stored (persisted then rendered), DOM (client sink).
**Signals:** server: unescaped output — Blade `{!! !!}`, Django `|safe`/`mark_safe`, Jinja `|safe`, ERB `raw`/`html_safe`, React `dangerouslySetInnerHTML`, Angular `bypassSecurityTrust*`, Vue `v-html`. DOM: `innerHTML`/`outerHTML`/`document.write`/`insertAdjacentHTML`/`$(...).html()` (bundled **jQuery < 3.5.0** + `.html()`/`.append()` on attacker markup = CVE-2020-11022/11023 htmlPrefilter self-closing-tag DOM-XSS — grep the bundled version, a very common real-world root), `location`/`location.hash` → sink, `eval`/`setTimeout(str)`, `postMessage` handler without origin check, `window.name`. Other client-side: open `addEventListener('message')` with no `event.origin` check; DOM clobbering; `target=_blank` w/o `noopener` (reverse tabnabbing — low).
**Confirm:** demonstrate browser execution with uniquely tagged owned test data. Use a benign DOM marker or an authorized action on an owned comparison account; treat session material or another person's data as impact models, not proof artifacts.
**Band:** $$ (reflected/DOM) – $$$ (stored, privileged context). Very scanner-camped; favor stored/DOM in complex SPAs where scanners are weak.

## 14. CSRF / SameSite / state-changing GET
**Where:** state-changing requests without anti-CSRF protection.
**Signals:** POST/PUT/DELETE with no CSRF token and `SameSite=None`/absent on the session cookie; state change via GET; CORS `Access-Control-Allow-Origin` reflecting the Origin **with** `Allow-Credentials:true` (CSRF-equivalent read). JSON endpoints that also accept `text/plain`/form content-types.
**Confirm:** in a local environment, or `PROGRAM_HOSTED` when permitted, show that a cross-site form or request changes state in an account you own. Check actual cookie attributes and negative controls before claiming impact.
**Band:** $–$$$ (impact-scaled).

## 15. Request smuggling / parser differentials / cache poisoning
**Where:** front-end proxy + back-end disagree on request boundaries; caches keyed wrong.
**Signals:** CL.TE/TE.CL/TE.TE handling differences; obscure headers reflected unkeyed into cached responses (web cache poisoning / cache deception); host-header injection; HTTP/2 downgrade desync. Mostly black-box, but the *config* (nginx/Apache/HAProxy/Varnish + app server) hints at it.
**Confirm:** reproduce the parser disagreement across a controlled local proxy/backend chain and use distinct canary requests to demonstrate response misrouting or cache contamination. Do not involve another person's traffic or shared cache.
**Band:** $$$–$$$$. Specialist class; requires an exact multi-hop parser/proxy model.

## 16. Race conditions / TOCTOU
**Where:** check-then-act on shared state without a lock/transaction — balance/credit, coupon/voucher redemption, invite/seat limits, "claim once," idempotency gaps, file create-then-chmod.
**Signals:** read-modify-write without DB transaction/row lock/atomic op; uniqueness enforced in app code not a DB constraint; `if exists … then create`.
**Confirm:** against a disposable local resource, send controlled concurrent requests and verify the authoritative state exceeds the invariant once. In `PROGRAM_HOSTED`, concurrency testing requires explicit permission and owned disposable state.
**Band:** $$–$$$$ (financial = high). Require an authoritative state transition and captured effect.

## 17. Business-logic & workflow flaws
**Where:** the rules of the app, not a code sink — price/quantity manipulation, negative amounts, currency rounding, skipping a workflow step, replaying a one-time action, parameter tampering on multi-step flows, coupon stacking, free-trial abuse with real impact.
**Signals:** none greppable — read the domain. Ask "what invariant does this flow assume, and can I break it from the client?"
**Confirm:** demonstrate the broken invariant end to end using controlled local state or explicitly permitted owned program data; record the capability gained without creating financial loss or consuming another person's resources.
**Band:** $$–$$$$. Pure human edge; zero scanner overlap.

## 18. GraphQL-specific
**Where:** GraphQL endpoints.
**Signals:** introspection enabled in prod; field-level authz missing (object-level checked, field not); batching/aliasing to bypass rate-limits or brute-force (100 aliased `login` in one request); deeply-nested query DoS; mutation IDOR; `__schema` leaking internal types; injection through resolvers.
**Confirm:** use owned comparison identities and uniquely tagged test records to show a field or mutation crosses the intended role boundary. Do not use batching for credential guessing or volumetric testing.
**Band:** $$–$$$$.

## 19. Secrets exposure & weak cryptography
**Where:** committed secrets; predictable tokens; misused crypto.
**Signals:**
- Secrets: API keys/tokens/private keys in repo, in git *history*, in force-pushed/deleted commits, in client bundles, in `.env`/CI logs/Docker layers. Tools: trufflehog, gitleaks, `git log -p`, GitHub code search.
- Weak randomness for security tokens: `Math.random()`, `mt_rand/rand/uniqid` (PHP), `random.` (Python — must be `secrets`), `math/rand` (Go — must be `crypto/rand`). Used for reset tokens / session ids / API keys → predictable → ATO.
- Crypto misuse: ECB mode, static/hardcoded IV or key, non-constant-time secret compare (`==`/`String.equals`/`bytes.Equal` instead of `hmac.compare_digest`/`subtle.ConstantTimeCompare`/`hash_equals`), MD5/SHA1 for passwords (vs bcrypt/argon2), missing signature verification, padding oracles, JWT secrets (→ §8).
**Confirm:** for a live secret, *do not* use it against prod — report the exposure and (if policy allows) prove validity minimally/with the program's blessing. For weak tokens, demonstrate predictability/recovery.
**Band:** $–$$$$ (a live high-priv key or predictable reset token = critical; an expired/test key = low/N/A).

## 20. Cross-cutting analysis lenses
These are systematic *methods* applied on top of the single-class signals above, ported from specialist audit roles. Use them when the class alone under-covers the surface.

**20A. Authorization guard matrix (deepens §6).** Enumerate *every* request-handling boundary, not just HTTP routes: gRPC methods, GraphQL resolvers, WebSocket handlers, queue/topic consumers, cron jobs, CLI subcommands, OAuth/webhook/payment callbacks. For each, extract guards across four layers — (1) declarative (decorators/middleware/annotations); (2) in-body (`current_user`, `.can()/.authorize()`, ownership filter `owner=`, tenant scope `org_id=`); (3) router composition; (4) hidden control channels (`X-User-*`, `X-Tenant-*`, `X-Original-URL`, `X-HTTP-Method-Override` trusted from an external request). Build a matrix `boundary | expected scope | actual guard | gap`, deriving expected scope from conventions (`owner_id` → self, `organization_id` → org). **Outlier heuristic:** if 90%+ of a sibling handler group shares a guard and one lacks it, flag the outlier — copy-paste omission is the highest-signal authz bug. Separately extract the **unauthenticated surface** (what an anonymous caller reaches) and label each entry by-design / missing-guard / middleware-gap; a sink reachable pre-auth is one severity band higher.

**20B. State & concurrency enumeration (deepens §16).** Before hunting races, list the state-holding entities: lifecycle columns (`state`, `*_at`, `is_*`), value counters (`balance`, `credit`, `quota`, `tokens`, `inventory` — a TOCTOU here is a double-spend), idempotency infra (`idempotency_key`, `nonce`, `jti`, `event_id`), and transition functions. Then, beyond the §16 check-then-act pattern: state-machine violations (can a transition run *backward* from a terminal state, cancelled→pending?), idempotency failures where **the provider's own retry is the attacker model** (a payment/webhook handler with no idempotency infra is itself a finding), replay windows on signed tokens (jti/exp/nbf), and **client-provided timestamps** (the attacker controls the clock). Never emit "potential race" without naming the exact contended rows and the concurrent flow.

**20C. Cross-service taint (multi-service targets).** Single-repo tracing misses bugs that cross a service edge — HTTP/gRPC/queue/**shared-DB write**/file/IPC. Propagate taint across the edge and look for: *sanitize-for-wrong-sink* (a producer HTML-escapes but the consumer uses the value in SQL/shell — correct for the producer's sink, wrong for the consumer's); *false trust marker* (a producer tags data `validated=True` / writes it to a "trusted" table, the consumer skips its own check, and an attacker reaches the producer via a *different* entry so the marker carries tainted data); *write-driven injection through shared storage* (producer writes attacker data to a column, consumer reads it into a SQL concat / shell / template / eval); queue-message deserialization without source authentication; an "internal-only" endpoint that is in fact externally reachable.

**20D. Fail-open vs fail-secure (insecure defaults).** `SECRET = env.get('KEY') or 'default'` is fail-open (critical); `SECRET = env['KEY']` (crashes if unset) is fail-secure. On a fallback, VERIFY by tracing the path — does the app *run* with the default or crash? — then CONFIRM whether a real production config supplies the value (moot) or not. Grep: `getenv(...) or ['"]`, `process.env.X || ['"]`, `ENV.fetch(..., default:)`, `AUTH_REQUIRED = env.get(X,'false')`, CORS `*` + credentials, `DEBUG=true` default, `0777`. Exclude test/example/dev-only files (they are not shipped).

**20E. Misuse-resistance footgun lens (deepens §7/§8/§19).** Run three adversary models against each security choice point: *the Scoundrel* (controls config), *the Lazy dev* (copies the first example), *the Confused dev* (swaps params/keys). Beyond the crypto/auth items already in §8/§19, watch for the ones those sections omit: **bcrypt 72-byte silent truncation** (long passwords collide on the first 72 bytes), PHP `strcmp(array, …)` returning NULL → `NULL == 0` true → auth bypass, `hash($algorithm, …)` accepting a caller-chosen weak algo (downgrade), and **unvalidated constructor params** ("time bombs" — a secure default does not protect a bad caller; validate `algo`/`cipher`/`*_lifetime`/`*_timeout`/`host`/`*_url` against an allowlist + bounds).

---

## How to use this file in the loop

1. Select the class whose primitive exists in the recorded invariant and architecture.
2. Use that class's signals to locate relevant enforcement points, not to generate findings directly.
3. For each hit, trace to a reachable attacker source and confirm with the class's "Confirm" method.
4. Map the reproduced capability to the band, then score honestly (`methodology-and-targeting.md` §6). Generic web classes are highly automated on mature programs; prefer product-specific authz, identity, state, logic, race, parser, or deserialization invariants when the architecture supports them.
