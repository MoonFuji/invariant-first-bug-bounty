# Emerging Surfaces & Force-Multiplier Techniques (2026)

The taxonomy in `bug-class-taxonomy.md` describes bug primitives. This file describes newer architectural surfaces and techniques such as fix-diffing, semantic variant analysis, and secret scanning. Load a section only after the target model shows that its boundary or primitive exists.

## Contents
- 1. Emerging surfaces — AI/LLM/MCP · CI/CD · supply-chain · cloud/IAM · modern auth · protocol/parser
- 2. Force-multiplier techniques — CVE-diff · incomplete-fix · variant analysis · secret-scanning · fresh-program windfall
- 3. Hot vs saturated — the 2026 read

---

## 1. Emerging surfaces

### 1A. AI / LLM / MCP applications
The fastest-growing surface, and most defenders haven't caught up. Dedicated programs exist (huntr's AI/ML lane; many vendors added LLM scope). Classes that actually pay (impact, not "the model said a bad word"):
- **Prompt injection with a real sink** — indirect injection (poisoned web page / doc / email the agent ingests) that drives a *consequential* tool call: exfiltrates data, sends a request, runs code, modifies state. The payout is in the downstream action, not the injection itself.
- **Tool/function-calling abuse** — an LLM agent wired to tools (shell, HTTP, file, DB) where crafted input makes it call a dangerous tool with attacker params. This is RCE/SSRF/IDOR *through* the agent.
- **MCP server vulnerabilities** — MCP servers are normal servers with a tool API: command injection in a tool that shells out, path traversal in a file tool, SSRF in a fetch tool, missing authz between tools, secret leakage through tool output. Audit them exactly like any backend (taxonomy §2/§5/§11) — most are young and lightly reviewed.
- **Unsafe output handling** — LLM output rendered as HTML (→XSS), passed to `eval`/a shell (→RCE), or used in a SQL query (→SQLi). The model is just another untrusted source.
- **RAG / vector-store injection**, training-data/file-upload poisoning, **insecure model deserialization** (pickle-backed model files → taxonomy §4; this is a live huntr lane).
- **Sandbox escapes** in code-interpreter / "run this Python" agent features.
**Confabulation guard (the #1 LLM-report killer):** the model will invent a plausible "system prompt" or "other user's data" that is not real. Never claim a prompt/data leak from free-form output — anchor to a *non-guessable* known value (a real tool name, internal URL, tenant-ID format, or a guardrail phrase you already saw leak in an error) and require a **reproducible echo of that anchor**. Prompt injection on its own is Informational; score by the sink it reaches.

**Avoid the slop:** jailbreaks, refusals, hallucinations, and "alignment" opinions with no security impact are not bounties. Always tie to a CIA-triad consequence.

### 1B. CI/CD & GitHub Actions (read `.github/workflows/*.yml`)
Pipelines run with high privilege and secrets; misconfig is common and greppable.
- **`pull_request_target` + checkout of PR head ("pwn request")** — runs *trusted* workflow with *fork* code/secrets in scope → secret theft / repo compromise.
- **Script injection** — `${{ github.event.issue.title }}` / `…pull_request.title` / `…comment.body` / branch name interpolated directly into a `run:` block → command injection in the runner. Fix is env-indirection; the bug is direct interpolation.
- **Over-broad `permissions:`**, `GITHUB_TOKEN` write where read suffices, secrets passed to fork PRs, self-hosted runner reuse, cache poisoning, unpinned third-party actions (`uses: foo/bar@main`) → supply-chain.
- Look in the org's *public* repos even when the bounty is for the product — a workflow that leaks a deploy token is in-scope impact.

### 1C. Supply-chain
- **Dependency confusion** — an internal package name not claimed on the public registry; publish it and the build pulls yours. Check `package.json`/`requirements.txt`/`pom.xml` for internal-looking names not on npm/PyPI.
- **Typosquat / install-script abuse**, postinstall hooks, malicious-maintainer patterns (report the *vector* in scope; never publish actual malware).
- **Lockfile / integrity gaps**, unpinned base images, compromised-action propagation (the 2025 worm-style Actions incidents).
- **n-day→0-day fork propagation** — a fix landed upstream but downstream forks/vendored copies still ship the bug (ties to §2).

### 1D. Cloud / IAM / infra-as-code
- **SSRF→metadata** is the bridge from app to cloud (taxonomy §5): IMDSv1 creds, GCP/Azure metadata.
- **IaC misconfig** in scope: public S3/buckets, over-permissive IAM (`*:*`), security groups open to `0.0.0.0/0`, secrets in Terraform state, exposed `.git`/`.env`/`/actuator`/`/debug`.
- **Subdomain takeover** — dangling DNS (CNAME to a deprovisioned SaaS) — fast recon win on broad-scope programs.
- **Container/k8s** — exposed kubelet/dashboard, SSRF to internal services, secrets in env.

### 1E. Modern authentication (deep dive of taxonomy §8)
- **OAuth/OIDC**: lax `redirect_uri` (path/subdomain/`%2F`/`#` tricks → code theft), missing/replayable `state` (login-CSRF / account-linking takeover), PKCE missing on public clients, code injection, `response_mode` leaks, mix-up attacks across multiple IdPs.
- **JWT**: `alg:none`, RS256→HS256 confusion, weak HMAC secret, `kid` injection (path/SQL), missing `aud`/`iss`/`exp`.
- **SAML**: XML signature wrapping (XSW), comment-truncation in NameID, unsigned-assertion acceptance, recipient/audience confusion.
- **WebAuthn/passkeys, magic links, OTP**: link not single-use/expiring, OTP without lockout (logic, not volumetric), cross-device flow confusion.

### 1F. Protocol & parser differentials
- **HTTP request smuggling / desync** (taxonomy §15), HTTP/2 downgrade, **web cache poisoning / deception**.
- **Parser differentials** — two components parse the same input differently (URL parser vs allow-list → SSRF bypass; JSON dup-key; charset/Unicode normalization; multipart boundary confusion). High-skill, low-competition.

---

## 2. Force-multiplier techniques

### 2A. CVE / patch diffing
A freshly-published fix is a map to where the dangerous code is and what the author believed they fixed.
- Pull the fix commit/PR (GitHub, the advisory's "patched in" link). Read the diff, not the prose.
- Ask: **what exactly did this guard block, and what does it still let through?** Sanitizers are often incomplete.
- This is the cheapest fresh-bug source because the hard part (locating the sink) is done for you.

### 2B. Incomplete-fix hunting
- The patch fixes the reported payload but not a *class* of payloads (e.g. blocks `../` but not `..\\` or URL-encoded `%2e%2e`; blocks one IMDS IP but not IPv6/decimal).
- The patch fixes one *entry point* but the vulnerable helper has other callers (→ 2C variant analysis).
- The patch is on `main` but **not released**, or released but **not back-ported** to LTS/older branches that are still in scope (n-day). A still-present sink at the released artifact's HEAD is reportable even if `main` was "fixed."

### 2C. Variant analysis
Turn one confirmed bug into a query and sweep for siblings.
- Write a **Semgrep** rule (or CodeQL query) for the pattern, run it across the repo and the whole org's repos.
- Example: confirmed an authz check missing on `updateUser` → grep every handler that loads a target by a global key without a tenant predicate (this routinely yields 3–5 sibling endpoints from one root cause).
- Variants are often *not* duplicates of the original report and pay separately or raise severity (systemic finding).

### 2D. Secret-scanning recon
- **trufflehog** / **gitleaks** across repos AND full git history.
- **Force-pushed / deleted commits** ("oops commit"): a secret committed then force-pushed away is still reachable via the GitHub events API / commit SHA — `mcp__plugin_github_github__run_secret_scanning` and dangling-commit enumeration find these.
- Client bundles, source maps, Docker image layers, CI logs, public Postman/Swagger.
- Validate a found secret *minimally and within policy* — never use a live prod credential to pivot; report the exposure.

### 2E. Fresh-program / new-scope windfall
- Diff `github.com/arkadiyt/bounty-targets-data` over time (it aggregates HackerOne/Bugcrowd/Intigriti/YWH scopes). A newly-added asset or newly-launched program has the largest untouched reserve — be first.
- `bbscope` to pull structured scope; subscribe to launch notifications. The freshness principle (reserves are largest at launch, decay with age) is *the* highest-leverage targeting move.

### 2F. Tooling that scales a code audit
- **Semgrep** (fast, writeable rules, great for variant analysis) and **CodeQL** (deep dataflow/taint, best for source→sink across a big codebase) on the cloned repo.
- Language-native: `gosec`, `bandit` (Python), `brakeman` (Rails), `phpcs`/`psalm` taint, `npm audit`/`osv-scanner` for known-CVE deps in scope.
- Use these for the *first pass* (sink discovery), then human-reason the authz/logic/race classes the tools can't see. Tools find injection-shaped bugs; you find the reasoning bugs that pay more and dup less.

---

## 3. Hot vs saturated — the 2026 read

**Architecture signals worth inspecting when present:**
- AI/LLM/MCP with a real sink — defenders behind, programs young.
- CI/CD & GitHub Actions misconfig — greppable, common, under-reported on product programs.
- Authorization / multi-tenant / business-logic / race — scanners and bots structurally can't find these; the human edge.
- Parser differentials & smuggling — high skill floor keeps competition thin.
- Fresh programs / newly-added scope — the reserve play.

**Saturated / low-EV (avoid unless the target is fresh or you have a real chain):**
- Reflected XSS / classic SQLi / open redirect on mature, scanned web programs — every bot runs these.
- Missing-header / no-rate-limit / self-XSS / theoretical-no-impact — usually OOS or N/A; they cost Signal.
- Hardened security-core libraries (crypto, auth SDKs, init systems) audited to death — they return repeated clean passes; the win is usually a *less-scrutinized tool*, not the hardened core.

**Ecosystem note:** automated low-quality submissions make proof, ownership, and honest scope more important than report volume. Lead with the exact causal trace and accepted proof artifact; preserve a non-reportable verdict when a gate fails.
