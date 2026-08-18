# Emerging Surfaces & Force-Multiplier Techniques (2026)

The taxonomy in `bug-class-taxonomy.md` describes bug primitives. This file describes newer architectural surfaces and techniques such as fix-diffing, semantic variant analysis, and secret scanning. Load a section only after the target model shows that its boundary or primitive exists.

## Contents
- 1. Emerging surfaces — AI/LLM/MCP · CI/CD · supply-chain · cloud/IAM · modern auth · protocol/parser · AI-agent CI actions
- 2. High-leverage techniques — CVE-diff · incomplete-fix · variant analysis · secret-scanning · recently expanded scope · tooling · history mining
- 3. Hot vs saturated — the 2026 read

---

## 1. Emerging surfaces

### 1A. AI / LLM / MCP applications
This is a rapidly changing surface with dedicated program coverage in some venues. Impact patterns that programs may accept require a consequential boundary failure, not merely undesirable model output:
- **Prompt injection with a real sink** — indirect injection (poisoned web page / doc / email the agent ingests) that drives a *consequential* tool call: exfiltrates data, sends a request, runs code, modifies state. The payout is in the downstream action, not the injection itself.
- **Tool/function-calling boundary failure** — an LLM agent wired to tools (shell, HTTP, file, DB) where crafted input causes a security-sensitive tool call with untrusted parameters. This is RCE/SSRF/IDOR *through* the agent.
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
- Public organization repositories can provide architectural context, but test or report them only when the program scope or disclosure policy covers the repository and affected asset.

### 1C. Supply-chain
- **Dependency confusion** — an internal package name can resolve to an unintended public package. Confirm resolution with a private local registry or package-manager dry run; do not claim or publish a package name used by another organization.
- **Typosquat / install-script abuse**, postinstall hooks, malicious-maintainer patterns (report the *vector* in scope; never publish actual malware).
- **Lockfile / integrity gaps**, unpinned base images, compromised-action propagation (the 2025 worm-style Actions incidents).
- **n-day→0-day fork propagation** — a fix landed upstream but downstream forks/vendored copies still ship the bug (ties to §2).

### 1D. Cloud / IAM / infra-as-code
- **SSRF→metadata** is the bridge from app to cloud (taxonomy §5): IMDSv1 creds, GCP/Azure metadata.
- **IaC misconfig** in scope: public S3/buckets, over-permissive IAM (`*:*`), security groups open to `0.0.0.0/0`, secrets in Terraform state, exposed `.git`/`.env`/`/actuator`/`/debug`.
- **Subdomain takeover** — dangling DNS to a deprovisioned service can create an ownership boundary failure. Verify provider behavior and program authorization before attempting any resource claim.
- **Container/k8s** — exposed kubelet/dashboard, SSRF to internal services, secrets in env.

### 1E. Modern authentication (deep dive of taxonomy §8)
- **OAuth/OIDC**: lax `redirect_uri` (path/subdomain/`%2F`/`#` tricks → code theft), missing/replayable `state` (login-CSRF / account-linking takeover), PKCE missing on public clients, code injection, `response_mode` leaks, mix-up attacks across multiple IdPs.
- **JWT**: `alg:none`, RS256→HS256 confusion, weak HMAC secret, `kid` injection (path/SQL), missing `aud`/`iss`/`exp`.
- **SAML**: XML signature wrapping (XSW), comment-truncation in NameID, unsigned-assertion acceptance, recipient/audience confusion.
- **WebAuthn/passkeys, magic links, OTP**: link not single-use/expiring, OTP without lockout (logic, not volumetric), cross-device flow confusion.

### 1F. Protocol & parser differentials
- **HTTP request smuggling / desync** (taxonomy §15), HTTP/2 downgrade, **web cache poisoning / deception**.
- **Parser differentials** — two components parse the same input differently (URL parser vs allow-list → SSRF bypass; JSON dup-key; charset/Unicode normalization; multipart boundary confusion). High-skill, low-competition.

### 1G. AI-agent CI actions (a live, low-competition surface)
Distinct from the classic CI injection in §1B: here the workflow wires an **AI agent** (e.g. `anthropics/claude-code-action`, `google-github-actions/run-gemini-cli`, `google-gemini/gemini-cli-action`, `openai/codex-action`, `actions/ai-inference`) whose *prompt* is the injection sink. Attacker-controlled contexts that reach it: `github.event.issue.body/.title`, `github.event.comment.body`, `github.event.pull_request.body/.title/.head.ref/.head.sha`, `github.head_ref`. Three flow paths — direct interpolation, an env-var intermediary (no `${{ }}` in the prompt at all), and a runtime fetch (attacker content never appears in the YAML). The vectors §1B does not already cover:
- **A — env-var intermediary:** an `env:` key set to `${{ github.event.*.body }}`, then the prompt references the var *by name* (`"$ISSUE_BODY"`). No `${{ }}` in the prompt, so a grep for expressions misses it.
- **C — CLI data fetch:** the prompt tells the agent to `gh issue view` / `gh pr diff` / `gh api` at runtime; only a safe integer (the issue number) is interpolated, tainted content arrives live. `GITHUB_TOKEN` on the AI step is the tell.
- **E — error-log injection:** `on: workflow_run`/`workflow_dispatch` with inputs like `error_logs`/`build_output`; a "fix these CI failures" prompt ingests attacker-crafted output.
- **F — subshell expansion in a "restricted" tool list:** an allowlisted safe command still passes args through a shell — `echo $(env)` dumps secrets. Confirmed RCE with Gemini `coreTools: ["run_shell_command(echo)"]` and Claude `--allowedTools "Bash(echo:*)"`. Expandable: echo, cat, printf, tee, head, tail, wc, sort.
- **G — eval of AI output:** a later step feeds `${{ steps.<ai>.outputs.* }}` into `eval`/`exec`/`$()`/`json.loads()→subprocess`; a prompt-injected response executes as code in a more-privileged step.
- **H — dangerous sandbox config** (amplifier only): `--allowedTools Bash(*)`, `sandbox: danger-full-access`, `{"sandbox": false}`, `--yolo`.
- **I — wildcard user allowlist** (amplifier only): `allowed_non_write_users: "*"`, `allow-bots: true`.

(Vectors **B** direct expression injection and **D** `pull_request_target` + PR-head checkout are the "pwn request"/script-injection items already in §1B — treat this list as additive.) Resolve across files: agents hide in composite actions (`./action.yml` `runs.steps[]`) and reusable workflows (`uses: owner/repo/.github/workflows/x.yml@ref`), tracing inputs through `${{ inputs.* }}`. Reject three rationalizations: "no `${{ }}` in the prompt so it's safe" (misses A), "allowed_tools restricts it" (echo→subshell), "only maintainers trigger it" (ignores `pull_request_target`/`issue_comment`). H and I are amplifiers, never standalone findings.

---

## 2. Force-multiplier techniques

### 2A. CVE / patch diffing
A freshly-published fix is a map to where the dangerous code is and what the author believed they fixed.
- Pull the fix commit/PR (GitHub, the advisory's "patched in" link). Read the diff, not the prose.
- Ask: **what exactly did this guard block, and what does it still let through?** Sanitizers are often incomplete.
- It is cheap to *find* — the hard part (locating the sink) is done for you — but often **expensive to resolve on the wrong target** (see the EV rule in 2B). A public advisory is a starting gun; on a fresh, marquee CVE the embargo crowd has already swept the obvious variants.

### 2B. Incomplete-fix hunting
- The patch fixes the reported payload but not a *class* of payloads (e.g. blocks `../` but not `..\\` or URL-encoded `%2e%2e`; blocks one IMDS IP but not IPv6/decimal).
- The patch fixes one *entry point* but the vulnerable helper has other callers (→ 2C variant analysis).
- The patch is on `main` but **not released**, or released but **not back-ported** to LTS/older branches that are still in scope (n-day). A still-present sink at the released artifact's HEAD is reportable even if `main` was "fixed."

**EV rule — incomplete-fix pays on *cold* CVEs and dupes on *hot* ones.** In the mined failure history, every incomplete-fix of a *freshly-published* CVE/GHSA on a *marquee* component duplicated — the crowd swept it during embargo — while the only incomplete-fix still alive was of a five-year-old CVE on a peripheral, less-audited component. Incomplete-fix is EV-positive mainly on **old CVEs in cold, peripheral components**. Do not abandon the vein — re-aim it.

**But the load-bearing axis is variant *character*, not CVE-age** — score every incomplete-fix on a dup-risk ladder (a public advisory being fresh/marquee is a prior that *character* overrides in both directions):

- **Tier 1 — near-certain dup:** a variant the public patch diff hands you (decode-once → twice, block `../` → `..\\`, enumerate the sibling methods the fix forgot). On any fresh advisory this is already swept.
- **Tier 2 — high dup, even when deep:** an unpatched surface / runtime / config path of the *same* published CVE class (edge vs node handler, an allow-list omission). Real tracing, often Critical and live-PoC-verified — and **still duped during embargo** (a Critical BAC with a working PoC duplicated anyway). Depth does not rescue a public-CVE finding.
- **Tier 3 — low dup, can pay even on a saturated marquee program:** a **cross-layer / cross-representation desync** (one layer canonicalizes an identity or value, another compares it raw), found by tracing a representation *across layers* rather than by reading a diff, whose only prior "fix" is a quiet in-repo partial-normalization with **no public advisory**. This is the only tier that clears the *distinct semantic invariant* bar above; Tiers 1–2 are the "merely a new payload or entry point" trap.

So a hit on the seven-vector table below is a *candidate*, not a green light — it must additionally clear the Tier-3 character gate before you invest. Two calibrations the data forces: an **in-repo correctness oracle** (the repo does it right elsewhere) defeats an *Informative / by-design* close — it proves oversight, not by-design — but does **not** lower duplicate risk (several duped variants had one), so never read it as "this won't dup." And never rank incomplete-fixes by **severity or PoC quality**: here they were *counter-correlated* with paying — the Criticals duped, a race and a Low paid.

Run the fix diff and its callers through seven bypass vectors before calling the class dead; record each in `candidate.json.patch_bypass.vectors`. Any hit is a fresh candidate — trace it as its own invariant (the original CVE proves plausibility, not this target's actor/reachability/impact).

| Vector | Question |
|---|---|
| Alternate entry | Does the same sink have other callers the fix didn't touch? |
| Config-gated | Is the fix conditional on a flag that can be disabled? |
| Default-state | Does the fix activate only after explicit configuration? |
| Compat branch | Is there a legacy path that skips the new check? |
| Parser diff | Do two layers parse the input differently, side-stepping the check? |
| Missing normalization | Can encoding / case / Unicode bypass the check? |
| Sibling path | Are analogous operations on sibling resources still vulnerable? |

### 2C. Variant analysis
Turn one confirmed bug into a query and sweep for siblings.
- Write a **Semgrep** rule (or CodeQL query) for the pattern, run it across the repo and the whole org's repos.
- Example: confirmed an authz check missing on `updateUser` → grep every handler that loads a target by a global key without a tenant predicate (this routinely yields 3–5 sibling endpoints from one root cause).
- Variants are often *not* duplicates of the original report and pay separately or raise severity (systemic finding).

State the root cause as a search pattern: *"[untrusted data] reaches [dangerous op] without [required protection]."* Then climb the **abstraction ladder** one rung at a time, reviewing every new match and reverting when the false-positive rate exceeds ~50%: L0 exact code (confirm the bug) → L1 replace variable names with metavariables (copy-paste clones) → L2 generalize structure (component-wide) → L3 taint source→sink (broad, high FP). Also run the **vulnerability-class expansion** — one root cause manifests across semantic siblings: if the bug is on `isAuthenticated`, also check `isAdmin`/`isActive`/`isVerified`; if on `userId`, also `ownerId`/`creatorId`/`authorId`; watch for null-equality bypass (`None == None` → True defeats an owner check when both sides can be null) and doc-vs-code inversion (a function named `deny`/`restrict` that returns True when the user *has* permission). Search the whole repo/org root, not just the module. The alternate-transport half of this sweep (HTTP → WebSocket/gRPC/GraphQL/CLI/queue) is in the SKILL depth contract.

### 2D. Secret-scanning recon
- **trufflehog** / **gitleaks** across repos AND full git history.
- **Force-pushed / deleted commits** ("oops commit"): a secret committed then force-pushed away is still reachable via the GitHub events API / commit SHA — `mcp__plugin_github_github__run_secret_scanning` and dangling-commit enumeration find these.
- Client bundles, source maps, Docker image layers, CI logs, public Postman/Swagger.
- Validate a found secret *minimally and within policy* — never use a live prod credential to pivot; report the exposure.

### 2E. Recently added program or scope
- Diff `github.com/arkadiyt/bounty-targets-data` over time (it aggregates HackerOne/Bugcrowd/Intigriti/YWH scopes). A newly-added asset or newly-launched program has the largest untouched reserve — be first.
- `bbscope` to pull structured scope; subscribe to launch notifications. The freshness principle (reserves are largest at launch, decay with age) is *the* highest-leverage targeting move.

### 2F. Tooling that scales a code audit
- **Semgrep** (fast, writeable rules, great for variant analysis) and **CodeQL** (deep dataflow/taint, best for source→sink across a big codebase) on the cloned repo.
- Language-native: `gosec`, `bandit` (Python), `brakeman` (Rails), `phpcs`/`psalm` taint, `npm audit`/`osv-scanner` for known-CVE deps in scope.
- Use these for the *first pass* (sink discovery), then human-reason the authz/logic/race classes the tools can't see. Tools find injection-shaped bugs; you find the reasoning bugs that pay more and dup less.

### 2G. History mining & silent-fix detection
§2A starts from a *published* advisory. This finds the fixes that never got one — so there is no dedup pool yet. Never iterate every commit; use pickaxe search over recent history.
- **Learn the project's own security vocabulary first:** grep HEAD for its `validate_*` / `sanitize_*` / `authorize` / `*Guard*` names, then use those as extra `git log -S` targets.
- **Silent security fix (3-signal):** signal A = the diff adds protective patterns; signal B = the commit message is generic ("refactor"/"cleanup"/"fix") with no security keywords; signal C = it touches a security-critical path. All three → reconstruct the pre-fix vulnerable state and attack it. Still confirm the flaw is live on the current default branch (novelty gate) — a silent fix may already be released.
- **Reverted / re-weakened control:** `git log -S "<code>" --all -p` for a guard added then removed, or a fix reverted for compatibility; `git log -p -G` then grep removed `isAdmin`/`requireAuth`/`csrf`.
- **Secret archaeology:** `git log --diff-filter=D` for deleted `.env`/`.pem`/`.key`; `-S 'AKIA'`/`ghp_` for committed-then-removed credentials (still valid until rotated — see §2D).
- **Structural recurrence:** a component patched *multiple times for the same bug class* signals a structurally incomplete fix; the next instance of the class is probably still there — the highest-priority patch-bypass target (§2B).

---

## 3. Hot vs saturated — the 2026 read

**Architecture signals worth inspecting when present:**
- AI/LLM/MCP with a real sink — defenders behind, programs young.
- CI/CD & GitHub Actions misconfig — greppable, common, under-reported on product programs.
- Authorization / multi-tenant / business-logic / race — scanners and bots structurally can't find these; the human edge.
- Parser differentials & smuggling — high skill floor keeps competition thin.
- Fresh programs or newly added scope — verify current rules and ownership before investing.

**Saturated / low-EV (avoid unless the target is fresh or you have a real chain):**
- Reflected XSS / classic SQLi / open redirect on mature, scanned web programs — every bot runs these.
- Missing-header / no-rate-limit / self-XSS / theoretical-no-impact — usually OOS or N/A; they cost Signal.
- Hardened security-core libraries (crypto, auth SDKs, init systems) audited to death — they return repeated clean passes; the win is usually a *less-scrutinized tool*, not the hardened core.

**Ecosystem note:** automated low-quality submissions make proof, ownership, and honest scope more important than report volume. Lead with the exact causal trace and accepted proof artifact; preserve a non-reportable verdict when a gate fails.
