# Hypothesis Generation

## Contents
- Hypothesis record and the mandatory creativity signal
- Eight attack modes (chaining, business-logic, race, second-order, trust-boundary, parser, state-machine, supply-chain)
- Pre-mortem (backward reasoning)
- Defensive code is a symptom
- Contradiction / tension scan (TRIZ)
- Adaptive-attacker (game-theoretic) framing

The controller is invariant-first: model, then trace. This file feeds the *front* of that
funnel when a target is large or unfamiliar and the single most valuable invariant is not
obvious. It produces a **ranked queue of hypotheses**, never candidates. A hypothesis becomes
a `candidate.json` only after it survives relevance and a first trace, exactly as in the main
workflow. Ideation widens what you consider; it never lowers a gate.

Discipline: every hypothesis carries a **creativity signal** — one line on why a grep sweep or
a first-pass read would miss it. No creativity signal → discard it. If the idea is obvious
("SQL built by string concatenation"), `recon-sweep.sh` or a scanner already has it, and it is
not worth an ideation slot.

Hypothesis record (keep it terse; store the survivors in `candidate.json.hypothesis_queue`):

- id, title
- attack class (primary mode) + any cross-modes
- chain (multi-step) or single-step
- preconditions (attacker starting position + required capability)
- target asset (what the attacker gains)
- suspected entrypoint and sink
- creativity signal (mandatory)

Promote exactly one hypothesis to the invariant and run the full workflow on it. Keep the rest
as the reinvestment queue; do not spawn a second trace until the first reaches a terminal verdict.
Volume of hypotheses is not depth — the depth contract still governs when to rotate.

A hypothesis that relevance or a first trace does not support is simply dropped from the queue and
you pivot to the next — that is the queue working, not a failed target, and it has no effect on
`candidate.json` (a hypothesis is not a candidate, so there is no gate to fail). Only give up on
the whole target when the queue is exhausted and the depth contract's clean-repository record is
complete for each invariant you tried.

## Eight attack modes

Cycle all eight against the recorded architecture. Cross-mode chains rank highest — they are
also the ideas that survive duplicate pools, which is where single-mode ideas usually die.

1. **Chaining** — combine individually-low issues across a trust boundary. IDOR on metadata +
   a token in that metadata = ATO. SSRF limited to internal DNS + DNS resolving a metadata
   endpoint = credential theft. A patch that covers the HTTP path but not the WebSocket path
   sharing the same unfixed parser.
2. **Business-logic abuse** (invisible to static rules) — negative quantity/refund, self-invite
   to a higher role, skip step 2 and go 1→3, exhaust another tenant's quota via accounting,
   abuse a legitimate export/share/webhook as an exfil channel, undo/rollback to restore a
   revoked privilege. (See taxonomy §17.)
3. **Race / TOCTOU** — non-atomic check-then-act (balance check then deduct = double spend),
   role changed between the authz check and the privileged action, symlink swap between stat()
   and open(), an isolation level permitting phantom reads inside a multi-query operation.
   (See taxonomy §16.)
4. **Second-order / stored** — input stored under strong sanitization, later consumed where the
   sanitization is weaker: stored XSS/SSRF/SSTI, second-order SQLi, a filename stored on upload
   then used in a shell command during processing.
5. **Trust-boundary confusion** — service A trusts B's claims without re-verifying; auth
   middleware registered *after* the route; a gateway validates the JWT but the downstream
   trusts any request from the gateway IP; an "internal" admin panel sharing origin/cookies with
   the public app; a CLI running as the user that shells to a root helper.
6. **Parser / protocol differential** — two components read the same bytes differently: CL vs TE
   request smuggling, duplicate-JSON-key precedence, URL authority/percent-encode/backslash
   handling, the Content-Type the validator checks vs the one the processor consumes, SAML
   namespace-aware vs -unaware signature wrapping, path normalization done by one library for the
   check and another for the route. (See taxonomy §15, emerging §1F.)
7. **State machine** — replay step 3 of an OAuth flow for a second token, reuse a one-time code
   by racing its invalidation, transition backward from a terminal state (cancelled→pending),
   jump A→C skipping a required B, act inside an async-invalidation window where the old session
   still works.
8. **Supply-chain interaction** — a known gadget in a dependency + does the app deserialize
   user-controlled data with it? safe-vs-unsafe API surface, an unoverridden insecure default,
   a server-only library used in a browser context (or vice-versa). (See emerging §1C.)

Attempt at least two explicit cross-mode combinations per session (e.g. parser-differential +
state-machine to bypass an OAuth `redirect_uri` check then replay the code; stored + trust-
boundary to land a payload via a low-trust API that a high-trust renderer executes).

## Pre-mortem (backward reasoning)

Assume this exact system is already catastrophically breached. Do **not** use generic outcomes
("RCE", "auth bypass"). Write 5–7 catastrophes specific to *this* code and *this* asset (e.g.
"any user drains any wallet by replaying a settlement", "a read-only token mints an admin
session"). For each, chain backward: catastrophe → what must be true immediately before it
(precondition) → what code operation produces that precondition → what attacker input or action
creates it → which entrypoint carries that input. Each complete chain is a hypothesis. Keep the
attack input concrete ("POST with Content-Length: 0 and a body", not "a malformed request").

A backward chain that only reaches a *precondition the attacker does not hold* is not a finding —
it is a `HOLD`/`KILL @ reachability`. Do not fill the gap with "assume a compromised backend" or
"assume a leaked credential"; those are the unevidenced preconditions the main workflow already
forbids (SKILL step 6, strongest refutation). The chain must terminate at a real target-supported ingress.

## Defensive code is a symptom

Enumerate every defensive construct on the path (guard, clamp, retry, fallback, try/except,
assert, sanitizer). For each ask: *what danger forced the author to write this?* Then: does the
fallback/error path grant any access, return any data, or skip any check the happy path enforces?
Does downstream code assume the happy path ran and behave differently on the fallback value? A
guard that exists is proof the author expected hostile input there — go find the input shape it
was meant to stop and test whether it fully stops it, especially the encoding/case/normalization
variants the author may not have considered.

## Contradiction / tension scan (TRIZ)

Every engineering decision resolves a tension; the vulnerability lives in what was sacrificed.
Scan for:

- **Compatibility** — multiple versions/protocols/clients supported → is the legacy/lenient path
  held to the same security treatment as the strict new path?
- **Performance** — caching, skipped steps, looser parsing → which security step got skipped?
- **Convenience** — a simpler API, a default value, auto-config → is the default path as secure
  as the explicit one?
- **Completeness** — an edge case handled later, out of band → does the edge path get the same
  checks as the main path?
- **Async** — validates synchronously but acts asynchronously → is state consistent between
  validation and action?

## Adaptive-attacker (game-theoretic) framing

Model the attacker as interacting many times and learning. What does it learn after 1, 10, 1000
requests? Look for: response differentiation (different error/timing/data for valid vs invalid
inputs — an oracle), a known rate limit or counter (tells the attacker exactly how many probes
are safe), state accumulation (inch forward in increments), timing oracles, cross-user side
effects. If a sequence of individually-allowed requests reaches a forbidden state while staying
under detection thresholds, that sequence is the hypothesis — trace it as one invariant about the
end state, not as many small findings.
