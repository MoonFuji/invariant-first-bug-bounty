# Methodology and targeting

This reference expands the core reasoning gates without adding mandatory
bookkeeping.

## 1. Target selection

Choose targets for provability, ownership, and expected value.

Before deep work, verify only what belongs in `target.json`:

- exact asset/repository/revision;
- authorization mode (`SOURCE_ONLY` or `PROGRAM_HOSTED`);
- current scope and severity ceiling;
- current accepted proof routes;
- selected/hold/rotation decision.

Duplicate pressure, prior outcomes, architecture notes, and hypothesis queues are
research inputs. They are not prerequisites for selecting a technically valid
target.

Useful ranking factors:

| Factor | Prefer |
|---|---|
| Proofability | exact executable or authorized hosted path available |
| Ownership | destination clearly owns the code/property |
| Reachability | attacker-supported ingress is concrete |
| Impact | target-owned capability delta can be demonstrated |
| Duplicate pressure | searchable lower-volume surface |
| Verification cost | safe controls and fixtures are available |

A crowded program is a ranking penalty, not a scope failure.

## 2. Invariant-first review

Comprehension is selective across the repository but exhaustive along the chosen
invariant. Read every claim-critical link on the source-to-effect path.

Model:

- principals;
- protected assets;
- trust boundaries;
- authoritative state stores;
- authentication/authorization/canonicalization points;
- one falsifiable invariant.

Examples:

- A tenant can read or mutate only objects it owns or was granted.
- A one-time verifier cannot be consumed twice across equivalent encodings.
- A denied tool event cannot execute a consequential local tool.
- Internal RPC methods cannot be reached through a public listener.

Trace:

```text
attacker representation
→ parser/transport
→ authentication
→ normalization
→ authorization/validation
→ state lookup/transition
→ persistence/external effect
→ observable capability
```

Check at least one meaningful sibling or alternate path. The sibling is evidence
only when you explain why its enforcement differs.

## 3. Discovery lenses

Apply lenses that fit the architecture:

- representation asymmetry between validation and later use;
- object-identity confusion;
- enforcement split between transports/versions;
- state-machine replay/reorder/race;
- trust-mode mismatch;
- TOCTOU/uniqueness gaps;
- parser/protocol differentials;
- stored/second-order interpretation;
- supply-chain caller-contract mismatch.

Broad grep is coverage, not proof. A sink becomes interesting only after an
attacker-controlled source and target-owned boundary are established.

## 4. Capability delta

Write:

1. attacker starts with `<access>`;
2. attacker controls `<input/state>`;
3. target performs `<security-relevant action>`;
4. attacker gains `<new capability>`.

If 4 is already included in 1, the candidate dies or must be narrowed.

For filesystem/process claims record runtime identity, permissions, sandbox,
exact path, and execution trigger. Controlling a pathname does not imply write
permission.

## 5. Strongest refutation

Test the explanation most likely to kill the report:

- input is trusted operator/deployer state;
- caller already owns the capability;
- production adds an authoritative re-check;
- path is unreachable under the supported contract;
- behavior is explicitly documented by design;
- another project owns the property;
- precondition already grants the claimed effect.

A terminal refutation is not defeated by a third-party misuse scenario. If
target-owned evidence genuinely defeats the objection, the objection is
non-terminal.

## 6. Proof quality

Use three proof levels:

### Primitive

The mechanism can produce the effect. Useful for shaping the hypothesis, not
enough for a report.

### Executable

The exact pinned/shipped executable or method, real invocation, and relevant
configuration produce the effect.

### Boundary

An actor allowed by the destination can supply the exploit-critical
representation through the product-facing path and cross a target-owned
boundary.

Every reportable proof needs:

- exact version/revision;
- command/setup;
- observable result;
- negative control;
- production/destination relevance.

Configuration is a precondition. A shipped default or supported option may be
valid when target-owned and not itself granting the effect. Operator-weakened,
test-only, or unknown configurations do not establish the supported boundary.

## 7. Ownership and routing

Before reporting, answer:

- Which repository/component contains the fault?
- Which maintainer would change it?
- Which release would carry the fix?
- Does the destination own that asset/property?
- Does it accept the available proof type?

Delegation is not ownership. Use `ROUTE_ELSEWHERE` when another project owns the
fix.

## 8. Novelty and duplicate risk

Fingerprint:

```text
boundary | primitive | invariant | effect
```

Search semantics, not titles/CWEs.

For repository-backed targets, inspect:

1. your own prior outcomes;
2. program disclosures;
3. upstream commits;
4. open/closed upstream issues;
5. upstream pull requests;
6. recent advisories;
7. current default branch.

Record the query and auditable artifact for each search. An unavailable source
is uncertainty, not zero results.

Interpretation:

- same boundary/primitive/invariant/effect: probable duplicate;
- same component, different invariant/effect: document the delta;
- no public match: public novelty only; private duplicates remain possible;
- current branch fixed: do not report as current without a route/version reason;
- wrong project owns fix: route elsewhere.

High or unknown private-duplicate risk should carry a concrete collision
differentiator.

## 9. Narrowing and recovery

Do not force every real primitive to support the strongest imagined deployment
story.

- `ready`: bounded claim is complete.
- `recover`: an available artifact can repair the missing proof.
- `narrow`: a lower security-relevant claim survives; list unsupported
  extensions.
- `operator_required`: next proof needs unavailable authorized environment.

`recover` and `operator_required` are not reportable.

## 10. Severity

Score the demonstrated capability, not the bug class or theoretical maximum.

- state attacker privileges honestly;
- separate demonstrated from conditional consequences;
- account for victim action, races, configuration, and unusual preconditions;
- do not raise severity for an unproven chain;
- keep the candidate `severity_ceiling` at or below current scope limits.

The final submission-time preflight refreshes the current program severity cap.

## 11. Report structure

A useful report normally contains:

1. bounded title;
2. exact asset/version;
3. attacker model and capability delta;
4. reproduction steps and command;
5. observed result and negative control;
6. security impact;
7. scope/severity rationale;
8. limitations/unsupported extensions;
9. fix-owner context where useful.

The report is the semantic submission artifact. `submission.json` is only an
exact-file manifest plus fresh preflight.

## 12. Terminal decisions

- `REPORTABLE`: bounded candidate cleared all technical gates.
- `HOLD`: named evidence is missing.
- `KILL`: this invariant failed a gate.
- `ROUTE_ELSEWHERE`: another disclosure rail owns the fix.

One `KILL` never means the target is clean. Use optional campaign mode for broad
coverage or exhausted-target conclusions.
