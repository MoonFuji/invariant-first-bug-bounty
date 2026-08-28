# Worked Examples

These examples are synthetic and do not reproduce private or undisclosed report details. Section 7 calibrates caveat handling through generic gate logic rather than submitted cases.

## 1. Documented raw-builder contract — `KILL @ refutation`

A query-builder exposes both a raw API and a parameterized API. A downstream application passes request input into the raw API and becomes injectable.

The library documents that the raw API accepts pre-sanitized fragments and delegates escaping to the caller. The downstream application is vulnerable, but the library did not violate a security property it owns.

```jsonc
"intent_corpus": {
  "intentional_behaviors": [
    {
      "quote": "Raw fragments must be sanitized by the caller; use bind() for parameterization.",
      "source": "README.md#raw-api"
    }
  ],
  "finding_match": "intentional"
},
"threat_model": {
  "strongest_refutation": {
    "claim": "the raw API delegates escaping to the caller",
    "kind": "behavior_is_documented_contract",
    "evidence": "README.md#raw-api",
    "resolution": "",
    "resolution_source": "none",
    "result": "confirmed"
  }
},
"decision": {
  "verdict": "KILL",
  "gate": "refutation",
  "failed_gates": ["refutation"],
  "missing_evidence": [],
  "reason": "the downstream caller violated the documented raw-input contract"
}
```

Route the real bug to the downstream application. A misuse-resistance improvement in the library may be worthwhile, but it is not automatically a bounty vulnerability.

## 2. Cross-tenant object read — `REPORTABLE`

The invariant is “tenant A reads only tenant A records.” A handler loads a record by global primary key without applying the authenticated tenant predicate.

Two owned tenants prove tenant A can retrieve tenant B’s canary. Anonymous and nonexistent-object controls behave as expected.

The one-sentence attacker model has no load-bearing hedge:

> The attacker, who holds a normal tenant-A account, crosses the tenant boundary to read tenant-B data they could not read before.

```jsonc
"threat_model": {
  "capability_before": "tenant A reads tenant A records",
  "capability_after": "tenant A reads tenant B records by id"
},
"proof": {
  "type": "executable-local-exact-path",
  "command": "./poc.sh",
  "observed_result": "tenant-A token returned tenant-B canary",
  "negative_controls": [
    "anonymous request returned 401",
    "nonexistent id returned 404"
  ],
  "config_dependency": "none"
},
"decision": {
  "verdict": "REPORTABLE",
  "gate": "reportability"
}
```

Ordinary limitations can remain: the PoC may not enumerate all affected object types, and severity should reflect only the data proven readable. Those limitations do not negate the crossed tenant boundary.

## 3. Substitute-client SSRF — `HOLD @ proof`

A copied helper or compatible HTTP client follows an attacker-controlled URL, but the exact shipped binary and real product invocation were not exercised.

The primitive is plausible, yet executable and boundary fidelity remain unproven.

```jsonc
"decision": {
  "verdict": "HOLD",
  "gate": "proof",
  "failed_gates": [],
  "missing_evidence": [
    "invoke the exact pinned binary through the real request/configuration path and capture the listener hit plus a blocked-URL control"
  ]
}
```

“The product exposes a URL field” is a load-bearing caveat when the proof depends on a representation that may be normalized or rejected before reaching the executable.

## 4. Vulnerable dependency owned upstream — `ROUTE_ELSEWHERE`

A product bundles an unmodified archive library with a traversal bug. The product proves reachability, but the faulty implementation and fix belong to the upstream project.

```jsonc
"threat_model": {
  "strongest_refutation": {
    "claim": "the target does not own this security property",
    "kind": "target_does_not_own_security_property",
    "evidence": "the vulnerable extract() implementation is shipped verbatim from upstream",
    "resolution": "",
    "resolution_source": "none",
    "result": "confirmed"
  }
},
"route": {
  "owning_project": "upstream/archive-lib",
  "type": "upstream-advisory",
  "owner_verified": true
},
"decision": {
  "verdict": "ROUTE_ELSEWHERE",
  "gate": "route"
}
```

## 5. Load-bearing versus ordinary caveats

Use this test:

> The attacker, who already holds X, crosses boundary Y to gain capability Z they could not exercise before.

Record every hedge this test surfaces in the candidate's `caveats` ledger — one `{quote, classification, justification}` entry per hedge, quoting your own draft wording. A `load_bearing` classification mechanically blocks `REPORTABLE`.

### Fatal caveat: precondition already grants the effect

> Exploitation requires the attacker to edit the victim service’s environment variables.

When environment control already permits secret replacement, code execution, or equivalent authority, the alleged token leak may add no new capability. This lands at `capability_delta` unless a less-trusted actor can reach that setting through a target-owned path.

### Fatal caveat: deployment route not demonstrated

> The local default is vulnerable, but the report does not establish that the accepted production or source-code route uses this default.

This is `HOLD @ proof` when the destination requires that deployment relevance. It is not fatal when the program explicitly accepts the exact local shipped path as sufficient proof.

### Fatal caveat: bypassed control is not a security boundary

> The action still requires the same valid API credential; only a user-confirmation prompt is bypassed.

If the credential-holder could already perform the operation directly, the prompt bypass may add no security capability. That is a `capability_delta` question, not an automatic finding.

### Ordinary limitation: narrower affected surface

> Only the report-read endpoint was tested; export and delete were not tested.

The proven cross-tenant read remains reportable. This limitation constrains blast radius and severity and belongs in the report.

### Ordinary limitation: no stronger chain demonstrated

> The PoC reads a benign canary file but does not prove cloud credentials or code execution.

The demonstrated file-read capability may still be reportable on the accepted boundary. Do not inflate it to stronger assets; keep the limitation and score the captured effect.

## 6. Target rotation examples

### Valid rotation at scope

A live scope artifact marks the exact asset ineligible. The ledger records:

```jsonc
"decision": {
  "disposition": "ROTATED",
  "gate": "scope",
  "rotation_basis": "scope_ineligible",
  "reason": "the live scope response marks this exact asset ineligible"
}
```

Downstream proof-policy and saturation fields may remain unassessed because scope already terminated selection.

### Invalid rotation

```jsonc
"decision": {
  "disposition": "ROTATED",
  "reason": "the target looks hardened and the proof would take too long"
}
```

This is not evidence. Use `HOLD` if a required live artifact is unavailable, or continue the selected target.

## 7. Synthetic calibration — the caveat is the verdict

These are synthetic gate examples. They do not come from a maintainer, researcher, program, or submitted report. Their purpose is to show when an apparently real defect still lacks a reportable security boundary or effect.

| Synthetic case | Load-bearing caveat | Why it blocks reporting | Gate |
|---|---|---|---|
| A recovery API returns material to the same principal that already controls the signer | No separate principal or reachable cross-context sink is demonstrated | The PoC changes representation, not authority | Boundary / reachability |
| A transport check can be disabled only by changing the victim process's trusted configuration | The assumed attacker can already rewrite security-sensitive configuration | The precondition subsumes the claimed credential impact | Precondition / capability delta |
| A query is exposed only when a development default remains enabled | No supported or deployed configuration using that default is demonstrated | Local behavior alone does not establish the program's proof route or production impact | Deployment / proof route |
| A warning or confirmation step can be skipped while using a valid privileged credential | Authentication and authorization still succeed exactly as designed | Removing a user-interface warning adds no new server-side capability | Control class / capability delta |

The meta-rule: **a load-bearing caveat is part of the verdict, not a footnote.** Run the one-sentence attacker-model test (section 5), record every caveat in `caveats`, and classify it honestly. The validator rejects `REPORTABLE` while any entry is `load_bearing`.
