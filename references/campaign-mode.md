# Optional campaign mode

Campaign mode exists for durable multi-hypothesis work. It is not a prerequisite
for investigating one vulnerability.

Use it when the request is broad:

- audit the whole repository or product;
- find multiple vulnerabilities;
- continue after each candidate;
- cover a bounded set of surfaces;
- justify a target-wide exhausted/clean conclusion.

Do not use it merely because the skill supports it.

## Minimal campaign state

A campaign records:

```json
{
  "schema_version": 1,
  "campaign_id": "campaign-example",
  "target_id": "target-example",
  "mode": "bounded",
  "status": "open",
  "stop_condition": "Investigate the highest-value auth and parser boundaries.",
  "hypotheses": [
    {
      "hypothesis_id": "H-001",
      "boundary": "request -> tenant object",
      "statement": "Direct lookup may omit tenant authorization.",
      "priority": "high",
      "status": "investigating",
      "candidate_id": null,
      "verdict": null,
      "reason": ""
    }
  ]
}
```

The queue is orchestration state, not evidence that a vulnerability exists.

## Hypothesis lifecycle

```text
queued → investigating → closed
                     ↘ parked
```

- `queued`: worth investigating, not yet active.
- `investigating`: exactly the hypothesis currently being traced.
- `closed`: reached `REPORTABLE`, `KILL`, or `ROUTE_ELSEWHERE`; retain candidate
  id, verdict, and a short reason.
- `parked`: explicitly deferred with a reason.

Never erase rejected ideas merely to make the queue look cleaner.

## Ranking

Rank by expected value, not novelty theater:

```text
reachability × owned-boundary confidence × impact × proofability ÷ duplicate pressure
```

A simple reachable authorization bug outranks a speculative chain.

Useful boundary inventory questions include:

- Where does untrusted representation first enter?
- Which component authenticates identity?
- Which component owns authorization?
- Where does canonicalization happen?
- Which state store is authoritative?
- Which transition is security-sensitive?
- What sibling transport or alternate parser reaches the same property?

Keep architecture notes in working research notes unless they are useful enough
to become a hypothesis. Do not force a formal architecture object into every
campaign.

## Continue-after-terminal rule

A candidate verdict closes one hypothesis, not the target.

After a terminal verdict:

1. update that campaign hypothesis;
2. preserve the candidate artifact;
3. select the next highest-value queued hypothesis when the stop condition says
   work should continue.

`HOLD` is not a terminal campaign state. It names missing candidate evidence.

## Campaign closure

`first_finding` may close after at least one reportable candidate.

`bounded` closes when its explicit stop condition is satisfied. Lower-value
queued ideas may remain; no hypothesis may remain `investigating`.

`exhaustive` closes only when every tracked hypothesis is `closed`.

A closed campaign cannot start new candidates. Reopening is a deliberate state
change, not an implicit side effect of starting work.

## Clean-target claims

There is no candidate-level `NO_REPORTABLE_FINDING` verdict. A candidate that
fails is `KILL`; that says only that this invariant did not become a report.

If the user needs a target-wide clean/exhausted conclusion, use an exhaustive
campaign and make the coverage argument in the final campaign summary:

- which high-value boundaries were represented;
- which hypotheses were closed;
- meaningful parked/unmodeled surfaces, if any;
- what dynamic probes were actually executed;
- why remaining uncertainty is acceptable or not.

The validator can check queue closure. It cannot certify that the hypothesis set
was complete.

## Why campaign mode is separate

The skill's core job is vulnerability reasoning. Campaign bookkeeping exists to
prevent long autonomous audits from stopping early or losing coverage.

Keeping campaign state separate from `target.json` and `candidate.json` avoids
making a one-finding hunt pay the same process cost as an exhaustive audit.
