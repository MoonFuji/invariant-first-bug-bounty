#!/usr/bin/env python3
"""Create a candidate from a validated SELECTED target ledger."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import validate_hunt
from hunt_validation.common import text
from hunt_validation.target import target_fingerprint


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--hypothesis-id",
        help="investigating hypothesis to promote; optional only when exactly one exists",
    )
    parser.add_argument(
        "--template",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "assets" / "candidate.template.json",
    )
    parser.add_argument("--force", action="store_true", help="replace an existing output file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.output.exists() and not args.force:
        print(f"ERROR: output already exists: {args.output} (use --force to replace)", file=sys.stderr)
        return 2
    try:
        target = validate_hunt.load_json(args.target_ledger)
        candidate = validate_hunt.load_json(args.template)
    except validate_hunt.ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    errors: list[str] = []
    validate_hunt.validate_target(target, errors)
    decision = target.get("decision") if isinstance(target.get("decision"), dict) else {}
    if decision.get("disposition") != "SELECTED":
        errors.append("start-candidate requires target decision.disposition SELECTED")

    campaign = target.get("campaign") if isinstance(target.get("campaign"), dict) else {}
    campaign_id = campaign.get("campaign_id")
    if not text(campaign_id):
        errors.append("start-candidate requires campaign.campaign_id")

    lifecycle = target.get("hypothesis_lifecycle")
    investigating = [
        hypothesis for hypothesis in lifecycle
        if isinstance(hypothesis, dict) and hypothesis.get("status") == "investigating"
    ] if isinstance(lifecycle, list) else []
    hypothesis_id = args.hypothesis_id
    if hypothesis_id:
        matches = [
            hypothesis for hypothesis in investigating
            if hypothesis.get("hypothesis_id") == hypothesis_id
        ]
        if not matches:
            errors.append(
                f"start-candidate requires hypothesis_id {hypothesis_id!r} to exist with status investigating"
            )
        hypothesis = matches[0] if matches else {}
    elif len(investigating) == 1:
        hypothesis = investigating[0]
        hypothesis_id = hypothesis.get("hypothesis_id")
    elif not investigating:
        errors.append(
            "start-candidate requires an existing hypothesis with status investigating; "
            "promote one in target.hypothesis_lifecycle first"
        )
        hypothesis = {}
    else:
        errors.append(
            "start-candidate found multiple investigating hypotheses; pass --hypothesis-id to choose one"
        )
        hypothesis = {}

    boundary_id = hypothesis.get("boundary_id") if isinstance(hypothesis, dict) else None
    if not text(boundary_id):
        errors.append("start-candidate requires the investigating hypothesis to reference boundary_id")
    if errors:
        validate_hunt.emit_messages("ERROR", errors)
        return 2

    candidate["target_ledger_id"] = target["target_id"]
    candidate["campaign_id"] = campaign_id
    candidate["target_fingerprint"] = target_fingerprint(target)
    candidate["boundary_id"] = boundary_id
    candidate["hypothesis_id"] = hypothesis_id
    ctarget = candidate.setdefault("target", {})
    for key in ("platform", "route_type", "asset_type", "program", "asset", "repository", "commit", "operating_mode"):
        ctarget[key] = validate_hunt.canonical_target_value(target, key) or ""
    scope = target.get("scope", {})
    ctarget["scope_evidence"] = validate_hunt.scope_evidence_summary(target)
    ctarget["scope_checked_at"] = scope.get("checked_at", "")
    ctarget.pop("saturation", None)
    ctarget.pop("contestability", None)

    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"ERROR: cannot write candidate: {exc}", file=sys.stderr)
        return 2
    print(f"CANDIDATE CREATED: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
