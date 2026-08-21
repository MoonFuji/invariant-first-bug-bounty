#!/usr/bin/env python3
"""Create a candidate from a validated SELECTED target ledger."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import validate_hunt


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
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
    if errors:
        validate_hunt.emit_messages("ERROR", errors)
        return 2

    candidate["target_ledger_id"] = target["target_id"]
    ctarget = candidate.setdefault("target", {})
    for key in ("platform", "route_type", "asset_type", "program", "asset", "repository", "commit", "operating_mode"):
        ctarget[key] = validate_hunt.canonical_target_value(target, key) or ""
    scope = target.get("scope", {})
    ctarget["scope_evidence"] = validate_hunt.scope_evidence_summary(target)
    ctarget["scope_checked_at"] = scope.get("checked_at", "")
    sat = target.get("saturation", {})
    csat = ctarget.setdefault("saturation", {})
    csat["discloses_reports"] = sat.get("discloses_reports") if sat.get("status") == "checked" else None
    csat["reports_last_90d"] = None
    csat["hot_cluster"] = None

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
