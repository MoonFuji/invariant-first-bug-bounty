#!/usr/bin/env python3
"""Create a lean candidate bound to a selected target and optional campaign hypothesis."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hunt_validation.common import ValidationError, emit_messages, load_json, text
from hunt_validation.target import (
    canonical_target_value,
    find_campaign_hypothesis,
    target_fingerprint,
    validate_campaign,
    validate_target,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-ledger", type=Path, required=True)
    parser.add_argument("--campaign-ledger", type=Path)
    parser.add_argument("--hypothesis-id")
    parser.add_argument("--candidate-id")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--template",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "assets" / "candidate.template.json",
    )
    return parser.parse_args()


def fail(errors: list[str]) -> int:
    emit_messages("ERROR", errors)
    return 2


def main() -> int:
    args = parse_args()
    if args.output.exists():
        return fail([f"refusing to overwrite existing output: {args.output}"])
    try:
        target = load_json(args.target_ledger)
        candidate = load_json(args.template)
    except ValidationError as exc:
        return fail([str(exc)])

    errors: list[str] = []
    validate_target(target, errors)
    decision = target.get("decision") if isinstance(target.get("decision"), dict) else {}
    if decision.get("disposition") != "SELECTED":
        errors.append("start-candidate requires target decision.disposition SELECTED")

    campaign = None
    if args.campaign_ledger is not None:
        try:
            campaign = load_json(args.campaign_ledger)
        except ValidationError as exc:
            errors.append(str(exc))
        else:
            validate_campaign(campaign, errors)
            if campaign.get("target_id") != target.get("target_id"):
                errors.append("campaign.target_id must match target.target_id")
            if campaign.get("status") != "open":
                errors.append("start-candidate requires campaign.status open")
            if not text(args.hypothesis_id):
                errors.append("--hypothesis-id is required with --campaign-ledger")
            else:
                hypothesis = find_campaign_hypothesis(campaign, args.hypothesis_id)
                if hypothesis is None:
                    errors.append("--hypothesis-id must identify one campaign hypothesis")
                elif hypothesis.get("status") != "investigating":
                    errors.append("start-candidate requires the campaign hypothesis status investigating")
    elif args.hypothesis_id is not None:
        errors.append("--hypothesis-id requires --campaign-ledger")

    if errors:
        return fail(errors)

    candidate_id = args.candidate_id.strip() if text(args.candidate_id) else args.output.stem
    if not candidate_id:
        return fail(["candidate id could not be derived from --output; pass --candidate-id"])

    candidate["candidate_id"] = candidate_id
    candidate["target_ledger_id"] = target["target_id"]
    candidate["target_fingerprint"] = target_fingerprint(target)
    candidate["campaign_id"] = campaign.get("campaign_id") if campaign is not None else None
    candidate["hypothesis_id"] = args.hypothesis_id if campaign is not None else None
    bound = candidate.setdefault("target", {})
    for key in (
        "platform", "route_type", "asset_type", "program", "asset",
        "repository", "commit", "operating_mode",
    ):
        bound[key] = canonical_target_value(target, key)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
    print(f"CANDIDATE CREATED: {args.output}")
    if campaign is None:
        print("Default mode: investigate this invariant without campaign bookkeeping.")
    else:
        print(f"Campaign mode: bound to {campaign['campaign_id']} / {args.hypothesis_id}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
