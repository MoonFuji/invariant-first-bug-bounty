#!/usr/bin/env python3
"""Exercise the public target-bound command-line entry points.

The unit-style regression suite imports validator functions directly. These
smoke tests make sure the documented wrappers keep enforcing the boundary:
candidate stages require a target ledger, incomplete ledgers cannot generate a
candidate, and failures do not leave a misleading output artifact behind.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATE = ROOT / "scripts" / "validate_hunt.py"
START = ROOT / "scripts" / "start_candidate.py"
TARGET_TEMPLATE = ROOT / "assets" / "target.template.json"
CANDIDATE_TEMPLATE = ROOT / "assets" / "candidate.template.json"


def run(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *(str(arg) for arg in args)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def require(
    condition: bool,
    message: str,
    process: subprocess.CompletedProcess[str] | None = None,
) -> None:
    if condition:
        return
    detail = ""
    if process is not None:
        detail = (
            f"\nreturncode={process.returncode}"
            f"\nstdout={process.stdout.strip()}"
            f"\nstderr={process.stderr.strip()}"
        )
    raise AssertionError(message + detail)


def main() -> int:
    checks = 0

    help_result = run(VALIDATE, "--help")
    require(help_result.returncode == 0, "validate_hunt --help failed", help_result)
    require(
        "--target-ledger" in help_result.stdout,
        "wrapper help omitted --target-ledger",
        help_result,
    )
    checks += 1

    no_ledger = run(VALIDATE, "--stage", "model", CANDIDATE_TEMPLATE)
    require(
        no_ledger.returncode != 0,
        "candidate model stage accepted no target ledger",
        no_ledger,
    )
    checks += 1

    incomplete_target = run(VALIDATE, "--stage", "target", TARGET_TEMPLATE)
    require(
        incomplete_target.returncode != 0,
        "blank target template validated as selected",
        incomplete_target,
    )
    checks += 1

    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "candidate.json"
        start_result = run(
            START,
            "--target-ledger",
            TARGET_TEMPLATE,
            "--output",
            output,
        )
        require(
            start_result.returncode != 0,
            "candidate generated from an incomplete target",
            start_result,
        )
        require(
            not output.exists(),
            "failed candidate generation left an output artifact",
            start_result,
        )
        checks += 1

    print(f"{checks}/{checks} target-bound CLI smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
