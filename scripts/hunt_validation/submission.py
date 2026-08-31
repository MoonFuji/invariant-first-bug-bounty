"""Exact-file validation for the final submission handoff.

The submission layer is deliberately separate from candidate validation.  A
candidate can be technically sound while its later report drifts in title,
impact, scope, or reproduction.  This module binds the files that will be
sent to the reviewed candidate and requires a second, timestamped attestation.

SHA-256 here authenticates bytes, not the truth of a claim or the independence
of a reviewer.  Paths in manifests are relative to the document containing
the manifest and may not escape that document's directory.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .common import DEFAULT_CLOCK_SKEW, ValidationError, parse_timestamp, sha256_file, text

SUBMISSION_SCHEMA_VERSION = 1
REVIEW_SCHEMA_VERSION = 1
# Campaign evidence can be older while work is in progress. The final handoff
# requires a recent platform preflight because scope and proof rules can change
# independently of the pinned source revision.
DEFAULT_FRESHNESS = timedelta(days=7)
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
REVIEW_MODES = {"independent_agent", "human"}
SEVERITY_RANK = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _now(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


def _add(errors: list[str], message: str) -> None:
    if message not in errors:
        errors.append(message)


def _required(document: dict[str, Any], key: str, path: str, errors: list[str]) -> Any:
    if key not in document:
        _add(errors, f"{path}.{key} is required")
        return None
    return document[key]


def _required_text(document: dict[str, Any], key: str, path: str, errors: list[str]) -> str:
    value = _required(document, key, path, errors)
    if value is None:
        return ""
    if not text(value):
        _add(errors, f"{path}.{key} must be a non-empty string")
        return ""
    return value.strip()


def _required_object(document: dict[str, Any], key: str, path: str, errors: list[str]) -> dict[str, Any]:
    value = _required(document, key, path, errors)
    if not isinstance(value, dict):
        _add(errors, f"{path}.{key} must be an object")
        return {}
    return value


def _checked_at(
    value: Any,
    label: str,
    current: datetime,
    errors: list[str],
    freshness: timedelta | None,
) -> datetime | None:
    parsed = parse_timestamp(value)
    if parsed is None:
        _add(errors, f"{label} must be an ISO-8601 timestamp with an explicit timezone")
        return None
    if parsed > current + DEFAULT_CLOCK_SKEW:
        _add(errors, f"{label} is in the future")
    if freshness is not None and current - parsed > freshness:
        _add(errors, f"{label} is stale (older than {freshness.days} days)")
    return parsed


def _path_for(base: Path, value: Any, label: str, errors: list[str]) -> Path | None:
    if not text(value):
        _add(errors, f"{label}.path must be a non-empty relative path")
        return None
    raw = Path(value.strip())
    if raw.is_absolute():
        _add(errors, f"{label}.path must be relative to the containing document")
        return None
    root = base.resolve()
    resolved = (root / raw).resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        _add(errors, f"{label}.path must stay inside the containing document directory")
        return None
    if not resolved.is_file():
        _add(errors, f"{label} file not found: {value}")
        return None
    return resolved


def _file_ref(
    value: Any,
    base: Path,
    label: str,
    errors: list[str],
    *,
    suffix: str | None = None,
) -> tuple[Path | None, str]:
    if not isinstance(value, dict):
        _add(errors, f"{label} must be an object with path and sha256")
        return None, ""
    path = _path_for(base, value.get("path"), label, errors)
    expected = value.get("sha256")
    if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
        _add(errors, f"{label}.sha256 must be a 64-character hexadecimal SHA-256")
        expected = ""
    if suffix and text(value.get("path")) and not str(value["path"]).lower().endswith(suffix):
        _add(errors, f"{label}.path must reference a {suffix} file")
    if path is not None and expected:
        try:
            actual = sha256_file(path)
        except ValidationError as exc:
            _add(errors, f"{label} cannot be hashed: {exc}")
        else:
            if actual.casefold() != expected.casefold():
                _add(errors, f"{label} sha-256 does not match the file bytes")
    return path, expected


def _load_object(path: Path | None, label: str, errors: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _add(errors, f"{label} must be readable UTF-8 JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        _add(errors, f"{label} root must be an object")
        return {}
    return value


def _evidence(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        _add(errors, f"{label} must be an object with method, source, and artifact")
        return
    for key in ("method", "source", "artifact"):
        if not text(value.get(key)):
            _add(errors, f"{label}.{key} must be a non-empty string")


def _preflight(
    document: dict[str, Any],
    current: datetime,
    errors: list[str],
    freshness: timedelta,
) -> list[datetime]:
    block = _required_object(document, "preflight", "submission", errors)
    result: list[datetime] = []
    scope = _required_object(block, "scope", "submission.preflight", errors)
    if scope.get("status") != "eligible":
        _add(errors, "submission.preflight.scope.status must be eligible")
    _required_text(scope, "asset_identifier", "submission.preflight.scope", errors)
    checked = _checked_at(scope.get("checked_at"), "submission.preflight.scope.checked_at", current, errors, freshness)
    if checked is not None:
        result.append(checked)
    _evidence(scope.get("evidence"), "submission.preflight.scope.evidence", errors)

    policy = _required_object(block, "proof_policy", "submission.preflight", errors)
    if policy.get("status") not in {"accepted", "checked"}:
        _add(errors, "submission.preflight.proof_policy.status must be accepted or checked")
    _required_text(policy, "accepted_proof_type", "submission.preflight.proof_policy", errors)
    checked = _checked_at(
        policy.get("checked_at"), "submission.preflight.proof_policy.checked_at", current, errors, freshness
    )
    if checked is not None:
        result.append(checked)
    _evidence(policy.get("evidence"), "submission.preflight.proof_policy.evidence", errors)
    return result


def _claim_scope(candidate: dict[str, Any], submission: dict[str, Any], errors: list[str]) -> None:
    scope = candidate.get("claim_scope")
    if not isinstance(scope, dict):
        _add(errors, "candidate.claim_scope is required to bound submission claims")
        return
    candidate_target = candidate.get("target") if isinstance(candidate.get("target"), dict) else {}
    if candidate_target.get("asset") != submission.get("asset"):
        _add(errors, "submission asset does not match candidate.target.asset")
    if text(candidate_target.get("commit")) and candidate_target.get("commit") != submission.get("version"):
        _add(errors, "submission version must match candidate.target.commit")
    demonstrated = submission.get("demonstrated") if isinstance(submission.get("demonstrated"), dict) else {}
    for key, candidate_key in (
        ("capability", "demonstrated_capability"),
        ("impact", "demonstrated_impact"),
    ):
        bound = scope.get(candidate_key)
        if not text(bound):
            _add(errors, f"candidate.claim_scope.{candidate_key} must bound the submission claim")
        elif demonstrated.get(key) != bound:
            _add(errors, f"submission {key} must exactly match candidate.claim_scope.{candidate_key}")

    # A primitive alone is not enough. An exact executable effect may be a
    # bounded reportable impact in its own right, so do not force every valid
    # narrow finding to claim an owned production deployment.
    rung_order = {"none": 0, "primitive": 1, "exact_executable": 2, "owned_boundary": 3, "demonstrated_impact": 4, "severity": 5}
    rung = scope.get("highest_proven_rung")
    if not isinstance(rung, str) or rung not in rung_order:
        _add(errors, "candidate.claim_scope.highest_proven_rung is invalid")
    elif rung_order[rung] < rung_order["exact_executable"]:
        _add(errors, "submission requires at least an exact executable proven claim")

    severity = submission.get("severity")
    ceiling = scope.get("severity_ceiling")
    if not isinstance(ceiling, str) or ceiling.casefold() not in SEVERITY_RANK:
        _add(errors, "candidate.claim_scope.severity_ceiling must be an accepted severity name")
    elif not isinstance(severity, str) or severity.casefold() not in SEVERITY_RANK:
        _add(errors, "submission.severity must be an accepted severity name")
    elif SEVERITY_RANK[severity.casefold()] > SEVERITY_RANK[ceiling.casefold()]:
        _add(errors, "submission severity exceeds candidate.claim_scope.severity_ceiling")


def validate_submission(
    document: dict[str, Any],
    submission_path: Path,
    errors: list[str],
    *,
    now: datetime | None = None,
    freshness: timedelta = DEFAULT_FRESHNESS,
) -> None:
    """Validate a submission manifest and every referenced byte artifact."""
    current = _now(now)
    if document.get("schema_version") != SUBMISSION_SCHEMA_VERSION:
        _add(errors, f"submission.schema_version must be {SUBMISSION_SCHEMA_VERSION}")
    for key in ("submission_id", "campaign_id", "candidate_id", "asset", "version", "title", "weakness", "severity"):
        _required_text(document, key, "submission", errors)
    report = _required_object(document, "report", "submission", errors)
    if "body" in document:
        _add(errors, "submission.body must not embed report text; use submission.report.path")
    report_path, _ = _file_ref(report, submission_path.resolve().parent, "submission.report", errors, suffix=".md")
    report_text = ""
    if report_path is not None:
        try:
            report_text = report_path.read_text(encoding="utf-8")
            if not report_text.strip():
                _add(errors, "submission.report must contain non-empty UTF-8 Markdown")
        except (OSError, UnicodeDecodeError) as exc:
            _add(errors, f"submission.report must be readable UTF-8 Markdown: {exc}")

    cvss = _required_object(document, "cvss", "submission", errors)
    score = cvss.get("score")
    if not isinstance(score, (int, float)) or isinstance(score, bool) or not 0 <= score <= 10:
        _add(errors, "submission.cvss.score must be a number from 0 through 10")
    _required_text(cvss, "vector", "submission.cvss", errors)
    demonstrated = _required_object(document, "demonstrated", "submission", errors)
    _required_text(demonstrated, "capability", "submission.demonstrated", errors)
    _required_text(demonstrated, "impact", "submission.demonstrated", errors)
    reproduction = _required_object(document, "reproduction", "submission", errors)
    commands = reproduction.get("commands")
    if not isinstance(commands, list) or not commands or any(not text(command) for command in commands):
        _add(errors, "submission.reproduction.commands must contain non-empty commands")
    elif report_text:
        for index, command in enumerate(commands):
            if command not in report_text:
                _add(errors, f"submission.reproduction.commands[{index}] must appear verbatim in report.md")

    if report_text and text(document.get("title")) and document["title"] not in report_text:
        _add(errors, "submission.title must appear verbatim in report.md")

    attachments = _required(document, "attachments", "submission", errors)
    if not isinstance(attachments, list):
        _add(errors, "submission.attachments must be an array")
        attachments = []
    attachment_paths: list[tuple[Path, str, str]] = []
    for index, attachment in enumerate(attachments):
        label = f"submission.attachments[{index}]"
        path, expected = _file_ref(attachment, submission_path.resolve().parent, label, errors)
        if isinstance(attachment, dict) and not text(attachment.get("role")):
            _add(errors, f"{label}.role must be a non-empty string")
        if path is not None:
            attachment_paths.append((path, expected, attachment.get("role", "") if isinstance(attachment, dict) else ""))
            if report_text and path.name not in report_text:
                _add(errors, f"{label} filename must appear in report.md")
    if len({path for path, _, _ in attachment_paths}) != len(attachment_paths):
        _add(errors, "submission.attachments must not repeat a file")

    candidate_path, _ = _file_ref(
        _required(document, "candidate_artifact", "submission", errors),
        submission_path.resolve().parent,
        "submission.candidate_artifact",
        errors,
    )
    candidate = _load_object(candidate_path, "submission.candidate_artifact", errors)
    if candidate and candidate.get("candidate_id") != document.get("candidate_id"):
        _add(errors, "submission.candidate_id must match candidate_artifact.candidate_id")
    if candidate and text(candidate.get("campaign_id")) and candidate.get("campaign_id") != document.get("campaign_id"):
        _add(errors, "submission.campaign_id must match candidate_artifact.campaign_id")
    _claim_scope(candidate, document, errors)
    claim_scope = candidate.get("claim_scope") if isinstance(candidate.get("claim_scope"), dict) else {}
    unsupported = claim_scope.get("unsupported_extensions")
    if isinstance(unsupported, list) and report_text:
        for index, limitation in enumerate(unsupported):
            if text(limitation) and limitation not in report_text:
                _add(
                    errors,
                    f"candidate.claim_scope.unsupported_extensions[{index}] must appear verbatim in report.md",
                )

    preflight_times = _preflight(document, current, errors, freshness)
    prepared = _checked_at(document.get("prepared_at"), "submission.prepared_at", current, errors, freshness)
    if prepared is not None:
        for checked in preflight_times:
            if checked > prepared:
                _add(errors, "submission preflight timestamps must be on or before prepared_at")
    if report_path is None:
        return


def _reviewer(
    review: dict[str, Any],
    errors: list[str],
    current: datetime,
    freshness: timedelta | None,
) -> datetime | None:
    reviewer = _required_object(review, "reviewer", "review", errors)
    mode = _required_text(reviewer, "mode", "review.reviewer", errors)
    if mode not in REVIEW_MODES:
        _add(errors, "review.reviewer.mode must be independent_agent or human")
    _required_text(reviewer, "id", "review.reviewer", errors)
    reviewed_at = _checked_at(reviewer.get("reviewed_at"), "review.reviewer.reviewed_at", current, errors, freshness)
    fresh = reviewer.get("fresh_context")
    if not isinstance(fresh, bool):
        _add(errors, "review.reviewer.fresh_context must be boolean")
    elif mode == "independent_agent" and fresh is not True:
        _add(errors, "independent_agent review requires fresh_context true")
    return reviewed_at


def validate_candidate_review_sidecar(
    review: dict[str, Any],
    review_path: Path,
    errors: list[str],
    *,
    candidate_path: Path | None = None,
    now: datetime | None = None,
    freshness: timedelta | None = None,
) -> None:
    """Validate a generic candidate review sidecar against exact candidate bytes."""
    current = _now(now)
    if review.get("schema_version") != REVIEW_SCHEMA_VERSION:
        _add(errors, f"review.schema_version must be {REVIEW_SCHEMA_VERSION}")
    if review.get("review_type") != "candidate":
        _add(errors, "review.review_type must be candidate")
    reviewed_at = _reviewer(review, errors, current, freshness)
    verdict = _required_text(review, "verdict", "review", errors)
    terminal_verdicts = {
        "REPORTABLE", "KILL", "ROUTE_ELSEWHERE", "NO_REPORTABLE_FINDING",
        "NOT_READY", "REJECTED",
    }
    if verdict not in terminal_verdicts:
        _add(errors, "candidate review.verdict is not recognized")
    path, _ = _file_ref(review.get("candidate"), review_path.resolve().parent, "review.candidate", errors)
    if candidate_path is not None and path is not None and path != candidate_path.resolve():
        _add(errors, "review.candidate.path does not match the candidate under review")
    candidate = _load_object(path, "review.candidate", errors)
    decision = candidate.get("decision") if isinstance(candidate.get("decision"), dict) else {}
    candidate_verdict = decision.get("verdict")
    if candidate_verdict in {"REPORTABLE", "KILL", "ROUTE_ELSEWHERE", "NO_REPORTABLE_FINDING"} and verdict != candidate_verdict:
        _add(errors, "candidate review.verdict must match candidate.decision.verdict")
    decided_at = parse_timestamp(decision.get("decided_at"))
    if decided_at is None:
        _add(errors, "reviewed candidate decision.decided_at must be a timezone-bearing timestamp")
    elif reviewed_at is not None and reviewed_at < decided_at:
        _add(errors, "candidate review must be completed after candidate decision.decided_at")


def _same_ref(left: Any, right: Any) -> bool:
    return isinstance(left, dict) and isinstance(right, dict) and left.get("path") == right.get("path") and str(left.get("sha256", "")).casefold() == str(right.get("sha256", "")).casefold()


def validate_submission_review_sidecar(
    review: dict[str, Any],
    review_path: Path,
    errors: list[str],
    *,
    submission: dict[str, Any],
    submission_path: Path,
    now: datetime | None = None,
    freshness: timedelta = DEFAULT_FRESHNESS,
) -> None:
    """Validate a submission review sidecar and bind every reviewed artifact."""
    current = _now(now)
    if review.get("schema_version") != REVIEW_SCHEMA_VERSION:
        _add(errors, f"review.schema_version must be {REVIEW_SCHEMA_VERSION}")
    if review.get("review_type") != "submission":
        _add(errors, "review.review_type must be submission")
    reviewed_at = _reviewer(review, errors, current, freshness)
    verdict = _required_text(review, "verdict", "review", errors)
    if verdict not in {"SUBMISSION_READY", "NOT_READY", "REJECTED"}:
        _add(errors, "submission review.verdict must be SUBMISSION_READY, NOT_READY, or REJECTED")

    base = review_path.resolve().parent
    submission_ref_path, _ = _file_ref(review.get("submission"), base, "review.submission", errors)
    candidate_ref_path, candidate_digest = _file_ref(review.get("candidate"), base, "review.candidate", errors)
    report_ref_path, report_digest = _file_ref(review.get("report"), base, "review.report", errors)
    if submission_ref_path is not None and submission_ref_path != submission_path.resolve():
        _add(errors, "review.submission.path does not match the submission under review")
    disk_submission = _load_object(submission_ref_path, "review.submission", errors)
    if disk_submission and disk_submission != submission:
        _add(errors, "review.submission bytes do not represent the submission object supplied for validation")
    if isinstance(submission.get("candidate_artifact"), dict) and not _same_ref(review.get("candidate"), submission["candidate_artifact"]):
        _add(errors, "review.candidate must match submission.candidate_artifact")
    if isinstance(submission.get("report"), dict) and not _same_ref(review.get("report"), submission["report"]):
        _add(errors, "review.report must match submission.report")
    if candidate_ref_path is not None and submission.get("candidate_id"):
        candidate = _load_object(candidate_ref_path, "review.candidate", errors)
        if candidate and candidate.get("candidate_id") != submission.get("candidate_id"):
            _add(errors, "review.candidate must carry the submission candidate_id")
    if not candidate_digest or not report_digest:
        pass

    sidecar_attachments = review.get("attachments")
    if not isinstance(sidecar_attachments, list):
        _add(errors, "review.attachments must be an array")
        sidecar_attachments = []
    submission_attachments = submission.get("attachments")
    if not isinstance(submission_attachments, list):
        submission_attachments = []
    if len(sidecar_attachments) != len(submission_attachments):
        _add(errors, "review.attachments must contain exactly the submission attachment manifest")
    for index, attachment in enumerate(sidecar_attachments):
        label = f"review.attachments[{index}]"
        _file_ref(attachment, base, label, errors)
        if index < len(submission_attachments):
            expected = submission_attachments[index]
            if not _same_ref(attachment, expected) or not isinstance(attachment, dict) or attachment.get("role") != expected.get("role"):
                _add(errors, f"{label} must match submission.attachments[{index}] exactly")

    prepared = parse_timestamp(submission.get("prepared_at"))
    if prepared is None:
        _add(errors, "submission.prepared_at must be valid before submission review")
    elif reviewed_at is not None and reviewed_at < prepared:
        _add(errors, "submission review must be completed after prepared_at")


def validate_review_sidecar(
    review: dict[str, Any],
    review_path: Path,
    errors: list[str],
    *,
    candidate_path: Path | None = None,
    submission: dict[str, Any] | None = None,
    submission_path: Path | None = None,
    now: datetime | None = None,
    freshness: timedelta = DEFAULT_FRESHNESS,
) -> None:
    """Dispatch generic review validation for candidate or submission sidecars."""
    if review.get("review_type") == "candidate":
        validate_candidate_review_sidecar(review, review_path, errors, candidate_path=candidate_path, now=now, freshness=freshness)
    elif review.get("review_type") == "submission" and submission is not None and submission_path is not None:
        validate_submission_review_sidecar(review, review_path, errors, submission=submission, submission_path=submission_path, now=now, freshness=freshness)
    else:
        _add(errors, "review requires review_type candidate or submission and its matching context")
