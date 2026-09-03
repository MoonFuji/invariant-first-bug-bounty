"""Exact-file final handoff validation with one fresh review over the actual bundle."""
from __future__ import annotations
import json, re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from .candidate import PROOF_TYPE_TO_TARGET_POLICY, SEVERITY_RANK
from .common import ValidationError, parse_timestamp, require_evidence, require_not_future, require_string_list, require_text, sha256_file, text
from .target import ACCEPTED_PROOF_TYPES, MAX_SEVERITIES

SUBMISSION_SCHEMA_VERSION = 2
FINAL_REVIEW_SCHEMA_VERSION = 2
FINAL_FRESHNESS = timedelta(days=7)
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
REVIEW_MODES = {"independent_agent", "human"}


def _add(errors: list[str], message: str) -> None:
    if message not in errors: errors.append(message)


def _path_for(base: Path, value: Any, label: str, errors: list[str]) -> Path | None:
    if not text(value): _add(errors, f"{label}.path must be a non-empty relative path"); return None
    raw = Path(value.strip())
    if raw.is_absolute(): _add(errors, f"{label}.path must be relative"); return None
    root = base.resolve(); resolved = (root / raw).resolve()
    try: resolved.relative_to(root)
    except ValueError: _add(errors, f"{label}.path must stay inside the bundle directory"); return None
    if not resolved.is_file(): _add(errors, f"{label} file not found: {value}"); return None
    return resolved


def _file_ref(value: Any, base: Path, label: str, errors: list[str], *, suffix: str | None = None) -> Path | None:
    if not isinstance(value, dict): _add(errors, f"{label} must be an object with path and sha256"); return None
    path = _path_for(base, value.get("path"), label, errors); expected = value.get("sha256")
    if not isinstance(expected, str) or not SHA256_RE.fullmatch(expected): _add(errors, f"{label}.sha256 must be a 64-character hexadecimal SHA-256"); expected = ""
    if suffix and text(value.get("path")) and not str(value["path"]).lower().endswith(suffix): _add(errors, f"{label}.path must reference a {suffix} file")
    if path is not None and expected:
        try: actual = sha256_file(path)
        except ValidationError as exc: _add(errors, f"{label} cannot be hashed: {exc}")
        else:
            if actual.casefold() != expected.casefold(): _add(errors, f"{label} sha-256 does not match the file bytes")
    return path


def _load_object(path: Path | None, label: str, errors: list[str]) -> dict[str, Any]:
    if path is None: return {}
    try: value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc: _add(errors, f"{label} must be readable UTF-8 JSON: {exc}"); return {}
    if not isinstance(value, dict): _add(errors, f"{label} root must be an object"); return {}
    return value


def _same_ref(left: Any, right: Any) -> bool:
    return isinstance(left, dict) and isinstance(right, dict) and left.get("path") == right.get("path") and str(left.get("sha256", "")).casefold() == str(right.get("sha256", "")).casefold()


def validate_submission(submission: dict[str, Any], submission_path: Path, candidate: dict[str, Any], target: dict[str, Any], errors: list[str], *, now: datetime | None = None) -> None:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if submission.get("schema_version") != SUBMISSION_SCHEMA_VERSION: _add(errors, f"submission.schema_version must be {SUBMISSION_SCHEMA_VERSION}")
    for key in ("submission_id", "candidate_id", "target_id"): require_text(submission, key, "submission", errors)
    if submission.get("candidate_id") != candidate.get("candidate_id"): _add(errors, "submission.candidate_id must match candidate.candidate_id")
    if submission.get("target_id") != target.get("target_id"): _add(errors, "submission.target_id must match target.target_id")
    base = submission_path.resolve().parent; files = submission.get("files")
    if not isinstance(files, dict): _add(errors, "submission.files must be an object"); return
    candidate_path = _file_ref(files.get("candidate"), base, "submission.files.candidate", errors, suffix=".json")
    report_path = _file_ref(files.get("report"), base, "submission.files.report", errors, suffix=".md")
    if candidate_path is not None:
        disk_candidate = _load_object(candidate_path, "submission.files.candidate", errors)
        if disk_candidate and disk_candidate != candidate: _add(errors, "submission candidate bytes do not match the candidate supplied for validation")
    report_text = ""
    if report_path is not None:
        try: report_text = report_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc: _add(errors, f"submission report must be readable UTF-8 Markdown: {exc}")
        if not report_text.strip(): _add(errors, "submission report must not be empty")
    attachments = files.get("attachments")
    if not isinstance(attachments, list): _add(errors, "submission.files.attachments must be an array"); attachments = []
    seen: set[Path] = set()
    for i, attachment in enumerate(attachments):
        label = f"submission.files.attachments[{i}]"; path = _file_ref(attachment, base, label, errors)
        if isinstance(attachment, dict): require_text(attachment, "role", label, errors)
        if path is not None:
            if path in seen: _add(errors, "submission attachments must not repeat a file")
            seen.add(path)
            if report_text and path.name not in report_text: _add(errors, f"{label} filename must appear in report.md")
    if report_text:
        required = [("candidate.invariant", candidate.get("invariant")), ("candidate.claim.capability", candidate.get("claim", {}).get("capability") if isinstance(candidate.get("claim"), dict) else None), ("candidate.claim.impact", candidate.get("claim", {}).get("impact") if isinstance(candidate.get("claim"), dict) else None), ("candidate.proof.command", candidate.get("proof", {}).get("command") if isinstance(candidate.get("proof"), dict) else None)]
        limitations = candidate.get("claim", {}).get("limitations") if isinstance(candidate.get("claim"), dict) else []
        if isinstance(limitations, list): required.extend((f"candidate.claim.limitations[{i}]", v) for i, v in enumerate(limitations))
        unsupported = candidate.get("recovery", {}).get("unsupported_claims") if isinstance(candidate.get("recovery"), dict) else []
        if isinstance(unsupported, list): required.extend((f"candidate.recovery.unsupported_claims[{i}]", v) for i, v in enumerate(unsupported))
        for label, value in required:
            if text(value) and value not in report_text: _add(errors, f"{label} must appear verbatim in report.md")
    preflight = submission.get("preflight")
    if not isinstance(preflight, dict): _add(errors, "submission.preflight must be an object"); return
    scope = preflight.get("scope")
    if not isinstance(scope, dict): _add(errors, "submission.preflight.scope must be an object")
    else:
        if scope.get("status") != "eligible": _add(errors, "submission.preflight.scope.status must be eligible")
        require_text(scope, "asset_identifier", "submission.preflight.scope", errors)
        if scope.get("asset_identifier") != target.get("scope", {}).get("asset_identifier"): _add(errors, "submission.preflight.scope.asset_identifier must match target scope asset_identifier")
        if scope.get("max_severity") not in MAX_SEVERITIES: _add(errors, "submission.preflight.scope.max_severity is invalid")
        require_not_future(scope.get("checked_at"), "submission.preflight.scope.checked_at", errors, now=current, max_age=FINAL_FRESHNESS); require_evidence(scope.get("evidence"), "submission.preflight.scope.evidence", errors)
    policy = preflight.get("proof_policy")
    if not isinstance(policy, dict): _add(errors, "submission.preflight.proof_policy must be an object")
    else:
        if policy.get("status") != "checked": _add(errors, "submission.preflight.proof_policy.status must be checked")
        accepted = require_string_list(policy.get("accepted_proof_types"), "submission.preflight.proof_policy.accepted_proof_types", errors, nonempty=True)
        if [item for item in accepted if item not in ACCEPTED_PROOF_TYPES]: _add(errors, "submission.preflight.proof_policy.accepted_proof_types contains invalid proof types")
        require_not_future(policy.get("checked_at"), "submission.preflight.proof_policy.checked_at", errors, now=current, max_age=FINAL_FRESHNESS); require_evidence(policy.get("evidence"), "submission.preflight.proof_policy.evidence", errors)
        proof = candidate.get("proof") if isinstance(candidate.get("proof"), dict) else {}
        if not PROOF_TYPE_TO_TARGET_POLICY.get(proof.get("type"), set()).intersection(set(accepted)): _add(errors, "fresh submission proof policy does not accept candidate proof.type")
    claim = candidate.get("claim") if isinstance(candidate.get("claim"), dict) else {}; fresh_max = scope.get("max_severity") if isinstance(scope, dict) else None; ceiling = claim.get("severity_ceiling")
    if fresh_max in SEVERITY_RANK and ceiling in SEVERITY_RANK and SEVERITY_RANK[ceiling] > SEVERITY_RANK[fresh_max]: _add(errors, "candidate claim.severity_ceiling exceeds fresh submission scope.max_severity")
    prepared = require_not_future(submission.get("prepared_at"), "submission.prepared_at", errors, now=current, max_age=FINAL_FRESHNESS)
    for block, label in ((scope, "scope"), (policy, "proof_policy")):
        if prepared is not None and isinstance(block, dict):
            checked = parse_timestamp(block.get("checked_at"))
            if checked is not None and checked > prepared: _add(errors, f"submission preflight {label}.checked_at must be on or before prepared_at")


def validate_final_review(review: dict[str, Any], review_path: Path, submission: dict[str, Any], submission_path: Path, errors: list[str], *, now: datetime | None = None) -> None:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if review.get("schema_version") != FINAL_REVIEW_SCHEMA_VERSION: _add(errors, f"review.schema_version must be {FINAL_REVIEW_SCHEMA_VERSION}")
    if review.get("review_type") != "final_submission": _add(errors, "review.review_type must be final_submission")
    if review.get("verdict") not in {"SUBMISSION_READY", "NOT_READY", "REJECTED"}: _add(errors, "review.verdict must be SUBMISSION_READY, NOT_READY, or REJECTED")
    reviewer = review.get("reviewer")
    if not isinstance(reviewer, dict): _add(errors, "review.reviewer must be an object"); reviewed_at = None
    else:
        mode = require_text(reviewer, "mode", "review.reviewer", errors)
        if mode not in REVIEW_MODES: _add(errors, "review.reviewer.mode must be independent_agent or human")
        require_text(reviewer, "id", "review.reviewer", errors)
        reviewed_at = require_not_future(reviewer.get("reviewed_at"), "review.reviewer.reviewed_at", errors, now=current, max_age=FINAL_FRESHNESS)
        if not isinstance(reviewer.get("fresh_context"), bool): _add(errors, "review.reviewer.fresh_context must be boolean")
        elif mode == "independent_agent" and reviewer.get("fresh_context") is not True: _add(errors, "independent_agent final review requires fresh_context true")
    base = review_path.resolve().parent
    submission_ref = _file_ref(review.get("submission"), base, "review.submission", errors, suffix=".json"); _file_ref(review.get("candidate"), base, "review.candidate", errors, suffix=".json"); _file_ref(review.get("report"), base, "review.report", errors, suffix=".md")
    if submission_ref is not None and submission_ref != submission_path.resolve(): _add(errors, "review.submission.path must match the submission under validation")
    disk_submission = _load_object(submission_ref, "review.submission", errors)
    if disk_submission and disk_submission != submission: _add(errors, "review.submission bytes do not match submission supplied for validation")
    files = submission.get("files") if isinstance(submission.get("files"), dict) else {}
    if not _same_ref(review.get("candidate"), files.get("candidate")): _add(errors, "review.candidate must exactly match submission.files.candidate")
    if not _same_ref(review.get("report"), files.get("report")): _add(errors, "review.report must exactly match submission.files.report")
    reviewed = review.get("attachments"); submitted = files.get("attachments")
    if not isinstance(reviewed, list): _add(errors, "review.attachments must be an array"); reviewed = []
    if not isinstance(submitted, list): submitted = []
    if len(reviewed) != len(submitted): _add(errors, "review.attachments must contain exactly the submission attachment manifest")
    for i, item in enumerate(reviewed):
        _file_ref(item, base, f"review.attachments[{i}]", errors)
        if i < len(submitted):
            expected = submitted[i]
            if not _same_ref(item, expected) or not isinstance(item, dict) or item.get("role") != expected.get("role"): _add(errors, f"review.attachments[{i}] must exactly match submission attachment")
    prepared = parse_timestamp(submission.get("prepared_at"))
    if prepared is None: _add(errors, "submission.prepared_at must be valid before final review")
    elif reviewed_at is not None and reviewed_at < prepared: _add(errors, "final review must be completed after submission.prepared_at")
    if review.get("verdict") != "SUBMISSION_READY": _add(errors, "final review must affirm SUBMISSION_READY for readiness output")
