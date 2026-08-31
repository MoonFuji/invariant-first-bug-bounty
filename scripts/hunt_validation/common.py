"""Shared helpers for target-bound hunt validation."""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable


class ValidationError(Exception):
    """Raised for an unreadable or malformed input document."""


DEFAULT_CLOCK_SKEW = timedelta(minutes=5)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON in {path}: {exc}") from exc
    except OSError as exc:
        raise ValidationError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"document root must be a JSON object: {path}")
    return value


def text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def normalized(value: Any) -> str:
    return value.strip().casefold() if isinstance(value, str) else ""


def require_text(obj: dict[str, Any], key: str, path: str, errors: list[str]) -> None:
    if not text(obj.get(key)):
        errors.append(f"{path}.{key} must be a non-empty string")


def parse_iso(value: Any) -> datetime | None:
    if not text(value):
        return None
    raw = value.strip()
    try:
        if raw.endswith("Z"):
            parsed = datetime.fromisoformat(raw[:-1] + "+00:00")
        elif "T" in raw:
            parsed = datetime.fromisoformat(raw)
        else:
            parsed = datetime.combine(date.fromisoformat(raw), datetime.min.time(), tzinfo=UTC)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def require_iso(value: Any, path: str, errors: list[str]) -> None:
    if parse_iso(value) is None:
        errors.append(f"{path} must be a non-empty ISO-8601 date or timestamp")


def parse_timestamp(value: Any) -> datetime | None:
    """Parse an explicit timezone-bearing ISO-8601 timestamp.

    Durable ordering claims use this stricter format. Date-only and naive
    values remain accepted by parse_iso for legacy records, but cannot certify
    new workflow order.
    """
    if not text(value):
        return None
    raw = value.strip()
    if "T" not in raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00" if raw.endswith("Z") else raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def require_timestamp(value: Any, path: str, errors: list[str]) -> datetime | None:
    parsed = parse_timestamp(value)
    if parsed is None:
        errors.append(f"{path} must be an ISO-8601 timestamp with an explicit timezone")
    return parsed


def require_not_future(
    value: Any,
    path: str,
    errors: list[str],
    *,
    now: datetime | None = None,
    clock_skew: timedelta = DEFAULT_CLOCK_SKEW,
) -> datetime | None:
    parsed = require_timestamp(value, path, errors)
    if parsed is None:
        return None
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if parsed > current + clock_skew:
        errors.append(f"{path} must not be in the future")
    return parsed


def require_ordered(
    earlier: Any,
    earlier_path: str,
    later: Any,
    later_path: str,
    errors: list[str],
) -> None:
    first = require_timestamp(earlier, earlier_path, errors)
    second = require_timestamp(later, later_path, errors)
    if first is not None and second is not None and first > second:
        errors.append(f"{earlier_path} must be at or before {later_path}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ValidationError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def require_evidence(
    value: Any,
    path: str,
    errors: list[str],
    *,
    attempted: bool = False,
) -> None:
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object with method, source, artifact")
        return
    for key in ("method", "source", "artifact"):
        if not text(value.get(key)):
            errors.append(f"{path}.{key} must be a non-empty string")
    if attempted and normalized(value.get("method")) in {"none", "not_checked", "unavailable"}:
        errors.append(f"{path}.method must describe the attempted live retrieval")


def emit_messages(prefix: str, messages: Iterable[str]) -> None:
    for message in dict.fromkeys(messages):
        print(f"{prefix}: {message}", file=sys.stderr)
