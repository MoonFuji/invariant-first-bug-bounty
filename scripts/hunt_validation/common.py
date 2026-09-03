"""Shared helpers for hunt validation."""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

DEFAULT_CLOCK_SKEW = timedelta(minutes=5)


class ValidationError(Exception):
    """Raised for unreadable or malformed input."""


def text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def normalized(value: Any) -> str:
    return value.strip().casefold() if isinstance(value, str) else ""


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"file not found: {path}") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"{path} root must be a JSON object")
    return value


def require_text(obj: Any, key: str, path: str, errors: list[str]) -> str:
    if not isinstance(obj, dict) or not text(obj.get(key)):
        errors.append(f"{path}.{key} must be a non-empty string")
        return ""
    return obj[key].strip()


def require_string_list(value: Any, path: str, errors: list[str], *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list):
        errors.append(f"{path} must be an array")
        return []
    if nonempty and not value:
        errors.append(f"{path} must contain at least one item")
    if any(not text(item) for item in value):
        errors.append(f"{path} must contain only non-empty strings")
    return [item.strip() for item in value if text(item)]


def require_evidence(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object with method, source, and artifact")
        return
    for key in ("method", "source", "artifact"):
        require_text(value, key, path, errors)


def require_search_evidence(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object with method, query, and artifact")
        return
    for key in ("method", "query", "artifact"):
        require_text(value, key, path, errors)


def parse_timestamp(value: Any) -> datetime | None:
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


def require_not_future(value: Any, path: str, errors: list[str], *, now: datetime | None = None, max_age: timedelta | None = None) -> datetime | None:
    parsed = parse_timestamp(value)
    if parsed is None:
        errors.append(f"{path} must be an ISO-8601 timestamp with an explicit timezone")
        return None
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if parsed > current + DEFAULT_CLOCK_SKEW:
        errors.append(f"{path} must not be in the future")
    if max_age is not None and current - parsed > max_age:
        errors.append(f"{path} is stale (older than {max_age.days} days)")
    return parsed


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ValidationError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def emit_messages(prefix: str, messages: Iterable[str]) -> None:
    for message in dict.fromkeys(messages):
        print(f"{prefix}: {message}", file=sys.stderr)
