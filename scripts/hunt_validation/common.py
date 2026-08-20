"""Shared helpers for target-bound hunt validation."""
from __future__ import annotations

import json
import sys
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Iterable


class ValidationError(Exception):
    """Raised for an unreadable or malformed input document."""


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


