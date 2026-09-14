from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.hashing import inspect_file


@dataclass(frozen=True)
class IntegrityResult:
    verified: bool
    expected_sha256: str
    actual_sha256: str | None
    expected_size: int | None
    actual_size: int | None
    checked_at: datetime
    error: str | None = None


def _normalize_sha256(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized): raise ValueError("expected_sha256 must be exactly 64 hexadecimal characters.")
    return normalized


def verify_quarantine_file(path: str | Path, expected_sha256: str, expected_size: int | None = None) -> IntegrityResult:
    """Hash a quarantined file and compare it with expected detection evidence."""
    expected_sha256 = _normalize_sha256(expected_sha256)
    if expected_size is not None and (type(expected_size) is not int or expected_size < 0): raise ValueError("expected_size must be a nonnegative integer or None.")

    checked_at = datetime.now(timezone.utc)
    try: inspection = inspect_file(path, follow_symlinks=False)
    except Exception as error: return IntegrityResult(verified=False, expected_sha256=expected_sha256, actual_sha256=None, expected_size=expected_size, actual_size=None, checked_at=checked_at, error=f"{type(error).__name__}: {error}")

    actual_sha256, actual_size = inspection.fingerprint.sha256, inspection.fingerprint.size_bytes
    problems: list[str] = []
    if actual_sha256 != expected_sha256: problems.append(f"SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}.")
    if expected_size is not None and actual_size != expected_size: problems.append(f"Size mismatch: expected {expected_size} bytes, got {actual_size} bytes.")

    return IntegrityResult(verified=not problems, expected_sha256=expected_sha256, actual_sha256=actual_sha256, expected_size=expected_size, actual_size=actual_size, checked_at=checked_at, error=" ".join(problems) if problems else None)