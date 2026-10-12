"""Load and index AutoGuard SHA-256 signatures.

AUTOGUARD_TEST entries are explicitly labelled, harmless test fixtures. Multiple
unique test signatures are supported; no test hash is hardcoded in this module.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from types import MappingProxyType
from typing import Iterable

from app.models import Signature, SignatureKind

DEFAULT_SIGNATURES_PATH = Path(__file__).resolve().parent.parent / "data" / "signatures.json"
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")


class SignatureLoadError(ValueError):
    """Missing, unreadable, or invalid signature data."""


class SignatureStore:
    """An immutable SHA-256 index for configured signatures."""

    def __init__(self, signatures: Iterable[Signature] = ()) -> None:
        by_hash: dict[str, Signature] = {}

        for signature in signatures:
            if not isinstance(signature, Signature):
                raise SignatureLoadError("Each entry must be a Signature.")
            if not isinstance(signature.name, str) or not signature.name.strip():
                raise SignatureLoadError("Signature names must be nonempty strings.")
            if not isinstance(signature.description, str):
                raise SignatureLoadError("Signature descriptions must be strings.")
            if not isinstance(signature.sha256, str) or _SHA256_RE.fullmatch(signature.sha256) is None:
                raise SignatureLoadError("Invalid SHA-256 in signature data.")

            try:
                kind = SignatureKind(signature.kind)
            except (ValueError, TypeError) as error:
                raise SignatureLoadError("Unsupported signature kind.") from error

            digest = signature.sha256.lower()
            if digest in by_hash:
                raise SignatureLoadError(f"Duplicate signature SHA-256: {digest}")

            by_hash[digest] = Signature(
                name=signature.name.strip(),
                sha256=digest,
                kind=kind,
                description=signature.description.strip(),
            )

        self._by_hash = MappingProxyType(by_hash)

    def lookup(self, sha256: str) -> Signature | None:
        """Return the configured signature for a SHA-256 digest, if present."""
        if not isinstance(sha256, str) or _SHA256_RE.fullmatch(sha256) is None:
            return None
        return self._by_hash.get(sha256.lower())

    def __len__(self) -> int:
        return len(self._by_hash)


def load_signatures(path: str | Path = DEFAULT_SIGNATURES_PATH) -> SignatureStore:
    """Load schema-version-1 signature JSON; fail explicitly on invalid data."""
    signature_path = Path(path).expanduser()
    try:
        payload = json.loads(signature_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SignatureLoadError(
            f"Cannot load signatures from {signature_path}: {error}"
        ) from error

    if (
        not isinstance(payload, dict)
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
        or not isinstance(payload.get("signatures"), list)
    ):
        raise SignatureLoadError("Expected schema_version 1 and a signatures list.")

    entries: list[Signature] = []
    for index, entry in enumerate(payload["signatures"]):
        if not isinstance(entry, dict):
            raise SignatureLoadError(f"Signature entry {index} must be a JSON object.")
        try:
            entries.append(Signature(**entry))
        except TypeError as error:
            raise SignatureLoadError(
                f"Invalid fields in signature entry {index}."
            ) from error

    return SignatureStore(entries)
