import hashlib, json, re
from pathlib import Path
from types import MappingProxyType
from typing import Iterable
from app.models import Signature, SignatureKind

DEFAULT_SIGNATURES_PATH = Path(__file__).resolve().parent.parent / "data" / "signatures.json"
AUTOGUARD_TEST_CONTENT = b"AUTOGUARD-HARMLESS-TEST-FILE-V1\n"
AUTOGUARD_TEST_SHA256 = hashlib.sha256(AUTOGUARD_TEST_CONTENT).hexdigest()

class SignatureLoadError(ValueError):
    """Missing, unreadable, or invalid signature data."""

class SignatureStore:
    """An immutable hash index; creation does not read files."""
    def __init__(self, signatures: Iterable[Signature] = ()) -> None:
        by_hash: dict[str, Signature] = {}
        for signature in signatures:
            if not isinstance(signature, Signature): raise SignatureLoadError("Each entry must be a Signature.")
            if not isinstance(signature.name, str) or not signature.name.strip(): raise SignatureLoadError("Signature names must be nonempty strings.")
            if not isinstance(signature.description, str): raise SignatureLoadError("Signature descriptions must be strings.")
            if not isinstance(signature.sha256, str) or re.fullmatch(r"[0-9a-fA-F]{64}", signature.sha256) is None: raise SignatureLoadError("Invalid SHA-256 in signature data.")
            try: kind = SignatureKind(signature.kind)
            except (ValueError, TypeError) as error: raise SignatureLoadError("Unsupported signature kind.") from error
            digest = signature.sha256.lower()
            if kind is SignatureKind.AUTOGUARD_TEST and digest != AUTOGUARD_TEST_SHA256: raise SignatureLoadError("AutoGuard test signature hash is incorrect.")
            if digest in by_hash: raise SignatureLoadError(f"Duplicate signature SHA-256: {digest}")
            by_hash[digest] = Signature(signature.name.strip(), digest, kind, signature.description)
        self._by_hash = MappingProxyType(by_hash)

    def lookup(self, sha256: str) -> Signature | None: return self._by_hash.get(sha256.lower())
    def __len__(self) -> int: return len(self._by_hash)

def load_signatures(path: str | Path = DEFAULT_SIGNATURES_PATH) -> SignatureStore:
    """Fail explicitly on load errors; never silently use empty definitions."""
    path = Path(path).expanduser()
    try: payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error: raise SignatureLoadError(f"Cannot load signatures from {path}: {error}") from error
    if not isinstance(payload, dict) or type(payload.get("schema_version")) is not int or payload["schema_version"] != 1 or not isinstance(payload.get("signatures"), list):
        raise SignatureLoadError("Expected schema_version 1 and a signatures list.")
    try: entries = [Signature(**entry) for entry in payload["signatures"]]
    except TypeError as error: raise SignatureLoadError("Invalid signature fields.") from error
    return SignatureStore(entries)