import hashlib, os, stat
from pathlib import Path
from app.config import HASH_CHUNK_SIZE
from app.models import FileFingerprint, FileInspection

class FileChangedError(OSError):
    """The file's metadata changed while its content was being read."""

def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def hash_file(path: str | Path, chunk_size: int = HASH_CHUNK_SIZE) -> FileFingerprint:
    """Preserve the Phase 1 hashing interface used by ThreatTrail."""
    return inspect_file(path, chunk_size=chunk_size).fingerprint

def inspect_file(path: str | Path, chunk_size: int = HASH_CHUNK_SIZE, *, preview_bytes: int = 0) -> FileInspection:
    """Hash the full file and capture a bounded prefix during the same read."""
    if chunk_size <= 0: raise ValueError("chunk_size must be greater than zero.")
    if preview_bytes < 0: raise ValueError("preview_bytes must not be negative.")
    normalized = Path(os.path.normcase(os.path.abspath(Path(path).expanduser())))
    initial = normalized.stat()
    if not stat.S_ISREG(initial.st_mode): raise ValueError(f"Only regular files can be observed: {normalized}")
    digest, size_bytes, preview = hashlib.sha256(), 0, bytearray()
    with normalized.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if _identity(initial) != _identity(before): raise FileChangedError(f"File changed before hashing: {normalized}")
        while chunk := stream.read(chunk_size):
            digest.update(chunk); size_bytes += len(chunk)
            if (remaining := preview_bytes - len(preview)) > 0: preview.extend(chunk[:remaining])
        after = os.fstat(stream.fileno())
    current = normalized.stat()
    if _identity(before) != _identity(after) or _identity(after) != _identity(current) or size_bytes != after.st_size:
        raise FileChangedError(f"File changed while hashing: {normalized}")
    return FileInspection(FileFingerprint(digest.hexdigest(), str(normalized), size_bytes), bytes(preview))