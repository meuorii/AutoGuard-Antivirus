import errno, hashlib, os, stat
from pathlib import Path

from app.config import HASH_CHUNK_SIZE
from app.models import FileFingerprint, FileInspection

class FileChangedError(OSError): """The file's metadata changed while its content was being read."""
class FileTooLargeError(OSError): """A file exceeds the configured byte limit, including during a read."""
class UnsupportedFileError(ValueError): """The supplied entry cannot be handled as a regular file."""

def normalize_path(path: str | Path) -> Path: return Path(os.path.normcase(os.path.abspath(Path(path).expanduser())))
def is_link_or_reparse(info: os.stat_result) -> bool: return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
def _identity(info: os.stat_result) -> tuple[int, ...]: return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
def hash_file(path: str | Path, chunk_size: int = HASH_CHUNK_SIZE) -> FileFingerprint: return inspect_file(path, chunk_size=chunk_size).fingerprint

def inspect_file(path: str | Path, chunk_size: int = HASH_CHUNK_SIZE, *, preview_bytes: int = 0, max_size_bytes: int | None = None, follow_symlinks: bool = True) -> FileInspection:
    if chunk_size <= 0: raise ValueError("chunk_size must be greater than zero.")
    if preview_bytes < 0: raise ValueError("preview_bytes must not be negative.")
    if max_size_bytes is not None and (type(max_size_bytes) is not int or max_size_bytes < 0): raise ValueError("max_size_bytes must be a nonnegative integer or None.")
    normalized = normalize_path(path)

    def validate(info: os.stat_result) -> None:
        if not follow_symlinks and is_link_or_reparse(info): raise UnsupportedFileError(f"Links/reparse points are unsupported: {normalized}")
        if not stat.S_ISREG(info.st_mode): raise UnsupportedFileError(f"Only regular files can be observed: {normalized}")
        check_size(info.st_size)

    def check_size(size: int) -> None:
        if max_size_bytes is not None and size > max_size_bytes: raise FileTooLargeError(f"File exceeds size limit ({max_size_bytes} bytes).")

    def opener(name: str, flags: int) -> int:
        flags |= getattr(os, "O_NONBLOCK", 0)
        if not follow_symlinks: flags |= getattr(os, "O_NOFOLLOW", 0)
        try: return os.open(name, flags)
        except OSError as error:
            if not follow_symlinks and error.errno == errno.ELOOP: raise UnsupportedFileError(f"Link encountered while opening: {normalized}") from error
            raise

    initial = normalized.stat() if follow_symlinks else normalized.lstat()
    validate(initial)
    size_bytes, preview = 0, bytearray()

    with open(normalized, "rb", opener=opener) as stream:
        before = os.fstat(stream.fileno()); validate(before)
        if _identity(initial) != _identity(before): raise FileChangedError(f"File changed before hashing: {normalized}")
        digest = hashlib.sha256()
        while True:
            read_size = min(chunk_size, max_size_bytes - size_bytes + 1) if max_size_bytes is not None else chunk_size
            chunk = stream.read(read_size)
            if not chunk: break
            size_bytes += len(chunk); check_size(size_bytes); digest.update(chunk)
            remaining = preview_bytes - len(preview)
            if remaining > 0: preview.extend(chunk[:remaining])
        after = os.fstat(stream.fileno()); validate(after)

    current = normalized.stat() if follow_symlinks else normalized.lstat()
    validate(current)
    if _identity(before) != _identity(after) or _identity(after) != _identity(current) or size_bytes != after.st_size: raise FileChangedError(f"File changed while hashing: {normalized}")
    return FileInspection(FileFingerprint(digest.hexdigest(), str(normalized), size_bytes), bytes(preview))