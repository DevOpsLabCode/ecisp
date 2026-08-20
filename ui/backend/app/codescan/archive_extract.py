"""Safe extraction of user-uploaded .zip/.tar/.tar.gz/.tgz archives.

The archive is untrusted input, so every member is checked before a single
byte is written:

  - path traversal ("zip-slip"/"tar-slip"): a member whose resolved
    destination path falls outside `dest_dir` is rejected outright, whether
    via `../` segments, an absolute path, or a symlink target that escapes.
  - decompression bombs: both a per-file and a running total size cap are
    enforced against the archive's own declared sizes *before* extracting,
    and actual bytes written are also capped during extraction in case the
    declared size lied.
  - member count cap, independent of size, against a bomb built from many
    tiny files.
  - only regular files and directories are extracted; symlinks, hardlinks,
    device/fifo/character-special members are rejected rather than
    followed, since a symlink is exactly how a "contained" path can end up
    pointing outside `dest_dir` at read time even if its own name looked
    safe.

This module only ever reads/writes files -- nothing here executes anything
from the archive.
"""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

MAX_TOTAL_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 500MB
MAX_SINGLE_FILE_BYTES = 100 * 1024 * 1024  # 100MB
MAX_MEMBER_COUNT = 50_000

_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_GZIP_MAGIC = b"\x1f\x8b"


class UnsafeArchiveError(ValueError):
    """The archive is malformed, oversized, or contains an unsafe member."""


def _detect_kind(path: Path) -> str:
    with open(path, "rb") as f:
        head = f.read(262)
    if head.startswith(_ZIP_MAGIC):
        return "zip"
    if head.startswith(_GZIP_MAGIC):
        return "tar.gz"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    raise UnsafeArchiveError("Unrecognized archive format (expected zip, tar, or tar.gz)")


def _safe_dest(dest_dir: Path, member_name: str) -> Path:
    # Reject absolute paths and drive letters outright -- Path.joinpath
    # with an absolute operand *discards* dest_dir entirely, which would
    # silently defeat the containment check below if not caught first.
    if member_name.startswith(("/", "\\")) or (len(member_name) > 1 and member_name[1] == ":"):
        raise UnsafeArchiveError(f"Archive member has an absolute path: {member_name!r}")

    resolved = (dest_dir / member_name).resolve()
    dest_root = dest_dir.resolve()
    if resolved != dest_root and dest_root not in resolved.parents:
        raise UnsafeArchiveError(f"Archive member escapes the extraction directory: {member_name!r}")
    return resolved


def _extract_zip(archive_path: Path, dest_dir: Path) -> None:
    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBER_COUNT:
            raise UnsafeArchiveError(f"Archive has too many members (>{MAX_MEMBER_COUNT})")

        total = 0
        for info in infos:
            if info.file_size > MAX_SINGLE_FILE_BYTES:
                raise UnsafeArchiveError(f"Archive member too large: {info.filename!r} ({info.file_size} bytes)")
            total += info.file_size
            if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise UnsafeArchiveError("Archive's total uncompressed size exceeds the limit")

            # The upper 16 bits of external_attr hold the Unix file mode for
            # zips written on Unix (the common case for anything a real
            # build produced) -- 0o120000 is S_IFLNK. A symlink's target
            # isn't validated by any check above (it's not even stored in
            # `filename`), so the only safe move is refusing to create one.
            unix_mode = info.external_attr >> 16
            if unix_mode and (unix_mode & 0o170000) == 0o120000:
                raise UnsafeArchiveError(f"Archive member is a symlink, which is not allowed: {info.filename!r}")

            dest = _safe_dest(dest_dir, info.filename)
            if info.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(dest, "wb") as out:
                _copy_capped(src, out, info.file_size)


def _extract_tar(archive_path: Path, dest_dir: Path, mode: str) -> None:
    with tarfile.open(archive_path, mode) as tf:
        members = tf.getmembers()
        if len(members) > MAX_MEMBER_COUNT:
            raise UnsafeArchiveError(f"Archive has too many members (>{MAX_MEMBER_COUNT})")

        total = 0
        for member in members:
            if member.issym() or member.islnk():
                raise UnsafeArchiveError(f"Archive member is a symlink/hardlink, which is not allowed: {member.name!r}")
            if not (member.isfile() or member.isdir()):
                raise UnsafeArchiveError(f"Archive member is not a regular file or directory: {member.name!r}")
            if member.size > MAX_SINGLE_FILE_BYTES:
                raise UnsafeArchiveError(f"Archive member too large: {member.name!r} ({member.size} bytes)")
            total += member.size
            if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise UnsafeArchiveError("Archive's total uncompressed size exceeds the limit")

            dest = _safe_dest(dest_dir, member.name)
            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, open(dest, "wb") as out:
                _copy_capped(src, out, member.size)


def _copy_capped(src, out, declared_size: int, chunk_size: int = 1024 * 1024) -> None:
    # Re-checks the actual byte count as it streams, in case the archive's
    # own declared size (already checked above) understated reality.
    written = 0
    while True:
        chunk = src.read(chunk_size)
        if not chunk:
            return
        written += len(chunk)
        if written > declared_size or written > MAX_SINGLE_FILE_BYTES:
            raise UnsafeArchiveError("Archive member's actual size exceeds its declared size")
        out.write(chunk)


def extract_archive(archive_path: Path, dest_dir: Path) -> Path:
    """Extracts `archive_path` into a fresh subdirectory of `dest_dir` and
    returns the path actually containing the extracted tree (a single
    top-level directory inside a real archive is unwrapped, matching how a
    user expects "my-project.zip" to extract as the project root rather
    than an extra nesting level)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    kind = _detect_kind(archive_path)

    if kind == "zip":
        _extract_zip(archive_path, dest_dir)
    elif kind == "tar.gz":
        _extract_tar(archive_path, dest_dir, "r:gz")
    else:
        _extract_tar(archive_path, dest_dir, "r:")

    entries = [p for p in dest_dir.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest_dir
