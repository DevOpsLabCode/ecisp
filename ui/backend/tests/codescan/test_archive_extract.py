"""Real attack payloads, not just theoretical assertions: each of these
malicious archives is a genuine zip-slip/tar-slip/symlink-escape payload
built the same way a real exploit would build one, and the test asserts
nothing lands outside the destination directory.
"""

import io
import tarfile
import zipfile

import pytest

from app.codescan.archive_extract import UnsafeArchiveError, extract_archive


def _zip_with(path, entries: dict[str, bytes]):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)


def _tar_with(path, entries: dict[str, bytes]):
    with tarfile.open(path, "w") as tf:
        for name, data in entries.items():
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))


def test_extracts_a_benign_zip(tmp_path):
    archive = tmp_path / "good.zip"
    _zip_with(archive, {"myproj/app.py": b"print(1)\n", "myproj/README.md": b"hi\n"})
    dest = tmp_path / "out"

    result = extract_archive(archive, dest)

    assert result == dest / "myproj"  # single top-level dir unwrapped
    assert (result / "app.py").read_bytes() == b"print(1)\n"


def test_extracts_a_benign_tar_gz(tmp_path):
    archive = tmp_path / "good.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        data = b"print(1)\n"
        ti = tarfile.TarInfo(name="myproj/app.py")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    dest = tmp_path / "out"

    result = extract_archive(archive, dest)

    assert (result / "app.py").read_bytes() == b"print(1)\n"


def test_does_not_unwrap_multiple_top_level_entries(tmp_path):
    archive = tmp_path / "multi.zip"
    _zip_with(archive, {"a.py": b"1", "b.py": b"2"})
    dest = tmp_path / "out"

    result = extract_archive(archive, dest)

    assert result == dest
    assert (dest / "a.py").exists()
    assert (dest / "b.py").exists()


def test_rejects_zip_slip(tmp_path):
    archive = tmp_path / "evil.zip"
    _zip_with(archive, {"../../../../tmp/pwned.txt": b"pwned", "normal.txt": b"fine"})
    dest = tmp_path / "out"

    with pytest.raises(UnsafeArchiveError, match="escapes"):
        extract_archive(archive, dest)
    assert not dest.exists() or not any(dest.rglob("pwned.txt"))


def test_rejects_tar_slip(tmp_path):
    archive = tmp_path / "evil.tar"
    _tar_with(archive, {"../../../../tmp/pwned.txt": b"pwned"})
    dest = tmp_path / "out"

    with pytest.raises(UnsafeArchiveError, match="escapes"):
        extract_archive(archive, dest)


def test_rejects_absolute_path_member_in_zip(tmp_path):
    archive = tmp_path / "evil.zip"
    _zip_with(archive, {"/etc/passwd": b"pwned"})
    dest = tmp_path / "out"

    with pytest.raises(UnsafeArchiveError, match="absolute"):
        extract_archive(archive, dest)


def test_rejects_symlink_member_in_tar(tmp_path):
    archive = tmp_path / "evil.tar"
    with tarfile.open(archive, "w") as tf:
        ti = tarfile.TarInfo(name="evil-link")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/tmp"
        tf.addfile(ti)
    dest = tmp_path / "out"

    with pytest.raises(UnsafeArchiveError, match="symlink"):
        extract_archive(archive, dest)


def test_rejects_hardlink_member_in_tar(tmp_path):
    archive = tmp_path / "evil.tar"
    with tarfile.open(archive, "w") as tf:
        data = b"x"
        ti = tarfile.TarInfo(name="real.txt")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
        link = tarfile.TarInfo(name="evil-hardlink")
        link.type = tarfile.LNKTYPE
        link.linkname = "real.txt"
        tf.addfile(link)
    dest = tmp_path / "out"

    with pytest.raises(UnsafeArchiveError, match="symlink/hardlink"):
        extract_archive(archive, dest)


def test_rejects_symlink_member_in_zip_via_unix_mode(tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("evil-link")
        info.external_attr = (0o120777 & 0xFFFF) << 16  # S_IFLNK
        zf.writestr(info, "/tmp")
    dest = tmp_path / "out"

    with pytest.raises(UnsafeArchiveError, match="symlink"):
        extract_archive(archive, dest)


def test_rejects_device_special_member_in_tar(tmp_path):
    archive = tmp_path / "evil.tar"
    with tarfile.open(archive, "w") as tf:
        ti = tarfile.TarInfo(name="evil-device")
        ti.type = tarfile.CHRTYPE
        tf.addfile(ti)
    dest = tmp_path / "out"

    with pytest.raises(UnsafeArchiveError, match="not a regular file"):
        extract_archive(archive, dest)


def test_rejects_too_many_members(tmp_path, monkeypatch):
    import app.codescan.archive_extract as mod

    monkeypatch.setattr(mod, "MAX_MEMBER_COUNT", 2)
    archive = tmp_path / "many.zip"
    _zip_with(archive, {"a.txt": b"1", "b.txt": b"2", "c.txt": b"3"})
    dest = tmp_path / "out"

    with pytest.raises(UnsafeArchiveError, match="too many members"):
        extract_archive(archive, dest)


def test_rejects_a_single_file_over_the_size_cap(tmp_path, monkeypatch):
    import app.codescan.archive_extract as mod

    monkeypatch.setattr(mod, "MAX_SINGLE_FILE_BYTES", 10)
    archive = tmp_path / "big.zip"
    _zip_with(archive, {"huge.bin": b"x" * 1000})
    dest = tmp_path / "out"

    with pytest.raises(UnsafeArchiveError, match="too large"):
        extract_archive(archive, dest)


def test_rejects_total_size_over_the_cap(tmp_path, monkeypatch):
    import app.codescan.archive_extract as mod

    monkeypatch.setattr(mod, "MAX_SINGLE_FILE_BYTES", 100)
    monkeypatch.setattr(mod, "MAX_TOTAL_UNCOMPRESSED_BYTES", 15)
    archive = tmp_path / "big.zip"
    _zip_with(archive, {"a.bin": b"x" * 10, "b.bin": b"x" * 10})
    dest = tmp_path / "out"

    with pytest.raises(UnsafeArchiveError, match="total uncompressed size"):
        extract_archive(archive, dest)


def test_rejects_unrecognized_format(tmp_path):
    archive = tmp_path / "not-an-archive.zip"
    archive.write_bytes(b"this is not a real archive, just text")
    dest = tmp_path / "out"

    with pytest.raises(UnsafeArchiveError, match="Unrecognized archive format"):
        extract_archive(archive, dest)


def test_detects_tar_gz_by_content_even_with_tgz_extension(tmp_path):
    archive = tmp_path / "good.tgz"
    with tarfile.open(archive, "w:gz") as tf:
        data = b"hi\n"
        ti = tarfile.TarInfo(name="f.txt")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    dest = tmp_path / "out"

    result = extract_archive(archive, dest)
    assert (result / "f.txt").read_bytes() == b"hi\n"


def test_detects_plain_tar_by_content_even_with_zip_extension(tmp_path):
    # A mismatched extension shouldn't matter -- detection is content-based.
    archive = tmp_path / "actually-a-tar.zip"
    with tarfile.open(archive, "w") as tf:
        data = b"hi\n"
        ti = tarfile.TarInfo(name="f.txt")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    dest = tmp_path / "out"

    result = extract_archive(archive, dest)
    assert (result / "f.txt").read_bytes() == b"hi\n"
