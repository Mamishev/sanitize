"""Тесты действий zero/delete/stub (AGENTS.md, фаза 2)."""

from __future__ import annotations

import hashlib
import os
import threading
import zipfile
from pathlib import Path

import pytest
from sanitize.core.actions import apply, stub_content
from sanitize.core.models import Action, FileEntry, ScanOptions
from sanitize.core.presets import load_preset
from sanitize.core.scanner import scan

from conftest import make_file


def _entry_for(root: Path, rel: str, preset_name: str = "bitrix") -> FileEntry:
    """Сканирует дерево и возвращает entry для указанного файла."""
    result = scan(ScanOptions(root=root, preset=preset_name, include_hidden=True))
    for entry in result.entries:
        if entry.path.relative_to(root).as_posix() == rel:
            return entry
    raise AssertionError(f"файл не найден при сканировании: {rel}")


def _apply_one(root: Path, rel: str, action: Action) -> tuple[FileEntry, object]:
    entry = _entry_for(root, rel)
    preset = load_preset("bitrix")
    results = apply([entry], action, preset=preset)
    assert len(results) == 1
    return entry, results[0]


class TestZero:
    def test_zero_clears_content_and_keeps_attrs(self, tmp_path: Path) -> None:
        content = b"sensitive personal data" * 10
        path = make_file(tmp_path / "site", "docs/report.pdf", content=content)
        st_before = os.stat(path)
        os.utime(path, ns=(st_before.st_atime_ns - 1000, st_before.st_mtime_ns - 1000))
        st = os.stat(path)

        entry = FileEntry(
            path=path,
            size=st.st_size,
            mtime=st.st_mtime,
            uid=st.st_uid,
            gid=st.st_gid,
            mode=st.st_mode,
            category_id="docs",
        )
        results = apply([entry], Action.ZERO, preset=load_preset("bitrix"))

        assert results[0].ok is True
        assert results[0].note is None
        assert path.read_bytes() == b""
        st_after = os.stat(path)
        assert st_after.st_size == 0
        assert st_after.st_uid == st.st_uid
        assert st_after.st_gid == st.st_gid
        assert (st_after.st_mode & 0o777) == (st.st_mode & 0o777)
        assert st_after.st_mtime_ns == st.st_mtime_ns

    def test_zero_empty_file_skipped_empty(self, fake_bitrix_tree: Path) -> None:
        _entry, result = _apply_one(fake_bitrix_tree, "empty.pdf", Action.ZERO)
        assert result.ok is True
        assert result.note == "skipped_empty"
        assert (fake_bitrix_tree / "empty.pdf").exists()

    def test_zero_idempotent(self, tmp_path: Path) -> None:
        path = make_file(tmp_path / "site", "data.csv")
        st = os.stat(path)
        entry = FileEntry(
            path=path,
            size=st.st_size,
            mtime=st.st_mtime,
            uid=st.st_uid,
            gid=st.st_gid,
            mode=st.st_mode,
            category_id="sheets",
        )
        preset = load_preset("bitrix")
        first = apply([entry], Action.ZERO, preset=preset)[0]
        second = apply([entry], Action.ZERO, preset=preset)[0]
        assert first.ok and second.ok
        assert second.note == "skipped_empty"

    def test_zero_records_sha256(self, tmp_path: Path) -> None:
        content = b"top secret"
        path = make_file(tmp_path / "site", "letter.eml", content=content)
        st = os.stat(path)
        entry = FileEntry(
            path=path,
            size=st.st_size,
            mtime=st.st_mtime,
            uid=st.st_uid,
            gid=st.st_gid,
            mode=st.st_mode,
            category_id="mail",
        )
        result = apply([entry], Action.ZERO, preset=load_preset("bitrix"))[0]
        assert result.sha256 == hashlib.sha256(content).hexdigest()


class TestDelete:
    def test_delete_removes_file_keeps_dirs(self, tmp_path: Path) -> None:
        path = make_file(tmp_path / "site", "upload/iblock/x/report.pdf")
        st = os.stat(path)
        entry = FileEntry(
            path=path,
            size=st.st_size,
            mtime=st.st_mtime,
            uid=st.st_uid,
            gid=st.st_gid,
            mode=st.st_mode,
            category_id="docs",
        )
        result = apply([entry], Action.DELETE, preset=load_preset("bitrix"))[0]
        assert result.ok is True
        assert not path.exists()
        assert path.parent.is_dir()  # каталоги не удаляем

    def test_delete_idempotent(self, tmp_path: Path) -> None:
        path = make_file(tmp_path / "site", "old.sql")
        st = os.stat(path)
        entry = FileEntry(
            path=path,
            size=st.st_size,
            mtime=st.st_mtime,
            uid=st.st_uid,
            gid=st.st_gid,
            mode=st.st_mode,
            category_id="backups",
        )
        preset = load_preset("bitrix")
        assert apply([entry], Action.DELETE, preset=preset)[0].ok is True
        second = apply([entry], Action.DELETE, preset=preset)[0]
        assert second.ok is True
        assert second.note == "already_absent"


class TestGuards:
    def test_report_only_refused_at_core_level(self, fake_bitrix_tree: Path) -> None:
        rel = "bitrix/php_interface/dbconn.php"
        path = fake_bitrix_tree / rel
        before = path.read_bytes()
        _entry, result = _apply_one(fake_bitrix_tree, rel, Action.ZERO)
        assert result.ok is False
        assert "report_only" in (result.error or "")
        assert path.read_bytes() == before

    def test_symlink_skipped(self, fake_bitrix_tree: Path, outside_dir: Path) -> None:
        link = fake_bitrix_tree / "link_outside_file"
        target = outside_dir / "secret.txt"
        before = target.read_bytes()
        # Симлинк не классифицируется сканером — создаём entry вручную
        st = link.lstat()
        entry = FileEntry(
            path=link,
            size=st.st_size,
            mtime=st.st_mtime,
            uid=st.st_uid,
            gid=st.st_gid,
            mode=st.st_mode,
            category_id="docs",
        )
        result = apply([entry], Action.DELETE, preset=load_preset("bitrix"))[0]
        assert result.ok is True
        assert result.note == "skipped_symlink"
        assert link.is_symlink()  # линк на месте
        assert target.read_bytes() == before  # цель не тронута

    def test_no_hash(self, tmp_path: Path) -> None:
        path = make_file(tmp_path / "site", "backup.sql", content=b"x" * 100)
        st = os.stat(path)
        entry = FileEntry(
            path=path,
            size=st.st_size,
            mtime=st.st_mtime,
            uid=st.st_uid,
            gid=st.st_gid,
            mode=st.st_mode,
            category_id="backups",
        )
        result = apply([entry], Action.DELETE, preset=load_preset("bitrix"), no_hash=True)[0]
        assert result.ok is True
        assert result.sha256 is None


class TestStub:
    def test_stub_pdf(self, tmp_path: Path) -> None:
        path = make_file(tmp_path / "site", "report.pdf", content=b"%PDF-evil ...")
        st = os.stat(path)
        entry = FileEntry(
            path=path,
            size=st.st_size,
            mtime=st.st_mtime,
            uid=st.st_uid,
            gid=st.st_gid,
            mode=st.st_mode,
            category_id="docs",
        )
        result = apply([entry], Action.STUB, preset=load_preset("bitrix"))[0]
        assert result.ok is True
        data = path.read_bytes()
        assert data.startswith(b"%PDF-")
        assert b"SANITIZED" in data
        assert b"%%EOF" in data
        assert os.stat(path).st_mode == st.st_mode  # права сохранены

    def test_stub_zip_container(self, tmp_path: Path) -> None:
        for name in ("archive.zip", "report.docx", "table.xlsx", "deck.pptx"):
            path = make_file(tmp_path / "site", name, content=b"PK\x03\x04 evil")
            st = os.stat(path)
            entry = FileEntry(
                path=path,
                size=st.st_size,
                mtime=st.st_mtime,
                uid=st.st_uid,
                gid=st.st_gid,
                mode=st.st_mode,
                category_id="archives",
            )
            result = apply([entry], Action.STUB, preset=load_preset("bitrix"))[0]
            assert result.ok is True, name
            assert zipfile.is_zipfile(path), name

    def test_stub_text_newline(self, tmp_path: Path) -> None:
        path = make_file(tmp_path / "site", "notes.txt", content=b"personal")
        st = os.stat(path)
        entry = FileEntry(
            path=path,
            size=st.st_size,
            mtime=st.st_mtime,
            uid=st.st_uid,
            gid=st.st_gid,
            mode=st.st_mode,
            category_id="docs",
        )
        result = apply([entry], Action.STUB, preset=load_preset("bitrix"))[0]
        assert result.ok is True
        assert path.read_bytes() == b"\n"

    def test_stub_unknown_type_falls_back_to_zero(self, tmp_path: Path) -> None:
        path = make_file(tmp_path / "site", "dump.sql", content=b"INSERT ...")
        st = os.stat(path)
        entry = FileEntry(
            path=path,
            size=st.st_size,
            mtime=st.st_mtime,
            uid=st.st_uid,
            gid=st.st_gid,
            mode=st.st_mode,
            category_id="backups",
        )
        result = apply([entry], Action.STUB, preset=load_preset("bitrix"))[0]
        assert result.ok is True
        assert path.read_bytes() == b""

    def test_stub_content_dispatch(self) -> None:
        assert stub_content("a.pdf") is not None
        assert stub_content("a.docx") is not None
        assert stub_content("b.txt") == b"\n"
        assert stub_content("c.sql") is None


class TestCancelAndCallback:
    def test_cancel_stops_processing(self, tmp_path: Path) -> None:
        paths = [make_file(tmp_path / "site", f"f{i}.pdf") for i in range(10)]
        st = os.stat(paths[0])
        entries = [
            FileEntry(
                path=p,
                size=st.st_size,
                mtime=st.st_mtime,
                uid=st.st_uid,
                gid=st.st_gid,
                mode=st.st_mode,
                category_id="docs",
            )
            for p in paths
        ]
        event = threading.Event()
        event.set()
        results = apply(entries, Action.ZERO, preset=load_preset("bitrix"), cancel_event=event)
        assert results == []
        assert all(p.read_bytes() != b"" for p in paths)

    def test_on_result_callback(self, tmp_path: Path) -> None:
        path = make_file(tmp_path / "site", "letter.eml", content=b"mail")
        st = os.stat(path)
        entry = FileEntry(
            path=path,
            size=st.st_size,
            mtime=st.st_mtime,
            uid=st.st_uid,
            gid=st.st_gid,
            mode=st.st_mode,
            category_id="mail",
        )
        seen: list[bool] = []
        apply(
            [entry],
            Action.ZERO,
            preset=load_preset("bitrix"),
            on_result=lambda r: seen.append(r.ok),
        )
        assert seen == [True]

    def test_quarantine_not_implemented_yet(self, tmp_path: Path) -> None:
        path = make_file(tmp_path / "site", "report.pdf")
        st = os.stat(path)
        entry = FileEntry(
            path=path,
            size=st.st_size,
            mtime=st.st_mtime,
            uid=st.st_uid,
            gid=st.st_gid,
            mode=st.st_mode,
            category_id="docs",
        )
        with pytest.raises(NotImplementedError):
            apply([entry], Action.QUARANTINE, preset=load_preset("bitrix"))
