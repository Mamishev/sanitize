"""Тесты сканера (AGENTS.md, фаза 1)."""

from __future__ import annotations

import os
import threading
import time
from datetime import timedelta
from pathlib import Path
from typing import ClassVar

import pytest
from sanitize.core.models import ScanOptions, ScanResult
from sanitize.core.scanner import scan


def _scan(root: Path, **kwargs: object) -> ScanResult:
    options = ScanOptions(root=root, **kwargs)  # type: ignore[arg-type]
    return scan(options)


def rel_map(result: ScanResult) -> dict[str, str]:
    """Относительный путь -> id категории."""
    return {
        entry.path.relative_to(result.root).as_posix(): entry.category_id
        for entry in result.entries
    }


def skipped_rel(result: ScanResult) -> dict[str, str]:
    """Относительный путь -> причина пропуска."""
    return {
        entry.path.relative_to(result.root).as_posix(): entry.reason for entry in result.skipped
    }


class TestCategoryDetection:
    """Каждая категория находит свои файлы."""

    EXPECTED: ClassVar[dict[str, str]] = {
        "report.pdf": "docs",
        "report_upper.PDF": "docs",
        "upload/iblock/4f3/doc.pdf": "docs",
        "upload/form/scan.pdf": "docs",
        "upload/webform/notes.txt": "docs",  # .txt только под upload/
        "data.xlsx": "sheets",
        "upload/iblock/table.xls": "sheets",
        "upload/webform/results.csv": "sheets",
        "deck.pptx": "slides",
        "archive.tar.gz": "archives",
        "archive.zip": "archives",
        "key.pem": "keys",
        "id_rsa": "keys",
        "backup.sql": "backups",
        "bitrix/backup/db_dump.sql": "backups",
        "bitrix/backup/20260105_full.tar.gz": "backups",
        "letter.eml": "mail",
        "contacts.vcf": "mail",
        "config.log": "logs",
        "bitrix/tmp/session.tmp": "logs",
        "upload/tmp/debug.log": "logs",
        "bitrix/cache/html.cache": "logs",
        "bitrix/html_pages/index.html": "logs",
        "bitrix/php_interface/dbconn.php": "secrets_report",
    }

    def test_every_expected_file_found_with_category(self, fake_bitrix_tree: Path) -> None:
        result = _scan(fake_bitrix_tree, include_hidden=True)
        found = rel_map(result)
        missing = {
            rel: expected for rel, expected in self.EXPECTED.items() if found.get(rel) != expected
        }
        assert not missing, f"Не найдены или неверная категория: {missing}"

    def test_media_disabled_by_default(self, fake_bitrix_tree: Path) -> None:
        result = _scan(fake_bitrix_tree)
        assert "song.mp3" not in rel_map(result)

    def test_media_enabled_on_request(self, fake_bitrix_tree: Path) -> None:
        result = _scan(fake_bitrix_tree, categories={"media"})
        found = rel_map(result)
        assert found.get("song.mp3") == "media"
        assert len(found) == 1  # только выбранная категория

    def test_secrets_paths_found_only_with_hidden(self, fake_bitrix_tree: Path) -> None:
        without = rel_map(_scan(fake_bitrix_tree))
        assert "bitrix/.settings.php" not in without
        assert ".env" not in without
        with_hidden = rel_map(_scan(fake_bitrix_tree, include_hidden=True))
        assert with_hidden.get("bitrix/.settings.php") == "secrets_report"
        assert with_hidden.get(".env") == "secrets_report"
        assert with_hidden.get(".env.local") == "secrets_report"
        assert with_hidden.get(".htpasswd") == "secrets_report"


class TestExclusions:
    """Исключённые каталоги не обходятся, лишние расширения игнорируются."""

    def test_resize_cache_and_modules_not_scanned(self, fake_bitrix_tree: Path) -> None:
        found = rel_map(_scan(fake_bitrix_tree, include_hidden=True))
        assert "upload/resize_cache/resize.pdf" not in found
        assert "bitrix/modules/main/include.php" not in found

    def test_txt_outside_upload_ignored(self, fake_bitrix_tree: Path) -> None:
        found = rel_map(_scan(fake_bitrix_tree))
        assert "notes.txt" not in found
        assert "local/readme.txt" not in found

    def test_double_ext_tar_gz_is_archives_once(self, fake_bitrix_tree: Path) -> None:
        result = _scan(fake_bitrix_tree)
        found = rel_map(result)
        assert found.get("archive.tar.gz") == "archives"
        assert sum(1 for e in result.entries if e.path.name == "archive.tar.gz") == 1

    def test_image_not_classified(self, fake_bitrix_tree: Path) -> None:
        assert "upload/iblock/4f3/photo.jpg" not in rel_map(_scan(fake_bitrix_tree))

    def test_exclude_globs_user_pattern(self, fake_bitrix_tree: Path) -> None:
        found = rel_map(_scan(fake_bitrix_tree, exclude_globs=["upload/iblock/**"]))
        assert "upload/iblock/table.xls" not in found
        assert "upload/iblock/4f3/doc.pdf" not in found
        assert "upload/webform/results.csv" in found


class TestSymlinks:
    """Симлинки не обходятся и не попадают в результаты."""

    def test_symlink_outside_not_followed(self, fake_bitrix_tree: Path, outside_dir: Path) -> None:
        result = _scan(fake_bitrix_tree)
        found = rel_map(result)
        assert "link_outside_dir/old_dump.sql" not in found
        assert not any(e.path == outside_dir / "old_dump.sql" for e in result.entries)
        skipped = skipped_rel(result)
        assert skipped.get("link_outside_file") == "symlink"

    def test_follow_symlinks_traverses_dir_link(
        self, fake_bitrix_tree: Path, outside_dir: Path
    ) -> None:
        result = _scan(fake_bitrix_tree, follow_symlinks=True)
        found = rel_map(result)
        # Цель симлинка классифицируется через путь симлинка внутри корня
        assert found.get("link_outside_dir/old_dump.sql") == "backups"
        assert (outside_dir / "old_dump.sql").is_file()  # сама цель не тронута


class TestPermissionAndLimit:
    def test_permission_error_collected(self, fake_bitrix_tree: Path) -> None:
        if os.geteuid() == 0:
            pytest.skip("под root права доступа не ограничивают обход")
        result = _scan(fake_bitrix_tree)
        assert "noaccess" in {Path(s.path).name for s in result.skipped}
        assert all("hidden.pdf" not in str(e.path) for e in result.entries)

    def test_cancel_event_stops_scan(self, fake_bitrix_tree: Path) -> None:
        event = threading.Event()
        event.set()
        result = scan(ScanOptions(root=fake_bitrix_tree), cancel_event=event)
        assert result.cancelled
        assert result.entries == []

    def test_min_size_filter(self, fake_bitrix_tree: Path) -> None:
        found = rel_map(_scan(fake_bitrix_tree, min_size=1000))
        assert "report.pdf" not in found
        assert "bitrix/backup/20260105_full.tar.gz" in found

    def test_older_than_filter(self, fake_bitrix_tree: Path) -> None:
        old = fake_bitrix_tree / "old_report.pdf"
        old.write_bytes(b"old")
        stamp = time.time() - 400 * 86400
        os.utime(old, (stamp, stamp))
        found = rel_map(_scan(fake_bitrix_tree, older_than=timedelta(days=365)))
        assert "old_report.pdf" in found
        assert "report.pdf" not in found  # свежий файл отфильтрован

    def test_one_filesystem_option_default(self, fake_bitrix_tree: Path) -> None:
        result = _scan(fake_bitrix_tree, one_filesystem=True)
        assert result.root == fake_bitrix_tree
        assert len(result.entries) > 10

    def test_extra_extensions(self, fake_bitrix_tree: Path) -> None:
        target = fake_bitrix_tree / "custom_export.foo"
        target.write_bytes(b"data")
        found = rel_map(_scan(fake_bitrix_tree, extra_extensions={".foo"}))
        assert found.get("custom_export.foo") == "extra"

    def test_progress_callback_called(self, fake_bitrix_tree: Path) -> None:
        seen: list[tuple[int, Path]] = []

        def on_progress(done: int, total: int | None, current: Path) -> None:
            seen.append((done, current))

        result = scan(ScanOptions(root=fake_bitrix_tree), on_progress=on_progress)
        assert result.entries
        assert seen, "колбэк прогресса не вызван"
        assert all(done > 0 for done, _ in seen)

    def test_risk_dirs_marked(self, fake_bitrix_tree: Path) -> None:
        result = _scan(fake_bitrix_tree)
        targets = {
            e.path.relative_to(result.root).as_posix(): e.risk_dirs
            for e in result.entries
            if e.risk_dirs
        }
        assert targets.get("bitrix/backup/db_dump.sql") == ("bitrix/backup",)
        assert targets.get("upload/webform/results.csv") == ("upload/webform",)
        assert targets.get("upload/iblock/table.xls") == ("upload/iblock",)
        assert not any(e.risk_dirs for e in result.entries if e.path.name == "report.pdf")
        assert targets  # sanity: есть помеченные рискованные файлы

    def test_user_documents_risky(self, fake_bitrix_tree: Path) -> None:
        """upload/user_documents — хранилище ПДн, найдено на реальном проекте."""
        target = fake_bitrix_tree / "upload" / "user_documents" / "passport_scan.pdf"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"%PDF-1.4 scan")
        result = _scan(fake_bitrix_tree)
        entry = next(e for e in result.entries if e.path.name == "passport_scan.pdf")
        assert entry.risk_dirs == ("upload/user_documents",)


class TestMagic:
    def test_no_ext_pdf_detected_by_magic(self, fake_bitrix_tree: Path) -> None:
        from sanitize.core import magic as magic_module

        if not magic_module.is_available():
            pytest.skip("python-magic/libmagic недоступны")
        target = fake_bitrix_tree / "invoice_no_ext"
        target.write_bytes(b"%PDF-1.4\n% test document bytes")
        result = _scan(fake_bitrix_tree, use_magic=True)
        found = {e.path.name: e for e in result.entries}
        entry = found.get("invoice_no_ext")
        assert entry is not None
        assert entry.category_id == "docs"
        assert entry.detected_by == "magic"

    def test_no_magic_flag_ignores_signature(self, fake_bitrix_tree: Path) -> None:
        target = fake_bitrix_tree / "invoice_no_ext"
        target.write_bytes(b"%PDF-1.4\n% test document bytes")
        result = _scan(fake_bitrix_tree)
        assert "invoice_no_ext" not in {e.path.name for e in result.entries}


class TestDeepScan:
    def test_content_hits_on_csv(self, fake_bitrix_tree: Path) -> None:
        target = fake_bitrix_tree / "upload" / "webform" / "results.csv"
        target.write_text(
            "email,phone\none@example.com,+7 912 345-67-89\ntwo@example.com,\n",
            encoding="utf-8",
        )
        result = _scan(fake_bitrix_tree, deep_scan=True)
        entry = next(e for e in result.entries if e.path.name == "results.csv")
        assert entry.content_hits == {"email": 2, "phone": 1}

    def test_deep_scan_off_no_hits(self, fake_bitrix_tree: Path) -> None:
        target = fake_bitrix_tree / "upload" / "webform" / "results.csv"
        target.write_text("email\none@example.com\n", encoding="utf-8")
        result = _scan(fake_bitrix_tree)
        entry = next(e for e in result.entries if e.path.name == "results.csv")
        assert entry.content_hits == {}

    def test_deep_scan_reported_in_result(self, fake_bitrix_tree: Path) -> None:
        target = fake_bitrix_tree / "config.log"
        target.write_text("user mail: user@example.com", encoding="utf-8")
        result = _scan(fake_bitrix_tree, deep_scan=True)
        entry = next(e for e in result.entries if e.path.name == "config.log")
        assert entry.content_hits == {"email": 1}


class TestSanitizeIgnore:
    def test_ignore_file_excludes_patterns(self, fake_bitrix_tree: Path) -> None:
        (fake_bitrix_tree / ".sanitizeignore").write_text(
            "# комментарий\nupload/iblock/\n*.log\n/notes_local.md\n",
            encoding="utf-8",
        )
        found = rel_map(_scan(fake_bitrix_tree))
        assert "upload/iblock/table.xls" not in found
        assert "upload/iblock/4f3/doc.pdf" not in found
        assert "config.log" not in found
        assert "upload/tmp/debug.log" not in found
        assert "report.pdf" in found  # не затронут

    def test_anchored_pattern(self, fake_bitrix_tree: Path) -> None:
        (fake_bitrix_tree / ".sanitizeignore").write_text("/report.pdf\n", encoding="utf-8")
        found = rel_map(_scan(fake_bitrix_tree))
        assert "report.pdf" not in found
        assert "upload/form/scan.pdf" in found  # другой pdf не тронут

    def test_double_star(self, fake_bitrix_tree: Path) -> None:
        (fake_bitrix_tree / ".sanitizeignore").write_text("upload/**/*.csv\n", encoding="utf-8")
        found = rel_map(_scan(fake_bitrix_tree))
        assert "upload/webform/results.csv" not in found
        assert "upload/webform/notes.txt" in found


class TestThreads:
    def test_parallel_scan_same_findings(self, fake_bitrix_tree: Path) -> None:
        serial = rel_map(_scan(fake_bitrix_tree, threads=1))
        parallel = rel_map(_scan(fake_bitrix_tree, threads=4))
        assert serial == parallel

    def test_parallel_respects_exclusions(self, fake_bitrix_tree: Path) -> None:
        found = rel_map(_scan(fake_bitrix_tree, threads=4))
        assert "upload/resize_cache/resize.pdf" not in found
        assert "bitrix/modules/main/include.php" not in found

    def test_parallel_cancel(self, fake_bitrix_tree: Path) -> None:
        event = threading.Event()
        event.set()
        result = scan(ScanOptions(root=fake_bitrix_tree, threads=4), cancel_event=event)
        assert result.cancelled
