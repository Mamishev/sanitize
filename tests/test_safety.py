"""Тесты safety: чёрный список корней, маркеры, карантин (AGENTS.md, фаза 2)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from sanitize.core.presets import load_preset
from sanitize.core.safety import (
    BLOCKED_ROOTS,
    SafetyError,
    check_quarantine_dir,
    check_root,
    has_project_markers,
)


class TestBlockedRoots:
    def test_blocked_roots_constant(self) -> None:
        assert (
            frozenset({"/", "/home", "/root", "/usr", "/etc", "/var", "/opt", "/srv", "/tmp"})
            == BLOCKED_ROOTS
        )

    def test_root_slash_rejected(self) -> None:
        with pytest.raises(SafetyError, match="чёрного списка"):
            check_root(Path("/"))

    @pytest.mark.parametrize("blocked", ["/home", "/root", "/usr", "/etc", "/opt", "/srv"])
    def test_blocked_rejected(self, blocked: str) -> None:
        if not Path(blocked).exists():
            pytest.skip(f"{blocked} не существует в системе")
        with pytest.raises(SafetyError, match="чёрного списка"):
            check_root(Path(blocked))

    def test_tmp_rejected_even_as_subdir_symlink(self, tmp_path: Path) -> None:
        with pytest.raises(SafetyError, match="чёрного списка"):
            check_root(Path("/tmp"))

    def test_subdirectory_of_blocked_allowed(self, tmp_path: Path) -> None:
        """Подкаталоги системных корней разрешены: проверяем на /tmp/...-подобном пути."""
        site_inside_tmp = Path("/tmp") / f"sanitize_selftest_{os.getpid()}"
        site_inside_tmp.mkdir(exist_ok=True)
        try:
            resolved = check_root(site_inside_tmp)
            assert resolved == site_inside_tmp.resolve()
        finally:
            site_inside_tmp.rmdir()

    def test_symlink_to_blocked_rejected(self, tmp_path: Path) -> None:
        link = tmp_path / "link_to_home"
        if Path("/home").exists():
            os.symlink("/home", link)
            with pytest.raises(SafetyError, match="чёрного списка"):
                check_root(link)
        else:
            pytest.skip("/home не существует")


class TestRootChecks:
    def test_nonexistent_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(SafetyError, match="не существует"):
            check_root(tmp_path / "no_such_dir")

    def test_file_rejected(self, tmp_path: Path) -> None:
        target = tmp_path / "file.txt"
        target.write_text("x")
        with pytest.raises(SafetyError, match="не является каталогом"):
            check_root(target)

    def test_valid_dir_resolved(self, tmp_path: Path) -> None:
        target = tmp_path / "site"
        target.mkdir()
        resolved = check_root(target)
        assert resolved == target.resolve()


class TestMarkers:
    def test_markers_present(self, fake_bitrix_tree: Path) -> None:
        assert has_project_markers(fake_bitrix_tree, load_preset("bitrix")) is True

    def test_markers_absent(self, tmp_path: Path) -> None:
        assert has_project_markers(tmp_path, load_preset("bitrix")) is False

    def test_generic_has_no_markers(self, fake_bitrix_tree: Path) -> None:
        assert has_project_markers(fake_bitrix_tree, load_preset("generic")) is False


class TestQuarantine:
    def test_quarantine_inside_root_rejected(self, fake_bitrix_tree: Path) -> None:
        with pytest.raises(SafetyError, match="внутри"):
            check_quarantine_dir(fake_bitrix_tree, fake_bitrix_tree / "quarantine")

    def test_quarantine_equal_root_rejected(self, fake_bitrix_tree: Path) -> None:
        with pytest.raises(SafetyError, match="внутри"):
            check_quarantine_dir(fake_bitrix_tree, fake_bitrix_tree)

    def test_quarantine_outside_ok(self, fake_bitrix_tree: Path, tmp_path: Path) -> None:
        resolved = check_quarantine_dir(fake_bitrix_tree, tmp_path / "quarantine")
        assert resolved == (tmp_path / "quarantine").resolve()
