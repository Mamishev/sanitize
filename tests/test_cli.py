"""Тесты CLI (AGENTS.md, фаза 3): через in-process вызов cli.main()."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

import pytest
from sanitize import __version__
from sanitize.cli import main

from conftest import _touch


class TestDryRun:
    def test_dry_run_changes_nothing(
        self, fake_bitrix_tree: Path, tree_hash: Callable[[], str]
    ) -> None:
        before = tree_hash()
        code = main(["--path", str(fake_bitrix_tree), "--dry-run"])
        assert code == 2  # dbconn.php — secrets_report в дереве
        assert tree_hash() == before

    def test_dry_run_generic_exit_ok(self, fake_bitrix_tree: Path) -> None:
        code = main(["--path", str(fake_bitrix_tree), "--dry-run", "--preset", "generic"])
        assert code == 0  # нет Битрикс-secrets путей

    def test_dry_run_json_parses(
        self, fake_bitrix_tree: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(["--path", str(fake_bitrix_tree), "--dry-run", "--json", "--preset", "generic"])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["root"] == str(fake_bitrix_tree)
        assert payload["summary"]["total_files"] > 0
        assert "entries" in payload and "actions" in payload

    def test_report_file_written(self, fake_bitrix_tree: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        code = main(["--path", str(fake_bitrix_tree), "--dry-run", "--report", str(out)])
        assert code == 2
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["summary"]["total_files"] > 0


class _FakeTtyStdin:
    """Заглушка stdin с isatty()=True для проверки интерактивного подтверждения."""

    def isatty(self) -> bool:
        return True


class TestActions:
    def test_yes_zero_zeroes_files(self, fake_bitrix_tree: Path) -> None:
        target = fake_bitrix_tree / "letter.eml"
        assert target.read_bytes() != b""
        code = main(["--path", str(fake_bitrix_tree), "--zero", "--yes", "--quiet"])
        assert code == 2  # успешно, но найдены secrets_report
        assert target.read_bytes() == b""
        assert (fake_bitrix_tree / "report.pdf").read_bytes() == b""

    def test_delete_requires_delete_word(
        self, fake_bitrix_tree: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("sys.stdin", _FakeTtyStdin())
        monkeypatch.setattr("builtins.input", lambda *a: "no")
        target = fake_bitrix_tree / "letter.eml"
        code = main(["--path", str(fake_bitrix_tree), "--delete"])
        assert code == 3
        assert target.exists()

    def test_delete_with_delete_word(
        self, fake_bitrix_tree: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("sys.stdin", _FakeTtyStdin())
        inputs = iter(["DELETE"])
        monkeypatch.setattr("builtins.input", lambda *a: next(inputs))
        code = main(["--path", str(fake_bitrix_tree), "--delete"])
        assert code == 2
        assert not (fake_bitrix_tree / "letter.eml").exists()
        assert (fake_bitrix_tree / "upload").is_dir()  # каталоги целы

    def test_no_tty_without_yes_refused(self, fake_bitrix_tree: Path) -> None:
        # stdin pytest не TTY
        code = main(["--path", str(fake_bitrix_tree)])
        assert code == 3

    def test_zero_idempotent_second_run(self, fake_bitrix_tree: Path) -> None:
        main(["--path", str(fake_bitrix_tree), "--zero", "--yes", "--quiet"])
        code = main(["--path", str(fake_bitrix_tree), "--zero", "--yes", "--quiet"])
        assert code == 2  # secrets остаются; ошибок нет


class TestSecretsExitCode:
    def test_env_detected_exit_2(self, fake_bitrix_tree: Path) -> None:
        code = main(
            [
                "--path",
                str(fake_bitrix_tree),
                "--dry-run",
                "--preset",
                "generic",
                "--include-hidden",
            ]
        )
        assert code == 2  # .env, .htpasswd и т.п.


class TestRefusals:
    def test_unsafe_path_rejected(self) -> None:
        assert main(["--path", "/"]) == 3

    def test_nonexistent_path_rejected(self, tmp_path: Path) -> None:
        assert main(["--path", str(tmp_path / "nope")]) == 3

    def test_unknown_category_rejected(self, fake_bitrix_tree: Path) -> None:
        assert main(["--path", str(fake_bitrix_tree), "--dry-run", "--category", "nope"]) == 3

    def test_quarantine_not_implemented(self, fake_bitrix_tree: Path) -> None:
        assert main(["--path", str(fake_bitrix_tree), "--quarantine", "/tmp/q"]) == 3

    def test_bad_size_rejected(self, fake_bitrix_tree: Path) -> None:
        assert main(["--path", str(fake_bitrix_tree), "--dry-run", "--min-size", "abc"]) == 3

    def test_bad_duration_rejected(self, fake_bitrix_tree: Path) -> None:
        assert main(["--path", str(fake_bitrix_tree), "--dry-run", "--older-than", "xx"]) == 3


class TestParsing:
    def test_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--version"])
        assert excinfo.value.code == 0
        assert __version__ in capsys.readouterr().out

    def test_size_and_duration_filters(
        self, fake_bitrix_tree: Path, tree_hash: Callable[[], str]
    ) -> None:
        before = tree_hash()
        code = main(
            [
                "--path",
                str(fake_bitrix_tree),
                "--dry-run",
                "--min-size",
                "1K",
                "--older-than",
                "1d",
                "--ext",
                ".foo,.bar",
                "--exclude",
                "upload/**",
            ]
        )
        assert code in (0, 2)
        assert tree_hash() == before


def test_python_m_entrypoint() -> None:
    """Санити: модуль __main__ импортируется и делегирует в cli.main."""
    import importlib

    module = importlib.import_module("sanitize.__main__")
    assert hasattr(module, "main")


def test_include_hidden_finds_env(
    fake_bitrix_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _touch(fake_bitrix_tree / ".env", size=5)
    code = main(
        [
            "--path",
            str(fake_bitrix_tree),
            "--dry-run",
            "--json",
            "--preset",
            "generic",
            "--include-hidden",
            "--quiet",
        ]
    )
    assert code == 2
    payload = json.loads(capsys.readouterr().out)
    paths = {e["path_rel"] for e in payload["entries"]}  # type: ignore[index]
    assert ".env" in paths
    assert os.path.exists(fake_bitrix_tree / ".env")
