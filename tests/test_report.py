"""Тесты отчётов JSON/Markdown (AGENTS.md, фаза 2)."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from sanitize.core.actions import apply
from sanitize.core.models import Action, ScanOptions
from sanitize.core.presets import load_preset
from sanitize.core.report import build_report, human_size, write_report
from sanitize.core.scanner import scan


def _report_for(fake_bitrix_tree: Path, **kwargs: object) -> dict[str, object]:
    options = ScanOptions(root=fake_bitrix_tree, include_hidden=True, **kwargs)  # type: ignore[arg-type]
    result = scan(options)
    now = datetime.now(UTC)
    return build_report(
        result=result,
        options=options,
        preset=load_preset(options.preset),
        started_at=now,
        finished_at=now,
    )


class TestBuildReport:
    def test_metadata(self, fake_bitrix_tree: Path) -> None:
        report = _report_for(fake_bitrix_tree)
        assert report["root"] == str(fake_bitrix_tree)
        assert report["host"]
        assert report["sanitize_version"]
        assert report["started_at"] and report["finished_at"]
        assert report["preset"]["id"] == "bitrix"

    def test_summary_counts(self, fake_bitrix_tree: Path) -> None:
        report = _report_for(fake_bitrix_tree)
        summary = report["summary"]
        total = sum(int(bucket["count"]) for bucket in summary["by_category"].values())  # type: ignore[index]
        assert summary["total_files"] == len(report["entries"])  # type: ignore[index]
        assert summary["total_files"] == total
        assert summary["total_size"] == sum(
            e.size
            for e in scan(  # type: ignore[union-attr]
                ScanOptions(root=fake_bitrix_tree, include_hidden=True)
            ).entries
        )

    def test_entries_fields(self, fake_bitrix_tree: Path) -> None:
        report = _report_for(fake_bitrix_tree)
        entry = report["entries"][0]  # type: ignore[index]
        for key in (
            "path",
            "path_rel",
            "size",
            "mtime",
            "uid",
            "gid",
            "mode",
            "category",
            "risk_dirs",
            "detected_by",
        ):
            assert key in entry
        paths = {e["path_rel"] for e in report["entries"]}  # type: ignore[index]
        assert "upload/webform/results.csv" in paths

    def test_skipped_section(self, fake_bitrix_tree: Path) -> None:
        report = _report_for(fake_bitrix_tree)
        assert "errors" in report
        reasons = {e["reason"] for e in report["errors"]}  # type: ignore[index]
        assert "permission" in reasons or "symlink" in reasons


class TestActionsInReport:
    def test_actions_recorded_with_sha256_and_attrs(self, fake_bitrix_tree: Path) -> None:
        options = ScanOptions(root=fake_bitrix_tree)
        result = scan(options)
        preset = load_preset("bitrix")
        actions = apply(result.entries, Action.ZERO, preset=preset)
        now = datetime.now(UTC)
        report = build_report(
            result=result,
            options=options,
            preset=preset,
            started_at=now,
            finished_at=now,
            actions=actions,
        )
        summary = report["summary"]
        assert summary["actions_total"] == len(actions)  # type: ignore[attr-defined]
        assert summary["actions_ok"] == sum(1 for a in actions if a.ok)  # type: ignore[attr-defined]
        action_entry = report["actions"][0]  # type: ignore[index]
        for key in ("path", "action", "ok", "sha256", "uid", "mode"):
            assert key in action_entry


class TestWriteReport:
    def test_json_roundtrip(self, fake_bitrix_tree: Path, tmp_path: Path) -> None:
        report = _report_for(fake_bitrix_tree)
        out = tmp_path / "report.json"
        write_report(out, report)
        loaded = json.loads(out.read_text(encoding="utf-8"))
        assert loaded["root"] == report["root"]

    def test_markdown_by_extension(self, fake_bitrix_tree: Path, tmp_path: Path) -> None:
        report = _report_for(fake_bitrix_tree)
        out = tmp_path / "report.md"
        write_report(out, report)
        text = out.read_text(encoding="utf-8")
        assert text.startswith("# Отчёт sanitize")
        assert "Сводка по категориям" in text
        assert "upload/webform/results.csv" in text


def test_human_size() -> None:
    assert human_size(0) == "0 Б"
    assert human_size(512) == "512 Б"
    assert human_size(2048) == "2.0 КиБ"
    assert "МиБ" in human_size(5 * 1024 * 1024)
    assert "ГиБ" in human_size(3.4 * 1024**3)


def test_report_options_reflected(fake_bitrix_tree: Path) -> None:
    report = _report_for(fake_bitrix_tree, min_size=1024, preset="generic")
    options = report["options"]
    assert options["min_size"] == 1024  # type: ignore[index]
    assert options["preset"] == "generic"  # type: ignore[index]
    assert os.path.isdir(fake_bitrix_tree)
