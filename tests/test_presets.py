"""Тесты загрузки и валидации профилей (AGENTS.md, фаза 1)."""

from __future__ import annotations

from pathlib import Path

import pytest
from sanitize.core.presets import PresetError, available_presets, load_preset


class TestBuiltinPresets:
    def test_bitrix_loads(self) -> None:
        preset = load_preset("bitrix")
        assert preset.id == "bitrix"
        assert len(preset.categories) == 10

    def test_generic_loads(self) -> None:
        preset = load_preset("generic")
        assert preset.id == "generic"
        assert len(preset.categories) == 10

    def test_available_presets(self) -> None:
        assert "bitrix" in available_presets()
        assert "generic" in available_presets()

    def test_category_ids_and_order(self) -> None:
        preset = load_preset("bitrix")
        assert [c.id for c in preset.categories] == [
            "docs",
            "sheets",
            "slides",
            "archives",
            "keys",
            "backups",
            "mail",
            "media",
            "logs",
            "secrets_report",
        ]

    def test_default_enabled_flags(self) -> None:
        preset = load_preset("bitrix")
        flags = {c.id: c.default_enabled for c in preset.categories}
        assert flags["media"] is False
        assert all(flags[cid] for cid in flags if cid != "media")

    def test_risk_levels(self) -> None:
        preset = load_preset("bitrix")
        risks = {c.id: c.risk for c in preset.categories}
        assert risks["media"] == "low"
        assert risks["docs"] == "medium"
        assert risks["logs"] == "medium"
        high = ("sheets", "archives", "keys", "backups", "mail", "secrets_report")
        assert all(risks[cid] == "high" for cid in high)

    def test_secrets_report_only(self) -> None:
        preset = load_preset("bitrix")
        secrets = preset.category("secrets_report")
        assert secrets.report_only is True

    def test_bitrix_dirs(self) -> None:
        preset = load_preset("bitrix")
        assert "bitrix/modules" in preset.excluded_dirs
        assert "upload/resize_cache" in preset.excluded_dirs
        assert "vendor" in preset.excluded_dirs
        assert ".git" in preset.excluded_dirs
        assert "bitrix/backup" in preset.risky_dirs
        assert "upload/webform" in preset.risky_dirs
        assert preset.markers == ("bitrix", "upload")

    def test_bitrix_category_details(self) -> None:
        preset = load_preset("bitrix")
        docs = preset.category("docs")
        assert ".pdf" in docs.extensions and ".txt" in docs.extensions
        assert docs.ext_only_under == {".txt": ("upload",), ".md": ("upload",)}
        assert preset.category("sheets").ext_only_under[".xml"] == ("upload",)
        assert ".csv" not in preset.category("sheets").ext_only_under  # csv без ограничений
        assert "id_rsa" in preset.category("keys").names
        assert ".key" in preset.category("keys").extensions
        assert "bitrix/backup" in preset.category("backups").dirs
        assert "bitrix/php_interface/dbconn.php" in preset.category("secrets_report").paths
        logs = preset.category("logs")
        assert "*.log.*" in logs.name_patterns
        assert ".~lock*" in logs.name_patterns
        assert "upload/tmp" in logs.dirs

    def test_generic_has_no_bitrix_specifics(self) -> None:
        preset = load_preset("generic")
        for cat in preset.categories:
            assert cat.only_under == ()
            assert cat.ext_only_under == {}
            assert cat.dirs == ()
            assert cat.paths == ()
        assert preset.risky_dirs == ()
        assert preset.markers == ()
        assert not any(d.startswith("bitrix") for d in preset.excluded_dirs)

    def test_key_extension_assigned_to_keys_not_slides(self) -> None:
        """Расширение .key отнесено к ключам (безопасность важнее Keynote)."""
        preset = load_preset("bitrix")
        assert ".key" in preset.category("keys").extensions
        assert ".key" not in preset.category("slides").extensions


class TestValidation:
    def _write_and_load(self, tmp_path: Path, content: str) -> None:
        presets = tmp_path / "presets"
        presets.mkdir()
        (presets / "broken.toml").write_text(content, encoding="utf-8")
        load_preset("broken", presets_dir=presets)

    def test_missing_preset(self, tmp_path: Path) -> None:
        with pytest.raises(PresetError, match="не найден"):
            load_preset("no_such", presets_dir=tmp_path)

    def test_duplicate_category(self, tmp_path: Path) -> None:
        content = """
[preset]
id = "broken"

[categories.docs]
title = "D"
extensions = [".pdf"]

[categories.docs]
title = "D2"
extensions = [".doc"]
"""
        with pytest.raises(PresetError, match=r"TOML|дубликат"):
            self._write_and_load(tmp_path, content)

    def test_extension_without_dot(self, tmp_path: Path) -> None:
        content = """
[preset]
id = "broken"

[categories.docs]
title = "D"
extensions = ["pdf"]
"""
        with pytest.raises(PresetError, match="точки"):
            self._write_and_load(tmp_path, content)

    def test_absolute_excluded_dir(self, tmp_path: Path) -> None:
        content = """
[preset]
id = "broken"

[dirs]
excluded = ["/etc"]

[categories.docs]
title = "D"
extensions = [".pdf"]
"""
        with pytest.raises(PresetError, match="относительным"):
            self._write_and_load(tmp_path, content)

    def test_parent_ref_in_dir(self, tmp_path: Path) -> None:
        content = """
[preset]
id = "broken"

[dirs]
excluded = ["../evil"]

[categories.docs]
title = "D"
extensions = [".pdf"]
"""
        with pytest.raises(PresetError, match="недопустимые части"):
            self._write_and_load(tmp_path, content)

    def test_ext_only_under_unknown_ext(self, tmp_path: Path) -> None:
        content = """
[preset]
id = "broken"

[categories.docs]
title = "D"
extensions = [".pdf"]
ext_only_under = { ".zzz" = ["upload"] }
"""
        with pytest.raises(PresetError, match="ext_only_under"):
            self._write_and_load(tmp_path, content)

    def test_category_without_criteria(self, tmp_path: Path) -> None:
        content = """
[preset]
id = "broken"

[categories.empty_cat]
title = "Пустая"
"""
        with pytest.raises(PresetError, match="критерия"):
            self._write_and_load(tmp_path, content)

    def test_unknown_risk(self, tmp_path: Path) -> None:
        content = """
[preset]
id = "broken"

[categories.docs]
title = "D"
extensions = [".pdf"]
risk = "extreme"
"""
        with pytest.raises(PresetError, match="risk"):
            self._write_and_load(tmp_path, content)

    def test_broken_toml(self, tmp_path: Path) -> None:
        with pytest.raises(PresetError, match="TOML"):
            self._write_and_load(tmp_path, "[preset\nid = ")
