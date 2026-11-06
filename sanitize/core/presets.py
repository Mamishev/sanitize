"""Загрузка и валидация профилей из sanitize/presets/*.toml (AGENTS.md, раздел 6).

Публичный API:
- load_preset(name, presets_dir=None) -> Preset
- available_presets(presets_dir=None) -> tuple[str, ...]
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sanitize.core.models import Category, Risk

BUILTIN_PRESETS_DIR = Path(__file__).resolve().parent.parent / "presets"

_RISKS: tuple[Risk, ...] = ("low", "medium", "high")
_DIR_PARTS_ALLOWED_BAD = {"", ".", ".."}


class PresetError(ValueError):
    """Профиль не найден или не прошёл валидацию."""


@dataclass(frozen=True)
class Preset:
    """Загруженный профиль поиска."""

    id: str
    title: str
    categories: tuple[Category, ...]
    excluded_dirs: tuple[str, ...]
    risky_dirs: tuple[str, ...]
    markers: tuple[str, ...]

    def category(self, category_id: str) -> Category:
        """Категория по id; KeyError, если отсутствует."""
        for cat in self.categories:
            if cat.id == category_id:
                return cat
        raise KeyError(category_id)


def _norm_dir(raw: str, *, context: str) -> str:
    """Нормализует относительный путь каталога: posix, без лишних частей."""
    raw_stripped = raw.strip()
    if not raw_stripped or raw_stripped.startswith(("/", "\\")) or ":" in raw_stripped:
        raise PresetError(f"{context}: путь должен быть относительным posix-путём: {raw!r}")
    value = raw_stripped.replace("\\", "/").strip("/")
    if not value:
        raise PresetError(f"{context}: путь должен быть относительным posix-путём: {raw!r}")
    parts = value.split("/")
    if any(part in _DIR_PARTS_ALLOWED_BAD for part in parts):
        raise PresetError(f"{context}: недопустимые части пути в {raw!r}")
    return value


def _norm_ext(raw: str, *, context: str) -> str:
    """Нормализует расширение: нижний регистр, ведущая точка, без разделителей пути."""
    value = raw.strip().lower()
    if not value.startswith(".") or len(value) < 2:
        raise PresetError(f"{context}: расширение должно начинаться с точки: {raw!r}")
    if "/" in value or "\\" in value or ".." in value:
        raise PresetError(f"{context}: недопустимое расширение: {raw!r}")
    if any(ch.isspace() for ch in value):
        raise PresetError(f"{context}: пробелы в расширении недопустимы: {raw!r}")
    return value


def _norm_pattern(raw: str, *, context: str) -> str:
    """Нормализует fnmatch-шаблон имени."""
    value = raw.strip().lower()
    if not value or "/" in value or "\\" in value:
        raise PresetError(f"{context}: шаблон применяется к имени файла: {raw!r}")
    return value


def _norm_name(raw: str, *, context: str) -> str:
    """Нормализует точное имя файла (basename, нижний регистр)."""
    value = raw.strip().lower()
    if not value or "/" in value or "\\" in value or value in (".", ".."):
        raise PresetError(f"{context}: ожидается имя файла без пути: {raw!r}")
    return value


def _parse_category(category_id: str, raw: dict[str, Any]) -> Category:
    """Строит Category из секции TOML с валидацией."""
    title = str(raw.get("title", category_id))
    extensions_raw: tuple[str, ...] | list[str] = raw.get("extensions", ())
    extensions = frozenset(
        _norm_ext(ext, context=f"categories.{category_id}.extensions") for ext in extensions_raw
    )
    names = frozenset(
        _norm_name(name, context=f"categories.{category_id}.names") for name in raw.get("names", ())
    )
    name_patterns = tuple(
        _norm_pattern(pat, context=f"categories.{category_id}.name_patterns")
        for pat in raw.get("name_patterns", ())
    )
    paths = tuple(
        _norm_dir(path, context=f"categories.{category_id}.paths") for path in raw.get("paths", ())
    )
    dirs_raw: tuple[str, ...] | list[str] = raw.get("dirs", ())
    dirs = tuple(_norm_dir(path, context=f"categories.{category_id}.dirs") for path in dirs_raw)
    only_under = tuple(
        _norm_dir(path, context=f"categories.{category_id}.only_under")
        for path in raw.get("only_under", ())
    )
    ext_only_under_raw = raw.get("ext_only_under", {})
    if not isinstance(ext_only_under_raw, dict):
        raise PresetError(f"categories.{category_id}.ext_only_under: ожидается таблица")
    ext_only_under: dict[str, tuple[str, ...]] = {}
    for ext, allowed in ext_only_under_raw.items():
        norm_ext = _norm_ext(ext, context=f"categories.{category_id}.ext_only_under")
        if norm_ext not in extensions:
            raise PresetError(
                f"categories.{category_id}: ext_only_under содержит {norm_ext!r}, "
                f"которого нет в extensions"
            )
        ext_only_under[norm_ext] = tuple(
            _norm_dir(path, context=f"categories.{category_id}.ext_only_under") for path in allowed
        )

    if not (extensions or names or name_patterns or paths or dirs):
        raise PresetError(f"categories.{category_id}: нет ни одного критерия поиска")

    risk_raw = raw.get("risk", "medium")
    if risk_raw not in _RISKS:
        raise PresetError(f"categories.{category_id}.risk: неизвестное значение {risk_raw!r}")
    risk: Risk = risk_raw

    return Category(
        id=category_id,
        title=title,
        extensions=extensions,
        names=names,
        name_patterns=name_patterns,
        paths=paths,
        dirs=dirs,
        only_under=only_under,
        ext_only_under=ext_only_under,
        default_enabled=bool(raw.get("default_enabled", True)),
        risk=risk,
        report_only=bool(raw.get("report_only", False)),
    )


def _parse_preset(data: dict[str, Any], source: Path) -> Preset:
    """Строит Preset из разобранного TOML с валидацией."""
    preset_raw = data.get("preset")
    if not isinstance(preset_raw, dict):
        raise PresetError(f"{source}: отсутствует секция [preset]")
    preset_id = str(preset_raw.get("id", "")).strip()
    if not preset_id:
        raise PresetError(f"{source}: [preset].id пуст")

    dirs_raw = data.get("dirs", {})
    if not isinstance(dirs_raw, dict):
        raise PresetError(f"{source}: секция [dirs] должна быть таблицей")
    excluded = tuple(
        _norm_dir(path, context="[dirs].excluded") for path in dirs_raw.get("excluded", ())
    )
    risky = tuple(_norm_dir(path, context="[dirs].risky") for path in dirs_raw.get("risky", ()))
    markers = tuple(
        _norm_dir(path, context="[preset].markers") for path in preset_raw.get("markers", ())
    )

    categories_raw = data.get("categories", {})
    if not isinstance(categories_raw, dict) or not categories_raw:
        raise PresetError(f"{source}: отсутствуют или пусты [categories.*]")
    categories: list[Category] = []
    seen: set[str] = set()
    for category_id, raw in categories_raw.items():
        if category_id in seen:
            raise PresetError(f"{source}: дубликат категории {category_id!r}")
        if not isinstance(raw, dict):
            raise PresetError(f"{source}: categories.{category_id} должна быть таблицей")
        seen.add(category_id)
        categories.append(_parse_category(category_id, raw))

    return Preset(
        id=preset_id,
        title=str(preset_raw.get("title", preset_id)),
        categories=tuple(categories),
        excluded_dirs=excluded,
        risky_dirs=risky,
        markers=markers,
    )


def load_preset(name: str, presets_dir: Path | None = None) -> Preset:
    """Загружает и валидирует профиль по имени (например, "bitrix").

    presets_dir — переопределение каталога с TOML (для тестов);
    по умолчанию — встроенные sanitize/presets/.
    """
    directory = presets_dir if presets_dir is not None else BUILTIN_PRESETS_DIR
    path = directory / f"{name}.toml"
    if not path.is_file():
        raise PresetError(f"Профиль {name!r} не найден: {path}")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise PresetError(f"{path}: ошибка разбора TOML: {exc}") from exc
    return _parse_preset(data, path)


def available_presets(presets_dir: Path | None = None) -> tuple[str, ...]:
    """Имена доступных профилей (по *.toml в каталоге профилей)."""
    directory = presets_dir if presets_dir is not None else BUILTIN_PRESETS_DIR
    return tuple(sorted(p.stem for p in directory.glob("*.toml")))
