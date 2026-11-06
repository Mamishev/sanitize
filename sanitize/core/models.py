"""Модели данных ядра sanitize (AGENTS.md, раздел 5).

Расширения относительно спеки (обоснование — docs/bitrix-notes.md):
- Category.name_patterns: fnmatch-шаблоны на базовое имя (".env.*", "*.log.*", ".~lock*");
- Category.paths: точные относительные пути ("bitrix/php_interface/dbconn.php");
- Category.dirs: каталоги, всё содержимое которых относится к категории
  ("bitrix/backup", "upload/tmp");
- Category.ext_only_under: ограничение отдельных расширений каталогом
  (".txt"/".md" — только под upload/, при этом остальные расширения категории
  ищутся везде);
- ActionResult.note: пометка вида skipped_empty / skipped_symlink.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
from pathlib import Path
from typing import Literal

Risk = Literal["low", "medium", "high"]
DetectedBy = Literal["ext", "name", "magic"]


class Action(Enum):
    """Действие, применяемое к найденному файлу."""

    ZERO = "zero"
    DELETE = "delete"
    STUB = "stub"
    QUARANTINE = "quarantine"


@dataclass(frozen=True)
class Category:
    """Категория поиска: расширения, имена, пути и каталоги."""

    id: str
    title: str
    extensions: frozenset[str] = frozenset()
    names: frozenset[str] = frozenset()
    name_patterns: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    dirs: tuple[str, ...] = ()
    only_under: tuple[str, ...] = ()
    ext_only_under: dict[str, tuple[str, ...]] = field(default_factory=dict)
    default_enabled: bool = True
    risk: Risk = "medium"
    report_only: bool = False


@dataclass(frozen=True)
class FileEntry:
    """Найденный файл: метаданные, категория, контекст."""

    path: Path
    size: int
    mtime: float
    uid: int
    gid: int
    mode: int
    category_id: str
    risk_dirs: tuple[str, ...] = ()
    detected_by: DetectedBy = "ext"
    content_hits: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class SkippedEntry:
    """Запись, пропущенная при обходе (нет доступа, симлинк, другая ФС)."""

    path: Path
    reason: str


@dataclass
class ScanResult:
    """Результат сканирования."""

    root: Path
    entries: list[FileEntry] = field(default_factory=list)
    skipped: list[SkippedEntry] = field(default_factory=list)
    cancelled: bool = False

    def files_by_category(self) -> dict[str, list[FileEntry]]:
        """Группировка найденных файлов по id категории."""
        grouped: dict[str, list[FileEntry]] = {}
        for entry in self.entries:
            grouped.setdefault(entry.category_id, []).append(entry)
        return grouped

    def total_size(self) -> int:
        """Суммарный размер найденных файлов, байты."""
        return sum(entry.size for entry in self.entries)


@dataclass
class ScanOptions:
    """Опции сканирования (AGENTS.md, раздел 5)."""

    root: Path
    preset: str = "bitrix"
    categories: set[str] | None = None
    extra_extensions: set[str] | tuple[str, ...] = ()
    exclude_globs: tuple[str, ...] | list[str] = ()
    include_hidden: bool = False
    follow_symlinks: bool = False
    one_filesystem: bool = True
    min_size: int = 0
    older_than: timedelta | None = None
    use_magic: bool = False
    deep_scan: bool = False
    #: Лимит чтения файла в deep-scan, байты (content.py).
    content_read_limit: int = 20 * 1024 * 1024
    threads: int = 4


@dataclass(frozen=True)
class ActionResult:
    """Результат применения действия к одному файлу."""

    entry: FileEntry
    action: Action
    ok: bool
    error: str | None = None
    sha256: str | None = None
    note: str | None = None  # "skipped_empty", "skipped_symlink", ...
