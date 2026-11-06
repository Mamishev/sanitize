"""Сканер: обход ФС, классификация, фильтры, отмена, прогресс (AGENTS.md, раздел 9).

Ключевые решения:
- обход os.scandir, итеративно-рекурсивный; симлинк-каталоги не посещаем
  при follow_symlinks=False, симлинк-файлы фиксируются в skipped;
- one_filesystem — сравнение st_dev с корнем;
- классификация в два прохода: (1) точные пути/имена/шаблоны/каталоги категории,
  (2) расширения — сначала двойные (.tar.gz), затем одинарные; всё в нижнем регистре;
- сопоставление префиксов каталогов — по непрерывным частям пути
  (поддержка Битрикс в подкаталоге и вложенных vendor/node_modules);
- прогресс через колбэк, троттлинг ~20 событий/сек (в сканере, не в GUI);
- PermissionError и прочие OSError собираются в ScanResult.skipped;
- отмена — threading.Event, результат помечается cancelled=True.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sanitize.core import content, magic
from sanitize.core.models import (
    Category,
    FileEntry,
    ScanOptions,
    ScanResult,
    SkippedEntry,
)
from sanitize.core.presets import Preset, load_preset

logger = logging.getLogger(__name__)

#: Минимальный интервал между событиями прогресса (~20 событий/сек).
PROGRESS_MIN_INTERVAL = 0.05

#: Идентификатор синтетической категории для extra_extensions.
EXTRA_CATEGORY_ID = "extra"

ProgressCallback = Callable[[int, int | None, Path], None]


def path_matches_prefixes(rel: str, prefixes: Iterable[str]) -> bool:
    """True, если относительный путь лежит под одним из префиксов.

    Сопоставление по непрерывным частям пути: "bitrix/modules" матчится и в
    "www/site/bitrix/modules/main" (Битрикс в подкаталоге), а "vendor" — на
    любой глубине. Публичный хелпер для переиспользования вне сканера (GUI).
    """
    parts = rel.split("/")
    return any(_contains_seq(parts, tuple(prefix.split("/"))) for prefix in prefixes)


def count_entries(
    root: Path,
    preset: Preset,
    *,
    include_hidden: bool = False,
    cancel_event: threading.Event | None = None,
) -> int:
    """Быстрый подсчёт файлов для детерминированного прогресса (фаза 1 GUI).

    Приближение: исключённые и скрытые каталоги пропускаются, вложенность
    не фильтруется по другим правилам сканера.
    """
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        if cancel_event is not None and cancel_event.is_set():
            break
        rel_dir = os.path.relpath(dirpath, root)
        rel_posix = "" if rel_dir == "." else Path(rel_dir).as_posix()
        kept: list[str] = []
        for name in dirnames:
            if not include_hidden and name.startswith("."):
                continue
            child_rel = f"{rel_posix}/{name}" if rel_posix else name
            if path_matches_prefixes(child_rel, preset.excluded_dirs):
                continue
            kept.append(name)
        dirnames[:] = kept
        total += len(filenames)
    return total


def _parts(rel: str) -> list[str]:
    return rel.split("/")


def _contains_seq(haystack: list[str], needle: tuple[str, ...]) -> bool:
    """Проверяет, входит ли последовательность частей как непрерывный фрагмент пути.

    Позволяет находить "bitrix/modules" в "www/site/bitrix/modules/main"
    (Битрикс в подкаталоге) и "vendor" на любой глубине.
    """
    n = len(needle)
    if n == 0 or n > len(haystack):
        return False
    first = needle[0]
    for i in range(len(haystack) - n + 1):
        if haystack[i] == first and haystack[i : i + n] == list(needle):
            return True
    return False


def _glob_dir_match(rel: str, pattern: str) -> bool:
    """Сопоставление каталога с пользовательским glob.

    Поддерживаются формы:
    - "dir/**" — сам каталог и всё его содержимое;
    - обычные fnmatch-шаблоны ("logs*", "2024-*").
    """
    if pattern.endswith("/**"):
        prefix = pattern[:-3].rstrip("/")
        if not prefix:
            return True
        return rel == prefix or rel.startswith(prefix + "/")
    return fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, pattern + "/*")


def _norm_extra_ext(raw: str) -> str:
    value = raw.strip().lower()
    if not value:
        return ""
    if not value.startswith("."):
        value = "." + value
    return value


def _translate_gitignore_segment(segment: str) -> str:
    """Преобразует сегмент шаблона в regex: ** -> .+, * -> [^/]*, ? -> [^/]."""
    out: list[str] = []
    i = 0
    while i < len(segment):
        if segment.startswith("**", i):
            out.append(".+")
            i += 2
            continue
        ch = segment[i]
        if ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


class SanitizeIgnore:
    """Минимальный парсер .sanitizeignore (подмножество gitignore).

    Поддержка: комментарии (#), каталоги с завершающим "/", якорные шаблоны
    с ведущим "/" или "/", "**", "*", "?". Отрицания ("!") не поддерживаются.
    Файл ищется в корне проекта; отсутствие файла — не ошибка.
    """

    def __init__(self, regexes: list[tuple[re.Pattern[str], bool]]) -> None:
        self._regexes = regexes

    @classmethod
    def load(cls, root: Path) -> SanitizeIgnore:
        path = root / ".sanitizeignore"
        regexes: list[tuple[re.Pattern[str], bool]] = []
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return cls(regexes)
        for raw in lines:
            compiled = cls._compile(raw)
            if compiled is not None:
                regexes.append(compiled)
        return cls(regexes)

    @staticmethod
    def _compile(raw: str) -> tuple[re.Pattern[str], bool] | None:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            return None
        dir_only = line.endswith("/")
        line = line.rstrip("/")
        if not line:
            return None
        anchored = line.startswith("/") or "/" in line
        line = line.lstrip("/")
        if not line:
            return None
        body = "/".join(_translate_gitignore_segment(seg) for seg in line.split("/"))
        pattern = rf"^{body}(?:/|$)" if anchored else rf"(?:^|/){body}(?:/|$)"
        try:
            return re.compile(pattern), dir_only
        except re.error as exc:  # pragma: no cover — перевод всегда валиден
            logger.debug("Некорректный шаблон .sanitizeignore %r: %s", raw, exc)
            return None

    def matches(self, rel: str, is_dir: bool) -> bool:
        return any(
            compiled.search(rel) and (is_dir or not dir_only)
            for compiled, dir_only in self._regexes
        )


class _CompiledCategory:
    """Категория с предвычисленными частями путей и сортированными расширениями."""

    __slots__ = (
        "cat",
        "dirs_parts",
        "ext_only_under_parts",
        "only_under_parts",
        "paths_parts",
        "sorted_extensions",
    )

    def __init__(self, cat: Category) -> None:
        self.cat = cat
        self.paths_parts = [tuple(p.split("/")) for p in cat.paths]
        self.dirs_parts = [tuple(p.split("/")) for p in cat.dirs]
        self.only_under_parts = [tuple(p.split("/")) for p in cat.only_under]
        self.ext_only_under_parts = {
            ext: [tuple(p.split("/")) for p in allowed]
            for ext, allowed in cat.ext_only_under.items()
        }
        self.sorted_extensions = sorted(cat.extensions, key=len, reverse=True)

    def _allowed_by_scope(self, parts: list[str]) -> bool:
        return not self.cat.only_under or any(
            _contains_seq(parts, p) for p in self.only_under_parts
        )

    def match_path(self, parts: list[str]) -> bool:
        return any(_contains_seq(parts, p) for p in self.paths_parts)

    def match_name(self, name: str) -> bool:
        return name in self.cat.names

    def match_pattern(self, name: str) -> bool:
        return any(fnmatch.fnmatch(name, pat) for pat in self.cat.name_patterns)

    def match_dir(self, parent_parts: list[str]) -> bool:
        return any(_contains_seq(parent_parts, p) for p in self.dirs_parts)

    def match_extension(self, name: str, parts: list[str]) -> bool:
        if not self.cat.extensions or not self._allowed_by_scope(parts):
            return False
        for ext in self.sorted_extensions:
            if not name.endswith(ext):
                continue
            allowed = self.ext_only_under_parts.get(ext)
            if allowed is not None and not any(_contains_seq(parts, p) for p in allowed):
                continue
            return True
        return False


class _Scanner:
    """Одноразовый обход дерева с накоплением результата."""

    def __init__(
        self,
        options: ScanOptions,
        preset: Preset,
        compiled: list[_CompiledCategory],
        extra_extensions: frozenset[str],
        enabled_ids: frozenset[str],
        ignore: SanitizeIgnore,
        on_progress: ProgressCallback | None,
        cancel_event: threading.Event | None,
    ) -> None:
        self._options = options
        self._preset = preset
        self._compiled = compiled
        self._extra = extra_extensions
        self._enabled_ids = enabled_ids
        self._ignore = ignore
        self._on_progress = on_progress
        self._cancel_event = cancel_event
        self._exclude_globs = tuple(options.exclude_globs)
        self._lock = threading.Lock()
        self._entries: list[FileEntry] = []
        self._skipped: list[SkippedEntry] = []
        self._done = 0
        self._last_emit = 0.0
        self._cancelled = False
        self._root_dev = 0

    # --- служебные проверки ---

    def _is_cancelled(self) -> bool:
        return self._cancel_event is not None and self._cancel_event.is_set()

    def _emit_progress(self, current: str) -> None:
        if self._on_progress is None:
            return
        now = time.monotonic()
        if now - self._last_emit < PROGRESS_MIN_INTERVAL:
            return
        self._last_emit = now
        try:
            self._on_progress(self._done, None, Path(current))
        except Exception:  # колбэк внешнего мира не должен ронять обход
            logger.exception("Колбэк прогресса вызвал исключение")

    def _add_entry(self, entry: FileEntry) -> None:
        with self._lock:
            self._entries.append(entry)

    def _add_skipped(self, skipped: SkippedEntry) -> None:
        with self._lock:
            self._skipped.append(skipped)

    def _advance(self) -> None:
        with self._lock:
            self._done += 1

    def _is_excluded_dir(self, rel: str) -> bool:
        parts = _parts(rel)
        for excluded in self._preset.excluded_dirs:
            if _contains_seq(parts, tuple(excluded.split("/"))):
                return True
        return any(_glob_dir_match(rel, glob) for glob in self._exclude_globs)

    def _risk_dirs(self, parts: list[str]) -> tuple[str, ...]:
        matched = [
            risky
            for risky in self._preset.risky_dirs
            if _contains_seq(parts, tuple(risky.split("/")))
        ]
        return tuple(matched)

    def _classify(self, name: str, rel: str) -> tuple[str, str] | None:
        """Возвращает (category_id, detected_by) или None, если файл не распознан."""
        lowered = name.lower()
        parts = _parts(rel)
        parent_parts = parts[:-1]

        # Проход 1: имена, пути, шаблоны, каталоги.
        for comp in self._compiled:
            if comp.match_path(parts) or comp.match_name(lowered) or comp.match_pattern(lowered):
                return comp.cat.id, "name"
        for comp in self._compiled:
            if comp.cat.dirs and comp.match_dir(parent_parts):
                return comp.cat.id, "name"

        # Проход 2: расширения (двойные раньше одинарных за счёт сортировки по длине).
        for comp in self._compiled:
            if comp.match_extension(lowered, parts):
                return comp.cat.id, "ext"

        if self._extra and any(lowered.endswith(ext) for ext in self._extra):
            return EXTRA_CATEGORY_ID, "ext"
        return None

    # --- обход ---

    def run(self) -> ScanResult:
        root = self._options.root
        try:
            self._root_dev = os.stat(root).st_dev
        except OSError as exc:
            logger.error("Недоступен корень %s: %s", root, exc)
            self._skipped.append(SkippedEntry(root, "io"))
            return ScanResult(root=root, entries=[], skipped=self._skipped)

        if self._options.threads > 1:
            self._run_parallel()
        else:
            self._walk(root, "")
        self._emit_final()
        return ScanResult(
            root=root,
            entries=self._entries,
            skipped=self._skipped,
            cancelled=self._cancelled,
        )

    def _emit_final(self) -> None:
        if self._on_progress is None:
            return
        try:
            self._on_progress(self._done, None, self._options.root)
        except Exception:
            logger.exception("Колбэк прогресса вызвал исключение")

    def _list_dir(self, path: Path) -> list[os.DirEntry[str]] | None:
        try:
            with os.scandir(path) as it:
                return sorted(it, key=lambda e: e.name)
        except PermissionError:
            self._add_skipped(SkippedEntry(path, "permission"))
            return None
        except OSError as exc:
            logger.debug("Не удалось открыть каталог %s: %s", path, exc)
            self._add_skipped(SkippedEntry(path, "io"))
            return None

    def _run_parallel(self) -> None:
        """ThreadPoolExecutor по подкаталогам первого уровня (AGENTS.md, фаза 5)."""
        items = self._list_dir(self._options.root)
        if items is None:
            self._cancelled = self._is_cancelled()
            return
        workers = max(1, min(self._options.threads, 32))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = []

            def submit_dir(path: Path, rel: str) -> None:
                futures.append(pool.submit(self._walk, path, rel))

            for entry in items:
                if self._is_cancelled():
                    self._cancelled = True
                    break
                name = entry.name
                self._visit_entry(entry, name, name, recurse=submit_dir)
        if self._is_cancelled():
            self._cancelled = True

    def _walk(self, path: Path, rel: str) -> None:
        if self._is_cancelled():
            self._cancelled = True
            return
        items = self._list_dir(path)
        if items is None:
            return

        for entry in items:
            if self._is_cancelled():
                self._cancelled = True
                return
            name = entry.name
            child_rel = f"{rel}/{name}" if rel else name
            self._visit_entry(entry, name, child_rel, recurse=self._walk)

    def _visit_entry(
        self,
        entry: os.DirEntry[str],
        name: str,
        child_rel: str,
        *,
        recurse: Callable[[Path, str], None],
    ) -> None:
        """Обрабатывает одну запись каталога; для каталогов вызывает recurse()."""
        self._advance()
        self._emit_progress(entry.path)

        if not self._options.include_hidden and name.startswith("."):
            return
        try:
            is_link = entry.is_symlink()
            is_dir = entry.is_dir(follow_symlinks=self._options.follow_symlinks)
        except OSError:
            self._add_skipped(SkippedEntry(Path(entry.path), "io"))
            return

        if is_dir:
            if is_link and not self._options.follow_symlinks:
                return  # симлинк на каталог не посещаем
            if self._is_excluded_dir(child_rel) or self._ignore.matches(child_rel, True):
                return
            if self._options.one_filesystem and not self._same_filesystem(entry):
                self._add_skipped(SkippedEntry(Path(entry.path), "filesystem"))
                return
            recurse(Path(entry.path), child_rel)
            return

        if is_link and not self._options.follow_symlinks:
            self._add_skipped(SkippedEntry(Path(entry.path), "symlink"))
            return
        if self._ignore.matches(child_rel, False):
            return
        self._handle_file(entry, child_rel)

    def _same_filesystem(self, entry: os.DirEntry[str]) -> bool:
        try:
            return entry.stat(follow_symlinks=False).st_dev == self._root_dev
        except OSError:
            self._add_skipped(SkippedEntry(Path(entry.path), "io"))
            return False

    def _handle_file(self, entry: os.DirEntry[str], rel: str) -> None:
        try:
            st = entry.stat(follow_symlinks=not self._options.follow_symlinks)
        except OSError:
            self._add_skipped(SkippedEntry(Path(entry.path), "io"))
            return

        if self._options.min_size and st.st_size < self._options.min_size:
            return
        if self._options.older_than is not None:
            threshold = time.time() - self._options.older_than.total_seconds()
            if st.st_mtime > threshold:
                return  # файл слишком свежий

        classified = self._classify(entry.name, rel)
        content_hits: dict[str, int] = {}
        if classified is None and self._options.use_magic and st.st_size > 0:
            mime = magic.mime_for(Path(entry.path))
            magic_category = magic.category_for_mime(mime)
            if magic_category is not None and magic_category in self._enabled_ids:
                content_hits = self._deep_scan_if_needed(entry, rel)
                self._add_entry(
                    FileEntry(
                        path=Path(entry.path),
                        size=st.st_size,
                        mtime=st.st_mtime,
                        uid=st.st_uid,
                        gid=st.st_gid,
                        mode=st.st_mode,
                        category_id=magic_category,
                        risk_dirs=self._risk_dirs(_parts(rel)),
                        detected_by="magic",
                        content_hits=content_hits,
                    )
                )
            return
        if classified is None:
            return
        category_id, detected_by = classified
        content_hits = self._deep_scan_if_needed(entry, rel)

        self._add_entry(
            FileEntry(
                path=Path(entry.path),
                size=st.st_size,
                mtime=st.st_mtime,
                uid=st.st_uid,
                gid=st.st_gid,
                mode=st.st_mode,
                category_id=category_id,
                risk_dirs=self._risk_dirs(_parts(rel)),
                detected_by=detected_by,  # type: ignore[arg-type]
                content_hits=content_hits,
            )
        )

    def _deep_scan_if_needed(self, entry: os.DirEntry[str], rel: str) -> dict[str, int]:
        """Deep-scan ПДн по содержимому, если опция включена (фаза 5)."""
        if not self._options.deep_scan:
            return {}
        try:
            return content.analyze_file(Path(entry.path), self._options.content_read_limit)
        except OSError as exc:
            logger.debug("deep-scan: %s: %s", rel, exc)
            return {}


def scan(
    options: ScanOptions,
    preset: Preset | None = None,
    *,
    on_progress: ProgressCallback | None = None,
    cancel_event: threading.Event | None = None,
) -> ScanResult:
    """Рекурсивно обходит options.root и возвращает результат классификации.

    preset — предзагруженный профиль; по умолчанию берётся options.preset.
    on_progress(done, total, current) — троттлированный колбэк прогресса.
    cancel_event — установка события мягко останавливает обход.
    """
    if preset is None:
        preset = load_preset(options.preset)

    if options.categories is None:
        enabled_ids: set[str] = {cat.id for cat in preset.categories if cat.default_enabled}
    else:
        enabled_ids = set(options.categories)
    compiled = [_CompiledCategory(cat) for cat in preset.categories if cat.id in enabled_ids]

    extra = frozenset(ext for ext in (_norm_extra_ext(e) for e in options.extra_extensions) if ext)
    ignore = SanitizeIgnore.load(options.root)

    scanner = _Scanner(
        options=options,
        preset=preset,
        compiled=compiled,
        extra_extensions=extra,
        enabled_ids=frozenset(enabled_ids),
        ignore=ignore,
        on_progress=on_progress,
        cancel_event=cancel_event,
    )
    return scanner.run()
