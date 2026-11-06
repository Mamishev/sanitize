"""Формирование отчётов JSON/Markdown (AGENTS.md, раздел 9).

Формат JSON задаётся build_report(); write_report() выбирает представление
по расширению файла (.md -> Markdown, иначе JSON).
"""

from __future__ import annotations

import json
import socket
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from sanitize.core.models import ActionResult, FileEntry, ScanOptions, ScanResult
from sanitize.core.presets import Preset

_HUMAN_UNITS = ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ")


def human_size(size: float) -> str:
    """Человекочитаемый размер: 1234 -> "1.2 КиБ"."""
    value = float(size)
    for unit in _HUMAN_UNITS:
        if value < 1024 or unit == _HUMAN_UNITS[-1]:
            precision = 0 if unit == "Б" else 1
            return f"{value:.{precision}f} {unit}"
        value /= 1024
    return f"{value:.1f} {_HUMAN_UNITS[-1]}"  # pragma: no cover — недостижимо


def _entry_payload(entry: FileEntry, root: Path) -> dict[str, Any]:
    try:
        rel = entry.path.relative_to(root).as_posix()
    except ValueError:
        rel = entry.path.as_posix()
    return {
        "path": str(entry.path),
        "path_rel": rel,
        "size": entry.size,
        "mtime": entry.mtime,
        "uid": entry.uid,
        "gid": entry.gid,
        "mode": oct(entry.mode),
        "category": entry.category_id,
        "risk_dirs": list(entry.risk_dirs),
        "detected_by": entry.detected_by,
        "content_hits": dict(entry.content_hits),
    }


def _action_payload(result: ActionResult, root: Path) -> dict[str, Any]:
    payload = _entry_payload(result.entry, root)
    payload.update(
        {
            "action": result.action.value,
            "ok": result.ok,
            "error": result.error,
            "sha256": result.sha256,
            "note": result.note,
        }
    )
    return payload


def _options_payload(options: ScanOptions) -> dict[str, Any]:
    return {
        "preset": options.preset,
        "categories": sorted(options.categories) if options.categories else None,
        "extra_extensions": sorted(options.extra_extensions),
        "exclude_globs": list(options.exclude_globs),
        "include_hidden": options.include_hidden,
        "follow_symlinks": options.follow_symlinks,
        "one_filesystem": options.one_filesystem,
        "min_size": options.min_size,
        "older_than": (
            options.older_than.total_seconds() if options.older_than is not None else None
        ),
        "use_magic": options.use_magic,
        "deep_scan": options.deep_scan,
        "threads": options.threads,
    }


def build_report(
    *,
    result: ScanResult,
    options: ScanOptions,
    preset: Preset,
    started_at: datetime,
    finished_at: datetime,
    actions: Sequence[ActionResult] = (),
) -> dict[str, Any]:
    """Собирает машиночитаемый отчёт о сканировании и действиях."""
    by_category: dict[str, dict[str, Any]] = {}
    for entry in result.entries:
        bucket = by_category.setdefault(
            entry.category_id,
            {
                "title": preset.category(entry.category_id).title
                if _known_category(preset, entry.category_id)
                else entry.category_id,
                "count": 0,
                "size": 0,
            },
        )
        bucket["count"] += 1
        bucket["size"] += entry.size

    skipped_by_reason: dict[str, int] = {}
    for skipped in result.skipped:
        skipped_by_reason[skipped.reason] = skipped_by_reason.get(skipped.reason, 0) + 1

    titles = {cat.id: cat.title for cat in preset.categories}
    return {
        "sanitize_version": _version(),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "host": socket.gethostname(),
        "root": str(result.root),
        "preset": {"id": preset.id, "title": preset.title, "categories": titles},
        "options": _options_payload(options),
        "cancelled": result.cancelled,
        "summary": {
            "total_files": len(result.entries),
            "total_size": result.total_size(),
            "by_category": by_category,
            "skipped": len(result.skipped),
            "skipped_by_reason": skipped_by_reason,
            "actions_total": len(actions),
            "actions_ok": sum(1 for a in actions if a.ok),
            "actions_failed": sum(1 for a in actions if not a.ok),
        },
        "entries": [_entry_payload(entry, result.root) for entry in result.entries],
        "actions": [_action_payload(a, result.root) for a in actions],
        "errors": [{"path": str(s.path), "reason": s.reason} for s in result.skipped],
    }


def _known_category(preset: Preset, category_id: str) -> bool:
    try:
        preset.category(category_id)
    except KeyError:
        return False
    return True


def _version() -> str:
    from sanitize import __version__

    return __version__


def _markdown(report: dict[str, Any]) -> str:
    """Человекочитаемая Markdown-версия отчёта."""
    summary = report["summary"]
    lines: list[str] = [
        "# Отчёт sanitize",
        "",
        f"- Корень: `{report['root']}`",
        f"- Профиль: {report['preset']['title']} ({report['preset']['id']})",
        f"- Хост: {report['host']}",
        f"- Начало: {report['started_at']}  |  Завершение: {report['finished_at']}",
        f"- Найдено файлов: {summary['total_files']} ({human_size(summary['total_size'])})",
    ]
    if summary["skipped"]:
        lines.append(f"- Пропущено: {summary['skipped']} ({summary['skipped_by_reason']})")
    if report.get("cancelled"):
        lines.append("- ВНИМАНИЕ: сканирование прервано")

    lines += [
        "",
        "## Сводка по категориям",
        "",
        "| Категория | Файлов | Размер |",
        "|---|---:|---:|",
    ]
    for category_id, bucket in summary["by_category"].items():
        lines.append(
            f"| {bucket['title']} (`{category_id}`) | {bucket['count']} "
            f"| {human_size(bucket['size'])} |"
        )

    for category_id, bucket in summary["by_category"].items():
        lines += ["", f"## {bucket['title']}", "", "| Файл | Размер |", "|---|---:|"]
        for entry in report["entries"]:
            if entry["category"] == category_id:
                risk = f" ⚠️ {', '.join(entry['risk_dirs'])}" if entry["risk_dirs"] else ""
                lines.append(f"| `{entry['path_rel']}` | {human_size(entry['size'])}{risk} |")

    if report["actions"]:
        lines += [
            "",
            "## Выполненные действия",
            "",
            "| Файл | Действие | Результат | SHA-256 |",
            "|---|---|---|---|",
        ]
        for action in report["actions"]:
            status = "OK" if action["ok"] else f"ОШИБКА: {action['error']}"
            if action.get("note"):
                status += f" ({action['note']})"
            digest = action["sha256"] or "-"
            lines.append(f"| `{action['path_rel']}` | {action['action']} | {status} | {digest} |")

    if report["errors"]:
        lines += ["", "## Пропущено", "", "| Файл | Причина |", "|---|---|"]
        for error in report["errors"]:
            lines.append(f"| `{error['path']}` | {error['reason']} |")

    lines.append("")
    return "\n".join(lines)


def write_report(path: Path, report: dict[str, Any]) -> Path:
    """Пишет отчёт в файл: Markdown для .md, JSON для остальных расширений."""
    if path.suffix.lower() == ".md":
        path.write_text(_markdown(report), encoding="utf-8")
    else:
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path
