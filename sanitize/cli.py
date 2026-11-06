"""CLI-интерфейс sanitize (AGENTS.md, раздел 7).

Exit-коды: 0 — успех; 1 — часть файлов не обработана; 2 — найдены report_only
файлы (секреты в конфигах); 3 — отказ (небезопасный путь, нет подтверждения,
неверные аргументы); 130 — прервано пользователем.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sanitize import __version__
from sanitize.core.actions import apply
from sanitize.core.models import Action, ScanOptions, ScanResult
from sanitize.core.presets import Preset, PresetError, load_preset
from sanitize.core.report import build_report, human_size, write_report
from sanitize.core.safety import SafetyError, check_root, has_project_markers
from sanitize.core.scanner import scan

EXIT_OK = 0
EXIT_PARTIAL = 1
EXIT_SECRETS = 2
EXIT_REFUSED = 3
EXIT_INTERRUPTED = 130

_SIZE_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([kKmMgG])?$")
_DURATION_RE = re.compile(r"^(\d+)\s*([smhdw])$")
_SIZE_MULTIPLIERS = {"k": 1024, "m": 1024**2, "g": 1024**3}
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

logger = logging.getLogger("sanitize.cli")


class _Parser(argparse.ArgumentParser):
    """argparse с exit-кодом 3 при ошибках аргументов (по умолчанию 2)."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        print(f"sanitize: ошибка аргументов: {message}", file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)


def build_parser() -> _Parser:
    parser = _Parser(
        prog="sanitize",
        description="Поиск и обезвреживание файлов с ПДн и секретами в веб-проектах.",
    )
    parser.add_argument(
        "--path", default=".", metavar="DIR", help="корень проекта (по умолчанию текущий каталог)"
    )
    action_group = parser.add_argument_group("действие (по умолчанию --zero)")
    action_group.add_argument("--zero", action="store_true", help="обнулить файлы (по умолчанию)")
    action_group.add_argument(
        "--delete", action="store_true", help="удалить файлы (требует ввода DELETE)"
    )
    action_group.add_argument(
        "--stub", action="store_true", help="заменить минимально валидной заглушкой"
    )
    action_group.add_argument(
        "--quarantine", metavar="DIR", help="упаковать в tar.gz вне корня (фаза 6)"
    )
    parser.add_argument("--dry-run", action="store_true", help="только показать, ничего не менять")
    parser.add_argument(
        "--preset", choices=("bitrix", "generic"), default="bitrix", help="профиль поиска"
    )
    parser.add_argument("--category", metavar="ID,...", help="только перечисленные категории")
    parser.add_argument("--ext", metavar=".X,.Y", help="дополнительные расширения")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="исключить glob (можно повторять)",
    )
    parser.add_argument(
        "--include-hidden", action="store_true", help="учитывать скрытые файлы (.env и т.п.)"
    )
    parser.add_argument("--follow-symlinks", action="store_true", help="следовать по симлинкам")
    parser.add_argument("--no-one-filesystem", action="store_true", help="переходить на другие ФС")
    parser.add_argument(
        "--min-size", metavar="SIZE", help="минимальный размер (K/M/G = КиБ/МиБ/ГиБ)"
    )
    parser.add_argument("--older-than", metavar="DURATION", help="только старше: 30d, 12h, 90m, 7w")
    parser.add_argument(
        "--magic", action="store_true", help="определять тип по сигнатуре (python-magic)"
    )
    parser.add_argument(
        "--deep-scan", action="store_true", help="искать ПДн по содержимому (фаза 5)"
    )
    parser.add_argument(
        "--threads", type=int, default=4, metavar="N", help="потоки обхода (фаза 5)"
    )
    parser.add_argument("--no-hash", action="store_true", help="не считать sha256 перед изменением")
    parser.add_argument("--report", metavar="FILE", help="сохранить отчёт (.json или .md)")
    parser.add_argument("--json", action="store_true", help="машиночитаемый вывод в stdout")
    parser.add_argument("--yes", "-y", action="store_true", help="не спрашивать подтверждение")
    parser.add_argument("--quiet", "-q", action="store_true", help="минимум вывода")
    parser.add_argument("--verbose", "-v", action="store_true", help="подробный журнал")
    parser.add_argument("--gui", action="store_true", help="запустить графический интерфейс")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _parse_size(raw: str) -> int:
    match = _SIZE_RE.match(raw.strip())
    if not match:
        raise ValueError(f"неверный размер: {raw!r} (примеры: 1024, 10M, 2G)")
    value = float(match.group(1))
    multiplier = _SIZE_MULTIPLIERS.get((match.group(2) or "").lower(), 1)
    return int(value * multiplier)


def _parse_duration(raw: str) -> timedelta:
    match = _DURATION_RE.match(raw.strip())
    if not match:
        raise ValueError(f"неверная длительность: {raw!r} (примеры: 30d, 12h, 90m, 7w)")
    return timedelta(seconds=int(match.group(1)) * _DURATION_UNITS[match.group(2)])


def _parse_ext(raw: str) -> tuple[str, ...]:
    exts: list[str] = []
    for part in raw.split(","):
        value = part.strip().lower()
        if not value:
            continue
        if not value.startswith("."):
            value = "." + value
        exts.append(value)
    return tuple(exts)


def _resolve_action(args: argparse.Namespace) -> Action:
    if args.delete:
        return Action.DELETE
    if args.stub:
        return Action.STUB
    return Action.ZERO  # --zero по умолчанию


def _category_summary(result: ScanResult, preset: Preset) -> list[str]:
    grouped = result.files_by_category()
    lines = []
    for cat in preset.categories:
        entries = grouped.get(cat.id)
        if not entries:
            continue
        size = sum(e.size for e in entries)
        mark = " ⚠️ только отчёт" if cat.report_only else ""
        lines.append(f"  {cat.title}: {len(entries)} файл(ов), {human_size(size)}{mark}")
    extra = grouped.get("extra")
    if extra:
        size = sum(e.size for e in extra)
        lines.append(f"  Доп. расширения: {len(extra)} файл(ов), {human_size(size)}")
    return lines


def _full_summary(result: ScanResult) -> str:
    skipped = len(result.skipped)
    return f"Найдено: {len(result.entries)} файл(ов), {human_size(result.total_size())}" + (
        f" · Пропущено: {skipped} (нет доступа и др.)" if skipped else ""
    )


def _secrets_present(result: ScanResult, preset: Preset) -> bool:
    report_only = {cat.id for cat in preset.categories if cat.report_only}
    return any(entry.category_id in report_only for entry in result.entries)


def _confirm(result: ScanResult, preset: Preset, action: Action, root: Path) -> bool:
    verb = {Action.ZERO: "обнулить", Action.DELETE: "УДАЛИТЬ", Action.STUB: "заменить заглушками"}
    print(f"\nКорень: {root}")
    print(_full_summary(result))
    for line in _category_summary(result, preset):
        print(line)
    question = f"\nПродолжить: {verb.get(action, action.value)} {len(result.entries)} файл(ов)?"
    if action is Action.DELETE:
        answer = input(f"{question}\nДля подтверждения введите DELETE: ").strip()
        return answer == "DELETE"
    answer = input(f"{question} [y/N]: ").strip().lower()
    return answer in ("y", "yes")


def _action_summary(actions: list[object]) -> str:
    ok = sum(1 for a in actions if a.ok)  # type: ignore[attr-defined]
    failed = len(actions) - ok
    skipped = sum(
        1
        for a in actions
        if getattr(a, "note", None)  # type: ignore[attr-defined]
    )
    parts = [f"Обработано: {ok}", f"Ошибок: {failed}"]
    if skipped:
        parts.append(f"Пропущено: {skipped} (пустые/симлинки)")
    return " · ".join(parts)


def _build_payload(
    result: ScanResult,
    options: ScanOptions,
    preset: Preset,
    started_at: datetime,
    actions: Sequence[object] = (),
) -> dict[str, object]:
    return build_report(
        result=result,
        options=options,
        preset=preset,
        started_at=started_at,
        finished_at=datetime.now(UTC),
        actions=actions,  # type: ignore[arg-type]
    )


def run(args: argparse.Namespace) -> int:
    if args.gui:
        try:
            from sanitize.gui.app import main as gui_main
        except ImportError:
            print(
                "GUI недоступен: установите зависимости — pip install 'sanitize[gui]'",
                file=sys.stderr,
            )
            return EXIT_REFUSED
        return gui_main()

    if args.quarantine:
        print("Карантин будет реализован в фазе 6 (AGENTS.md, раздел 10).", file=sys.stderr)
        return EXIT_REFUSED

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    elif not args.quiet:
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.ERROR)

    try:
        preset = load_preset(args.preset)
    except PresetError as exc:
        print(f"Ошибка профиля: {exc}", file=sys.stderr)
        return EXIT_REFUSED

    try:
        root = check_root(Path(args.path))
    except SafetyError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_REFUSED

    categories: set[str] | None = None
    if args.category:
        categories = {c.strip() for c in args.category.split(",") if c.strip()}
        known = {cat.id for cat in preset.categories}
        unknown = categories - known
        if unknown:
            print(f"Неизвестные категории: {', '.join(sorted(unknown))}", file=sys.stderr)
            return EXIT_REFUSED

    try:
        min_size = _parse_size(args.min_size) if args.min_size else 0
        older_than = _parse_duration(args.older_than) if args.older_than else None
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_REFUSED

    options = ScanOptions(
        root=root,
        preset=preset.id,
        categories=categories,
        extra_extensions=_parse_ext(args.ext) if args.ext else (),
        exclude_globs=tuple(args.exclude),
        include_hidden=args.include_hidden,
        follow_symlinks=args.follow_symlinks,
        one_filesystem=not args.no_one_filesystem,
        min_size=min_size,
        older_than=older_than,
        use_magic=args.magic,
        deep_scan=args.deep_scan,
        threads=args.threads,
    )

    started_at = datetime.now(UTC)
    try:
        result = scan(options)
    except KeyboardInterrupt:
        print("\nПрервано пользователем", file=sys.stderr)
        return EXIT_INTERRUPTED

    if not has_project_markers(root, preset):
        print(
            "⚠️  Предупреждение: в корне нет маркеров проекта "
            f"({', '.join(preset.markers) or '—'}). Убедитесь, что путь верен.",
            file=sys.stderr,
        )

    actions: list[object] = []
    exit_code = EXIT_OK
    if args.dry_run:
        if not args.quiet and not args.json:
            for entry in result.entries:
                rel = entry.path.relative_to(root).as_posix()
                risk = f"  [{', '.join(entry.risk_dirs)}]" if entry.risk_dirs else ""
                print(f"  {rel}  ({human_size(entry.size)}){risk}")
            print()
            print(_full_summary(result))
            for line in _category_summary(result, preset):
                print(line)
    else:
        action = _resolve_action(args)
        if result.entries:
            if not args.yes:
                if not sys.stdin.isatty():
                    print(
                        "stdin не TTY: интерактивное подтверждение недоступно. "
                        "Используйте --yes (осознанно) или --dry-run.",
                        file=sys.stderr,
                    )
                    return EXIT_REFUSED
                if not _confirm(result, preset, action, root):
                    print("Отменено пользователем")
                    return EXIT_REFUSED
            # report_only-файлы не передаём в действия (двойная защита: и тут, и в core)
            report_only_ids = {cat.id for cat in preset.categories if cat.report_only}
            targets = [e for e in result.entries if e.category_id not in report_only_ids]
            if targets:
                try:
                    actions = list(
                        apply(
                            targets,
                            action,
                            preset=preset,
                            no_hash=args.no_hash,
                        )
                    )
                except KeyboardInterrupt:
                    print("\nПрервано пользователем", file=sys.stderr)
                    return EXIT_INTERRUPTED
            if not args.quiet and not args.json:
                print(_action_summary(actions))

    if not result.cancelled:
        if any(getattr(a, "ok", True) is False for a in actions):
            exit_code = EXIT_PARTIAL
        elif _secrets_present(result, preset):
            exit_code = EXIT_SECRETS

    payload = _build_payload(result, options, preset, started_at, actions)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    if args.report:
        write_report(Path(args.report).expanduser(), payload)
        if not args.quiet:
            print(f"Отчёт: {args.report}")

    if _secrets_present(result, preset) and not args.quiet:
        print(
            "⚠️  Найдены конфиги с секретами (report_only) — они не изменялись, но попали в отчёт.",
            file=sys.stderr,
        )
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """Точка входа CLI (используется консольным скриптом sanitize)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nПрервано пользователем", file=sys.stderr)
        return EXIT_INTERRUPTED
