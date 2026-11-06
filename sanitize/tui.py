"""Минимальный TUI на Textual для headless-стендов по SSH (AGENTS.md, фаза 6).

Минимум по спеке: путь, чекбоксы категорий, список найденного, действие
(обнулить/удалить) с подтверждением. Карантин/magic/deep-scan — через CLI.
Действие применяется ко всем найденным файлам выбранных категорий.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import ClassVar

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Footer, Header, Input, Label, RichLog

from sanitize.core.actions import apply as core_apply
from sanitize.core.models import Action, FileEntry, ScanOptions, ScanResult
from sanitize.core.presets import load_preset
from sanitize.core.report import human_size
from sanitize.core.safety import SafetyError, check_root, has_project_markers
from sanitize.core.scanner import scan

_CATEGORY_LABELS: tuple[tuple[str, str], ...] = (
    ("docs", "Документы"),
    ("sheets", "Таблицы"),
    ("slides", "Презентации"),
    ("archives", "Архивы"),
    ("keys", "Ключи"),
    ("backups", "Бэкапы"),
    ("mail", "Почта"),
    ("logs", "Логи"),
)


class ConfirmScreen(ModalScreen[bool]):
    """Модальное подтверждение; для DELETE требует ввода слова DELETE."""

    BINDINGS: ClassVar[list] = [("escape", "app.pop_screen", "Отмена")]

    def __init__(self, verb: str, count: int, size: int, require_delete: bool) -> None:
        super().__init__()
        self._verb = verb
        self._count = count
        self._size = size
        self._require_delete = require_delete

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm_box"):
            yield Label(
                f"{self._verb}: {self._count} файл(ов), {human_size(self._size)}. "
                + ("Введите DELETE и нажмите OK." if self._require_delete else "Продолжить?")
            )
            if self._require_delete:
                yield Input(placeholder="DELETE", id="confirm_input")
            with Horizontal():
                ok_button = Button("OK", id="confirm_ok", variant="error")
                if self._require_delete:
                    ok_button.disabled = True
                yield ok_button
                yield Button("Отмена", id="confirm_cancel")

    @on(Input.Changed, "#confirm_input")
    def _validate(self, event: Input.Changed) -> None:
        self.query_one("#confirm_ok", Button).disabled = event.value.strip() != "DELETE"

    @on(Button.Pressed, "#confirm_ok")
    def _ok(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#confirm_cancel")
    def _cancel(self) -> None:
        self.dismiss(False)


class SanitizeTUI(App[int]):
    """Минимальный терминальный интерфейс sanitize."""

    TITLE = "sanitize — ПДн/секреты"
    CSS = """
    #confirm_box { width: 60%; height: auto; border: round red; padding: 1 2;
                   background: $surface; }
    #confirm_box Horizontal { height: 3; }
    #log { border: round $primary; height: 1fr; }
    #table { height: 2fr; }
    """
    BINDINGS: ClassVar[list] = [
        ("q", "quit", "Выход"),
        ("s", "scan", "Сканировать"),
        ("x", "stop", "Стоп"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._cancel_event = threading.Event()
        self._result: ScanResult | None = None
        self._entries: list[FileEntry] = []
        self._pending_action: Action | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(placeholder="/var/www/site", id="path")
        with Horizontal(id="checks"):
            for category_id, label in _CATEGORY_LABELS:
                yield Checkbox(label, value=category_id != "logs", id=f"cat_{category_id}")
        with Horizontal(id="buttons"):
            yield Button("Сканировать (s)", id="scan", variant="primary")
            yield Button("Стоп (x)", id="stop")
            yield Button("Обнулить", id="zero", variant="warning")
            yield Button("Удалить", id="delete", variant="error")
        yield DataTable(id="table")
        yield RichLog(id="log", markup=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#table", DataTable)
        table.add_columns("Категория", "Файл", "Размер")
        self.query_one("#log", RichLog).write("Укажите путь и нажмите «Сканировать».")

    # --- сканирование ---

    @work(thread=True, exclusive=True)
    def _scan_worker(self, options: ScanOptions) -> None:
        result = scan(options, cancel_event=self._cancel_event)
        self.call_from_thread(self._scan_done, result)

    def _action_scan(self) -> None:
        raw = self.query_one("#path", Input).value.strip()
        if not raw:
            self.query_one("#log", RichLog).write("[red]Путь не задан[/red]")
            return
        try:
            root = check_root(Path(raw))
        except SafetyError as exc:
            self.query_one("#log", RichLog).write(f"[red]{exc}[/red]")
            return
        preset = load_preset("bitrix")
        if not has_project_markers(root, preset):
            self.query_one("#log", RichLog).write(
                "[yellow]Нет маркеров Битрикс — проверьте путь.[/yellow]"
            )
        categories = {
            category_id
            for category_id, _label in _CATEGORY_LABELS
            if self.query_one(f"#cat_{category_id}", Checkbox).value
        }
        categories.add("secrets_report")
        self._cancel_event = threading.Event()
        self._result = None
        self.query_one("#table", DataTable).clear()
        self.query_one("#log", RichLog).write("Сканирую…")
        self._scan_worker(ScanOptions(root=root, preset=preset.id, categories=categories))

    def _scan_done(self, result: ScanResult) -> None:
        self._result = result
        table = self.query_one("#table", DataTable)
        table.clear()
        self._entries = result.entries
        for entry in result.entries:
            try:
                rel = entry.path.relative_to(result.root).as_posix()
            except ValueError:
                rel = entry.path.name
            table.add_row(entry.category_id, rel, human_size(entry.size))
        log = self.query_one("#log", RichLog)
        note = " — прервано" if result.cancelled else ""
        log.write(
            f"Найдено: {len(result.entries)} файл(ов), {human_size(result.total_size())}"
            f", пропущено: {len(result.skipped)}{note}"
        )

    # --- действия ---

    def _apply(self, action: Action) -> None:
        if self._result is None or not self._entries:
            self.query_one("#log", RichLog).write("[yellow]Сначала сканируйте.[/yellow]")
            return
        verb = "Обнулить" if action is Action.ZERO else "Удалить"
        self._pending_action = action
        self.push_screen(
            ConfirmScreen(
                verb,
                len(self._entries),
                sum(e.size for e in self._entries),
                require_delete=action is Action.DELETE,
            ),
            callback=self._on_confirmed,
        )

    def _on_confirmed(self, confirmed: bool | None) -> None:
        if not confirmed or self._pending_action is None:
            self.query_one("#log", RichLog).write("Отменено.")
            self._pending_action = None
            return
        action = self._pending_action
        self._pending_action = None
        self.query_one("#log", RichLog).write("Выполняю…")
        self._cancel_event = threading.Event()
        self._apply_worker(action)

    @work(thread=True, exclusive=True)
    def _apply_worker(self, action: Action) -> None:
        preset = load_preset("bitrix")
        results = core_apply(self._entries, action, preset=preset, cancel_event=self._cancel_event)
        self.call_from_thread(self._apply_done, action, results)

    def _apply_done(self, action: Action, results: list) -> None:
        ok = sum(1 for r in results if r.ok)
        failed = len(results) - ok
        self.query_one("#log", RichLog).write(f"{action.value}: обработано {ok}, ошибок {failed}")

    # --- события и команды ---

    @on(Button.Pressed, "#scan")
    def _press_scan(self) -> None:
        self._action_scan()

    @on(Button.Pressed, "#stop")
    def _press_stop(self) -> None:
        self.action_stop()

    @on(Button.Pressed, "#zero")
    def _press_zero(self) -> None:
        self._apply(Action.ZERO)

    @on(Button.Pressed, "#delete")
    def _press_delete(self) -> None:
        self._apply(Action.DELETE)

    def action_scan(self) -> None:
        self._action_scan()

    def action_stop(self) -> None:
        self._cancel_event.set()


def run() -> int:
    """Точка входа TUI (sanitize --tui)."""
    app: SanitizeTUI = SanitizeTUI()
    app.run()
    return 0
