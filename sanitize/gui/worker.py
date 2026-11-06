"""QObject+QThread-обёртки над scanner/actions: сигналы прогресса и отмена (AGENTS.md, разд. 8).

Все воркеры — наследники QThread с потокобезопасной отменой через
threading.Event (событие живёт в ядре, как требует раздел 3 AGENTS.md).
Имена сигналов завершения не совпадают со встроенным QThread.finished.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from sanitize.core.actions import apply
from sanitize.core.models import Action, ActionResult, FileEntry, ScanOptions
from sanitize.core.presets import Preset
from sanitize.core.scanner import count_entries, scan

logger = logging.getLogger(__name__)


class ScanWorker(QThread):
    """Сканирование дерева в фоне. Сигналы: progress(done, total, current_path)."""

    progress = Signal(int, int, str)
    scan_finished = Signal(object)  # ScanResult
    failed = Signal(str)

    def __init__(self, options: ScanOptions, preset: Preset, parent=None) -> None:
        super().__init__(parent)
        self._options = options
        self._preset = preset
        self.cancel_event = threading.Event()

    def stop(self) -> None:
        self.cancel_event.set()

    def run(self) -> None:
        try:
            result = scan(
                self._options,
                self._preset,
                on_progress=self._emit_progress,
                cancel_event=self.cancel_event,
            )
        except Exception as exc:
            logger.exception("Сканирование упало")
            self.failed.emit(str(exc))
            return
        self.scan_finished.emit(result)

    def _emit_progress(self, done: int, total: int | None, current: Path) -> None:
        self.progress.emit(done, -1 if total is None else total, str(current))


class CountWorker(QThread):
    """Быстрый подсчёт файлов (фаза 1 прогресса: indeterminate)."""

    count_finished = Signal(int)
    failed = Signal(str)

    def __init__(self, root: Path, preset: Preset, parent=None) -> None:
        super().__init__(parent)
        self._root = root
        self._preset = preset
        self.cancel_event = threading.Event()

    def stop(self) -> None:
        self.cancel_event.set()

    def run(self) -> None:
        try:
            total = count_entries(self._root, self._preset, cancel_event=self.cancel_event)
        except Exception as exc:
            logger.exception("Подсчёт каталогов упал")
            self.failed.emit(str(exc))
            return
        self.count_finished.emit(total)


class ActionWorker(QThread):
    """Применение действия к выбранным файлам в фоне."""

    action_progress = Signal(int, int)  # обработано, всего
    action_finished = Signal(object)  # list[ActionResult]
    failed = Signal(str)

    def __init__(
        self,
        entries: list[FileEntry],
        action: Action,
        preset: Preset,
        *,
        no_hash: bool = False,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._entries = entries
        self._action = action
        self._preset = preset
        self._no_hash = no_hash
        self.cancel_event = threading.Event()

    def stop(self) -> None:
        self.cancel_event.set()

    def run(self) -> None:
        total = len(self._entries)
        processed = 0

        def on_result(_result: ActionResult) -> None:
            nonlocal processed
            processed += 1
            self.action_progress.emit(processed, total)

        try:
            results = apply(
                self._entries,
                self._action,
                preset=self._preset,
                no_hash=self._no_hash,
                cancel_event=self.cancel_event,
                on_result=on_result,
            )
        except Exception as exc:
            logger.exception("Действие упало")
            self.failed.emit(str(exc))
            return
        self.action_finished.emit(results)
