"""Тесты GUI (фаза 4): pytest-qt, QT_QPA_PLATFORM=offscreen (AGENTS.md, раздел 10)."""

from __future__ import annotations

import hashlib
import os
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

pytest.importorskip("PySide6", reason="GUI-тесты требуют extras 'gui' (PySide6)")

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from sanitize.core.models import Action, FileEntry, ScanOptions
from sanitize.core.presets import load_preset
from sanitize.core.scanner import scan
from sanitize.gui.results_model import ResultsFilterProxy, ResultsModel
from sanitize.gui.worker import ActionWorker, ScanWorker

from conftest import make_file


@pytest.fixture(autouse=True)
def _isolated_qsettings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Изолирует QSettings тестов от пользовательского конфига."""
    config_dir = tmp_path / "config"
    config_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_dir))
    from PySide6.QtCore import QSettings

    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(config_dir))


@pytest.fixture()
def scan_result(fake_bitrix_tree: Path) -> object:
    preset = load_preset("bitrix")
    options = ScanOptions(
        root=fake_bitrix_tree,
        preset="bitrix",
        categories={c.id for c in preset.categories if c.default_enabled} | {"secrets_report"},
    )
    return scan(options, preset)


def _make_model(fake_bitrix_tree: Path, result: object) -> ResultsModel:
    model = ResultsModel(fake_bitrix_tree)
    model.set_result(result, load_preset("bitrix").categories)  # type: ignore[arg-type]
    return model


# ------------------------- ScanWorker -------------------------


class TestScanWorker:
    def test_scan_fills_result(self, qtbot: object, fake_bitrix_tree: Path) -> None:
        preset = load_preset("bitrix")
        options = ScanOptions(
            root=fake_bitrix_tree,
            preset="bitrix",
            categories={c.id for c in preset.categories if c.default_enabled} | {"secrets_report"},
        )
        worker = ScanWorker(options, preset)
        with qtbot.waitSignal(worker.scan_finished, timeout=15000) as blocker:  # type: ignore[attr-defined]
            worker.start()
        result = blocker.args[0]
        assert not result.cancelled
        # 27 файлов в fake_bitrix_tree попадают в категории (см. фикстуру)
        assert len(result.entries) == 27

    def test_pre_cancelled_scan_returns_cancelled(
        self, qtbot: object, fake_bitrix_tree: Path
    ) -> None:
        preset = load_preset("bitrix")
        worker = ScanWorker(ScanOptions(root=fake_bitrix_tree), preset)
        worker.stop()  # отмена до старта
        with qtbot.waitSignal(worker.scan_finished, timeout=15000) as blocker:  # type: ignore[attr-defined]
            worker.start()
        assert blocker.args[0].cancelled
        assert blocker.args[0].entries == []

    def test_scan_does_not_modify_fs(
        self, qtbot: object, fake_bitrix_tree: Path, tree_hash: Callable[[], str]
    ) -> None:
        before = tree_hash()
        preset = load_preset("bitrix")
        worker = ScanWorker(ScanOptions(root=fake_bitrix_tree), preset)
        with qtbot.waitSignal(worker.scan_finished, timeout=15000):  # type: ignore[attr-defined]
            worker.start()
        assert tree_hash() == before

    def test_progress_emitted(self, qtbot: object, fake_bitrix_tree: Path) -> None:
        preset = load_preset("bitrix")
        worker = ScanWorker(ScanOptions(root=fake_bitrix_tree), preset)
        seen: list[int] = []
        worker.progress.connect(lambda done, total, current: seen.append(done))
        with qtbot.waitSignal(worker.scan_finished, timeout=15000):  # type: ignore[attr-defined]
            worker.start()
        assert seen  # троттлинг не съедает все события на маленьком дереве


# ------------------------- ResultsModel -------------------------


class TestResultsModel:
    def test_tree_structure(self, fake_bitrix_tree: Path, scan_result: object) -> None:
        model = _make_model(fake_bitrix_tree, scan_result)
        # 9 категорий с файлами (media пустая — отсутствует)
        assert model.rowCount() == 9
        docs = model.index(0, 0)
        assert str(docs.data(Qt.ItemDataRole.DisplayRole)).startswith("Документы")
        assert (
            model.rowCount(docs) == 6
        )  # report.pdf, report_upper.PDF, doc.pdf, scan.pdf, notes.txt, empty.pdf
        child = model.index(0, 0, docs)
        assert child.data(Qt.ItemDataRole.DisplayRole).endswith(".pdf")

    def test_all_checked_by_default_and_uncheck_propagates(
        self, fake_bitrix_tree: Path, scan_result: object
    ) -> None:
        model = _make_model(fake_bitrix_tree, scan_result)
        assert model.checked_count() == 26  # 27 минус dbconn.php (report_only)
        docs = model.index(0, 0)
        assert model.setData(docs, False, Qt.ItemDataRole.CheckStateRole)
        assert model.checked_count() == 26 - 6
        # файлы категории сняты:
        for row in range(model.rowCount(docs)):
            child = model.index(row, 0, docs)
            assert child.data(Qt.ItemDataRole.CheckStateRole) == Qt.CheckState.Unchecked
        # tri-state категории:
        assert docs.data(Qt.ItemDataRole.CheckStateRole) == Qt.CheckState.Unchecked

    def test_report_only_not_selectable(self, fake_bitrix_tree: Path, scan_result: object) -> None:
        model = _make_model(fake_bitrix_tree, scan_result)
        secrets_row = next(
            r
            for r in range(model.rowCount())
            if str(model.index(r, 0).data(Qt.ItemDataRole.DisplayRole)).startswith("Конфиги")
        )
        secrets_index = model.index(secrets_row, 0)
        flags = model.flags(secrets_index)
        assert not (flags & Qt.ItemFlag.ItemIsUserCheckable)
        assert model.checked_count() == 26  # dbconn.php никогда не выбирается

    def test_filter_proxy(self, fake_bitrix_tree: Path, scan_result: object) -> None:
        model = _make_model(fake_bitrix_tree, scan_result)
        proxy = ResultsFilterProxy()
        proxy.setSourceModel(model)
        assert proxy.rowCount() == model.rowCount()
        proxy.set_filter_text("webform")
        # webform-файлы живут в docs и sheets
        assert proxy.rowCount() == 2
        proxy.set_filter_text("% Нет такого пути %")
        assert proxy.rowCount() == 0

    def test_mark_processed_strikes_out(self, fake_bitrix_tree: Path, scan_result: object) -> None:
        model = _make_model(fake_bitrix_tree, scan_result)
        docs = model.index(0, 0)
        entry = model.index(0, 0, docs).data(Qt.ItemDataRole.UserRole)
        model.mark_processed({entry.path})
        assert model.index(0, 0, docs).data(Qt.ItemDataRole.FontRole).strikeOut()


# ------------------------- ActionWorker -------------------------


class TestActionWorker:
    def _entries(self, root: Path, count: int = 3) -> list[FileEntry]:
        paths = [make_file(root, f"act{i}.txt", content=f"data{i}".encode()) for i in range(count)]
        entries = []
        for path in paths:
            st = os.stat(path)
            entries.append(
                FileEntry(
                    path=path,
                    size=st.st_size,
                    mtime=st.st_mtime,
                    uid=st.st_uid,
                    gid=st.st_gid,
                    mode=st.st_mode,
                    category_id="docs",
                )
            )
        return entries

    def test_zero_action_worker(self, qtbot: object, tmp_path: Path) -> None:
        entries = self._entries(tmp_path)
        worker = ActionWorker(entries, Action.ZERO, load_preset("bitrix"))
        with qtbot.waitSignal(worker.action_finished, timeout=15000) as blocker:  # type: ignore[attr-defined]
            worker.start()
        results = blocker.args[0]
        assert all(r.ok for r in results)
        assert all(p.read_bytes() == b"" for p in (e.path for e in entries))

    def test_cancelled_action_worker(self, qtbot: object, tmp_path: Path) -> None:
        entries = self._entries(tmp_path)
        worker = ActionWorker(entries, Action.ZERO, load_preset("bitrix"))
        worker.cancel_event.set()
        with qtbot.waitSignal(worker.action_finished, timeout=15000):  # type: ignore[attr-defined]
            worker.start()
        assert all(p.read_bytes() != b"" for p in (e.path for e in entries))


# ------------------------- MainWindow -------------------------


def _tree_hash(root: Path) -> str:
    sha = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        sha.update(str(path.relative_to(root)).encode())
        if path.is_file():
            try:
                sha.update(path.read_bytes())
            except PermissionError:
                sha.update(b"<noaccess>")
    return sha.hexdigest()


class TestMainWindow:
    def test_full_scan_flow_updates_ui(self, qtbot: object, fake_bitrix_tree: Path) -> None:
        from sanitize.gui.main_window import MainWindow

        window = MainWindow()
        qtbot.addWidget(window)
        assert not window.run_button.isEnabled()

        for checkbox in window.category_checks.values():
            checkbox.setChecked(True)
        window.category_checks["media"].setChecked(False)

        before = _tree_hash(fake_bitrix_tree)
        window.path_edit.setText(str(fake_bitrix_tree))
        window.start_scan()
        with qtbot.waitSignal(window.scan_completed, timeout=30000):  # type: ignore[attr-defined]
            pass
        qtbot.waitUntil(window._update_buttons, timeout=5000)  # type: ignore[attr-defined]

        assert window.run_button.isEnabled()  # есть выбранные файлы
        assert window.find_button.isEnabled()  # сканирование завершено
        assert "Найдено" in window.summary_label.text()
        assert _tree_hash(fake_bitrix_tree) == before  # только поиск — ФС не тронута

    def test_execute_disabled_when_all_unchecked(
        self, qtbot: object, fake_bitrix_tree: Path
    ) -> None:
        from sanitize.gui.main_window import MainWindow

        window = MainWindow()
        qtbot.addWidget(window)
        for checkbox in window.category_checks.values():
            checkbox.setChecked(False)
        window.path_edit.setText(str(fake_bitrix_tree))
        window.start_scan()
        with qtbot.waitSignal(window.scan_completed, timeout=30000):  # type: ignore[attr-defined]
            pass
        qtbot.waitUntil(window._update_buttons, timeout=5000)  # type: ignore[attr-defined]
        # secrets_report не выбираем, остальные сняты — «Выполнить» недоступна
        assert not window.run_button.isEnabled()
        assert window.model.checked_count() == 0

    def test_stop_button_lifecycle(self, qtbot: object, fake_bitrix_tree: Path) -> None:
        from sanitize.gui.main_window import MainWindow

        window = MainWindow()
        qtbot.addWidget(window)
        window.path_edit.setText(str(fake_bitrix_tree))
        assert not window.stop_button.isEnabled()
        window.start_scan()
        assert window.stop_button.isEnabled()
        with qtbot.waitSignal(window.scan_completed, timeout=30000):  # type: ignore[attr-defined]
            pass
        qtbot.waitUntil(window._update_buttons, timeout=5000)  # type: ignore[attr-defined]
        assert not window.stop_button.isEnabled()


def test_qapp_offscreen() -> None:
    """Санити: offscreen-платформа доступна и QApplication создаётся."""
    app = QApplication.instance() or QApplication([])
    assert app is not None
    assert threading.current_thread().name == "MainThread"
