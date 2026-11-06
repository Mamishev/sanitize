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
from sanitize.core.models import Action, FileEntry, ScanOptions, ScanResult
from sanitize.core.presets import load_preset
from sanitize.core.scanner import scan
from sanitize.gui.results_model import GroupMode, ResultsFilterProxy, ResultsModel
from sanitize.gui.worker import ActionWorker, ScanWorker

from conftest import make_file


@pytest.fixture(autouse=True)
def _isolated_qsettings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Изолирует QSettings тестов: уникальный ini-файл на тест.

    Нативный QSettings кеширует путь конфига на процесс, поэтому подмена
    XDG_CONFIG_HOME между тестами не работает — патчим фабрику QSettings
    в модуле settings на явный файл (tmp_path уникален для каждого теста).
    """
    config_dir = tmp_path / "config"
    config_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_dir))
    from PySide6.QtCore import QSettings as _RealQSettings
    from sanitize.gui import settings as settings_module

    settings_file = str(config_dir / "sanitize.ini")

    class _IsolatedSettings(_RealQSettings):
        def __init__(self, *_args, **_kwargs) -> None:
            super().__init__(settings_file, _RealQSettings.Format.IniFormat)

    monkeypatch.setattr(settings_module, "QSettings", _IsolatedSettings)


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


# --------------------- UX: свёртывание, группировка, колонки, «?» ---------------------


def _make_entries(root: Path, rels: list[str]) -> list:
    entries = []
    for rel in rels:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"data")
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


class TestCollapseRules:
    def test_large_category_collapsed_small_expanded(self, qtbot: object, tmp_path: Path) -> None:
        from sanitize.gui.main_window import MainWindow

        root = tmp_path / "site"
        for i in range(12):
            (root / "big" / f"doc{i}.pdf").parent.mkdir(parents=True, exist_ok=True)
            (root / "big" / f"doc{i}.pdf").write_bytes(b"x")
        for i in range(3):
            (root / f"note{i}.pdf").write_bytes(b"x")
        (root / "app.log").write_bytes(b"log")

        window = MainWindow()
        qtbot.addWidget(window)
        window.path_edit.setText(str(root))
        window.start_scan()
        with qtbot.waitSignal(window.scan_completed, timeout=30000):  # type: ignore[attr-defined]
            pass

        # порядок категорий: docs (15 файлов -> свёрнута), logs (1 -> развёрнута)
        assert window.model.rowCount() == 2
        docs_proxy = window.proxy.index(0, 0)
        logs_proxy = window.proxy.index(1, 0)
        assert str(window.proxy.data(docs_proxy)).startswith("Документы")
        assert not window.tree.isExpanded(docs_proxy)  # 15 > COLLAPSE_THRESHOLD
        assert window.tree.isExpanded(logs_proxy)  # 1 <= COLLAPSE_THRESHOLD


class TestGrouping:
    def _grouped_model(self, root: Path, mode: GroupMode) -> ResultsModel:
        rels = [f"docs_a/f{i}.pdf" for i in range(10)]
        rels += [f"docs_b/f{i}.pdf" for i in range(10)]
        rels += [f"top{i}.pdf" for i in range(5)]
        entries = _make_entries(root, rels)
        model = ResultsModel(root)
        model.set_result(ScanResult(root=root, entries=entries), load_preset("bitrix").categories)
        model.set_group_mode(mode)
        return model

    def _docs_group_row(self, model: ResultsModel, label_prefix: str) -> int:
        """Номер строки группы внутри категории docs по префиксу метки."""
        docs = model.index(0, 0)
        for row in range(model.rowCount(docs)):
            label = str(model.index(row, 0, docs).data(Qt.ItemDataRole.DisplayRole))
            if label.startswith(label_prefix):
                return row
        raise AssertionError(f"группа {label_prefix!r} не найдена")

    def test_over_threshold_grouped_by_dirs(self, tmp_path: Path) -> None:
        model = self._grouped_model(tmp_path / "site", GroupMode.DIRS)
        docs = model.index(0, 0)
        assert model.rowCount(docs) == 3  # docs_a, docs_b, (корень)
        labels = [str(model.index(r, 0, docs).data(Qt.ItemDataRole.DisplayRole)) for r in range(3)]
        assert any(label.startswith("docs_a") for label in labels)
        assert any(label.startswith("(корень)") for label in labels)

    def test_under_threshold_flat(self, tmp_path: Path) -> None:
        entries = _make_entries(tmp_path / "site", [f"f{i}.pdf" for i in range(6)])
        model = ResultsModel(tmp_path / "site")
        model.set_result(
            ScanResult(root=tmp_path / "site", entries=entries), load_preset("bitrix").categories
        )
        model.set_group_mode(GroupMode.DIRS)
        docs = model.index(0, 0)
        assert model.rowCount(docs) == 6  # <= GROUP_THRESHOLD -> плоско

    def test_group_checkbox_aggregates(self, tmp_path: Path) -> None:
        model = self._grouped_model(tmp_path / "site", GroupMode.DIRS)
        assert model.checked_count() == 25
        docs = model.index(0, 0)
        docs_a_row = self._docs_group_row(model, "docs_a")  # 10 файлов
        docs_a = model.index(docs_a_row, 0, docs)
        model.setData(docs_a, False, Qt.ItemDataRole.CheckStateRole)
        assert model.checked_count() == 15
        assert docs_a.data(Qt.ItemDataRole.CheckStateRole) == Qt.CheckState.Unchecked
        assert docs.data(Qt.ItemDataRole.CheckStateRole) == Qt.CheckState.PartiallyChecked
        checked_rels = {e.path.name for e in model.checked_entries()}
        assert len(checked_rels) == 15

    def test_mode_none_flat(self, tmp_path: Path) -> None:
        model = self._grouped_model(tmp_path / "site", GroupMode.NONE)
        docs = model.index(0, 0)
        assert model.rowCount(docs) == 25

    def test_checked_state_preserved_on_mode_switch(self, tmp_path: Path) -> None:
        model = self._grouped_model(tmp_path / "site", GroupMode.DIRS)
        docs = model.index(0, 0)
        docs_a_row = self._docs_group_row(model, "docs_a")
        model.setData(model.index(docs_a_row, 0, docs), False, Qt.ItemDataRole.CheckStateRole)
        model.set_group_mode(GroupMode.EXTS)
        assert model.checked_count() == 15  # состояние не сброшено

    def test_grouping_combo_persisted_and_applied(
        self, qtbot: object, fake_bitrix_tree: Path
    ) -> None:
        from sanitize.gui.main_window import MainWindow

        window = MainWindow()
        qtbot.addWidget(window)
        window.grouping_combo.setCurrentIndex(2)  # «По расширениям»
        window.path_edit.setText(str(fake_bitrix_tree))
        window.start_scan()
        with qtbot.waitSignal(window.scan_completed, timeout=30000):  # type: ignore[attr-defined]
            pass
        # все категории fake-дерева <= 20 файлов -> группы не строятся, режим применён
        assert window.model.group_mode is GroupMode.EXTS

        window.close()  # closeEvent сохраняет настройки
        window2 = MainWindow()
        qtbot.addWidget(window2)
        assert window2.grouping_combo.currentData() is GroupMode.EXTS


class TestColumnRatios:
    def test_file_column_four_times_wider(self, qtbot: object, fake_bitrix_tree: Path) -> None:
        from sanitize.gui.main_window import MainWindow

        window = MainWindow()
        qtbot.addWidget(window)
        window.resize(900, 700)
        window.show()
        qtbot.wait(100)  # даём layout примениться к viewport дерева
        window._apply_column_ratios()  # явный пересчёт (resizeEvent мог не дойти)
        tree = window.tree
        w0, w1 = tree.columnWidth(0), tree.columnWidth(1)
        assert w1 > 30  # колонки не схлопнулись
        assert abs(w0 - 4 * w1) <= 8  # 4:1:1 с округлением
        assert tree.columnWidth(2) == w1


class TestHelpButtons:
    def test_all_checkboxes_have_help(self, qtbot: object) -> None:
        from sanitize.gui.main_window import _PARAM_HINTS, MainWindow

        window = MainWindow()
        qtbot.addWidget(window)
        buttons = window.help_buttons()
        assert len(buttons) == len(_PARAM_HINTS) == 14
        for button in buttons:
            assert button.text() == "?"
            assert button.toolTip()  # краткий hover-текст

    def test_popup_opens_and_toggles(self, qtbot: object) -> None:
        from sanitize.gui.main_window import MainWindow

        window = MainWindow()
        qtbot.addWidget(window)
        button = window.help_buttons()[0]
        assert not button.popup_visible()
        button.click()
        assert button.popup_visible()
        popup_text = button._popup.text()  # type: ignore[union-attr]
        assert len(popup_text) > 50  # подробный текст, не краткий
        button.click()  # повторный клик закрывает
        assert not button.popup_visible()

    def test_only_one_popup_at_a_time(self, qtbot: object) -> None:
        from sanitize.gui.main_window import MainWindow

        window = MainWindow()
        qtbot.addWidget(window)
        buttons = window.help_buttons()
        first, second = buttons[0], buttons[1]
        first.click()
        assert first.popup_visible()
        second.click()  # клик по другой «?» закрывает первый
        assert not first.popup_visible()
        assert second.popup_visible()
        second.click()
        assert not second.popup_visible()

    def test_browse_opens_home_folder(self, qtbot: object, monkeypatch: pytest.MonkeyPatch) -> None:
        from PySide6.QtWidgets import QFileDialog
        from sanitize.gui.main_window import MainWindow

        captured: dict[str, str] = {}

        def fake_get_existing_directory(parent, caption, directory="", *args, **kwargs):  # type: ignore[no-untyped-def]
            captured["dir"] = directory
            return ""

        monkeypatch.setattr(QFileDialog, "getExistingDirectory", fake_get_existing_directory)
        window = MainWindow()
        qtbot.addWidget(window)
        window.path_edit.setText("/var/www/site")
        window.browse_button.click()
        assert captured["dir"] == str(Path.home())


def test_qapp_offscreen() -> None:
    """Санити: offscreen-платформа доступна и QApplication создаётся."""
    app = QApplication.instance() or QApplication([])
    assert app is not None
    assert threading.current_thread().name == "MainThread"
