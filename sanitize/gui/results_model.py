"""QAbstractItemModel: категории -> файлы, tri-state чекбоксы, фильтр (AGENTS.md, разд. 8).

Уровень 1 — категории (счётчик, размер, метка риска), уровень 2 — файлы
(относительный путь, размер, дата). Категория secrets_report (report_only)
показывается, но её элементы не выбираемы для действий (нет чекбокса и
ItemIsUserCheckable). Обработанные файлы помечаются серым/зачёркнуто.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QAbstractItemModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
    Signal,
)
from PySide6.QtGui import QBrush, QColor, QFont

from sanitize.core.models import Category, FileEntry, ScanResult
from sanitize.core.report import human_size

ENTRY_ROLE = Qt.ItemDataRole.UserRole
SORT_ROLE = Qt.ItemDataRole.UserRole + 1

_COLS = 3
_GRAY = QColor(130, 130, 130)


class FileNode:
    __slots__ = ("checked", "entry", "parent", "processed", "rel", "row")

    def __init__(self, entry: FileEntry, rel: str, parent: CategoryNode, row: int) -> None:
        self.entry = entry
        self.rel = rel
        self.parent = parent
        self.row = row
        self.checked = False
        self.processed = False


class CategoryNode:
    __slots__ = ("category", "files", "row", "selectable")

    def __init__(self, category: Category, selectable: bool, row: int) -> None:
        self.category = category
        self.selectable = selectable
        self.row = row
        self.files: list[FileNode] = []

    @property
    def checked(self) -> bool:
        return self.selectable and all(f.checked for f in self.files)

    def check_state(self) -> Qt.CheckState:
        if not self.selectable:
            return Qt.CheckState.Unchecked
        if not self.files:
            return Qt.CheckState.Unchecked
        checked = sum(1 for f in self.files if f.checked)
        if checked == 0:
            return Qt.CheckState.Unchecked
        if checked == len(self.files):
            return Qt.CheckState.Checked
        return Qt.CheckState.PartiallyChecked


class ResultsModel(QAbstractItemModel):
    """Модель результатов сканирования."""

    counts_changed = Signal()

    def __init__(self, root: Path, parent=None) -> None:
        super().__init__(parent)
        self._root = root
        self._categories: list[CategoryNode] = []

    # --- наполнение ---

    def set_result(self, result: ScanResult, categories: list[Category]) -> None:
        """Заполняет дерево: категории в порядке профиля, файлы по категориям."""
        self.beginResetModel()
        grouped = result.files_by_category()
        by_id = {cat.id: cat for cat in categories}
        if "extra" in grouped and "extra" not in by_id:
            by_id["extra"] = Category(id="extra", title="Доп. расширения", extensions=frozenset())
        order = {cat.id: position for position, cat in enumerate(categories)}
        self._categories = []
        for row, category_id in enumerate(
            sorted(grouped, key=lambda cid: order.get(cid, len(order)))
        ):
            cat = by_id.get(category_id)
            if cat is None:
                continue
            node = CategoryNode(cat, selectable=not cat.report_only, row=row)
            for i, entry in enumerate(grouped[category_id]):
                try:
                    rel = entry.path.relative_to(self._root).as_posix()
                except ValueError:
                    rel = entry.path.name
                node.files.append(FileNode(entry, rel, node, i))
            self._categories.append(node)
        for node in self._categories:
            if node.selectable:
                for f in node.files:
                    f.checked = True
        self.endResetModel()
        self.counts_changed.emit()

    def clear(self) -> None:
        """Очищает дерево (перед новым сканированием)."""
        self.beginResetModel()
        self._categories = []
        self.endResetModel()
        self.counts_changed.emit()

    def is_empty(self) -> bool:
        return not self._categories

    # --- служебное ---

    def _category_at(self, index) -> CategoryNode | None:  # type: ignore[no-untyped-def]
        ptr = index.internalPointer()
        return ptr if isinstance(ptr, CategoryNode) else None

    def _file_at(self, index) -> FileNode | None:  # type: ignore[no-untyped-def]
        ptr = index.internalPointer()
        return ptr if isinstance(ptr, FileNode) else None

    # --- QAbstractItemModel ---

    def index(self, row: int, column: int, parent=None) -> Any:  # type: ignore[no-untyped-def]
        if parent is None:
            parent = QModelIndex()
        if not parent.isValid():
            if 0 <= row < len(self._categories):
                return self.createIndex(row, column, self._categories[row])
            return QModelIndex()
        category = self._category_at(parent)
        if category is not None and 0 <= row < len(category.files):
            return self.createIndex(row, column, category.files[row])
        return QModelIndex()

    def parent(self, child) -> Any:  # type: ignore[no-untyped-def]
        file = self._file_at(child)
        if file is not None:
            return self.createIndex(file.parent.row, 0, file.parent)
        return QModelIndex()

    def rowCount(self, parent=None) -> int:  # type: ignore[no-untyped-def]
        if parent is None or not parent.isValid():
            return len(self._categories)
        category = self._category_at(parent)
        return len(category.files) if category is not None else 0

    def columnCount(self, parent=None) -> int:  # type: ignore[no-untyped-def]
        return _COLS

    def data(self, index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # type: ignore[no-untyped-def]
        file = self._file_at(index)
        column = index.column()
        if file is not None:
            return self._file_data(file, column, role)
        category = self._category_at(index)
        if category is not None:
            return self._category_data(category, column, role)
        return None

    def _file_data(self, file: FileNode, column: int, role: int) -> Any:
        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                label = file.rel
                if file.entry.content_hits:
                    hits = ", ".join(
                        f"{kind}: {count}"
                        for kind, count in sorted(file.entry.content_hits.items())
                    )
                    label += f"  [ПДн: {hits}]"
                return label
            if column == 1:
                return human_size(file.entry.size)
            if column == 2:
                return datetime.fromtimestamp(file.entry.mtime).strftime("%Y-%m-%d")
            return None
        if role == Qt.ItemDataRole.CheckStateRole and file.parent.selectable:
            return Qt.CheckState.Checked if file.checked else Qt.CheckState.Unchecked
        if role == Qt.ItemDataRole.UserRole:
            return file.entry
        if role == SORT_ROLE:
            if column == 0:
                return file.rel.casefold()
            if column == 1:
                return file.entry.size
            return file.entry.mtime
        if role == Qt.ItemDataRole.FontRole and file.processed:
            font = QFont()
            font.setStrikeOut(True)
            return font
        if role == Qt.ItemDataRole.ForegroundRole and file.processed:
            return QBrush(_GRAY)
        return None

    def _category_data(self, node: CategoryNode, column: int, role: int) -> Any:
        count = len(node.files)
        size = sum(f.entry.size for f in node.files)
        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                label = f"{node.category.title} ({count}, {human_size(size)})"
                if node.category.report_only:
                    label += " — только отчёт"
                elif node.category.risk == "high":
                    label += "  ⚠️ высокий риск"
                return label
            return None
        if role == Qt.ItemDataRole.CheckStateRole:
            return node.check_state()
        if role == Qt.ItemDataRole.FontRole:
            font = QFont()
            font.setBold(True)
            return font
        if role == Qt.ItemDataRole.ForegroundRole and node.category.risk == "high":
            return QBrush(QColor(176, 32, 32))
        if role == SORT_ROLE and column == 0:
            return node.category.title.casefold()
        return None

    def flags(self, index) -> Qt.ItemFlag:  # type: ignore[no-untyped-def]
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        file = self._file_at(index)
        if file is not None:
            return base | (Qt.ItemFlag.ItemIsUserCheckable if file.parent.selectable else base)
        category = self._category_at(index)
        if category is not None and category.selectable:
            return base | Qt.ItemFlag.ItemIsUserCheckable
        return base

    def setData(self, index, value, role: int = Qt.ItemDataRole.EditRole) -> bool:  # type: ignore[no-untyped-def]
        if role != Qt.ItemDataRole.CheckStateRole:
            return False
        file = self._file_at(index)
        if file is not None and file.parent.selectable:
            file.checked = bool(value)
            self._emit_row(index)
            self._emit_row(self.index(file.parent.row, 0))
            self.counts_changed.emit()
            return True
        category = self._category_at(index)
        if category is not None and category.selectable:
            new_state = bool(value)
            first = self.index(0, 0, index)
            last = self.index(len(category.files) - 1, _COLS - 1, index)
            for f in category.files:
                f.checked = new_state
            if len(category.files):
                self.dataChanged.emit(first, last, [Qt.ItemDataRole.CheckStateRole])
            self._emit_row(index)
            self.counts_changed.emit()
            return True
        return False

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:  # type: ignore[no-untyped-def]
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return ("Файл", "Размер", "Дата")[section]
        return None

    # --- выборки и пометки ---

    def _emit_row(self, index) -> None:  # type: ignore[no-untyped-def]
        self.dataChanged.emit(
            self.index(index.row(), 0, self.parent(index)),
            self.index(index.row(), _COLS - 1, self.parent(index)),
            [Qt.ItemDataRole.CheckStateRole, Qt.ItemDataRole.FontRole],
        )

    def checked_entries(self) -> list[FileEntry]:
        """Все файлы с включённым чекбоксом (report_only сюда не попадают)."""
        return [
            f.entry for node in self._categories if node.selectable for f in node.files if f.checked
        ]

    def checked_count(self) -> int:
        return sum(
            1 for node in self._categories if node.selectable for f in node.files if f.checked
        )

    def mark_processed(self, processed_paths: set[Path]) -> None:
        """Помечает обработанные файлы серым/зачёркнуто (не удаляет из дерева)."""
        for node in self._categories:
            for f in node.files:
                if f.entry.path in processed_paths:
                    f.processed = True
                    f.checked = False
        top_left = self.index(0, 0)
        bottom_right = self.index(len(self._categories) - 1, _COLS - 1)
        self.dataChanged.emit(
            top_left,
            bottom_right,
            [
                Qt.ItemDataRole.CheckStateRole,
                Qt.ItemDataRole.FontRole,
                Qt.ItemDataRole.ForegroundRole,
            ],
        )
        self.counts_changed.emit()


class ResultsFilterProxy(QSortFilterProxyModel):
    """Рекурсивная фильтрация по подстроке пути + сортировка по SORT_ROLE."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._text = ""
        self.setSortRole(SORT_ROLE)
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def set_filter_text(self, text: str) -> None:
        self._text = text.casefold()
        self.invalidate()

    def filterAcceptsRow(self, source_row: int, source_parent) -> bool:  # type: ignore[no-untyped-def]
        if not self._text:
            return True
        model = self.sourceModel()
        index = model.index(source_row, 0, source_parent)
        return self._accept(index)

    def _accept(self, index) -> bool:  # type: ignore[no-untyped-def]
        text = str(index.data(Qt.ItemDataRole.DisplayRole) or "").casefold()
        if self._text in text:
            return True
        model = self.sourceModel()
        return any(self._accept(model.index(r, 0, index)) for r in range(model.rowCount(index)))
