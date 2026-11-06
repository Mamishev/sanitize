"""QAbstractItemModel: категории -> группы -> файлы, tri-state чекбоксы (AGENTS.md, разд. 8).

Уровень 1 — категории (счётчик, размер, метка риска), уровень 2 — необязательные
группы (включаются при > GROUP_THRESHOLD файлов в категории; ключ — каталог или
расширение), уровень 3 — файлы (путь, размер, дата). Категория secrets_report
(report_only) показывается, но её элементы не выбираемы. Обработанные файлы
помечаются серым/зачёркнуто.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
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

#: Категория разворачивается по умолчанию, если файлов не больше этого числа.
COLLAPSE_THRESHOLD = 10
#: Категория группируется, если файлов строго больше этого числа.
GROUP_THRESHOLD = 20

_NO_DIR_LABEL = "(корень)"
_NO_EXT_LABEL = "(без расширения)"


class GroupMode(Enum):
    """Признак группировки файлов внутри категории."""

    NONE = "none"
    DIRS = "dirs"
    EXTS = "exts"


def _group_label(rel: str, mode: GroupMode) -> str:
    if mode is GroupMode.DIRS:
        return rel.rsplit("/", 1)[0] if "/" in rel else _NO_DIR_LABEL
    if mode is GroupMode.EXTS:
        dot = rel.rfind(".")
        return rel[dot:].lower() if dot > rel.rfind("/") else _NO_EXT_LABEL
    return ""


class FileNode:
    __slots__ = ("category", "checked", "entry", "parent", "processed", "rel", "row")

    def __init__(
        self,
        entry: FileEntry,
        rel: str,
        category: CategoryNode,
        parent: CategoryNode | GroupNode,
        row: int,
    ) -> None:
        self.entry = entry
        self.rel = rel
        self.category = category
        self.parent = parent
        self.row = row
        self.checked = False
        self.processed = False


class GroupNode:
    """Виртуальный узел-группа (каталог или расширение) внутри категории."""

    __slots__ = ("files", "label", "parent", "row")

    def __init__(self, label: str, files: list[FileNode], parent: CategoryNode, row: int) -> None:
        self.label = label
        self.files = files
        self.parent = parent
        self.row = row

    @property
    def size(self) -> int:
        return sum(f.entry.size for f in self.files)

    def check_state(self) -> Qt.CheckState:
        checked = sum(1 for f in self.files if f.checked)
        if checked == 0:
            return Qt.CheckState.Unchecked
        if checked == len(self.files):
            return Qt.CheckState.Checked
        return Qt.CheckState.PartiallyChecked


class CategoryNode:
    __slots__ = ("category", "files", "groups", "row", "selectable")

    def __init__(self, category: Category, selectable: bool, row: int) -> None:
        self.category = category
        self.selectable = selectable
        self.row = row
        self.files: list[FileNode] = []  # все файлы категории
        self.groups: list[GroupNode] = []  # пусто -> плоский список files

    @property
    def children(self) -> list[Any]:
        return self.groups if self.groups else self.files

    def check_state(self) -> Qt.CheckState:
        if not self.selectable or not self.files:
            return Qt.CheckState.Unchecked
        checked = sum(1 for f in self.files if f.checked)
        if checked == 0:
            return Qt.CheckState.Unchecked
        if checked == len(self.files):
            return Qt.CheckState.Checked
        return Qt.CheckState.PartiallyChecked


class ResultsModel(QAbstractItemModel):
    """Модель результатов сканирования с опциональной группировкой."""

    counts_changed = Signal()

    def __init__(self, root: Path, parent=None) -> None:
        super().__init__(parent)
        self._root = root
        self._categories: list[CategoryNode] = []
        self._group_mode = GroupMode.NONE
        self._last_result: ScanResult | None = None
        self._last_categories: list[Category] = []

    # --- наполнение ---

    def set_result(self, result: ScanResult, categories: list[Category]) -> None:
        """Заполняет дерево; группировка — по текущему group_mode."""
        self._last_result = result
        self._last_categories = list(categories)
        self._rebuild()

    def set_group_mode(self, mode: GroupMode) -> None:
        """Меняет признак группировки и перестраивает дерево (чекбоксы сохраняются)."""
        if mode is self._group_mode and self._categories:
            return
        self._group_mode = mode
        self._rebuild()

    @property
    def group_mode(self) -> GroupMode:
        return self._group_mode

    def _rebuild(self) -> None:
        if self._last_result is None:
            return
        state = self._snapshot_state()
        self.beginResetModel()
        self._build_nodes(self._last_result, self._last_categories)
        self.endResetModel()
        self._restore_state(state)
        self.counts_changed.emit()

    def _snapshot_state(self) -> dict[Path, tuple[bool, bool]]:
        state: dict[Path, tuple[bool, bool]] = {}
        for node in self._categories:
            for f in node.files:
                state[f.entry.path] = (f.checked, f.processed)
        return state

    def _restore_state(self, state: dict[Path, tuple[bool, bool]]) -> None:
        for node in self._categories:
            if not node.selectable:
                continue
            for f in node.files:
                saved = state.get(f.entry.path)
                if saved is None:
                    f.checked = True
                else:
                    f.checked, f.processed = saved

    def _build_nodes(self, result: ScanResult, categories: list[Category]) -> None:
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
                node.files.append(FileNode(entry, rel, node, node, i))
            self._split_groups(node)
            self._categories.append(node)

    def _split_groups(self, node: CategoryNode) -> None:
        """Раскладывает файлы категории по группам, если их > GROUP_THRESHOLD."""
        if self._group_mode is GroupMode.NONE or len(node.files) <= GROUP_THRESHOLD:
            node.groups = []
            for i, f in enumerate(node.files):
                f.parent = node
                f.row = i
            return
        buckets: dict[str, list[FileNode]] = {}
        for f in node.files:
            buckets.setdefault(_group_label(f.rel, self._group_mode), []).append(f)
        node.groups = []
        for row, (label, files) in enumerate(sorted(buckets.items())):
            node.groups.append(GroupNode(label, files, node, row))
            for i, f in enumerate(files):
                f.parent = node.groups[-1]
                f.row = i

    def clear(self) -> None:
        """Очищает дерево (перед новым сканированием)."""
        self.beginResetModel()
        self._categories = []
        self._last_result = None
        self.endResetModel()
        self.counts_changed.emit()

    def is_empty(self) -> bool:
        return not self._categories

    def category_file_count(self, row: int) -> int:
        """Число файлов в категории верхнего уровня (для правил свёртывания)."""
        if 0 <= row < len(self._categories):
            return len(self._categories[row].files)
        return 0

    # --- служебное ---

    def _node_at(self, index) -> Any:  # type: ignore[no-untyped-def]
        return index.internalPointer()

    def _category_at(self, index) -> CategoryNode | None:  # type: ignore[no-untyped-def]
        ptr = self._node_at(index)
        return ptr if isinstance(ptr, CategoryNode) else None

    def _group_at(self, index) -> GroupNode | None:  # type: ignore[no-untyped-def]
        ptr = self._node_at(index)
        return ptr if isinstance(ptr, GroupNode) else None

    def _file_at(self, index) -> FileNode | None:  # type: ignore[no-untyped-def]
        ptr = self._node_at(index)
        return ptr if isinstance(ptr, FileNode) else None

    # --- QAbstractItemModel ---

    def index(self, row: int, column: int, parent=None) -> Any:  # type: ignore[no-untyped-def]
        if parent is None:
            parent = QModelIndex()
        if not parent.isValid():
            if 0 <= row < len(self._categories):
                return self.createIndex(row, column, self._categories[row])
            return QModelIndex()
        node = self._node_at(parent)
        children: list[Any] = []
        if isinstance(node, CategoryNode):
            children = node.children
        elif isinstance(node, GroupNode):
            children = node.files
        if 0 <= row < len(children):
            return self.createIndex(row, column, children[row])
        return QModelIndex()

    def parent(self, child) -> Any:  # type: ignore[no-untyped-def]
        file = self._file_at(child)
        if file is not None:
            return self.createIndex(file.parent.row, 0, file.parent)
        group = self._group_at(child)
        if group is not None:
            return self.createIndex(group.parent.row, 0, group.parent)
        return QModelIndex()

    def rowCount(self, parent=None) -> int:  # type: ignore[no-untyped-def]
        if parent is None or not parent.isValid():
            return len(self._categories)
        node = self._node_at(parent)
        if isinstance(node, CategoryNode):
            return len(node.children)
        if isinstance(node, GroupNode):
            return len(node.files)
        return 0

    def columnCount(self, parent=None) -> int:  # type: ignore[no-untyped-def]
        return _COLS

    def data(self, index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # type: ignore[no-untyped-def]
        column = index.column()
        file = self._file_at(index)
        if file is not None:
            return self._file_data(file, column, role)
        group = self._group_at(index)
        if group is not None:
            return self._group_data(group, column, role)
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
        if role == Qt.ItemDataRole.CheckStateRole and file.category.selectable:
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

    def _group_data(self, group: GroupNode, column: int, role: int) -> Any:
        selectable = group.parent.selectable
        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return f"{group.label} ({len(group.files)}, {human_size(group.size)})"
            return None
        if role == Qt.ItemDataRole.CheckStateRole and selectable:
            return group.check_state()
        if role == Qt.ItemDataRole.FontRole:
            font = QFont()
            font.setBold(True)
            return font
        if role == SORT_ROLE:
            if column == 0:
                return group.label.casefold()
            if column == 1:
                return group.size
            files = group.files
            return max((f.entry.mtime for f in files), default=0.0)
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
            return base | (Qt.ItemFlag.ItemIsUserCheckable if file.category.selectable else base)
        group = self._group_at(index)
        if group is not None:
            return base | (Qt.ItemFlag.ItemIsUserCheckable if group.parent.selectable else base)
        category = self._category_at(index)
        if category is not None and category.selectable:
            return base | Qt.ItemFlag.ItemIsUserCheckable
        return base

    def setData(self, index, value, role: int = Qt.ItemDataRole.EditRole) -> bool:  # type: ignore[no-untyped-def]
        if role != Qt.ItemDataRole.CheckStateRole:
            return False
        new_state = bool(value)
        file = self._file_at(index)
        if file is not None:
            if not file.category.selectable:
                return False
            file.checked = new_state
            self._emit_row(index)
            self._emit_row(self.index(file.parent.row, 0, self.parent(index)))
            self.counts_changed.emit()
            return True
        group = self._group_at(index)
        if group is not None:
            if not group.parent.selectable:
                return False
            for f in group.files:
                f.checked = new_state
            self._emit_children(index, len(group.files))
            self._emit_row(index)
            self._emit_row(self.index(group.parent.row, 0))
            self.counts_changed.emit()
            return True
        category = self._category_at(index)
        if category is not None and category.selectable:
            for f in category.files:
                f.checked = new_state
            self._emit_children(index, len(category.children))
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
        parent_index = self.parent(index)
        self.dataChanged.emit(
            self.index(index.row(), 0, parent_index),
            self.index(index.row(), _COLS - 1, parent_index),
            [
                Qt.ItemDataRole.CheckStateRole,
                Qt.ItemDataRole.FontRole,
                Qt.ItemDataRole.ForegroundRole,
            ],
        )

    def _emit_children(self, index, count: int) -> None:
        if count:
            self.dataChanged.emit(
                self.index(0, 0, index),
                self.index(count - 1, _COLS - 1, index),
                [Qt.ItemDataRole.CheckStateRole],
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
        bottom_right = self.index(max(len(self._categories) - 1, 0), _COLS - 1)
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
