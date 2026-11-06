"""Главное окно GUI: макет из AGENTS.md, раздел 8.

Единственное окно, четыре блока сверху вниз: параметры поиска -> прогресс ->
результаты -> действия. Сканирование и действия — в QThread (gui/worker.py),
UI не блокируется. Кнопка «Стоп» ставит cancel_event.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

from PySide6.QtCore import QPoint, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QToolButton,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from sanitize.core.models import (
    Action,
    ActionResult,
    FileEntry,
    ScanOptions,
    ScanResult,
)
from sanitize.core.presets import Preset, load_preset
from sanitize.core.report import build_report, human_size, write_report
from sanitize.core.safety import (
    SafetyError,
    check_quarantine_dir,
    check_root,
    has_project_markers,
)
from sanitize.gui.dialogs import (
    ConfirmDialog,
    SummaryDialog,
    ask_report_path,
    show_sudo_hint,
)
from sanitize.gui.results_model import (
    COLLAPSE_THRESHOLD,
    ENTRY_ROLE,
    GroupMode,
    ResultsFilterProxy,
    ResultsModel,
)
from sanitize.gui.settings import Settings
from sanitize.gui.worker import ActionWorker, CountWorker, ScanWorker

logger = logging.getLogger(__name__)

_CATEGORY_LABELS: dict[str, str] = {
    "docs": "Документы",
    "sheets": "Таблицы/экспорт",
    "slides": "Презентации",
    "archives": "Архивы",
    "keys": "Подписи/ключи",
    "backups": "Бэкапы/дампы",
    "mail": "Почта/контакты",
    "media": "Аудио/видео",
    "logs": "Логи и кэш",
}

#: (краткий hover-тултип, подробный текст попапа «?»)
_PARAM_HINTS: dict[str, tuple[str, str]] = {
    "docs": (
        "Документы: PDF/Word и подобное",
        "Документы офисных форматов (pdf, doc(x), rtf, odt, сканы). Чаще всего "
        "именно здесь живут договоры, резюме, удостоверения и прочие ПДн. "
        "Файлы .txt/.md учитываются только внутри upload/.",
    ),
    "sheets": (
        "Таблицы и выгрузки",
        "Табличные форматы и экспорт (xls(x), csv, tsv, xml, json, yaml): "
        "реестры, выгрузки из 1С/CRM — высокий риск ПДн. xml/json/yaml "
        "учитываются только внутри upload/.",
    ),
    "slides": (
        "Презентации",
        "Презентации (ppt(x), pps, odp). Внутренние материалы, могут содержать "
        "персональные и коммерческие данные.",
    ),
    "archives": (
        "Архивы zip/rar/tar.gz",
        "Архивы и образы (zip, rar, 7z, tar.gz, iso, dmg). Часто содержат копии "
        "документов, дампы и резервные копии — высокий риск.",
    ),
    "keys": (
        "Сертификаты и приватные ключи",
        "Подписи и ключи (pem, p12, pfx, gpg, id_rsa и др.). Утечка приватного "
        "ключа = компрометация сервера или переписки. Всегда высокий риск.",
    ),
    "backups": (
        "Бэкапы и дампы БД",
        "Резервные копии и дампы (sql, bak, sqlite и др.) плюс всё содержимое "
        "bitrix/backup/. Полные копии сайта с ПДн — высокий риск.",
    ),
    "mail": (
        "Письма и контакты",
        "Почтовые форматы и контакты (eml, msg, pst, vcf, ics). Переписка и "
        "контактные данные — высокий риск.",
    ),
    "media": (
        "Аудио/видео: возможны записи звонков",
        "Медиафайлы (mp3, mp4, mkv и др.). Могут оказаться записями звонков и "
        "встреч. По умолчанию выключено — обычно это просто контент сайта.",
    ),
    "logs": (
        "Логи, кэш, временные файлы",
        "Логи и мусор (log, tmp, swp) плюс служебные каталоги bitrix/cache, "
        "bitrix/tmp, upload/tmp, bitrix/html_pages. Логи часто содержат токены "
        "и ПДн пользователей.",
    ),
    "exclude_bitrix_dirs": (
        "Не трогать служебные каталоги CMS",
        "Исключить из обхода bitrix/modules, bitrix/components, bitrix/templates, "
        "bitrix/js|css|images|fonts и др., vendor/, node_modules/, "
        "upload/resize_cache. Код и ресурсы CMS не содержат ПДн, а их изменение "
        "ломает сайт. Снимайте галочку только осознанно.",
    ),
    "magic": (
        "Определение типа по содержимому",
        "Для файлов без расширения (или нераспознанных) определять тип по "
        "сигнатуре через libmagic: находит PDF/архивы, замаскированные под "
        "безымянные файлы. Требует extras magic (python-magic).",
    ),
    "deep_scan": (
        "Поиск ПДн внутри файлов",
        "Искать в содержимом текстовых файлов и docx/xlsx: e-mail, телефоны РФ, "
        "паспорта, СНИЛС и ИНН (с контрольными суммами), номера карт (алгоритм "
        "Луна). Замедляет сканирование; счётчики показываются у файлов и в отчёте.",
    ),
    "symlinks": (
        "Заходить в каталоги-ссылки",
        "Следовать по симлинкам на каталоги. Риск: выход за пределы корня "
        "(ссылка на /etc) и зацикливание. По умолчанию выключено; файлы-симлинки "
        "не изменяются никогда.",
    ),
    "hidden": (
        "Учитывать скрытые файлы (.env и др.)",
        "Файлы, начинающиеся с точки: .env, .htpasswd, .my.cnf — там живут "
        "секреты. По умолчанию скрыты: работа с ними — отдельное решение. "
        "bitrix/.settings.php тоже скрытый — включите, чтобы увидеть его в отчёте.",
    ),
}

_GROUP_MODE_ITEMS: list[tuple[str, GroupMode]] = [
    ("Нет", GroupMode.NONE),
    ("По каталогам", GroupMode.DIRS),
    ("По расширениям", GroupMode.EXTS),
]


class HelpPopup(QLabel):
    """Немодальное окно-подсказка: закрывается кликом, Esc или повторным «?»."""

    def __init__(self, text: str, anchor: QPoint) -> None:
        super().__init__(None, Qt.WindowType.ToolTip | Qt.WindowType.FramelessWindowHint)
        self.setWordWrap(True)
        self.setMaximumWidth(440)
        self.setText(text)
        self.setStyleSheet(
            "QLabel { background: #fffbe6; color: #333333;"
            " border: 1px solid #b0a871; border-radius: 4px; padding: 8px; }"
        )
        self.adjustSize()
        screen = self.screen() or QGuiApplication.primaryScreen()
        available = screen.availableGeometry() if screen is not None else None
        x = anchor.x() + 12
        y = anchor.y() + 18
        if available is not None:
            x = min(x, available.right() - self.width() - 8)
            y = min(y, available.bottom() - self.height() - 8)
        self.move(max(x, 8), max(y, 8))

    def mousePressEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        self.close()

    def keyPressEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        if event.key() == Qt.Key.Key_Escape:
            self.close()
        super().keyPressEvent(event)


class HelpButton(QToolButton):
    """Кнопка «?» с кликабельной подсказкой (подробный текст — в попапе).

    Открытым может быть только один попап: клик по другой кнопке «?»
    закрывает предыдущий.
    """

    _instances: ClassVar[list[HelpButton]] = []

    def __init__(self, long_text: str, short_text: str = "", parent=None) -> None:  # type: ignore[no-untyped-def]
        super().__init__(parent)
        self._long_text = long_text
        self._popup: HelpPopup | None = None
        self.setText("?")
        self.setFixedSize(18, 18)
        if short_text:
            self.setToolTip(short_text)
        HelpButton._instances.append(self)
        self.clicked.connect(self._toggle)

    def _toggle(self) -> None:
        for other in HelpButton._instances:
            if other is not self:
                other.close_popup()
        if self._popup is not None and self._popup.isVisible():
            self._popup.close()
            self._popup = None
            return
        self._popup = HelpPopup(self._long_text, self.mapToGlobal(QPoint(0, 0)))
        self._popup.show()

    def popup_visible(self) -> bool:
        return self._popup is not None and self._popup.isVisible()

    def close_popup(self) -> None:
        if self._popup is not None:
            self._popup.close()
            self._popup = None


class ElidedLabel(QLabel):
    """QLabel с обрезкой текста слева при нехватке ширины."""

    def __init__(self, text: str = "", parent=None) -> None:  # type: ignore[no-untyped-def]
        super().__init__(text, parent)
        self._full = text

    def set_text(self, text: str) -> None:
        self._full = text
        self._elide()

    def resizeEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        super().resizeEvent(event)
        self._elide()

    def _elide(self) -> None:
        metrics = self.fontMetrics()
        self.setText(metrics.elidedText(self._full, Qt.TextElideMode.ElideLeft, self.width()))


class MainWindow(QMainWindow):
    """Единственное окно приложения."""

    #: испускается после завершения сканирования (для тестов)
    scan_completed = Signal(object)

    def __init__(self, parent=None) -> None:  # type: ignore[no-untyped-def]
        super().__init__(parent)
        self.setWindowTitle("sanitize — обезвреживание файлов с ПДн")
        self.resize(960, 720)

        self._settings = Settings()
        self._session_excludes: list[str] = []
        self._scan_worker: ScanWorker | None = None
        self._count_worker: CountWorker | None = None
        self._action_worker: ActionWorker | None = None
        self._last_result: ScanResult | None = None
        self._last_options: ScanOptions | None = None
        self._last_preset: Preset | None = None
        self._last_actions: list[ActionResult] = []
        self._scan_started: datetime | None = None
        self._markers_warning: str | None = None

        central = QWidget(self)
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)

        outer.addWidget(self._build_params_group())
        outer.addWidget(self._build_progress_group())
        outer.addWidget(self._build_results_group())
        outer.addWidget(self._build_action_group())

        self._bind_hotkeys()
        self._restore_settings()
        self._update_buttons()

    # ---------- построение UI ----------

    def _build_params_group(self) -> QGroupBox:
        group = QGroupBox("Параметры поиска", self)
        layout = QVBoxLayout(group)

        path_row = QHBoxLayout()
        path_row.addWidget(QLabel("Путь:", group))
        self.path_edit = QLineEdit(group)
        self.path_edit.setPlaceholderText("/var/www/site")
        path_row.addWidget(self.path_edit, 1)
        self.browse_button = QPushButton("Обзор…", group)
        self.find_button = QPushButton("Найти", group)
        self.find_button.setDefault(True)
        self.stop_button = QPushButton("Стоп", group)
        path_row.addWidget(self.browse_button)
        path_row.addWidget(self.find_button)
        path_row.addWidget(self.stop_button)
        layout.addLayout(path_row)

        preset_row = QHBoxLayout()
        preset_row.addWidget(QLabel("Профиль:", group))
        self.preset_bitrix = QRadioButton("Битрикс", group)
        self.preset_generic = QRadioButton("Общий", group)
        self.preset_bitrix.setChecked(True)
        preset_group = QButtonGroup(group)
        preset_group.addButton(self.preset_bitrix)
        preset_group.addButton(self.preset_generic)
        preset_row.addWidget(self.preset_bitrix)
        preset_row.addWidget(self.preset_generic)
        preset_row.addStretch(1)
        layout.addLayout(preset_row)

        grid = QGridLayout()
        self.category_checks: dict[str, QCheckBox] = {}
        default_off = {"media"}
        for position, (category_id, label) in enumerate(_CATEGORY_LABELS.items()):
            checkbox = QCheckBox(label, group)
            checkbox.setChecked(category_id not in default_off)
            self.category_checks[category_id] = checkbox
            grid.addWidget(
                self._with_help(checkbox, category_id, group), position // 4, position % 4
            )
        layout.addLayout(grid)

        flags_grid = QGridLayout()
        self.exclude_bitrix_dirs = QCheckBox("Исключить служебные каталоги Битрикс", group)
        self.exclude_bitrix_dirs.setChecked(True)
        self.magic_check = QCheckBox("Проверять по сигнатуре (magic)", group)
        self.deep_scan_check = QCheckBox("Глубокий поиск ПДн", group)
        self.symlinks_check = QCheckBox("Следовать по симлинкам", group)
        self.hidden_check = QCheckBox("Скрытые файлы", group)
        flags_grid.addWidget(
            self._with_help(self.exclude_bitrix_dirs, "exclude_bitrix_dirs", group), 0, 0, 1, 2
        )
        flags_grid.addWidget(self._with_help(self.magic_check, "magic", group), 0, 2)
        flags_grid.addWidget(self._with_help(self.deep_scan_check, "deep_scan", group), 0, 3)
        flags_grid.addWidget(self._with_help(self.symlinks_check, "symlinks", group), 1, 0)
        flags_grid.addWidget(self._with_help(self.hidden_check, "hidden", group), 1, 1)
        layout.addLayout(flags_grid)

        self.browse_button.clicked.connect(self._browse)
        self.find_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_all)
        self.preset_bitrix.toggled.connect(self._preset_changed)
        return group

    def _with_help(self, checkbox: QCheckBox, hint_key: str, group: QWidget) -> QWidget:
        """Чекбокс + кнопка «?» с кликабельной подробной подсказкой."""
        container = QWidget(group)
        row = QHBoxLayout(container)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(4)
        row.addWidget(checkbox)
        short_text, long_text = _PARAM_HINTS[hint_key]
        checkbox.setToolTip(short_text)
        row.addWidget(HelpButton(long_text, short_text, container))
        row.addStretch(1)
        return container

    def help_buttons(self) -> list[HelpButton]:
        """Все кнопки «?» блока параметров (для тестов и закрытия попапов)."""
        return self.findChildren(HelpButton)

    def _build_progress_group(self) -> QGroupBox:
        group = QGroupBox("Прогресс", self)
        layout = QVBoxLayout(group)
        self.progress_bar = QProgressBar(group)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.current_path_label = ElidedLabel("", group)
        self.summary_label = QLabel("Найдено: — · Пропущено: —", group)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.current_path_label)
        layout.addWidget(self.summary_label)
        return group

    def _build_results_group(self) -> QGroupBox:
        group = QGroupBox("Результаты", self)
        layout = QVBoxLayout(group)
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Фильтр:", group))
        self.filter_edit = QLineEdit(group)
        self.filter_edit.setClearButtonEnabled(True)
        filter_row.addWidget(self.filter_edit, 1)
        filter_row.addWidget(QLabel("Группировка:", group))
        self.grouping_combo = QComboBox(group)
        for label_text, mode in _GROUP_MODE_ITEMS:
            self.grouping_combo.addItem(label_text, mode)
        self.grouping_combo.setCurrentIndex(1)  # по умолчанию «По каталогам»
        filter_row.addWidget(self.grouping_combo)
        self.collapse_button = QPushButton("Свернуть всё", group)
        filter_row.addWidget(self.collapse_button)
        layout.addLayout(filter_row)

        self.model = ResultsModel(Path("/"), self)
        self.proxy = ResultsFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.tree = QTreeView(group)
        self.tree.setModel(self.proxy)
        self.tree.setUniformRowHeights(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.header().setStretchLastSection(False)
        layout.addWidget(self.tree)

        self.filter_edit.textChanged.connect(self.proxy.set_filter_text)
        self.collapse_button.clicked.connect(self.tree.collapseAll)
        self.grouping_combo.currentIndexChanged.connect(self._on_grouping_changed)
        self.model.counts_changed.connect(self._update_buttons)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._context_menu)
        return group

    def _build_action_group(self) -> QGroupBox:
        group = QGroupBox("Действие", self)
        layout = QVBoxLayout(group)

        radios_row = QHBoxLayout()
        self.zero_radio = QRadioButton("Обнулить", group)
        self.zero_radio.setChecked(True)
        self.delete_radio = QRadioButton("Удалить (--delete)", group)
        self.quarantine_radio = QRadioButton("Карантин →", group)
        action_group = QButtonGroup(group)
        for radio in (self.zero_radio, self.delete_radio, self.quarantine_radio):
            action_group.addButton(radio)
            radios_row.addWidget(radio)
        self.quarantine_dir_edit = QLineEdit(group)
        self.quarantine_dir_edit.setPlaceholderText("/var/quarantine (вне корня)")
        self.quarantine_dir_edit.setEnabled(False)
        self.quarantine_browse = QPushButton("…", group)
        self.quarantine_browse.setEnabled(False)
        radios_row.addWidget(self.quarantine_dir_edit, 1)
        radios_row.addWidget(self.quarantine_browse)
        radios_row.addStretch(0)
        layout.addLayout(radios_row)

        self.keep_attrs_check = QCheckBox("Сохранять владельца/права/mtime", group)
        self.keep_attrs_check.setChecked(True)
        self.keep_attrs_check.setEnabled(False)
        self.keep_attrs_check.setToolTip("Атрибуты сохраняются всегда (гарантия ядра)")
        layout.addWidget(self.keep_attrs_check)

        buttons_row = QHBoxLayout()
        self.save_report_button = QPushButton("Сохранить отчёт…", group)
        self.run_button = QPushButton("Выполнить для выбранных", group)
        self.run_button.setDefault(False)
        buttons_row.addWidget(self.save_report_button)
        buttons_row.addStretch(1)
        buttons_row.addWidget(self.run_button)
        layout.addLayout(buttons_row)

        self.save_report_button.clicked.connect(self._save_report)
        self.run_button.clicked.connect(self._run_action)
        self.quarantine_radio.toggled.connect(self.quarantine_dir_edit.setEnabled)
        self.quarantine_radio.toggled.connect(self.quarantine_browse.setEnabled)
        self.quarantine_browse.clicked.connect(self._browse_quarantine)
        return group

    def _browse_quarantine(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Каталог карантина (вне корня)", self.quarantine_dir_edit.text() or "/"
        )
        if chosen:
            self.quarantine_dir_edit.setText(chosen)

    def _bind_hotkeys(self) -> None:
        focus_find = QShortcut(QKeySequence("Ctrl+F"), self)
        focus_find.activated.connect(lambda: self.path_edit.setFocus())
        stop_shortcut = QShortcut(QKeySequence("Esc"), self)
        stop_shortcut.activated.connect(self.stop_all)
        self.path_edit.returnPressed.connect(self.start_scan)

    # ---------- настройки ----------

    def _restore_settings(self) -> None:
        last_path = self._settings.last_path
        if last_path:
            self.path_edit.setText(last_path)
        (
            self.preset_bitrix if self._settings.preset == "bitrix" else self.preset_generic
        ).setChecked(True)
        preset = load_preset(self._settings.preset)
        for category in preset.categories:
            checkbox = self.category_checks.get(category.id)
            if checkbox is not None:
                checkbox.setChecked(
                    self._settings.category_checked(category.id, checkbox.isChecked())
                )
        mode_name = str(self._settings.get("results/group_mode", GroupMode.DIRS.value))
        try:
            mode = GroupMode(mode_name)
        except ValueError:
            mode = GroupMode.DIRS
        index = self.grouping_combo.findData(mode)
        self.grouping_combo.setCurrentIndex(max(index, 0))
        geometry = self._settings.restore_geometry()
        if geometry is not None:
            self.restoreGeometry(geometry)

    def _save_settings(self) -> None:
        self._settings.last_path = self.path_edit.text()
        self._settings.preset = "bitrix" if self.preset_bitrix.isChecked() else "generic"
        for category_id, checkbox in self.category_checks.items():
            self._settings.set_category_checked(category_id, checkbox.isChecked())
        mode = self.grouping_combo.currentData()
        if isinstance(mode, GroupMode):
            self._settings.set("results/group_mode", mode.value)
        self._settings.save_geometry(self.saveGeometry())
        self._settings.sync()

    def closeEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        self.stop_all()
        self._save_settings()
        super().closeEvent(event)

    # ---------- вспомогательное ----------

    def _busy(self) -> bool:
        return any(
            worker is not None and worker.isRunning()
            for worker in (self._scan_worker, self._count_worker, self._action_worker)
        )

    def _update_buttons(self) -> None:
        busy = self._busy()
        self.find_button.setEnabled(not busy and bool(self.path_edit.text().strip()))
        self.browse_button.setEnabled(not busy)
        self.stop_button.setEnabled(busy)
        self.run_button.setEnabled(not busy and self.model.checked_count() > 0)
        self.save_report_button.setEnabled(self._last_result is not None)

    def _preset_changed(self, checked: bool) -> None:
        if not checked:
            return
        preset = load_preset(self._preset_id())
        for category in preset.categories:
            checkbox = self.category_checks.get(category.id)
            if checkbox is not None:
                checkbox.setChecked(category.default_enabled)

    def _preset_id(self) -> str:
        return "bitrix" if self.preset_bitrix.isChecked() else "generic"

    def _current_preset(self) -> Preset:
        preset = load_preset(self._preset_id())
        if self._preset_id() == "bitrix" and not self.exclude_bitrix_dirs.isChecked():
            preset = replace(preset, excluded_dirs=())
        return preset

    def _checked_category_ids(self) -> set[str]:
        chosen = {
            category_id
            for category_id, checkbox in self.category_checks.items()
            if checkbox.isChecked()
        }
        chosen.add("secrets_report")  # всегда показываем в отчёте
        return chosen

    # ---------- сканирование ----------

    def _browse(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Каталог проекта", str(Path.home()))
        if chosen:
            self.path_edit.setText(chosen)
            self._update_buttons()

    def start_scan(self) -> None:
        if self._busy():
            return
        raw = self.path_edit.text().strip()
        if not raw:
            return
        try:
            root = check_root(Path(raw))
        except SafetyError as exc:
            QMessageBox.critical(self, "Небезопасный путь", str(exc))
            return

        preset = self._current_preset()
        self._markers_warning = (
            None
            if has_project_markers(root, preset)
            else (
                "В корне нет маркеров проекта "
                f"({', '.join(preset.markers) or '—'}). Проверьте путь."
            )
        )

        options = ScanOptions(
            root=root,
            preset=preset.id,
            categories=self._checked_category_ids(),
            exclude_globs=tuple(self._session_excludes),
            include_hidden=self.hidden_check.isChecked(),
            follow_symlinks=self.symlinks_check.isChecked(),
            use_magic=self.magic_check.isChecked(),
            deep_scan=self.deep_scan_check.isChecked(),
        )
        self._last_options = options
        self._last_preset = preset
        self._scan_started = datetime.now(UTC)
        self._last_result = None
        self._last_actions = []
        self.model.clear()
        self.summary_label.setText("Подсчёт каталогов…")
        self.progress_bar.setRange(0, 0)  # indeterminate

        self._count_worker = CountWorker(root, preset, self)
        self._count_worker.count_finished.connect(self._on_count_finished)
        self._count_worker.failed.connect(self._on_worker_failed)
        self._count_worker.start()
        self._update_buttons()  # после старта воркера: Стоп активна, Найти нет

    def _on_count_finished(self, total: int) -> None:
        if self._last_options is None or self._last_preset is None:
            return
        self.progress_bar.setRange(0, max(total, 1))
        self.progress_bar.setValue(0)
        self.summary_label.setText(f"Сканирую… (файлов: ~{total})")
        self._scan_worker = ScanWorker(self._last_options, self._last_preset, self)
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.scan_finished.connect(self._on_scan_finished)
        self._scan_worker.failed.connect(self._on_worker_failed)
        self._scan_worker.start()

    def _on_scan_progress(self, done: int, _total: int, current: str) -> None:
        self.progress_bar.setValue(min(done, self.progress_bar.maximum()))
        self.current_path_label.set_text(current)

    def _on_scan_finished(self, result: ScanResult) -> None:
        self._last_result = result
        assert self._last_preset is not None
        self.model.set_result(result, self._last_preset.categories)
        self._apply_expand_rules()
        self._apply_column_ratios()
        self._after_finish()
        skipped = len(result.skipped)
        note = f" · Пропущено: {skipped} (нет доступа)" if skipped else ""
        self.summary_label.setText(
            f"Найдено: {len(result.entries)} файл(ов), "
            f"{human_size(result.total_size())}{note}" + (" · прервано" if result.cancelled else "")
        )
        if result.cancelled:
            self.summary_label.setText(self.summary_label.text() + " — сканирование остановлено")
        self.scan_completed.emit(result)

    def _apply_expand_rules(self) -> None:
        """Категория с ≤ COLLAPSE_THRESHOLD файлами развёрнута, больше — свёрнута.

        Группы внутри развёрнутой категории всегда раскрыты (это навигация).
        """
        tree = self.tree
        tree.collapseAll()
        for row in range(self.model.rowCount()):
            source_index = self.model.index(row, 0)
            proxy_index = self.proxy.mapFromSource(source_index)
            if not proxy_index.isValid():
                continue
            if self.model.category_file_count(row) <= COLLAPSE_THRESHOLD:
                tree.expand(proxy_index)
                for child_row in range(self.model.rowCount(source_index)):
                    child_proxy = self.proxy.mapFromSource(
                        self.model.index(child_row, 0, source_index)
                    )
                    if child_proxy.isValid():
                        tree.expand(child_proxy)

    def _apply_column_ratios(self) -> None:
        """Колонка «Файл» в 4 раза шире каждой из остальных (4:1:1)."""
        width = max(self.tree.viewport().width() - 4, 120)
        small = max(width // 6, 30)
        large = width - 2 * small
        self.tree.setColumnWidth(0, large)
        self.tree.setColumnWidth(1, small)
        self.tree.setColumnWidth(2, small)

    def resizeEvent(self, event) -> None:  # type: ignore[no-untyped-def]
        super().resizeEvent(event)
        self._apply_column_ratios()

    def _on_grouping_changed(self, index: int) -> None:
        mode = self.grouping_combo.itemData(index)
        if isinstance(mode, GroupMode):
            self.model.set_group_mode(mode)
            self._apply_expand_rules()
            self._apply_column_ratios()
            self._settings.set("results/group_mode", mode.value)

    def _on_worker_failed(self, message: str) -> None:
        self._after_finish()
        QMessageBox.critical(self, "Ошибка", message)

    def _after_finish(self) -> None:
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.current_path_label.set_text("")
        self._scan_worker = None
        self._count_worker = None
        self._action_worker = None
        self._update_buttons()

    def stop_all(self) -> None:
        for worker in (self._count_worker, self._scan_worker, self._action_worker):
            if worker is not None and worker.isRunning():
                worker.stop()

    # ---------- действия ----------

    def _current_action(self) -> Action:
        if self.delete_radio.isChecked():
            return Action.DELETE
        if self.quarantine_radio.isChecked() and self.quarantine_radio.isEnabled():
            return Action.QUARANTINE
        return Action.ZERO

    def _run_action(self) -> None:
        if self._busy() or self._last_result is None or self._last_preset is None:
            return
        entries = self.model.checked_entries()
        if not entries:
            return
        action = self._current_action()

        quarantine_dir = None
        if action is Action.QUARANTINE:
            raw_dir = self.quarantine_dir_edit.text().strip()
            if not raw_dir:
                QMessageBox.warning(
                    self, "Карантин", "Укажите каталог карантина (вне корня проекта)."
                )
                return
            try:
                quarantine_dir = check_quarantine_dir(self._last_options.root, Path(raw_dir))
            except SafetyError as exc:
                QMessageBox.critical(self, "Карантин", str(exc))
                return

        warnings: list[str] = []
        if self._markers_warning:
            warnings.append(self._markers_warning)
        if action is Action.DELETE:
            warnings.append("Удалённые файлы не восстановимы. Обнуление — обратимая альтернатива.")
        if self._last_options is not None and (self._last_options.root / ".git").exists():
            warnings.append("В корне есть .git: файлы остаются в истории репозитория.")
        dialog = ConfirmDialog(
            self,
            action=action,
            count=len(entries),
            total_size=sum(e.size for e in entries),
            warnings=warnings,
        )
        if dialog.exec() != ConfirmDialog.DialogCode.Accepted:
            return

        self._last_actions = []
        self.summary_label.setText("Выполняю…")
        self.progress_bar.setRange(0, max(len(entries), 1))
        self._update_buttons()
        self._action_worker = ActionWorker(
            entries,
            action,
            self._last_preset,
            quarantine_dir=quarantine_dir,
            parent=self,
        )
        self._action_worker.action_progress.connect(self._on_action_progress)
        self._action_worker.action_finished.connect(self._on_action_finished)
        self._action_worker.failed.connect(self._on_worker_failed)
        self._action_worker.start()

    def _on_action_progress(self, done: int, total: int) -> None:
        self.progress_bar.setValue(min(done, self.progress_bar.maximum()))
        self.summary_label.setText(f"Выполняю… {done}/{total}")

    def _on_action_finished(self, results: object) -> None:
        cancelled = self._action_worker is not None and self._action_worker.cancel_event.is_set()
        action_results: list[ActionResult] = list(results)  # type: ignore[arg-type]
        self._last_actions = action_results
        processed = {r.entry.path for r in action_results if r.ok and r.note is None}
        self.model.mark_processed(processed)

        ok = sum(1 for r in action_results if r.ok)
        failed = len(action_results) - ok
        skipped = sum(1 for r in action_results if r.note)
        has_access_errors = any(
            r.ok is False and "Permission" in (r.error or "") for r in action_results
        )
        self._after_finish()
        self.summary_label.setText(
            f"Готово: обработано {ok}, ошибок {failed}"
            + (f", пропущено {skipped}" if skipped else "")
        )

        report_path = self._write_report_silent()
        SummaryDialog(
            self,
            ok=ok,
            failed=failed,
            skipped=skipped,
            cancelled=cancelled,
            report_path=report_path,
        ).exec()
        if has_access_errors and self._last_options is not None:
            show_sudo_hint(
                self,
                self._last_options.root,
                report_path.as_posix() if report_path else "sanitize-report.json",
                delete=self._current_action() is Action.DELETE,
            )

    def _write_report_silent(self) -> Path | None:
        """Автоотчёт после действий: sanitize-report.json рядом с корнем."""
        if self._last_result is None or self._last_options is None or self._last_preset is None:
            return None
        try:
            payload = build_report(
                result=self._last_result,
                options=self._last_options,
                preset=self._last_preset,
                started_at=self._scan_started or datetime.now(UTC),
                finished_at=datetime.now(UTC),
                actions=self._last_actions,
            )
            target = Path("sanitize-report.json").resolve()
            write_report(target, payload)
            return target
        except OSError:
            logger.exception("Не удалось записать автоотчёт")
            return None

    def _save_report(self) -> None:
        if self._last_result is None or self._last_options is None or self._last_preset is None:
            QMessageBox.information(self, "Отчёт", "Сначала выполните поиск.")
            return
        chosen = ask_report_path(self)
        if not chosen:
            return
        payload = build_report(
            result=self._last_result,
            options=self._last_options,
            preset=self._last_preset,
            started_at=self._scan_started or datetime.now(UTC),
            finished_at=datetime.now(UTC),
            actions=self._last_actions,
        )
        write_report(Path(chosen), payload)
        QMessageBox.information(self, "Отчёт", f"Сохранено: {chosen}")

    # ---------- контекстное меню ----------

    def _context_menu(self, pos) -> None:  # type: ignore[no-untyped-def]
        index = self.tree.indexAt(pos)
        if not index.isValid():
            return
        source = self.proxy.mapToSource(index)
        entry: FileEntry | None = source.data(ENTRY_ROLE)
        if entry is None:
            return
        menu = QMenu(self)
        open_dir = menu.addAction("Открыть каталог")
        copy_path = menu.addAction("Копировать путь")
        exclude_dir = menu.addAction("Исключить каталог из поиска")
        chosen = menu.exec(self.tree.viewport().mapToGlobal(pos))
        if chosen is open_dir:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(entry.path.parent)))
        elif chosen is copy_path:
            clipboard = QGuiApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(str(entry.path))
        elif chosen is exclude_dir:
            if self._last_options is not None:
                base = self._last_options.root
            else:
                base = Path(self.path_edit.text() or "/")
            try:
                rel = entry.path.parent.relative_to(base).as_posix()
            except ValueError:
                rel = entry.path.parent.as_posix()
            pattern = rel + "/**"
            if pattern not in self._session_excludes:
                self._session_excludes.append(pattern)
            self.statusBar().showMessage(f"Исключено из поиска: {pattern}", 5000)
