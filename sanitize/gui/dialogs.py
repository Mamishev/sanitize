"""Диалоги GUI: подтверждение (ввод DELETE), сводка, sudo-подсказка (AGENTS.md, разд. 8)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from sanitize.core.models import Action
from sanitize.core.report import human_size

_VERBS = {
    Action.ZERO: "Обнулить",
    Action.DELETE: "Удалить",
    Action.STUB: "Заменить заглушками",
    Action.QUARANTINE: "Отправить в карантин",
}

_DELETE_WORD = "DELETE"


class ConfirmDialog(QDialog):
    """Подтверждение действия: действие, число файлов, объём, предупреждения.

    Для Action.DELETE требует ввода слова DELETE; кнопка OK неактивна,
    пока слово не введено точно.
    """

    def __init__(
        self,
        parent=None,  # type: ignore[no-untyped-def]
        *,
        action: Action = Action.ZERO,
        count: int = 0,
        total_size: int = 0,
        warnings: list[str] | None = None,
        keep_attrs: bool = True,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Подтверждение действия")
        layout = QVBoxLayout(self)

        layout.addWidget(
            QLabel(
                f"<b>{_VERBS.get(action, action.value)}</b> файлов: {count}<br>"
                f"Суммарный объём: {human_size(total_size)}"
            )
        )
        if keep_attrs:
            layout.addWidget(QLabel("Владелец, права и mtime файлов будут сохранены."))
        if warnings:
            for warning in warnings:
                layout.addWidget(QLabel(f"⚠️ {warning}"))

        if action is Action.DELETE:
            layout.addWidget(QLabel(f"Для подтверждения введите слово <b>{_DELETE_WORD}</b>:"))
            self._delete_input = QLineEdit(self)
            self._delete_input.setPlaceholderText(_DELETE_WORD)
            layout.addWidget(self._delete_input)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._buttons = buttons

        if action is Action.DELETE:
            buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
            self._delete_input.textChanged.connect(self._validate_delete)
            self._delete_input.setFocus()

    def _validate_delete(self, text: str) -> None:
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(
            text.strip() == _DELETE_WORD
        )


class SummaryDialog(QDialog):
    """Итоговая сводка после выполнения: успех/ошибки/пропуски + «Открыть отчёт»."""

    def __init__(
        self,
        parent=None,  # type: ignore[no-untyped-def]
        *,
        ok: int = 0,
        failed: int = 0,
        skipped: int = 0,
        cancelled: bool = False,
        report_path: Path | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Готово")
        self._report_path = report_path
        layout = QVBoxLayout(self)
        lines = [f"Успешно обработано: {ok}"]
        if failed:
            lines.append(f"Ошибок: {failed}")
        if skipped:
            lines.append(f"Пропущено (пустые/симлинки): {skipped}")
        if cancelled:
            lines.append("⚠️ Операция была прервана — часть файлов не обработана.")
        layout.addWidget(QLabel("<br>".join(lines)))

        buttons_row = QHBoxLayout()
        if report_path is not None:
            open_button = QPushButton("Открыть отчёт…", self)
            open_button.clicked.connect(self._open_report)
            buttons_row.addWidget(open_button)
        buttons_row.addStretch(1)
        close_button = QPushButton("Закрыть", self)
        close_button.clicked.connect(self.accept)
        buttons_row.addWidget(close_button)
        layout.addLayout(buttons_row)

    def _open_report(self) -> None:
        if self._report_path is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._report_path)))


def show_sudo_hint(parent, root: Path, report: str, delete: bool) -> None:  # type: ignore[no-untyped-def]
    """При ошибках доступа — диалог с командой для копирования (GUI под root не запускаем)."""
    command = f"sudo sanitize --path {root} --report {report}"
    if delete:
        command += " --delete"
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setWindowTitle("Нужны права доступа")
    box.setText(
        "Часть файлов недоступна для текущего пользователя. "
        "Команда для запуска с нужными правами (скопируйте):"
    )
    box.setDetailedText(command)
    copy_button = box.addButton("Копировать команду", QMessageBox.ButtonRole.ActionRole)
    box.addButton(QMessageBox.StandardButton.Close)
    copy_button.clicked.connect(lambda: _copy(command))
    box.exec()


def _copy(text: str) -> None:
    from PySide6.QtWidgets import QApplication

    clipboard = QApplication.clipboard()
    if clipboard is not None:
        clipboard.setText(text)


def ask_report_path(parent, suggested: str = "sanitize-report.json") -> str | None:  # type: ignore[no-untyped-def]
    """Диалог сохранения отчёта; возвращает путь или None."""
    chosen, _filter = QFileDialog.getSaveFileName(
        parent, "Сохранить отчёт", suggested, "Отчёты (*.json *.md)"
    )
    return chosen or None
