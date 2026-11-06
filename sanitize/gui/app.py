"""Точка входа GUI: sanitize --gui / sanitize-gui.

QApplication + главное окно. GUI под root не запускаем — предупреждаем.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Sequence

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_REFUSED = 3


def prepare_application(argv: Sequence[str] | None = None):  # type: ignore[no-untyped-def]
    """Создаёт QApplication с общими настройками (отдельно — для тестов)."""
    from PySide6.QtWidgets import QApplication

    application = QApplication(sys.argv if argv is None else list(argv))
    application.setApplicationName("sanitize")
    application.setOrganizationName("sanitize")
    application.setApplicationDisplayName("sanitize")
    return application


def _warn_if_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        from PySide6.QtWidgets import QMessageBox

        QMessageBox.warning(
            None,
            "Запуск под root",
            "Не рекомендуется запускать GUI под root.\n"
            "Для обработки каталогов с чужими правами используйте CLI:\n"
            "sudo sanitize --path /var/www/site --dry-run",
        )


def main(argv: Sequence[str] | None = None) -> int:
    """Вход для консольного скрипта sanitize-gui и флага sanitize --gui."""
    try:
        import PySide6  # noqa: F401 — проверка наличия extras
    except ImportError:
        print(
            "GUI недоступен: установите зависимости — pip install 'sanitize[gui]'",
            file=sys.stderr,
        )
        return EXIT_REFUSED

    application = prepare_application(argv)
    from sanitize.gui.main_window import MainWindow

    _warn_if_root()
    window = MainWindow()
    window.show()
    logger.info("GUI запущен")
    return application.exec()
